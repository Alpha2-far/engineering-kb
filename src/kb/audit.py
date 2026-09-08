"""Application d'un profil compile a un projet reel.

Ce module fait le pont entre le livrable (`packs/profiles/*.json`) et du code
sur disque. Il ne remplace pas l'auditeur humain ni le sous-agent : il produit
le *reperage mecanique* — quelles regles ont matiere a etre examinees sur ce
projet — pour qu'un agent recoive 15 regles accrochees a des lignes precises
plutot que 40 regles a evaluer dans le vide.

Deux natures de detection, et la seconde est la plus facile a oublier :

  - `grep`   : le motif TROUVE est le probleme (une f-string dans un execute()).
  - `absent` : le motif MANQUANT est le probleme (aucun `permissions:` dans un
               workflow). Un scanner qui ne traite que `grep` rate ces regles
               *en silence* et les compte comme « rien a signaler ». C'est
               exactement le mode de panne du portail d'ancrage : ne pas
               planter, et taire du travail reel. 14 des 74 detections du profil
               `ai-rag` sont de ce type.

Un `absent` ne se resout pas fichier par fichier comme un `grep` : la question
n'est pas « ce fichier contient-il le motif ? » mais « parmi les fichiers
concernes par cette regle, lesquels ne le contiennent pas ? ». Si aucun fichier
ne correspond au glob, la regle est *hors-perimetre*, pas *satisfaite* — un
projet sans workflow GitHub ne viole pas la regle sur les permissions de
workflow. Confondre les deux produit des rapports qui affirment.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

from .registry import PACKS_DIR

# Repertoires sans valeur d'audit : dependances, artefacts de build, caches.
# Les scanner triple le temps et noie le signal sous du code tiers.
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    ".next", ".nuxt", ".mypy_cache", ".pytest_cache", ".ruff_cache", "coverage",
    ".turbo", "target", "vendor", ".terraform", "site-packages", ".tox",
}
MAX_FILE_BYTES = 2_000_000  # au-dela : donnee/artefact, pas du code relu
MAX_HITS_PER_RULE = 200  # borne le rapport ; le compte total reste exact


@dataclass
class Hit:
    path: str
    line: int
    text: str


@dataclass
class Finding:
    rule: dict
    hits: list[Hit] = field(default_factory=list)
    kind: str = "grep"  # grep | absent
    scoped_files: int = 0  # fichiers concernes par le glob (pour `absent`)
    truncated: int = 0  # occurrences au-dela de MAX_HITS_PER_RULE

    @property
    def severity(self) -> str:
        return self.rule.get("severity", "medium")


@dataclass
class AuditResult:
    profile: str
    root: Path
    files_scanned: int
    findings: list[Finding]
    silent: list[dict]
    out_of_scope: list[dict]
    bad_patterns: list[tuple[str, str, str]]


def iter_files(root: Path):
    for p in root.rglob("*"):
        if not p.is_file() or p.is_symlink():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield p


def glob_match(rel: str, patterns: list[str]) -> bool:
    """Un glob vide vaut « tout fichier » (contrat du schema `applies_to`).

    On teste trois formes parce que les regles ecrivent indifferemment
    `**/*.py`, `*.py` ou `.github/workflows/*.yml`, et que `fnmatch` ne
    comprend pas `**` comme un shell : sans le repli sur le nom de base, un
    motif `**/*.py` ne matcherait aucun fichier a la racine.
    """
    if not patterns:
        return True
    name = Path(rel).name
    for pat in patterns:
        if fnmatch(rel, pat) or fnmatch(rel, pat.removeprefix("**/")):
            return True
        if "/" not in pat and fnmatch(name, pat):
            return True
    return False


def _read(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def run_audit(profile: str, root: Path, packs_dir: Path | None = None) -> AuditResult:
    packs = packs_dir or PACKS_DIR
    pack_path = packs / "profiles" / f"{profile}.json"
    if not pack_path.is_file():
        available = sorted(p.stem for p in (packs / "profiles").glob("*.json"))
        raise FileNotFoundError(
            f"profil inconnu : {profile}. Disponibles : {', '.join(available)}"
        )
    rules = json.loads(pack_path.read_text())["rules"]

    texts: dict[str, str] = {}
    for f in iter_files(root):
        content = _read(f)
        if content is not None:
            texts[str(f.relative_to(root))] = content

    findings: list[Finding] = []
    silent: list[dict] = []
    out_of_scope: list[dict] = []
    bad_patterns: list[tuple[str, str, str]] = []

    for rule in rules:
        detections = rule.get("detection", [])
        grep_hits: list[Hit] = []
        absent_hits: list[Hit] = []
        scoped_total = 0
        saw_absent = False
        saw_mechanical = False

        for det in detections:
            kind = det.get("kind")
            if kind not in ("grep", "absent"):
                continue  # ast/config/dependency/manual : hors reperage textuel
            saw_mechanical = True
            try:
                # MULTILINE est obligatoire, pas cosmetique : les motifs `absent`
                # sont ancres par ligne (`^USER `, `^permissions:`) et sont
                # cherches dans le texte ENTIER du fichier. Sans le drapeau, `^`
                # ne matche qu'a l'offset 0 : un Dockerfile qui declare `USER` en
                # ligne 2 serait declare tournant en root. Faux positif
                # silencieux, sur la moitie des motifs `absent` du corpus.
                rx = re.compile(det["pattern"], re.MULTILINE)
            except re.error as exc:
                bad_patterns.append((rule["id"], det["pattern"], str(exc)))
                continue

            applies = det.get("applies_to") or []
            scoped = [rel for rel in texts if glob_match(rel, applies)]

            if kind == "grep":
                for rel in scoped:
                    for i, line in enumerate(texts[rel].splitlines(), 1):
                        if rx.search(line):
                            grep_hits.append(Hit(rel, i, line.strip()[:160]))
            else:
                # `absent` : le manque est le probleme. Sans fichier dans le
                # perimetre, la regle ne s'applique pas — on ne conclut rien.
                saw_absent = True
                scoped_total += len(scoped)
                for rel in scoped:
                    if not rx.search(texts[rel]):
                        absent_hits.append(
                            Hit(rel, 0, det.get("note") or f"motif requis absent : {det['pattern']}")
                        )

        if not saw_mechanical:
            silent.append(rule)
            continue

        all_hits = grep_hits + absent_hits
        if all_hits:
            truncated = max(0, len(all_hits) - MAX_HITS_PER_RULE)
            findings.append(
                Finding(
                    rule=rule,
                    hits=all_hits[:MAX_HITS_PER_RULE],
                    kind="absent" if absent_hits and not grep_hits else "grep",
                    scoped_files=scoped_total,
                    truncated=truncated,
                )
            )
        elif saw_absent and scoped_total == 0:
            out_of_scope.append(rule)
        else:
            silent.append(rule)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 9), -len(f.hits)))
    return AuditResult(
        profile=profile,
        root=root,
        files_scanned=len(texts),
        findings=findings,
        silent=silent,
        out_of_scope=out_of_scope,
        bad_patterns=bad_patterns,
    )


def to_json(res: AuditResult) -> dict:
    """Sortie destinee a un agent : chaque regle avec ses ancrages de code.

    On ne recopie pas `evidence` (la citation source) : elle pese lourd et
    l'agent la lira dans le pack s'il doit justifier un constat dans un rapport.
    """
    return {
        "profile": res.profile,
        "root": str(res.root),
        "files_scanned": res.files_scanned,
        "counts": {
            "fired": len(res.findings),
            "silent": len(res.silent),
            "out_of_scope": len(res.out_of_scope),
            "bad_patterns": len(res.bad_patterns),
        },
        "findings": [
            {
                "ref": f.rule.get("ref"),
                "id": f.rule["id"],
                "title": f.rule.get("title"),
                "severity": f.severity,
                "detection_kind": f.kind,
                "remediation": f.rule.get("remediation"),
                "occurrences": len(f.hits) + f.truncated,
                "hits": [{"path": h.path, "line": h.line, "text": h.text} for h in f.hits],
            }
            for f in res.findings
        ],
        "out_of_scope": [r["id"] for r in res.out_of_scope],
        "bad_patterns": [{"id": i, "pattern": p, "error": e} for i, p, e in res.bad_patterns],
    }
