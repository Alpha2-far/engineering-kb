"""Validation : schema, ancrage, doublons.

Ordre volontaire — le moins cher d'abord, pour que l'echec le plus probable soit
aussi le plus rapide a diagnostiquer :
  1. schema Pydantic  (structure, exemples exiges, regex compilables)
  2. ancrage          (chaque citation retrouvee dans le document archive)
  3. unicite          (id deja pris)
  4. quasi-doublons   (signale, ne rejette pas : le jugement reste humain)
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path

import yaml
from pydantic import ValidationError

from .ground import normalize, verify_quote, verify_sha
from .registry import PACKS_DIR, RULES_DIR
from .schema import Rule

NEAR_DUP_THRESHOLD = 0.90


@dataclass
class Rejection:
    rule_id: str
    file: str
    stage: str
    reason: str


@dataclass
class ValidationReport:
    accepted: list[Rule] = field(default_factory=list)
    rejections: list[Rejection] = field(default_factory=list)
    near_duplicates: list[tuple[str, str, float]] = field(default_factory=list)
    stale_docs: list[tuple[str, str]] = field(default_factory=list)
    files_seen: int = 0

    @property
    def total_submitted(self) -> int:
        return len(self.accepted) + len(self.rejections)

    def summary(self) -> dict:
        by_stage = Counter(r.stage for r in self.rejections)
        return {
            "files_seen": self.files_seen,
            "submitted": self.total_submitted,
            "accepted": len(self.accepted),
            "rejected": len(self.rejections),
            "rejected_by_stage": dict(by_stage),
            "near_duplicates": len(self.near_duplicates),
            "stale_docs": len(self.stale_docs),
            "by_category": dict(Counter(r.category.value for r in self.accepted)),
            "by_severity": dict(Counter(r.severity.value for r in self.accepted)),
            "by_confidence": dict(Counter(r.confidence.value for r in self.accepted)),
        }


def _iter_rule_files(rules_dir: Path) -> list[Path]:
    return sorted(p for p in rules_dir.glob("*.yaml") if p.name != "_template.yaml")


def validate_all(
    rules_dir: Path | None = None,
    *,
    check_grounding: bool = True,
    only_file: Path | None = None,
) -> ValidationReport:
    """`only_file` sert la boucle d'auto-correction d'un extracteur : il valide son
    propre pack sans se noyer dans les rejets des autres. La detection de doublons
    d'id, elle, n'a de sens qu'en passe globale."""
    rd = rules_dir or RULES_DIR
    report = ValidationReport()
    seen_ids: dict[str, str] = {}

    targets = [only_file] if only_file else _iter_rule_files(rd)
    for path in targets:
        report.files_seen += 1
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:
            report.rejections.append(Rejection("<fichier>", path.name, "yaml", str(e)[:300]))
            continue

        entries = raw.get("rules", raw if isinstance(raw, list) else [])
        for i, entry in enumerate(entries):
            rid = (entry or {}).get("id", f"<sans id #{i}>")

            # 1. schema
            try:
                rule = Rule.model_validate(entry)
            except ValidationError as e:
                first = e.errors()[0]
                loc = ".".join(str(x) for x in first.get("loc", ()))
                report.rejections.append(
                    Rejection(rid, path.name, "schema", f"{loc}: {first.get('msg')}")
                )
                continue

            # 2. ancrage — toutes les citations, pas seulement la premiere.
            # Une regle dont une reference sur trois est inventee est contaminee.
            if check_grounding:
                failed = []
                for ev in rule.evidence:
                    v = verify_quote(ev.quote, ev.doc_path)
                    if not v.grounded:
                        failed.append(f"{ev.doc_path} [{v.method}] {v.detail}")
                    elif not verify_sha(ev.doc_path, ev.doc_sha256):
                        report.stale_docs.append((rule.id, ev.doc_path))
                if failed:
                    report.rejections.append(
                        Rejection(rule.id, path.name, "grounding", " ; ".join(failed)[:400])
                    )
                    continue

            # 3. unicite
            if rule.id in seen_ids:
                report.rejections.append(
                    Rejection(rule.id, path.name, "duplicate-id", f"deja defini dans {seen_ids[rule.id]}")
                )
                continue
            seen_ids[rule.id] = path.name
            report.accepted.append(rule)

    report.near_duplicates = _find_near_duplicates(report.accepted)
    return report


def _find_near_duplicates(rules: list[Rule]) -> list[tuple[str, str, float]]:
    """Deux sources differentes enoncent souvent la meme exigence (OWASP ASVS et
    la cheat sheet correspondante). On les signale au lieu de les fusionner : la
    redondance entre standards est une information, et la fusion automatique
    perdrait une citation."""
    out: list[tuple[str, str, float]] = []
    buckets: dict[tuple[str, str], list[Rule]] = defaultdict(list)
    for r in rules:
        buckets[(r.category.value, r.subcategory)].append(r)

    for group in buckets.values():
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                a, b = group[i], group[j]
                ratio = SequenceMatcher(
                    None, normalize(a.title), normalize(b.title)
                ).ratio()
                if ratio >= NEAR_DUP_THRESHOLD:
                    out.append((a.id, b.id, round(ratio, 3)))
    return out


def write_report(report: ValidationReport, path: Path | None = None) -> Path:
    dest = path or (PACKS_DIR / "validation-report.json")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        json.dumps(
            {
                "summary": report.summary(),
                "rejections": [vars(r) for r in report.rejections],
                "near_duplicates": [
                    {"a": a, "b": b, "similarity": s} for a, b, s in report.near_duplicates
                ],
                "stale_docs": [{"rule": r, "doc": d} for r, d in report.stale_docs],
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return dest
