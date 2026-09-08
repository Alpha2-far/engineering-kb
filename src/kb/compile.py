"""Compilation des regles en paquets consommables par un agent.

Contrainte de conception : on ne peut PAS charger toute la base dans le contexte
d'un agent, et il ne faut surtout pas essayer. Une base qui noie l'agent produit
des audits plus mauvais qu'une petite base bien ciblee — l'attention est la
ressource rare.

D'ou deux vues :
  - by-category/ : pour une question ciblee (« que dit la KB sur JWT ? »)
  - profiles/    : pour un audit de projet. Un site statique vanilla ne doit
                   jamais voir les regles pgvector. Les regles sans
                   `project_types` sont universelles et entrent dans tous les
                   profils.

Le routage est deterministe (index en table de correspondance) plutot que
semantique : les regles se classent par technologie, ce qui est une recherche
categorielle. Des embeddings couteraient plus cher pour un rappel moins bon.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .registry import PACKS_DIR
from .schema import Rule, Severity

PROFILES = ["static-site", "saas", "ai-rag", "api", "pipeline", "cli", "mobile"]
SEVERITY_ORDER = {
    Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
    Severity.LOW: 3, Severity.INFO: 4,
}


def _sort_key(r: Rule) -> tuple:
    return (SEVERITY_ORDER[r.severity], r.category.value, r.subcategory, r.id)


def assign_short_refs(rules: list[Rule]) -> dict[str, str]:
    """`KB-0001` pour citer une regle dans un rapport sans y coller un chemin.

    Attribue par ordre alphabetique d'id : deterministe, donc stable d'une
    compilation a l'autre tant que la regle existe.
    """
    return {r.id: f"KB-{i:04d}" for i, r in enumerate(sorted(rules, key=lambda x: x.id), start=1)}


def _dump(rule: Rule, short_ref: str) -> dict:
    d = rule.model_dump(mode="json", exclude_none=True)
    d["ref"] = short_ref
    return d


def compile_packs(rules: list[Rule], out_dir: Path | None = None) -> dict:
    out = out_dir or PACKS_DIR
    (out / "by-category").mkdir(parents=True, exist_ok=True)
    (out / "profiles").mkdir(parents=True, exist_ok=True)

    refs = assign_short_refs(rules)
    ordered = sorted(rules, key=_sort_key)
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # --- par categorie
    by_cat: dict[str, list[Rule]] = defaultdict(list)
    for r in ordered:
        by_cat[r.category.value].append(r)
    cat_index = {}
    for cat, rs in sorted(by_cat.items()):
        fname = f"{cat}.json"
        (out / "by-category" / fname).write_text(
            json.dumps(
                {"category": cat, "generated_at": generated, "count": len(rs),
                 "rules": [_dump(r, refs[r.id]) for r in rs]},
                indent=2, ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        cat_index[cat] = {
            "file": f"by-category/{fname}",
            "count": len(rs),
            "severities": dict(Counter(r.severity.value for r in rs)),
        }

    # --- par profil de projet
    profile_index = {}
    for prof in PROFILES:
        rs = [r for r in ordered if not r.context.project_types or prof in r.context.project_types]
        fname = f"{prof}.json"
        (out / "profiles" / fname).write_text(
            json.dumps(
                {"profile": prof, "generated_at": generated, "count": len(rs),
                 "rules": [_dump(r, refs[r.id]) for r in rs]},
                indent=2, ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        profile_index[prof] = {
            "file": f"profiles/{fname}",
            "count": len(rs),
            "critical": sum(1 for r in rs if r.severity is Severity.CRITICAL),
        }

    # --- routage par axe technique
    routing: dict[str, dict[str, list[str]]] = {
        "languages": defaultdict(list), "frameworks": defaultdict(list),
        "platforms": defaultdict(list),
    }
    for r in ordered:
        for axis, values in (
            ("languages", r.context.languages),
            ("frameworks", r.context.frameworks),
            ("platforms", r.context.platforms),
        ):
            for v in values:
                routing[axis][v.lower()].append(refs[r.id])

    index = {
        "generated_at": generated,
        "rule_count": len(rules),
        "categories": cat_index,
        "profiles": profile_index,
        "routing": {k: dict(sorted(v.items())) for k, v in routing.items()},
        "severity_totals": dict(Counter(r.severity.value for r in ordered)),
        "autofix_totals": dict(Counter(r.autofix.value for r in ordered)),
        "sources_used": dict(
            Counter(ev.source_id for r in ordered for ev in r.evidence)
        ),
    }
    (out / "index.json").write_text(json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8")
    (out / "id-map.json").write_text(
        json.dumps({v: k for k, v in sorted(refs.items(), key=lambda kv: kv[1])},
                   indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    _write_markdown_view(ordered, refs, out / "RULES.md", generated)
    return index


def _write_markdown_view(rules: list[Rule], refs: dict[str, str], dest: Path, generated: str) -> None:
    """Vue humaine. Farel doit pouvoir relire la base sans lire du JSON —
    et pouvoir s'en servir pour repondre a un client."""
    lines = [
        "# Regles compilees — Knowledge Base d'ingenierie",
        "",
        f"> Genere le {generated[:10]} — {len(rules)} regles. **Ne pas editer a la main** :",
        "> ce fichier est produit par `uv run kb compile`. Corriger la source dans `kb/rules/`.",
        "",
        "Chaque regle porte une citation verifiee dans un document officiel archive.",
        "Une regle dont la citation n'a pas pu etre retrouvee a ete rejetee et n'apparait pas ici.",
        "",
    ]
    current = None
    for r in rules:
        if r.category.value != current:
            current = r.category.value
            lines += ["", f"## {current}", ""]
        sev = r.severity.value.upper()
        lines.append(f"### `{refs[r.id]}` · {sev} · {r.title}")
        lines.append("")
        lines.append(f"- **id** : `{r.id}`")
        lines.append(f"- **exige** : {r.description}")
        lines.append(f"- **pourquoi** : {r.rationale}")
        lines.append(f"- **correction** : {r.remediation}")
        if r.context.frameworks or r.context.languages or r.context.platforms:
            scope = ", ".join(r.context.languages + r.context.frameworks + r.context.platforms)
            lines.append(f"- **portee** : {scope}")
        det = "; ".join(f"`{d.kind.value}:{d.pattern}`" for d in r.detection[:3])
        lines.append(f"- **detection** : {det}")
        srcs = ", ".join(
            f"[{ev.source_id}]({ev.url})" if ev.url else ev.source_id for ev in r.evidence
        )
        lines.append(f"- **source** : {srcs} · confiance {r.confidence.value}")
        lines.append("")
    dest.write_text("\n".join(lines), encoding="utf-8")
