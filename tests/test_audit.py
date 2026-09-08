"""Tests du reperage mecanique.

Ce que ces tests protegent n'est pas la couverture de lignes mais deux
proprietes dont la violation est *silencieuse* — le meme mode de panne que le
portail d'ancrage (cf. `test_ground.py`) : le scanner ne plante pas, il tait.

  1. Les detections `absent` sont reellement evaluees. Le premier essai du
     livrable ne traitait que `grep` et comptait les 4 regles purement `absent`
     du profil `ai-rag` comme « rien a signaler ». Un Dockerfile tournant en
     root n'etait pas rapporte : il etait invisible.
  2. « Hors-perimetre » n'est pas « conforme ». Un projet sans Dockerfile ne
     satisfait pas la regle sur l'utilisateur du conteneur — elle ne s'applique
     pas. Rendre les deux indistinguables produit un rapport qui affirme la
     securite d'une zone jamais regardee, ce qui est pire qu'un rapport muet.

Les fixtures fabriquent leur propre pack : ces tests ne dependent ni de `raw/`
ni du corpus reel, donc ils ne cassent pas quand une regle evolue.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kb.audit import glob_match, run_audit, to_json


def _pack(tmp_path: Path, rules: list[dict]) -> Path:
    packs = tmp_path / "packs"
    (packs / "profiles").mkdir(parents=True)
    (packs / "profiles" / "essai.json").write_text(
        json.dumps({"profile": "essai", "count": len(rules), "rules": rules})
    )
    return packs


def _regle(rid: str, detection: list[dict], severity: str = "high") -> dict:
    return {
        "id": rid,
        "ref": "KB-0001",
        "title": rid,
        "severity": severity,
        "category": "devops",
        "detection": detection,
    }


# --------------------------------------------------------------------------- #
# 1. Les detections `absent` sont evaluees
# --------------------------------------------------------------------------- #


def test_motif_requis_absent_est_rapporte(tmp_path):
    """La regression qui a motive ce fichier.

    Un scanner qui filtre sur `kind == "grep"` laisse passer ce cas sans erreur
    et sans occurrence : le Dockerfile sans `USER` est declare propre.
    """
    projet = tmp_path / "projet"
    projet.mkdir()
    (projet / "Dockerfile").write_text("FROM python:3.12\nCMD [\"python\", \"app.py\"]\n")

    packs = _pack(
        tmp_path,
        [_regle("devops/containers/root", [
            {"kind": "absent", "pattern": "^USER ", "applies_to": ["**/Dockerfile"],
             "note": "Aucune directive USER : le processus tourne en root."},
        ])],
    )

    res = run_audit("essai", projet, packs_dir=packs)
    assert len(res.findings) == 1, "la detection `absent` n'a pas ete evaluee"
    assert res.findings[0].kind == "absent"
    assert "USER" in res.findings[0].hits[0].text


def test_motif_requis_present_ne_declenche_pas(tmp_path):
    """Symetrie du test precedent : sans ce controle, on ne saurait pas si la
    regle declenche parce que le motif manque ou parce qu'elle declenche toujours.

    Ce test a trouve un vrai defaut : les motifs `absent` sont ancres par ligne
    (`^USER `) mais cherches dans le texte entier du fichier. Sans `re.MULTILINE`,
    `^` ne matche qu'a l'offset 0 — un Dockerfile declarant `USER` ailleurs qu'en
    premiere ligne etait rapporte comme tournant en root. Le `USER` est ici en
    ligne 2 exactement pour cette raison : en ligne 1, le test passerait meme
    avec le defaut.
    """
    projet = tmp_path / "projet"
    projet.mkdir()
    (projet / "Dockerfile").write_text("FROM python:3.12\nUSER 10001\nCMD [\"python\"]\n")

    packs = _pack(
        tmp_path,
        [_regle("devops/containers/root", [
            {"kind": "absent", "pattern": "^USER ", "applies_to": ["**/Dockerfile"]},
        ])],
    )

    res = run_audit("essai", projet, packs_dir=packs)
    assert res.findings == []
    assert len(res.silent) == 1, "la regle a ete evaluee : elle est muette, pas hors-perimetre"


# --------------------------------------------------------------------------- #
# 2. Hors-perimetre n'est pas conforme
# --------------------------------------------------------------------------- #


def test_absence_de_fichier_concerne_est_hors_perimetre_pas_conforme(tmp_path):
    """Un projet sans Dockerfile ne « respecte » pas la regle sur le conteneur.

    C'est la distinction qui empeche un rapport d'affirmer la securite d'une
    zone qui n'a jamais ete regardee.
    """
    projet = tmp_path / "projet"
    projet.mkdir()
    (projet / "app.py").write_text("print('rien a voir avec docker')\n")

    packs = _pack(
        tmp_path,
        [_regle("devops/containers/root", [
            {"kind": "absent", "pattern": "^USER ", "applies_to": ["**/Dockerfile"]},
        ])],
    )

    res = run_audit("essai", projet, packs_dir=packs)
    assert res.findings == []
    assert res.silent == [], "un fichier hors-perimetre ne doit pas etre compte comme evalue"
    assert len(res.out_of_scope) == 1


def test_hors_perimetre_est_distinct_dans_la_sortie_json(tmp_path):
    """L'agent consommateur doit pouvoir faire la difference sans la deviner."""
    projet = tmp_path / "projet"
    projet.mkdir()
    (projet / "app.py").write_text("x = 1\n")

    packs = _pack(
        tmp_path,
        [
            _regle("devops/containers/root", [
                {"kind": "absent", "pattern": "^USER ", "applies_to": ["**/Dockerfile"]},
            ]),
            _regle("app-security/injection/eval", [
                {"kind": "grep", "pattern": r"\beval\s*\(", "applies_to": ["**/*.py"]},
            ]),
        ],
    )

    sortie = to_json(run_audit("essai", projet, packs_dir=packs))
    assert sortie["counts"]["out_of_scope"] == 1
    assert sortie["out_of_scope"] == ["devops/containers/root"]
    assert sortie["counts"]["fired"] == 0
    assert sortie["counts"]["silent"] == 1  # la regle eval a bien tourne


# --------------------------------------------------------------------------- #
# Robustesse : le scanner ne doit pas s'arreter sur une regle cassee
# --------------------------------------------------------------------------- #


def test_motif_invalide_est_signale_sans_interrompre_le_scan(tmp_path):
    """Le schema compile les regex a la construction, mais un pack edite a la
    main ou une regle future peut en casser une. Une regle cassee ne doit pas
    faire perdre les 39 autres — elle doit etre nommee."""
    projet = tmp_path / "projet"
    projet.mkdir()
    (projet / "app.py").write_text("eval('2+2')\n")

    packs = _pack(
        tmp_path,
        [
            _regle("cassee/regex/invalide", [
                {"kind": "grep", "pattern": "([non-ferme", "applies_to": ["**/*.py"]},
            ]),
            _regle("app-security/injection/eval", [
                {"kind": "grep", "pattern": r"\beval\s*\(", "applies_to": ["**/*.py"]},
            ]),
        ],
    )

    res = run_audit("essai", projet, packs_dir=packs)
    assert len(res.bad_patterns) == 1
    assert res.bad_patterns[0][0] == "cassee/regex/invalide"
    assert [f.rule["id"] for f in res.findings] == ["app-security/injection/eval"]


def test_profil_inconnu_liste_les_profils_disponibles(tmp_path):
    """Une erreur qui ne dit pas quoi taper ensuite coute un aller-retour."""
    packs = _pack(tmp_path, [])
    with pytest.raises(FileNotFoundError, match="essai"):
        run_audit("nexiste-pas", tmp_path, packs_dir=packs)


def test_repertoires_de_dependances_sont_ignores(tmp_path):
    """Sans ce filtre, `node_modules` noie le signal sous du code tiers qu'on
    ne corrigera pas — et fait exploser le temps de scan."""
    projet = tmp_path / "projet"
    (projet / "node_modules" / "paquet").mkdir(parents=True)
    (projet / "node_modules" / "paquet" / "index.js").write_text("eval('x')\n")
    (projet / "src").mkdir()
    (projet / "src" / "app.js").write_text("const x = 1;\n")

    packs = _pack(
        tmp_path,
        [_regle("app-security/injection/eval", [
            {"kind": "grep", "pattern": r"\beval\s*\(", "applies_to": ["**/*.js"]},
        ])],
    )

    res = run_audit("essai", projet, packs_dir=packs)
    assert res.files_scanned == 1
    assert res.findings == []


# --------------------------------------------------------------------------- #
# Globs : les regles ecrivent `**/*.py`, `*.py` ou un chemin — les trois doivent
# resoudre, sinon une regle correcte ne s'applique a rien, silencieusement.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("chemin", "motifs", "attendu"),
    [
        ("app.py", ["**/*.py"], True),                       # racine + prefixe **/
        ("backend/app/main.py", ["**/*.py"], True),
        ("backend/app/main.py", ["*.py"], True),             # nom de base
        ("main.ts", ["**/*.py"], False),
        (".github/workflows/ci.yml", [".github/workflows/*.yml"], True),
        ("backend/Dockerfile", ["**/Dockerfile"], True),
        ("app.py", [], True),                                # glob vide = tout fichier
    ],
)
def test_globs_des_regles_resolvent(chemin, motifs, attendu):
    assert glob_match(chemin, motifs) is attendu
