"""Tests du Moteur de Guardrails de Projet et de la commande CLI 'kb init-guardrail' (Milestone 5).

Vérifie que :
1. generate_guardrail_content produit un bloc délimité propre, avec ou sans contrat de stack.
2. inject_guardrail_into_file est strictement idempotent et préserve les règles existantes de l'utilisateur.
3. detect_agent_files identifie fidèlement les fichiers d'agents présents (.cursorrules, AGENTS.md, etc.).
4. check_project_guardrails audite la présence et le statut actif des balises de sécurité.
5. init_project_guardrails gère les créations par défaut, le ciblage existant et l'option force_all.
6. La commande CLI 'kb init-guardrail' supporte l'injection, l'option --stack, le flag --check,
   le mode --create-all et la sortie JSON structurée.
"""

from __future__ import annotations

import json
from pathlib import Path
import re

import pytest
from typer.testing import CliRunner

from kb.cli import app
from kb.contracts import get_contract
from kb.guardrail import (
    DEFAULT_INIT_FILES,
    GUARDRAIL_END,
    GUARDRAIL_START,
    SUPPORTED_AGENT_FILES,
    check_project_guardrails,
    detect_agent_files,
    generate_guardrail_content,
    init_project_guardrails,
    inject_guardrail_into_file,
)
from kb.schema import SecurityContract

runner = CliRunner()


def _strip_ansi(text: str) -> str:
    """Supprime les codes d'échappement ANSI pour des assertions fiables."""
    return re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)


# --------------------------------------------------------------------------- #
# 1. Génération de Contenu de Guardrail
# --------------------------------------------------------------------------- #


def test_generate_guardrail_content_universal():
    """Vérifie la génération du bloc de sécurité universel sans contrat spécifique."""
    content = generate_guardrail_content()
    assert GUARDRAIL_START in content
    assert GUARDRAIL_END in content
    assert "Mandatory Engineering & Security Guardrails" in content
    assert "Pre-Coding Obligation" in content
    assert "Core Invariants (Universal)" in content
    assert "Post-Coding Verification & Self-Audit" in content


def test_generate_guardrail_content_with_stack_contract():
    """Vérifie l'intégration des invariants et patterns DO d'un contrat de stack."""
    contract = get_contract("fastapi-supabase-rag")
    assert contract is not None

    content = generate_guardrail_content(contract)
    assert GUARDRAIL_START in content
    assert GUARDRAIL_END in content
    assert f"Stack-Enforced Contract: {contract.name} (`{contract.stack_id}`)" in content
    assert "Invariants Absolus (Non Négociables)" in content
    # Vérifie qu'au moins un invariant du contrat FastAPI/Supabase est présent
    assert "pgvector" in content or "RLS" in content
    assert "Checklist Pré-Codage" in content
    assert "Patterns DO de Référence" in content


# --------------------------------------------------------------------------- #
# 2. Injection Idempotente et Préservation du Contenu
# --------------------------------------------------------------------------- #


def test_inject_guardrail_new_file(tmp_path: Path):
    """Vérifie la création d'un fichier neuf avec le bloc délimité."""
    target = tmp_path / "AGENTS.md"
    block = generate_guardrail_content()

    success, action = inject_guardrail_into_file(target, block)
    assert success is True
    assert action == "created"
    assert target.is_file()

    content = target.read_text(encoding="utf-8")
    assert content.startswith(GUARDRAIL_START)
    assert content.strip().endswith(GUARDRAIL_END)


def test_inject_guardrail_preserves_user_content(tmp_path: Path):
    """Vérifie que le contenu préexistant de l'utilisateur n'est jamais altéré."""
    target = tmp_path / "CLAUDE.md"
    user_header = "# Règles Développeur\n\nToujours utiliser du typage strict.\nPréférer Python 3.12."
    target.write_text(user_header, encoding="utf-8")

    block = generate_guardrail_content()
    success, action = inject_guardrail_into_file(target, block)
    assert success is True
    assert action == "injected"

    content = target.read_text(encoding="utf-8")
    assert user_header in content
    assert content.startswith(user_header)
    assert GUARDRAIL_START in content
    assert content.strip().endswith(GUARDRAIL_END)


def test_inject_guardrail_idempotency(tmp_path: Path):
    """Vérifie qu'une deuxième injection avec le même bloc ne modifie rien (unchanged)."""
    target = tmp_path / ".cursorrules"
    target.write_text("prefix rules\n", encoding="utf-8")
    block = generate_guardrail_content()

    _, action1 = inject_guardrail_into_file(target, block)
    assert action1 == "injected"

    content_after_first = target.read_text(encoding="utf-8")

    # Seconde injection
    success2, action2 = inject_guardrail_into_file(target, block)
    assert success2 is True
    assert action2 == "unchanged"

    content_after_second = target.read_text(encoding="utf-8")
    assert content_after_first == content_after_second


def test_inject_guardrail_update_preserves_surrounding_code(tmp_path: Path):
    """Vérifie que le remplacement d'un bloc existant conserve le texte avant ET après."""
    target = tmp_path / "AGENTS.md"
    before_text = "# Instructions Personnelles\n- Règle 1\n"
    after_text = "\n# Instructions Postérieures\n- Règle 2\n"

    old_block = generate_guardrail_content()
    target.write_text(before_text + old_block + after_text, encoding="utf-8")

    # Nouveau bloc avec contrat
    contract = get_contract("docker-compose")
    new_block = generate_guardrail_content(contract)

    success, action = inject_guardrail_into_file(target, new_block)
    assert success is True
    assert action == "updated"

    updated_content = target.read_text(encoding="utf-8")
    assert before_text in updated_content
    assert after_text in updated_content
    assert "docker-compose" in updated_content
    assert updated_content.count(GUARDRAIL_START) == 1
    assert updated_content.count(GUARDRAIL_END) == 1


# --------------------------------------------------------------------------- #
# 3. Détection et Audit des Fichiers du Projet
# --------------------------------------------------------------------------- #


def test_detect_agent_files(tmp_path: Path):
    """Vérifie la détection exhaustive des fichiers d'agents supportés."""
    assert detect_agent_files(tmp_path) == []

    (tmp_path / ".cursorrules").write_text("rule", encoding="utf-8")
    (tmp_path / "CLAUDE.md").write_text("rule", encoding="utf-8")

    detected = detect_agent_files(tmp_path)
    rel_names = [p.name for p in detected]
    assert len(detected) == 2
    assert ".cursorrules" in rel_names
    assert "CLAUDE.md" in rel_names


def test_check_project_guardrails_scenarios(tmp_path: Path):
    """Vérifie les 3 états d'audit : no_agent_files, missing, active."""
    # 1. Aucun fichier
    rep1 = check_project_guardrails(tmp_path)
    assert rep1["status"] == "no_agent_files"
    assert rep1["total_files"] == 0

    # 2. Fichier présent mais sans guardrail
    f = tmp_path / "AGENTS.md"
    f.write_text("# Unprotected config", encoding="utf-8")

    rep2 = check_project_guardrails(tmp_path)
    assert rep2["status"] == "missing"
    assert rep2["active_files"] == 0
    assert rep2["missing_files"] == 1
    assert rep2["files"]["AGENTS.md"]["is_active"] is False

    # 3. Injection du guardrail -> actif
    block = generate_guardrail_content(get_contract("github-actions-ci"))
    inject_guardrail_into_file(f, block)

    rep3 = check_project_guardrails(tmp_path)
    assert rep3["status"] == "active"
    assert rep3["active_files"] == 1
    assert rep3["missing_files"] == 0
    assert rep3["files"]["AGENTS.md"]["is_active"] is True
    assert rep3["files"]["AGENTS.md"]["stack_id"] == "github-actions-ci"


# --------------------------------------------------------------------------- #
# 4. Fonction init_project_guardrails
# --------------------------------------------------------------------------- #


def test_init_project_guardrails_default_files(tmp_path: Path):
    """Si aucun fichier n'existe, init initialise les fichiers par défaut (AGENTS.md, CLAUDE.md)."""
    res = init_project_guardrails(tmp_path)
    assert len(res["targets"]) == 2
    assert "AGENTS.md" in res["targets"]
    assert "CLAUDE.md" in res["targets"]
    assert res["results"]["AGENTS.md"] == "created"
    assert res["results"]["CLAUDE.md"] == "created"


def test_init_project_guardrails_force_all(tmp_path: Path):
    """Avec force_all, tous les fichiers supportés sont créés/équipés."""
    res = init_project_guardrails(tmp_path, force_all=True)
    assert len(res["targets"]) == len(SUPPORTED_AGENT_FILES)
    for f in SUPPORTED_AGENT_FILES:
        assert f in res["targets"]
        assert (tmp_path / f).is_file()


def test_init_project_guardrails_invalid_stack(tmp_path: Path):
    """Une stack invalide lève une ValueError explicite."""
    with pytest.raises(ValueError, match="Contrat introuvable"):
        init_project_guardrails(tmp_path, stack_id="stack-inexistante-123")


# --------------------------------------------------------------------------- #
# 5. Tests de la Commande CLI (kb init-guardrail)
# --------------------------------------------------------------------------- #


def test_cli_init_guardrail_basic(tmp_path: Path):
    """Test de la commande CLI de base créant les guardrails dans un dossier."""
    result = runner.invoke(app, ["init-guardrail", str(tmp_path)])
    assert result.exit_code == 0
    output = _strip_ansi(result.output)
    assert "KB Shift-Left Guardrail configuré avec succès" in output
    assert "AGENTS.md" in output
    assert "CLAUDE.md" in output


def test_cli_init_guardrail_with_stack(tmp_path: Path):
    """Test de la commande CLI avec injection d'un contrat de stack."""
    result = runner.invoke(app, ["init-guardrail", str(tmp_path), "--stack", "fastapi-supabase-rag"])
    assert result.exit_code == 0
    output = _strip_ansi(result.output)
    assert "FastAPI + Supabase RAG Stack" in output

    agents_file = tmp_path / "AGENTS.md"
    assert agents_file.is_file()
    content = agents_file.read_text(encoding="utf-8")
    assert "fastapi-supabase-rag" in content
    assert GUARDRAIL_START in content
    assert GUARDRAIL_END in content


def test_cli_init_guardrail_check_mode(tmp_path: Path):
    """Test de l'option --check : échoue si absent, réussit si présent."""
    # Dossier vide -> code 1
    res1 = runner.invoke(app, ["init-guardrail", str(tmp_path), "--check"])
    assert res1.exit_code == 1
    assert "Aucun fichier d'instructions d'agent" in _strip_ansi(res1.output)

    # Initialisation des guardrails
    runner.invoke(app, ["init-guardrail", str(tmp_path)])

    # Dossier équipé -> code 0
    res2 = runner.invoke(app, ["init-guardrail", str(tmp_path), "--check"])
    assert res2.exit_code == 0
    assert "Guardrails conformes et actifs" in _strip_ansi(res2.output)


def test_cli_init_guardrail_check_missing_block(tmp_path: Path):
    """Test de l'option --check lorsqu'un fichier d'agent existe mais sans balises."""
    (tmp_path / ".cursorrules").write_text("# Custom rules only", encoding="utf-8")
    res = runner.invoke(app, ["init-guardrail", str(tmp_path), "--check"])
    assert res.exit_code == 1
    assert "Guardrail manquant ou incomplet" in _strip_ansi(res.output)


def test_cli_init_guardrail_json_output(tmp_path: Path):
    """Test du flag --json en mode init et en mode check."""
    # 1. Mode init --json
    res_init = runner.invoke(app, ["init-guardrail", str(tmp_path), "--stack", "docker-compose", "--json"])
    assert res_init.exit_code == 0
    data = json.loads(res_init.output)
    assert data["contract"]["stack_id"] == "docker-compose"
    assert "AGENTS.md" in data["results"]

    # 2. Mode check --json
    res_check = runner.invoke(app, ["init-guardrail", str(tmp_path), "--check", "--json"])
    assert res_check.exit_code == 0
    check_data = json.loads(res_check.output)
    assert check_data["status"] == "active"
    assert check_data["active_files"] >= 1


def test_cli_init_guardrail_invalid_stack_fails(tmp_path: Path):
    """Test qu'une stack inconnue retourne une erreur propre et code 1."""
    res = runner.invoke(app, ["init-guardrail", str(tmp_path), "--stack", "unknown-stack-xyz"])
    assert res.exit_code == 1
    assert "Contrat introuvable" in _strip_ansi(res.output)
