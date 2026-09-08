"""Tests des Contrats de Sécurité Normatifs et du serveur FastMCP Proactif (Milestone 4).

Vérifie que :
1. Le modèle SecurityContract valide les invariants, la checklist et génère un Markdown propre.
2. Les 4 contrats intégrés (fastapi-supabase-rag, nextjs-auth, docker-compose, github-actions-ci)
   sont complets et cohérents avec les règles de la KB.
3. La fonction get_contract résout fidèlement par stack_id, mot-clé ou alias.
4. L'outil FastMCP get_security_contract est bien enregistré et répond aux requêtes.
5. L'interface mcp.call_tool fonctionne pour get_security_contract.
6. La commande CLI 'kb contract' supporte l'affichage, le listing et le format JSON.
"""

from __future__ import annotations

import asyncio
import json
import re

import pytest
from typer.testing import CliRunner

from kb.cli import app
from kb.contracts import BUILTIN_CONTRACTS, get_contract, list_contracts
from kb.schema import SecurityContract
from kb.server import get_security_contract, mcp

runner = CliRunner()


def _strip_ansi(text: str) -> str:
    """Supprime les codes d'échappement ANSI pour des assertions robustes."""
    return re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)


# --------------------------------------------------------------------------- #
# 1. Modèle SecurityContract
# --------------------------------------------------------------------------- #


def test_security_contract_model_and_markdown():
    """Valide l'instanciation du modèle et la génération du rendu Markdown."""
    c = SecurityContract(
        stack_id="test-stack",
        name="Test Stack",
        description="Stack de test pour validation.",
        invariants=["Invariant 1", "Invariant 2"],
        pre_coding_checklist=["Point A", "Point B"],
        do_patterns=[{"title": "Exemple 1", "lang": "python", "code": "x = 1"}],
        rule_ids=["test/rule/sample"],
    )
    assert c.stack_id == "test-stack"
    assert len(c.invariants) == 2

    md = c.to_markdown()
    assert "# Contrat de Sécurité Normatif : Test Stack (`test-stack`)" in md
    assert "## 🔒 Invariants Absolus" in md
    assert "- **Invariant 1**" in md
    assert "## ✅ Checklist Pré-Codage" in md
    assert "- [ ] Point A" in md
    assert "## 💡 Patterns Sécurisés de Référence (DO)" in md
    assert "### Exemple 1" in md
    assert "```python\nx = 1\n```" in md
    assert "## 📜 Règles Normatives Associées" in md
    assert "- `test/rule/sample`" in md


# --------------------------------------------------------------------------- #
# 2. Contrats Intégrés & Résolution
# --------------------------------------------------------------------------- #


def test_builtin_contracts_list():
    """Vérifie la présence et la complétude des 4 contrats normatifs pré-intégrés."""
    contracts = list_contracts()
    assert len(contracts) >= 4
    stack_ids = [c.stack_id for c in contracts]
    assert "fastapi-supabase-rag" in stack_ids
    assert "nextjs-auth" in stack_ids
    assert "docker-compose" in stack_ids
    assert "github-actions-ci" in stack_ids

    for c in contracts:
        assert len(c.invariants) >= 3
        assert len(c.pre_coding_checklist) >= 3
        assert len(c.do_patterns) >= 1
        assert len(c.rule_ids) >= 1


def test_get_contract_resolution_exact_and_aliases():
    """Résolution exacte et par alias sémantiques usuels."""
    # Exact
    c1 = get_contract("fastapi-supabase-rag")
    assert c1 is not None
    assert c1.stack_id == "fastapi-supabase-rag"

    # Alias / Mots-clés
    assert get_contract("supabase") == c1
    assert get_contract("rag") == c1
    assert get_contract("docker") is not None
    assert get_contract("docker").stack_id == "docker-compose"
    assert get_contract("next") is not None
    assert get_contract("next").stack_id == "nextjs-auth"
    assert get_contract("ci") is not None
    assert get_contract("ci").stack_id == "github-actions-ci"


def test_get_contract_not_found():
    """Recherche d'une stack inexistante renvoie None."""
    assert get_contract("unknown-non-existent-framework-xyz") is None


# --------------------------------------------------------------------------- #
# 3. FastMCP Tool get_security_contract
# --------------------------------------------------------------------------- #


def test_mcp_tool_get_security_contract_success():
    """L'outil MCP retourne le contrat complet pour une stack valide."""
    res = get_security_contract("fastapi-supabase-rag")
    assert res["found"] is True
    assert res["stack_id"] == "fastapi-supabase-rag"
    assert "FastAPI" in res["name"]
    assert len(res["invariants"]) >= 4
    assert len(res["pre_coding_checklist"]) >= 3
    assert len(res["do_patterns"]) >= 1
    assert len(res["rule_ids"]) >= 3
    assert "Contrat de Sécurité Normatif" in res["markdown"]


def test_mcp_tool_get_security_contract_not_found():
    """L'outil MCP gère gracieusement les stacks inconnues."""
    res = get_security_contract("unknown-stack")
    assert res["found"] is False
    assert res["stack_id"] is None
    assert "Contrat non trouvé" in res["name"]
    assert len(res["invariants"]) == 0
    assert "Stacks disponibles" in res["markdown"]


def test_mcp_call_tool_protocol_contract():
    """L'outil peut être invoqué via l'interface standard mcp.call_tool."""
    res = asyncio.run(
        mcp.call_tool("get_security_contract", {"stack": "docker-compose"})
    )
    assert res.structured_content is not None
    assert res.structured_content["found"] is True
    assert res.structured_content["stack_id"] == "docker-compose"


# --------------------------------------------------------------------------- #
# 4. Commande CLI kb contract
# --------------------------------------------------------------------------- #


def test_cli_contract_list():
    """kb contract --list affiche un tableau avec les contrats disponibles."""
    result = runner.invoke(app, ["contract", "--list"])
    assert result.exit_code == 0
    clean_out = _strip_ansi(result.stdout)
    assert "fastapi-supabase-rag" in clean_out
    assert "nextjs-auth" in clean_out
    assert "docker-compose" in clean_out
    assert "github-actions-ci" in clean_out


def test_cli_contract_detail():
    """kb contract <stack> affiche le Markdown formaté de la stack."""
    result = runner.invoke(app, ["contract", "fastapi-supabase-rag"])
    assert result.exit_code == 0
    clean_out = _strip_ansi(result.stdout)
    assert "Contrat de Sécurité Normatif" in clean_out
    assert "Invariants Absolus" in clean_out
    assert "Checklist Pré-Codage" in clean_out


def test_cli_contract_json():
    """kb contract <stack> --json fournit un objet JSON parsable."""
    result = runner.invoke(app, ["contract", "docker-compose", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["stack_id"] == "docker-compose"
    assert len(data["invariants"]) > 0


def test_cli_contract_unknown():
    """kb contract <inconnu> échoue avec un code de sortie non-zéro."""
    result = runner.invoke(app, ["contract", "inconnu-xyz"])
    assert result.exit_code != 0
    clean_out = _strip_ansi(result.stdout)
    assert "Erreur" in clean_out
