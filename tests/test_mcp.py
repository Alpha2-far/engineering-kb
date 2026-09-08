"""Tests du serveur FastMCP et de l'audit de snippets à la volée.

Vérifie que :
  1. Les 3 outils FastMCP sont bien enregistrés sur le serveur.
  2. resolve_security_topic résout les topics prédéfinis et les requêtes en langage naturel.
  3. get_security_rules fournit des fiches compactes avec directives claires DO et DON'T.
  4. audit_code_snippet détecte fidèlement en mémoire les failles mécaniques (grep et absent)
     sans faux positif sur du code sain ni sur les fichiers hors-périmètre.
  5. La commande CLI 'kb mcp --help' fonctionne correctement.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from kb.cli import app
from kb.server import (
    audit_code_snippet,
    get_security_rules,
    mcp,
    resolve_security_topic,
)

runner = CliRunner()


# --------------------------------------------------------------------------- #
# 1. Enregistrement et schéma du serveur FastMCP
# --------------------------------------------------------------------------- #


def test_mcp_server_tools_registered():
    """Le serveur FastMCP expose bien les 3 outils prévus par le PRD."""
    import asyncio

    tools = asyncio.run(mcp.list_tools())
    tool_names = [tool.name for tool in tools]
    assert "resolve_security_topic" in tool_names
    assert "get_security_rules" in tool_names
    assert "audit_code_snippet" in tool_names


# --------------------------------------------------------------------------- #
# 2. Tool 1 : resolve_security_topic
# --------------------------------------------------------------------------- #


def test_resolve_security_topic_predefined():
    """Résolution exacte d'un topic prédéfini (ex: fastapi-jwt-auth)."""
    res = resolve_security_topic("fastapi-jwt-auth")
    assert res["matched_topic"] is True
    assert res["topic"] == "fastapi-jwt-auth"
    assert len(res["rule_ids"]) > 0
    assert "jwt" in res["title"].lower() or "auth" in res["title"].lower()
    assert len(res["rules_summary"]) > 0


def test_resolve_security_topic_natural_language():
    """Résolution d'une intention en langage naturel ('docker container root')."""
    res = resolve_security_topic("docker container root")
    assert res["matched_topic"] is True
    assert res["topic"] == "docker-container-security"
    assert "devops/containers/container-runs-as-root" in res["rule_ids"]


def test_resolve_security_topic_rag_tenant():
    """Résolution pour un sujet RAG multi-tenant ('vector search Supabase tenant isolation')."""
    res = resolve_security_topic("vector search Supabase tenant isolation")
    assert res["matched_topic"] is True
    assert res["topic"] == "rag-vector-search"
    assert "ai-ml/rag/vector-search-without-tenant-filter" in res["rule_ids"]


def test_resolve_security_topic_empty():
    """Une requête vide retourne une réponse gracieuse sans lever d'exception."""
    res = resolve_security_topic("")
    assert res["matched_topic"] is False
    assert res["rule_ids"] == []
    assert res["rules_summary"] == []


# --------------------------------------------------------------------------- #
# 3. Tool 2 : get_security_rules
# --------------------------------------------------------------------------- #


def test_get_security_rules_by_topic_slug():
    """Récupération des fiches compactes via un topic slug avec patterns Do et Don't."""
    res = get_security_rules("fastapi-jwt-auth", max_rules=3)
    assert res["topic"] == "fastapi-jwt-auth"
    assert len(res["rules"]) > 0
    assert len(res["rules"]) <= 3

    first = res["rules"][0]
    assert "id" in first
    assert "title" in first
    assert "severity" in first
    assert "do_pattern" in first
    assert "dont_pattern" in first
    assert res["markdown"].startswith("# Directives de Sécurité Applicables")


def test_get_security_rules_by_query():
    """Récupération par mot-clé libre ('command injection shell')."""
    res = get_security_rules("command injection shell", max_rules=2)
    assert len(res["rules"]) > 0
    assert len(res["rules"]) <= 2
    assert any("command-injection" in r["id"] for r in res["rules"])


def test_get_security_rules_empty():
    """Un topic vide retourne 0 règle et un message clair."""
    res = get_security_rules("")
    assert res["count"] == 0
    assert res["rules"] == []


# --------------------------------------------------------------------------- #
# 4. Tool 3 : audit_code_snippet
# --------------------------------------------------------------------------- #


def test_audit_code_snippet_command_injection_detected():
    """Détecte une injection shell critique dans du code Python."""
    vulnerable_py = (
        "import subprocess\n"
        "def run_cmd(user_arg):\n"
        "    subprocess.run('echo ' + user_arg, shell=True)\n"
    )
    verdict = audit_code_snippet(code=vulnerable_py, filename="app/utils.py")
    assert verdict["clean"] is False
    assert verdict["findings_count"] >= 1

    finding = verdict["findings"][0]
    assert finding["severity"] == "critical"
    assert "command-injection" in finding["rule_id"]
    assert finding["line"] == 3
    assert "shell=True" in finding["snippet"]
    assert finding["do_pattern"] is not None
    assert "❌" in verdict["summary"]


def test_audit_code_snippet_clean_python():
    """Du code Python sécurisé ne lève aucune infraction."""
    clean_py = (
        "import subprocess\n"
        "def run_cmd(url):\n"
        "    subprocess.run(['curl', '-sS', '--', url], check=True)\n"
    )
    verdict = audit_code_snippet(code=clean_py, filename="app/utils.py")
    assert verdict["clean"] is True
    assert verdict["findings_count"] == 0
    assert len(verdict["findings"]) == 0
    assert "✅" in verdict["summary"]


def test_audit_code_snippet_dockerfile_missing_user():
    """Détecte l'absence de directive USER dans un Dockerfile (pattern absent)."""
    vulnerable_dockerfile = (
        "FROM python:3.12-slim\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        "CMD [\"python\", \"main.py\"]\n"
    )
    verdict = audit_code_snippet(code=vulnerable_dockerfile, filename="Dockerfile")
    assert verdict["clean"] is False
    assert verdict["findings_count"] >= 1

    finding = next(f for f in verdict["findings"] if "container-runs-as-root" in f["rule_id"])
    assert finding["severity"] in ("critical", "high", "medium")
    assert finding["line"] == 0  # 0 pour motif absent
    assert "USER" in finding["snippet"] or "root" in finding["snippet"].lower()


def test_audit_code_snippet_dockerfile_clean():
    """Un Dockerfile spécifiant un utilisateur non-root est déclaré conforme."""
    clean_dockerfile = (
        "FROM python:3.12-slim\n"
        "RUN useradd -u 1000 appuser\n"
        "USER appuser\n"
        "CMD [\"python\", \"main.py\"]\n"
    )
    verdict = audit_code_snippet(code=clean_dockerfile, filename="Dockerfile")
    root_findings = [f for f in verdict["findings"] if "container-runs-as-root" in f["rule_id"]]
    assert len(root_findings) == 0


def test_audit_code_snippet_out_of_scope_file():
    """Un fichier markdown ou de documentation n'active pas de détections de code applicatif."""
    doc_content = "# Documentation\nThis is a readme file mentioning shell=True in text."
    verdict = audit_code_snippet(code=doc_content, filename="README.md")
    assert verdict["clean"] is True
    assert verdict["findings_count"] == 0


# --------------------------------------------------------------------------- #
# 5. Commande CLI kb mcp
# --------------------------------------------------------------------------- #


def test_cli_mcp_help():
    """La commande 'kb mcp --help' s'exécute correctement."""
    result = runner.invoke(app, ["mcp", "--help"])
    assert result.exit_code == 0
    assert "Démarre le serveur MCP natif" in result.output
    assert "--transport" in result.output
