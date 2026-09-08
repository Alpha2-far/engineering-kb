"""Tests d'intégration End-to-End simulant un agent IA autonome.

Ce module teste la boucle complète de self-remediation (Context7 for Security) :
1. L'agent formule une intention technique ("session cookie", "docker compose socket", "github actions pull_request_target").
2. Il appelle `resolve_security_topic` sur le serveur FastMCP.
3. Il récupère les règles normatives via `get_security_rules` (directives DO / DON'T).
4. Il soumet son code initial vulnérable à `audit_code_snippet`.
5. Le serveur renvoie un verdict `passed=False` avec findings et conseils précis.
6. L'agent applique le correctif recommandé.
7. Le serveur ré-audite le code et confirme `passed=True` avec 0 violations.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from kb.server import (
    audit_code_snippet,
    get_security_rules,
    mcp,
    resolve_security_topic,
)


# --------------------------------------------------------------------------- #
# 1. Scénario Cookie SameSite (FastAPI / Auth)
# --------------------------------------------------------------------------- #


def test_agent_cookie_samesite_remediation_loop():
    """Scénario E2E : Remédiation automatique d'un cookie sans attribut SameSite."""
    # Étape 1 : Résolution du sujet de sécurité
    topic_res = resolve_security_topic("FastAPI cookie session SameSite")
    assert topic_res["matched_topic"] is True
    assert "authentication/session-management/cookie-missing-samesite-attribute" in topic_res["rule_ids"]

    # Étape 2 : Récupération des directives DO / DON'T
    rules_res = get_security_rules(rule_ids=["authentication/session-management/cookie-missing-samesite-attribute"])
    assert rules_res["rules_count"] == 1
    rule_card = rules_res["markdown"]
    assert "DO" in rule_card
    assert "DON'T" in rule_card
    assert "SameSite" in rule_card

    # Étape 3 : Code initial vulnérable généré par l'agent (SameSite=none sans Secure)
    vulnerable_code = """
from fastapi import FastAPI, Response

app = FastAPI()

@app.post("/session")
def create_session(response: Response):
    # Mauvaise pratique : SameSite=none sans Secure=True
    response.set_cookie(key="session_token", value="xyz123", httponly=True, samesite="none")
    return {"status": "ok"}
"""
    # Étape 4 : Audit par le serveur MCP
    verdict_fail = audit_code_snippet(code=vulnerable_code, filename="app/session.py")
    assert verdict_fail["clean"] is False
    assert verdict_fail["findings_count"] >= 1
    found_rule_ids = [f["rule_id"] for f in verdict_fail["findings"]]
    assert "authentication/session-management/cookie-missing-samesite-attribute" in found_rule_ids

    # Étape 5 : L'agent applique la remédiation en ajoutant samesite="lax" et secure=True
    remediated_code = """
from fastapi import FastAPI, Response

app = FastAPI()

@app.post("/session")
def create_session(response: Response):
    # Protégé avec SameSite lax et Secure
    response.set_cookie(key="session_token", value="xyz123", httponly=True, secure=True, samesite="lax")
    return {"status": "ok"}
"""
    # Étape 6 : Deuxième audit après remédiation
    verdict_success = audit_code_snippet(code=remediated_code, filename="app/session.py")
    assert verdict_success["clean"] is True
    assert verdict_success["findings_count"] == 0


# --------------------------------------------------------------------------- #
# 2. Scénario Docker Socket (DevOps / Conteneurs)
# --------------------------------------------------------------------------- #


def test_agent_docker_socket_remediation_loop():
    """Scénario E2E : Remédiation du montage dangereux de /var/run/docker.sock."""
    # Étape 1 : Résolution
    topic_res = resolve_security_topic("docker compose socket root")
    assert topic_res["matched_topic"] is True
    assert "devops/containers/docker-socket-mounted-in-container" in topic_res["rule_ids"]

    # Étape 2 : Instructions
    rules_res = get_security_rules(rule_ids=["devops/containers/docker-socket-mounted-in-container"])
    assert "docker.sock" in rules_res["markdown"]

    # Étape 3 : Fichier docker-compose vulnérable
    vulnerable_compose = """
version: '3.8'
services:
  app:
    image: myorg/app:1.0.0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""
    verdict_fail = audit_code_snippet(code=vulnerable_compose, filename="docker-compose.yml")
    assert verdict_fail["clean"] is False
    assert any(f["rule_id"] == "devops/containers/docker-socket-mounted-in-container" for f in verdict_fail["findings"])

    # Étape 4 : Fichier docker-compose corrigé
    remediated_compose = """
version: '3.8'
services:
  app:
    image: myorg/app:1.0.0
    volumes:
      - app_storage:/data
volumes:
  app_storage:
"""
    verdict_success = audit_code_snippet(code=remediated_compose, filename="docker-compose.yml")
    assert verdict_success["clean"] is True
    assert verdict_success["findings_count"] == 0


# --------------------------------------------------------------------------- #
# 3. Scénario CI/CD GitHub Actions (pull_request_target)
# --------------------------------------------------------------------------- #


def test_agent_github_actions_pull_request_target_loop():
    """Scénario E2E : Remédiation du déclencheur vulnérable pull_request_target."""
    # Étape 1 : Résolution
    topic_res = resolve_security_topic("github actions pull_request_target checkout")
    assert topic_res["matched_topic"] is True
    assert "devops/github-actions/pull-request-target-untrusted-checkout" in topic_res["rule_ids"]

    # Étape 2 : Workflow CI vulnérable
    vulnerable_ci = """
name: CI
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
"""
    verdict_fail = audit_code_snippet(code=vulnerable_ci, filename=".github/workflows/ci.yml")
    assert verdict_fail["clean"] is False
    assert any(f["rule_id"] == "devops/github-actions/pull-request-target-untrusted-checkout" for f in verdict_fail["findings"])

    # Étape 3 : Workflow CI entièrement durci et conforme aux règles KB
    remediated_ci = """
name: CI
on: pull_request
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - run: npm test
"""
    verdict_success = audit_code_snippet(code=remediated_ci, filename=".github/workflows/ci.yml")
    assert verdict_success["clean"] is True
    assert verdict_success["findings_count"] == 0


# --------------------------------------------------------------------------- #
# 4. Scénario RAG Multi-Tenant (Pre-filtrage vs Post-filtrage)
# --------------------------------------------------------------------------- #


def test_agent_rag_pre_filter_remediation_loop():
    """Scénario E2E : Remédiation d'un filtrage post-recuperation sur recherche vectorielle."""
    # Étape 1 : Résolution
    topic_res = resolve_security_topic("rag vector search tenant isolation")
    assert topic_res["matched_topic"] is True
    assert "ai-ml/rag/vector-search-post-retrieval-filtering-leak" in topic_res["rule_ids"]

    # Étape 2 : Code vulnérable (post-filtrage sur similarity_search)
    vulnerable_rag = """
def search_knowledge(query: str, tenant_id: str):
    raw_chunks = vector_store.similarity_search(query, k=10) ; user_chunks = [chunk for doc in raw_chunks if doc.metadata.get("tenant_id") == tenant_id]
    return user_chunks
"""
    verdict_fail = audit_code_snippet(code=vulnerable_rag, filename="services/rag.py")
    assert verdict_fail["clean"] is False
    assert any(f["rule_id"] == "ai-ml/rag/vector-search-post-retrieval-filtering-leak" for f in verdict_fail["findings"])

    # Étape 3 : Code sain (remédiation de la règle de post-filtrage)
    remediated_rag = """
def search_knowledge(query: str, tenant_id: str):
    user_chunks = vector_store.similarity_search(
        query,
        k=10,
        filter={"tenant_id": tenant_id},
    )
    return user_chunks
"""
    verdict_remediated = audit_code_snippet(code=remediated_rag, filename="services/rag.py")
    leak_findings = [f for f in verdict_remediated["findings"] if f["rule_id"] == "ai-ml/rag/vector-search-post-retrieval-filtering-leak"]
    assert len(leak_findings) == 0

    # Étape 4 : Architecture propre de service (100% clean, 0 findings)
    clean_rag = """
def search_knowledge(query: str, tenant_id: str):
    return tenant_vector_service.query_tenant_chunks(query=query, tenant_id=tenant_id, limit=10)
"""
    verdict_clean = audit_code_snippet(code=clean_rag, filename="services/rag.py")
    assert verdict_clean["clean"] is True
    assert verdict_clean["findings_count"] == 0


# --------------------------------------------------------------------------- #
# 5. FastMCP Protocol Client Simulation (mcp.call_tool)
# --------------------------------------------------------------------------- #


def test_agent_fastmcp_call_tool_protocol():
    """Vérifie que l'agent peut appeler le serveur MCP via son interface standard call_tool."""
    # 1. Résolution de topic via call_tool
    res_topic = asyncio.run(
        mcp.call_tool("resolve_security_topic", {"query": "jwt authentication fastapi"})
    )
    assert res_topic.structured_content is not None
    assert res_topic.structured_content["matched_topic"] is True

    # 2. Audit de code via call_tool
    test_code = 'response.set_cookie("token", "val", secure=True)'
    res_audit = asyncio.run(
        mcp.call_tool("audit_code_snippet", {"code": test_code, "filename": "auth.py"})
    )
    assert res_audit.structured_content is not None
    assert res_audit.structured_content["clean"] is False
    assert res_audit.structured_content["findings_count"] >= 1
