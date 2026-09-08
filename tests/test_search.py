"""Tests du moteur de recherche sémantique et de distribution de règles.

Vérifie que :
  1. Les intentions courantes des agents ("JWT auth", "docker root", "rag vector", "command injection")
     font remonter les règles prioritaires associées en tête de liste.
  2. Les patterns Do / Don't sont correctement extraits et formatés.
  3. Les filtres par framework et catégorie restreignent fidèlement le périmètre.
  4. L'export agent card et le markdown d'injection respectent le format token-efficient.
"""

from __future__ import annotations

import pytest

from kb.schema import Category, Rule, SecurityTopic, Severity
from kb.search import (
    DEFAULT_TOPICS,
    SearchResult,
    SecuritySearchEngine,
    format_for_agent,
    search_rules,
)


# --------------------------------------------------------------------------- #
# 1. Requêtes courantes sur le corpus réel
# --------------------------------------------------------------------------- #


def test_search_jwt_auth_fastapi():
    """Une recherche 'JWT auth FastAPI' remonte des règles d'authentification ou tokens."""
    results = search_rules("JWT auth FastAPI", limit=5)
    assert len(results) > 0

    rule_ids = [r.rule.id for r in results]
    # Doit matcher au moins une règle pertinente d'authentification ou session
    assert any("auth" in rid or "session" in rid or "password" in rid for rid in rule_ids)
    assert results[0].score > 0.0
    assert len(results[0].matched_terms) > 0


def test_search_docker_root():
    """Une recherche 'docker container root' remonte la règle container-runs-as-root."""
    results = search_rules("docker container root", limit=3)
    assert len(results) > 0
    rule_ids = [r.rule.id for r in results]
    assert "devops/containers/container-runs-as-root" in rule_ids
    container_rule = next(r.rule for r in results if r.rule.id == "devops/containers/container-runs-as-root")
    assert container_rule.severity == Severity.MEDIUM
    assert "USER" in container_rule.title or "Docker" in container_rule.title


def test_search_rag_tenant_isolation():
    """Une recherche 'rag vector tenant' remonte la règle d'isolation multi-tenant."""
    results = search_rules("rag vector tenant", limit=3)
    assert len(results) > 0
    top = results[0]
    assert top.rule.id == "ai-ml/rag/vector-search-without-tenant-filter"
    assert top.rule.severity == Severity.CRITICAL
    assert top.rule.effective_do_pattern is not None
    assert "org_id" in top.rule.effective_do_pattern.lower()


def test_search_command_injection():
    """Une recherche 'command injection shell' remonte la règle critique de concaténation shell."""
    results = search_rules("command injection shell", limit=3)
    assert len(results) > 0
    top = results[0]
    assert top.rule.id == "app-security/command-injection/user-input-concatenated-into-shell"
    assert top.rule.severity == Severity.CRITICAL
    assert top.rule.effective_do_pattern is not None
    assert top.rule.effective_dont_pattern is not None
    assert "shell=False" in top.rule.effective_do_pattern
    assert "shell=True" in top.rule.effective_dont_pattern


def test_search_empty_or_short_query():
    """Une requête vide ou composée de tokens < 2 caractères retourne une liste vide."""
    assert search_rules("") == []
    assert search_rules("   ") == []
    assert search_rules("a b c") == []


# --------------------------------------------------------------------------- #
# 2. Filtres par Framework & Catégorie
# --------------------------------------------------------------------------- #


def test_search_category_filter():
    """Le filtre de catégorie isole strictement les règles de la catégorie demandée."""
    results = search_rules("injection", category=Category.AI_ML, limit=10)
    assert len(results) > 0
    for r in results:
        assert r.rule.category == Category.AI_ML


def test_search_framework_filter():
    """Le filtre framework booste les règles associées."""
    results = search_rules("auth", framework="fastapi", limit=5)
    assert len(results) > 0
    # Le matched_terms du top résultat doit contenir le match framework ou token
    assert any("framework:fastapi" in r.matched_terms or "fastapi" in r.matched_terms for r in results)


# --------------------------------------------------------------------------- #
# 3. Format Agent Card & Injection Markdown
# --------------------------------------------------------------------------- #


def test_search_result_agent_card():
    """SearchResult.to_agent_card() fournit un dictionnaire complet et sérialisable."""
    results = search_rules("command injection shell", limit=1)
    assert len(results) == 1
    card = results[0].to_agent_card()

    assert card["id"] == "app-security/command-injection/user-input-concatenated-into-shell"
    assert card["severity"] == "critical"
    assert card["category"] == "app-security"
    assert "relevance_score" in card
    assert "matched_terms" in card
    assert "do_pattern" in card
    assert "dont_pattern" in card
    assert "shell=False" in card["do_pattern"]
    assert "shell=True" in card["dont_pattern"]


def test_format_for_agent_markdown():
    """format_for_agent() génère un markdown avec directives claires DO et DON'T."""
    results = search_rules("command injection shell", limit=1)
    md = format_for_agent(results)

    assert "# Directives de Sécurité Applicables" in md
    assert "app-security/command-injection/user-input-concatenated-into-shell" in md
    assert "❌ **DON'T (Piège fréquent LLM) :**" in md
    assert "✅ **DO (Pattern sécurisé recommandé) :**" in md
    assert "subprocess.run" in md
    assert "Norme officielle" in md


def test_format_for_agent_empty():
    """format_for_agent() gère gracieusement une liste de résultats vide."""
    md = format_for_agent([])
    assert "Aucune règle de sécurité spécifique trouvée" in md


# --------------------------------------------------------------------------- #
# 4. Tests Unitaires Isolés avec Moteur Personnalisé
# --------------------------------------------------------------------------- #


def test_engine_scoring_and_severity_multiplier():
    """Vérifie que la sévérité critique amplifie le score d'une règle."""
    base_rules = SecuritySearchEngine._load_rules()
    assert len(base_rules) >= 1

    rule_crit = base_rules[0].model_copy(
        update={
            "id": "devops/ci/critical-test-rule",
            "title": "Unique Keyword Target Alpha",
            "severity": Severity.CRITICAL,
        }
    )
    rule_med = base_rules[0].model_copy(
        update={
            "id": "devops/ci/medium-test-rule",
            "title": "Unique Keyword Target Beta",
            "severity": Severity.MEDIUM,
        }
    )

    engine = SecuritySearchEngine(rules=[rule_med, rule_crit], topics=[])
    res = engine.search("Unique Keyword Target", limit=2)

    assert len(res) == 2
    assert res[0].rule.id == "devops/ci/critical-test-rule"
    assert res[1].rule.id == "devops/ci/medium-test-rule"
    assert res[0].score > res[1].score

