"""Serveur MCP Natif de la Knowledge Base de Sécurité (FastMCP).

Fournit un serveur de contexte de sécurité temps-réel (Context7 for Security)
pour agents de code (Claude Code, Cursor, Codex, Antigravity).
"""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from .audit import audit_snippet
from .contracts import get_contract, list_contracts
from .schema import SecurityContract, SecurityTopic
from .search import SearchResult, format_for_agent, get_search_engine

# Initialisation du serveur FastMCP
mcp = FastMCP(
    "KB Security Context Server",
)


@mcp.tool(
    name="resolve_security_topic",
    description=(
        "SHIFT-LEFT OBLIGATOIRE : À appeler AVANT de concevoir ou d'écrire du code. "
        "Mappe une intention technique naturelle ou un sujet (ex. 'JWT auth FastAPI', "
        "'Supabase vector search', 'Dockerfile root') vers le topic de sécurité associé "
        "et renvoie les identifiants de règles normatives prioritaires à respecter."
    ),
)
def resolve_security_topic(query: str) -> dict[str, Any]:
    """Résout une intention d'agent vers un topic structuré et la liste ordonnée des règles clés."""
    engine = get_search_engine()
    query_clean = query.strip()
    if not query_clean:
        return {
            "query": query,
            "matched_topic": False,
            "topic": None,
            "title": "Requête vide",
            "description": "Veuillez fournir une intention technique ou un framework.",
            "frameworks": [],
            "rule_ids": [],
            "rules_summary": [],
        }

    # Recherche sémantique
    results = engine.search(query_clean, limit=5)

    # 1. Vérification si un topic prédéfini correspond directement
    matched_topic: SecurityTopic | None = None
    for res in results:
        if res.topic:
            matched_topic = res.topic
            break

    if not matched_topic:
        from .search import _tokenize

        tokens = set(_tokenize(query_clean))
        for t in engine.topics:
            t_tokens = set(_tokenize(f"{t.slug} {t.title} {' '.join(t.keywords)}"))
            if tokens & t_tokens:
                matched_topic = t
                break

    if matched_topic:
        rules_in_topic = [engine.rule_by_id[rid] for rid in matched_topic.rule_ids if rid in engine.rule_by_id]
        return {
            "query": query,
            "matched_topic": True,
            "topic": matched_topic.slug,
            "title": matched_topic.title,
            "description": matched_topic.description,
            "frameworks": matched_topic.frameworks,
            "rule_ids": matched_topic.rule_ids,
            "rules_summary": [
                {
                    "id": r.id,
                    "title": r.title,
                    "severity": r.severity.value,
                    "category": r.category.value,
                }
                for r in rules_in_topic
            ],
        }

    # Si aucun topic fixe n'a matché mais qu'on a des règles trouvées via search
    if results:
        rule_ids = [res.rule.id for res in results]
        return {
            "query": query,
            "matched_topic": False,
            "topic": f"custom-{results[0].rule.category.value}",
            "title": f"Sécurité : {results[0].rule.category.value}",
            "description": f"Règles prioritaires résolues pour l'intention '{query_clean}'.",
            "frameworks": sorted({fw for res in results for fw in res.rule.all_frameworks}),
            "rule_ids": rule_ids,
            "rules_summary": [
                {
                    "id": res.rule.id,
                    "title": res.rule.title,
                    "severity": res.rule.severity.value,
                    "category": res.rule.category.value,
                }
                for res in results
            ],
        }

    return {
        "query": query,
        "matched_topic": False,
        "topic": None,
        "title": "Aucun topic correspondant",
        "description": f"Aucune règle spécifique identifiée pour '{query_clean}'.",
        "frameworks": [],
        "rule_ids": [],
        "rules_summary": [],
    }


@mcp.tool(
    name="get_security_rules",
    description=(
        "PRÉ-CODAGE OBLIGATOIRE : À appeler AVANT d'implémenter du code pour charger les directives "
        "de sécurité officielles et les patterns concrets Do / Don't. Évite les pièges fréquents "
        "générés par les LLMs (SameSite manquant, root Docker, injection shell, fuite RAG)."
    ),
)
def get_security_rules(
    topic: str = "",
    rule_ids: list[str] | None = None,
    max_rules: int = 5,
) -> dict[str, Any]:
    """Injecte les fiches de règles enrichies avec code vulnérable (Don't) et code sécurisé (Do)."""
    engine = get_search_engine()
    topic_clean = topic.strip()
    rules_to_return = []
    search_results: list[SearchResult] = []

    if rule_ids:
        for rid in rule_ids[:max_rules]:
            if rid in engine.rule_by_id:
                rule = engine.rule_by_id[rid]
                rules_to_return.append(rule)
                search_results.append(SearchResult(rule=rule, score=10.0))
    elif topic_clean:
        # 1. Est-ce un slug de topic exact ?
        matched_topic = next((t for t in engine.topics if t.slug == topic_clean), None)
        if matched_topic:
            for rid in matched_topic.rule_ids[:max_rules]:
                if rid in engine.rule_by_id:
                    rule = engine.rule_by_id[rid]
                    rules_to_return.append(rule)
                    search_results.append(SearchResult(rule=rule, score=10.0, topic=matched_topic))
        else:
            # Recherche par mot-clé / intention
            search_results = engine.search(topic_clean, limit=max_rules)
            rules_to_return = [res.rule for res in search_results]
    else:
        return {
            "topic": topic,
            "count": 0,
            "rules_count": 0,
            "rules": [],
            "markdown": "Aucune règle demandée (requête vide).",
        }

    markdown = format_for_agent(search_results)
    cards = [r.to_agent_card() for r in rules_to_return]

    return {
        "topic": topic,
        "count": len(cards),
        "rules_count": len(cards),
        "rules": cards,
        "markdown": markdown,
    }


@mcp.tool(
    name="get_security_contract",
    description=(
        "CONTRAT DE SÉCURITÉ SHIFT-LEFT : À appeler au démarrage d'une tâche pour obtenir "
        "le contrat normatif complet d'une stack (fastapi-supabase-rag, nextjs-auth, "
        "docker-compose, github-actions-ci) avec ses invariants absolus, sa checklist pré-codage "
        "et ses patterns DO de référence."
    ),
)
def get_security_contract(stack: str) -> dict[str, Any]:
    """Fournit le contrat de sécurité normatif complet pour guider la conception avant codage."""
    contract = get_contract(stack)
    if not contract:
        available = [c.stack_id for c in list_contracts()]
        return {
            "found": False,
            "query": stack,
            "stack_id": None,
            "name": "Contrat non trouvé",
            "description": f"Aucun contrat ne correspond à '{stack}'. Stacks disponibles : {', '.join(available)}",
            "invariants": [],
            "pre_coding_checklist": [],
            "do_patterns": [],
            "rule_ids": [],
            "markdown": f"# Contrat non trouvé pour `{stack}`\n\nStacks disponibles : {', '.join(f'`{s}`' for s in available)}",
        }

    return {
        "found": True,
        "query": stack,
        "stack_id": contract.stack_id,
        "name": contract.name,
        "description": contract.description,
        "invariants": contract.invariants,
        "pre_coding_checklist": contract.pre_coding_checklist,
        "do_patterns": contract.do_patterns,
        "rule_ids": contract.rule_ids,
        "markdown": contract.to_markdown(),
    }


@mcp.tool(
    name="audit_code_snippet",
    description=(
        "GARDE-FOU POST-CODAGE : Audite en mémoire (< 10 ms) un extrait de code généré par l'agent "
        "AVANT de le sauvegarder ou de le commiter, pour certifier l'absence de faille mécanique "
        "(grep & absent) et renvoyer la remédiation exacte si nécessaire."
    ),
)
def audit_code_snippet(code: str, filename: str) -> dict[str, Any]:
    """Analyse instantanée en mémoire d'un bloc de code généré avec contrat AuditVerdict."""
    verdict = audit_snippet(code=code, filename=filename)
    return verdict.model_dump(mode="json")



def run_server(transport: str = "stdio") -> None:
    """Démarre le serveur MCP."""
    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        raise ValueError(f"Transport non supporté : {transport}")


if __name__ == "__main__":
    run_server()
