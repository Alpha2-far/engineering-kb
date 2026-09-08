"""Moteur de recherche sémantique et de distribution de règles pour agents IA.

Permet à un agent de code (Claude Code, Cursor, Codex, Antigravity) de trouver
les règles de sécurité prioritaires et leurs patterns concrets Do/Don't à partir
d'une intention technique ("JWT auth FastAPI", "vector search Supabase", "docker root").
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

import yaml

from .registry import RULES_DIR
from .schema import Category, Rule, SecurityTopic, Severity


# --------------------------------------------------------------------------- #
# Index des Topics Prédéfinis
# --------------------------------------------------------------------------- #

DEFAULT_TOPICS: list[SecurityTopic] = [
    SecurityTopic(
        slug="fastapi-jwt-auth",
        title="Authentification JWT & Sessions FastAPI / Python",
        keywords=["jwt", "auth", "token", "fastapi", "bearer", "session", "oauth", "password", "argon2", "bcrypt"],
        frameworks=["fastapi", "python", "pydantic"],
        rule_ids=[
            "authentication/password-storage/weak-hashing-algorithm",
            "authentication/session-management/session-token-in-url",
            "app-security/command-injection/user-input-concatenated-into-shell",
        ],
        description="Bonnes pratiques d'authentification par jeton, hachage robuste et validation stricte.",
    ),
    SecurityTopic(
        slug="rag-vector-search",
        title="Sécurité des Systèmes RAG & Bases Vectorielles",
        keywords=["rag", "vector", "embedding", "pgvector", "supabase", "tenant", "isolation", "llm", "prompt"],
        frameworks=["supabase", "fastapi", "python", "postgresql"],
        rule_ids=[
            "ai-ml/rag/vector-search-without-tenant-filter",
            "ai-ml/prompt-injection/direct-context-concatenation",
            "ai-ml/output-handling/raw-llm-output-executed",
        ],
        description="Isolation stricte multi-tenant sur les recherches vectorielles et sanitization des flux IA.",
    ),
    SecurityTopic(
        slug="docker-container-security",
        title="Durcissement des Conteneurs Docker & Images",
        keywords=["docker", "container", "dockerfile", "root", "user", "uid", "alpine"],
        frameworks=["docker", "devops"],
        rule_ids=[
            "devops/containers/container-runs-as-root",
        ],
        description="Exécution de conteneurs sous utilisateur non-privilégié et minimisation de surface d'attaque.",
    ),
    SecurityTopic(
        slug="github-actions-ci",
        title="Sécurité des Pipelines CI/CD & GitHub Actions",
        keywords=["github", "actions", "ci", "workflow", "sha", "pinned", "permissions", "token"],
        frameworks=["devops", "github-actions"],
        rule_ids=[
            "devops/github-actions/action-not-pinned-to-commit-sha",
            "devops/github-actions/workflow-permissions-not-restricted",
            "devops/github-actions/context-interpolated-into-run-block",
        ],
        description="Épinglage strict des actions par SHA immuable et réduction des privilèges GITHUB_TOKEN.",
    ),
    SecurityTopic(
        slug="secrets-management",
        title="Gestion des Secrets & Variables d'Environnement",
        keywords=["secret", "token", "api_key", "password", "env", "hardcoded", "credential", "leak"],
        frameworks=["python", "javascript", "typescript", "devops"],
        rule_ids=[
            "devops/secrets/secret-hardcoded-in-source",
        ],
        description="Interdiction formelle des identifiants et tokens en clair dans le code source.",
    ),
    SecurityTopic(
        slug="command-injection",
        title="Protection contre l'Injection de Commandes Shell",
        keywords=["shell", "command", "injection", "subprocess", "exec", "system", "popen", "cli"],
        frameworks=["python", "javascript", "typescript", "cli"],
        rule_ids=[
            "app-security/command-injection/user-input-concatenated-into-shell",
        ],
        description="Séparation systématique des exécutables et de leurs arguments sans passer par un interpréteur shell.",
    ),
]


# --------------------------------------------------------------------------- #
# Moteur d'indexation & Recherche
# --------------------------------------------------------------------------- #

TOKEN_RE = re.compile(r"[a-z0-9_-]{2,}")


def _tokenize(text: str) -> list[str]:
    return TOKEN_RE.findall(text.lower())


@dataclass
class SearchResult:
    rule: Rule
    score: float
    matched_terms: list[str] = field(default_factory=list)
    topic: SecurityTopic | None = None

    def to_agent_card(self) -> dict:
        card = self.rule.to_agent_card()
        card["relevance_score"] = round(self.score, 2)
        card["matched_terms"] = self.matched_terms
        if self.topic:
            card["topic"] = self.topic.title
        return card


class SecuritySearchEngine:
    """Index en mémoire des règles de sécurité pour agents IA."""

    def __init__(self, rules: Sequence[Rule] | None = None, topics: Sequence[SecurityTopic] | None = None) -> None:
        self.rules: list[Rule] = list(rules) if rules is not None else self._load_rules()
        self.topics: list[SecurityTopic] = list(topics) if topics is not None else DEFAULT_TOPICS
        self.rule_by_id: dict[str, Rule] = {r.id: r for r in self.rules}

    @classmethod
    def _load_rules(cls, rules_dir: Path | None = None) -> list[Rule]:
        rd = rules_dir or RULES_DIR
        loaded: list[Rule] = []
        for path in sorted(rd.glob("*.yaml")):
            if path.name.startswith("_"):
                continue
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except Exception:
                continue
            entries = data.get("rules", data if isinstance(data, list) else [])
            for item in entries:
                if not isinstance(item, dict):
                    continue
                try:
                    loaded.append(Rule.model_validate(item))
                except Exception:
                    continue
        return loaded

    def search(
        self,
        query: str,
        *,
        limit: int = 5,
        framework: str | None = None,
        category: Category | str | None = None,
    ) -> list[SearchResult]:
        """Recherche sémantique pondérée par intentions, technologies et sévérité."""
        query_tokens = set(_tokenize(query))
        if not query_tokens:
            return []

        cat_val = category.value if isinstance(category, Category) else category

        # Détection de topic
        matched_topic: SecurityTopic | None = None
        for t in self.topics:
            topic_tokens = set(_tokenize(f"{t.slug} {t.title} {' '.join(t.keywords)}"))
            if query_tokens & topic_tokens:
                matched_topic = t
                break

        results: list[SearchResult] = []

        for rule in self.rules:
            if cat_val and rule.category.value != cat_val:
                continue

            score = 0.0
            matches: set[str] = set()

            id_tokens = set(_tokenize(f"{rule.id} {rule.title} {rule.subcategory}"))
            fw_tokens = set(_tokenize(" ".join(rule.all_frameworks + rule.tags)))
            desc_tokens = set(_tokenize(f"{rule.description} {rule.rationale} {rule.remediation}"))

            # 1. Matching sur ID, titre et sous-catégorie (poids très fort)
            id_hits = query_tokens & id_tokens
            if id_hits:
                score += len(id_hits) * 5.0
                matches.update(id_hits)

            # 2. Matching sur frameworks & tags (poids fort)
            fw_hits = query_tokens & fw_tokens
            if fw_hits:
                score += len(fw_hits) * 4.0
                matches.update(fw_hits)

            # 3. Matching sur description et rationale
            desc_hits = query_tokens & desc_tokens
            if desc_hits:
                score += len(desc_hits) * 1.5
                matches.update(desc_hits)

            # 4. Appartenance à un topic reconnu
            if matched_topic and rule.id in matched_topic.rule_ids:
                score += 6.0
                matches.add(f"topic:{matched_topic.slug}")

            # 5. Filtre framework optionnel
            if framework:
                req_fw = framework.lower().strip()
                if any(req_fw in fw.lower() for fw in rule.all_frameworks):
                    score += 4.0
                    matches.add(f"framework:{req_fw}")

            if score <= 0.0:
                continue

            # 6. Multiplicateur de sévérité (les failles critiques passent devant)
            if rule.severity == Severity.CRITICAL:
                score *= 1.4
            elif rule.severity == Severity.HIGH:
                score *= 1.2
            elif rule.severity == Severity.MEDIUM:
                score *= 1.0

            results.append(SearchResult(rule=rule, score=score, matched_terms=sorted(matches), topic=matched_topic))

        results.sort(key=lambda r: r.score, reverse=True)
        return results[:limit]


# Instance singleton par défaut pour les appels rapides
_DEFAULT_ENGINE: SecuritySearchEngine | None = None


def get_search_engine() -> SecuritySearchEngine:
    global _DEFAULT_ENGINE
    if _DEFAULT_ENGINE is None:
        _DEFAULT_ENGINE = SecuritySearchEngine()
    return _DEFAULT_ENGINE


def search_rules(
    query: str,
    *,
    limit: int = 5,
    framework: str | None = None,
    category: Category | str | None = None,
) -> list[SearchResult]:
    """Point d'entrée standard de recherche pour la CLI et le serveur MCP."""
    engine = get_search_engine()
    return engine.search(query, limit=limit, framework=framework, category=category)


def format_for_agent(results: Sequence[SearchResult]) -> str:
    """Produit un bloc Markdown condensé et prêt pour injection dans le contexte d'un agent."""
    if not results:
        return "Aucune règle de sécurité spécifique trouvée pour cette requête."

    lines: list[str] = ["# Directives de Sécurité Applicables (Grounded Standards)\n"]
    for res in results:
        r = res.rule
        sev = r.severity.value.upper()
        lines.append(f"## [{sev}] {r.title} (`{r.id}`)")
        lines.append(f"- **Catégorie** : `{r.category.value}` | **Frameworks** : {', '.join(r.all_frameworks) or 'universel'}")
        lines.append(f"- **Impact si ignoré** : {r.rationale.strip()}")

        if r.effective_dont_pattern:
            lang = r.vulnerable_example.lang if r.vulnerable_example else "python"
            lines.append(f"\n❌ **DON'T (Piège fréquent LLM) :**\n```{lang}\n{r.effective_dont_pattern.strip()}\n```")

        if r.effective_do_pattern:
            lang = r.fixed_example.lang if r.fixed_example else "python"
            lines.append(f"\n✅ **DO (Pattern sécurisé recommandé) :**\n```{lang}\n{r.effective_do_pattern.strip()}\n```")

        if r.evidence:
            ev = r.evidence[0]
            lines.append(f"- **Norme officielle** : *« {ev.quote.strip()} »* (source: `{ev.source_id}`)")
        lines.append("\n---\n")

    return "\n".join(lines)
