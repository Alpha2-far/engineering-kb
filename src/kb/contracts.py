"""Contrats de Sécurité Normatifs par Stack Technologique (Shift-Left Engineering).

Fournit des ensembles d'invariants absolus, de checklists pré-codage et de patterns DO
à injecter dans le contexte des agents IA AVANT l'écriture de code afin d'éradiquer
le vibe coding et d'assurer une conception sécurisée dès le départ.
"""

from __future__ import annotations

from typing import Sequence

from .schema import SecurityContract

BUILTIN_CONTRACTS: list[SecurityContract] = [
    SecurityContract(
        stack_id="fastapi-supabase-rag",
        name="FastAPI + Supabase RAG Stack",
        description="Standards normatifs pour les backends IA / RAG manipulant des embeddings multi-tenant, tokens d'authentification et base PostgreSQL/pgvector.",
        invariants=[
            "Row Level Security (RLS) obligatoire sur toute table stockant des embeddings ou données client.",
            "Pré-filtrage par tenant impératif dans les requêtes de similarité vectorielle (aucun post-filtrage en mémoire Python).",
            "Cookies de session configurés avec SameSite=Lax ou Strict, Secure=True et HttpOnly=True.",
            "Mots de passe hachés exclusivement avec Argon2id ou Bcrypt (interdiction formelle de SHA/MD5).",
            "Séparation des entrées utilisateurs et des commandes système (interdiction de shell=True).",
        ],
        pre_coding_checklist=[
            "Ai-je vérifié que le tenant_id de l'utilisateur authentifié est injecté dans le filtre de recherche vectorielle ?",
            "Ai-je exclu toute possibilité pour le client de spécifier un tenant_id arbitraire sans validation par JWT ?",
            "Les cookies générés portent-ils tous samesite='lax' (ou 'strict') et secure=True ?",
            "Les prompts du LLM traitent-ils les chunks récupérés comme des données non fiables (balisage XML explicite) ?",
        ],
        do_patterns=[
            {
                "title": "Pré-filtrage multi-tenant dans la requête vectorielle",
                "lang": "python",
                "code": (
                    "# Pre-filtrage dans la requête vectorielle avant calcul de similarité\n"
                    "chunks = vector_store.similarity_search(\n"
                    "    query,\n"
                    "    k=8,\n"
                    "    filter={\"tenant_id\": current_user.tenant_id},\n"
                    ")"
                ),
            },
            {
                "title": "Configuration sécurisée des cookies de session",
                "lang": "python",
                "code": (
                    "response.set_cookie(\n"
                    "    key=\"session_token\",\n"
                    "    value=token,\n"
                    "    httponly=True,\n"
                    "    secure=True,\n"
                    "    samesite=\"lax\",\n"
                    ")"
                ),
            },
        ],
        rule_ids=[
            "ai-ml/rag/vector-search-without-tenant-filter",
            "ai-ml/rag/vector-search-post-retrieval-filtering-leak",
            "authentication/session-management/cookie-missing-samesite-attribute",
            "authentication/password-storage/weak-hashing-algorithm",
            "app-security/command-injection/user-input-concatenated-into-shell",
        ],
    ),
    SecurityContract(
        stack_id="nextjs-auth",
        name="Next.js & Modern Web Auth Stack",
        description="Standards pour applications Next.js (App Router), gestion de sessions par cookies, Server Actions et protection CSRF/XSS.",
        invariants=[
            "Aucun secret sensible ni clé d'API privée préfixé par NEXT_PUBLIC_ ou importé dans un composant 'use client'.",
            "Cookies d'authentification protégés avec SameSite=Lax/Strict, Secure=True et HttpOnly=True.",
            "Validation stricte des payloads d'entrées de Server Actions et Route Handlers via un schéma Zod.",
            "Headers de sécurité HTTP configurés (X-Content-Type-Options, X-Frame-Options, Content-Security-Policy).",
        ],
        pre_coding_checklist=[
            "Les clés privées (SUPABASE_SERVICE_ROLE_KEY, DATABASE_URL) sont-elles cantonnées aux Server Components et Route Handlers ?",
            "Les Server Actions valident-elles l'autorisation de l'utilisateur appelant avant toute mutation de données ?",
            "Tous les cookies de session sont-ils HTTP-only et SameSite ?",
        ],
        do_patterns=[
            {
                "title": "Validation d'entrée stricte dans les Server Actions",
                "lang": "typescript",
                "code": (
                    "// Validation d'entrée stricte dans les Server Actions\n"
                    "export async function updateProfile(formData: FormData) {\n"
                    "  const session = await auth();\n"
                    "  if (!session?.user) throw new Error(\"Unauthorized\");\n"
                    "  const validated = ProfileSchema.parse(Object.fromEntries(formData));\n"
                    "  await db.updateProfile(session.user.id, validated);\n"
                    "}"
                ),
            },
        ],
        rule_ids=[
            "authentication/session-management/cookie-missing-samesite-attribute",
            "devops/secrets/secret-hardcoded-in-source",
        ],
    ),
    SecurityContract(
        stack_id="docker-compose",
        name="Docker & Container Orchestration Stack",
        description="Règles de durcissement des conteneurs applicatifs et fichiers docker-compose pour éliminer l'escalade de privilèges.",
        invariants=[
            "Interdiction absolue d'exposer ou monter /var/run/docker.sock dans un conteneur applicatif.",
            "Exécution obligatoire sous un utilisateur non-privilégié (directive USER avec UID non-zéro).",
            "Système de fichiers racine monté en lecture seule (read_only: true) avec volumes temporaires restreints (tmpfs).",
            "Limitation explicite des ressources CPU et mémoire (deploy.resources.limits).",
        ],
        pre_coding_checklist=[
            "Le conteneur utilise-t-il un utilisateur applicatif dédié (ex: appuser, UID 10001) et non root ?",
            "Le socket hôte Docker (/var/run/docker.sock) est-il complètement absent des volumes montés ?",
            "Les secrets d'environnement sont-ils passés par fichiers sécurisés et non écrits en clair dans le compose ?",
        ],
        do_patterns=[
            {
                "title": "Service Docker Compose durci sans socket root",
                "lang": "yaml",
                "code": (
                    "services:\n"
                    "  app:\n"
                    "    image: myapp:1.0.0\n"
                    "    user: \"10001:10001\"\n"
                    "    read_only: true\n"
                    "    tmpfs:\n"
                    "      - /tmp:rw,noexec,nosuid\n"
                    "    volumes:\n"
                    "      - app_data:/data:rw\n"
                    "volumes:\n"
                    "  app_data:\n"
                ),
            },
        ],
        rule_ids=[
            "devops/containers/docker-socket-mounted-in-container",
            "devops/containers/container-runs-as-root",
        ],
    ),
    SecurityContract(
        stack_id="github-actions-ci",
        name="GitHub Actions CI/CD Security Stack",
        description="Standards de sécurisation de la chaîne de livraison logicielle et des workflows GitHub Actions.",
        invariants=[
            "Déclaration explicite de permissions: {} vides par défaut au niveau du workflow (principe du moindre privilège).",
            "Épinglage obligatoire de chaque action tierce à un SHA de commit immuable à 40 caractères.",
            "Interdiction absolue de faire un checkout ou d'exécuter du code provenant de forks sous le déclencheur pull_request_target.",
            "Pas d'interpolation directe de variables contextuelles (ex: github.event.*) dans les blocs run.",
        ],
        pre_coding_checklist=[
            "Le workflow déclare-t-il permissions: {} au sommet du fichier ?",
            "Toutes les actions tierces sont-elles épinglées par SHA avec le tag de version en commentaire ?",
            "Le workflow utilise-t-il on: pull_request pour tester le code non approuvé des contributeurs ?",
        ],
        do_patterns=[
            {
                "title": "Workflow CI durci avec permissions réduites et SHA pinning",
                "lang": "yaml",
                "code": (
                    "name: CI\n"
                    "on: pull_request\n"
                    "permissions: {}\n"
                    "jobs:\n"
                    "  test:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    permissions:\n"
                    "      contents: read\n"
                    "    steps:\n"
                    "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n"
                    "      - run: npm test\n"
                ),
            },
        ],
        rule_ids=[
            "devops/github-actions/action-not-pinned-to-commit-sha",
            "devops/github-actions/workflow-permissions-not-restricted",
            "devops/github-actions/pull-request-target-untrusted-checkout",
            "devops/github-actions/context-interpolated-into-run-block",
        ],
    ),
]


def list_contracts() -> list[SecurityContract]:
    """Retourne la liste ordonnée des contrats de sécurité normatifs intégrés."""
    return list(BUILTIN_CONTRACTS)


def get_contract(stack_id: str) -> SecurityContract | None:
    """Résout un contrat par son identifiant ou par correspondance approchée."""
    clean = stack_id.strip().lower()
    # 1. Correspondance exacte
    for c in BUILTIN_CONTRACTS:
        if c.stack_id == clean:
            return c

    # 2. Correspondance par mot-clé
    for c in BUILTIN_CONTRACTS:
        if clean in c.stack_id or clean in c.name.lower():
            return c

    # 3. Correspondances sémantiques usuelles
    aliases = {
        "fastapi": "fastapi-supabase-rag",
        "supabase": "fastapi-supabase-rag",
        "rag": "fastapi-supabase-rag",
        "next": "nextjs-auth",
        "nextjs": "nextjs-auth",
        "react": "nextjs-auth",
        "docker": "docker-compose",
        "compose": "docker-compose",
        "ci": "github-actions-ci",
        "github-actions": "github-actions-ci",
        "actions": "github-actions-ci",
    }
    if clean in aliases:
        target_id = aliases[clean]
        for c in BUILTIN_CONTRACTS:
            if c.stack_id == target_id:
                return c

    return None
