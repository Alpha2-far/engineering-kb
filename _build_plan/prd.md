# KB Security Context Server (Context7 for Security)

> **About these build-plan files:** Everything in `_build_plan/` (this PRD and the per-milestone folders) is a **temporary documentation and guidance artifact** for the initial build-out of this codebase. These files are not functional — no code, configuration, runtime logic, tests, or deployment process should import, read, reference, or depend on anything in `_build_plan/`. Once the initial milestones are built and shipped, the entire `_build_plan/` folder is expected to be deleted from the codebase. Do not treat it as long-living documentation.

## What we're building

KB Security Context Server transforme la Knowledge Base (`kb`) en un fournisseur de contexte de sécurité temps-réel pour agents de code (Claude Code, Cursor, Codex, Antigravity, Copilot) — à l'image exacte de ce que Context7 accomplit pour la documentation de bibliothèques. Les agents d'IA générative écrivent du code fonctionnel mais négligent régulièrement les invariants de sécurité critiques (secrets en clair, injections ORM, absence d'isolation multi-tenant dans les RAGs, permissions Docker root, tokens non vérifiés).

Ce projet dote KB d'un serveur MCP natif et d'un moteur de recherche sémantique économe en tokens. À chaque étape de génération ou de modification de code, l'agent peut interroger KB pour obtenir à chaud les règles normatives officielles applicables (OWASP, NIST, RFC), des snippets concrets de code sécurisé (« Do / Don't ») et auditer instantanément le code en mémoire avant de le valider.

Le projet repose sur Python 3.12+, uv, FastMCP, Pydantic et Typer, avec une exécution 100 % locale et zéro dépendance cloud payante au runtime. La construction est articulée autour de 3 jalons progressifs.

---

### What the app does

- **Résolution sémantique à chaud** : Permet à un agent de soumettre une intention technique (ex. "JWT auth with FastAPI", "vector search Supabase", "Dockerfile setup") et d'obtenir immédiatement l'index des règles de sécurité critiques applicables.
- **Injection de règles taillées pour le contexte** : Renvoie des fiches de sécurité ultra-compactes (~1 000 tokens) contenant les obligations normatives et la justification officielle ancrée.
- **Bibliothèque de patterns Do / Don't** : Fournit pour chaque règle un exemple de code vulnérable fréquent (le piège classique des LLMs) et le code sécurisé de référence à adopter.
- **Audit de code à la volée en mémoire** : Analyse en quelques millisecondes un extrait de code soumis par un agent (`audit_code_snippet`) pour détecter mécaniquement les violations de sécurité et renvoyer la remédiation exacte.
- **Serveur MCP standardisé** : Branchement transparent via stdio dans Claude Desktop, Cursor, Claude Code et Antigravity en une seule ligne de configuration (`uvx kb mcp`).
- **Garantie d'ancrage normatif inviolable** : Chaque conseil et règle distribués à l'agent proviennent d'un document officiel vérifié mathématiquement par le Grounding Judge (seuil >= 85 %).

---

### Already provided by the existing codebase

- **Registre de 95 sources autoritaires** (`sources/registry.yaml`) couvrant OWASP, RFCs, NIST, guides éditeurs.
- **Moteur d'ancrage et de vérification** (`ground.py`, `validate.py`) garantissant 0 hallucination et 0 divergence de citation.
- **Corpus initial de 47 règles vérifiées** réparties dans 4 packs YAML (`rules/`).
- **Moteur d'audit statique CLI** (`audit.py`, `cli.py`) avec séparation tri-state (`matière`, `sans occurrence`, `hors-périmètre`).
- **Suite de tests automatisés** (`tests/`) et pipeline GitHub Actions CI opérationnel et vert.
- **Packaging uv et hatchling** (`pyproject.toml`, `uv.lock`) sous licence MIT.

---

### Out of scope (v1)

- **Plateforme SaaS / Dashboard web multi-tenant / Facturation** — L'outil est conçu comme une brique d'infrastructure pour développeurs et agents, pas une application web grand public.
- **Auto-fix aveugle en boîte noire** — L'outil informe, alerte et guide l'agent avec des snippets Do/Don't précis, mais ne réécrit pas silencieusement les fichiers sur disque.
- **Scraping web en direct pendant l'appel MCP** — Aucune requête réseau imprévisible au runtime ; seules les règles validées du registre sont servies.
- **Analyse dynamique en runtime (DAST) / Sandbox Docker** — L'analyse repose sur le repérage statique de motifs et de structures, évitant la lenteur et les risques d'une sandbox d'exécution.
- **Base vectorielle cloud payante obligatoire** — L'indexation sémantique et la recherche fonctionnent en local-first (zéro abonnement, zéro dépendance réseau).
- **Support initial d'une multitude de langages rares** — Priorité absolue aux langages piliers du développement moderne (Python, TypeScript/JavaScript, SQL, Dockerfile, YAML CI).

---

### Data model

#### Rule (Règle enrichie)
- **id** — Identifiant unique et immuable de la règle (ex. `KB-0015`).
- **title** — Intitulé impératif décrivant l'exigence de sécurité.
- **category** — Domaine technique (sécurité applicative, authentification, autorisation, IA/RAG, base de données, DevOps).
- **severity** — Niveau de gravité (`critical`, `high`, `medium`).
- **frameworks** — Liste de tags et technologies cibles (ex. `fastapi`, `supabase`, `nextjs`, `docker`, `jwt`, `pgvector`).
- **evidence** — Citations verbatim officielles, chemin du document archivé et sha256 de provenance.
- **rationale** — Explication de la conséquence technique d'un non-respect.
- **do_pattern** — Extrait de code propre, moderne et sécurisé à appliquer.
- **dont_pattern** — Extrait de code vulnérable représentatif des erreurs fréquentes d'IA.
- **detection** — Motifs regex (`grep`) et vérifications de présence obligatoire (`absent`).

#### SecurityTopic (Index de Résolution Sémantique)
- **slug** — Identifiant du sujet technique (ex. `fastapi-jwt-auth`, `rag-vector-isolation`, `docker-security`).
- **title** — Nom lisible du sujet.
- **keywords** — Liste de synonymes et termes de recherche associés employés par les agents.
- **rule_ids** — Liste ordonnée des identifiants de règles applicables, triés par sévérité décroissante.

#### AuditVerdict (Contrat de Diagnostic d'Audit)
- **clean** — Booléen indiquant si le code inspecté est exempt de violation mécanique.
- **findings** — Liste détaillée des infractions détectées (règle violée, numéro de ligne, extrait suspect, explication et code de remédiation suggéré).

---

## Milestone 1 — Fondations Schéma, Patterns Do/Don't & Recherche Sémantique

Ce jalon pose le socle de données enrichi pour les agents IA et le moteur d'appariement sémantique local.

### What gets built
- Enrichissement du schéma de données des règles pour supporter les champs `do_pattern`, `dont_pattern` et `frameworks` / `tags`.
- Mise à jour des règles existantes prioritaires avec des exemples concrets Do / Don't.
- Module de résolution sémantique en mémoire (`search.py`) permettant de mapper une requête en langage naturel d'un agent vers les règles et topics pertinents avec scoring de pertinence.
- Nouvelle commande CLI `kb search <query>` pour tester interactivement la résolution sémantique en console.
- Tests automatisés validant la conformité du schéma enrichi, la présence des patterns et la précision de recherche.

### What milestone 1 explicitly does NOT include
- Le serveur MCP interactif (objet du jalon 2).
- L'outil d'audit de snippets de code à la volée.
- Les fichiers de configuration pour les clients MCP tiers.

### Done when
- L'utilisateur peut exécuter `uv run kb search "JWT auth FastAPI"` en console et voir remonter instantanément les règles de sécurité associées avec leurs snippets Do / Don't formatés en Rich text, avec 100 % des tests unitaires au vert.

---

## Milestone 2 — Serveur MCP Natif pour Agents & Audit à la Volée

Ce jalon dote KB de son interface MCP standardisée (`FastMCP`) et de l'outil d'audit en mémoire pour les agents de codage.

### What gets built
- Serveur MCP complet (`server.py` ou `mcp.py`) utilisant le protocole officiel Model Context Protocol sur transport standard stdio.
- Implémentation des 3 outils MCP majeurs :
  1. `resolve_security_topic(query: str)` : résolution de la thématique et liste des règles clés.
  2. `get_security_rules(topic: str, max_rules: int)` : injection des fiches compactes de règles et patterns Do/Don't.
  3. `audit_code_snippet(code: str, filename: str)` : audit mécanique instantané en mémoire d'un bloc de code généré.
- Commande CLI `kb mcp` démarrant le serveur en local.
- Suite de tests unitaires dédiés simulant des appels d'outils MCP et vérifiant la structure des réponses.

### What milestone 2 explicitly does NOT include
- L'expansion massive du corpus (réservée au jalon 3).
- La documentation de distribution et les presets pour tous les clients du marché.

### Done when
- Le serveur MCP démarre via `uv run kb mcp` et répond correctement aux requêtes d'outils MCP de test (résolution de topic, lecture de règles et audit d'un code Python/Docker contenant une faille avec détection immédiate).

---

## Milestone 3 — Expansion du Corpus & Packaging Zéro-Config

Ce jalon enrichit la base sur les failles typiques des agents IA et finalise la distribution universelle de KB.

### What gets built
- Rédaction et ancrage strict de nouveaux packs de règles ciblant les angles morts majeurs des LLMs : authentification moderne (sessions/cookies/tokens), sanitization et validation d'API, sécurité RAG/vecteurs, durcissement CI/CD.
- Toutes les nouvelles règles sont validées par le Grounding Judge à 100 % d'ancrage sans exception.
- Documentation d'onboarding et fichiers de configuration copier-coller pour intégrer KB dans : Claude Desktop (`claude_desktop_config.json`), Cursor (`cursor/mcp.json`), Claude Code et Antigravity.
- Packaging final dans `pyproject.toml` permettant l'exécution en une ligne `uvx kb mcp` sans installation préalable.
- Validation end-to-end de bout en bout avec un agent IA réel branché sur le serveur MCP.

### What milestone 3 explicitly does NOT include
- Portails web ou interfaces graphiques tierces.
- Règles de sécurité non ancrées dans des sources officielles.

### Done when
- N'importe quel développeur ou agent peut ajouter KB dans sa configuration MCP via `uvx kb mcp` et obtenir des recommandations de sécurité en direct lors de la génération de code, avec tous les tests et la CI GitHub Actions au vert.
