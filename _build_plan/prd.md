# Knowledge Base (KB) — Shift-Left Engineering & Anti-Vibe-Coding System

> **About these build-plan files:** Everything in `_build_plan/` (this PRD and the per-milestone folders) is a **temporary documentation and guidance artifact** for the build-out of this codebase. These files are not functional — no code, configuration, runtime logic, tests, or deployment process should import, read, reference, or depend on anything in `_build_plan/`. Once the initial milestones are built and shipped, the entire `_build_plan/` folder is expected to be deleted from the codebase. Do not treat it as long-living documentation.

## What we're building

Transformer KB en un système d'ingénierie de sécurité proactif (*Shift-Left*) façon Context7 : forcer l'injection des standards normatifs officiels et des patterns DO/DON'T dans les agents IA **avant** l'écriture du code, éliminer le *vibe coding* par des contrats de sécurité explicites, et garantir l'auto-remédiation mécanique avant tout commit.

Le problème fondamental du *vibe coding* réside dans l'illusion de conformité : les agents IA génèrent du code qui « marche en apparence », mais qui viole silencieusement les règles de base de la sécurité industrielle (cookies sans attribut SameSite, sockets Docker montés en root, contextes de forks non approuvés dans GitHub Actions, isolation multi-tenant différée après extraction vectorielle). En intervenant en amont de la génération via FastMCP, par des contrats de sécurité explicites et un filet d'interception git pre-commit, KB transforme l'IA en un développeur guidé par des preuves normatives.

La stack repose sur Python 3.12, FastMCP (stdio), Typer/Rich pour la CLI, Pydantic/PyYAML pour la modélisation formelle, et une distribution zero-config par `uvx`.

---

### What the app does

- **Injonction Proactive Pré-Codage (Shift-Left)** : Les descriptions et métadonnées des outils FastMCP indiquent explicitement aux LLMs qu'ils doivent résoudre le sujet de sécurité et charger les patterns DO/DON'T avant de poser la première ligne de code.
- **Contrats de Sécurité Normatifs par Stack** : Fournit des fiches synthétiques (`SecurityContract`) pour les 4 stacks majeures (FastAPI/Supabase RAG, Next.js Auth, Docker Compose, GitHub Actions CI) comprenant 3 à 5 invariants absolus et une checklist pré-codage.
- **Générateur de Règles de Projet (`kb init-guardrail`)** : Une commande CLI capable d'inspecter un projet cible et d'injecter automatiquement les directives de sécurité obligatoires dans les fichiers d'instructions d'agents (`.cursorrules`, `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`).
- **Hook Git Pré-Commit Local (`kb guard`)** : Un garde-fou local instantané (< 100 ms) installé via `kb guard --install-hook` qui analyse le code stagé avant commit et bloque immédiatement l'opération si une infraction critique subsiste, en affichant la remédiation exacte.
- **Certification d'Auditabilité & Badge de Conformité (`kb verify`)** : Génère un certificat formel et un badge de conformité normatif attestant de 100% de respect des standards OWASP/RFC sans fausse affirmation de conformité.
- **Recherche Sémantique & Audit en Mémoire** : Conserve et exploite le moteur de recherche sémantique (`kb search`) et l'analyseur instantané de snippets (`audit_code_snippet`).

---

### Already provided by the existing codebase

- Moteur de recherche sémantique instantané avec scoring d'intention et amplification de sévérité (`src/kb/search.py`).
- Serveur FastMCP natif (`src/kb/server.py`) avec outils `resolve_security_topic`, `get_security_rules`, et `audit_code_snippet`.
- Validateur d'ancrage textuel strict (*Grounding Judge* à seuil >= 85%) avec 51 règles normatives vérifiées sans aucun rejet (`rules/*.yaml`).
- Compilateur de profils de sécurité par typologie de projet (`packs/profiles/*.json`).
- Packaging autonome Hatchling avec intégration embarquée des packs et règles pour exécution one-liner via `uvx kb mcp`.
- Suite de tests complète de 52 tests pytest unitaires et d'intégration validés en CI GitHub Actions.

---

### Out of scope

- **Pas de dashboard web SaaS lourd** : KB demeure un outil d'ingénierie CLI et serveur FastMCP ultra-léger et rapide (< 10 ms), sans serveur HTTP permanent ni base de données hébergée.
- **Pas d'interception réseau en runtime (WAF / proxy)** : KB opère exclusivement sur le code source et les flux d'agents, pas sur le trafic applicatif déployé.
- **Pas d'entraînement ou fine-tuning de modèle LLM** : Le système fonctionne par injection de contexte déterministe (RAG normatif fondé sur des preuves) et non par altération de poids neuronaux.
- **Pas de réécriture aveugle automatique de code sans revue** : L'ingénierie de confiance exige la validation explicite ; KB propose des patterns DO chirurgicaux mais ne modifie pas le code arbitrairement à l'aveugle.
- **Pas de multi-tenant ou facturation SaaS** : KB est conçu pour tourner en local et dans les runners CI de chaque dépôt.

---

### Data model

#### Rule (existant)
- `id` — Identifiant taxonomique unique (ex: `authentication/session-management/cookie-missing-samesite-attribute`)
- `title` — Titre clair et impératif de la règle
- `category` & `subcategory` — Domaine technique (authentication, devops, ai-ml, database, etc.)
- `severity` — Niveau de criticité (`critical`, `high`, `medium`)
- `rationale` — Risque réel et impact technique si la règle est ignorée
- `remediation` — Action précise recommandée
- `detection` — Motifs mécaniques d'analyse statique (`grep` ou `absent`)
- `vulnerable_example` & `fixed_example` — Exemples concrets DON'T et DO
- `evidence` — Citation officielle ancrée avec SHA-256 et URL canonique

#### SecurityTopic (existant)
- `slug` — Identifiant court du topic (ex: `fastapi-jwt-auth`, `docker-container-security`)
- `title` — Nom lisible du topic
- `keywords` — Termes naturels et intentions fréquentes des agents
- `frameworks` — Technologies concernées
- `rule_ids` — Liste ordonnée des règles normatives applicables

#### SecurityContract (nouveau)
- `stack_id` — Identifiant unique de la stack (ex: `fastapi-supabase-rag`, `nextjs-auth`, `docker-compose`, `github-actions-ci`)
- `name` — Nom lisible de la stack technologique
- `description` — Cadre d'application du contrat
- `invariants` — 3 à 5 règles d'or absolues et non négociables à respecter avant d'écrire du code
- `pre_coding_checklist` — Points de contrôle explicites que l'agent doit attester avant de commiter
- `do_patterns` — Extraits de code de référence prêts pour injection
- `rule_ids` — Règles normatives associées au contrat

#### GuardrailConfig (nouveau)
- `project_path` — Chemin vers le projet cible
- `detected_agents` — Fichiers d'agents repérés (`.cursorrules`, `AGENTS.md`, `CLAUDE.md`, etc.)
- `pre_commit_hook_installed` — Statut booléen de l'installation du hook git
- `strict_mode` — Si activé, bloque les commits contenant des violations critiques

---

## Milestone 4 — Proactive Shift-Left MCP & Security Contracts

Rendre le serveur FastMCP proactif en amont de l'écriture du code (façon Context7) et implémenter les Contrats de Sécurité par stack technologique.

### What gets built

- **Descriptions d'Outils MCP Révisées** : Mise à jour des descriptions de `resolve_security_topic`, `get_security_rules` et `audit_code_snippet` avec des directives impératives de pré-génération ("MUST call before generating or editing code").
- **Modèle et Outil MCP `get_security_contract`** : Nouvel outil FastMCP retournant le contrat de sécurité complet d'une stack technologique avec ses invariants et sa checklist pré-codage.
- **4 Contrats de Sécurité Normatifs Pré-intégrés** :
  1. `fastapi-supabase-rag` (RLS pgvector, pré-filtrage obligatoire de tenant, cookies SameSite, hash Argon2)
  2. `nextjs-auth` (SameSite/Secure cookies, validation zod stricte, absence de secrets client-side)
  3. `docker-compose` (utilisateur non-root explicite, interdiction absolue de `/var/run/docker.sock`, volumes nommés)
  4. `github-actions-ci` (permissions `{}` par défaut, SHA-pinning systématique, proscription de checkout sous `pull_request_target`)
- **Commande CLI `kb contract`** : Commande console pour afficher ou exporter un contrat de sécurité (`uv run kb contract fastapi-supabase-rag`).
- **Tests Unitaires & Intégration** : Validation des 4 contrats, de l'outil MCP `get_security_contract` et du rendu Markdown pour agents.

### What milestone 4 explicitly does NOT include

- Pas d'installation automatique de hooks git (Milestone 6).
- Pas de modification des fichiers d'agents des projets cibles (Milestone 5).

### Done when

Un agent appelant `get_security_contract(stack="fastapi-supabase-rag")` reçoit un contrat structuré contenant les invariants absolus et patterns DO, et la commande CLI `kb contract --list` liste l'ensemble des contrats disponibles.

---

## Milestone 5 — Project Guardrail CLI (`kb init-guardrail`)

Permettre à un développeur de configurer en 1 commande les directives de sécurité obligatoires dans n'importe quel projet de code pour asservir Cursor, Claude Code, Antigravity et GitHub Copilot.

### What gets built

- **Commande CLI `kb init-guardrail`** : Commande inspectant le projet cible (`kb init-guardrail /path/to/project`).
- **Détection Automatique des Configurations d'Agents** : Détecte la présence ou propose la création de `.cursorrules`, `AGENTS.md`, `CLAUDE.md`, et `.github/copilot-instructions.md`.
- **Injection Idempotente et Délimitée** : Injecte le bloc de consignes Shift-Left entouré de marqueurs explicites (`<!-- KB-SECURITY-GUARDRAIL-START -->` ... `<!-- KB-SECURITY-GUARDRAIL-END -->`), permettant des mises à jour sans écraser les règles existantes de l'utilisateur.
- **Option `--stack`** : Permet d'associer un contrat spécifique (ex: `--stack fastapi-supabase-rag`) pour injecter directement les invariants clés dans le prompt de l'agent.
- **Option `--check`** : Vérifie si les guardrails d'un projet sont à jour et actifs.

### What milestone 5 explicitly does NOT include

- Pas de hook git pré-commit bloquant (Milestone 6).
- Pas d'audit des fichiers du projet pendant l'initialisation du guardrail.

### Done when

L'exécution de `kb init-guardrail . --stack fastapi-supabase-rag` injecte avec succès le bloc de sécurité délimité dans les fichiers d'agents détectés sans altérer leur contenu préexistant.

---

## Milestone 6 — Git Pre-Commit Guard & Engineering Certificate (`kb guard` & `kb verify`)

Clôturer la boucle de confiance par un garde-fou git local mécanique bloquant les régressions et un certificat d'auditabilité pour les livrables d'ingénierie.

### What gets built

- **Commande CLI `kb guard`** : Analyse instantanée (< 100 ms) des fichiers modifiés ou stagés dans le git local. Déclenche une alerte bloquante si une règle critique est violée.
- **Installateur de Hook Git (`kb guard --install-hook`)** : Installe ou met à jour le fichier `.git/hooks/pre-commit` pour bloquer mécaniquement tout `git commit` non conforme avec affichage direct de la ligne fautive et du pattern DO.
- **Commande de Certification `kb verify`** : Génère un rapport d'auditabilité formel (`kb-audit-certificate.json` et Markdown) récapitulant les règles vérifiées, les sources officielles citées, et le statut 100% propre du code.
- **Générateur de Badge de Conformité** : Option `--badge` produisant un badge SVG ou Markdown pour les README de projets client (*"KB Security: Verified 100%"*).
- **Suite de Tests E2E Complète & CI** : Validation de la chaîne de self-remediation complète, tests d'exécution de `kb guard` et passage au vert de la CI GitHub Actions.

### What milestone 6 explicitly does NOT include

- Pas d'authentification utilisateur distante ni d'hébergement cloud du certificat.

### Done when

Une tentative de commit d'un fichier contenant `/var/run/docker.sock` ou un cookie sans SameSite est interceptée et bloquée par le hook `.git/hooks/pre-commit`, et `kb verify` produit un certificat JSON normatif valide après remédiation.
