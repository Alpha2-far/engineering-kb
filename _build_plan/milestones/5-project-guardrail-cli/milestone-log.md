## What's new in the app

- **Nouvelle Commande CLI `kb init-guardrail`** : Permet à un développeur ou à un agent d'équiper n'importe quel projet de code des directives de sécurité obligatoires (*Shift-Left Engineering*) en une seule commande.
- **Détection Automatique Multi-Agents** : Détecte automatiquement les fichiers d'instructions des grands environnements de développement IA :
  - **Cursor** (`.cursorrules`)
  - **Antigravity IDE / Codex** (`AGENTS.md`)
  - **Claude Code CLI** (`CLAUDE.md`)
  - **GitHub Copilot** (`.github/copilot-instructions.md`)
- **Injection Idempotente et Délimitée** : Encadre les directives de sécurité par les balises explicites `<!-- KB-SECURITY-GUARDRAIL-START -->` et `<!-- KB-SECURITY-GUARDRAIL-END -->`. Aucune directive préexistante de l'utilisateur (conventions, styles, personas) n'est altérée ou écrasée en dehors de ce bloc.
- **Option `--stack <stack_id>`** : Associe et injecte directement les invariants normatifs, la checklist pré-codage et les patterns de référence (DO) d'une stack technologique donnée (ex: `fastapi-supabase-rag`, `docker-compose`, `nextjs-auth`, `github-actions-ci`).
- **Option d'Audit Non Destructif `--check`** : Inspecte instantanément le projet sans modifier aucun fichier pour certifier si les guardrails sont présents, actifs et conformes (code de sortie 0 si conforme, 1 si manquant).
- **Option `--create-all`** : Force la création simultanée des 4 configurations d'agents supportées pour un démarrage de projet clé en main.
- **Support JSON Structuré (`--json`)** : Permet l'intégration programmatique dans des pipelines CI ou des workflows d'orchestration multi-agents.
- **Suite de Tests Dédiée & 100% au Vert** : 17 tests unitaires et CLI dans `tests/test_guardrail_cli.py`. Suite globale du projet portée à **80 tests / 80 passants à 100%**.

---

## What was built

1. **Moteur de Guardrails de Projet (`src/kb/guardrail.py`)** :
   - Constantes de délimitation `GUARDRAIL_START` et `GUARDRAIL_END`.
   - Liste des fichiers d'agents supportés `SUPPORTED_AGENT_FILES` et cibles par défaut `DEFAULT_INIT_FILES`.
   - Fonction `generate_guardrail_content(contract)` : construit le bloc normatif Markdown avec directives pré-codage, consultation MCP obligatoire, invariants de stack et consignes d'auto-audit.
   - Fonction `inject_guardrail_into_file(file_path, block)` : insertion / remplacement délimité idempotent avec préservation intégrale du contenu avant et après.
   - Fonction `detect_agent_files(project_root)` : identification des fichiers d'agents existants.
   - Fonction `check_project_guardrails(project_root)` : audit des balises et extraction du contrat actif par fichier.
   - Fonction `init_project_guardrails(project_root, stack_id, force_all)` : orchestration de l'injection sur les fichiers détectés ou par défaut.

2. **Intégration CLI Typer (`src/kb/cli.py`)** :
   - Commande `@app.command(name="init-guardrail")` supportant `path`, `--stack`, `--check`, `--create-all`, `--json`.
   - Rendu console soigné avec panneaux et tableaux Rich détaillant les statuts d'action (`CRÉÉ`, `INJECTÉ`, `MIS À JOUR`, `INCHANGÉ`).

3. **Suite de Tests Automatisés (`tests/test_guardrail_cli.py`)** :
   - 17 tests automatisés couvrant les cas nominaux, la préservation des instructions existantes, l'idempotence stricte, les formats JSON et les erreurs de stack.

---

## Decisions made during implementation

1. **Préservation absolue du contenu utilisateur par délimiteurs HTML** :
   L'utilisation de balises de commentaires Markdown (`<!-- KB-SECURITY-GUARDRAIL-START -->` et `<!-- KB-SECURITY-GUARDRAIL-END -->`) permet aux agents de lire les directives sans polluer le rendu Markdown des viewers, tout en garantissant un ciblage chirurgical lors des mises à jour sans duplication.
2. **Cibles par défaut (`AGENTS.md` et `CLAUDE.md`) en cas d'absence de configuration existante** :
   Si un projet est vierge de tout fichier d'agent et que l'utilisateur n'a pas spécifié `--create-all`, l'outil crée `AGENTS.md` (norme Codex/Antigravity/Cursor) et `CLAUDE.md` (norme Claude Code). Cela couvre immédiatement 95% des agents utilisés au quotidien.
3. **Extraction de la stack active lors du `--check`** :
   `check_project_guardrails` analyse par regex le bloc injecté pour afficher dans le tableau de contrôle quelle stack contractuelle (`fastapi-supabase-rag`, etc.) est activement imposée à chaque agent.

---

## Anything the next milestone will need to know

- Le **Milestone 6** (`kb guard` & `kb verify`) s'appuiera sur la présence de ces guardrails pour installer le hook git `.git/hooks/pre-commit` et délivrer le certificat d'auditabilité `kb-audit-certificate.json`.
- La logique de vérification rapide (< 100 ms) pour `kb guard` s'intégrera directement avec le moteur de matching et les expressions régulières déjà rodées dans `audit.py`.

---

## Deviations from the PRD and why

- **Aucune déviation**. L'ensemble des fonctionnalités spécifiées pour le Milestone 5 (commande CLI, détection multi-agents, injection idempotente délimitée, support `--stack`, support `--check`, suite de tests) est strictement implémenté et conforme aux exigences du PRD.
