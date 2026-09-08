## What's new in the app

- **Contrats de Sécurité Normatifs par Stack (`SecurityContract`)** : Introduction d'une nouvelle entité de modélisation regroupant pour chaque grande stack technologique les 3 à 5 invariants absolus, une checklist d'attestation pré-codage et les patterns de code sécurisés (DO) prêts à injecter.
- **4 Contrats Normatifs Intégrés** :
  1. `fastapi-supabase-rag` (RLS pgvector, pré-filtrage obligatoire de tenant, cookies SameSite, hachage Argon2)
  2. `nextjs-auth` (SameSite/Secure cookies, validation zod stricte, absence de secrets en Client Components)
  3. `docker-compose` (utilisateur non-root explicite, interdiction absolue de `/var/run/docker.sock`, volumes nommés)
  4. `github-actions-ci` (permissions `{}` par défaut, SHA-pinning systématique, proscription de checkout sous `pull_request_target`)
- **Nouvel Outil FastMCP Proactif (`get_security_contract`)** : Permet aux agents de code d'interroger directement le contrat de sécurité complet d'une stack dès le début d'une session de build pour conditionner la génération de code en amont.
- **Injonctions Proactives Shift-Left dans les Descriptions MCP** : Toutes les descriptions des outils FastMCP (`resolve_security_topic`, `get_security_rules`, `get_security_contract`, `audit_code_snippet`) forcent désormais les modèles LLMs à s'informer avant de concevoir ou de générer du code.
- **Nouvelle Commande CLI `kb contract`** :
  - `kb contract --list` : tableau Rich récapitulant les contrats disponibles, leurs invariants et leurs règles liées.
  - `kb contract <stack>` : affichage Markdown formaté en console du contrat complet.
  - `kb contract <stack> --json` : export JSON brut pour outillage automatisé.
- **Suite de Tests Étendue & 100% au Vert** : 11 nouveaux tests unitaires et d'intégration validant le modèle `SecurityContract`, la bibliothèque `contracts.py`, l'outil MCP et la CLI. Total de la suite du projet : **63 tests / 63 passants à 100%**.

---

## What was built

1. **Modèle de Données `SecurityContract` (`src/kb/schema.py`)** :
   - Modèle Pydantic strict (`extra="forbid"`) avec validation des champs `stack_id`, `name`, `description`, `invariants`, `pre_coding_checklist`, `do_patterns` et `rule_ids`.
   - Méthode `to_markdown()` générant un bloc Markdown structuré optimisé pour l'injection dans le contexte des agents.

2. **Bibliothèque des Contrats de Sécurité (`src/kb/contracts.py`)** :
   - Définition immuable des 4 contrats fondateurs de l'écosystème.
   - Fonctions `list_contracts()` et `get_contract(stack_id: str)` avec résolution insensible à la casse, par mot-clé et par alias sémantiques usuels (`supabase`, `docker`, `next`, `ci`, `rag`).

3. **Serveur FastMCP Proactif (`src/kb/server.py` & `src/kb/mcp.py`)** :
   - Implémentation du décorateur `@mcp.tool(name="get_security_contract")`.
   - Reformulation impérative des métadonnées des 4 outils MCP orientée Shift-Left.
   - Ré-export propre de `get_security_contract` dans `src/kb/mcp.py`.

4. **Commande CLI `kb contract` (`src/kb/cli.py`)** :
   - Nouvelle commande Typer avec support de l'affichage individuel, du listing en tableau Rich et du flag `--json`.

5. **Suite de Tests Automatisés (`tests/test_contracts.py`)** :
   - 11 tests couvrant l'instanciation, la résolution d'alias, les cas d'erreur, les appels MCP directs et asynchrones (`mcp.call_tool`), et les exécutions CLI.

---

## Decisions made during implementation

1. **Contrats codés en dur dans `contracts.py` plutôt que YAML externe** :
   Pour garantir une performance instantanée (< 1 ms), aucune dépendance d'E/S disque supplémentaire et une disponibilité immédiate dans le wheel binaire `uvx`, les 4 contrats fondamentaux sont instanciés directement dans `src/kb/contracts.py` avec le modèle Pydantic.
2. **Support des alias sémantiques usuels dans `get_contract`** :
   Les développeurs et agents utilisent souvent des raccourcis comme `docker` au lieu de `docker-compose`, ou `next` au lieu de `nextjs-auth`. La fonction `get_contract` résout intelligemment ces alias sans échouer inutilement.
3. **Descriptions MCP avec balises impératives** :
   Les modèles de langage (Claude 3.7 Sonnet, GPT-4o, Codex) répondent très fortement aux mots-clés impératifs en majuscules dans les descriptions d'outils (`SHIFT-LEFT OBLIGATOIRE`, `PRÉ-CODAGE OBLIGATOIRE`). Cette formulation modifie directement leur propension à appeler l'outil en amont sans nécessiter de fine-tuning.

---

## What the next milestone will need to know

- Le Milestone 5 (`kb init-guardrail`) s'appuiera directement sur `get_contract(stack_id)` et `list_contracts()` pour injecter les invariants spécifiques dans `.cursorrules`, `AGENTS.md` et `CLAUDE.md`.
- Les marqueurs de délimitation prévus pour l'injection dans les fichiers d'agents sont `<!-- KB-SECURITY-GUARDRAIL-START -->` et `<!-- KB-SECURITY-GUARDRAIL-END -->`.

---

## Verification & Validation

- `uv run pytest tests/test_contracts.py -v` : 11/11 tests passés.
- `uv run pytest -v` : 63/63 tests passés.
- `uv run kb validate` : 51/51 règles acceptées, 0 rejet.
- `uv run kb contract --list` : tableau Rich affiché avec succès.
- `uv run kb contract fastapi-supabase-rag` : Markdown rendu avec succès.
- `uv run kb contract docker-compose --json` : JSON valide extrait.
