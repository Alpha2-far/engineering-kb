## What's new in the app

- **Serveur MCP Natif pour Agents IA (`kb mcp`)** : Un serveur FastMCP complet communicant sur le protocole standard Model Context Protocol (transport `stdio`), permettant à Claude Code, Cursor, Antigravity et Codex d'interroger la base de règles normatives en direct pendant la génération de code.
- **Résolution Sémantique d'Intentions (`resolve_security_topic`)** : Outil MCP mappant instantanément une intention technique ou un framework (ex: *"JWT auth FastAPI"*, *"Docker root"*, *"Supabase vector search tenant"*) vers le topic de sécurité structuré et la liste ordonnée des identifiants de règles prioritaires.
- **Distribution de Cartes de Sécurité avec DO & DON'T (`get_security_rules`)** : Outil MCP fournissant des fiches compactes (~1 000 tokens) prêtes à l'emploi contenant le piège fréquent généré par les LLMs (❌ **DON'T**), le code sécurisé recommandé (✅ **DO**), l'impact technique et la citation officielle ancrée.
- **Audit de Code en Mémoire à la Volée (`audit_code_snippet`)** : Outil MCP exécutant un scan statique mécanique ultra-rapide (< 10 ms, sans écriture disque) sur un extrait de code produit par l'agent pour détecter les failles (`grep` et `absent`, ex: argument/command injection, Dockerfile tournant en root) et renvoyer un verdict structuré (`AuditVerdict`) avec ligne exacte et snippet de remédiation.
- **Suite de Tests Complète** : 14 nouveaux tests unitaires validant l'enregistrement des outils FastMCP, la résolution d'intentions, la précision des diagnostics d'audit et la CLI. Total de la suite du projet : **47 tests / 47 passants à 100%**.

---

## What was built

1. **Serveur FastMCP (`src/kb/server.py` & alias `src/kb/mcp.py`)** :
   - Initialisation de l'instance `FastMCP("KB Security Context Server")`.
   - Implémentation des 3 outils MCP majeurs :
     - `resolve_security_topic(query: str) -> dict`
     - `get_security_rules(topic: str, max_rules: int = 5) -> dict`
     - `audit_code_snippet(code: str, filename: str) -> dict`
   - Point d'entrée `run_server(transport: str = "stdio")`.
   - Export universel via `src/kb/mcp.py`.

2. **Modèles de Données & Diagnostics (`src/kb/schema.py`)** :
   - Modèle `SnippetFinding` : détail d'une infraction détectée en mémoire (ID de règle, sévérité, catégorie, ligne 1-indexée, extrait/note, rationale, remédiation, pattern DO et citation officielle).
   - Modèle `AuditVerdict` : contrat de retour structuré (statut booléen `clean`, nom de fichier, nombre de règles vérifiées, nombre d'infractions, liste des `SnippetFinding`, synthèse textuelle).

3. **Moteur d'Audit de Snippets en Mémoire (`src/kb/audit.py`)** :
   - Fonction pure `audit_snippet(code: str, filename: str, rules: Sequence[Rule] | None = None) -> AuditVerdict`.
   - Évaluation ciblée selon les globs `applies_to` de chaque règle (`glob_match`).
   - Analyse ligne par ligne pour `grep` et globale multiligne pour `absent` (`re.MULTILINE`).
   - Tri des infractions par sévérité décroissante (`critical` -> `high` -> `medium`).

4. **Commande CLI `kb mcp` (`src/kb/cli.py`)** :
   - Nouvelle commande Typer démarrant le serveur MCP en console (`uv run kb mcp`).
   - Options `--transport / -t` (par défaut `stdio`).

5. **Suite de Tests Automatisés (`tests/test_mcp.py`)** :
   - 14 tests unitaires couvrant :
     - Enregistrement effectif des 3 outils sur le serveur FastMCP.
     - Résolution de topics prédéfinis et d'intentions en langage naturel.
     - Gestion gracieuse des requêtes vides.
     - Extraction des fiches de sécurité compactes avec DO et DON'T.
     - Détection d'injection de commande shell (`subprocess.run(shell=True)`).
     - Détection d'argument injection avec suggestion du délimiteur `--`.
     - Détection de l'absence de directive `USER` dans un Dockerfile.
     - Validation de conformité pour Dockerfile avec utilisateur non-root.
     - Validation sans faux positif pour code sain et fichiers hors périmètre (`README.md`).
     - Exécution sans erreur de `kb mcp --help`.

---

## Decisions made during implementation

1. **Sérialisation JSON stricte des Enums (`mode="json"`)** :
   Pour garantir une interopérabilité parfaite avec tous les clients MCP (Claude Code, Cursor, Antigravity) sans dépendance aux types Python côté client, `audit_code_snippet` sérialise les Enums Pydantic (`Severity`, `Category`) en chaînes de caractères primitives (`"critical"`, `"devops"`).
2. **Support simultané de `server.py` et `mcp.py`** :
   Le serveur principal est implémenté dans `src/kb/server.py` conformément aux conventions du playbook Farel, et `src/kb/mcp.py` ré-exporte l'ensemble des symboles afin de satisfaire les deux chemins cités dans le PRD et le prompt.
3. **Pinnage Python 3.12 et FastMCP** :
   Conformément aux directives de `references/playbook-stack.md`, le projet s'exécute sous Python 3.12 avec `.python-version`, assurant la disponibilité immédiate de wheels précompilées sans compilation Rust locale sur macOS x86_64.

---

## Notes for Milestone 3

- Le serveur FastMCP est prêt pour le packaging universel zéro-config (`uvx kb mcp`).
- Le Jalon 3 ajoutera de nouveaux packs de règles (authentification moderne, validation d'API, sécurité RAG/vecteurs, durcissement CI/CD) et les fichiers de configuration prêts à l'emploi (`claude_desktop_config.json`, `cursor/mcp.json`).

---

## Deviations from PRD

Aucune déviation. Les 3 outils MCP, le transport stdio, l'audit en mémoire, la commande CLI et les critères de validation sont 100 % conformes aux spécifications.
