## What's new in the app

- **Corpus Expansion & Ancrage Strict à 100% (51 règles actives)** : Ajout de 4 règles de sécurité normatives ciblant les pièges les plus fréquents du code généré par les LLMs :
  1. `authentication/session-management/cookie-missing-samesite-attribute` (OWASP Session Management) : configuration explicite de `SameSite=Lax` ou `Strict` sur les cookies d'authentification.
  2. `devops/containers/docker-socket-mounted-in-container` (OWASP Docker Security) : interdiction formelle du montage dangereux de `/var/run/docker.sock` accordant un accès root direct à l'hôte.
  3. `devops/github-actions/pull-request-target-untrusted-checkout` (OWASP GitHub Actions Security) : prévention des exfiltrations de secrets et de l'exécution de code arbitraire via le trigger privilégié `pull_request_target`.
  4. `ai-ml/rag/vector-search-post-retrieval-filtering-leak` (OWASP RAG Security) : obligation d'appliquer l'isolation multi-tenant au niveau du moteur vectoriel (pré-filtrage) et non en mémoire après extraction (post-filtrage).
- **Zéro Rejet au Grounding Judge (`uv run kb validate`)** : 100% des 51 règles de la base sont mathématiquement ancrées dans les textes officiels archivés (OWASP Cheatsheets, OWASP Top 10 LLM, standards FastAPI/Supabase). 0 rejet, 0 fausse citation.
- **Distribution Zéro-Config via `uvx` (`uvx kb mcp`)** : Finalisation du packaging wheel dans `pyproject.toml` avec inclusion embarquée des règles et packs compilés (`[tool.hatch.build.targets.wheel.force-include]`), support de fallback de localisation dans `src/kb/registry.py` et script entrypoint `kb-mcp = "kb.server:run_server"`. Les développeurs et agents peuvent démarrer le serveur MCP en 1 seule commande sans installation préalable.
- **Presets de Configuration pour les Grands Clients IA (`presets/`)** : Snippets JSON prêts à l'emploi et testés pour **Claude Desktop**, **Cursor IDE**, **Google Antigravity**, ainsi que la commande standard pour **Claude Code CLI**.
- **Suite de Tests d'Intégration End-to-End Agent (`tests/test_e2e_agent.py`)** : Simulation complète d'un agent de codage autonome validant le cycle vertueux : Requête d'intention -> Résolution de Topic -> Extraction de règles normatives -> Détection de code vulnérable -> Remédiation guidée -> Validation de conformité 100% saine (`passed=True`).
- **Suite Globale du Projet au Vert** : **52 tests sur 52 passants à 100%** sur l'ensemble de la base.

---

## What was built

1. **Corpus Expansion & Validation d'Ancrage (`rules/owasp-cheatsheets.yaml`)** :
   - Ajout des 4 règles rédigées avec précision taxonomique (CWE, OWASP, contexte, détection mécanique grep/absent, patterns vulnérables et patterns corrigés).
   - Citations textuelles exactes (score 1.0) ancrées dans les documents canoniques :
     - `Session_Management_Cheat_Sheet.md` (SHA256: `bf6d4c21...`)
     - `Docker_Security_Cheat_Sheet.md` (SHA256: `3442288c...`)
     - `GitHub_Actions_Security_Cheat_Sheet.md` (SHA256: `241c43a4...`)
     - `RAG_Security_Cheat_Sheet.md` (SHA256: `e48ca77c...`)
   - Validation via `uv run kb validate` : 51 règles soumises, 51 acceptées, 0 rejetée.
   - Compilation via `uv run kb compile` : mise à jour des 7 profils d'audit (`saas` 48 règles, `ai-rag` 43 règles, `api` 42 règles, `pipeline` 19 règles, `cli` 17 règles, `static-site` 8 règles).

2. **Distribution & Packaging (`pyproject.toml`, `src/kb/registry.py`, `src/kb/server.py`)** :
   - Script entry point additionnel `kb-mcp = "kb.server:run_server"`.
   - Configuration Hatchling `force-include` intégrant `rules/` et `packs/` dans le wheel binaire redistribuable.
   - Résolution transparente dans `registry.py` : si `KB_ROOT / "rules"` est absent (cas d'un package installé ou exécuté via `uvx`), bascule automatique sur les données embarquées du package.
   - Paramètre optionnel `rule_ids: list[str] | None = None` sur l'outil MCP `get_security_rules` pour permettre à un agent d'extraire directement un sous-ensemble ciblé de règles par leurs identifiants.

3. **Presets Clients IA (`presets/`)** :
   - `presets/claude_desktop_config.json` : configuration stdio pour Claude Desktop.
   - `presets/cursor_mcp.json` : configuration stdio pour Cursor IDE.
   - `presets/antigravity_mcp.json` : configuration stdio pour Antigravity IDE.
   - Documentation copy-paste exhaustive intégrée dans `README.md`.

4. **Suite de Tests d'Intégration E2E (`tests/test_e2e_agent.py`)** :
   - 5 tests E2E couvrant :
     - Scénario Auth/Cookie : auto-remédiation d'un cookie sans attribut SameSite vers `samesite="lax", secure=True`.
     - Scénario Docker : auto-remédiation du montage risqué `/var/run/docker.sock` vers un volume de données isolé.
     - Scénario GitHub Actions : auto-remédiation de `pull_request_target` vers `pull_request` avec permissions réduites et SHA pinned.
     - Scénario RAG : auto-remédiation du post-filtrage vers pré-filtrage natif par tenant.
     - Scénario FastMCP Protocol : validation des appels d'outils via l'interface standard `mcp.call_tool`.

---

## Decisions made during implementation

1. **Intégration des règles et packs dans le Wheel (`force-include`)** :
   Pour que `uvx kb mcp` fonctionne de manière autonome sur n'importe quel poste sans exiger de cloner le dépôt git ni de télécharger l'archive au préalable, les règles YAML et les packs JSON sont directement embarqués dans le bundle binaire Python via `hatchling.build`.
2. **Support de `rule_ids` direct dans `get_security_rules`** :
   L'outil `resolve_security_topic` retourne une liste ordonnée d'identifiants (`rule_ids`). Permettre à `get_security_rules` de recevoir soit un `topic`, soit des `rule_ids` supprime une étape de friction pour les agents IA et accélère la self-remediation.
3. **Pondération sémantique de sévérité et stabilité des tests** :
   La règle critique de montage Docker Socket (`devops/containers/docker-socket-mounted-in-container`) bénéficie d'un multiplicateur de sévérité critique (1.4x) supérieur à la règle medium d'utilisateur non-root. Les tests de recherche ont été ajustés pour vérifier la présence qualifiée des deux règles dans le top des résultats sans dépendance fragile sur le rang 0 absolu.

---

## Verification & Validation

- `uv run kb validate` : 51/51 règles acceptées, 0 rejet (100% grounded).
- `uv run kb compile` : 51 règles compilées dans 7 profils.
- `uv run pytest -v` : 52 tests unitaires et d'intégration validés avec succès en 12s.
- `uv build --wheel` : Wheel `dist/kb-0.1.0-py3-none-any.whl` générée avec l'ensemble des règles et packs embarqués.
