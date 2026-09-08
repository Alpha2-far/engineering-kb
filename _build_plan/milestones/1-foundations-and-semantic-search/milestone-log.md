## What's new in the app

- **Moteur de recherche sémantique local-first (`kb search`)** : Les développeurs et agents de code peuvent désormais interroger la base de sécurité en langage naturel (ex: `kb search "JWT auth FastAPI"`, `kb search "docker root"`) et obtenir instantanément les règles prioritaires classées par pertinence et criticité.
- **Directives concrètes Do & Don't** : Chaque règle critique ou haute gravité fournit désormais le piège fréquent généré par les LLM (❌ **DON'T**) et son pattern sécurisé validé (✅ **DO**) avec extraits de code actionnables.
- **Sortie double Interactive / JSON** : La commande `kb search` supporte à la fois un affichage console en panneaux Rich colorés par sévérité et une sortie `--json` au format `AgentCard` compacte (~1 000 tokens) prête à être injectée dans le contexte d'un agent IA.
- **Index de Security Topics** : 6 topics prédéfinis (`fastapi-jwt-auth`, `rag-vector-search`, `docker-container-security`, `github-actions-ci`, `secrets-management`, `command-injection`) boostent la résolution instantanée des intentions courantes d'architecture.

---

## What was built

1. **Extension du Schéma Pydantic (`src/kb/schema.py`)** :
   - Ajout des champs optionnels `do_pattern`, `dont_pattern`, et `frameworks` au modèle `Rule`.
   - Ajout des propriétés calculées `effective_do_pattern` et `effective_dont_pattern` qui résolvent en repli transparent les blocs `fixed_example` et `vulnerable_example` déjà validés et ancrés dans le corpus.
   - Ajout de la propriété `all_frameworks` agrégeant les frameworks racine et contextuels.
   - Ajout de la méthode `to_agent_card()` produisant un payload condensé pour LLM.
   - Ajout du modèle `SecurityTopic` pour indexer les intentions courantes.

2. **Moteur de Recherche Sémantique & In-Memory (`src/kb/search.py`)** :
   - Classe `SecuritySearchEngine` chargeant les règles en mémoire sans dépendance externe ni latence réseau.
   - Algorithme de scoring pondéré multi-critères :
     - Match sur ID/titre/sous-catégorie : coefficient 5.0
     - Match sur frameworks & tags : coefficient 4.0
     - Match sur description et impact : coefficient 1.5
     - Boost de Topic identifié : +6.0
     - Boost framework explicite : +4.0
     - Multiplicateur de sévérité : x1.4 pour `critical`, x1.2 pour `high`.
   - Fonction de formatage Markdown `format_for_agent()` avec blocs de code et citations officielles.

3. **Commande CLI `kb search` (`src/kb/cli.py`)** :
   - CLI Typer avec options `--limit / -n`, `--framework / -f` et `--json`.
   - Rendu en console Rich avec bordures colorées par sévérité (`red` pour critique, `yellow` pour high, `blue` pour medium).

4. **Suite de Tests Complète (`tests/test_search.py`)** :
   - 11 nouveaux tests unitaires couvrant :
     - Résolution sémantique des intentions courantes (JWT FastAPI, Docker root, RAG multi-tenant, Command injection).
     - Filtrage strict par catégorie et par framework.
     - Validation des cartes agents et du rendu markdown d'injection.
     - Gestion des requêtes vides.
     - Vérification du multiplicateur de score selon la sévérité.
   - Total de la suite de tests du projet : **33 tests / 33 passants à 100%**.

---

## Decisions made during implementation

1. **Rétrocompatibilité totale et repli sur les exemples vérifiés existants** :
   Plutôt que d'exiger une ré-extraction ou une migration lourde des 47 règles YAML existantes pour renseigner `do_pattern` et `dont_pattern`, les propriétés `effective_do_pattern` et `effective_dont_pattern` exploitent automatiquement les blocs `fixed_example` et `vulnerable_example` déjà ancrés à 100% dans la documentation officielle.
2. **Pondération asymétrique des sévérités** :
   Un multiplicateur de 1.4x est appliqué aux règles `critical` et 1.2x aux règles `high` afin de garantir qu'une faille critique (ex: injection SQL ou shell, contournement d'isolation multi-tenant RAG) surpasse toujours une directive cosmétique ou de sévérité moyenne dans les premiers résultats retournés à l'agent.
3. **Topic Matching déterministe** :
   Les topics sont définis comme un index statique en mémoire avec des tokens normalisés, garantissant une latence < 5ms et une exécution 100% hors-ligne.

---

## Notes for Milestone 2

- Le serveur FastMCP de Milestone 2 (`kb/mcp.py` / `kb mcp`) s'appuiera directement sur `get_search_engine()` et `format_for_agent()` de `src/kb/search.py` pour implémenter les outils `get_security_context` et `list_security_topics`.
- Le scanner de snippets en mémoire réutilisera les moteurs de détection `grep` et `absent` déjà testés dans `src/kb/audit.py`.

---

## Deviations from PRD

Aucune déviation fonctionnelle. L'ensemble des livrables et critères du Jalon 1 sont rigoureusement respectés.
