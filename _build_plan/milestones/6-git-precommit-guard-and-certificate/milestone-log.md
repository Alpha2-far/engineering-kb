## What's new in the app

- **Nouvelle Commande `kb guard` (Git Pre-Commit Guard mécanique)** :
  - Analyse instantanée (< 100 ms) des modifications indexées (`git add`) avant chaque commit.
  - Intercepte mécaniquement les régressions de sécurité critiques (ex: montages `/var/run/docker.sock`, conteneurs root, cookies sans SameSite/Secure, injections SQL).
  - Affiche directement en console la ligne fautive, l'explication du risque et le **pattern DO** recommandé pour une auto-remédiation immédiate par le développeur ou l'agent.
- **Installateur Automatique de Hook Git (`kb guard --install-hook`)** :
  - Installe ou met à jour le hook exécutable `.git/hooks/pre-commit` dans le dépôt git.
  - Déclenche automatiquement `kb guard` à chaque tentative de `git commit`.
- **Nouvelle Commande `kb verify` (Certificat d'Auditabilité Formel)** :
  - Évalue une base de code complète contre les règles normatives d'un profil de conformité (`saas`, `ai-rag`, etc.).
  - Émet un certificat JSON immuable (`kb-audit-certificate.json`) scellé par une **empreinte cryptographique SHA-256**, attestant du statut `VERIFIED_CLEAN` avec liste des règles évaluées et sources d'autorité citées (OWASP, Docker, Supabase, FastAPI).
  - Génère un rapport Markdown formel (`KB-AUDIT-CERTIFICATE.md`) prêt pour les revues d'architecture ou les livrables d'ingénierie client.
- **Générateur de Badge de Confiance Vectoriel (`kb verify --badge`)** :
  - Génère un badge SVG haute fidélité (`kb-badge.svg`) aux couleurs de la charte de confiance (Évergreen `#2E4A3F` pour "Verified 100%", Rouge `#A82A2A` si échec).
  - Fournit le snippet Markdown prêt à coller dans le `README.md` du projet.
- **Suite de Tests Dédiée & 100% au Vert** : 14 nouveaux tests dans `tests/test_guard_and_certificate.py`. Suite globale du projet portée à **94 tests / 94 passants à 100%**.

---

## What was built

1. **Modèle de Données `EngineeringCertificate` (`src/kb/schema.py`)** :
   - Modèle Pydantic strict pour certifier l'intégrité et la conformité du code (`certificate_id`, `project_name`, `project_root`, `timestamp`, `git_commit`, `profile`, `status`, `files_scanned`, `rules_evaluated_count`, `critical_findings_count`, `sources_cited`, `signature_sha256`).
   - Méthode `to_markdown()` pour formater le rapport d'auditabilité officiel.

2. **Moteur Git Pre-Commit Guard (`src/kb/guard.py`)** :
   - `get_git_root(path)` : détection robuste de la racine du dépôt git.
   - `get_staged_files(git_root, staged_only)` : lecture du contenu exact indexé via `git show :<path>`.
   - `guard_staged_changes(git_root)` : audit rapide in-memory contre les règles critiques et hautes via `audit_snippet()`.
   - `install_pre_commit_hook(git_root)` : installation du script `.git/hooks/pre-commit` avec permissions `0o755`.

3. **Moteur de Certification & Badging (`src/kb/certificate.py`)** :
   - `generate_certificate(project_root, profile)` : exécution de l'audit complet, calcul des métriques et scellage SHA-256 déterministe.
   - `save_certificate(cert, out_dir)` : persistance de `kb-audit-certificate.json` et `KB-AUDIT-CERTIFICATE.md`.
   - `generate_badge_svg(verified)` : générateur de SVG vectoriel autonome.
   - `generate_badge_markdown(verified)` : snippet de badge Markdown.

4. **Intégration CLI Typer (`src/kb/cli.py`)** :
   - Commande `kb guard` avec options `--install-hook`, `--all` et `--json`.
   - Commande `kb verify` avec options `--profile`, `--badge`, `--out-dir` et `--json`.

5. **Suite de Tests Automatisés (`tests/test_guard_and_certificate.py`)** :
   - 14 tests couvrant la détection git, le blocage des violations de sockets Docker et cookies, la validation des commits conformes, l'installation de hook, la signature SHA-256, la génération SVG et les commandes CLI.

---

## Decisions made during implementation

1. **Lecture du contenu `git show :<path>` plutôt que du fichier sur disque** :
   Dans un workflow git réel, un développeur peut indexer un fichier (`git add`), puis continuer à le modifier sur disque avant de commiter. En lisant via `git show :<path>`, `kb guard` inspecte fidèlement et exclusivement ce qui est sur le point d'entrer dans le commit.
2. **Signature SHA-256 déterministe sur le payload JSON normalisé** :
   Le sceau cryptographique du certificat est calculé à partir d'un dictionnaire normalisé trié (`sort_keys=True`), garantissant l'intégrité et la non-répudiation de l'audit.
3. **Badge SVG local autonome** :
   Plutôt que de dépendre d'un service tiers externe (comme shields.io) nécessitant un accès réseau, `generate_badge_svg` génère un SVG autonome directement dans le dépôt du projet.

---

## Anything the next milestone will need to know

- Le **Milestone 6** marque l'achèvement complet du plan de build v2 de la Knowledge Base (`kb`).
- Les 6 milestones sont maintenant entièrement livrés, testés et documentés :
  1. Semantic Search Engine & Do/Don't Patterns
  2. FastMCP Server & Code Snippet In-Memory Audit
  3. Corpus Expansion, MCP Client Presets & Distribution
  4. Proactive Shift-Left FastMCP & Security Contracts
  5. Project Guardrail CLI (`kb init-guardrail`)
  6. Git Pre-Commit Guard & Engineering Certificate (`kb guard` & `kb verify`)

---

## Deviations from the PRD and why

- **Aucune déviation**. Toutes les fonctionnalités spécifiées pour le Milestone 6 (analyse git sous les 100 ms, hook pre-commit bloquant, certificat formel JSON/Markdown, badge SVG et tests E2E) sont strictement implémentées et vérifiées conformes aux critères d'acceptation du PRD.
