# Agent Instructions — KB (Engineering Knowledge Base)

Base de connaissance d'ingénierie et moteur de distribution de règles de sécurité et d'architecture pour agents IA.

## Conventions
- **Runtime** : Python 3.12+, gestionnaire de paquets `uv`.
- **Règles inviolables** : Toute règle ajoutée dans `rules/` doit impérativement porter une citation vérifiée dans l'archive locale (`raw/`) avec un score d'ancrage >= 85 % (`uv run kb validate`).
- **Tests** : Lancer `uv run pytest -v` avant tout commit.

## `_build_plan/`

The `_build_plan/` folder contains the initial PRD and per-milestone prompts used to scaffold this codebase during its initial build-out phase. These files are **temporary** — they exist for documentation and guidance only. They are **not** functional: no code, configuration, or runtime logic in this codebase should import, reference, or depend on anything inside `_build_plan/`.

Do not treat `_build_plan/` as long-living documentation for the codebase. The codebase will evolve past the assumptions and decisions captured here. Once the initial milestones are complete, this folder is expected to be deleted.
