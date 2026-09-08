# Milestone 1 — Fondations Schéma, Do/Don't Patterns & Recherche Sémantique

You are entering plan mode to plan and then build milestone 1 of this project.

## Context

- Read `@_build_plan/prd.md` for the full project context, scope, data model, and tech stack.
- Read previous milestone folders if any exist to understand what has already been built. For milestone 1, there is no prior milestone to read.

## Your task

1. Plan the implementation for **only** milestone 1 as defined in the PRD. Do not plan or build anything from later milestones.
2. After the user confirms the plan, build only what is in milestone 1's scope:
   - Extension of Pydantic Rule schema with `do_pattern`, `dont_pattern`, and `frameworks`/`tags`.
   - Update of key priority security rules with concrete Do / Don't snippets.
   - Local-first in-memory semantic search engine (`search.py`) with ranking and token-efficient formatting.
   - Interactive CLI command `kb search <query>` with Rich colored output.
   - Comprehensive unit tests covering schema compliance, pattern availability, and search ranking.
3. Verify your work against the "Done when" criteria for milestone 1 in the PRD:
   - `uv run kb search "JWT auth FastAPI"` renders matching rules and formatted Do/Don't snippets in console.
   - `uv run pytest -v` passes with 100% green tests.
4. When complete, write a `milestone-log.md` in this folder (`_build_plan/milestones/1-foundations-and-semantic-search/milestone-log.md`). Structure it as follows:
   - **Start with a `## What's new in the app` section at the very top.** This is a concise, human-readable, bulleted list of the main user-facing features or functionality added in this milestone.
   - Then include the implementation detail sections below:
     - What was built (files created, models added, commands added, etc.)
     - Any decisions made during implementation that weren't pre-specified in the PRD
     - Anything the next milestone will need to know
     - Any deviations from the PRD and why

Ask me any clarifying questions using AskUserQuestion tool to lock in the implementation plan for this milestone.
