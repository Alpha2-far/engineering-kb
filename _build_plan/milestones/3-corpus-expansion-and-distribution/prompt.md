# Milestone 3 — Expansion du Corpus & Packaging Zéro-Config

You are entering plan mode to plan and then build milestone 3 of this project.

## Context

- Read `@_build_plan/prd.md` for the full project context, scope, data model, and tech stack.
- Read previous milestone folders (`@_build_plan/milestones/1-foundations-and-semantic-search/milestone-log.md`, `@_build_plan/milestones/2-mcp-server-and-code-audit/milestone-log.md`) to understand what has already been built.

## Your task

1. Plan the implementation for **only** milestone 3 as defined in the PRD. Do not plan or build anything from later milestones.
2. After the user confirms the plan, build only what is in milestone 3's scope:
   - Targeted expansion of security rules addressing common LLM coding vulnerabilities (modern auth, RAG tenant isolation, SQL/ORM injection, Docker non-root, CI security).
   - Strict Grounding Judge validation on all new rules (100% verified citations, 0 rejections).
   - Pre-configured setup snippets for major AI coding tools: Claude Desktop, Cursor, Claude Code, and Antigravity.
   - Packaging finalization in `pyproject.toml` supporting one-line execution via `uvx kb mcp`.
   - End-to-end integration test validating a real agent interacting with the MCP server.
3. Verify your work against the "Done when" criteria for milestone 3 in the PRD:
   - Server runs seamlessly via `uvx kb mcp`.
   - All rules pass `uv run kb validate` and compile to packs.
   - All tests pass in local and GitHub Actions CI.
4. When complete, write a `milestone-log.md` in this folder (`_build_plan/milestones/3-corpus-expansion-and-distribution/milestone-log.md`). Structure it as follows:
   - **Start with a `## What's new in the app` section at the very top.** This is a concise, human-readable, bulleted list of the main user-facing features or functionality added in this milestone.
   - Then include the implementation detail sections below:
     - What was built (rules added, packages configured, setup docs created, etc.)
     - Any decisions made during implementation that weren't pre-specified in the PRD
     - Anything future contributors will need to know
     - Any deviations from the PRD and why

Ask me any clarifying questions using AskUserQuestion tool to lock in the implementation plan for this milestone.
