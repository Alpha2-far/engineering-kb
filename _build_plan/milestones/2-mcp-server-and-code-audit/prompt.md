# Milestone 2 — Serveur MCP Natif pour Agents & Audit à la Volée

You are entering plan mode to plan and then build milestone 2 of this project.

## Context

- Read `@_build_plan/prd.md` for the full project context, scope, data model, and tech stack.
- Read previous milestone folders (`@_build_plan/milestones/1-foundations-and-semantic-search/milestone-log.md`) to understand what has already been built.

## Your task

1. Plan the implementation for **only** milestone 2 as defined in the PRD. Do not plan or build anything from later milestones.
2. After the user confirms the plan, build only what is in milestone 2's scope:
   - FastMCP server implementation (`src/kb/server.py` or `src/kb/mcp.py`) supporting standard stdio transport.
   - MCP Tool 1: `resolve_security_topic(query: str)` mapping agent queries to topics and high-priority rule IDs.
   - MCP Tool 2: `get_security_rules(topic: str, max_rules: int)` returning compact rule cards with Do/Don't code patterns.
   - MCP Tool 3: `audit_code_snippet(code: str, filename: str)` executing fast in-memory static checks on agent-generated code.
   - CLI command `kb mcp` to start the server.
   - Unit tests simulating MCP client calls and asserting verdict accuracy.
3. Verify your work against the "Done when" criteria for milestone 2 in the PRD:
   - Server runs and responds to tool invocations.
   - `audit_code_snippet` correctly identifies injected vulnerabilities in test code snippets.
   - `uv run pytest -v` passes with 100% green tests.
4. When complete, write a `milestone-log.md` in this folder (`_build_plan/milestones/2-mcp-server-and-code-audit/milestone-log.md`). Structure it as follows:
   - **Start with a `## What's new in the app` section at the very top.** This is a concise, human-readable, bulleted list of the main user-facing features or functionality added in this milestone.
   - Then include the implementation detail sections below:
     - What was built (files created, models added, MCP tools exposed, etc.)
     - Any decisions made during implementation that weren't pre-specified in the PRD
     - Anything the next milestone will need to know
     - Any deviations from the PRD and why

Ask me any clarifying questions using AskUserQuestion tool to lock in the implementation plan for this milestone.
