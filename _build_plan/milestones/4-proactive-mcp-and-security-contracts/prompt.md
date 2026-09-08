# Milestone 4 — Proactive Shift-Left MCP & Security Contracts

You are entering plan mode to plan and then build milestone 4 of this project.

## Context

- Read `@_build_plan/prd.md` for the full project context, scope, data model, and tech stack.
- Read previous milestone folders (`@_build_plan/milestones/1-*/milestone-log.md`, `@_build_plan/milestones/2-*/milestone-log.md`, `@_build_plan/milestones/3-*/milestone-log.md`) to understand what has already been built.

## Your task

1. Plan the implementation for **only** milestone 4 as defined in the PRD:
   - Proactive FastMCP tool descriptions forcing LLM agents to call KB **before** code generation.
   - Pydantic model `SecurityContract` and FastMCP tool `get_security_contract(stack: str) -> dict`.
   - 4 built-in normative security contracts (`fastapi-supabase-rag`, `nextjs-auth`, `docker-compose`, `github-actions-ci`).
   - CLI command `kb contract` to view and list contracts (`uv run kb contract --list`, `uv run kb contract <stack>`).
   - Comprehensive test suite in `tests/test_contracts.py`.
2. After the user confirms the plan, build only what is in milestone 4's scope.
3. Verify your work against the "Done when" criteria for milestone 4 in the PRD.
4. When complete, write a `milestone-log.md` in this folder (`_build_plan/milestones/4-proactive-mcp-and-security-contracts/milestone-log.md`). Structure it as follows:
   - **Start with a `## What's new in the app` section at the very top.** Concise, human-readable bulleted list of user-facing capabilities added in this milestone.
   - Then include the implementation detail sections below:
     - What was built (files created, models added, routes added, etc.)
     - Any decisions made during implementation that weren't pre-specified in the PRD
     - Anything the next milestone will need to know
     - Any deviations from the PRD and why

Ask me any clarifying questions using AskUserQuestion tool to lock in the implementation plan for this milestone.
