# Milestone 5 — Project Guardrail CLI (`kb init-guardrail`)

You are entering plan mode to plan and then build milestone 5 of this project.

## Context

- Read `@_build_plan/prd.md` for the full project context, scope, data model, and tech stack.
- Read previous milestone folders (`@_build_plan/milestones/1-*/milestone-log.md`, `@_build_plan/milestones/2-*/milestone-log.md`, `@_build_plan/milestones/3-*/milestone-log.md`, `@_build_plan/milestones/4-*/milestone-log.md`) to understand what has already been built.

## Your task

1. Plan the implementation for **only** milestone 5 as defined in the PRD:
   - CLI command `kb init-guardrail [PATH]` with automatic agent detection (`.cursorrules`, `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`).
   - Idempotent delimited block injection (`<!-- KB-SECURITY-GUARDRAIL-START -->` ... `<!-- KB-SECURITY-GUARDRAIL-END -->`).
   - Support for `--stack <stack_id>` to inject stack-specific invariants directly into agent prompts.
   - Support for `--check` flag to verify if a project's guardrails are present and up to date.
   - Comprehensive unit and CLI tests in `tests/test_guardrail_cli.py`.
2. After the user confirms the plan, build only what is in milestone 5's scope.
3. Verify your work against the "Done when" criteria for milestone 5 in the PRD.
4. When complete, write a `milestone-log.md` in this folder (`_build_plan/milestones/5-project-guardrail-cli/milestone-log.md`). Structure it as follows:
   - **Start with a `## What's new in the app` section at the very top.** Concise, human-readable bulleted list of user-facing capabilities added in this milestone.
   - Then include the implementation detail sections below:
     - What was built (files created, models added, routes added, etc.)
     - Any decisions made during implementation that weren't pre-specified in the PRD
     - Anything the next milestone will need to know
     - Any deviations from the PRD and why

Ask me any clarifying questions using AskUserQuestion tool to lock in the implementation plan for this milestone.
