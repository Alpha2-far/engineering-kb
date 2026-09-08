# Milestone 6 — Git Pre-Commit Guard & Engineering Certificate (`kb guard` & `kb verify`)

You are entering plan mode to plan and then build milestone 6 of this project.

## Context

- Read `@_build_plan/prd.md` for the full project context, scope, data model, and tech stack.
- Read previous milestone folders (`@_build_plan/milestones/1-*/milestone-log.md` through `5-*/milestone-log.md`) to understand what has already been built.

## Your task

1. Plan the implementation for **only** milestone 6 as defined in the PRD:
   - CLI command `kb guard` analyzing staged git changes in under 100 ms against critical security rules.
   - Command `kb guard --install-hook` installing `.git/hooks/pre-commit` to prevent unsafe commits.
   - Command `kb verify [PATH]` generating a formal audit certificate (`kb-audit-certificate.json` and Markdown summary) certifying 100% compliance.
   - Option `kb verify --badge` to generate a verifiable status badge.
   - Complete end-to-end integration test suite and validation on CI.
2. After the user confirms the plan, build only what is in milestone 6's scope.
3. Verify your work against the "Done when" criteria for milestone 6 in the PRD.
4. When complete, write a `milestone-log.md` in this folder (`_build_plan/milestones/6-git-precommit-guard-and-certificate/milestone-log.md`). Structure it as follows:
   - **Start with a `## What's new in the app` section at the very top.** Concise, human-readable bulleted list of user-facing capabilities added in this milestone.
   - Then include the implementation detail sections below:
     - What was built (files created, models added, routes added, etc.)
     - Any decisions made during implementation that weren't pre-specified in the PRD
     - Anything the next milestone will need to know
     - Any deviations from the PRD and why

Ask me any clarifying questions using AskUserQuestion tool to lock in the implementation plan for this milestone.
