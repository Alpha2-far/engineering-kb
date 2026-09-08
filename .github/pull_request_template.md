## Description
<!-- Provide a clear summary of the changes, rules added/updated, or features introduced. -->

## Rule Grounding & Source Verification (If modifying rules)
- [ ] Source exists in `sources/registry.yaml` (official, authoritative documentation).
- [ ] Each rule contains an exact verbatim citation and reference to the archived document.
- [ ] Citations meet the strict grounding threshold (>= 85% match via `kb validate`).
- [ ] No duplicated or conflicting rules (`near_duplicates == 0`).

## Automated Checks
- [ ] Ran `uv run pytest` (all unit tests pass).
- [ ] Ran `uv run kb validate` (0 rejections, 0 stale docs).
- [ ] Ran `uv run kb compile` (updated compiled packs in `packs/`).
