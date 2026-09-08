# Contributing to Engineering Knowledge Base (`kb`)

Thank you for your interest in contributing! This Knowledge Base is engineered to give AI agents and security engineers an actionable, audit-ready corpus of software architecture, security, and quality rules.

---

## 🎯 The Non-Negotiable Grounding Rule

**Every single rule must be backed by an exact, verbatim citation in an official, publicly archived document.**

- **No unsubstantiated advice**: A rule without an authoritative source is immediately rejected by our automated Grounding Judge.
- **Opposable in production**: Because each citation is anchored to an official standard (OWASP, NIST, RFC, CIS, Cloud documentation) and verified with an exact SHA-256 hash and offset, findings are mathematically defensible to clients, auditors, and regulators.
- **Threshold**: Automated similarity checks must meet or exceed an **85% grounding score** during validation.

---

## 🛠️ Development Setup

Prerequisites:
- [Python 3.12+](https://www.python.org/)
- [`uv`](https://docs.astral.sh/uv/) (Astral's fast Python package manager)

```bash
# Clone the repository
git clone https://github.com/Alpha2-far/engineering-kb.git
cd engineering-kb

# Install dependencies and sync virtual environment
uv sync

# Run tests
uv run pytest -v
```

---

## 📖 Rule Addition Workflow

### 1. Register or Verify Source
Check [`sources/registry.yaml`](sources/registry.yaml). If the authoritative source isn't listed:
- Add an entry with `tier`, `id`, `name`, `url`, and `method` (prefer `git` for repositories).
- Verify connectivity:
  ```bash
  uv run kb doctor --only <source_id>
  ```
- Acquire the canonical text into local `raw/`:
  ```bash
  uv run kb acquire --only <source_id>
  ```

### 2. Extract Rules
Write new rules in `rules/<pack-name>.yaml`. For each rule, provide:
- `ref`: Unique immutable ID (e.g. `KB-0048`).
- `name`: Crisp title describing the imperative requirement.
- `category`: Category (`app-security`, `authentication`, `authorization`, `ai-ml`, `database`, `devops`, `api`, `frontend`, `network`, `data-protection`).
- `severity`: `critical`, `high`, `medium`, or `low`.
- `anchors`: Source ID, document relative path, and the verbatim quote.
- `rationale`: Why this rule exists and the technical consequences of non-compliance.
- `detection`: File globs and detection patterns (`grep` patterns indicating defects or `absent` patterns indicating missing mandatory controls).

Refer to [`EXTRACTION.md`](EXTRACTION.md) for full extraction guidelines.

### 3. Validate and Compile
Run the validation gate:
```bash
uv run kb validate
```
This checks:
- Pydantic schema conformance
- Exact string / fuzzy match of citations against local `raw/`
- Near-duplicate detection against all active rules
- Document staleness (SHA-256 drift)

Once validation reports **0 rejected** and **0 stale docs**, re-compile the agent packs:
```bash
uv run kb compile
```

### 4. Run Test Suite
```bash
uv run pytest -v
```

---

## 🚀 Submitting Your Changes

1. Fork the repo and create a descriptive branch (`git checkout -b rule/add-jwt-revocation`).
2. Ensure `uv run pytest` and `uv run kb validate` pass without warnings.
3. Commit your changes with clear, conventional commit messages (`feat: add rule KB-0048 for JWT revocation`).
4. Push to your branch and open a Pull Request!
