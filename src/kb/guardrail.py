"""Moteur de Guardrails de Projet pour Agents IA (Shift-Left Engineering).

Permet d'injecter ou de vérifier de manière idempotente des directives de sécurité
normatives et des invariants d'architecture dans les fichiers d'instruction des agents :
- Cursor (.cursorrules)
- Antigravity IDE / Codex (AGENTS.md)
- Claude Code (CLAUDE.md)
- GitHub Copilot (.github/copilot-instructions.md)
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from .contracts import get_contract
from .schema import SecurityContract

GUARDRAIL_START = "<!-- KB-SECURITY-GUARDRAIL-START -->"
GUARDRAIL_END = "<!-- KB-SECURITY-GUARDRAIL-END -->"

SUPPORTED_AGENT_FILES: list[str] = [
    ".cursorrules",
    "AGENTS.md",
    "CLAUDE.md",
    ".github/copilot-instructions.md",
]

DEFAULT_INIT_FILES: list[str] = [
    "AGENTS.md",
    "CLAUDE.md",
]


def generate_guardrail_content(contract: SecurityContract | None = None) -> str:
    """Génère le bloc de consignes de sécurité Shift-Left délimité pour agents."""
    lines: list[str] = [
        GUARDRAIL_START,
        "# 🛡️ Mandatory Engineering & Security Guardrails (Shift-Left)",
        "",
        "> **Normative AI Agent Directive**: This repository strictly enforces zero-vibe, security-first",
        "> engineering. Hallucinated security configs, weak credentials, and bypasses are strictly forbidden.",
        "",
        "## 🛑 Pre-Coding Obligation",
        "Before generating, refactoring, or proposing ANY code or configuration:",
        "1. **Consult Security Rules & Contracts**:",
        "   - If KB FastMCP tools are active, query `get_security_contract` or `resolve_security_topic` / `get_security_rules`.",
        "   - Adhere strictly to the recommended DO patterns and eliminate known anti-patterns (DON'T).",
        "2. **Strict Parameterization & Zero Hardcoded Secrets**:",
        "   - Never inject raw SQL, shell commands, or unescaped user inputs.",
        "   - Never commit tokens, credentials, or private keys; always read from validated environment variables.",
        "",
    ]

    if contract:
        lines.extend([
            f"## 🔒 Stack-Enforced Contract: {contract.name} (`{contract.stack_id}`)",
            "",
        ])
        if contract.description:
            lines.extend([f"> {contract.description}", ""])

        if contract.invariants:
            lines.extend(["### ⚠️ Invariants Absolus (Non Négociables) :", ""])
            for inv in contract.invariants:
                lines.append(f"- **{inv}**")
            lines.append("")

        if contract.pre_coding_checklist:
            lines.extend(["### ✅ Checklist Pré-Codage :", ""])
            for check in contract.pre_coding_checklist:
                lines.append(f"- [ ] {check}")
            lines.append("")

        if contract.do_patterns:
            lines.extend(["### 💡 Patterns DO de Référence :", ""])
            for pat in contract.do_patterns:
                title = pat.get("title", "Pattern")
                lang = pat.get("lang", "")
                code = pat.get("code", "").strip()
                lines.append(f"**{title}**:")
                lines.append(f"```{lang}\n{code}\n```")
                lines.append("")
    else:
        lines.extend([
            "## 🔒 Core Invariants (Universal)",
            "- **Least Privilege**: Run containers as non-root, restrict database roles, enable strict CORS and secure cookies (`HttpOnly`, `Secure`, `SameSite`).",
            "- **Defense in Depth**: Authenticate before authorization, validate all inputs with strict schemas, isolate multi-tenant data.",
            "- **Auditability**: Verify code against known security flaws before presenting it.",
            "",
        ])

    lines.extend([
        "## 🔍 Post-Coding Verification & Self-Audit",
        "- Run self-audit against security checklists before staging or committing.",
        "- If `kb` CLI is installed: verify compliance with `kb guard` or `kb run-audit`.",
        GUARDRAIL_END,
    ])

    return "\n".join(lines)


def inject_guardrail_into_file(file_path: Path, block: str) -> tuple[bool, str]:
    """Injecte ou met à jour le bloc de guardrail de manière idempotente.

    Retourne (succès: bool, action: str) où action est:
    - 'created' : le fichier n'existait pas et a été créé avec le bloc
    - 'updated' : le bloc délimité a été mis à jour dans le fichier existant
    - 'injected' : le bloc délimité a été ajouté à la fin du fichier existant
    - 'unchanged' : le fichier contenait déjà exactement le même bloc
    """
    block = block.strip()

    if not file_path.exists():
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(block + "\n", encoding="utf-8")
        return True, "created"

    content = file_path.read_text(encoding="utf-8")

    start_idx = content.find(GUARDRAIL_START)
    end_idx = content.find(GUARDRAIL_END)

    if start_idx != -1 and end_idx != -1 and end_idx >= start_idx:
        full_end_idx = end_idx + len(GUARDRAIL_END)
        existing_block = content[start_idx:full_end_idx].strip()
        if existing_block == block:
            return True, "unchanged"

        new_content = content[:start_idx] + block + content[full_end_idx:]
        file_path.write_text(new_content, encoding="utf-8")
        return True, "updated"
    elif start_idx != -1 and end_idx == -1:
        # Balise début sans fin (bloc tronqué) -> remplacer jusqu'à la fin
        new_content = content[:start_idx].rstrip() + "\n\n" + block + "\n"
        file_path.write_text(new_content, encoding="utf-8")
        return True, "updated"
    else:
        # Pas de balises -> ajout propre à la fin sans altérer le début
        clean_content = content.rstrip()
        if clean_content:
            new_content = clean_content + "\n\n" + block + "\n"
        else:
            new_content = block + "\n"
        file_path.write_text(new_content, encoding="utf-8")
        return True, "injected"


def detect_agent_files(project_root: Path) -> list[Path]:
    """Détecte les fichiers de configuration d'agents existants dans le projet."""
    found: list[Path] = []
    for rel_path in SUPPORTED_AGENT_FILES:
        candidate = project_root / rel_path
        if candidate.is_file():
            found.append(candidate)
    return found


def check_project_guardrails(project_root: Path) -> dict[str, Any]:
    """Inspecte l'état des guardrails dans les fichiers d'agents du projet."""
    files_status: dict[str, dict[str, Any]] = {}

    for rel_path in SUPPORTED_AGENT_FILES:
        target = project_root / rel_path
        if not target.is_file():
            continue

        content = target.read_text(encoding="utf-8")
        has_start = GUARDRAIL_START in content
        has_end = GUARDRAIL_END in content
        is_active = has_start and has_end

        stack_match = re.search(r"Stack-Enforced Contract:.*?`([^`]+)`", content)
        stack_id = stack_match.group(1) if stack_match else None

        files_status[rel_path] = {
            "exists": True,
            "has_start": has_start,
            "has_end": has_end,
            "is_active": is_active,
            "stack_id": stack_id,
        }

    active_count = sum(1 for f in files_status.values() if f["is_active"])
    missing_count = sum(1 for f in files_status.values() if not f["is_active"])

    if not files_status:
        overall_status = "no_agent_files"
    elif missing_count > 0:
        overall_status = "missing"
    else:
        overall_status = "active"

    return {
        "status": overall_status,
        "total_files": len(files_status),
        "active_files": active_count,
        "missing_files": missing_count,
        "files": files_status,
    }


def init_project_guardrails(
    project_root: Path,
    stack_id: str | None = None,
    force_all: bool = False,
) -> dict[str, Any]:
    """Initialise ou met à jour les guardrails dans le projet cible."""
    contract = None
    if stack_id:
        contract = get_contract(stack_id)
        if not contract:
            raise ValueError(f"Contrat introuvable pour la stack '{stack_id}'")

    block = generate_guardrail_content(contract)

    if force_all:
        targets = [project_root / rel for rel in SUPPORTED_AGENT_FILES]
    else:
        detected = detect_agent_files(project_root)
        if detected:
            targets = detected
        else:
            targets = [project_root / rel for rel in DEFAULT_INIT_FILES]

    results: dict[str, str] = {}
    for target in targets:
        rel_str = str(target.relative_to(project_root))
        _, action = inject_guardrail_into_file(target, block)
        results[rel_str] = action

    return {
        "project_root": str(project_root),
        "contract": contract.model_dump(mode="json") if contract else None,
        "targets": [str(t.relative_to(project_root)) for t in targets],
        "results": results,
    }
