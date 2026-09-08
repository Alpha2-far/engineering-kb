"""Moteur de Détection Git Pré-Commit Shift-Left (kb guard).

Analyse les modifications git stagées en moins de 100 ms et intercepte les régressions
critiques avant qu'elles ne soient validées dans l'historique du dépôt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import subprocess
import time
from typing import Sequence

from .audit import audit_snippet
from .schema import Severity, SnippetFinding


@dataclass
class GuardResult:
    """Résultat de l'analyse pré-commit git."""

    git_root: Path
    files_checked: int
    clean: bool
    violations: list[SnippetFinding] = field(default_factory=list)
    elapsed_ms: float = 0.0
    summary: str = ""


def get_git_root(path: Path | None = None) -> Path | None:
    """Retourne la racine du dépôt git englobant, ou None si hors dépôt git."""
    cwd = path or Path.cwd()
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            return Path(res.stdout.strip()).resolve()
    except OSError:
        pass
    return None


def get_staged_files(git_root: Path, staged_only: bool = True) -> list[tuple[str, str]]:
    """Récupère les fichiers modifiés et leur contenu exact.

    Si staged_only est True (défaut), lit le contenu indexé par `git add`
    via `git show :<path>`.
    Si aucun fichier n'est staged et que staged_only est False, se replie sur
    les fichiers modifiés du répertoire de travail.
    """
    cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"]
    res = subprocess.run(cmd, cwd=str(git_root), capture_output=True, text=True, check=False)

    rel_paths = [p.strip() for p in res.stdout.splitlines() if p.strip()]

    if not rel_paths and not staged_only:
        # Repli sur les fichiers modifiés de l'arbre de travail
        res_work = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACM"],
            cwd=str(git_root),
            capture_output=True,
            text=True,
            check=False,
        )
        rel_paths = [p.strip() for p in res_work.stdout.splitlines() if p.strip()]

    staged_data: list[tuple[str, str]] = []
    for rel in rel_paths:
        # Tenter d'abord de lire le contenu indexé dans git (:path)
        show_res = subprocess.run(
            ["git", "show", f":{rel}"],
            cwd=str(git_root),
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
        if show_res.returncode == 0:
            content = show_res.stdout
        else:
            file_on_disk = git_root / rel
            if file_on_disk.is_file():
                try:
                    content = file_on_disk.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
            else:
                continue

        staged_data.append((rel, content))

    return staged_data


def guard_staged_changes(
    git_root: Path,
    staged_only: bool = True,
    blocking_severities: Sequence[Severity] | None = None,
) -> GuardResult:
    """Audite instantanément les fichiers stagés contre les règles critiques de sécurité."""
    t0 = time.perf_counter()
    staged = get_staged_files(git_root, staged_only=staged_only)

    severities = blocking_severities or (Severity.CRITICAL, Severity.HIGH)

    violations: list[SnippetFinding] = []

    for rel_path, content in staged:
        verdict = audit_snippet(content, filename=rel_path)
        for f in verdict.findings:
            if f.severity in severities:
                # Enrichit le snippet avec le chemin de fichier complet
                violations.append(
                    SnippetFinding(
                        rule_id=f.rule_id,
                        rule_title=f.rule_title,
                        severity=f.severity,
                        category=f.category,
                        line=f.line,
                        snippet=f"{rel_path}:{f.line} -> {f.snippet}",
                        rationale=f.rationale,
                        remediation=f.remediation,
                        do_pattern=f.do_pattern,
                        evidence=f.evidence,
                    )
                )

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    clean = (len(violations) == 0)

    if not staged:
        summary = "Aucun fichier staged à analyser."
    elif clean:
        summary = (
            f"✅ KB Guard: Staged changes conformes ({len(staged)} fichier(s) vérifié(s) "
            f"en {elapsed_ms:.1f} ms — 0 violation critique)."
        )
    else:
        summary = (
            f"❌ KB Guard: {len(violations)} violation(s) critique(s) interceptée(s) "
            f"en {elapsed_ms:.1f} ms dans le commit git !"
        )

    return GuardResult(
        git_root=git_root,
        files_checked=len(staged),
        clean=clean,
        violations=violations,
        elapsed_ms=elapsed_ms,
        summary=summary,
    )


def install_pre_commit_hook(git_root: Path) -> Path:
    """Installe le hook git pre-commit mécanique pour bloquer les commits non conformes."""
    # Déterminer l'emplacement du dossier hooks via git
    res = subprocess.run(
        ["git", "rev-parse", "--git-path", "hooks"],
        cwd=str(git_root),
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode == 0 and res.stdout.strip():
        hooks_dir = Path(res.stdout.strip())
        if not hooks_dir.is_absolute():
            hooks_dir = (git_root / hooks_dir).resolve()
    else:
        hooks_dir = git_root / ".git" / "hooks"

    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_file = hooks_dir / "pre-commit"

    script = """#!/usr/bin/env bash
# ==============================================================================
# KB Shift-Left Pre-Commit Guard
# Intercepte mécaniquement les régressions de sécurité critiques (< 100 ms).
# ==============================================================================

set -e

if command -v kb >/dev/null 2>&1; then
    kb guard
elif command -v uvx >/dev/null 2>&1; then
    uvx --from engineering-kb kb guard
else
    echo "⚠️  [KB Guard] Commande 'kb' introuvable. Passez par 'uv tool install engineering-kb'."
fi
"""

    hook_file.write_text(script, encoding="utf-8")
    # Permissions d'exécution (0755)
    try:
        hook_file.chmod(hook_file.stat().st_mode | 0o111)
    except OSError:
        pass

    return hook_file
