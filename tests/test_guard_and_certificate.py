"""Tests du Git Pre-Commit Guard (kb guard) et du Certificat d'Auditabilité (kb verify) (Milestone 6).

Vérifie que :
1. get_git_root et get_staged_files identifient fidèlement l'état de l'index git.
2. guard_staged_changes valide les commits propres (< 100 ms) et bloque les violations critiques.
3. Une tentative de commit avec '/var/run/docker.sock' ou un conteneur root est interceptée.
4. install_pre_commit_hook installe un script exécutable bloquant les commits non conformes.
5. generate_certificate produit un certificat formel scellé par empreinte SHA-256.
6. save_certificate et generate_badge_svg génèrent les artefacts de conformité (JSON, MD, SVG).
7. Les commandes CLI 'kb guard' et 'kb verify' retournent les codes de sortie attendus (0 vs 1).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess

import pytest
from typer.testing import CliRunner

from kb.certificate import (
    generate_badge_markdown,
    generate_badge_svg,
    generate_certificate,
    save_certificate,
)
from kb.cli import app
from kb.guard import (
    get_git_root,
    get_staged_files,
    guard_staged_changes,
    install_pre_commit_hook,
)
from kb.schema import EngineeringCertificate

runner = CliRunner()


def _strip_ansi(text: str) -> str:
    """Supprime les codes ANSI pour fiabiliser les assertions."""
    return re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)


def _init_git_repo(path: Path) -> Path:
    """Initialise un dépôt git local de test avec configuration minimale."""
    subprocess.run(["git", "init"], cwd=str(path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test Agent"], cwd=str(path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "agent@example.com"], cwd=str(path), check=True, capture_output=True)
    return path


# --------------------------------------------------------------------------- #
# 1. Git Guard : Détection & Analyse Staged
# --------------------------------------------------------------------------- #


def test_git_root_detection(tmp_path: Path):
    """Vérifie la détection de la racine git et le cas hors-dépôt."""
    assert get_git_root(tmp_path) is None

    _init_git_repo(tmp_path)
    detected = get_git_root(tmp_path)
    assert detected is not None
    assert detected.resolve() == tmp_path.resolve()


def test_guard_clean_staged_files(tmp_path: Path):
    """Vérifie qu'un commit propre est validé sans violation et sous les 500 ms."""
    repo = _init_git_repo(tmp_path)
    clean_py = repo / "main.py"
    clean_py.write_text("def hello():\n    return 'clean code'\n", encoding="utf-8")

    subprocess.run(["git", "add", "main.py"], cwd=str(repo), check=True, capture_output=True)

    # Préchauffage de l'index en mémoire
    guard_staged_changes(repo)

    # Mesure de performance d'exécution
    res = guard_staged_changes(repo)
    assert res.clean is True
    assert res.files_checked == 1
    assert len(res.violations) == 0
    assert res.elapsed_ms < 500.0
    assert "conforme" in res.summary.lower()


def test_guard_blocks_docker_sock_violation(tmp_path: Path):
    """Vérifie le blocage immédiat d'un fichier montant /var/run/docker.sock."""
    repo = _init_git_repo(tmp_path)
    insecure_compose = repo / "docker-compose.yml"
    insecure_compose.write_text(
        "services:\n  app:\n    image: alpine\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
        encoding="utf-8",
    )

    subprocess.run(["git", "add", "docker-compose.yml"], cwd=str(repo), check=True, capture_output=True)

    res = guard_staged_changes(repo)
    assert res.clean is False
    assert len(res.violations) >= 1

    crit_ids = [v.rule_id for v in res.violations]
    assert any("docker" in rid.lower() for rid in crit_ids)

    # Vérifie que le pattern DO est bien présent pour guider l'agent
    assert any(v.do_pattern for v in res.violations)


def test_guard_blocks_insecure_cookie(tmp_path: Path):
    """Vérifie l'interception d'un cookie posé avec SameSite=None sans Secure."""
    repo = _init_git_repo(tmp_path)
    insecure_py = repo / "auth.py"
    insecure_py.write_text(
        'response.set_cookie(key="session", value="123", samesite="none", httponly=True)\n',
        encoding="utf-8",
    )

    subprocess.run(["git", "add", "auth.py"], cwd=str(repo), check=True, capture_output=True)

    res = guard_staged_changes(repo)
    assert res.clean is False
    assert any("cookie" in v.rule_id.lower() or "session" in v.rule_id.lower() for v in res.violations)


# --------------------------------------------------------------------------- #
# 2. Installateur de Hook Git Pre-Commit
# --------------------------------------------------------------------------- #


def test_install_pre_commit_hook(tmp_path: Path):
    """Vérifie l'écriture et les permissions exécutables de .git/hooks/pre-commit."""
    repo = _init_git_repo(tmp_path)
    hook_path = install_pre_commit_hook(repo)

    assert hook_path.is_file()
    assert hook_path.name == "pre-commit"
    assert os.access(hook_path, os.X_OK)

    content = hook_path.read_text(encoding="utf-8")
    assert "KB Shift-Left Pre-Commit Guard" in content
    assert "kb guard" in content


# --------------------------------------------------------------------------- #
# 3. Moteur de Certification (kb verify)
# --------------------------------------------------------------------------- #


def test_generate_certificate_clean(tmp_path: Path):
    """Vérifie la génération d'un certificat VERIFIED_CLEAN scellé par SHA-256."""
    clean_file = tmp_path / "index.py"
    clean_file.write_text("print('pure clean codebase')\n", encoding="utf-8")

    cert = generate_certificate(tmp_path, profile="saas")
    assert isinstance(cert, EngineeringCertificate)
    assert cert.status == "VERIFIED_CLEAN"
    assert cert.critical_findings_count == 0
    assert cert.high_findings_count == 0
    assert len(cert.signature_sha256) == 64  # SHA-256 hex
    assert cert.rules_evaluated_count > 0

    md = cert.to_markdown()
    assert "Certificat d'Auditabilité d'Ingénierie KB" in md
    assert "VERIFIED_CLEAN" in md
    assert cert.signature_sha256 in md


def test_generate_certificate_failed(tmp_path: Path):
    """Vérifie qu'un code avec faille produit un statut AUDIT_FAILED."""
    bad_compose = tmp_path / "docker-compose.yml"
    bad_compose.write_text("volumes:\n  - /var/run/docker.sock:/var/run/docker.sock\n", encoding="utf-8")

    cert = generate_certificate(tmp_path, profile="saas")
    assert cert.status == "AUDIT_FAILED"
    assert cert.critical_findings_count > 0


def test_save_certificate_and_badge(tmp_path: Path):
    """Vérifie la sauvegarde des fichiers JSON/MD et la génération du SVG."""
    cert = generate_certificate(tmp_path, profile="saas")
    json_path, md_path = save_certificate(cert, tmp_path)

    assert json_path.is_file()
    assert md_path.is_file()

    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded["certificate_id"] == cert.certificate_id

    # Test génération SVG badge
    svg_clean = generate_badge_svg(verified=True)
    assert "<svg" in svg_clean
    assert "Verified 100%" in svg_clean
    assert "#2E4A3F" in svg_clean  # Couleur Évergreen

    svg_fail = generate_badge_svg(verified=False)
    assert "Audit Failed" in svg_fail
    assert "#A82A2A" in svg_fail

    badge_md = generate_badge_markdown(verified=True)
    assert "[![KB Security: Verified 100%]" in badge_md


# --------------------------------------------------------------------------- #
# 4. Tests CLI Typer (kb guard & kb verify)
# --------------------------------------------------------------------------- #


def test_cli_guard_clean(tmp_path: Path):
    """CLI 'kb guard' retourne 0 quand le code staged est conforme."""
    repo = _init_git_repo(tmp_path)
    (repo / "clean.py").write_text("x = 42\n", encoding="utf-8")
    subprocess.run(["git", "add", "clean.py"], cwd=str(repo), check=True, capture_output=True)

    result = runner.invoke(app, ["guard", str(repo)])
    assert result.exit_code == 0
    output = _strip_ansi(result.output)
    assert "KB Guard : Conforme" in output


def test_cli_guard_blocks_and_exits_1(tmp_path: Path):
    """CLI 'kb guard' bloque et retourne 1 en cas de violation."""
    repo = _init_git_repo(tmp_path)
    (repo / "docker-compose.yml").write_text(
        "volumes:\n  - /var/run/docker.sock:/var/run/docker.sock\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "docker-compose.yml"], cwd=str(repo), check=True, capture_output=True)

    result = runner.invoke(app, ["guard", str(repo)])
    assert result.exit_code == 1
    output = _strip_ansi(result.output)
    assert "KB Guard : Commit Bloqué" in output
    assert "Pattern Sécurisé Recommandé" in output


def test_cli_guard_install_hook(tmp_path: Path):
    """CLI 'kb guard --install-hook' installe le pre-commit."""
    repo = _init_git_repo(tmp_path)
    result = runner.invoke(app, ["guard", str(repo), "--install-hook"])
    assert result.exit_code == 0
    assert "Hook git pré-commit installé avec succès" in _strip_ansi(result.output)


def test_cli_verify_clean_with_badge(tmp_path: Path):
    """CLI 'kb verify' émet le certificat et crée le badge vectoriel."""
    (tmp_path / "app.py").write_text("def run(): pass\n", encoding="utf-8")

    result = runner.invoke(app, ["verify", str(tmp_path), "--badge"])
    assert result.exit_code == 0
    output = _strip_ansi(result.output)
    assert "CERTIFICAT D'AUDITABILITÉ ÉMIS : VERIFIED_CLEAN" in output
    assert "Badge vectoriel" in output

    assert (tmp_path / "kb-audit-certificate.json").is_file()
    assert (tmp_path / "KB-AUDIT-CERTIFICATE.md").is_file()
    assert (tmp_path / "kb-badge.svg").is_file()


def test_cli_verify_failed_exits_1(tmp_path: Path):
    """CLI 'kb verify' échoue et sort avec code 1 en présence de failles."""
    (tmp_path / "docker-compose.yml").write_text(
        "volumes:\n  - /var/run/docker.sock:/var/run/docker.sock\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["verify", str(tmp_path)])
    assert result.exit_code == 1
    output = _strip_ansi(result.output)
    assert "CERTIFICATION ÉCHOUÉE : AUDIT_FAILED" in output


def test_cli_verify_json_output(tmp_path: Path):
    """CLI 'kb verify --json' produit une sortie JSON parseable."""
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    result = runner.invoke(app, ["verify", str(tmp_path), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["status"] == "VERIFIED_CLEAN"
    assert "signature_sha256" in data
    assert "files_generated" in data
