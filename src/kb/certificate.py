"""Moteur de Certification d'Auditabilité d'Ingénierie KB (kb verify).

Génère des certificats formels scellés cryptographiquement attestant de la
conformité d'une base de code aux règles normatives de sécurité et d'architecture.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import uuid

from .audit import run_audit
from .guard import get_git_root
from .schema import EngineeringCertificate, Severity


def _get_git_commit(root: Path) -> str | None:
    """Récupère le SHA-1 court du commit git actif s'il existe."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except OSError:
        pass
    return None


def generate_certificate(
    project_root: Path,
    profile: str = "saas",
) -> EngineeringCertificate:
    """Exécute un audit complet et produit un certificat d'auditabilité scellé."""
    audit_res = run_audit(profile=profile, root=project_root)

    crit_count = sum(1 for f in audit_res.findings if f.severity == "critical")
    high_count = sum(1 for f in audit_res.findings if f.severity == "high")
    total_findings = len(audit_res.findings)

    # Récupération des sources officielles citées
    sources: set[str] = set()
    for f in audit_res.findings:
        for ev in f.rule.get("evidence", []):
            if ev.get("source_id"):
                sources.add(ev["source_id"])
    for rule in audit_res.silent:
        for ev in rule.get("evidence", []):
            if ev.get("source_id"):
                sources.add(ev["source_id"])

    sorted_sources = sorted(sources)
    rules_evaluated_count = len(audit_res.findings) + len(audit_res.silent)
    status = "VERIFIED_CLEAN" if (crit_count == 0 and high_count == 0) else "AUDIT_FAILED"

    timestamp = datetime.now(timezone.utc).isoformat()
    project_name = project_root.name or "project"
    git_commit = _get_git_commit(project_root)

    # Calcul de la signature cryptographique SHA-256
    sig_payload = {
        "project_name": project_name,
        "project_root": str(project_root.resolve()),
        "timestamp": timestamp,
        "git_commit": git_commit,
        "profile": profile,
        "status": status,
        "files_scanned": audit_res.files_scanned,
        "rules_evaluated_count": rules_evaluated_count,
        "critical_findings_count": crit_count,
        "high_findings_count": high_count,
        "total_findings_count": total_findings,
        "sources_cited": sorted_sources,
    }
    raw_bytes = json.dumps(sig_payload, sort_keys=True).encode("utf-8")
    signature = hashlib.sha256(raw_bytes).hexdigest()

    cert_id = f"KB-CERT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"

    return EngineeringCertificate(
        certificate_id=cert_id,
        project_name=project_name,
        project_root=str(project_root.resolve()),
        timestamp=timestamp,
        git_commit=git_commit,
        profile=profile,
        status=status,
        files_scanned=audit_res.files_scanned,
        rules_evaluated_count=rules_evaluated_count,
        critical_findings_count=crit_count,
        high_findings_count=high_count,
        total_findings_count=total_findings,
        sources_cited=sorted_sources,
        signature_sha256=signature,
    )


def save_certificate(
    cert: EngineeringCertificate,
    out_dir: Path,
) -> tuple[Path, Path]:
    """Sauvegarde le certificat JSON et le rapport Markdown dans le dossier cible."""
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "kb-audit-certificate.json"
    md_path = out_dir / "KB-AUDIT-CERTIFICATE.md"

    json_path.write_text(
        json.dumps(cert.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(cert.to_markdown(), encoding="utf-8")

    return json_path, md_path


def generate_badge_svg(verified: bool = True) -> str:
    """Génère un badge vectoriel SVG autonome aux couleurs de la charte de confiance."""
    if verified:
        status_text = "Verified 100%"
        color = "#2E4A3F"  # Évergreen de confiance
    else:
        status_text = "Audit Failed"
        color = "#A82A2A"  # Rouge alerte

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="180" height="28" role="img" aria-label="KB Security: {status_text}">
  <title>KB Security: {status_text}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="180" height="28" rx="4" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="84" height="28" fill="#1A1A17"/>
    <rect x="84" width="96" height="28" fill="{color}"/>
    <rect width="180" height="28" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif" font-size="12" font-weight="600">
    <text x="42" y="19" fill="#010101" fill-opacity=".3">KB Security</text>
    <text x="42" y="18" fill="#fff">KB Security</text>
    <text x="132" y="19" fill="#010101" fill-opacity=".3">{status_text}</text>
    <text x="132" y="18" fill="#fff">{status_text}</text>
  </g>
</svg>
"""


def generate_badge_markdown(
    verified: bool = True,
    badge_file: str = "kb-badge.svg",
    cert_file: str = "kb-audit-certificate.json",
) -> str:
    """Génère le snippet Markdown prêt pour intégration dans un README."""
    status_label = "Verified 100%" if verified else "Audit Failed"
    return f"[![KB Security: {status_label}]({badge_file})]({cert_file})"
