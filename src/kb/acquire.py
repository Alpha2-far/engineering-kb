"""Acquisition du texte canonique — a cout nul.

Pourquoi git plutot que le scraping : un depot officiel donne le *source* du
document (markdown, rst, txt) au lieu d'un rendu HTML a re-nettoyer, il coute zero
credit, et son SHA de commit constitue une provenance exacte et diffable. On sait
donc precisement quelle version d'un standard a fonde une regle, et on peut
detecter qu'une source a change sans re-payer une acquisition.

Firecrawl reste reserve a `discover.py` : trouver ce qui n'existe qu'en HTML.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .registry import MANIFEST_PATH, RAW_DIR, Method, Source

# Extensions porteuses de texte normatif. Tout le reste (images, binaires,
# fixtures de test) est du poids mort dans une base de connaissance.
TEXT_EXT = {
    ".md", ".mdx", ".txt", ".rst", ".adoc", ".asciidoc", ".sgml", ".xml",
    ".bs", ".html", ".htm", ".json", ".yaml", ".yml", ".csv", ".pdf",
}
MAX_FILE_BYTES = 4_000_000
SKIP_DIR_PARTS = {".git", "node_modules", "__pycache__", "img", "images", "assets", "static"}

UA = "kb-acquire/0.1 (+knowledge base interne)"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class AcquisitionResult:
    source_id: str
    ok: bool
    files: int = 0
    bytes: int = 0
    commit: str | None = None
    error: str | None = None
    warnings: list[str] = field(default_factory=list)


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
    )


def _manifest_append(entries: list[dict]) -> None:
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with MANIFEST_PATH.open("a", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")


def _manifest_purge(source_id: str) -> int:
    """Retire du manifeste les lignes d'une source avant sa re-acquisition.

    `acquire(force=True)` supprime `raw/<id>/` puis reecrit les documents. Sans
    cette purge, les lignes de l'acquisition precedente survivent et decrivent des
    fichiers qui n'existent plus : c'est ainsi qu'un checkout complet restreint
    ensuite par `paths` laisse 600 entrees fantomes. Le manifeste etant la matiere
    premiere des extracteurs (ils y lisent le sha256 a recopier), une ligne perimee
    fait rejeter une regle correcte sans raison visible.
    """
    if not MANIFEST_PATH.is_file():
        return 0
    kept: list[str] = []
    dropped = 0
    for line in MANIFEST_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            if json.loads(line).get("source_id") == source_id:
                dropped += 1
                continue
        except json.JSONDecodeError:
            pass  # ligne illisible : on la conserve, sa suppression doit etre explicite
        kept.append(line)
    if dropped:
        MANIFEST_PATH.write_text("\n".join(kept) + "\n", encoding="utf-8")
    return dropped


def _store(source: Source, rel_path: str, data: bytes, extra: dict) -> dict:
    """Ecrit le document dans raw/ et renvoie son entree de manifeste."""
    dest = RAW_DIR / source.id / rel_path
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return {
        "source_id": source.id,
        "doc_path": f"{source.id}/{rel_path}",
        "sha256": sha256_bytes(data),
        "bytes": len(data),
        "retrieved_at": _now(),
        "method": source.method.value,
        "license": source.license,
        "redistribute": source.redistribute,
        **extra,
    }


# --------------------------------------------------------------------------- #
# git
# --------------------------------------------------------------------------- #


def acquire_git(source: Source) -> AcquisitionResult:
    res = AcquisitionResult(source_id=source.id, ok=False)
    url = f"https://github.com/{source.repo}.git"

    with tempfile.TemporaryDirectory(prefix=f"kb-{source.id}-") as tmp:
        tmpdir = Path(tmp)
        # --filter=blob:none + --depth=1 : on ne telecharge que les blobs des
        # chemins demandes. Sur un depot comme cpython, la difference est de
        # plusieurs centaines de Mo.
        clone = _run([
            "git", "clone", "--filter=blob:none", "--no-checkout", "--depth", "1",
            "--branch", source.ref or "HEAD", url, str(tmpdir / "r"),
        ])
        if clone.returncode != 0:
            res.error = f"clone echoue ({source.ref}) : {clone.stderr.strip()[:300]}"
            return res
        repo_dir = tmpdir / "r"

        if source.paths:
            # --no-cone : necessaire pour cibler des FICHIERS precis et pas
            # seulement des repertoires (le mode cone ne gere que les dossiers).
            _run(["git", "sparse-checkout", "init", "--no-cone"], cwd=repo_dir)
            sp = _run(["git", "sparse-checkout", "set", *source.paths], cwd=repo_dir)
            if sp.returncode != 0:
                res.warnings.append(f"sparse-checkout : {sp.stderr.strip()[:200]}")

        co = _run(["git", "checkout"], cwd=repo_dir)
        if co.returncode != 0:
            res.error = f"checkout echoue : {co.stderr.strip()[:300]}"
            return res

        head = _run(["git", "rev-parse", "HEAD"], cwd=repo_dir)
        commit = head.stdout.strip() or None
        res.commit = commit

        entries: list[dict] = []
        for f in sorted(repo_dir.rglob("*")):
            if not f.is_file():
                continue
            rel = f.relative_to(repo_dir)
            if SKIP_DIR_PARTS & set(rel.parts):
                continue
            if f.suffix.lower() not in TEXT_EXT:
                continue
            size = f.stat().st_size
            if size == 0 or size > MAX_FILE_BYTES:
                if size > MAX_FILE_BYTES:
                    res.warnings.append(f"ignore (trop gros, {size}o) : {rel}")
                continue
            entries.append(
                _store(source, str(rel), f.read_bytes(), {
                    "repo": source.repo, "ref": source.ref, "commit": commit,
                    "url": f"https://github.com/{source.repo}/blob/{commit}/{rel}",
                })
            )

        if not entries:
            res.error = (
                f"0 document texte recupere — les chemins {source.paths} n'existent "
                f"probablement plus sur {source.repo}@{source.ref}"
            )
            return res

        _manifest_append(entries)
        res.ok = True
        res.files = len(entries)
        res.bytes = sum(e["bytes"] for e in entries)
        return res


# --------------------------------------------------------------------------- #
# http / feed
# --------------------------------------------------------------------------- #


def _fetch(url: str, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def acquire_http(source: Source) -> AcquisitionResult:
    res = AcquisitionResult(source_id=source.id, ok=False)
    entries: list[dict] = []
    for url in source.urls:
        try:
            data = _fetch(url)
        except urllib.error.HTTPError as e:
            res.warnings.append(f"HTTP {e.code} sur {url}")
            continue
        except Exception as e:  # noqa: BLE001 — on veut qu'une URL morte n'arrete pas le lot
            res.warnings.append(f"{type(e).__name__} sur {url}")
            continue

        name = url.rstrip("/").split("/")[-1].split("?")[0] or "document"
        if "." not in name:
            name += ".html"
        entries.append(_store(source, name, data, {"url": url}))

    if not entries:
        res.error = "aucune URL recuperee"
        return res
    _manifest_append(entries)
    res.ok = True
    res.files = len(entries)
    res.bytes = sum(e["bytes"] for e in entries)
    return res


def acquire_feed(source: Source) -> AcquisitionResult:
    """Flux structures officiels (CWE/CAPEC XML). Un dump vaut mieux qu'un crawl :
    c'est la donnee que le mainteneur publie *pour* etre consommee."""
    res = AcquisitionResult(source_id=source.id, ok=False)
    if source.format == "json-api":
        # Donnee vivante (NVD) : on ne la fige pas dans raw/, on l'interroge au
        # moment de l'audit. Figer un instantane de CVE creerait une base perimee
        # qui ment avec assurance — exactement ce qu'on veut eviter.
        res.warnings.append("json-api : interroge a la demande, non archive")
        res.ok = True
        return res

    entries: list[dict] = []
    for url in source.urls:
        try:
            data = _fetch(url, timeout=300)
        except Exception as e:  # noqa: BLE001
            res.warnings.append(f"{type(e).__name__} sur {url}")
            continue

        name = url.rstrip("/").split("/")[-1]
        if source.format == "xml-zip" or name.endswith(".zip"):
            tmp = RAW_DIR / source.id / "_tmp.zip"
            tmp.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_bytes(data)
            try:
                with zipfile.ZipFile(tmp) as zf:
                    for member in zf.namelist():
                        if member.endswith("/"):
                            continue
                        inner = zf.read(member)
                        if len(inner) > MAX_FILE_BYTES * 8:
                            res.warnings.append(f"ignore (volumineux) : {member}")
                            continue
                        entries.append(_store(source, member, inner, {"url": url}))
            finally:
                tmp.unlink(missing_ok=True)
        else:
            entries.append(_store(source, name, data, {"url": url}))

    if not entries:
        res.error = "aucun flux recupere"
        return res
    _manifest_append(entries)
    res.ok = True
    res.files = len(entries)
    res.bytes = sum(e["bytes"] for e in entries)
    return res


def acquire_firecrawl(source: Source) -> AcquisitionResult:
    """Scrape des URL EXPLICITEMENT listees. **1 credit par page.**

    Deux garde-fous volontaires :
      - jamais de crawl : on ne scrape que `source.urls`, pas ce qu'un crawler
        decouvrirait. Un `map` sur un gros site suivi d'un crawl viderait le
        budget du mois en une commande.
      - jamais appele par defaut : `acquire()` refuse cette methode sans
        `allow_firecrawl=True`. Les credits sont de l'argent reel.
    """
    from .discover import credits, scrape

    res = AcquisitionResult(source_id=source.id, ok=False)
    if not source.urls:
        res.error = "aucune URL explicite — utiliser `kb discover` pour les etablir d'abord"
        return res

    entries: list[dict] = []
    for url in source.urls:
        r = scrape(url)
        if "error" in r:
            res.warnings.append(f"{r['error'][:80]} sur {url}")
            continue
        md = r.get("markdown") or ""
        if not md.strip():
            res.warnings.append(f"reponse vide sur {url}")
            continue
        name = (url.rstrip("/").split("/")[-1] or "index").split("?")[0]
        name = (name[:80] or "index") + ".md"
        entries.append(_store(source, name, md.encode("utf-8"), {"url": url, "via": "firecrawl"}))

    if not entries:
        res.error = "aucune page recuperee"
        return res
    _manifest_append(entries)
    res.ok = True
    res.files = len(entries)
    res.bytes = sum(e["bytes"] for e in entries)
    remaining = credits().get("remainingCredits")
    res.warnings.append(f"{len(entries)} credit(s) depense(s) · reste {remaining}")
    return res


DISPATCH = {
    Method.GIT: acquire_git,
    Method.HTTP: acquire_http,
    Method.FEED: acquire_feed,
    Method.FIRECRAWL: acquire_firecrawl,
}


def acquire(source: Source, *, force: bool = False, allow_firecrawl: bool = False) -> AcquisitionResult:
    if source.method is Method.MANUAL:
        return AcquisitionResult(
            source_id=source.id, ok=False,
            error="method=manual : acces sous inscription/licence restrictive, "
                  "a recuperer a la main (ne pas automatiser)",
        )
    if source.method is Method.FIRECRAWL and not allow_firecrawl:
        return AcquisitionResult(
            source_id=source.id, ok=False,
            error="method=firecrawl : payant — relancer avec --allow-firecrawl",
        )
    dest = RAW_DIR / source.id
    if dest.exists() and not force:
        n = sum(1 for _ in dest.rglob("*") if _.is_file())
        return AcquisitionResult(
            source_id=source.id, ok=True, files=n,
            warnings=["deja acquis (utiliser --force pour re-acquerir)"],
        )
    if dest.exists() and force:
        shutil.rmtree(dest)
        # Les documents viennent d'etre supprimes : leurs lignes de manifeste
        # doivent partir avec eux, sinon le manifeste decrit un disque qui n'existe plus.
        _manifest_purge(source.id)
    return DISPATCH[source.method](source)
