"""Decouverte de sources via Firecrawl — le SEUL poste payant du pipeline.

Repartition des roles :
  Firecrawl  -> TROUVER (quelles pages existent, ou est la doc normative)
  Python/git -> RECUPERER (le texte canonique, gratuitement)

Budget : ~1000 credits/mois, 1 credit par page scrapee. `map` coute bien moins
cher qu'un crawl et suffit a etablir une liste d'URL, qu'on filtre AVANT de
depenser un credit de scrape. Toute fonction de ce module affiche son cout.

La cle vit dans le `.env` a la racine du depot, sous le nom `FIRECEAWL_TOKEN`
(faute de frappe historique conservee telle quelle pour ne rien casser ailleurs ;
les deux orthographes sont acceptees ici).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

API = "https://api.firecrawl.dev/v2"
ENV_CANDIDATES = ("FIRECRAWL_API_KEY", "FIRECRAWL_TOKEN", "FIRECEAWL_TOKEN")


def load_key(env_path: Path | None = None) -> str:
    import os

    for name in ENV_CANDIDATES:
        if os.environ.get(name):
            return os.environ[name]

    candidates: list[Path] = []
    if env_path:
        candidates.append(env_path)
    candidates.append(Path.cwd() / ".env")
    # repo root: <repo>/src/kb/discover.py -> parents[2] is <repo>
    candidates.append(Path(__file__).resolve().parents[2] / ".env")
    # monorepo root fallback
    try:
        candidates.append(Path(__file__).resolve().parents[3] / ".env")
    except IndexError:
        pass

    for p in candidates:
        if p.is_file():
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                if k.strip() in ENV_CANDIDATES:
                    return v.strip().strip('"').strip("'")
    raise RuntimeError(
        f"cle Firecrawl introuvable (cherchee dans l'environnement et .env sous {ENV_CANDIDATES})"
    )


def _post(path: str, payload: dict, key: str, timeout: int = 180) -> dict:
    req = urllib.request.Request(
        API + path,
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return {"success": False, "error": f"HTTP {e.code}: {e.read().decode()[:300]}"}


def credits(key: str | None = None) -> dict:
    k = key or load_key()
    req = urllib.request.Request(
        f"{API}/team/credit-usage", headers={"Authorization": f"Bearer {k}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode()).get("data", {})
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)[:200]}


def search(query: str, limit: int = 10, key: str | None = None) -> list[dict]:
    """Trouve les pages candidates. Sert a alimenter `registry.yaml`, pas a
    extraire du contenu."""
    k = key or load_key()
    r = _post("/search", {"query": query, "limit": limit}, k)
    if not r.get("success"):
        return [{"error": r.get("error", "echec")}]
    data = r.get("data") or {}
    items = data.get("web", data if isinstance(data, list) else [])
    return [
        {"url": i.get("url"), "title": i.get("title"), "description": i.get("description")}
        for i in items
    ]


def site_map(url: str, search_term: str | None = None, limit: int = 500,
             key: str | None = None) -> list[str]:
    """Liste les URL d'un site sans en scraper le contenu.

    C'est l'etape a faire AVANT toute depense : on obtient l'inventaire, on
    choisit les pages a fort rendement normatif, et on ne paie que celles-la.
    """
    k = key or load_key()
    payload: dict = {"url": url, "limit": limit}
    if search_term:
        payload["search"] = search_term
    r = _post("/map", payload, k)
    if not r.get("success"):
        return []
    links = (r.get("data") or {}).get("links") or r.get("links") or []
    return [l.get("url", l) if isinstance(l, dict) else l for l in links]


def scrape(url: str, key: str | None = None) -> dict:
    """Recupere une page en markdown. **1 credit.** A n'utiliser que si le texte
    canonique n'est accessible ni par git, ni par HTTP direct."""
    k = key or load_key()
    r = _post(
        "/scrape",
        {"url": url, "formats": ["markdown"], "onlyMainContent": True},
        k,
    )
    if not r.get("success"):
        return {"url": url, "error": r.get("error", "echec")}
    d = r.get("data") or {}
    return {"url": url, "markdown": d.get("markdown", ""), "metadata": d.get("metadata", {})}
