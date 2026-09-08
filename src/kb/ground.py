"""Portail d'ancrage — la piece qui rend la base opposable.

Un extracteur LLM peut inventer une regle plausible et lui attacher une reference
d'apparence credible. C'est le mode d'echec exact que le Livre Blanc decrit :
une affirmation sans preuve, presentee avec assurance. Une base construite sans
ce garde-fou blanchit des hallucinations en leur donnant l'autorite d'« OWASP ».

La parade est deterministe et ne fait appel a aucun modele : la citation portee
par une regle doit etre RETROUVABLE dans le document archive. Si elle ne l'est
pas, la regle est rejetee — mecaniquement, pas par relecture humaine.

C'est la couche « Grounding Judge » du Livre Blanc, appliquee a notre propre
outillage plutot qu'a un produit client.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .registry import RAW_DIR

# Seuil de couverture de n-grammes accepte quand la citation n'est pas un
# sous-ensemble exact (l'extracteur a normalise une puce, coupe un retour a la
# ligne, retire un lien markdown). En dessous, ce n'est plus une citation.
COVERAGE_THRESHOLD = 0.85
SHINGLE = 5

_QUOTES = {
    "‘": "'", "’": "'", "‚": "'", "‛": "'",
    "“": '"', "”": '"', "„": '"', "«": '"', "»": '"',
    "–": "-", "—": "-", "−": "-", " ": " ", "​": "",
}
_TAG_RE = re.compile(r"<[^>\n]+>")
_MD_NOISE_RE = re.compile(r"[*_`#>|]+")
_LINK_RE = re.compile(r"\[([^\]\n]*)\]\([^)\n]*\)")
_WS_RE = re.compile(r"\s+")


def normalize(text: str) -> str:
    """Ramene deux formulations du meme texte a une forme comparable.

    On neutralise ce qui varie sans changer le sens (typographie, emphase
    markdown, cible des liens, blancs) et rien d'autre : les mots restent
    intacts, sinon on accepterait des citations qui ne disent pas la meme chose.

    Une balise ne franchit jamais un retour a la ligne : `<[^>\\n]+>` et non
    `<[^>]+>`. Sans cette borne, un `<` isole — un `# <-- commentaire` dans un
    bloc de code, un `$i <= NF` dans un script awk — avale tout le texte jusqu'au
    `>` suivant, parfois des milliers de caracteres plus loin. Le document
    verifie n'est alors plus le document archive, et le portail rejette des
    citations pourtant litterales : sur cette archive, 501 documents et 683 000
    caracteres etaient concernes, dont 82 % du RFC 6749.
    """
    t = unicodedata.normalize("NFKC", text)
    for bad, good in _QUOTES.items():
        t = t.replace(bad, good)
    t = _LINK_RE.sub(r"\1", t)  # garde le libelle, jette l'URL
    t = _TAG_RE.sub(" ", t)
    t = _MD_NOISE_RE.sub(" ", t)
    t = _WS_RE.sub(" ", t)
    return t.strip().lower()


def _shingles(text: str, n: int = SHINGLE) -> set[str]:
    words = text.split()
    if len(words) < n:
        return {" ".join(words)} if words else set()
    return {" ".join(words[i : i + n]) for i in range(len(words) - n + 1)}


def _pdf_text(data: bytes) -> str:
    try:
        import io

        from pypdf import PdfReader
    except ImportError:  # pragma: no cover
        raise RuntimeError(
            "extraction PDF indisponible : `uv add pypdf` (requis pour les sources NIST/AWS)"
        ) from None
    reader = PdfReader(io.BytesIO(data))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


@lru_cache(maxsize=512)
def doc_text(doc_path: str) -> str:
    """Texte normalise d'un document archive. `doc_path` est relatif a kb/raw/."""
    p = RAW_DIR / doc_path
    if not p.is_file():
        raise FileNotFoundError(f"document absent de l'archive : {doc_path}")
    data = p.read_bytes()
    if p.suffix.lower() == ".pdf":
        return normalize(_pdf_text(data))
    return normalize(data.decode("utf-8", errors="replace"))


@dataclass
class GroundingVerdict:
    grounded: bool
    score: float
    method: str
    detail: str = ""


def verify_quote(quote: str, doc_path: str) -> GroundingVerdict:
    try:
        haystack = doc_text(doc_path)
    except FileNotFoundError as e:
        return GroundingVerdict(False, 0.0, "missing-doc", str(e))
    except RuntimeError as e:
        return GroundingVerdict(False, 0.0, "unreadable-doc", str(e))

    needle = normalize(quote)
    if not needle:
        return GroundingVerdict(False, 0.0, "empty-quote")

    if needle in haystack:
        return GroundingVerdict(True, 1.0, "exact")

    q = _shingles(needle)
    if not q:
        return GroundingVerdict(False, 0.0, "too-short")
    d = _shingles(haystack)
    coverage = len(q & d) / len(q)
    if coverage >= COVERAGE_THRESHOLD:
        return GroundingVerdict(True, coverage, "shingle", f"couverture {coverage:.0%}")
    return GroundingVerdict(
        False, coverage, "shingle",
        f"couverture {coverage:.0%} < {COVERAGE_THRESHOLD:.0%} — citation introuvable",
    )


def verify_sha(doc_path: str, expected_sha256: str) -> bool:
    """Le document a-t-il change depuis l'extraction ?

    Un faux ici ne rejette pas la regle : il signale qu'une source a bouge et
    que la regle doit etre re-verifiee. C'est le mecanisme de fraicheur.
    """
    import hashlib

    p = RAW_DIR / doc_path
    if not p.is_file():
        return False
    return hashlib.sha256(p.read_bytes()).hexdigest() == expected_sha256


def available_docs(source_id: str | None = None) -> list[str]:
    base = RAW_DIR / source_id if source_id else RAW_DIR
    if not base.exists():
        return []
    return sorted(
        str(p.relative_to(RAW_DIR))
        for p in base.rglob("*")
        if p.is_file() and p.name != "manifest.jsonl"
    )


def resolve_path(doc_path: str) -> Path:
    return RAW_DIR / doc_path
