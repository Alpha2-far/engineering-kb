"""Tests du portail d'ancrage.

Le portail est la seule piece dont la defaillance est invisible : il ne plante
pas, il rejette silencieusement des regles correctes ou — pire — accepterait une
citation qui n'est pas dans le document. Ce qui est teste ici, ce sont donc les
proprietes dont depend cette garantie, pas la couverture de lignes.

    uv run pytest tests/ -q
"""

from __future__ import annotations

import pytest

from kb.ground import normalize, verify_quote
from kb.registry import RAW_DIR


# --------------------------------------------------------------------------- #
# Regression : les motifs de nettoyage ne franchissent pas une ligne
# --------------------------------------------------------------------------- #


def test_chevron_isole_n_avale_pas_le_document():
    """Le defaut qui a motive ce fichier.

    `<[^>]+>` traversait les retours a la ligne : un `<` seul dans un bloc de
    code avalait tout le texte jusqu'au `>` suivant. Sur l'archive reelle, 501
    documents et 683 000 caracteres disparaissaient avant verification — 82 % du
    RFC 6749. Des citations litterales etaient donc declarees introuvables.
    """
    texte = (
        "runAsUser: 4000 # <-- ceci est un commentaire\n"
        "\n"
        "Always run your docker images with --security-opt=no-new-privileges.\n"
        "\n"
        "if ($i > 2) print $i\n"
    )
    sortie = normalize(texte)
    assert "no-new-privileges" in sortie
    assert "runasuser" in sortie


def test_lien_markdown_incomplet_n_avale_pas_la_suite():
    """Meme propriete pour `[libelle](url)` : un crochet ouvert sans fermeture
    sur sa ligne ne doit pas consommer le paragraphe suivant."""
    texte = "Voir [la liste ci-dessous :\n\nLe secret ne doit jamais etre commite.\n"
    assert "le secret ne doit jamais etre commite" in normalize(texte)


def test_balise_html_reelle_est_bien_retiree():
    """La correction ne doit pas desactiver le nettoyage qu'elle borne."""
    assert normalize("<strong>mot</strong> de passe") == "mot de passe"


def test_lien_markdown_garde_le_libelle_jette_l_url():
    assert normalize("voir [la fiche](https://exemple.test/a/b)") == "voir la fiche"


# --------------------------------------------------------------------------- #
# Le portail accepte ce qui est dans le document, et rien d'autre
# --------------------------------------------------------------------------- #

DOC = "owasp-cheatsheets/cheatsheets/Docker_Security_Cheat_Sheet.md"
pytestmark_archive = pytest.mark.skipif(
    not (RAW_DIR / DOC).is_file(),
    reason="archive absente (raw/ n'est pas versionne) — lancer `uv run kb acquire`",
)


@pytestmark_archive
def test_citation_litterale_est_ancree():
    q = (
        "Always run your docker images with `--security-opt=no-new-privileges` "
        "in order to prevent privilege escalation."
    )
    v = verify_quote(q, DOC)
    assert v.grounded, v.detail
    assert v.method == "exact"


@pytestmark_archive
def test_citation_inventee_est_rejetee():
    """La propriete qui justifie tout le dispositif : une phrase plausible mais
    absente du document ne passe pas."""
    q = (
        "Docker exige imperativement une rotation trimestrielle des jetons de "
        "registre pour toute image publiee en production."
    )
    assert not verify_quote(q, DOC).grounded


@pytestmark_archive
def test_reformulation_partielle_est_rejetee():
    """Une citation a moitie reecrite tombe sous le seuil de couverture : c'est
    la frontiere entre citer et paraphraser."""
    q = (
        "Always run your docker containers with the no-new-privileges option "
        "because it is generally considered a very good idea by most teams."
    )
    assert not verify_quote(q, DOC).grounded


def test_document_absent_ne_leve_pas():
    v = verify_quote("une citation quelconque de longueur suffisante ici", "source-inexistante/x.md")
    assert not v.grounded
    assert v.method == "missing-doc"
