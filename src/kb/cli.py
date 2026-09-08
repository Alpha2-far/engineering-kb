"""CLI de la Knowledge Base.

    uv run kb doctor            verifie que chaque source du registre resout encore
    uv run kb acquire --tier 1  recupere le texte canonique (git/http/feed) : 0 credit
    uv run kb docs <source>     liste les documents archives (entree des extracteurs)
    uv run kb validate          schema + ancrage + doublons
    uv run kb compile           produit les packs consommables par les agents
    uv run kb audit <prof> <ch> applique un profil compile a un projet reel
    uv run kb stats             etat de la base
    uv run kb discover <src>    Firecrawl : trouve les URL d'une source HTML-only
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import acquire as acq
from . import discover as disco
from .audit import run_audit, to_json
from .compile import compile_packs
from .ground import available_docs
from .registry import MANIFEST_PATH, PACKS_DIR, RAW_DIR, RULES_DIR, Method, load_registry
from .validate import validate_all, write_report

app = typer.Typer(add_completion=False, help="Knowledge Base d'ingenierie")
console = Console()


def _url_alive(url: str, timeout: int = 45) -> bool:
    """Une URL est-elle servie ?

    On n'utilise PAS HEAD seul : nvlpubs.nist.gov (et d'autres serveurs de
    publications) repondent 404 a un HEAD sur un fichier qui existe et se
    telecharge parfaitement en GET. Une sonde HEAD-only declarait donc mortes des
    sources vivantes — un faux negatif est aussi couteux qu'un faux positif ici,
    puisqu'il fait supprimer une bonne source du registre. On retombe sur un GET
    a plage d'octets, qui ne telecharge que le premier kilo-octet.
    """
    import urllib.error
    import urllib.request

    from . import acquire as _acq

    for req in (
        urllib.request.Request(url, method="HEAD", headers={"User-Agent": _acq.UA}),
        urllib.request.Request(
            url, headers={"User-Agent": _acq.UA, "Range": "bytes=0-1023"}
        ),
    ):
        try:
            urllib.request.urlopen(req, timeout=timeout)
            return True
        except urllib.error.HTTPError as e:
            if e.code in (403, 405, 416):  # refus de la methode, pas absence
                continue
        except Exception:  # noqa: BLE001 — DNS, TLS, timeout : on tente la suite
            continue
    return False


@app.command()
def doctor(
    tier: int = typer.Option(3, help="Ne verifier que les sources de tier <= N"),
    only: str = typer.Option("", help="Ids separes par des virgules"),
) -> None:
    """Verifie mecaniquement que chaque source resout — depot, branche, URL.

    Un registre ecrit a la main contient forcement des chemins perimes. Les faire
    constater par une sonde plutot que les supposer valides est la seule facon
    honnete de tenir une base a jour.
    """
    import subprocess
    import urllib.error
    import urllib.request

    reg = load_registry()
    ids = [x.strip() for x in only.split(",") if x.strip()] or None
    sources = reg.select(tier=tier, ids=ids)

    table = Table("source", "tier", "methode", "verdict", title=f"kb doctor — {len(sources)} sources")
    ko = 0
    for s in sources:
        verdict = ""
        if s.method is Method.GIT:
            url = f"https://github.com/{s.repo}.git"
            r = subprocess.run(
                ["git", "ls-remote", "--heads", "--tags", url, s.ref or "HEAD"],
                capture_output=True, text=True, timeout=90, check=False,
            )
            if r.returncode != 0:
                verdict = f"[red]depot injoignable[/red]"
            elif not r.stdout.strip():
                verdict = f"[yellow]branche/tag '{s.ref}' absent[/yellow]"
            else:
                verdict = "[green]ok[/green]"
        elif s.method in (Method.HTTP, Method.FEED):
            if s.format == "json-api":
                verdict = "[cyan]api vivante (non archivee)[/cyan]"
            else:
                bad = []
                for u in s.urls:
                    if not _url_alive(u):
                        bad.append(u.rsplit("/", 1)[-1])
                verdict = "[green]ok[/green]" if not bad else f"[red]{len(bad)}/{len(s.urls)} KO[/red]"
        else:
            verdict = f"[dim]{s.method.value} — hors sonde[/dim]"

        if "red" in verdict or "yellow" in verdict:
            ko += 1
        table.add_row(s.id, str(s.tier), s.method.value, verdict)

    console.print(table)
    console.print(f"\n{ko} source(s) a corriger dans sources/registry.yaml" if ko else "\nRegistre sain.")


@app.command()
def acquire(
    tier: int = typer.Option(1, help="Acquerir les sources de tier <= N"),
    only: str = typer.Option("", help="Ids separes par des virgules"),
    force: bool = typer.Option(False, help="Re-acquerir meme si deja present"),
    allow_firecrawl: bool = typer.Option(
        False, "--allow-firecrawl",
        help="Autoriser les sources payantes (1 credit/page). Desactive par defaut.",
    ),
) -> None:
    """Recupere le texte canonique. Cout Firecrawl : 0 sauf --allow-firecrawl."""
    reg = load_registry()
    ids = [x.strip() for x in only.split(",") if x.strip()] or None
    allowed = {Method.GIT, Method.HTTP, Method.FEED}
    if allow_firecrawl:
        allowed.add(Method.FIRECRAWL)
    sources = [s for s in reg.select(tier=tier, ids=ids) if s.method in allowed]
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    table = Table("source", "fichiers", "octets", "verdict", title=f"acquisition — {len(sources)} sources")
    total_files = total_bytes = 0
    failures: list[str] = []
    for s in sources:
        console.print(f"[dim]→ {s.id}[/dim]")
        r = acq.acquire(s, force=force, allow_firecrawl=allow_firecrawl)
        total_files += r.files
        total_bytes += r.bytes
        if r.ok:
            note = "; ".join(r.warnings)[:60]
            table.add_row(s.id, str(r.files), f"{r.bytes/1_000_000:.1f} Mo",
                          f"[green]ok[/green] [dim]{note}[/dim]")
        else:
            failures.append(f"{s.id}: {r.error}")
            table.add_row(s.id, "-", "-", f"[red]{(r.error or '')[:70]}[/red]")

    console.print(table)
    console.print(f"\n{total_files} documents · {total_bytes/1_000_000:.1f} Mo · manifeste : {MANIFEST_PATH}")
    if failures:
        console.print("\n[yellow]Echecs (corriger le registre) :[/yellow]")
        for f in failures:
            console.print(f"  • {f}")


@app.command()
def docs(source_id: str = typer.Argument(""), limit: int = 40) -> None:
    """Liste les documents archives — c'est la matiere premiere des extracteurs."""
    paths = available_docs(source_id or None)
    console.print(f"{len(paths)} document(s) dans raw/{source_id or ''}")
    for p in paths[:limit]:
        console.print(f"  {p}")
    if len(paths) > limit:
        console.print(f"  [dim]… +{len(paths)-limit}[/dim]")


@app.command()
def manifest(
    source_id: str = typer.Argument("", help="Filtrer sur une source"),
    grep: str = typer.Option("", help="Ne garder que les chemins contenant ce texte"),
) -> None:
    """Affiche `sha256<TAB>doc_path` pour chaque document archive.

    Les extracteurs doivent reporter le sha256 exact dans chaque `evidence`. Le
    recopier a la main est la premiere cause de rejet : cette commande le donne
    pret a coller.
    """
    import json as _json

    if not MANIFEST_PATH.is_file():
        console.print("[red]manifeste absent — lancer `kb acquire` d'abord.[/red]")
        raise typer.Exit(1)

    n = 0
    for line in MANIFEST_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        e = _json.loads(line)
        if source_id and e.get("source_id") != source_id:
            continue
        if grep and grep.lower() not in e.get("doc_path", "").lower():
            continue
        # print() et non console.print() : sortie brute, copiable, sans mise en forme
        print(f"{e['sha256']}\t{e['doc_path']}")
        n += 1
    if n == 0:
        console.print("[yellow]aucun document ne correspond.[/yellow]")


@app.command("manifest-repair")
def manifest_repair(
    apply: bool = typer.Option(False, "--apply", help="Ecrire les corrections (sinon simulation)"),
) -> None:
    """Reconcilie le manifeste avec le contenu reel de raw/.

    Trois derives possibles, toutes silencieuses jusqu'ici :
      - lignes mortes  : le document decrit n'existe plus sur le disque
      - doublons       : le meme doc_path apparait plusieurs fois (on garde le dernier,
                         c'est-a-dire l'acquisition la plus recente)
      - sha256 divergent : la ligne annonce une empreinte que le fichier n'a pas

    Les deux premieres sont corrigees. La troisieme est seulement signalee : un
    sha256 qui ne correspond plus veut dire que le fichier a change apres son
    acquisition, et c'est une information a examiner, pas a effacer.
    """
    if not MANIFEST_PATH.is_file():
        console.print("[red]manifeste absent — lancer `kb acquire` d'abord.[/red]")
        raise typer.Exit(1)

    lines = [l for l in MANIFEST_PATH.read_text(encoding="utf-8").splitlines() if l.strip()]
    by_path: dict[str, str] = {}  # doc_path -> derniere ligne vue
    dead: list[str] = []
    dupes = 0
    unreadable = 0

    for line in lines:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            unreadable += 1
            continue
        dp = e.get("doc_path", "")
        if not (RAW_DIR / dp).is_file():
            dead.append(dp)
            continue
        if dp in by_path:
            dupes += 1
        by_path[dp] = line  # le dernier gagne : acquisition la plus recente

    # sha256 annonce vs sha256 reel
    drifted: list[str] = []
    for dp, line in by_path.items():
        e = json.loads(line)
        actual = acq.sha256_bytes((RAW_DIR / dp).read_bytes())
        if e.get("sha256") != actual:
            drifted.append(dp)

    on_disk = set(available_docs())
    orphans = sorted(on_disk - set(by_path))

    table = Table("constat", "nombre", title="manifest-repair")
    table.add_row("lignes lues", str(len(lines)))
    table.add_row("documents sur le disque", str(len(on_disk)))
    table.add_row("[red]lignes mortes (fichier absent)[/red]", str(len(dead)))
    table.add_row("[yellow]doublons de doc_path[/yellow]", str(dupes))
    table.add_row("[yellow]sha256 divergent[/yellow]", str(len(drifted)))
    table.add_row("[yellow]fichiers non references[/yellow]", str(len(orphans)))
    if unreadable:
        table.add_row("[red]lignes illisibles[/red]", str(unreadable))
    console.print(table)

    if dead:
        from collections import Counter as _C
        top = _C(d.split("/")[0] for d in dead).most_common(5)
        console.print("\n[dim]lignes mortes par source : " + ", ".join(f"{k}={v}" for k, v in top) + "[/dim]")
    if drifted:
        console.print(f"\n[yellow]sha256 divergent — a re-acquerir ou re-verifier :[/yellow]")
        for d in drifted[:10]:
            console.print(f"  • {d}")
    if orphans:
        console.print(
            f"\n[yellow]{len(orphans)} fichier(s) presents sans ligne de manifeste.[/yellow] "
            "[dim]Leur provenance est inconnue : `kb acquire --only <source> --force` pour la retablir.[/dim]"
        )
        for o in orphans[:5]:
            console.print(f"  • {o}")

    if not (dead or dupes):
        console.print("\n[green]Manifeste coherent avec le disque.[/green]")
        return

    if not apply:
        console.print(
            f"\n[dim]Simulation. `kb manifest-repair --apply` retirerait "
            f"{len(dead) + dupes} ligne(s).[/dim]"
        )
        return

    ordered = [by_path[dp] for dp in sorted(by_path)]
    MANIFEST_PATH.write_text("\n".join(ordered) + "\n", encoding="utf-8")
    console.print(
        f"\n[green]Manifeste reecrit[/green] : {len(ordered)} lignes "
        f"({len(dead) + dupes} retirees)."
    )


@app.command()
def validate(
    no_grounding: bool = typer.Option(False, "--no-grounding", help="Sauter l'ancrage (deconseille)"),
    file: str = typer.Option("", "--file", help="Ne valider qu'un pack, ex. rules/authn-core.yaml"),
) -> None:
    """Valide les regles : schema, ancrage des citations, doublons."""
    target = Path(file) if file else None
    if target and not target.is_file():
        target = RULES_DIR / Path(file).name
        if not target.is_file():
            console.print(f"[red]fichier introuvable : {file}[/red]")
            raise typer.Exit(1)
    report = validate_all(check_grounding=not no_grounding, only_file=target)
    s = report.summary()

    table = Table("metrique", "valeur", title="validation")
    for k in ("files_seen", "submitted", "accepted", "rejected", "near_duplicates", "stale_docs"):
        table.add_row(k, str(s[k]))
    console.print(table)

    if s["rejected_by_stage"]:
        console.print("\n[yellow]Rejets par etape :[/yellow] " + json.dumps(s["rejected_by_stage"]))
        for r in report.rejections[:25]:
            console.print(f"  [red]✗[/red] {r.rule_id} [dim]({r.file} · {r.stage})[/dim] {r.reason[:150]}")
        if len(report.rejections) > 25:
            console.print(f"  [dim]… +{len(report.rejections)-25} autres[/dim]")

    if report.stale_docs:
        console.print(
            f"\n[yellow]{len(report.stale_docs)} regle(s) citent un document qui a change "
            f"depuis l'extraction — a re-verifier.[/yellow]"
        )
    dest = write_report(report)
    console.print(f"\nRapport : {dest}")
    if s["accepted"]:
        console.print(f"Par categorie : {json.dumps(s['by_category'], ensure_ascii=False)}")
        console.print(f"Par severite  : {json.dumps(s['by_severity'], ensure_ascii=False)}")


@app.command()
def compile(  # noqa: A001 — nom de commande volontaire
    no_grounding: bool = typer.Option(False, "--no-grounding", help="Compiler sans verifier l'ancrage (utile en CI sans archive raw/)"),
) -> None:
    """Compile les regles validees en packs par categorie et par profil de projet."""
    report = validate_all(check_grounding=not no_grounding)
    if not report.accepted:
        console.print("[red]Aucune regle validee — rien a compiler.[/red]")
        raise typer.Exit(1)
    index = compile_packs(report.accepted)
    write_report(report)
    console.print(f"[green]{index['rule_count']} regles compilees[/green] → {PACKS_DIR}")

    table = Table("profil", "regles", "critiques", title="profils")
    for prof, info in index["profiles"].items():
        table.add_row(prof, str(info["count"]), str(info["critical"]))
    console.print(table)
    if report.rejections:
        console.print(f"[yellow]{len(report.rejections)} regle(s) rejetee(s) — voir validation-report.json[/yellow]")


@app.command()
def audit(
    profile: str = typer.Argument(..., help="Profil compile : ai-rag, saas, api, pipeline, static-site"),
    path: str = typer.Argument(".", help="Racine du projet a auditer"),
    json_out: str = typer.Option("", "--json", help="Ecrit le resultat en JSON (pour un agent)"),
    show: int = typer.Option(4, "--show", help="Fichiers affiches par regle"),
) -> None:
    """Applique un profil compile a un projet : quelles regles ont matiere ici.

    C'est un *reperage*, pas un verdict. Une regle declenchee signale un endroit
    a regarder, pas une faille prouvee — le tri revient a un humain ou au
    sous-agent `auditeur-securite`, a qui `--json` donne les ancrages de code.
    """
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        console.print(f"[red]repertoire introuvable : {root}[/red]")
        raise typer.Exit(1)

    try:
        res = run_audit(profile, root)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    console.print(
        f"[bold]{res.profile}[/bold] sur [bold]{root.name}[/bold] — "
        f"{res.files_scanned} fichiers lus\n"
    )

    colors = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "dim"}
    for f in res.findings:
        sev = f.severity
        marque = "  [dim](motif requis absent)[/dim]" if f.kind == "absent" else ""
        total = len(f.hits) + f.truncated
        console.print(
            f"[{colors.get(sev, 'white')}]{sev.upper():8}[/] "
            f"{f.rule.get('ref', '')} {f.rule['id']} — {total} occurrence(s){marque}"
        )
        vus: dict[str, tuple[int, str]] = {}
        for h in f.hits:
            vus.setdefault(h.path, (h.line, h.text))
        for rel, (ln, text) in list(vus.items())[:show]:
            loc = f"{rel}:{ln}" if ln else rel
            console.print(f"    [dim]{loc}[/dim]  {text}")
        if len(vus) > show:
            console.print(f"    [dim]… +{len(vus) - show} autre(s) fichier(s)[/dim]")
        console.print()

    console.print(
        f"[bold]{len(res.findings)}[/bold] regle(s) avec matiere · "
        f"[dim]{len(res.silent)} sans occurrence · "
        f"{len(res.out_of_scope)} hors-perimetre[/dim]"
    )
    if res.out_of_scope:
        console.print(
            "[dim]Hors-perimetre = aucun fichier concerne par le glob (ex. pas de "
            "workflow GitHub). Ce n'est pas « conforme », c'est « non evalue ».[/dim]"
        )
    for rid, pat, err in res.bad_patterns:
        console.print(f"[red]MOTIF INVALIDE[/red] {rid} : {err} — {pat}")

    if json_out:
        dest = Path(json_out).expanduser()
        dest.write_text(json.dumps(to_json(res), indent=2, ensure_ascii=False))
        console.print(f"\nJSON : {dest}")


@app.command()
def stats() -> None:
    """Etat de la base : sources, archive, regles, credits Firecrawl."""
    reg = load_registry()
    by_tier = {t: len([s for s in reg.sources if s.tier == t]) for t in (1, 2, 3)}
    by_method = {m.value: len([s for s in reg.sources if s.method is m]) for m in Method}

    console.print(f"[bold]Registre[/bold] : {len(reg.sources)} sources · tiers {by_tier} · methodes {by_method}")

    n_docs = len(available_docs())
    raw_mb = sum(p.stat().st_size for p in RAW_DIR.rglob("*") if p.is_file()) / 1_000_000 if RAW_DIR.exists() else 0
    console.print(f"[bold]Archive[/bold]  : {n_docs} documents · {raw_mb:.1f} Mo")

    n_rule_files = len(list(RULES_DIR.glob("*.yaml"))) if RULES_DIR.exists() else 0
    idx = PACKS_DIR / "index.json"
    compiled = json.loads(idx.read_text())["rule_count"] if idx.is_file() else 0
    console.print(f"[bold]Regles[/bold]   : {n_rule_files} fichier(s) source · {compiled} compilees")

    c = disco.credits()
    if "error" not in c:
        console.print(
            f"[bold]Firecrawl[/bold]: {c.get('remainingCredits')}/{c.get('planCredits')} credits "
            f"[dim](reset {str(c.get('billingPeriodEnd'))[:10]})[/dim]"
        )


@app.command()
def discover(
    source_id: str = typer.Argument(..., help="Source en method=firecrawl"),
    limit: int = typer.Option(30, help="Nombre max d'URL a proposer"),
) -> None:
    """Trouve les URL d'une source HTML-only. Cout : quelques credits, pas de scrape."""
    reg = load_registry()
    s = reg.by_id(source_id)
    if not s.discover:
        console.print(f"[red]{source_id} n'a pas de requete `discover`.[/red]")
        raise typer.Exit(1)

    console.print(f"[dim]recherche : {s.discover}[/dim]")
    results = disco.search(s.discover, limit=limit)
    table = Table("url", "titre", title=f"candidats — {s.name}")
    for r in results[:limit]:
        if "error" in r:
            console.print(f"[red]{r['error']}[/red]")
            break
        table.add_row((r.get("url") or "")[:80], (r.get("title") or "")[:50])
    console.print(table)
    console.print(
        "\n[dim]Etape suivante : ajouter les URL retenues au registre en method=http si le "
        "texte est accessible directement, sinon `kb fetch-page` (1 credit/page).[/dim]"
    )


@app.command()
def fetch_page(
    source_id: str = typer.Argument(...),
    url: str = typer.Argument(...),
) -> None:
    """Scrape UNE page via Firecrawl et l'archive. **Coute 1 credit.**"""
    reg = load_registry()
    s = reg.by_id(source_id)
    r = disco.scrape(url)
    if "error" in r:
        console.print(f"[red]{r['error']}[/red]")
        raise typer.Exit(1)

    md = r["markdown"]
    name = (url.rstrip("/").split("/")[-1] or "index").split("?")[0] + ".md"
    entry = acq._store(s, name, md.encode("utf-8"), {"url": url, "via": "firecrawl"})
    acq._manifest_append([entry])
    console.print(f"[green]{len(md)} caracteres[/green] → raw/{entry['doc_path']}")
    c = disco.credits()
    console.print(f"[dim]credits restants : {c.get('remainingCredits')}[/dim]")


@app.command()
def search(
    query: str = typer.Argument(..., help="Intention technique, framework ou mot-clé (ex: 'JWT auth FastAPI')"),
    limit: int = typer.Option(5, "--limit", "-n", help="Nombre maximum de règles à renvoyer"),
    framework: str = typer.Option("", "--framework", "-f", help="Filtrer par framework (ex: fastapi, supabase, docker)"),
    json_output: bool = typer.Option(False, "--json", help="Sortie JSON structurée pour agents"),
) -> None:
    """Recherche sémantique des règles de sécurité et de leurs patterns Do/Don't."""
    from rich.panel import Panel
    from .search import search_rules

    results = search_rules(query, limit=limit, framework=framework or None)
    if not results:
        if json_output:
            console.print(json.dumps({"query": query, "count": 0, "results": []}))
        else:
            console.print(f"[yellow]Aucune règle trouvée pour :[/yellow] {query!r}")
        return

    if json_output:
        data = {
            "query": query,
            "count": len(results),
            "results": [r.to_agent_card() for r in results],
        }
        console.print(json.dumps(data, indent=2, ensure_ascii=False))
        return

    console.print(f"\n[bold cyan]Résultats pour :[/bold cyan] [white]{query}[/white] ({len(results)} règle(s) trouvée(s))\n")
    for res in results:
        rule = res.rule
        sev_color = "red" if rule.severity.value == "critical" else ("yellow" if rule.severity.value == "high" else "blue")
        title = f"[{sev_color} bold][{rule.severity.value.upper()}][/{sev_color} bold] {rule.title} [dim]({rule.id})[/dim]"

        lines: list[str] = [
            f"[bold]Catégorie :[/bold] {rule.category.value} | [bold]Frameworks :[/bold] {', '.join(rule.all_frameworks) or 'universel'}",
            f"[bold]Score de pertinence :[/bold] {res.score:.1f} [dim](termes : {', '.join(res.matched_terms)})[/dim]",
            f"\n[bold]Pourquoi :[/bold]\n{rule.rationale.strip()}",
        ]

        if rule.effective_dont_pattern:
            lines.append("\n[red bold]❌ DON'T (Piège fréquent LLM) :[/red bold]")
            lines.append(f"[red]{rule.effective_dont_pattern.strip()}[/red]")

        if rule.effective_do_pattern:
            lines.append("\n[green bold]✅ DO (Pattern sécurisé recommandé) :[/green bold]")
            lines.append(f"[green]{rule.effective_do_pattern.strip()}[/green]")

        if rule.evidence:
            lines.append(f"\n[dim italic]Source : « {rule.evidence[0].quote.strip()[:180]}… » ({rule.evidence[0].source_id})[/dim italic]")

        console.print(Panel("\n".join(lines), title=title, border_style=sev_color))



def main() -> None:
    app()


if __name__ == "__main__":
    main()
