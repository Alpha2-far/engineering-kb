# Knowledge Base d'ingénierie — architecture

> **À lire avant tout travail sur `kb/`.** Document vivant : le mettre à jour à
> chaque évolution structurelle.

## Le problème

Les modèles produisent du code qui **fonctionne**. Fonctionner n'est pas être
sécurisé, robuste, ni prêt pour la production. On veut une base de connaissance
qui permette à des agents d'auditer et corriger ce code selon les standards
réels de l'industrie — pas selon l'opinion moyenne d'internet.

## Le piège qu'on évite

La tentation naturelle est de **miroiter la documentation du monde** : scraper
OWASP, AWS, Kubernetes, PostgreSQL, tout stocker, tout donner à l'agent.

Trois raisons pour lesquelles ça ne marche pas :

1. **Volume.** Une seule cheat sheet OWASP fait 45 600 caractères (~12 000
   tokens). La documentation AWS fait des dizaines de milliers de pages. Un
   miroir se compte en centaines de millions de tokens : ni chargeable dans un
   contexte, ni utile.
2. **Densité normative.** La page de référence `CREATE INDEX` de PostgreSQL
   contient zéro règle. La cheat sheet OWASP sur l'authentification en contient
   trente. Le volume et la valeur ne sont pas corrélés — ils sont presque
   inversement corrélés.
3. **Attention.** Un agent noyé sous 5 000 règles audite **plus mal** qu'un agent
   qui reçoit les 80 règles pertinentes pour le projet devant lui. L'attention
   est la ressource rare, pas le stockage.

Le livrable n'est donc pas une archive. C'est un **corpus de règles dense,
routable et prouvé**.

## La contrainte qui a dicté l'architecture

Budget Firecrawl : **~1 000 crédits/mois**, 1 crédit par page. La liste de
sources visée en compte plus de 120, dont plusieurs documentations entières.
L'écart entre l'ambition et le budget est de 3 à 4 ordres de grandeur.

**Résolution : séparer trouver de récupérer.**

| Rôle | Outil | Coût |
|---|---|---|
| **Trouver** — quelles pages existent, où est la doc normative | Firecrawl (`search`, `map`) | quelques crédits |
| **Récupérer** — le texte canonique | git / HTTP / flux officiels (Python) | **0** |

C'est possible parce que la quasi-totalité des sources autoritaires sont des
dépôts git publics : OWASP CheatSheetSeries (120 fichiers markdown), ASVS, WSTG,
Kubernetes, Docker, FastAPI, Supabase, React, Next.js, MDN… Un `git clone
--filter=blob:none --sparse` donne le **texte source** (pas un rendu HTML à
re-nettoyer), coûte zéro, et son SHA de commit est une provenance exacte et
diffable.

Les catalogues (CWE, CAPEC, CVE) ne se scrapent pas non plus : ils publient des
**dumps XML/JSON officiels**, faits pour être consommés.

Firecrawl reste indispensable pour ce qui n'existe qu'en HTML rendu : PortSwigger,
Cloudflare Learning Center, doc Railway, portails éditeurs.

## Les trois couches

Cette séparation est la **Loi n°1** (faits ≠ interprétations) appliquée à
l'outillage lui-même.

```
   sources/registry.yaml          94 sources : méthode, licence, tier
            │
            ▼  acquire.py — git / http / feed          coût Firecrawl : 0
   ┌──────────────────────────────────────────────────┐
   │  raw/                    LE FAIT                 │  jamais commité
   │  documents officiels, content-hashés             │  (volume + licences)
   │  manifest.jsonl : sha256, commit, url, licence   │  reconstructible
   └──────────────────────────────────────────────────┘
            │
            ▼  extraction — LA SEULE ÉTAPE LLM, isolée
   ┌──────────────────────────────────────────────────┐
   │  rules/<source>.yaml     L'INTERPRÉTATION        │  commité, diffable
   │  chaque règle cite raw/ par chemin + sha256      │
   └──────────────────────────────────────────────────┘
            │
            ▼  validate.py — PORTAIL D'ANCRAGE, déterministe, sans LLM
            │  citation introuvable dans raw/ ⇒ règle rejetée
            ▼
   ┌──────────────────────────────────────────────────┐
   │  packs/                  LE LIVRABLE             │  commité
   │  by-category/ · profiles/ · index.json · RULES.md│
   └──────────────────────────────────────────────────┘
```

### Pourquoi le portail d'ancrage est la pièce maîtresse

Un extracteur LLM peut produire une règle plausible et lui attacher une référence
d'apparence crédible. C'est exactement le mode d'échec que le Livre Blanc décrit :
une affirmation sans preuve, énoncée avec assurance. Une base construite sans ce
garde-fou **blanchit des hallucinations en leur donnant l'autorité d'« OWASP »** —
et devient plus dangereuse qu'utile, puisqu'elle sert à corriger du code.

La parade ne fait appel à aucun modèle : la citation portée par la règle doit être
**retrouvable** dans le document archivé (`ground.py` — égalité exacte après
normalisation, sinon couverture de 5-grammes ≥ 85 %). Sinon, rejet mécanique.

C'est la couche « Grounding Judge » du Livre Blanc, retournée contre notre propre
outillage. La base est construite avec la doctrine qu'elle encode.

Corollaire assumé : **pas d'archive, pas de preuve, pas de règle.** `raw/` étant
gitignoré, un clone frais doit lancer `uv run kb acquire` avant de pouvoir
valider. C'est voulu.

### Pourquoi le routage est déterministe et non sémantique

Les règles se classent par **technologie** (`python`, `fastapi`, `supabase`) —
c'est une recherche catégorielle, pas sémantique. Une table de correspondance
donne un rappel parfait pour zéro coût. Des embeddings coûteraient plus cher pour
un rappel moins bon. pgvector n'a de sens qu'au-delà de quelques milliers de
règles, quand la question devient « qu'est-ce qui ressemble à ce problème ? ».
Ne pas le construire d'avance.

Deux vues compilées :
- `by-category/` — question ciblée (« que dit la base sur JWT ? »)
- `profiles/` — audit de projet. Un site statique vanilla ne doit **jamais**
  charger les règles pgvector. Les règles sans `project_types` sont universelles
  et entrent dans tous les profils — **aucune ne l'est aujourd'hui**, ce qui rend
  le tag explicite obligatoire pour qu'une règle entre dans un profil.

Sept profils : `static-site`, `saas`, `ai-rag`, `api`, `pipeline`, `cli`,
`mobile`. Ils décrivent une **surface d'exécution**, pas un langage : `cli` et
`pipeline` partagent l'absence de surface HTTP et se séparent sur la ligne de
commande. Ajouter un profil = trois fichiers (cf. « Le profil `cli` » plus bas).

## Priorisation : le tier

La liste de sources traite « OWASP ASVS » et « C++ » comme équivalents. Ils ne le
sont pas pour cette stack.

- **Tier 1 (30)** — déclenche des règles sur le code écrit aujourd'hui : OWASP
  (cheat sheets, ASVS, Top 10, API, LLM, WSTG), FastAPI, Supabase, PostgreSQL,
  React, Next.js, Docker, GitHub Actions, RFC OAuth/JWT/TLS/HTTP, NIST crypto +
  AI RMF, RGPD, Cloudflare, Railway.
- **Tier 2 (30)** — standards transverses et stack adjacente crédible :
  Kubernetes, NGINX, Redis, Django, Express, GraphQL, WebSocket, AWS
  Well-Architected, CAPEC, CVSS, PortSwigger, MDN, NIS2.
- **Tier 3 (34)** — écosystèmes non livrés aujourd'hui : Java/Spring, C#/ASP.NET,
  C++, Swift, Kotlin, PHP/Laravel, Angular, Vue, SAML, gRPC, mobile, GitLab,
  Terraform, MongoDB/MySQL.

Rien n'est perdu : les 94 sources sont enregistrées avec leur méthode
d'acquisition. Un tier 3 s'acquiert à la demande (`kb acquire --only <id>`) le jour
où un projet le justifie.

## Licences — une contrainte réelle, pas un détail

Les sources n'ont pas le même régime : OWASP est CC-BY-SA, NIST et les RFC sont
libres de réutilisation, mais MITRE, PortSwigger, Oracle, AWS, MongoDB
(CC-BY-NC-SA) et CIS autorisent la consultation sans la rediffusion.

Deux conséquences structurelles :
- `raw/` n'est **jamais** commité — archive locale de vérification.
- Le drapeau `redistribute` du registre borne la longueur des citations
  publiables dans les packs.
- **CIS Benchmarks est délibérément en `method: manual`** : téléchargement sous
  inscription et licence restrictive. L'automatiser nous mettrait en faute — pour
  une entreprise qui vend de la conformité, c'est disqualifiant.

## Fraîcheur

Le manifeste porte le `sha256` de chaque document et le SHA du commit source.
`validate` compare le sha256 cité par une règle à celui du fichier actuel : une
divergence signale **« la source a changé depuis l'extraction, cette règle est à
re-vérifier »** (`stale_docs` dans le rapport). Ça ne rejette pas la règle — ça
la marque. C'est le mécanisme de synchronisation avec l'état de l'art, et il est
gratuit parce que git donne le diff.

Exemple concret de pourquoi ça compte : NIST SP 800-63B **révision 4** renverse
les recommandations de la révision 3 (fin de la rotation obligatoire des mots de
passe, fin de la complexité imposée). Une base figée sur la r3 conseillerait
exactement l'inverse de l'état de l'art, avec autorité.

## Arborescence

| Chemin | Rôle |
|---|---|
| `sources/registry.yaml` | 94 sources : `method`, `tier`, `license`, `redistribute`, chemins git |
| `src/kb/schema.py` | **le contrat** — `Rule`, `Evidence`, `Detection`, vocabulaires fermés |
| `src/kb/registry.py` | chargement/validation du registre, chemins du projet |
| `src/kb/acquire.py` | git sparse-checkout · HTTP · dumps ; écrit `raw/` + manifeste |
| `src/kb/ground.py` | **portail d'ancrage** — normalisation + vérification de citation |
| `src/kb/validate.py` | schéma → ancrage → unicité → quasi-doublons ; rapport JSON |
| `src/kb/compile.py` | packs par catégorie et par profil, index de routage, vue markdown |
| `src/kb/audit.py` | **consommation** — applique un profil compilé à un projet sur disque |
| `src/kb/discover.py` | **seul consommateur de Firecrawl** (search/map/scrape unitaire) |
| `src/kb/cli.py` | `doctor` `acquire` `docs` `manifest` `manifest-repair` `validate` `compile` `audit` `stats` `discover` `fetch-page` |
| `EXTRACTION.md` | contrat donné aux agents extracteurs |
| `raw/` | archive brute — **gitignorée**, reconstructible |
| `rules/` | règles sources en YAML — commitées |
| `packs/` | livrable compilé — commité |
| `tests/` | 22 tests — portail d'ancrage et repérage, les deux pièces dont la panne est silencieuse |

## Commandes

```bash
cd kb
uv run kb doctor --tier 1      # chaque source résout-elle encore ?
uv run kb acquire --tier 1      # récupère le texte canonique — 0 crédit
uv run kb docs owasp-cheatsheets  # ce que voient les extracteurs
uv run kb validate              # schéma + ancrage + doublons
uv run kb compile               # produit packs/
uv run kb audit <profil> <ch>   # applique un profil à un projet réel
uv run kb stats                 # état de la base + crédits Firecrawl restants
uv run kb discover railway      # Firecrawl : trouve les URL d'une source HTML-only
uv run pytest -q                # 22 tests — 3 sautent sans raw/
```

## État du corpus — 2026-08-11

**47 règles, 4 packs, 0 rejet d'ancrage, 0 quasi-doublon, 0 `stale_doc`.**

| Pack | Règles | Ce qu'il couvre |
|---|---|---|
| `owasp-llm-top10.yaml` | 16 | injection de prompt, sortie de modèle, RAG/embeddings, agentivité, inférence |
| `owasp-cheatsheets.yaml` | 17 | SQL, mots de passe, JWT, autorisation, upload, SSRF, logs, GitHub Actions, Docker |
| `stack-supabase-fastapi.yaml` | 7 | RLS (le noyau), clé service, vues `security_invoker`, comparaison à temps constant |
| `cli-tooling.yaml` | 7 | injection de commande et d'argument, traversée de chemin, secret en `argv`, `pickle`/`yaml.load`, verrouillage des dépendances |

Sévérité : 14 critical · 21 high · 12 medium. Répartition par profil compilé :
`saas` 44 · `ai-rag` 42 · `api` 39 · `pipeline` 17 · `cli` 16 · `static-site` 7 · `mobile` 0.

Le profil `mobile` est vide **et c'est correct** : aucune source mobile n'est en
tier 1, et un profil vide vaut mieux qu'un profil rempli de règles hors sujet.

### Le profil `cli` — ajouté le 2026-08-11

Un CLI n'a ni session, ni CORS, ni cookie : les profils existants décrivaient des
surfaces qu'il n'a pas. Ce qui lui est propre est la ligne de commande elle-même
— arguments composés en commande shell, chemins choisis par l'appelant, secrets
visibles dans `ps` et dans l'historique du shell, fichiers d'état désérialisés
depuis le disque.

7 règles neuves tirées de sources archivées mais jamais exploitées
(`OS_Command_Injection_Defense`, `Input_Validation`, `Deserialization`,
`Secrets_Management`, `Software_Supply_Chain_Security`, ASVS V5), plus 9 règles
existantes taguées `cli` — retenues sur un critère unique : leur détection se
déclenche sur du code de CLI **et** le mode de panne existe pour un process
local. Les règles de surface HTTP (JWT, RLS, mass assignment, XSS) sont
délibérément exclues.

L'ajout d'un profil suppose trois modifications, pas une : `PROFILES` dans
`compile.py`, le vocabulaire de `RuleContext.project_types` dans `schema.py`, et
la liste des `project_types` connus dans `EXTRACTION.md`. Aucune règle du corpus
n'étant universelle (toutes déclarent leurs `project_types`), un profil ajouté
sans tagger une seule règle compile à zéro — c'est le cas de `mobile`.

### Le défaut trouvé en éprouvant le profil `cli`

La première version de `dependencies-not-pinned-to-verified-version` portait une
détection `absent` cherchant `^uv\.lock` **dans le texte de** `pyproject.toml`.
Or `absent` ne sait pas interroger le système de fichiers : il cherche un motif
manquant dans le contenu des fichiers cadrés. Le motif ne pouvait donc jamais
matcher, et la règle accusait **tous** les projets, lockfile commité ou non — à
commencer par `kb/` lui-même, qui commite `uv.lock`.

Son `grep` était faux aussi : il signalait `pydantic>=2.9` dans `pyproject.toml`,
alors qu'une contrainte large dans le manifeste **avec** un lock commité est
exactement la pratique que la source prescrit. La règle contredisait sa propre
citation.

Les deux motifs sont désormais bornés à `requirements*.txt` (seul cas où une
contrainte ouverte tient lieu de résolution) et aux commandes d'installation qui
ignorent le verrouillage (`pip install -r`, `npm install`). Leçon durable :
**une détection `absent` teste un contenu, jamais une présence de fichier.**

### Le défaut d'ancrage corrigé le 2026-08-01

Deux motifs de la normalisation n'étaient pas bornés au retour à la ligne :
`_TAG_RE = <[^>]+>` et `_LINK_RE`. Un `<` isolé dans un document — un `# <--
commentaire`, un `$i <= NF` dans un script awk — avalait tout le texte jusqu'au
`>` suivant, parfois des milliers de caractères plus loin.

Conséquence : **le document vérifié n'était plus le document archivé**, et le
portail rejetait des citations pourtant littérales. Mesure sur l'archive avant
correction : **501 documents sur 2 502 touchés, 683 161 caractères escamotés** —
82 % du RFC 6749, 63 % de `deployment/versions.md` de FastAPI, 43 % de la cheat
sheet Docker.

C'est le mode de panne le plus coûteux qu'on pouvait avoir : le portail ne
plantait pas, il **rejetait silencieusement du travail correct**. D'où
`tests/test_ground.py` — la première suite de tests du projet, et elle couvre
cette pièce en premier parce que c'est celle dont la défaillance est invisible.

### La consommation : `kb audit`

Compiler les packs ne suffit pas à rendre la base utilisable — un profil pèse
~42 000 tokens, on ne le charge pas dans le contexte d'un agent. `audit.py` fait
le pont : il applique un profil à un projet sur disque et ne rend que les règles
**ayant matière**, chacune ancrée à des lignes précises.

La sortie distingue trois états, et c'est la distinction qui compte :

| État | Sens |
|---|---|
| **avec matière** | des lignes à examiner — pas une faille prouvée |
| **sans occurrence** | évaluée, rien trouvé |
| **hors-périmètre** | aucun fichier concerné par le glob — **non évalué**, pas « conforme » |

Un projet sans Dockerfile ne *respecte* pas la règle sur l'utilisateur du
conteneur : elle ne s'applique pas. Fondre les deux derniers états produirait un
rapport qui affirme la sécurité d'une zone jamais regardée — le même défaut de
fond que la base entière cherche à éviter.

### Essai du livrable sur du code réel

Le profil `ai-rag` a été passé sur `document-copilot/` (548 fichiers) :
**16 règles avec matière, 16 muettes, 7 hors-périmètre, 0 motif invalide.**
Deux constats de fond en sont sortis, à traiter côté Document Copilot
(pas côté `kb`) :

- **`workspace_id` est optionnel dans `SearchFilters`** (`backend/app/retrieval/types.py:16`).
  Les deux appelants le passent aujourd'hui, mais rien ne l'impose : un troisième
  appelant qui l'oublie fait une recherche vectorielle sur le corpus entier,
  tous cabinets confondus. Le RLS ne rattrape pas : la connexion applicative est
  `postgres.<ref>` (propriétaire), et il n'y a ni `FORCE ROW LEVEL SECURITY` ni
  `SET LOCAL` d'identité — les politiques `auth.uid()` ne s'appliquent donc pas
  au backend. Le filtre applicatif est le **seul** rempart de cloisonnement.
- **Les deux Dockerfiles tournent en root** (aucune directive `USER`) — constat
  rendu par une détection `absent`, invisible au premier essai (cf. ci-dessous).
- **Beaucoup de bruit sur les `.env`** — vérifié : ils sont gitignorés, aucune
  clé n'est commitée. Le motif `secret-hardcoded-in-source` devrait exclure
  `.env` (fichier de configuration locale) et ne garder que le code source.

### Les deux défauts trouvés en écrivant le consommateur

Tous deux étaient **silencieux** — ni exception, ni message, juste un résultat
faux. C'est le mode de panne récurrent de ce projet, et la raison pour laquelle
chaque pièce est désormais testée avant d'être crue.

1. **Le premier essai ne traitait que `kind: "grep"`.** Les 14 détections
   `absent` du profil (« ce motif DOIT être présent et manque ») n'étaient pas
   évaluées : 4 règles étaient comptées « muettes » sans avoir tourné. Les
   Dockerfiles en root étaient invisibles, pas absents du rapport parce que
   propres — absents parce que jamais regardés.
2. **Les motifs `absent` sont ancrés par ligne mais cherchés dans le texte
   entier** (`^USER `, `^permissions:`). Sans `re.MULTILINE`, `^` ne matche qu'à
   l'offset 0 : un Dockerfile déclarant `USER` en ligne 2 était rapporté comme
   tournant en root. Faux positif, sur la moitié des motifs `absent` du corpus.
   Trouvé par un test, pas par lecture — d'où le `USER` en ligne 2 dans
   `test_motif_requis_present_ne_declenche_pas` : en ligne 1, le test passait
   malgré le défaut.


## Points de vigilance

- **`git ls-remote` en HEAD-only produit des faux négatifs.** nvlpubs.nist.gov
  répond 404 à un `HEAD` sur un PDF qui se télécharge en `GET`. `_url_alive()`
  retombe sur un GET à plage d'octets. Un faux négatif coûte aussi cher qu'un
  faux positif : il fait supprimer une bonne source.
- **`sparse-checkout` en mode `--no-cone`** est obligatoire pour cibler des
  fichiers précis (le mode cone ne gère que les répertoires).
- **PostgreSQL est en SGML**, pas en markdown — nettoyage nécessaire à
  l'extraction. Seules les pages denses sont ciblées (`ddl`, `client-auth`), pas
  les 3 000 pages de référence.
- **NVD/CVE est une donnée vivante**, jamais archivée : un instantané de CVE
  devient une base périmée qui affirme avec assurance. À interroger au moment de
  l'audit des dépendances.
- **Le seuil d'ancrage à 85 %** est un compromis. Le baisser laisserait passer des
  citations reconstruites ; le monter rejetterait des citations légitimement
  retouchées (puce markdown, retour à la ligne).
- **Un motif de normalisation ne doit jamais franchir un retour à la ligne.**
  C'est la leçon du défaut du 2026-08-01 : toute classe de caractères négative
  dans `ground.py` s'écrit `[^X\n]`, jamais `[^X]`. Sinon le portail vérifie un
  document qui n'est pas celui qui est archivé.
- **Une détection `absent` se compile avec `re.MULTILINE`.** Le motif est ancré
  par ligne, le texte cherché est le fichier entier. Sans le drapeau, `^` ne
  matche qu'à l'offset 0 et la règle accuse un fichier conforme.
- **Une détection `absent` teste un contenu, jamais l'existence d'un fichier.**
  Elle demande « parmi les fichiers cadrés par le glob, lesquels ne contiennent
  pas ce motif ? ». Un motif du genre `^uv\.lock` appliqué à `pyproject.toml` ne
  matche jamais et accuse donc **tous** les projets. Pour exprimer « ce fichier
  voisin devrait exister », il faudrait un nouveau `DetectionKind` — il n'existe
  pas aujourd'hui.
- **Un audit lancé sur `kb/` lui-même se lit avec précaution.** `raw/` contient
  des documents tiers bourrés d'exemples de secrets, et `rules/` contient des
  `vulnerable_example` volontairement fautifs. Les deux déclenchent des règles à
  juste titre selon le motif, à tort selon l'intention.
- **« Hors-périmètre » n'est pas « conforme ».** Toute sortie d'audit doit garder
  les deux séparés. Les fondre fait affirmer la sécurité d'une zone non regardée,
  ce qui est précisément ce que cette base existe pour empêcher.
- **`kb/` n'est pas suivi par git** (`git ls-files kb` → 0). Ni ignoré : jamais
  ajouté. Le corpus, le code et les packs n'ont **aucune sauvegarde distante** —
  décision à prendre, cf. ci-dessous.

## Ce qui reste à faire

- **Trancher le versionnement.** `raw/` doit rester hors git (volume + licences),
  mais `src/`, `rules/`, `packs/`, `tests/` et `sources/` doivent y entrer. En
  l'état, une perte de disque efface le corpus. Décision de Farel.
- **Affiner deux motifs de détection** repérés à l'essai sur `document-copilot` :
  exclure `.env` de `secret-hardcoded-in-source`, et resserrer
  `authorization/object-level/missing-ownership-check-on-id`, qui déclenche
  aujourd'hui sur toute occurrence de `{id}` y compris en documentation.
  ⚠️ S'ajoute un troisième cas vu en auditant `kb/` lui-même :
  `secret-hardcoded-in-source` remonte 20 occurrences dont la quasi-totalité
  vient de `raw/` (documents tiers archivés, exemples de JWT dans les cheat
  sheets) et des blocs `vulnerable_example` de `rules/`. Le scanner n'a pas de
  notion de « corpus » ni d'« exemple volontaire » — à traiter par une exclusion
  de chemins dans `audit.py` plutôt qu'en tordant le motif.
- Étendre l'extraction aux sources tier 1 acquises encore inexploitées : React,
  Next.js (442 docs archivés, non lus), RFC OAuth/JWT, NIST, PostgreSQL.
  ⚠️ L'archive FastAPI est **partielle** — seulement `advanced/`, `deployment/`
  et `tutorial/security/` (48 docs) ; il n'y a pas de `tutorial/*.md` général,
  ce qui a limité l'extraction sur CORS et `response_model`.
  Cheat sheets exploitées à ce jour : **18 sur 120** (29 documents distincts
  cités, toutes sources confondues).
- Ingérer CWE/CAPEC depuis leurs dumps XML pour peupler les champs `cwe` des
  règles existantes (parseur dédié, pas d'extraction LLM — c'est de la donnée
  structurée).
- Acquérir le tier 2 (**0/30 acquis** à ce jour) quand le tier 1 est exploité.
- Brancher les agents correcteurs sur `autofix: safe` (aucun aujourd'hui —
  volontaire : on ne laisse pas un agent réécrire du code avant que la base soit
  éprouvée).
