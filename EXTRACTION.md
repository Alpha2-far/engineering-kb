# Contrat d'extraction — à lire avant de produire une seule règle

Tu transformes un document officiel **déjà archivé localement** en règles
exploitables par un agent d'audit. Tu ne cherches rien sur le web : tout ce dont
tu as besoin est dans `kb/raw/`.

## La règle qui gouverne toutes les autres

**Une règle sans citation retrouvable dans le document archivé sera rejetée
automatiquement.** Le validateur (`kb/src/kb/ground.py`) normalise ta citation et
la cherche dans le fichier. Si elle n'y est pas, la règle disparaît — personne ne
la relira, personne ne la repêchera.

Conséquence pratique : **copie-colle** la citation depuis le fichier. Ne la
reformule pas, ne la « nettoie » pas, ne la reconstruis pas de mémoire. Une
citation approximative est le seul moyen de perdre du travail ici.

Tu peux couper une phrase, mais garde ≥ 40 caractères de texte littéral contigu.

## Ce qui fait une bonne règle

Une bonne règle **se déclenche sur du code réel**. Le test à s'appliquer :

> « Un agent qui lit cette règle et un dépôt, peut-il dire *ce fichier, cette
> ligne, voilà le problème* ? »

Si la réponse est non, la règle est du bruit — même si elle est vraie.

| Mauvais | Bon |
|---|---|
| « Utiliser une authentification robuste » | « Un JWT doit être vérifié avec un algorithme explicitement listé ; accepter `alg` depuis le token permet `alg: none` » |
| « Attention aux injections SQL » | « Toute requête construite par f-string/concaténation avec une variable est vulnérable : détecter `execute(f"`, `execute("... " +` » |
| « Configurer CORS correctement » | « `allow_origins=["*"]` avec `allow_credentials=True` est refusé par le navigateur et signale une intention de contournement : détecter les deux ensemble » |

## Le champ `detection` est le cœur

C'est ce qui différencie cette base d'un article de blog. Chaque règle porte au
moins une condition **mécanique** :

- `grep` — regex qui trouve le motif fautif. `pattern: "execute\\(f[\"']"`
- `absent` — regex d'un motif qui **devrait** être là et manque (ex. `ENABLE ROW LEVEL SECURITY` sur une table)
- `config` — clé/valeur dans un fichier de config
- `dependency` — présence ou version d'une dépendance
- `ast` — structure du code, quand une regex ne suffit pas
- `manual` — jugement humain requis

`manual` est autorisé mais **interdit comme seule détection** sur une règle
`critical`/`high` : une règle grave qui ne se déclenche jamais ne protège rien.
Le schéma refuse ce cas.

Renseigne `applies_to` avec des globs (`["**/*.py"]`) : c'est ce qui évite qu'une
règle Python soit testée sur du CSS.

## `severity` — la conséquence, pas l'agacement

- `critical` — compromission directe : exécution de code, contournement d'auth, fuite de données inter-tenant, secret exposé
- `high` — faille exploitable sous condition, ou perte d'intégrité
- `medium` — durcissement réel, défense en profondeur
- `low` — hygiène
- `info` — convention, lisibilité

`critical` et `high` **exigent** `vulnerable_example` **et** `fixed_example`
(le schéma les impose). Une alerte grave sans montrer le correctif oblige
l'humain à repartir de zéro au pire moment.

## `confidence` — fidélité à la source, pas ton avis

- `high` — la source l'énonce explicitement (« MUST », « never », « required »)
- `medium` — la source le recommande, ou tu as reformulé une exigence diffuse
- `low` — tu l'as déduite du contexte

Ne gonfle pas la confiance. `low` est une information utile ; un `high` faux
détruit la valeur de tout le champ.

## `autofix` — droit d'écriture d'un agent correcteur

- `safe` — substitution mécanique sans changement de comportement (exige `fixed_example`)
- `review` — correctif proposé, validation humaine (**défaut**)
- `never` — dépend d'une décision métier ou d'architecture

En cas de doute : `review`. Un `safe` mal placé casse du code en production.

## `context` — ce qui rend le routage possible

Remplis `languages` / `frameworks` / `platforms` / `project_types` dès que la
règle est spécifique. **Laisse vide seulement si la règle est vraiment
universelle** — un champ vide la fait entrer dans *tous* les profils, y compris
l'audit d'un site statique vanilla.

`project_types` connus : `static-site`, `saas`, `ai-rag`, `api`, `pipeline`, `cli`, `mobile`.

Le profil `cli` couvre un outil en ligne de commande : un process local, sans
surface HTTP, dont les entrees arrivent par `argv`, `stdin`, les variables
d'environnement et des chemins de fichiers fournis par l'utilisateur. Il partage
beaucoup avec `pipeline` ; ce qui lui est propre est la ligne de commande
elle-meme (arguments passes a un shell, secrets visibles dans `ps`, chemins non
bornes, permissions du fichier de configuration).

## Ce qu'il ne faut pas extraire

- **Le narratif.** Historique, remerciements, « pourquoi ce document existe ».
- **La redite.** Un document répète souvent la même exigence dans trois sections : une règle, plusieurs `evidence`.
- **La documentation de référence pure.** La signature d'une fonction n'est pas une règle.
- **Ce que tu sais sans que le document le dise.** Ta connaissance générale n'est pas une source. Si le document ne le dit pas, ça n'entre pas — c'est précisément ce que le portail d'ancrage vérifie.

## Format de sortie

Un fichier `kb/rules/<source_id>.yaml` :

```yaml
source_id: owasp-cheatsheets
rules:
  - id: authentication/jwt/algorithm-must-be-pinned   # categorie/sous-categorie/slug
    title: L'algorithme de vérification d'un JWT doit être fixé côté serveur
    category: authentication          # vocabulaire fermé, voir schema.py
    subcategory: jwt                  # doit correspondre au 2e segment de l'id
    severity: critical
    confidence: high
    description: >
      Le serveur doit imposer la liste des algorithmes acceptés lors de la
      vérification, au lieu de lire `alg` dans l'en-tête du token.
    rationale: >
      Un attaquant qui contrôle l'en-tête peut poser `alg: none` ou substituer
      HMAC à RSA, faisant valider un token qu'il a forgé avec la clé publique.
    remediation: >
      Passer explicitement `algorithms=["RS256"]` à la fonction de décodage et
      rejeter tout autre algorithme.
    context:
      languages: [python]
      frameworks: [fastapi]
      project_types: [saas, api, ai-rag]
    detection:
      - kind: grep
        pattern: "jwt\\.decode\\([^)]*verify\\s*=\\s*False"
        applies_to: ["**/*.py"]
        note: vérification désactivée
      - kind: absent
        pattern: "algorithms\\s*="
        applies_to: ["**/*.py"]
        note: décodage sans liste blanche d'algorithmes
    autofix: review
    vulnerable_example:
      lang: python
      code: |
        payload = jwt.decode(token, key, options={"verify_signature": False})
    fixed_example:
      lang: python
      code: |
        payload = jwt.decode(token, key, algorithms=["RS256"], audience=EXPECTED_AUD)
    evidence:
      - source_id: owasp-cheatsheets
        doc_path: owasp-cheatsheets/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.md
        doc_sha256: "<sha256 exact repris du manifeste>"
        quote: "<>= 40 caracteres copies-colles du fichier>"
        url: https://cheatsheetseries.owasp.org/cheatsheets/...
        anchor: Token sighting
    cwe: [CWE-347]
    owasp: ["A07:2025"]
    tags: [jwt, auth]
    extracted_at: "2026-07-28"
    extractor: <ton identifiant>
```

`doc_path` et `doc_sha256` se lisent dans `kb/raw/manifest.jsonl` — ne les
invente jamais, un sha256 faux fait rejeter la règle.

## Vérifie avant de rendre

```bash
cd kb && uv run kb validate
```

Le rapport te dit exactement quelle règle a été rejetée et pourquoi.
Viser **zéro rejet en `grounding`** : un rejet d'ancrage signifie que la citation
a été reconstruite au lieu d'être copiée.
