# Regles compilees — Knowledge Base d'ingenierie

> Genere le 2026-09-08 — 47 regles. **Ne pas editer a la main** :
> ce fichier est produit par `uv run kb compile`. Corriger la source dans `kb/rules/`.

Chaque regle porte une citation verifiee dans un document officiel archive.
Une regle dont la citation n'a pas pu etre retrouvee a ete rejetee et n'apparait pas ici.


## ai-ml

### `KB-0007` · CRITICAL · Parametrer toute requete SQL construite a partir d'une sortie de modele

- **id** : `ai-ml/output-handling/llm-generated-sql-not-parameterized`
- **exige** : Une valeur issue d'un LLM qui entre dans une requete SQL doit passer par un parametre lie, jamais par une f-string, une concatenation ou un formatage de chaine.
- **pourquoi** : Le modele produit du texte, et rien ne garantit que ce texte respecte le role syntaxique qu'on lui destine. Une valeur contenant une apostrophe et un point-virgule referme la requete et en ouvre une autre, avec les droits de la connexion applicative. Le cas est aggrave par rapport a l'injection classique : la charge peut venir d'un document indexe, donc d'un canal que l'equipe considere comme interne.
- **correction** : Utiliser des requetes parametrees ou des instructions preparees pour toute operation impliquant une sortie de modele. Si c'est la structure de la requete qui est generee (colonne, tri), la valider contre une liste d'autorisation explicite plutot que de l'echapper.
- **portee** : python, typescript, sql, sqlalchemy, fastapi, postgresql, supabase
- **detection** : `grep:(?i)(execute|executemany|text)\s*\(\s*f["']`; `grep:(?i)(select|insert|update|delete)\s[^;]{0,200}["']\s*[%+]\s*\w`
- **source** : [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM05_ImproperOutputHandling.md), [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM05_ImproperOutputHandling.md) · confiance high

### `KB-0009` · CRITICAL · Ne jamais passer une sortie de modele a exec, eval ou un shell

- **id** : `ai-ml/output-handling/llm-output-passed-to-exec`
- **exige** : Le texte produit par un LLM ne doit jamais atteindre eval, exec, os.system, subprocess avec shell, ni aucun evaluateur dynamique, directement ou apres concatenation.
- **pourquoi** : La sortie du modele est controlable par l'entree, donc par un attaquant, y compris de facon indirecte via un document recupere. La donner a un evaluateur revient a exposer un interpreteur de commandes a l'exterieur, avec les privileges du processus applicatif. C'est le chemin le plus court entre une injection de prompt et une execution de code a distance.
- **correction** : Remplacer l'evaluation dynamique par un aiguillage vers un ensemble ferme d'operations nommees, valide contre une liste d'autorisation. Si un sous-processus est indispensable, passer une liste d'arguments sans shell et valider chaque valeur contre un motif strict.
- **portee** : python, typescript, javascript
- **detection** : `grep:(?i)\b(eval|exec)\s*\(|os\.system\s*\(|subprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True`; `grep:\b(eval|new\s+Function)\s*\(|child_process\.(exec|execSync)\s*\(`
- **source** : [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM05_ImproperOutputHandling.md), [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM05_ImproperOutputHandling.md) · confiance high

### `KB-0015` · CRITICAL · Filtrer la recherche vectorielle par tenant avant le calcul de similarite

- **id** : `ai-ml/rag/vector-search-without-tenant-filter`
- **exige** : Toute requete de similarite sur une base vectorielle partagee doit porter un filtre d'appartenance (tenant, organisation, utilisateur) applique cote base, et non un tri des resultats apres coup.
- **pourquoi** : Un index vectoriel n'a aucune notion de propriete : il retourne les k plus proches voisins de l'embedding, tous locataires confondus. Sans predicat de partitionnement dans la requete, un cabinet peut recevoir en contexte le passage d'un dossier appartenant a un autre cabinet, et le LLM le restituera comme s'il s'agissait de sa propre matiere. La fuite est invisible dans les logs applicatifs : la reponse est bien formee, seulement fondee sur la mauvaise source.
- **correction** : Poser le filtre dans la clause WHERE de la requete de similarite, ou activer Row Level Security sur la table d'embeddings pour que le predicat soit impose par le moteur meme si l'appelant l'oublie. Ne jamais se contenter de filtrer la liste de resultats en Python : le top-k a deja ete calcule sur le corpus entier, et les documents legitimes ont pu etre evinces.
- **portee** : python, sql, typescript, langchain, llamaindex, supabase, postgresql, pgvector
- **detection** : `grep:(?i)order\s+by\s+[\w."]+\s*<[=\-~]>`; `grep:(?i)\.(rpc|similarity_search|max_marginal_relevance_search)\s*\(`
- **source** : [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM08_VectorAndEmbeddingWeaknesses.md), [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM08_VectorAndEmbeddingWeaknesses.md) · confiance high


## app-security

### `KB-0018` · CRITICAL · Ne jamais construire une commande shell par concatenation d'entree utilisateur

- **id** : `app-security/command-injection/user-input-concatenated-into-shell`
- **exige** : Un CLI qui compose une commande systeme en concatenant un argument recu (argv, stdin, variable d'environnement) doit passer par une API qui separe le programme de ses arguments, sans shell intermediaire.

- **pourquoi** : Le shell interprete les metacaracteres `& | ; $ > < ` \ ! ' " ( )`. Un argument contenant l'un d'eux ne complete plus la commande : il en ajoute une seconde, qui s'execute avec les privileges du process appelant. En Python, c'est exactement ce que `shell=True` reintroduit apres qu'une liste d'arguments l'ait supprime.

- **correction** : Passer une liste d'arguments a `subprocess.run([...])` sans `shell=True`. Bannir `os.system` et `os.popen`. Si le shell est inevitable, valider les arguments contre une allowlist stricte avant de les composer.

- **portee** : python, javascript, typescript
- **detection** : `grep:shell\s*=\s*True`; `grep:os\.(system|popen)\s*\(`; `grep:child_process\.exec\s*\(`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) · confiance high

### `KB-0020` · CRITICAL · Ne jamais deserialiser un fichier local avec pickle ou yaml.load

- **id** : `app-security/deserialization/untrusted-data-loaded-with-pickle-or-yaml`
- **exige** : Un CLI qui lit un cache, un etat ou une configuration depuis le disque doit utiliser un format de donnees inerte (JSON, `yaml.safe_load`), jamais `pickle.load` ni `yaml.load` sans chargeur sur.

- **pourquoi** : `pickle` et `yaml.load` reconstruisent des objets arbitraires : le document `!!python/object/apply:os.system ['ipconfig']` execute la commande au chargement. Pour un CLI, le fichier n'a pas besoin de venir du reseau — un cache dans un repertoire partage, un artefact de CI ou un fichier de projet clone suffisent a porter la charge.

- **correction** : Remplacer `yaml.load(f)` par `yaml.safe_load(f)`, et `pickle` par JSON. Si un format binaire est indispensable, signer le fichier et verifier la signature avant de le charger.

- **portee** : python
- **detection** : `grep:pickle\.(load|loads)\s*\(`; `grep:yaml\.load\s*\((?![^)]*SafeLoader)`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) · confiance high


## authentication

### `KB-0027` · CRITICAL · Imposer l'algorithme attendu a la verification d'un JWT

- **id** : `authentication/jwt/algorithm-not-pinned-at-verification`
- **exige** : La verification d'un JWT doit exiger explicitement l'algorithme attendu, au lieu de se fier a l'en-tete alg du jeton presente.
- **pourquoi** : L'en-tete du jeton est fourni par celui qui le presente : lui laisser choisir l'algorithme revient a laisser l'attaquant choisir comment sa signature sera verifiee. La valeur none a fait accepter des jetons non signes par plusieurs bibliotheques, et un basculement de RS256 vers HS256 permet de signer avec la cle publique, qui est publique par construction. Le controle doit venir du code du verificateur, pas du jeton.
- **correction** : Passer la liste des algorithmes acceptes a la fonction de verification et refuser tout le reste, y compris none. Verifier egalement les revendications d'emetteur et d'audience, qu'une signature valide ne garantit pas.
- **portee** : python, typescript, fastapi, next, express
- **detection** : `grep:(?i)jwt\.decode\s*\([^)]*verify_signature\s*:\s*False|jwt\.decode\s*\([^)]*options\s*=\s*\{[^}]*verify[^}]*False`; `grep:(?i)(jwt\.decode|jwtVerify|verify)\s*\(\s*\w+\s*,\s*\w+\s*\)`; `grep:(?i)["']alg["']\s*:\s*["']none["']|algorithms\s*=\s*\[[^\]]*none`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html) · confiance high

### `KB-0029` · CRITICAL · Hacher les mots de passe avec Argon2id, scrypt, bcrypt ou PBKDF2

- **id** : `authentication/password-storage/fast-hash-used-for-passwords`
- **exige** : Un mot de passe doit etre hache avec un algorithme lent et parametrable (Argon2id en premier choix, sinon scrypt, bcrypt ou PBKDF2), avec un sel unique par mot de passe. Ni stockage en clair, ni chiffrement reversible, ni fonction de hachage rapide de la famille SHA ou MD5.
- **pourquoi** : SHA-256 est concu pour etre rapide : c'est exactement la propriete que l'attaquant exploite, en essayant des milliards de candidats a la seconde sur un GPU. Un algorithme lent et gourmand en memoire rend chaque essai couteux, et le sel unique interdit d'attaquer toute la base d'un seul calcul. Le chiffrement est exclu parce qu'il est reversible : la cle compromise rend tous les mots de passe en clair.
- **correction** : Utiliser Argon2id avec au minimum 19 MiB de memoire, 2 iterations et 1 degre de parallelisme ; bcrypt avec un facteur de travail d'au moins 10 pour un systeme existant. Passer par la bibliotheque du framework, qui gere le sel, et rehacher au moment de la connexion quand les parametres evoluent.
- **portee** : python, typescript
- **detection** : `grep:(?i)(hashlib\.(md5|sha1|sha256|sha512)|createHash\s*\(\s*["'](md5|sha1|sha256)["'])`; `grep:(?i)(password|mot_de_passe|passwd)\s*=\s*[^=\n]{0,40}(md5|sha1|sha256|sha512|encrypt|cipher)\s*\(`; `absent:(?i)(argon2|bcrypt|scrypt|pbkdf2|passlib|CryptContext)`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) · confiance high


## authorization

### `KB-0031` · CRITICAL · Deriver le locataire de la session authentifiee, jamais de la requete

- **id** : `authorization/multi-tenant/tenant-id-taken-from-request`
- **exige** : L'identifiant de locataire qui sert a filtrer les donnees doit etre lu dans la session ou le jeton verifie, jamais dans un en-tete, un parametre de requete ou un champ du corps fourni par le client.
- **pourquoi** : Un identifiant de locataire transmis par le client est une valeur que le client controle : le modifier suffit a basculer tout le filtrage vers un autre cabinet. Le controle d'acces devient alors declaratif, exactement comme si on demandait poliment a l'appelant de ne pas tricher. Le seul identifiant opposable est celui qui a ete etabli a l'authentification et signe.
- **correction** : Etablir le contexte de locataire tot dans le cycle de requete, a partir de la session, et l'injecter dans la couche d'acces aux donnees. Si un en-tete de locataire existe pour des raisons de routage, verifier qu'il correspond a celui de la session et refuser sinon.
- **portee** : python, typescript, fastapi, next, express, supabase, postgresql
- **detection** : `grep:(?i)(headers|query_params|args|params|body|cookies)[\.\[]\s*["']?[xX]?-?(tenant|org|organisation|organization|account|workspace)[_-]?id`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html) · confiance high

### `KB-0032` · CRITICAL · Verifier la propriete de l'objet a chaque acces par identifiant

- **id** : `authorization/object-level/missing-ownership-check-on-id`
- **exige** : Toute route qui recoit un identifiant d'objet doit verifier, cote serveur, que l'utilisateur authentifie a le droit d'acceder a cet objet precis, avant de le lire ou de le modifier.
- **pourquoi** : Etre authentifie ne dit rien sur ce a quoi on a droit. Sans controle au niveau de l'objet, changer un chiffre dans l'URL suffit a lire le dossier d'un autre client : l'attaque ne demande aucun outil et laisse des traces indistinguables d'un usage normal. Un identifiant difficile a deviner ne remplace pas le controle : une URL partagee ou un journal fuite suffit a l'obtenir.
- **correction** : Charger l'objet avec un predicat de propriete dans la requete meme, plutot que de le charger puis de comparer. Sur Postgres, doubler d'une policy Row Level Security pour que l'oubli d'un filtre ne suffise pas a ouvrir l'acces.
- **portee** : python, typescript, fastapi, next, express, supabase, postgresql
- **detection** : `grep:(?i)\{\s*(id|uuid|\w+_id)\s*(:[^}]*)?\}`; `grep:(?i)\.(get|filter_by|find_one|findUnique|findFirst)\s*\(\s*(id\s*=|\{\s*id\s*:)`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) · confiance high


## database

### `KB-0036` · CRITICAL · Ne jamais exposer la cle de service au navigateur

- **id** : `database/rls/service-key-used-outside-server`
- **exige** : La cle de service Supabase, qui contourne RLS, ne doit apparaitre ni dans du code client, ni dans une variable d'environnement prefixee pour le navigateur. Elle reste sur le serveur, pour des taches d'administration.
- **pourquoi** : Cette cle annule le seul mecanisme qui separe les locataires : elle donne lecture et ecriture sur toutes les lignes de toutes les tables. Livree au navigateur, elle est lisible dans le paquet compile par n'importe quel utilisateur, et la base entiere devient publique. Les prefixes d'exposition des frameworks front — NEXT_PUBLIC_, VITE_, REACT_APP_ — inscrivent la valeur dans le paquet sans avertissement.
- **correction** : Reserver la cle de service au code serveur, sans prefixe d'exposition. Cote navigateur, utiliser exclusivement la cle publique, dont la surface est bornee par les politiques RLS. Toute cle ayant ete exposee est consideree comme compromise et remplacee.
- **portee** : typescript, javascript, python, next, react, vite, supabase
- **detection** : `grep:(?i)(NEXT_PUBLIC|VITE|REACT_APP|PUBLIC|EXPO_PUBLIC)_[A-Z_]*(SERVICE_ROLE|SERVICE_KEY|SECRET)`; `grep:(?i)service_role`
- **source** : [supabase](https://supabase.com/docs/guides/database/postgres/row-level-security), [supabase](https://supabase.com/docs/guides/database/postgres/row-level-security) · confiance high

### `KB-0037` · CRITICAL · Activer RLS sur toute table d'un schema expose par l'API

- **id** : `database/rls/table-in-exposed-schema-without-rls`
- **exige** : Toute table creee dans un schema expose par l'API — le schema public par defaut — doit avoir la securite au niveau des lignes activee, et les privileges accordes role par role.
- **pourquoi** : Le modele Supabase repose sur un acces direct depuis le navigateur : la cle publique est, par construction, entre les mains de tous les utilisateurs. Ce qui separe les donnees d'un cabinet de celles d'un autre n'est donc pas le reseau ni le code applicatif, c'est uniquement la politique RLS. Une table creee en SQL brut n'en a aucune : elle est integralement lisible par toute personne detenant la cle publique. L'editeur de tables du tableau de bord active RLS automatiquement, ce qui rend l'oubli invisible jusqu'au jour ou la table a ete creee par migration.
- **correction** : Faire suivre chaque create table d'un alter table enable row level security dans la meme migration, puis ecrire les politiques. Verifier en revue que toute migration ajoutant une table dans le schema public comporte les deux.
- **portee** : sql, supabase, postgresql
- **detection** : `grep:(?i)create\s+table\s+(if\s+not\s+exists\s+)?(public\.)?[\w"]+`; `absent:(?i)enable\s+row\s+level\s+security`
- **source** : [supabase](https://supabase.com/docs/guides/database/postgres/row-level-security), [supabase](https://supabase.com/docs/guides/database/postgres/row-level-security) · confiance high

### `KB-0039` · CRITICAL · Parametrer les requetes SQL au lieu de concatener les entrees

- **id** : `database/sql-injection/dynamic-query-string-concatenation`
- **exige** : Toute requete SQL doit etre construite avec des parametres lies : le code SQL est defini d'abord, les valeurs sont passees ensuite. Aucune donnee externe ne doit etre inseree par concatenation, f-string ou formatage de chaine.
- **pourquoi** : Une requete construite par concatenation ne distingue plus le code de la donnee : le moteur recoit une seule chaine et l'analyse entierement comme du SQL. Une valeur contenant une apostrophe referme la chaine litterale et le reste de l'entree devient de la syntaxe executable, avec les droits de la connexion applicative. Le parametrage supprime la classe entiere de defauts plutot que de filtrer ses manifestations.
- **correction** : Utiliser des instructions preparees ou des requetes parametrees partout. Quand c'est la structure de la requete qui varie (nom de colonne, sens du tri), valider la valeur contre une liste d'autorisation explicite : le parametrage ne couvre que les valeurs, pas les identifiants.
- **portee** : python, typescript, sql, sqlalchemy, fastapi, prisma, postgresql, supabase
- **detection** : `grep:(?i)(execute|executemany|raw|query|text)\s*\(\s*f["']`; `grep:(?i)(select|insert\s+into|update|delete\s+from)\s[^;'"]{0,200}["']\s*[%+]\s*\w`; `grep:\$queryRawUnsafe|\$executeRawUnsafe`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) · confiance high


## devops

### `KB-0043` · CRITICAL · Passer le contexte GitHub par variable d'environnement, jamais dans run

- **id** : `devops/github-actions/context-interpolated-into-run-block`
- **exige** : Une expression de contexte GitHub ne doit pas etre interpolee directement dans un bloc run : la valeur transite par une variable d'environnement intermediaire, qui est ensuite referencee dans le script.
- **pourquoi** : L'interpolation a lieu avant l'execution du shell : la valeur est collee dans le script, si bien qu'un titre de pull request contenant une substitution de commande devient du code execute par le coureur. Ce coureur detient le jeton du depot et les secrets du workflow : l'injection donne donc acces a la chaine de livraison, pas seulement au job. Le passage par l'environnement supprime l'etape d'interpolation.
- **correction** : Declarer la valeur dans env au niveau de l'etape, puis la referencer par la syntaxe du shell dans run. Appliquer la regle a tous les contextes, y compris ceux qui paraissent surs, pour ne pas avoir a juger au cas par cas.
- **portee** : github-actions
- **detection** : `grep:\$\{\{\s*(github|inputs|env)\.[^}]*(title|body|message|name|label|ref|head_ref|email|description)[^}]*\}\}`; `grep:pull_request_target`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html) · confiance high

### `KB-0045` · CRITICAL · Ne jamais ecrire un secret dans le code ou un fichier de configuration suivi

- **id** : `devops/secrets/secret-hardcoded-in-source`
- **exige** : Cles d'API, identifiants de base, jetons et cles privees ne doivent figurer ni dans le code source, ni dans un fichier de configuration versionne, ni dans une instruction ENV ou ARG d'image Docker.
- **pourquoi** : Un secret commite est diffuse a toute personne ayant acces au depot, present dans chaque copie locale, et conserve dans l'historique meme apres suppression du fichier. Le retirer ne suffit donc jamais : il faut le faire tourner. Dans une image, ENV et ARG fuient avec la definition du conteneur, que l'on peut lire sans l'executer.
- **correction** : Charger les secrets depuis un gestionnaire dedie ou la configuration d'environnement de la plateforme, faire echouer le demarrage en cas d'absence, et poser une analyse de secrets en pre-commit et sur les pull requests. Tout secret ayant ete expose est considere comme compromis et remplace.
- **portee** : python, typescript
- **detection** : `grep:(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key|client[_-]?secret|service[_-]?role[_-]?key|password)\s*[:=]\s*["'][A-Za-z0-9_\-/+.]{20,}["']`; `grep:(?i)(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)`; `grep:(?i)^\s*(ENV|ARG)\s+\w*(SECRET|TOKEN|KEY|PASSWORD)\w*\s*=`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) · confiance high


## ai-ml

### `KB-0001` · HIGH · Soumettre toute action a fort impact a une approbation humaine

- **id** : `ai-ml/agency/high-impact-tool-without-human-approval`
- **exige** : Un outil qui supprime, envoie, publie, paie ou deploie ne doit pas s'executer sur la seule decision du modele : l'action est preparee, presentee, puis confirmee par un humain avant d'etre effectuee.
- **pourquoi** : L'autonomie excessive rend irreversible ce qui aurait du etre une proposition. Une hallucination sur un identifiant, ou une instruction glissee dans un document, suffisent alors a produire un effet que l'on ne peut pas defaire : un courriel parti, un dossier supprime, un virement emis. Le point de controle humain ne corrige pas le modele, il borne le domaine de ses erreurs.
- **correction** : Scinder l'outil en deux temps : une fonction qui prepare et retourne l'action envisagee, et une fonction d'execution qui exige un jeton de confirmation emis par l'interface apres validation. Poser la mediation dans le systeme en aval quand c'est possible, pas seulement dans l'outil.
- **portee** : python, typescript
- **detection** : `grep:(?i)(def|async\s+def|function|const)\s+\w*(delete|remove|drop|send|email|pay|transfer|refund|publish|deploy|revoke)\w*\s*[\(=]`; `absent:(?i)(confirm|approval|approve|human_in_the_loop|pending_review|require_confirmation)`
- **source** : [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM06_ExcessiveAgency.md), [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM06_ExcessiveAgency.md) · confiance high

### `KB-0003` · HIGH · Restreindre l'identite base de donnees d'un outil a ses operations utiles

- **id** : `ai-ml/agency/tool-identity-has-write-permissions`
- **exige** : L'identite avec laquelle un outil appele par un modele se connecte aux systemes en aval ne doit porter que les droits necessaires a sa fonction : un outil de lecture se connecte avec un role limite au SELECT sur les tables concernees.
- **pourquoi** : Un outil de consultation branche sur une identite qui possede aussi INSERT, UPDATE et DELETE transforme n'importe quel derapage du modele en ecriture destructrice. Le probleme n'est pas la qualite du modele : la premiere hallucination venue, ou la premiere injection indirecte, disposera de tous les droits de la connexion. La borne doit etre posee par la base, pas par la docstring de l'outil.
- **correction** : Creer un role dedie par outil, avec les seuls GRANT necessaires, et l'utiliser dans la chaine de connexion de cet outil. Sur Supabase, ne jamais utiliser la cle service_role dans un outil expose au modele : elle contourne Row Level Security.
- **portee** : python, sql, typescript, supabase, postgresql
- **detection** : `grep:(?i)service[_-]?role`; `grep:(?i)grant\s+(all|insert|update|delete|truncate)`
- **source** : [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM06_ExcessiveAgency.md), [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM06_ExcessiveAgency.md) · confiance high

### `KB-0005` · HIGH · Limiter le debit et poser des quotas sur les endpoints d'inference

- **id** : `ai-ml/inference/llm-endpoint-without-rate-limit`
- **exige** : Toute route qui declenche un appel a un modele doit etre protegee par une limitation de debit et un quota par entite appelante, appliques avant l'appel au fournisseur.
- **pourquoi** : Un appel d'inference coute de l'argent reel a chaque requete. Sans borne, une boucle laissee ouverte ou un tiers malveillant transforme le produit en facture : c'est le deni de portefeuille, ou l'attaquant ne cherche pas a faire tomber le service mais a le rendre insoutenable. Le meme canal permet d'extraire assez de sorties pour repliquer le comportement du systeme.
- **correction** : Poser une limitation par cle d'API et par utilisateur devant la route, avec un quota journalier distinct du debit instantane, et refuser la requete avant d'engager le cout. Surveiller la consommation par locataire pour reperer une derive avant la facture.
- **portee** : python, typescript, fastapi, next, express
- **detection** : `absent:(?i)(rate_?limit|ratelimit|slowapi|limiter|throttl|quota|Depends\(\s*\w*[Ll]imit)`; `grep:(?i)(anthropic|openai|mistral|groq|cohere)[\w.]*\.(messages|chat|completions|responses)\.(create|stream)`
- **source** : [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM10_UnboundedConsumption.md), [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM10_UnboundedConsumption.md) · confiance high

### `KB-0008` · HIGH · Encoder la sortie du modele avant de la rendre dans le navigateur

- **id** : `ai-ml/output-handling/llm-markdown-rendered-unescaped`
- **exige** : Le texte ou le Markdown produit par un LLM ne doit jamais etre injecte dans le DOM sans encodage ni assainissement, ni via innerHTML, dangerouslySetInnerHTML ou un rendu Markdown autorisant le HTML brut.
- **pourquoi** : Le modele peut etre amene a produire une balise script, un attribut de gestionnaire d'evenement ou une image pointant vers un serveur controle par un tiers. Rendue telle quelle, cette sortie s'execute dans la session de la victime : c'est un XSS dont la charge a transite par le modele, et dont la source peut etre un document indexe plutot qu'un champ de saisie.
- **correction** : Rendre le Markdown avec le HTML brut desactive et passer le resultat par un assainisseur avec liste d'autorisation. Poser une Content Security Policy stricte pour que meme un script injecte ne s'execute pas.
- **portee** : typescript, javascript, react, next, vue
- **detection** : `grep:dangerouslySetInnerHTML|\.innerHTML\s*=|v-html|\{\@html`; `grep:(?i)(marked|markdown-it|showdown)[\s\S]{0,120}(html\s*:\s*true|allowDangerousHtml|skipHtml\s*:\s*false)`
- **source** : [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM05_ImproperOutputHandling.md), [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM05_ImproperOutputHandling.md) · confiance high

### `KB-0010` · HIGH · Ne jamais confier un secret ou un jeton privilegie au modele

- **id** : `ai-ml/prompt-injection/model-holds-privileged-credentials`
- **exige** : Les jetons d'API, cles de service et identifiants ne doivent jamais figurer dans un prompt, une description d'outil ou un argument que le modele peut choisir : l'application detient ses propres jetons et appelle les fonctions depuis le code.
- **pourquoi** : Tout ce qui entre dans la fenetre de contexte est extractible par injection ou par fuite de prompt systeme. Un secret place la devient une donnee que le modele peut restituer, et le privilege qu'il porte s'ajoute a la surface d'attaque du modele au lieu de rester dans l'application. Le modele n'a pas besoin du secret : il a besoin qu'une fonction s'execute.
- **correction** : Deplacer les secrets dans la configuration serveur, exposer au modele une fonction sans parametre d'authentification, et resoudre les identifiants cote code au moment de l'appel. Si un outil doit agir pour le compte d'un utilisateur, resoudre son jeton depuis la session, jamais depuis un argument produit par le modele.
- **portee** : python, typescript
- **detection** : `grep:(?i)(api[_-]?key|secret|token|password|service[_-]?role)\s*[:=]\s*["'][^"']{16,}`; `grep:(?i)def\s+\w+\s*\([^)]*\b(api_key|token|secret|credential)\b[^)]*\)`
- **source** : [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM01_PromptInjection.md) · confiance high

### `KB-0011` · HIGH · Delimiter explicitement le contenu externe injecte dans un prompt

- **id** : `ai-ml/prompt-injection/untrusted-content-not-delimited`
- **exige** : Tout contenu d'origine externe interpole dans un prompt (chunks recuperes, page web, fichier televerse, message d'un tiers) doit etre entoure de delimiteurs qui le designent comme donnee non fiable, et le prompt systeme doit dire au modele de ne pas y obeir.
- **pourquoi** : Concatener un document dans un prompt sans marqueur place la matiere externe et les consignes du developpeur au meme niveau : le modele ne dispose d'aucune information lui permettant de distinguer les deux. Une phrase imperative presente dans un document recupere est alors traitee comme une instruction legitime. La delimitation ne rend pas l'injection impossible, mais elle retire l'ambiguite dont l'attaque depend entierement.
- **correction** : Encadrer chaque bloc externe par un delimiteur explicite (balise nommee, separateur unique) en indiquant sa provenance, et enoncer dans le prompt systeme que le contenu ainsi delimite est une donnee a analyser et jamais une consigne a suivre. Ne jamais laisser l'utilisateur choisir le delimiteur.
- **portee** : python, typescript, langchain, llamaindex, fastapi
- **detection** : `grep:\{\s*(context|documents|docs|chunks|retrieved|content|page|text|user_input)\s*\}`; `grep:(?i)(system|prompt|messages)\s*=\s*f?["']{1,3}[\s\S]{0,400}\+\s*(context|document|chunk|content)`
- **source** : [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM01_PromptInjection.md), [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM01_PromptInjection.md) · confiance high

### `KB-0013` · HIGH · Valider et nettoyer un document avant son entree dans la base de connaissance

- **id** : `ai-ml/rag/ingested-document-not-sanitized`
- **exige** : Un document ingere dans un index RAG doit passer par une extraction de texte qui ignore la mise en forme et detecte le contenu dissimule, et par une validation explicite, avant d'etre decoupe et vectorise.
- **pourquoi** : Le texte cache dans un document (blanc sur blanc, taille nulle, calque invisible, metadonnees PDF) est illisible pour l'humain qui depose le fichier mais parfaitement lisible pour l'extracteur. Il devient un chunk comme un autre, remonte au titre de sa pertinence, et se retrouve dans le contexte du modele avec le meme statut que la matiere legitime. C'est une injection indirecte deposee par la voie normale du produit, sans exploit.
- **correction** : Extraire le texte via un outil qui rend la mise en forme (couleur, taille, opacite, calques) pour pouvoir la controler, rejeter ou signaler les segments invisibles, et journaliser la decision par document. Traiter tout contenu ingere comme non fiable jusqu'a validation.
- **portee** : python, typescript, fastapi, langchain, llamaindex
- **detection** : `grep:(?i)(pypdf|PdfReader|pdfplumber|fitz\.open|extract_text|docx2txt|UnstructuredFileLoader|mammoth)`; `absent:(?i)(sanitiz|validate_document|hidden_text|suspicious|quarantine)`
- **source** : [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM08_VectorAndEmbeddingWeaknesses.md), [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM08_VectorAndEmbeddingWeaknesses.md) · confiance high


## api

### `KB-0016` · HIGH · Ne pas lier directement le corps de requete au modele persiste

- **id** : `api/mass-assignment/request-body-bound-to-model`
- **exige** : Le corps d'une requete ne doit pas etre affecte en bloc a l'objet persiste : la couche d'entree declare explicitement les champs modifiables, et les attributs sensibles n'y figurent pas.
- **pourquoi** : La liaison automatique cree des parametres que le developpeur n'a jamais prevus : il suffit d'ajouter un champ au corps JSON pour ecrire un attribut qui n'apparait dans aucun formulaire. C'est ainsi qu'un utilisateur se donne un role d'administrateur, change le proprietaire d'un objet ou remet a zero un compteur de facturation, sans qu'aucune route dediee n'existe.
- **correction** : Definir un schema d'entree ne contenant que les champs que le client a le droit d'ecrire, refuser les champs inconnus, et recopier explicitement vers le modele. Ne jamais construire l'entite a partir du dictionnaire brut de la requete.
- **portee** : python, typescript, fastapi, pydantic, prisma, express
- **detection** : `grep:(?i)(Model|User|Account|Order|Dossier|\w+)\s*\(\s*\*\*\s*(request|payload|body|data|dto)\b`; `grep:(?i)(setattr\s*\(|Object\.assign\s*\(|\.\.\.\s*(req\.body|body|payload)\b)`; `grep:(?i)model_config\s*=\s*ConfigDict\((?![^)]*extra)`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html) · confiance high


## app-security

### `KB-0017` · HIGH · Coder en dur l'executable appele plutot que de le lire depuis l'entree

- **id** : `app-security/command-injection/executable-chosen-by-user-input`
- **exige** : Le nom du programme lance par un CLI doit etre fixe dans le code ou resolu contre une liste d'autorisation explicite, jamais compose a partir d'un argument, d'une variable d'environnement ou d'un fichier de config.

- **pourquoi** : Si l'appelant choisit le binaire, aucune validation d'argument ne compte : il ne detourne plus la commande, il en designe une autre. La commande elle-meme doit etre validee contre une liste d'autorisation, au meme titre que ses arguments.

- **correction** : Definir un dictionnaire des commandes permises et n'accepter qu'une cle de ce dictionnaire. Refuser toute valeur absente de la liste au lieu de la nettoyer.

- **portee** : python, javascript, typescript
- **detection** : `grep:subprocess\.(run|Popen|call)\s*\(\s*(args\.|os\.environ|sys\.argv|config\[)`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) · confiance high

### `KB-0019` · HIGH · Terminer les options par -- avant toute valeur fournie par l'utilisateur

- **id** : `app-security/command-injection/user-input-passed-as-command-option`
- **exige** : Meme sans shell, une valeur utilisateur placee sur une ligne de commande doit etre separee des options par le delimiteur `--`, sinon une valeur qui commence par `-` est interpretee comme un drapeau du programme appele.

- **pourquoi** : Echapper les metacaracteres ne protege que du shell, pas du programme invoque. Une valeur comme `--output=/etc/cron.d/x` reste un argument parfaitement valide : l'attaquant ne lance pas une seconde commande, il detourne la premiere. C'est l'injection d'argument, et elle survit a `escapeshellarg()` comme a une liste `subprocess`.

- **correction** : Inserer `--` entre les options fixes et les valeurs variables (`["curl", "--", url]`). Coder en dur le binaire et ses drapeaux ; ne jamais laisser l'utilisateur choisir l'executable.

- **portee** : python, javascript, typescript
- **detection** : `grep:subprocess\.(run|call|check_output|Popen)\s*\(\s*\[[^\]]*(args|argv|sys\.argv|input|user)`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) · confiance high

### `KB-0022` · HIGH · Valider extension et type reel d'un fichier televerse, et le renommer

- **id** : `app-security/file-upload/extension-and-type-not-validated`
- **exige** : Un fichier televerse doit etre accepte sur liste d'extensions autorisees, voir son type reel controle sans se fier a l'en-tete Content-Type, etre renomme par l'application, et etre stocke hors de la racine web.
- **pourquoi** : L'extension et le Content-Type sont fournis par le client : les deux se falsifient trivialement. Un fichier accepte sur sa seule extension declaree, conserve sous le nom choisi par l'appelant et depose dans un repertoire servi par le serveur web, permet de deposer puis d'invoquer du code. La double extension et l'octet nul contournent en outre les filtres naifs.
- **correction** : Autoriser explicitement les seules extensions utiles au metier, verifier la signature reelle du contenu, generer un nom aleatoire cote application, et servir les fichiers par un gestionnaire qui fait correspondre un identifiant au fichier plutot que d'exposer le chemin.
- **portee** : python, typescript, fastapi, next, express
- **detection** : `grep:(?i)\.(filename|originalname|content_type|mimetype)\b`; `absent:(?i)(ALLOWED_EXTENSIONS|allowed_types|allowlist|uuid4|token_hex|randomUUID|magic|filetype|imghdr)`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) · confiance high

### `KB-0023` · HIGH · Exclure secrets et donnees sensibles des journaux

- **id** : `app-security/logging/secrets-written-to-logs`
- **exige** : Les journaux ne doivent contenir ni mot de passe, ni jeton d'acces, ni identifiant de session, ni chaine de connexion, ni cle de chiffrement, ni donnee personnelle sensible : ces valeurs sont retirees, masquees ou hachees avant ecriture.
- **pourquoi** : Un journal circule bien plus largement que la base : il est agrege, expedie vers un service tiers, conserve longtemps et lu par des personnes qui n'ont pas acces a la production. Un secret qui y apparait est donc diffuse au-dela de tout controle, et sa rotation devient obligatoire des qu'on s'en apercoit. Pour un cabinet, la meme logique vaut pour la donnee client.
- **correction** : Poser un filtre de redaction dans la configuration de journalisation plutot que de compter sur la vigilance a chaque appel, ne jamais journaliser un objet de requete entier, et verifier les traces d'exception qui embarquent souvent les parametres.
- **portee** : python, typescript
- **detection** : `grep:(?i)(logger|log|console)\.(debug|info|warn|warning|error)\s*\([^)]{0,120}\b(password|passwd|secret|token|api_key|apikey|authorization|credential|connection_string)\b`; `grep:(?i)(logger|log|console)\.(debug|info|warn|warning|error)\s*\(\s*[^)]{0,40}\b(request|req|payload|body|headers|event)\s*\)`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) · confiance high

### `KB-0024` · HIGH · Confiner tout chemin de fichier construit a partir d'une entree utilisateur

- **id** : `app-security/path-traversal/user-controlled-path-not-confined`
- **exige** : Un chemin bati a partir d'un argument ou d'un nom de fichier fourni doit etre resolu en chemin canonique puis verifie comme etant sous un repertoire de base autorise, avant toute lecture ou ecriture.

- **pourquoi** : `os.path.join(base, user)` ne confine rien : si `user` est absolu, la base est ecartee ; s'il contient `../`, la resolution sort du repertoire. Un CLI tourne avec les droits de celui qui le lance — souvent son poste de travail entier, parfois root en CI. La resolution canonique est la seule verification qui tienne.

- **correction** : Resoudre avec `Path(base).resolve()` et `Path(base, user).resolve()`, puis exiger `resolved.is_relative_to(base)`. Preferer un nom genere en interne au nom fourni par l'utilisateur.

- **portee** : python, javascript, typescript
- **detection** : `grep:os\.path\.join\s*\([^)]*(args\.|sys\.argv|input\(|request\.)`; `grep:open\s*\(\s*(args\.|sys\.argv)`
- **source** : [owasp-asvs](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x14-V5-File-Handling.md), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) · confiance high

### `KB-0025` · HIGH · Ne jamais recevoir un secret par argument de ligne de commande

- **id** : `app-security/secrets/secret-passed-as-command-line-argument`
- **exige** : Un CLI ne doit pas accepter cle d'API, mot de passe ou jeton via une option de ligne de commande. Il les lit depuis un fichier a permissions restreintes, l'entree standard, ou un gestionnaire de secrets.

- **pourquoi** : Les arguments d'un process sont lisibles par tout utilisateur de la machine (`ps aux`, `/proc/<pid>/cmdline`), et le shell les archive en clair dans son historique. Les variables d'environnement sont a peine meilleures : OWASP note qu'elles sont generalement accessibles a tous les process et peuvent se retrouver dans les journaux ou un vidage systeme.

- **correction** : Proposer `--token-file` plutot que `--token`, lire sur stdin quand le terminal est interactif, ou deleguer a un gestionnaire de secrets. Si une variable d'environnement reste le seul choix, le documenter comme un repli.

- **portee** : python, javascript, typescript
- **detection** : `grep:add_argument\s*\(\s*["']--(token|password|secret|api-key|apikey|passwd)`; `grep:\.option\s*\(\s*["']--(token|password|secret|api-key)`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) · confiance medium


## authentication

### `KB-0028` · HIGH · Utiliser un secret HMAC long et aleatoire pour signer les JWT

- **id** : `authentication/jwt/hmac-secret-too-short`
- **exige** : Le secret utilise pour signer un JWT en HMAC doit compter au moins 64 caracteres issus d'une source d'alea sure, etre unique par environnement, et ne jamais figurer dans le code ni avoir de valeur de repli.
- **pourquoi** : La securite d'un jeton HMAC ne depend de rien d'autre que de la force du secret. Un attaquant qui detient un jeton valide peut attaquer le secret hors ligne, sans limite de debit et sans laisser de trace ; une phrase courte ou un mot du dictionnaire tombe en quelques minutes. Le secret casse, il peut forger n'importe quelle identite, y compris administrateur.
- **correction** : Generer le secret avec un generateur cryptographique, le stocker dans la configuration d'environnement, et faire echouer le demarrage s'il est absent plutot que de retomber sur une valeur par defaut. Envisager une signature asymetrique quand plusieurs services verifient les jetons.
- **portee** : python, typescript
- **detection** : `grep:(?i)(jwt_secret|secret_key|JWT_SECRET|SECRET_KEY)\s*[:=]\s*["'][^"']{0,63}["']`; `grep:(?i)(getenv|environ\.get|process\.env\.\w*SECRET\w*)[^)\n]{0,60}(,\s*["'][^"']+["']|\|\|\s*["'])`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html) · confiance high


## data-protection

### `KB-0033` · HIGH · Rediger les donnees sensibles avant tout envoi a un fournisseur externe

- **id** : `data-protection/pii/content-sent-to-provider-without-redaction`
- **exige** : Avant d'envoyer du contenu client a un fournisseur d'inference tiers, les elements identifiants et confidentiels qui ne sont pas necessaires a la tache doivent etre detectes et remplaces par des jetons reversibles cote application.
- **pourquoi** : Le contenu transmis sort du perimetre de traitement maitrise : il devient soumis aux conditions du fournisseur, a sa retention et a sa juridiction. Pour un cabinet, cela touche le secret professionnel, et l'argument ne se plaide pas apres coup. Le pseudonymat reduit la surface sans degrader la tache dans la plupart des cas, parce que le modele raisonne sur la structure du document plus que sur l'identite des parties.
- **correction** : Inserer une etape de detection et de substitution avant l'appel, conserver la table de correspondance cote application, et retablir les valeurs dans la reponse. Documenter ce qui reste transmis : une redaction partielle annoncee vaut mieux qu'une garantie qui ne tient pas.
- **portee** : python, typescript
- **detection** : `absent:(?i)(redact|anonymi|pseudonymi|scrub|mask_pii|presidio|deidentif)`
- **source** : [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM02_SensitiveInformationDisclosure.md), [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM02_SensitiveInformationDisclosure.md) · confiance medium


## database

### `KB-0035` · HIGH · Garder les fonctions security definer hors des schemas exposes

- **id** : `database/rls/security-definer-function-in-exposed-schema`
- **exige** : Une fonction declaree security definer ne doit jamais etre creee dans un schema expose par l'API : elle appartient a un schema prive, appele uniquement depuis les politiques.
- **pourquoi** : Une fonction security definer s'execute avec les droits de son createur ; creee par un role administrateur, elle contourne RLS. Utile a l'interieur d'une politique pour eviter le cout d'un balayage recursif, elle devient un point d'entree ouvert des lors qu'elle est joignable par l'API : l'appelant execute alors du code privilegie qu'il choisit d'invoquer.
- **correction** : Placer ces fonctions dans un schema prive non expose, fixer explicitement leur search_path, et n'accorder l'execution qu'aux roles qui en ont besoin.
- **portee** : sql, supabase, postgresql
- **detection** : `grep:(?i)create\s+(or\s+replace\s+)?function\s+public\.`; `grep:(?i)security\s+definer(?![\s\S]{0,80}set\s+search_path)`
- **source** : [supabase](https://supabase.com/docs/guides/database/postgres/row-level-security), [supabase](https://supabase.com/docs/guides/database/postgres/row-level-security) · confiance high

### `KB-0038` · HIGH · Declarer security_invoker sur les vues d'un schema expose

- **id** : `database/rls/view-bypasses-underlying-policies`
- **exige** : Une vue creee dans un schema expose contourne par defaut les politiques RLS des tables sous-jacentes : elle doit etre declaree avec security_invoker, ou son acces revoque pour les roles publics.
- **pourquoi** : Postgres cree les vues en security definer : elles s'executent avec les droits de leur createur, en general un role administrateur. La vue devient donc une porte laterale qui expose sans filtrage les lignes que la table protege. Le piege est particulierement discret : la table a bien sa politique, l'audit de la table est vert, et la fuite passe a cote.
- **correction** : Creer les vues avec security_invoker a vrai sur Postgres 15 et au-dela, pour qu'elles obeissent aux politiques de l'appelant. Sur les versions anterieures, revoquer l'acces aux roles anon et authenticated ou deplacer la vue dans un schema non expose.
- **portee** : sql, supabase, postgresql
- **detection** : `grep:(?i)create\s+(or\s+replace\s+)?view\s+(?!.*security_invoker)`
- **source** : [supabase](https://supabase.com/docs/guides/database/postgres/row-level-security), [supabase](https://supabase.com/docs/guides/database/postgres/row-level-security) · confiance high


## devops

### `KB-0042` · HIGH · Epingler chaque action tierce a un SHA de commit complet

- **id** : `devops/github-actions/action-not-pinned-to-commit-sha`
- **exige** : Les actions et workflows reutilisables tiers doivent etre references par un SHA de commit complet, jamais par une etiquette de version ni par un nom de branche.
- **pourquoi** : Une etiquette est une reference mutable : celui qui controle le depot de l'action peut la deplacer vers un autre commit sans que rien ne change chez l'appelant. Le code execute dans le coureur, avec le jeton du depot et les secrets du workflow, devient donc silencieusement different. C'est le vecteur des compromissions de chaine de livraison observees sur des actions populaires.
- **correction** : Remplacer chaque reference par le SHA complet, en gardant la version en commentaire pour la lisibilite, et confier la mise a jour a un outil automatise configure avec un delai avant adoption.
- **portee** : github-actions
- **detection** : `grep:^\s*-?\s*uses:\s*[\w.-]+/[\w.-]+@(?![0-9a-f]{40})`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html) · confiance high


## frontend

### `KB-0046` · HIGH · Ne pas ecrire de variable dans un puits HTML sans assainissement

- **id** : `frontend/xss/unsanitized-html-sink`
- **exige** : Les points d'ecriture directe dans le DOM (innerHTML, dangerouslySetInnerHTML, v-html) ne doivent pas recevoir de valeur dynamique sans assainissement prealable par une bibliotheque dediee.
- **pourquoi** : Ces puits interpretent la chaine recue comme du balisage : une valeur contenant une balise ou un attribut de gestionnaire d'evenement s'execute dans la session de l'utilisateur, avec ses cookies et ses droits. Le rendu par defaut du framework echappe deja les valeurs ; ces API sont precisement les sorties de secours qui desactivent cette protection.
- **correction** : Preferer textContent ou le rendu normal du framework, qui traitent la valeur comme du texte. Quand du HTML doit reellement etre rendu, le passer par un assainisseur avec liste d'autorisation avant l'affectation.
- **portee** : typescript, javascript, react, next, vue, svelte
- **detection** : `grep:dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|v-html|\{@html`; `grep:(?i)document\.write\s*\(|\.insertAdjacentHTML\s*\(`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) · confiance high


## network

### `KB-0047` · HIGH · Restreindre les requetes sortantes a une liste d'hotes autorisee

- **id** : `network/ssrf/outbound-url-not-allowlisted`
- **exige** : Quand l'application effectue une requete vers une URL derivee d'une entree externe, l'hote doit etre valide contre une liste d'autorisation ; une liste d'interdiction ne suffit pas.
- **pourquoi** : Le serveur applicatif atteint des ressources que le client ne peut pas atteindre : reseau interne, service de metadonnees de l'hebergeur, bases sans exposition publique. Une URL controlee par un tiers transforme donc l'application en relais vers ce perimetre. Les listes d'interdiction se contournent par les redirections, les notations d'adresse alternatives et les noms qui resolvent vers une adresse privee.
- **correction** : Construire la liste des hotes legitimes, comparer strictement apres resolution, refuser les redirections vers un hote hors liste, et bloquer les plages d'adresses privees et de bouclage. Si le domaine fonctionnel n'admet pas de liste fermee, isoler l'appel dans un composant sans acces au reseau interne.
- **portee** : python, typescript
- **detection** : `grep:(?i)(requests|httpx|aiohttp)\.(get|post|put|request)\s*\(\s*(url|target|link|endpoint|\w*_url)\b`; `grep:(?i)\bfetch\s*\(\s*(url|target|link|endpoint|\w*Url)\b`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) · confiance high


## ai-ml

### `KB-0002` · MEDIUM · Preferer des outils a fonction unique aux outils ouverts

- **id** : `ai-ml/agency/open-ended-tool-exposed-to-model`
- **exige** : Eviter d'exposer au modele des outils generiques du type executer une commande shell, recuperer une URL arbitraire ou executer du SQL libre ; leur preferer des outils dont la fonction est etroitement definie.
- **pourquoi** : Un outil ouvert donne au modele un espace d'action bien plus large que le besoin : l'outil qui ecrit un fichier via le shell peut aussi lire les secrets, et celui qui recupere une URL peut atteindre le service de metadonnees de l'hote. La surface exposee n'est plus celle du produit, mais celle de l'interpreteur sous-jacent.
- **correction** : Remplacer l'outil generique par une fonction dediee a l'operation reellement necessaire. Si un acces reseau sortant est requis, le borner a une liste d'hotes autorisee cote code.
- **portee** : python, typescript
- **detection** : `grep:(?i)(def|function)\s+\w*(run_shell|execute_command|run_command|fetch_url|http_get|run_sql|execute_sql|query_db)\w*\s*[\(=]`
- **source** : [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM06_ExcessiveAgency.md) · confiance high

### `KB-0004` · MEDIUM · Poser un delai maximal sur tout appel a un fournisseur de modele

- **id** : `ai-ml/inference/llm-call-without-timeout`
- **exige** : Chaque appel sortant vers un fournisseur d'inference doit porter un delai d'expiration explicite, ainsi qu'un plafond de jetons produits.
- **pourquoi** : Un appel sans delai retient un worker aussi longtemps que le fournisseur tarde. Quelques requetes lentes suffisent alors a immobiliser le pool et a rendre le service indisponible, sans qu'aucune erreur ne soit levee : la panne se presente comme une lenteur, ce qui retarde le diagnostic. Le plafond de jetons borne symetriquement le cout d'une generation qui ne s'arrete pas.
- **correction** : Passer un timeout explicite au client du fournisseur, plafonner max_tokens, et prevoir une degradation lisible du service en cas d'expiration plutot qu'une erreur brute.
- **portee** : python, typescript
- **detection** : `grep:(?i)(Anthropic|OpenAI|Mistral|Groq|Cohere)\s*\(\s*\)`; `absent:(?i)(timeout|max_tokens|maxTokens)`
- **source** : [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM10_UnboundedConsumption.md) · confiance high

### `KB-0006` · MEDIUM · Borner la taille des entrees avant de les envoyer au modele

- **id** : `ai-ml/inference/prompt-input-size-not-bounded`
- **exige** : Les champs transmis a un modele (question, document colle, historique) doivent porter une borne de taille validee cote serveur, avant tokenisation et avant l'appel au fournisseur.
- **pourquoi** : Le cout et la latence d'un appel croissent avec la longueur de l'entree, et un envoi demesure sature la memoire au moment de la tokenisation. Sans borne, une seule requete peut immobiliser un worker et couter le prix de milliers de requetes normales. La borne doit etre posee cote serveur : celle du client est une suggestion.
- **correction** : Declarer une longueur maximale sur chaque champ textuel du schema d'entree, refuser au-dela avec un code explicite, et borner egalement le nombre de tours d'historique renvoyes au modele.
- **portee** : python, typescript, fastapi, pydantic, zod
- **detection** : `absent:(?i)(max_length|max_len|maxLength|\.max\(|Field\([^)]*max)`
- **source** : [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM10_UnboundedConsumption.md), [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM10_UnboundedConsumption.md) · confiance high

### `KB-0012` · MEDIUM · Exiger des citations sourcees et les valider par du code deterministe

- **id** : `ai-ml/rag/answer-without-verifiable-citations`
- **exige** : Une reponse RAG doit imposer un format de sortie contenant des references aux documents utilises, et ce format doit etre verifie par du code : chaque reference doit correspondre a un chunk reellement presente dans le contexte.
- **pourquoi** : Demander des citations dans le prompt ne suffit pas : le modele produit des references plausibles avec la meme aisance qu'il produit du texte plausible. Seule une verification deterministe apres generation distingue une citation reelle d'une citation inventee, et c'est cette verification qui transforme une reponse en affirmation opposable. Sans elle, le produit ajoute a l'hallucination l'autorite d'une source apparente.
- **correction** : Contraindre la sortie a un schema structure ou chaque affirmation porte un identifiant de chunk, puis rejeter ou signaler en post-traitement toute reference absente du contexte transmis, ainsi que tout extrait cite introuvable dans le chunk designe.
- **portee** : python, typescript
- **detection** : `absent:(?i)(citation|source_id|chunk_id|quote|excerpt|span)`; `absent:(?i)(verify|validate|check)\w*\s*\(\s*\w*(citation|quote|source)`
- **source** : [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM01_PromptInjection.md) · confiance high

### `KB-0014` · MEDIUM · Journaliser les recuperations RAG de maniere immuable

- **id** : `ai-ml/rag/retrieval-not-logged`
- **exige** : Chaque recuperation doit laisser une trace inalterable de la requete, des identifiants de chunks retournes et du demandeur, conservee independamment de la base applicative.
- **pourquoi** : Sans journal de recuperation, une fuite inter-locataires ou un empoisonnement reste indetectable apres coup : on ne peut ni etablir quels documents ont reellement alimente une reponse, ni dire quels clients ont ete touches. C'est aussi le seul artefact qui permet de rejouer une reponse contestee, ce qui est la demande premiere d'un professionnel dont l'erreur engage la responsabilite.
- **correction** : Emettre une ligne de journal append-only par recuperation (horodatage, acteur, requete, ids de chunks, scores) vers une destination que l'application ne peut pas reecrire. Ne pas journaliser le contenu des chunks si celui-ci est sensible : les identifiants suffisent a rejouer.
- **portee** : python, typescript
- **detection** : `absent:(?i)(logger|log|audit|trace)\s*\.\s*(info|warning|audit|event)`
- **source** : [owasp-llm-top10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/020595761a4b7b0c3f9cf01a0457b78f9f1e7f9c/2_0_vulns/LLM08_VectorAndEmbeddingWeaknesses.md) · confiance high


## app-security

### `KB-0021` · MEDIUM · Renvoyer une reponse d'erreur generique et journaliser le detail cote serveur

- **id** : `app-security/error-handling/stack-trace-returned-to-client`
- **exige** : Une erreur inattendue doit produire une reponse generique pour l'appelant, tandis que la trace complete est journalisee cote serveur. Aucun message d'exception, chemin de fichier, requete SQL ni version de composant ne doit figurer dans la reponse.
- **pourquoi** : Une trace d'exception renseigne l'attaquant sur la pile, l'arborescence, le schema de base et les points ou l'entree n'est pas geree : elle transforme une erreur en cartographie gratuite du systeme. La meme information est utile a l'equipe, mais dans les journaux, ou son acces est controle.
- **correction** : Installer un gestionnaire d'erreurs global qui retourne un corps neutre avec un identifiant de correlation, et journaliser l'exception complete avec ce meme identifiant. Verifier que le mode debug est desactive en production.
- **portee** : python, typescript, fastapi, next, express
- **detection** : `grep:(?i)(debug\s*=\s*True|DEBUG\s*[:=]\s*(true|1)\b)`; `grep:(?i)(JSONResponse|jsonify|res\.(json|send)|HTTPException)\s*\([^)]{0,120}(str\s*\(\s*e\s*\)|traceback\.|\.stack\b|repr\s*\(\s*e)`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) · confiance high


## authentication

### `KB-0026` · MEDIUM · Ne pas laisser l'echec d'authentification reveler l'existence du compte

- **id** : `authentication/enumeration/login-reveals-account-existence`
- **exige** : Un echec d'authentification doit produire la meme reponse et la meme duree, que l'identifiant existe ou non : message identique, code identique, et verification d'un condensat factice quand le compte est absent.
- **pourquoi** : Un point d'entree qui distingue compte inconnu et mot de passe errone offre un oracle d'existence : on y teste une liste d'adresses et on obtient la liste des clients. Pour un produit destine aux cabinets d'avocats, la seule liste des comptes est deja une information commerciale et deontologique sensible. La difference se lit dans le message, mais aussi dans le temps de reponse quand le chemin du compte inconnu court-circuite la verification.
- **correction** : Retourner un message unique pour tous les echecs, et executer la verification de mot de passe contre un condensat factice lorsque le compte n'existe pas. Appliquer la meme discipline aux parcours d'inscription et de reinitialisation.
- **portee** : python, typescript, fastapi, next
- **detection** : `grep:(?i)(detail|message|error)\s*[:=]\s*["'][^"']*(utilisateur inconnu|user not found|unknown user|no such user|email not registered|compte introuvable)`; `grep:(?i)if\s+not\s+(user|utilisateur|account|compte)\s*:\s*\n\s*(return|raise)`
- **source** : [fastapi](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/), [fastapi](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/) · confiance high

### `KB-0030` · MEDIUM · Comparer secrets et jetons en temps constant

- **id** : `authentication/timing/secret-compared-with-equality-operator`
- **exige** : La comparaison d'un secret fourni par l'appelant — mot de passe, jeton d'API, signature de webhook — se fait avec une primitive a temps constant, jamais avec l'operateur d'egalite du langage.
- **pourquoi** : La comparaison de chaines s'arrete au premier caractere different : plus le prefixe fourni est correct, plus la reponse tarde. Cet ecart de quelques microsecondes se mesure a distance sur un grand nombre de requetes, et permet de reconstituer le secret caractere par caractere — l'application aide alors l'attaquant a la deviner. Une primitive a temps constant supprime le signal.
- **correction** : Utiliser secrets.compare_digest en Python, timingSafeEqual en Node. Appliquer la meme logique au chemin d'echec de l'authentification : quand l'identifiant n'existe pas, verifier tout de meme un condensat factice pour que la duree de reponse ne revele pas l'existence du compte.
- **portee** : python, typescript, javascript, fastapi, express, next
- **detection** : `grep:(?i)if\s+[\w.\[\]"']*\b(password|passwd|token|secret|signature|api_key|apikey)\b[\w.\[\]"']*\s*(==|!=)`; `absent:(?i)(compare_digest|timingSafeEqual)`
- **source** : [fastapi](https://fastapi.tiangolo.com/advanced/security/http-basic-auth/), [fastapi](https://fastapi.tiangolo.com/advanced/security/http-basic-auth/) · confiance high


## database

### `KB-0034` · MEDIUM · Ne pas exposer le schema auth — passer par une table de profil protegee

- **id** : `database/rls/auth-schema-exposed-instead-of-profile-table`
- **exige** : Les donnees utilisateur accessibles par l'API vivent dans une table de profil du schema public, protegee par RLS et referencant auth.users par sa cle primaire avec suppression en cascade — jamais dans le schema auth lui-meme.
- **pourquoi** : Le schema auth contient les elements d'authentification : jetons de recuperation, etats de confirmation, metadonnees d'identite. Il est volontairement tenu hors de l'API generee. Le contourner pour eviter d'ecrire une table de profil revient a exposer ce materiel. La reference par cle primaire compte aussi : les autres colonnes gerees par la plateforme peuvent changer sans preavis, ce qui casse silencieusement l'integrite.
- **correction** : Creer une table de profil dans le schema public, activer RLS, accorder les privileges role par role, et referencer auth.users(id) avec on delete cascade. Alimenter la table par un declencheur a la creation de compte.
- **portee** : sql, supabase
- **detection** : `grep:(?i)\bfrom\s+auth\.users\b|\.from\s*\(\s*["']auth\.users["']\s*\)`
- **source** : [supabase](https://supabase.com/docs/guides/auth/managing-user-data), [supabase](https://supabase.com/docs/guides/auth/managing-user-data) · confiance high


## devops

### `KB-0040` · MEDIUM · Declarer un utilisateur non privilegie dans l'image Docker

- **id** : `devops/containers/container-runs-as-root`
- **exige** : Une image Docker doit comporter une directive USER designant un compte non privilegie, et le conteneur doit etre lance avec l'interdiction d'acquerir de nouveaux privileges.
- **pourquoi** : Sans directive USER, le processus s'execute en root dans le conteneur. Une execution de code arbitraire dans l'application obtient alors les pleins pouvoirs sur le systeme de fichiers du conteneur et une bien meilleure position pour tenter une evasion. La bascule vers un compte dedie coute une ligne et supprime cette marche.
- **correction** : Creer un utilisateur dans l'image, effectuer les installations avant la bascule, puis declarer USER avant la commande de demarrage. Lancer le conteneur avec l'option interdisant l'elevation par binaire setuid.
- **portee** : docker, railway
- **detection** : `absent:^\s*USER\s+\w`; `grep:^\s*USER\s+(root|0)\s*$`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html), [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) · confiance high

### `KB-0041` · MEDIUM · Epingler les dependances a une version verifiee via un fichier de verrouillage

- **id** : `devops/dependencies/dependencies-not-pinned-to-verified-version`
- **exige** : Un outil distribue doit resoudre ses dependances de maniere deterministe : un fichier de verrouillage commite (`uv.lock`, `poetry.lock`, `package-lock.json`) et une installation qui le respecte.

- **pourquoi** : Une contrainte ouverte dans un `requirements.txt` — le seul artefact de resolution dans ce mode — laisse chaque installation choisir une version differente. Une version compromise en amont entre alors dans l'outil sans qu'aucun changement local ne l'ait demande. Pour un CLI installe sur des postes de developpeurs ou en CI, c'est une execution de code sur des machines de confiance.

- **correction** : Commiter le fichier de verrouillage et installer avec `uv sync --frozen`, `poetry install`, ou `npm ci` — jamais `pip install -r` ni `npm install` dans un contexte reproductible. Faire remonter les mises a jour par des changements de lock explicites et relus.

- **portee** : python, javascript, typescript
- **detection** : `grep:^\s*[a-zA-Z0-9_.-]+\s*(>=|>|\*|~=)`; `grep:(pip\s+install\s+-r|npm\s+install(?!\s+-g))`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html) · confiance high

### `KB-0044` · MEDIUM · Partir de permissions vides et n'accorder que le necessaire par job

- **id** : `devops/github-actions/workflow-permissions-not-restricted`
- **exige** : Un workflow doit declarer des permissions vides a son niveau, puis accorder explicitement au niveau de chaque job les seules permissions dont il a besoin.
- **pourquoi** : Sans declaration, le jeton du workflow herite des permissions par defaut du depot, souvent en ecriture sur tout le contenu. Une seule etape compromise, ou une action tierce malveillante, peut alors pousser du code, modifier des versions publiees ou ouvrir des acces. Partir de zero rend le privilege visible dans le fichier.
- **correction** : Ecrire permissions vide au niveau du workflow, puis ajouter par job le strict necessaire. Utiliser des environnements avec approbation requise pour les deploiements en production.
- **portee** : github-actions
- **detection** : `absent:^permissions:`; `grep:^\s*permissions:\s*write-all`
- **source** : [owasp-cheatsheets](https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html) · confiance high
