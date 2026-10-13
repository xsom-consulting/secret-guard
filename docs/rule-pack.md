# Pack de règles — spécification

Schéma : `RulePack` (JSON Schema `schema/RulePack.json`, schéma Zod `generator/src/rule-pack.ts`, type Go `pack.Pack`). Ce dépôt n'a qu'une copie du contrat : un programme qui signe et distribue des Packs (xSOM Fleet, par exemple) en reste la source, et le test `TestSchemaCopy` du paquet `pack` compare le type Go à cette copie. Un champ manquant s'ajoute avec un `schemaVersion` suivant.

Le moteur lit un Pack par `pack.Decode` (décodage strict : membre inconnu, en double ou d'une autre casse, champ absent ou null, nombre non entier, borne ou motif du schéma non respectés : refus) puis le charge par `detect.LoadRules`, qui le refuse en entier s'il ne peut pas l'exécuter (section « Exécution par le moteur Go »). Le moteur ne vérifie aucune signature : celui qui distribue des Packs signés vérifie la signature avant de passer les octets à `pack.Decode`.

## Champs

Objets fermés ; chaînes et entiers seulement.

| Champ | Contenu |
|---|---|
| `schemaVersion` | entier de 1 à 1 000 000 ; 1 pour le Pack initial |
| `minAgentVersion` | semver `MAJEUR.MINEUR.CORRECTIF`, sans pré-version ni métadonnées : version minimale du programme qui exécute le Pack (le moteur ne la juge pas) ; `0.0.0` pour le Pack initial |
| `packVersion` | entier de 1 à 2^53 − 1 |
| `issuedAt` | horodatage UTC `AAAA-MM-JJTHH:MM:SS[.mmm]Z` qui existe (forme et calendrier vérifiés par `pack.Decode`) |
| `rules` | tableau de 1 à 1 000 règles, dans l'ordre du catalogue |

Règle :

| Champ | Contenu |
|---|---|
| `ruleId` | identifiant de la règle du catalogue (`^[a-z][a-z0-9_]*$`, 64 caractères au plus), unique dans le Pack |
| `family` | `fixed_pattern` (motif seul), `private_key` (clé privée), `credential_url` (URL à identifiants), `contextual_assignment` (affectation contextuelle), `entropy` (entropie) |
| `secretType` | type de secret de Secret Guard (`private_key`, `provider_token`, `access_token`, `jwt`, `database_credentials`, `cloud_credential`, `password`, `api_key`, `generic_secret`, `high_entropy`) |
| `score` | entier de 0 à 100, score de base de la règle (avant pénalité d'encodage, logique du moteur) |
| `validator` | validateur nommé de la liste fermée `RULE_VALIDATORS` (`generator/src/rule-pack.ts`) : `jwt_structure` (`isStructurallyValidJwt`), ou chaîne vide sans validateur ; tout autre nom est refusé |
| `pattern` | motif en syntaxe RE2 ; obligatoire (non vide) pour les familles `fixed_pattern`, `private_key`, `credential_url` et `entropy` (`RULE_FAMILIES_WITH_PATTERN`) ; vide admis seulement pour `contextual_assignment`, quand la règle combine plusieurs motifs de `rules.ts` (logique du moteur) |
| `minLength`, `maxLength` | bornes de longueur, en caractères, de la valeur détectée, reportées des répétitions de plus de 1 000 du motif d'origine et contrôlées en code ; voir « Bornes de longueur » |

### Bornes de longueur

Règle appliquée par le moteur Go (`LoadRules`, refus `invalid_bounds`) :

- `0` = borne absente, pour chacune **indépendamment de l'autre** : `{minLength: 5, maxLength: 0}` (minimum seul) et `{minLength: 0, maxLength: 5}` (maximum seul) sont admis ;
- si les deux sont non nulles, `minLength ≤ maxLength` : `{minLength: 10, maxLength: 5}` est refusé ;
- une règle sans motif (`pattern` vide) n'a aucune borne (`0` et `0`).

### Groupes de capture

- **Règle « premier groupe capturant »** (famille `fixed_pattern` seulement) : la valeur détectée est le groupe capturant numéro 1 du motif RE2 s'il en a un, sinon la correspondance entière. Un groupe non capturant `(?:…)` ne compte pas. Dans le Pack initial, seule `azure_storage_key` a un groupe capturant (`capture: 1` à l'origine) ; le schéma n'a pas de champ `capture`, et un motif de cette famille ne doit donc jamais ajouter de groupe capturant avant celui de la valeur.
- **`cli_basic_auth`** : la réécriture de la rétro-référence (`(["']?)X\1` → `(?:"X"|'X'|X)`) triple les deux groupes de `X` (utilisateur, mot de passe). Les groupes se lisent par paires selon la forme reconnue : **1-2** entre guillemets doubles, **3-4** entre guillemets simples, **5-6** sans guillemets ; une seule paire participe à une correspondance (les autres sont vides, non participantes). Le moteur lit la paire participante.
- Pour les autres familles, l'usage des groupes et du motif est du code du moteur, activé par `family` et `ruleId` (`docker_auth` : groupe 1 = la clé `auth`).

Un motif est présent quand la fonction de `rules.ts` qui produit la règle clone un seul motif constant (`clonePattern(NOM)`) ; il est vide quand elle en combine plusieurs ou les reçoit en paramètre (`contextual_<type>` : six motifs d'affectation ; `cookie_session_credential` : en-tête puis cookies). Les motifs auxiliaires (blocs YAML, heredoc, préfixes de chaînes, schémas de base de données, filtres de valeurs fictives et d'exemples publics) sont du code du moteur.

## Traduction JavaScript → RE2

`generator/rule-pack/js-to-re2.ts`. Toute construction absente de RE2 qui n'est pas listée ici fait échouer la traduction.

| JavaScript (sans drapeau `u`) | RE2 |
|---|---|
| `\s`, et `\s` dans une classe | classe explicite des espaces de JavaScript : `\t \n \x0B \f \r`, espace, U+00A0, U+1680, U+2000–U+200A, U+2028, U+2029, U+202F, U+205F, U+3000, U+FEFF (`\s` de RE2 ne connaît que `[\t\n\f\r ]`) |
| `\S` hors classe | négation de cette classe |
| `.` | `[^\n\r\x{2028}\x{2029}]` |
| drapeau `i` | classes explicites des lettres ASCII (`[sS]`) : `(?i)` de RE2 replierait aussi `ſ` (U+017F) et `K` (U+212A), ce que JavaScript sans `u` ne fait pas ; dans une classe, une lettre ASCII ou une plage qui couvre des lettres ASCII reçoit l'autre casse, en tête de classe (`[A-Z_]` → `[a-zA-Z_]`) |
| drapeau `m` | `(?m)` |
| drapeau `y` (collant) | `\A(?:…)`, appliqué par le moteur au texte qui commence à la position voulue |
| drapeau `g` | ignoré (le moteur parcourt toutes les correspondances) |
| répétition `{m,n}` avec `n` > 1 000 (limite de RE2) | répétition ouverte (`*`, `+` ou `{m,}`), bornes reportées dans `minLength`/`maxLength` |
| `\b` | inchangé : ASCII dans les deux moteurs |
| `(["']?)X\1` (seule rétro-référence du catalogue) | `(?:"X"|'X'|X)` : formes à guillemets doubles, simples et sans guillemets. Seul un `\N` non échappé et hors classe est une rétro-référence ; la réécriture est refusée si un élément de `X` peut reconnaître `"` ou `'` (vérifié élément par élément avec le moteur JavaScript), sinon la forme sans guillemets reconnaîtrait des guillemets dépareillés |
| `\uXXXX` | `\x{XXXX}` |
| `\d \D \w \W \b \B \t \n \r \f \v \xHH \0`, ponctuation ASCII échappée | inchangés (même sens) |

Refusés (`UnsupportedPatternError`), parce que le sens diffère ou n'existe pas en RE2 :

- l'échappement de toute autre lettre (`\a`, `\z`, `\A`, `\Q`, `\E`, `\e`, `\c`, `\k`, `\p`…) : lettre elle-même en JavaScript sans `u`, autre sens ou erreur en RE2 ; l'échappement d'un espace ou d'un caractère non ASCII ; l'octal hérité (`\0` suivi d'un chiffre, `\N` dans une classe) ;
- sous le drapeau `i` : un échappement `\x`/`\u` isolé qui code une lettre (ou un caractère à casse), dans une classe ou non (une plage aux extrémités échappées qui couvre des lettres ASCII, `[\x41-\x5A]`, reçoit l'autre casse comme toute plage), une lettre non ASCII, une plage de classe qui couvre un caractère non ASCII à casse ;
- une classe d'échappement (`\s`, `\d`, `\w`…) en extrémité de plage dans une classe (`[\s-z]`) ;
- `[:` dans une classe (classe POSIX en RE2) et les demi-codes de substitution UTF-16.

Écarts connus, laissés au corpus de parité (qui peut faire corriger `pack.json`) :

- en mode `m`, `^` de JavaScript reconnaît aussi le début de ligne après `\r`, U+2028 et U+2029, `^` de RE2 seulement après `\n` (aucun regard arrière en RE2). Sans effet quand `^` est en alternative avec `\s` (`cli_basic_auth`, `docker_auth`) ;
- de même, en mode `m`, `$` de JavaScript s'arrête aussi avant `\r`, U+2028 et U+2029, `$` de RE2 seulement avant `\n` (ou en fin de texte). Aucun motif du Pack initial n'utilise `$` ;
- JavaScript compte en unités UTF-16, Go en octets et en points de code : hors BMP, les longueurs et positions diffèrent ;
- une répétition ouverte reconnaît une suite plus longue que la borne d'origine, là où JavaScript s'arrête à la borne (URL à identifiants : correspondance tronquée) ou revient en arrière (`jwt`, suivi de `\b`) ; `minLength`/`maxLength` portent sur la valeur détectée entière (`jwt` : un seul couple pour trois segments), et leur application exacte est du code du moteur, prouvée par le corpus (JWT de plus de 1 000 répétitions).

## Exécution par le moteur Go

`LoadRules` (`detect/rules.go`) charge le Pack décodé et le refuse en entier (`PackError`, `ErrPackUnusable`, raison en liste fermée `PackRefusal`) si une règle a une famille, un type de secret ou un validateur inconnus du moteur, un motif qui ne compile pas en RE2 ou qui reconnaît le texte vide, des bornes incohérentes, un score hors de 0 à 100 ou un identifiant en double, ou si une famille du moteur n'a qu'une partie de ses règles (les deux règles de clé privée, les deux d'URL, les sept `contextual_<type>` vont ensemble).

- **Règles « motif seul »** (`fixed_pattern`, sauf `jwt`) : exécutées telles que le Pack les décrit (motif, groupe capturant 1, type de secret, score, validateur, bornes `minLength`/`maxLength` en unités UTF-16 de la valeur détectée, 0 = absente). Une telle règle peut être ajoutée par un Pack sans changer le moteur.
- **Règles du moteur** (familles `private_key`, `credential_url`, `contextual_assignment`, `entropy`, et `jwt`) : leur logique est du code du moteur, activé par `ruleId` ; une règle absente du Pack n'est pas exécutée, et une règle présente doit être exactement celle que le moteur exécute (famille, type de secret, validateur, motif, bornes), sinon le Pack est refusé (`engine_rule_mismatch`) ; un identifiant inconnu dans ces familles est refusé (`unknown_engine_rule`). Le score de base vient du Pack. Les attentes du moteur (`engineRules`) et ses motifs auxiliaires sont générés depuis la même copie de `rules.ts`, par la même traduction (`generator/rule-pack/engine-patterns.ts`, écrit avec `pack/initial/pack.json` par `npm run pack:initial` dans `detect/engine_patterns.go`).
- **Bornes au-delà de RE2** : le Pack porte la somme ; le moteur applique celle de chaque partie comme la répétition de JavaScript (segments de `jwt` : 4..2 048, 4..8 192, 8..4 096, la signature coupée à la dernière limite de mot ; queue d'une URL : 2 048 unités ; mot de passe de `cli_basic_auth` : 1 024 unités, refusé entre guillemets, coupé sans guillemets).
