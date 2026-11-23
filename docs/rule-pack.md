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
| `rules` | tableau de 1 à 1 000 règles, dans l'ordre du catalogue (426 dans le Pack initial de la v0.11.0) |

Règle :

| Champ | Contenu |
|---|---|
| `ruleId` | identifiant de la règle du catalogue (`^[a-z][a-z0-9_]*$`, 64 caractères au plus), unique dans le Pack |
| `family` | `fixed_pattern` (motif seul), `private_key` (clé privée), `credential_url` (URL à identifiants), `contextual_assignment` (affectation contextuelle), `entropy` (entropie) |
| `secretType` | type de secret de Secret Guard (`private_key`, `provider_token`, `access_token`, `jwt`, `database_credentials`, `cloud_credential`, `password`, `api_key`, `generic_secret`, `high_entropy`) ou, depuis la v0.7.0, type de donnée personnelle (`iban`, `fr_social_security_number`, `fr_siret`, `fr_siren`, `payment_card_number`), depuis la v0.9.0 type de donnée à contexte (`email_address`, `phone_number`, `passport_number`, `payment_card_security_code`, `one_time_code`, `internal_ip_address`, `cloud_resource_address`), depuis la v0.10.0 `national_identifier`, `vat_number`, `bank_account_number`, `vehicle_registration_plate`, `postal_address` |
| `score` | entier de 0 à 100, score de base de la règle (avant pénalité d'encodage, logique du moteur) |
| `validator` | validateur nommé de la liste fermée `RULE_VALIDATORS` (`generator/src/rule-pack.ts`) : `jwt_structure` (`isStructurallyValidJwt`) ; depuis la v0.7.0 `iban_mod97`, `fr_nir_key`, `fr_siret_luhn`, `fr_siren_luhn`, `payment_card_luhn` (section « Règles de données personnelles ») ; depuis la v0.10.0 `token_entropy_25` à `token_entropy_45` (section « Vraisemblance d'un jeton de fournisseur ») et les douze validateurs des identifiants européens et français (section « Identifiants européens et français ») ; ou chaîne vide sans validateur ; tout autre nom est refusé |
| `pattern` | motif en syntaxe RE2 ; obligatoire (non vide) pour les familles `fixed_pattern`, `private_key`, `credential_url` et `entropy` (`RULE_FAMILIES_WITH_PATTERN`) ; vide admis seulement pour `contextual_assignment`, quand la règle combine plusieurs motifs de `rules.ts` (logique du moteur) |
| `minLength`, `maxLength` | bornes de longueur, en caractères, de la valeur détectée, reportées des répétitions de plus de 1 000 du motif d'origine et contrôlées en code ; voir « Bornes de longueur » |

### Bornes de longueur

Règle appliquée par le moteur Go (`LoadRules`, refus `invalid_bounds`) :

- `0` = borne absente, pour chacune **indépendamment de l'autre** : `{minLength: 5, maxLength: 0}` (minimum seul) et `{minLength: 0, maxLength: 5}` (maximum seul) sont admis ;
- si les deux sont non nulles, `minLength ≤ maxLength` : `{minLength: 10, maxLength: 5}` est refusé ;
- une règle sans motif (`pattern` vide) n'a aucune borne (`0` et `0`).

### Règles de données personnelles (v0.7.0)

Cinq règles « motif seul » (`fixed_pattern`) s'ajoutent après les 35 du catalogue d'origine. Elles n'ont aucune origine dans Secret Guard : leur motif est écrit directement en RE2 dans `generator/rule-pack/personal-data.ts` (jamais à la main dans `pack.json`), et leur validateur est du code du moteur (`detect/personaldata.go`). Un moteur qui ne connaît pas leur type de secret ou leur validateur refuse le Pack en entier (`unknown_secret_type`, `unknown_validator`).

| `ruleId` | `secretType` | `validator` | Score | Motif (résumé) | Bornes |
|---|---|---|---:|---|---|
| `iban` | `iban` | `iban_mod97` | 45 | deux lettres, deux chiffres, 2 à 7 groupes de quatre caractères (espace facultative devant chacun), reste de 1 à 3 caractères ; lettres des deux casses | 15 à 42 |
| `fr_nir` | `fr_social_security_number` | `fr_nir_key` | 60 | sexe `[1-478]`, année, mois `01`–`12` ou `20`–`99`, département ou `2A`/`2B`, commune, ordre, clé ; espace facultative entre éléments | 15 à 21 |
| `fr_siret` | `fr_siret` | `fr_siret_luhn` | 35 | 14 chiffres, groupes 3-3-3-5 ou 9-5 ou d'un bloc | 14 à 17 |
| `fr_siren` | `fr_siren` | `fr_siren_luhn` | 35 | le mot « SIREN » (toute casse), guillemet, séparateurs `:` `=` `#` `n°` `no` facultatifs, puis 9 chiffres en un groupe capturant (la valeur) | 9 à 11 |
| `payment_card` | `payment_card_number` | `payment_card_luhn` | 70 | 13 à 19 chiffres d'un bloc, 4-4-4-4 ou 4-6-4/5, séparés d'une espace ou d'un tiret | 13 à 19 |

Les motifs délimitent un candidat ; le validateur le juge. Il reçoit la valeur détectée telle qu'écrite (séparateurs compris) et ne garde rien :

- `iban_mod97` : chiffres de contrôle 02 à 98 ; longueur imposée du pays quand il est dans `ibanLengths` (76 pays depuis la v0.10.0, 52 avant : registre ISO 13616), 15 à 34 caractères sinon ; reste modulo 97 égal à 1 (quatre premiers caractères passés à la fin, lettres remplacées par 10 à 35). **Raccourcissement** : le motif étant générique, il peut absorber le mot de quatre caractères qui suit l'IBAN. Pour cette règle seule (`trimmers`), le moteur retient, avant les bornes et le validateur, la plus longue fin de groupe de la correspondance (fin d'un mot, ou multiple de quatre caractères alphanumériques) dont le préfixe est un IBAN valide ; le constat s'arrête là, et le reste de la correspondance n'est pas un constat. Aucun préfixe valide : pas de constat.
- `fr_nir_key` : 13 caractères et une clé de 2 chiffres égale à 97 − (nombre mod 97) ; `2A` compte pour 19 et `2B` pour 18 ; département, commune et numéro d'ordre jamais nuls.
- `fr_siret_luhn` : 14 chiffres, Luhn ; si les 9 premiers sont `356000000` (La Poste), la somme des chiffres est un multiple de 5 à la place ; jamais un nombre de chiffres tous égaux, ni un nombre qui se lit AAAAMMJJHHMMSS (années 1900 à 2099).
- `fr_siren_luhn` : 9 chiffres, Luhn, pas de chiffre répété.
- `payment_card_luhn` : 13 à 19 chiffres, un seul séparateur (espace ou tiret), Luhn, pas de chiffre répété, préfixe et longueur d'un réseau : Visa (`4`, 16 ou 19), Mastercard (`51`–`55`, `2221`–`2720`, 16), American Express (`34`, `37`, 15), Discover (`6011`, `644`–`649`, `65`, 16 à 19), Diners (`300`–`305`, `3095`, `36`, `38`, `39`, 14 à 19), JCB (`3528`–`3589`, 16 à 19), UnionPay (`62`, 16 à 19), Maestro (`5018`, `5020`, `5038`, `5893`, `6304`, `6759`, `6761`–`6763`, 13 à 19). Les Visa de 13 chiffres sont écartés (forme des codes-barres EAN-13).

Les validateurs ne s'exécutent pas dans un texte décodé de base64 (`allowStructured`, comme `jwt`). Les attentes du corpus viennent d'une seconde écriture indépendante des contrôles (`generator/rule-pack/personal-data.ts`, BigInt), comparée au moteur Go sur 82 cas (`vectors/detection/rules-personal-data.json`) ; la table `ibanLengths` du moteur est comparée à celle du générateur par un test.

### Identifiants européens et français, règle composée AWS (v0.10.0)

Quinze règles « motif seul » ferment le Pack initial, après les règles de données à contexte de la v0.9.0. Elles sont écrites dans `generator/rule-pack/context-data.ts` ; les validateurs sont du code du moteur (`detect/personaldata.go`), leur seconde écriture est dans `generator/rule-pack/personal-data.ts`. Origine (Presidio, MIT), formules et sources : `UPSTREAM.md`, « Identifiants européens et français, règle composée AWS ».

| `ruleId` | `secretType` | `validator` | Score | Mot-clé obligatoire (extraits) | Valeur |
|---|---|---|---:|---|---|
| `es_nif` | `national_identifier` | `es_nif_mod23` | 60 | DNI, NIF, carte d'identité espagnole, Spanish ID card | 7 ou 8 chiffres et la lettre du nombre modulo 23 |
| `es_nie` | `national_identifier` | `es_nie_mod23` | 60 | NIE, numéro d'identité d'étranger, foreigner identity number | X, Y ou Z, 7 chiffres, lettre modulo 23 |
| `it_fiscal_code` | `national_identifier` | `it_fiscal_code_check` | 60 | codice fiscale, code fiscal italien, Italian fiscal (tax) code | 16 caractères, lettre de contrôle modulo 26 |
| `it_vat` | `vat_number` | `it_vat_luhn` | 35 | partita IVA, P. IVA, TVA italienne, Italian VAT | 11 chiffres, Luhn (« IT » admis devant) |
| `de_tax_id` | `national_identifier` | `de_tax_id_iso7064` | 60 | Steuer-ID, IdNr, identifiant fiscal allemand, German tax ID | 11 chiffres, ISO 7064 MOD 11,10 |
| `de_vat` | `vat_number` | `de_vat_iso7064` | 35 | USt-IdNr, Umsatzsteuer-ID, TVA allemande, German VAT | « DE » et 9 chiffres, ISO 7064 MOD 11,10 |
| `pl_pesel` | `national_identifier` | `pl_pesel_check` | 60 | PESEL | 11 chiffres, date possible, poids 1-3-7-9 |
| `uk_nhs` | `national_identifier` | `uk_nhs_mod11` | 60 | NHS, National Health Service | 10 chiffres, modulo 11 |
| `se_personnummer` | `national_identifier` | `se_personnummer_luhn` | 60 | personnummer, samordningsnummer, numéro personnel suédois, personal identity number | 10 ou 12 chiffres, Luhn |
| `fi_personal_identity_code` | `national_identifier` | `fi_hetu_mod31` | 60 | HETU, henkilötunnus, identifiant personnel finlandais, personal identity code | date, séparateur du siècle, 3 chiffres, caractère modulo 31 |
| `fr_vat` | `vat_number` | `fr_vat_key` | 35 | aucun (préfixe « FR ») | clé de 2 chiffres dérivée du SIREN, SIREN valide |
| `fr_rib` | `bank_account_number` | `fr_rib_key` | 45 | RIB, relevé d'identité bancaire, coordonnées bancaires, bank account details | banque, guichet, compte, clé modulo 97 |
| `fr_license_plate` | `vehicle_registration_plate` | aucun | 30 | immatricul…, plaque, plate, registration (30 caractères au plus avant la valeur) | deux lettres, trois chiffres, deux lettres, en majuscules |
| `fr_postal_address` | `postal_address` | aucun | 30 | type de voie en liste fermée | numéro, voie, code postal, commune ; **règle « à activer »** |
| `aws_access_key_pair` | `cloud_credential` | aucun | 95 | aucun | identifiant AKIA ou ASIA et valeur de 40 caractères à 200 octets au plus |

- Le mot-clé précède la valeur sur la même ligne, avec la liaison bornée des règles de la v0.9.0 (« : », « = », « est », « is », guillemets) ; sans lui, pas de constat. Chaque règle a une porte littérale (ses mots-clés).
- Comme les autres validateurs, ceux-ci ne s'exécutent pas dans un texte décodé de base64.
- `aws_access_key_pair` est exécutée par une famille du moteur (`detect/awspair.go`), activée par son `ruleId` : les deux ordres, valeur de 40 caractères exactement, avec minuscule, majuscule et chiffre, jamais une empreinte hexadécimale. Le motif du Pack n'en décrit que la forme « identifiant, puis valeur » et donne la porte littérale. Le constat va de l'identifiant à la valeur ; l'identifiant seul reste `aws_access_key_id` (45).
- Règles « à activer » du Pack initial : `email_address`, `fr_postal_address`.
- Version minimale : un Pack signé qui porte ces types de secret ou ces validateurs déclare en `minAgentVersion` la première version qui embarque le moteur v0.10.0.

### Règles de fournisseurs (v0.8.1)

360 règles « motif seul » (`fixed_pattern`, type de secret `provider_token`, sans borne) s'ajoutent après les règles de données personnelles : 294 depuis la v0.8.1, reprises de Titus, et 66 depuis la v0.10.0, reprises de Betterleaks. Leur source est `generator/rule-pack/provider-rules.json` (une règle par ligne : identifiant, règle d'origine, libellés de Substitut, score, validateur de vraisemblance facultatif, motif RE2, forme d'une valeur d'essai et d'un presque positif), entretenue à la main depuis ces reprises (UPSTREAM.md, « Règles de fournisseurs » et « Règles reprises de Betterleaks, vraisemblance et banc de comparaison ») ; `npm run pack:initial` en écrit le Pack et la table Go des libellés (`detect/substitute_providers.go`).

- Score 95 (177 règles) : la valeur porte un préfixe fixe du fournisseur. Score 80 (183 règles) : le motif exige le nom du fournisseur avant la valeur, à quelques dizaines de caractères au plus.
- La valeur détectée est l'unique groupe capturant du motif. Un motif peut replier la casse (`(?i:…)`) et porter des drapeaux de groupe (`(?s:…)`, `(?-m:…)`).
- Chaque règle doit avoir une porte littérale (`TestProviderRules`) : un littéral d'au moins trois octets présent dans toute correspondance. Une règle sans porte s'exécuterait sur tout texte.
- Ajouter une règle : une ligne dans `provider-rules.json`, puis `npm run pack:initial`, `npm run vectors:detection -- --upstream <checkout>`, `node corpus/provider-noise.ts` et les tests ; un moteur plus ancien exécute la règle (famille connue) si elle ne porte pas de validateur qu'il ignore, mais écrit le libellé de repli « secret » dans ses Substituts.

### Vraisemblance d'un jeton de fournisseur (v0.10.0)

Une règle de fournisseur reconnaît une forme ; une valeur faite d'un caractère répété a la forme et n'est pas un jeton. Deux contrôles, du code du moteur (`detect/validators.go`), sans champ nouveau dans le Pack :

- **D'office**, pour toute règle « motif seul » de type `provider_token` hors des quinze règles du catalogue d'origine (dont la parité fixe le comportement) : une valeur de moins de 6 octets distincts, ou d'entropie de Shannon inférieure à 3,0 bits par octet, n'est pas un constat. Une règle de ce type ajoutée par un Pack y est soumise.
- **Par validateur nommé** `token_entropy_NN`, NN de 25 à 45 : au moins 6 octets distincts et une entropie d'au moins NN dixièmes de bit par octet. Le seuil nommé remplace le seuil d'office (il peut être plus bas : `token_entropy_26` pour vingt chiffres hexadécimaux) et s'applique à une règle « motif seul » de n'importe quel type. Les 183 règles à proximité du Pack initial en portent un, et 48 règles à préfixe fixe.

Le contrôle porte sur la valeur détectée entière (octets du texte de la vue), ne décode rien, ne débite aucun budget, et s'exécute aussi dans un texte décodé de base64. Choisir un seuil : pas plus haut que ce que 99,5 % de valeurs tirées de la forme du motif passent (`generator/test/provider-rules.test.ts` le vérifie pour chaque règle du Pack initial) ; un seuil de 3,5 écarte 19 % des clés de 32 chiffres hexadécimaux. Quand la clé réelle du fournisseur est hexadécimale alors que le motif admet tout l'alphabet alphanumérique, la forme se tire en hexadécimal (`HEX_KEY_RULES` du même test, treize règles du Pack initial).

**Version minimale.** Un moteur antérieur à la v0.10.0 ne connaît pas ces validateurs et refuse le Pack en entier (`unknown_validator`). Un Pack signé qui en porte un doit donc déclarer en `minAgentVersion` la première version du programme qui embarque le moteur v0.10.0 ; le Pack initial, embarqué avec son moteur, garde `0.0.0`.

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

- **Règles « motif seul »** (`fixed_pattern`, sauf `jwt`) : exécutées telles que le Pack les décrit (motif, groupe capturant 1, type de secret, score, validateur, bornes `minLength`/`maxLength` en unités UTF-16 de la valeur détectée, 0 = absente), avec, pour le type `provider_token`, le contrôle de vraisemblance d'office (section « Vraisemblance d'un jeton de fournisseur »). Une telle règle peut être ajoutée par un Pack sans changer le moteur.
- **Règles du moteur** (familles `private_key`, `credential_url`, `contextual_assignment`, `entropy`, et `jwt`) : leur logique est du code du moteur, activé par `ruleId` ; une règle absente du Pack n'est pas exécutée, et une règle présente doit être exactement celle que le moteur exécute (famille, type de secret, validateur, motif, bornes), sinon le Pack est refusé (`engine_rule_mismatch`) ; un identifiant inconnu dans ces familles est refusé (`unknown_engine_rule`). Le score de base vient du Pack. Les attentes du moteur (`engineRules`) et ses motifs auxiliaires sont générés depuis la même copie de `rules.ts`, par la même traduction (`generator/rule-pack/engine-patterns.ts`, écrit avec `pack/initial/pack.json` par `npm run pack:initial` dans `detect/engine_patterns.go`).
- **Bornes au-delà de RE2** : le Pack porte la somme ; le moteur applique celle de chaque partie comme la répétition de JavaScript (segments de `jwt` : 4..2 048, 4..8 192, 8..4 096, la signature coupée à la dernière limite de mot ; queue d'une URL : 2 048 unités ; mot de passe de `cli_basic_auth` : 1 024 unités, refusé entre guillemets, coupé sans guillemets).
