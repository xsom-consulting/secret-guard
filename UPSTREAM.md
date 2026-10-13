# Origine du moteur de détection

Le moteur Go de ce dépôt (`detect/`), le Pack initial (`pack/initial/pack.json`) et le corpus de parité (`vectors/detection/`) sont un portage du moteur de détection TypeScript de Secret Guard, comme les paquets `hidden/` et `mentions/` et leurs vecteurs (`vectors/hidden.json`, `vectors/mentions.json`, section « Instructions cachées et mentions »). Ce fichier est le seul relevé de cette origine.

## Origine

| Élément | Valeur |
|---|---|
| Dépôt | `jt33120/poc-AI_guard`, dépôt privé de xSOM, archivé le 2026-10-13 sous `xsom-consulting/ai-guard-legacy` (privé). Les fichiers repris sont copiés ici avec leur empreinte : le corpus se vérifie sans accès à ce dépôt. |
| Commit | `c177a447b8cdf8ce07e0c3160ea45dace99b6dc9` (branche `main`) |
| Chemin | `secret-guard/packages/core` |
| Licence | Apache License, Version 2.0 (`secret-guard/packages/core/LICENSE`, dans le périmètre ouvert de `LICENSING.md` du dépôt d'origine) |

## Fichiers repris

| Fichier d'origine | Copie dans ce dépôt | SHA-256 de la copie (octets identiques à l'origine) |
|---|---|---|
| `secret-guard/packages/core/src/rules.ts` | `pack/initial/upstream/rules.ts.txt` | `f7ec4603f9184d773b0bdf18227994df785cb7522dced50163c27231f8853499` |
| `secret-guard/packages/core/LICENSE` | `pack/initial/upstream/LICENSE` | `c95bae1d1ce0235ecccd3560b772ec1efb97f348a79f0fbe0a634f0c2ccefe2c` |

La copie de `rules.ts` est non modifiée (extension `.txt` : elle n'est ni compilée ni exécutée). Le test `le Pack initial reprend chaque règle du catalogue Secret Guard` (`generator/test/rule-pack.test.ts`) vérifie son SHA-256 ci-dessus, en extrait les règles et compare `pack.json` à leur traduction.

## Modifications (Apache-2.0, §4 b)

`pack/initial/pack.json` est une œuvre dérivée de `rules.ts` : les motifs JavaScript y sont traduits en syntaxe RE2 par `generator/rule-pack/` (règles de traduction : `docs/rule-pack.md`), et la rétro-référence de la règle `cli_basic_auth` est réécrite par alternative. Identifiants de règle, familles, types de secret et scores sont ceux de l'origine.

## Corpus de parité

`vectors/detection/` : corpus figé « entrée → résultat attendu » produit par le moteur TypeScript de Secret Guard au commit ci-dessus, que le moteur Go doit passer à 100 % (`TestParity`). Seul corpus de parité : toute évolution des règles y ajoute ses cas.

- **Production** : `npm run vectors:detection -- --upstream <checkout>` dans `generator/` (`generator/corpus/main.ts`) ; `--check` régénère en mémoire et compare octet pour octet. Le checkout (dépôt `jt33120/poc-AI_guard`, extrait dans un répertoire temporaire, jamais dans ce dépôt) doit être au commit ci-dessus : le SHA-256 de chaque fichier lu est vérifié (`UPSTREAM_FILES` de `generator/corpus/upstream.ts` : tout `secret-guard/packages/core/src`, et les quatre tests ci-dessous). Les fichiers sont transpilés par le TypeScript de ce dépôt dans un répertoire temporaire ; aucune dépendance du dépôt d'origine n'est installée ni exécutée.
- **Fichiers lus** (Apache-2.0, périmètre ouvert de `LICENSING.md` du dépôt d'origine) : le moteur `secret-guard/packages/core/src/**`, et les tests `secret-guard/tests/core/{scan,security,encoding,text}.test.ts`, exécutés sur la copie transpilée avec le `expect` de Vitest (une assertion d'origine en échec arrête le générateur). Les entrées que ces tests passent au moteur deviennent des cas `upstream/<fichier> > <suites> > <titre> [rang] #n` (fichiers `upstream-*.json`) ; aucun fichier d'origine n'est copié dans ce dépôt. Les entrées de `decodeBase64`, `isStructurallyValidJwt`, `decodeScannableText` et `redactAndRescan` sont reprises comme entrées de `scan` : leur cas prouve la parité de l'analyse, pas celle de la fonction éprouvée par le test d'origine.
- **Cas synthétiques** (`generator/corpus/synthetic.ts`) : valeurs tirées de SHA-256 sur des étiquettes fixes, jamais copiées d'un vrai secret ; seules les trois valeurs d'exemple public de `rules.ts` (`PUBLIC_EXAMPLES`) y sont écrites, en morceaux comme à l'origine. Le générateur échoue si une règle du Pack n'a pas de cas positif, négatif, de valeur fictive ou d'exemple public (sauf exemption motivée : `PLACEHOLDER_NOT_APPLICABLE`, `PUBLIC_EXAMPLE_NOT_APPLICABLE`), si une vue n'a pas de cas positif, ou si un test repris ne passe aucune entrée au moteur (sauf `TESTS_WITHOUT_INPUT`, quatre tests sans entrée de texte). L'étiquette des valeurs synthétiques (`xsom-fleet/detection-corpus/v1/…`) est celle du dépôt où le corpus a été produit ; elle ne change pas, car elle détermine chaque valeur.
- **Format** : un fichier = un tableau JSON, un cas par ligne : `{id, input, inputEncoding: "utf8"|"base64", languageId?, expected: {complete, failure: "none"|"scan_limit"|"scan_error", findings[]}}`, constat `{ruleId, secretType, encoding, score, level, byteStart, byteEnd}` (étendue en octets UTF-8 de l'entrée, fin exclue), triés par `(byteStart, ruleId)` puis `byteEnd`. Analyse en échec : `complete` faux, aucun constat (le constat d'échec de Secret Guard, `input_too_large`/`scanner_failure`, devient `failure`). `manifest.json` : version du format, commit d'origine, nombre de cas par fichier.
- **Octets** : `input` est le texte quand l'entrée est de l'UTF-8 valide, sinon ses octets en base64 standard. Le texte analysé par Secret Guard est le décodage des octets à la manière de Go : un octet hors séquence UTF-8 valide vaut U+FFFD, un par octet (`utf8.DecodeRune`) ; NUL est un caractère ordinaire. La limite de 1 Mio porte sur les octets reçus ; une entrée hors UTF-8 qu'elle classerait autrement que Secret Guard (qui mesure le texte décodé) arrête le générateur. Positions UTF-16 du moteur converties en octets ; une position au milieu d'une paire de substitution arrête le générateur.
- **Écriture** : caractères visibles tels quels ; caractères de contrôle, de format, séparateurs, ignorables par défaut, privés et non attribués en `\uXXXX` (tables Unicode de Node, `\p{…}`).
- **Recherche de secrets** : les fichiers de cas (`vectors/detection/{rules,views,edge,limits,upstream}*.json`, ni manifeste ni sous-dossier) sont la seule exception de `.gitleaks.toml` ; le générateur, le Pack et sa copie d'origine restent analysés (test `generator/test/detection-corpus.test.ts`).
- **Vérification de l'extraction** : le 13 octobre 2026, `npm run vectors:detection -- --upstream <checkout> --check` sur un checkout au commit ci-dessus rend « Corpus identique : 823 cas, 12 fichiers ».

## Vues et décodages

Portage en Go, sans copie de code d'origine dans le dépôt, de :

| Fichier d'origine (commit ci-dessus) | SHA-256 | Portage |
|---|---|---|
| `secret-guard/packages/core/src/mapping.ts` | `6f32fffb85cadb3209405b5befd04f9f32f6c5298cf2541eaed51f58ed522f70` | `detect/views.go` : `identityView`, `normalizedView`, `percentDecodedView`, `jsonEscapedView`, `joinedLineView`, `sliceMappedView` (fondu dans `joinedWindow`), `mapRange`/`originalBounds` |
| `secret-guard/packages/core/src/encoding.ts` | `e7eedea817282bf801e655a9cfc0f99234f1b0e2c49406653701f86bef54efd0` | `detect/encoding.go` : `decodeBase64`, `decodeBase64Budgeted` (`decodeBudget.decodeBase64`), `isStructurallyValidJwt`, `MAX_DECODE_ATTEMPTS`, `MAX_DECODED_BYTES` |
| `secret-guard/packages/core/src/scanner.ts` (en partie) | `80ba8d74d90bd3fd045542fadfd8792171d5b7beaa2ac1067edbacbaee77cafc` | `detect/views.go` : `canonicalizedView`, `transformedTextViews`, `TOKEN_PREFIXES`/`SPLIT_TOKEN_PREFIX`, `lineWrappedFixedViews`, `consumeWrappedTail`, `lineWrappedBase64Views` ; `detect/encoding.go` : `BASE64_CANDIDATE`, `isKnownSriCandidate`, `isPlausibleBase64Payload`, boucle de `scanBase64Candidates` sans l'analyse du texte décodé |

Le reste de `scanner.ts` (`collectFindings`, `scanDecodedText`, `dedupeOverlaps`, limite de 1 Mio) est porté dans `detect/scan.go` (section « Analyse »), les règles (`rules.ts`) dans les fichiers de la section « Règles ».

**Modifications (Apache-2.0, §4 b)** : traduction de TypeScript en Go ; texte lu en octets et non en unités UTF-16 (correspondance par octet vers la source ; un octet invalide vaut U+FFFD, un par octet, comme dans le corpus de parité ; la vue d'identité garde les octets tels quels, les vues dérivées écrivent U+FFFD) ; substitut UTF-16 isolé d'un échappement JSON écrit U+FFFD et recombiné avec son pendant quand une vue dérivée les rend adjacents, comme dans une chaîne JavaScript ; `SPLIT_TOKEN_PREFIX` et `BASE64_CANDIDATE` lus à la main (RE2 ne borne pas une répétition au-delà de 1 000 ; même suite de correspondances, prouvée par fuzz contre l'expression RE2 équivalente) ; fin de suite de caractères de jeton fixe calculée une fois par vue (`fixedRunEnds`) au lieu d'un parcours par préfixe ; ajout d'un budget d'octets de vues (`maxViewBytes`, 16 Mio) absent de l'origine : au-delà, analyse incomplète. Les budgets de l'origine (128 décodages, 262 144 octets décodés, 128 fenêtres de lignes jointes, 16 384 caractères par fenêtre) sont repris tels quels.

**Vérification** : tests de `detect/` portés de `encoding.test.ts`, `text.test.ts` et des tests de budget de `scan.test.ts`, cas « views », « edge » et « limits » du corpus de parité, et, une fois à la main sur un checkout au commit ci-dessus (avant l'extraction de ce dépôt), comparaison différentielle des vues, fenêtres, candidats décodés, budgets et JWT entre le moteur d'origine (Node) et le portage sur 31 200 entrées aléatoires : aucune différence.

## Règles

Portage en Go, sans copie de code d'origine dans le dépôt (la copie figée `pack/initial/upstream/rules.ts.txt` n'est pas exécutée), de `secret-guard/packages/core/src/rules.ts` (SHA-256 `f7ec4603f9184d773b0bdf18227994df785cb7522dced50163c27231f8853499`, commit ci-dessus) :

| Origine | Portage |
|---|---|
| `scanFixedRules`, `capturedRange`, `encodingPenalty`, `encodingReasons` | `detect/rules.go`, `detect/families.go` (`scanFixedRules`, `scanPrivateKeys`, `scanFixedPattern`, `scanJWT`) |
| `scanCredentialUrls`, `stripTrailingUrlPunctuation`, constructeur `URL` et `decodeURIComponent` de JavaScript | `detect/families.go` (`scanCredentialURLs`), `detect/urlparse.go` |
| `scanContextualAssignments` et ses fonctions (`parseAssignmentValue`, `safeContextualValue`, `isSafeReference`, `isClearlyNonLiteralExpression`, `isSymbolicEnumValue`, `typeForSensitiveKey`, cookies, `-u`, Docker) | `detect/contextual.go` |
| `scanEntropy`, `entropyExcluded`, `shannonEntropy` (`Math.log2` de V8) | `detect/families.go`, `detect/jsstring.go` (`jsLog2`) |
| `isPlaceholder`, `isExactPublicExample`, `safeLiteral`, `PUBLIC_EXAMPLES` | `detect/validators.go` |
| motifs constants et littéraux | `detect/engine_patterns.go`, généré par `generator/rule-pack/engine-patterns.ts` (même traduction que le Pack) |

**Modifications (Apache-2.0, §4 b)** : traduction de TypeScript en Go ; règles chargées d'un Pack (`LoadRules`), refus typé d'un Pack inexploitable ; motifs en RE2 (`regexp`) : répétitions de plus de 1 000 (segments de JWT, queue d'URL, mot de passe de `-u`, préfixe de heredoc) lues à la main avec les bornes de l'origine ; positions en octets de la source, longueurs en unités UTF-16 comme JavaScript ; reprise de la recherche à `lastIndex` avec le contexte qui précède (`execFrom`) ; début de ligne de JavaScript après U+2028 et U+2029 pour les motifs de cookies et de `_authToken` ; lecture linéaire là où l'origine relit un préfixe de ligne ou un texte à chaque correspondance (`contextualText`) ; analyse d'URL de la norme WHATWG réduite à ce que lit `scanCredentialUrls`, sans UTS 46 (hôte spécial non ASCII ou `xn--` tenu pour valide, sauf U+FFFD) ; valeurs d'exemple public assemblées à l'exécution.

**Vérification** : tests de `detect/rules_test.go` (scores, raisons et pénalités de chaque règle), `corpus_rules_test.go` (cas du corpus de parité de chaque règle, par `Scan`), oracles et fuzz de `rules_fuzz_test.go`, pires cas de `rules_worstcase_test.go` ; comparaison différentielle avec le moteur d'origine (checkout au commit ci-dessus, répertoire temporaire supprimé, banc non commité, `TestDifferentialCases`) sur 71 000 entrées aléatoires : seul écart, des hôtes `xn--` (UTS 46).

## Analyse

Portage en Go, sans copie de code d'origine dans le dépôt, de la partie de `secret-guard/packages/core/src/scanner.ts` (SHA-256 `80ba8d74d90bd3fd045542fadfd8792171d5b7beaa2ac1067edbacbaee77cafc`, commit ci-dessus) qui assemble l'analyse, et de la forme du résultat de `types.ts` :

| Origine | Portage |
|---|---|
| `scan` (limite `MAX_INPUT_BYTES`, constat d'échec `input_too_large` / `scanner_failure`) | `detect/scan.go` : `Scan`, `MaxInputBytes`, issue `scan_limit` / `scan_error` (`detect/result.go`) |
| `collectFindings`, `scanDetectors`, `scanDecodedText`, `scanBase64Candidates`, `MAX_FINDINGS` | `detect/scan.go` : `collect`, `detectors`, `decodedText`, `base64Candidates`, `MaxFindings` |
| `dedupeOverlaps`, `specificityRank`, `boundedScore`, `levelForScore` | `detect/scan.go` |
| `ScanResult`, `Finding` | `detect/result.go` : `Result`, `Finding`, `Failure`, `Level`, `Options` |

**Modifications (Apache-2.0, §4 b)** : traduction de TypeScript en Go ; entrée en octets (limite de 1 Mio mesurée sur les octets reçus, jamais un préfixe analysé) ; résultat réduit à ce qui peut sortir du moteur (ni valeur, ni extrait, ni masque, ni condensat, ni raison ; pas de rédaction) ; échec rendu par une issue en liste fermée sans constat (au lieu d'un constat d'échec) ; panique rattrapée en `scan_error` ; longueurs comparées par `dedupeOverlaps` en unités UTF-16 de la source et ordre `localeCompare` des identifiants de règle (`localeOrder`) ; budget de décodage épuisé dans un validateur vérifié après chaque passe de règles « motif seul » (fenêtres des textes décodés comprises). Ajout absent de l'origine : l'Empreinte locale (`detect/fingerprint.go`, `ScanWithFingerprint`), HMAC-SHA256 tronqué à 16 octets de la valeur sous une clé de l'appelant.

**Vérification** : `TestParity` (`detect/scan_test.go`) : les 823 cas de tous les fichiers du manifeste, nombre de cas égal au manifeste, aucun écart.

## Extraction de xSOM Fleet

Le portage a d'abord été écrit dans xSOM Fleet (dépôt privé, `agent/internal/detection`), puis extrait ici le 13 octobre 2026, au commit `652415d` de Fleet, avec ses tests et ses données. Changements de l'extraction, sans effet sur les résultats (`TestParity` : 823 cas, 0 écart) :

- paquet `detection` → `detect` (API publique inchangée : `LoadRules`, `Scan`, `ScanWithFingerprint`, `Rules.Has`, `Result`, `Finding`, `FingerprintKey`, `NewFingerprintKey`, `PackError`, `PackRefusal`, `ErrPackUnusable`, `ErrFingerprintKeyInvalid`, `MaxInputBytes`, `MaxFindings`, `FingerprintKeyBytes`) ;
- type du Pack : le type généré `contracts.RulePack` de Fleet devient `pack.Pack` (mêmes champs et mêmes noms JSON ; `RuleId` → `RuleID`), lu par le décodage strict `pack.Decode` ; Pack initial embarqué (`pack.Initial`) ;
- limites : la constante générée `checklimits.MaxScanBytes` de Fleet devient `internal/limits` (seule source du moteur et du Pack) ;
- noms des tests : le préfixe des exigences de Fleet est retiré. `TestFR13<Nom>` devient `Test<Nom>` (par exemple `TestFR13Parity` → `TestParity`, `TestFR13UnicodeParity` → `TestUnicodeParity`, `TestFR13DifferentialCases` → `TestDifferentialCases`), `TestFR8<Nom>` devient `Test<Nom>`, et les sous-tests perdent leur préfixe `FR-13: ` ou `FR-8: ` (« FR-13: parité à 100 % avec Secret Guard » → « parité à 100 % avec Secret Guard ») ; les tests du générateur TypeScript de même ;
- test resté dans Fleet : `signed_pack_external_test.go` (acceptation d'un Pack signé par les paquets de Fleet), remplacé ici par `detect/public_api_test.go` (même corpus, par l'API publique seule) ;
- copie du schéma : `schema/RulePack.json` est la copie du JSON Schema du contrat signé de Fleet, qui en reste la source ; le test `TestSchemaCopy` (`pack/`) compare `pack.Pack` à cette copie.

## Instructions cachées et mentions

Portage en Go, sans copie de code d'origine dans le dépôt, de deux fonctions de Secret Guard (même dépôt et même commit que ci-dessus ; fichiers identiques au commit `cefe30a10854432911ec08eba32a15d2400732fc`, où ils ont été lus le 13 octobre 2026) :

| Fichier d'origine | SHA-256 | Portage |
|---|---|---|
| `secret-guard/packages/core/src/hidden.ts` | `b148532f7573b83afb457eedc639e1a3c512f62434691c24a3add45b8e3c7914` | `hidden/hidden.go` : `findHidden` → `Find`, `stripHidden` → `Strip`, `flagTags`, `benignInvisible`, `classify`, `resolveInvisible`, `MAX_HIDDEN_FINDINGS` → `MaxFindings`, `SCATTERED_INVISIBLE_THRESHOLD` → `ScatteredInvisibleThreshold` ; ses cinq expressions à propriétés Unicode → `hidden/unicode_tables.go` |
| `secret-guard/packages/cli/src/file-guard.ts` | `d6a29932509fe6b74ad2bce0fcffd30f8456e5cced4f48e1eeb8784966babcce` | `mentions/mentions.go` : `mentionedPaths` → `Parse` (sans `readLocalFile`, sans résolution) |

Licence : Apache-2.0, `secret-guard/packages/core/` et `secret-guard/packages/cli/` dans le périmètre ouvert de `LICENSING.md` du dépôt d'origine (même texte de licence, `pack/initial/upstream/LICENSE`).

**Modifications (Apache-2.0, §4 b)** :

- `hidden` : traduction de TypeScript en Go ; texte lu en octets (un octet hors UTF-8 vaut U+FFFD, un par octet, comme dans le corpus de parité ; jamais signalé, il compte comme un caractère) ; limite de 1 Mio mesurée sur les octets reçus (l'origine mesure l'UTF-8 du texte décodé ; les deux ne diffèrent que pour des octets invalides, et une entrée qu'elles classeraient différemment arrête le générateur) ; chaque suite porte en plus son étendue en octets (`ByteStart`, `ByteEnd`) ; ligne et colonne comptées comme à l'origine (points de code, fins de ligne `\n`) ; lecture en deux passes linéaires sans tableau de caractères (un jugement d'un octet par caractère), drapeau de subdivision reconnu par une lecture de 8 caractères au plus après le drapeau noir ; `Strip` rend une copie, toujours en UTF-8 valide (un octet invalide y devient U+FFFD, comme `Find` le lit : garder l'octet pourrait, une fois retiré un voisin, former un caractère absent du texte) ; au-delà de 1 Mio, copie inchangée (l'origine rend le texte inchangé avec `complete: false`, ici `Find` le dit). Le message caché n'est jamais décodé ni rendu (l'origine ne l'expose pas non plus) ; le libellé français `hiddenKindLabel` n'est pas porté (l'appelant a son catalogue).
- Classes Unicode : `\p{Default_Ignorable_Code_Point}`, `[\p{Extended_Pictographic}\p{Emoji_Modifier}\p{Regional_Indicator}]`, `[\p{L}\p{M}\p{N}]`, les dix-huit écritures liantes avec `\p{M}`, `\p{Script=Mongolian}` : tables explicites calculées par Node sur chaque point de code (`generator/hidden/unicode-tables.ts`, Unicode 17.0.0), indépendantes de la version Unicode de la chaîne Go ; le test `TestUnicodeTables` les compare à la bibliothèque standard de Go 1.27 (même version), et le générateur des vecteurs vérifie que `hidden.ts` porte exactement ces cinq expressions.
- `mentions` : traduction de TypeScript en Go ; aucune lecture de fichier ni résolution de chemin (l'appelant résout et lit) ; mêmes expressions, en RE2 (`regexp`), `\s` et `\S` de JavaScript écrits par une classe explicite (le `\s` de RE2 n'a que l'ASCII), `\d` en `[0-9]` ; chaque mention porte en plus le chemin tel qu'écrit, les chiffres de son suffixe `#L` (`Lines`, que l'origine jette) et son étendue en octets ; doublons fusionnés sur le chemin tel qu'écrit, et non résolu comme à l'origine (l'appelant fusionne après résolution) ; fusionner des suffixes de lignes différents vide `Lines` (la fusion ne restreint jamais la lecture). L'ordre des retraits est celui de l'origine : dans `@a.ts#L1-2,`, la virgule est retirée après le suffixe, qui reste dans le chemin.

**Vecteurs de parité** : `vectors/hidden.json` (152 cas) et `vectors/mentions.json` (122 cas), produits par `npm run vectors:hidden -- --upstream <checkout>` dans `generator/` (`generator/hidden/main.ts` ; `--check` régénère en mémoire et compare octet pour octet). Le générateur lit le checkout (SHA-256 de chaque fichier vérifié : tout `secret-guard/packages/core/src`, `secret-guard/packages/cli/src/{file-guard,hook,instructions,report}.ts`, `secret-guard/tests/cli/file-guard.test.ts` (SHA-256 `2804cd6eb96488f3956b3132120823879647841ece96f94eab0ba6318ec2b583`)), les transpile dans un répertoire temporaire (aucune dépendance d'origine installée), exécute `tests/cli/file-guard.test.ts` avec le `expect` de Vitest et relève chaque texte passé à `findHidden` et chaque prompt passé à `mentionedPaths` (cas `upstream/file-guard.test.ts > …`). Les autres cas sont synthétiques (`generator/hidden/synthetic.ts`) : chaque porteur, chaque usage légitime, mélanges, positions, bornes de 1 Mio, octets hors UTF-8 ; chaque forme de mention, chaque espacement de JavaScript. Résultats attendus : sortie même de `findHidden` et `stripHidden` (positions converties en octets par la ligne et la colonne d'origine), et de `mentionedPaths` avec le répertoire de travail `/work` ; les étendues des mentions viennent des expressions mêmes de `mentionedPaths`, lues dans le source vérifié et exécutées avec leurs positions (drapeau `d`), et le générateur exige que leurs chemins, résolus et fusionnés comme à l'origine, redonnent exactement sa sortie. Tests d'origine non repris : `tests/core/hidden.test.ts` et `tests/cli/instructions.test.ts` sont hors du périmètre ouvert de `LICENSING.md` (ni lus ni copiés ; les cas synthétiques couvrent les mêmes comportements) ; `tests/cli/hook.test.ts` n'apporte ni caractère caché ni mention, et deux de ses prompts portent une valeur synthétique de jeton. Le 13 octobre 2026, `npm run vectors:hidden -- --upstream <checkout> --check` sur un checkout au commit `cefe30a` rend « Vecteurs identiques : hidden.json 152 cas, mentions.json 122 cas ».

**Vérification** : `TestHiddenParity` et `TestMentionsParity` (100 %, échec par identifiant de cas seulement) ; `TestFindMatchesReference` (20 000 textes aléatoires contre une transcription directe de l'origine) et `FuzzHiddenFind` (même oracle) ; `TestParseMatchesOracle` (50 000 prompts contre un parcours écrit à la main) et `FuzzMentions` ; `TestJSSpace` (classe d'espacements égale à `\s` de JavaScript sur chaque point de code) ; pires cas de 1 Mio bornés en temps (`TestWorstCases`, `TestParseWorstCases`).

## Tables Unicode

`hidden/unicode_tables.go` (classes de `hidden.ts`, section « Instructions cachées et mentions ») est calculé par Node 26, même version Unicode 17.0.0, et comparé à la bibliothèque standard de Go par `TestUnicodeTables` ; il est couvert par le même avis ci-dessous.

`detect/unicode_tables.go` : propriété `Default_Ignorable_Code_Point` (absente de RE2), **Unicode 17.0.0**, générée par `tools/unicodetables` depuis `https://www.unicode.org/Public/17.0.0/ucd/DerivedCoreProperties.txt` (SHA-256 `24c7fed1195c482faaefd5c1e7eb821c5ee1fb6de07ecdbaa64b56a99da22c08`, vérifié par le générateur ; le fichier n'est pas dans le dépôt). Unicode 17.0.0 est la version de Node 26 (ICU 78) qui a produit le corpus, de la bibliothèque standard de Go 1.27 et de `golang.org/x/text` sous Go 1.27. `vectors/unicode-parity.json` fige ce que calcule Node (plages de la propriété, empreinte de la normalisation NFKC de chaque point de code) ; le test Vitest `generator/test/unicode-parity.test.ts` le recalcule avec Node, le test Go `TestUnicodeParity` avec la table et `golang.org/x/text` (et recalcule la propriété depuis la bibliothèque standard). Une montée de version Unicode se fait des deux côtés à la fois : régénérer la table, puis `npm run vectors:unicode` dans `generator/`.

Données Unicode, avis de la licence Unicode v3 (option b, documentation associée) :

```text
UNICODE LICENSE V3

COPYRIGHT AND PERMISSION NOTICE

Copyright © 1991-2026 Unicode, Inc.

NOTICE TO USER: Carefully read the following legal agreement. BY
DOWNLOADING, INSTALLING, COPYING OR OTHERWISE USING DATA FILES, AND/OR
SOFTWARE, YOU UNEQUIVOCALLY ACCEPT, AND AGREE TO BE BOUND BY, ALL OF THE
TERMS AND CONDITIONS OF THIS AGREEMENT. IF YOU DO NOT AGREE, DO NOT
DOWNLOAD, INSTALL, COPY, DISTRIBUTE OR USE THE DATA FILES OR SOFTWARE.

Permission is hereby granted, free of charge, to any person obtaining a
copy of data files and any associated documentation (the "Data Files") or
software and any associated documentation (the "Software") to deal in the
Data Files or Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, and/or sell
copies of the Data Files or Software, and to permit persons to whom the
Data Files or Software are furnished to do so, provided that either (a)
this copyright and permission notice appear with all copies of the Data
Files or Software, or (b) this copyright and permission notice appear in
associated Documentation.

THE DATA FILES AND SOFTWARE ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF
THIRD PARTY RIGHTS.

IN NO EVENT SHALL THE COPYRIGHT HOLDER OR HOLDERS INCLUDED IN THIS NOTICE
BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES,
OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THE DATA
FILES OR SOFTWARE.

Except as contained in this notice, the name of a copyright holder shall
not be used in advertising or otherwise to promote the sale, use or other
dealings in these Data Files or Software without prior written
authorization of the copyright holder.
```

## Dépendances

| Module | Version | Paquet utilisé | Justification |
|---|---|---|---|
| `golang.org/x/text` | v0.43.0 | `golang.org/x/text/unicode/norm` | NFKC, absent de la bibliothèque standard ; `normalizedView` normalise chaque point de code comme `String.prototype.normalize("NFKC")`. Module officiel du projet Go (BSD-3-Clause, « Copyright 2009 The Go Authors »), tables Unicode 17.0.0 sous Go 1.27 ; seule dépendance du moteur. L'empreinte NFKC de chaque point de code est égale à celle de Node (`TestUnicodeParity`). |

Le générateur TypeScript (`generator/`, outil de développement, absent du moteur livré) dépend de `typescript`, `vitest`, `zod`, `smol-toml` et `@types/node`, versions exactes dans `generator/package.json` et `generator/package-lock.json`.

Licence de `golang.org/x/text` (BSD-3-Clause, fichier `LICENSE` du module v0.43.0), reproduite pour la distribution des binaires :

```text
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Avis de licence

```text
Secret Guard (secret-guard/packages/core)
Copyright (c) 2026 XSOM CONSULTING ("xSOM")

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

Origine de la ligne de copyright : fichier `LICENSE` à la racine du dépôt `jt33120/poc-AI_guard`, au commit `c177a447b8cdf8ce07e0c3160ea45dace99b6dc9`, ligne 2, citée telle quelle :

```text
Copyright (c) 2026 XSOM CONSULTING ("xSOM")
```

Le `LICENSE` de `secret-guard/packages/core`, copié dans `pack/initial/upstream/LICENSE`, est le texte Apache-2.0 seul, sans ligne de copyright propre. Le dépôt d'origine n'a pas de fichier `NOTICE` à ce commit. La licence n'accorde aucun droit sur les noms et marques « xSOM AI Guard » et « Secret Guard ».
