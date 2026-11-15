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
- **Fichiers lus** (Apache-2.0, périmètre ouvert de `LICENSING.md` du dépôt d'origine) : le moteur `secret-guard/packages/core/src/**`, et les tests `secret-guard/tests/core/{scan,security,encoding,text}.test.ts`, exécutés sur la copie transpilée avec le `expect` de Vitest (une assertion d'origine en échec arrête le générateur). Les entrées que ces tests passent au moteur deviennent des cas `upstream/<fichier> > <suites> > <titre> [rang] #n` (fichiers `upstream-*.json`) ; aucun fichier d'origine n'est copié dans ce dépôt. Les entrées de `decodeBase64`, `isStructurallyValidJwt`, `decodeScannableText` et `redactAndRescan` sont reprises comme entrées de `scan` : leur cas prouve la parité de l'analyse, pas celle de la fonction éprouvée par le test d'origine (celle de `redactAndRescan` est prouvée à part : section « Masquage et décisions »).
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

**Liens de ressources de claude.ai (v0.7.0)** : l'entropie écarte la fin d'un lien `https://claude.ai/[code/]{artifact,chat,project}/<identifiant>` (`detect/entropylinks.go`, `isKnownResourceLink`) : l'identifiant d'une ressource qui exige une session n'est pas un secret (faux positif relevé sur un Poste réel le 10 novembre 2026). Les liens de partage public (`/share/`), les autres hôtes, un identifiant de connexion ou `http://` restent détectés (`TestEntropyIgnoresClaudeResourceLinks`).

**Règles de données personnelles (v0.7.0), sans origine dans Secret Guard** : `iban`, `fr_nir`, `fr_siret`, `fr_siren` et `payment_card` s'ajoutent aux 35 règles du catalogue d'origine dans le Pack initial (`generator/rule-pack/personal-data.ts`, après l'extraction de `rules.ts`) ; leurs validateurs sont dans `detect/personaldata.go`, avec le raccourcissement de la correspondance de l'IBAN (`trimmers`, `scanFixedPattern`). Ce sont les seules règles du Pack initial dont le résultat attendu ne vient pas du moteur d'origine : le corpus les éprouve dans `vectors/detection/rules-personal-data.json` (80 cas), dont les attentes viennent d'une seconde écriture indépendante des contrôles et des positions (le moteur d'origine doit ne rien trouver dans ces textes), jamais du moteur Go. Les 823 cas du moteur d'origine, les vecteurs du masquage hors de ces règles et ceux du Pack du client sont inchangés. Types de Substituts : un par règle (`SubstituteLabels()`).

**Vérification des règles de données personnelles** : `TestPersonalDataValidators` (49 numéros connus ou calculés), `TestIBANEveryCountry` (un IBAN calculé pour chacun des 52 pays de la table, par groupes et d'un bloc, seul ou suivi d'un mot, d'un nombre ou d'une ponctuation), `TestIBANPrefixLength`, `TestPersonalDataScan`, `TestPersonalDataNoFalsePositives`, `TestPersonalDataViews`, `TestPersonalDataRedaction`, `TestPersonalDataSubstitutes`, `TestRuleCorpus` (cas `<ruleId>/…` du corpus), `TestRuleScoresAndReasons` (score, raisons et pénalité d'encodage), pires cas de 1 Mio (`TestWorstCases`, `TestScanWorstCases` : têtes d'IBAN, groupes de chiffres, suite de chiffres, IBAN valide répété, mot SIREN répété) ; côté générateur, `test/personal-data.test.ts` (exemples connus, table des pays comparée à celle du moteur Go, types et validateurs comparés au schéma) et la régénération `npm run vectors:detection -- --upstream <checkout> --check`.

## Règles de fournisseurs (v0.8.1)

**Origine.** Les 294 premières règles de fournisseurs du Pack initial (`generator/rule-pack/provider-rules.json`, puis `pack/initial/pack.json` ; les 66 suivantes, depuis la v0.10.0, viennent de Betterleaks : dernière section de ce fichier) reprennent des motifs des règles de détection de Titus : dépôt `praetorian-inc/titus`, dossier `pkg/rule/rules/` (318 fichiers YAML), commit `b3964d4352ac2f84af11d1396e864bdc772f2b92` du 12 novembre 2026, Apache License, Version 2.0. Ces règles sont elles-mêmes dérivées de NoseyParker (`praetorian-inc/noseyparker`, identifiants `np.*`) et de Kingfisher (`mongodb/kingfisher`, identifiants `kingfisher.*`), sous la même licence ; avis reproduits dans `NOTICE`. Chaque règle du Pack garde l'identifiant de sa règle d'origine (champ `upstream` de `provider-rules.json`). Seuls les motifs (et, pour en tirer des valeurs d'essai, leur forme) sont repris : ni les exemples publiés avec les règles, ni leurs appels de validation, ni leur code.

**Sélection.** Des 508 règles d'origine qui ont un motif et un exemple, 294 sont retenues. Sont écartées : 54 dont RE2 ne lit pas le motif (regards avant ou arrière, répétitions de plus de 1 000) ; 48 dont chaque exemple est déjà trouvé par une règle dédiée du Pack (GitHub, GitLab, OpenAI, Slack, Stripe, SendGrid, npm, Hugging Face, Shopify, DigitalOcean, Google, URL à identifiants, clés privées, cartes bancaires…) ; 92 par liste : clés publiques, identifiants et valeurs non secrètes (clé publiable Stripe, jeton public Mapbox, clé de projet PostHog, clés PubNub, DSN Sentry, identifiants de client, de compte ou de clé, variable chiffrée Travis CI…), règles génériques et constructions de code que les affectations du moteur lisent déjà (`np.generic.*`, en-têtes HTTP, chaînes de connexion, appels de connexion à une base, fichiers de configuration), doublons entre règles d'origine et mots-clés trop faibles (`lob`, `exa`) ; 20 dont aucune valeur d'essai ne pouvait être construite depuis le motif.

**Modifications (Apache-2.0, §4 b).** Par rapport aux motifs d'origine :

- *Un seul groupe capturant.* La valeur détectée est le premier groupe capturant d'une règle « motif seul » (docs/rule-pack.md) : le groupe de la valeur (le plus long sur les exemples d'origine) est gardé, sans nom, les autres groupes deviennent non capturants. Le motif est réécrit par `regexp/syntax` de Go (mode étendu développé, classes POSIX développées).
- *Limite de mot de tête* ajoutée devant un préfixe quand les exemples d'origine la tiennent (`apify_api_…`, `sbp_…`, `pa-…`) : un préfixe au milieu d'un mot n'est pas une clé.
- *Alias de moins de trois lettres retirés* du nom du fournisseur (`dd`, `pd`, `ic`, `zd`, `mg`, `mc`, `cio`, `bx`, `mm`, `tn`, `wpe`), sources de bruit et sans porte littérale possible ; pour Datadog, `dd` reste admis dans `DD_API_KEY` et `DD_APP_KEY` (ou `DD_APPLICATION_KEY`).
- *Préfixe de 1Password* (`ops_eyJ`) : casse du jeton réel.
- *Aucun contrôle hors motif* jusqu'à la v0.9.0. Les règles d'origine portent une entropie minimale, des exigences de classes de caractères et un appel de validation au fournisseur : rien de cela n'était repris (le moteur n'ouvre aucune connexion ; le schéma `RulePack` n'a pas ces champs). Depuis la v0.10.0, l'entropie minimale est reprise par un validateur nommé, sans changement du schéma (« Vraisemblance des règles de fournisseurs », dernière section).
- *Scores* : 95 pour les 113 règles à préfixe fixe, 80 pour les 181 règles qui exigent le nom du fournisseur à proximité de la valeur. *Type de secret* `provider_token`. *Identifiants* et *libellés de Substitut* (français, anglais) écrits pour ce dépôt.

**Écarts d'analyse du moteur ajoutés avec ces règles, sans effet sur le corpus d'origine** (`detect/prefilter.go`, `detect/literalindex.go`) :

- *Porte repliée.* Un motif qui replie la casse (`(?i)`, classe `[xX]` réécrite par l'analyseur) avait toujours été exécuté sans porte. Il reçoit une porte dont les littéraux, en minuscules ASCII, sont cherchés sans tenir compte de la casse ASCII ; RE2 repliant aussi K (U+212A) sur « k » et ſ (U+017F) sur « s », un texte qui porte l'un de ces deux points de code est admis d'office ; un littéral replié qui porte une autre lettre hors ASCII retire la porte. Quatre règles antérieures reçoivent ainsi une porte (`database_url_credentials`, `basic_auth_url`, `docker_auth`, `fr_siren`), sans effet sur leurs résultats.
- *Index des portes.* Les littéraux des portes des règles « motif seul » sont réunis dans un automate d'Aho-Corasick ; une seule lecture du texte rend les règles à exécuter (celles sans porte, celles dont un littéral figure dans le texte sans tenir compte de la casse ASCII, et les règles à porte repliée si le texte porte U+212A ou U+017F). Chaque règle admise rejoue sa porte exacte. L'index n'écarte jamais une règle que sa porte admet (`TestLiteralIndex`).
- *Jeton fini par un tiret* (`dashtail.go`) : avec une porte repliée, les candidats sont cherchés sur tout le texte (les littéraux en minuscules ne disent pas où le jeton commence).

**Corpus.** `vectors/detection/rules-providers.json`, 588 cas (un positif et un négatif par règle), hors des vecteurs du masquage comme les données personnelles. Valeurs synthétiques tirées de SHA-256 (`synth`) selon la forme du motif ; le cas négatif est la même valeur trop courte d'un caractère, ou réduite à ses littéraux quand la valeur est une adresse. Résultat attendu : motifs exécutés par le moteur d'expressions de JavaScript (seconde exécution, sans RE2 ni le moteur Go), fusionnés avec les constats du moteur d'origine par une seconde écriture de `dedupeOverlaps` (`generator/corpus/provider-rules.ts`). Le 13 novembre 2026, `npm run vectors:detection -- --upstream <checkout> --check` rend « Corpus identique : 1518 cas, 15 fichiers ».

**Mesures du 13 novembre 2026** (Apple M2 Pro, indicatives). Rappel sur les 1 142 valeurs d'exemple des règles d'origine (317 fournisseurs) : dans leur texte d'origine, 84 % trouvées (73 % avec les 40 règles antérieures), 66 % par une règle dédiée (13 %), 300 fournisseurs avec au moins une valeur trouvée (270) ; valeur seule dans une phrase, 60 % (52 %), 31 % par une règle dédiée (9 %). Bruit : aucun constat des règles de fournisseurs sur 72 091 lignes de code Go et JavaScript, de prose française et anglaise et de prompts, ni sur 4 860 fichiers d'un dépôt réel (46 Mo), où le nombre total de constats ne change pas (852 sur 300 morceaux de 64 Kio). Latence sur ces 300 morceaux : médiane 22,1 ms (21,9 ms), 95e centile 49 ms (36 ms) ; `BenchmarkScan/64KiB/propre` : 11,5 ms (13,8 ms avant l'index).

Vérification : `TestProviderRules`, `TestLiteralIndex`, `TestPrefilterInitialPack`, `TestPrefilterProof`, `TestPrefilterFoldCase`, `TestRuleCorpus`, `TestParity` et `TestParityWorkers` (1 518 cas), `TestExpurgateCorpus` (module `expurgation`), `FuzzPrefilterParity`.

## Analyse

Portage en Go, sans copie de code d'origine dans le dépôt, de la partie de `secret-guard/packages/core/src/scanner.ts` (SHA-256 `80ba8d74d90bd3fd045542fadfd8792171d5b7beaa2ac1067edbacbaee77cafc`, commit ci-dessus) qui assemble l'analyse, et de la forme du résultat de `types.ts` :

| Origine | Portage |
|---|---|
| `scan` (limite `MAX_INPUT_BYTES`, constat d'échec `input_too_large` / `scanner_failure`) | `detect/scan.go` : `Scan`, `MaxInputBytes`, issue `scan_limit` / `scan_error` (`detect/result.go`) |
| `collectFindings`, `scanDetectors`, `scanDecodedText`, `scanBase64Candidates`, `MAX_FINDINGS` | `detect/scan.go` : `collect`, `sequentialDetectors`, `decodedText`, `base64Candidates`, `MaxFindings` ; `detect/detectors.go` : `detectors`, `parallelDetectors` (même résultat, familles sans budget en parallèle) |
| `dedupeOverlaps`, `specificityRank`, `boundedScore`, `levelForScore` | `detect/scan.go` |
| `ScanResult`, `Finding` | `detect/result.go` : `Result`, `Finding`, `Failure`, `Level`, `Options` |

**Modifications (Apache-2.0, §4 b)** : traduction de TypeScript en Go ; entrée en octets (limite de 1 Mio mesurée sur les octets reçus, jamais un préfixe analysé) ; résultat réduit à ce qui peut sortir du moteur (ni valeur, ni extrait, ni masque, ni condensat, ni raison ; le masquage est une fonction à part, section « Masquage et décisions ») ; échec rendu par une issue en liste fermée sans constat (au lieu d'un constat d'échec) ; panique rattrapée en `scan_error` ; longueurs comparées par `dedupeOverlaps` en unités UTF-16 de la source et ordre `localeCompare` des identifiants de règle (`localeOrder`) ; budget de décodage épuisé dans un validateur vérifié après chaque passe de règles « motif seul » (fenêtres des textes décodés comprises). Ajout absent de l'origine : l'Empreinte locale (`detect/fingerprint.go`, `ScanWithFingerprint`), HMAC-SHA256 tronqué à 16 octets de la valeur sous une clé de l'appelant. Exécution plus rapide, sans écart de résultat : porte littérale exacte d'une règle à motif (`detect/prefilter.go` : aucun de ses littéraux obligatoires dans la vue, le motif n'est pas exécuté), familles de règles sans budget partagé exécutées en parallèle et constats concaténés dans l'ordre de `scanDetectors` (`detect/detectors.go`, `Options.Workers`) ; vitesse mesurée dans [docs/bench.md](docs/bench.md).

**Vérification** : `TestParity` (`detect/scan_test.go`) : les 823 cas de tous les fichiers du manifeste, nombre de cas égal au manifeste, aucun écart.

## Masquage et décisions

Portage en Go, sans copie de code d'origine dans le dépôt, de :

| Fichier d'origine (commit ci-dessus) | SHA-256 | Portage |
|---|---|---|
| `secret-guard/packages/core/src/scanner.ts` (en partie) | `80ba8d74d90bd3fd045542fadfd8792171d5b7beaa2ac1067edbacbaee77cafc` | `detect/redact.go` : `redact` et `validSpan` → `Redact`, `mergeRedactSpans`, `redactSpans` ; `placeholderName` (règles intégrées) → `placeholderName` ; `redactAndRescan` → `RedactAndRescan` |
| `secret-guard/packages/core/src/types.ts` (en partie) | `5dba44ed269730dd761ce1ec244681667ff01add4da4f5fbb22ae8a258608ceb` | `detect/redact.go` : `SanitizeResult` → `SanitizeResult`, `SanitizeFailure` ; `detect/decision.go` : `Decision` |
| `secret-guard/packages/core/src/risk.ts` | `1f65736ad6dd032ccb4ed15edbccbb24f631e05f7940b201cfe02a1e2ef54e40` | `detect/decision.go` : `decisionForLevel` → `DecisionForLevel` ; `levelForScore` et `boundedScore` étaient déjà portés dans `detect/scan.go`, identiques (vecteurs ci-dessous) |

**Modifications et écarts (Apache-2.0, §4 b)** : traduction de TypeScript en Go, et :

- **Octets au lieu d'unités UTF-16.** Les étendues sont en octets ; l'ordre et les égalités des positions sont ceux des positions UTF-16 de l'origine (étendues aux limites de caractères), le texte masqué d'une entrée UTF-8 valide est donc identique octet pour octet. Pour une entrée hors UTF-8, l'origine travaille sur le texte décodé (U+FFFD par octet invalide) et rend U+FFFD ; le moteur Go garde les octets d'origine hors des étendues. Les vecteurs écrivent le texte attendu du moteur Go, et le générateur vérifie que son décodage octet par octet est exactement le texte rendu par l'origine. Un caractère hors du plan multilingue de base dans un identifiant de règle devient deux « _ », comme les deux unités UTF-16 de JavaScript.
- **Analyse incomplète refusée par `Redact`** (`ErrRedactIncomplete`, aucun texte). À l'origine, le constat d'échec a une étendue vide : `redact` rendrait le texte inchangé.
- **Étendue hors du contenu refusée par `Redact`** (`ErrRedactSpan`, aucun texte), là où l'origine ignore le constat (`validSpan`).
- **Résidu : tout constat après masquage.** `RedactAndRescan` échoue (`SanitizeResidual`) dès que la nouvelle analyse a un constat. L'origine rend le texte quand la décision finale est `ALLOW`, c'est-à-dire avec des constats LOW seulement ; ses appelants (presse-papiers, références du chat, envoi d'un prompt) exigent zéro constat, comme le moteur Go. Sans effet avec le Pack initial : le plus petit score possible y est 30 (MEDIUM). Le générateur s'arrête sur tout cas où l'origine rendrait un texte avec un constat LOW.
- **Échec : aucun texte, copie effacée.** Le texte est rendu à part (`[]byte`), pas dans `SanitizeResult` ; la chaîne vide de l'origine devient `nil`. La copie masquée d'un échec (résidu, texte masqué de plus de 1 Mio) est effacée avant le retour.
- **Pas de seconde analyse sans constat initial** : le moteur est déterministe, elle rendrait la même chose (`Final` égal à `Initial`).
- **Règles propres à un client** : portées avec le Pack de règles du client (section « Règles du client ») : `RedactOptions.Custom` (Pack des libellés, celui d'`Options.Custom` par défaut dans `RedactAndRescan`) et `RedactOptions.NeutralCustomNames` (`neutralCustomNames`), libellé tiré de `displayLabel` puis `placeholderName`, second masquage aux libellés neutres. Le second masquage est fait quand la nouvelle analyse échoue (tout constat restant, règle ci-dessus), là où l'origine le fait quand la décision finale n'est pas `ALLOW`.
- **Niveau hors liste** : `DecisionForLevel` bloque ; l'origine rendrait `ALLOW` (niveau non représentable dans ses types). `boundedScore` de l'origine arrondit et rend 100 pour une valeur non finie ; les scores du moteur Go sont entiers (schéma du Pack), l'arrondi y est sans effet.

Comportement d'origine gardé tel quel, à connaître : une valeur d'affectation qui déborde sur la ligne suivante (`API_KEY=<jeton>` puis `NEXT=another`) est masquée avec cette ligne, et `<REDACTED_github_token>=another` est relu comme une nouvelle valeur : le masquage échoue (résidu) plutôt que de rendre un texte. Cinq cas des vecteurs sont dans ce cas ou un cas voisin (bloc YAML).

**Vecteurs** (`generator/redact/`, `npm run vectors:redact -- --upstream <checkout> [--check]`, même checkout, même commit et même transpilation que le corpus de parité) :

- `vectors/redact.json` : 593 renvois aux cas du corpus de parité qui ont un constat ou une analyse incomplète (leur entrée n'est pas recopiée), 26 cas synthétiques (vues, non ASCII, hors UTF-8, constats contigus, résidus, limites de 1 Mio avant et après masquage, plus de 2 048 constats ; valeurs tirées de SHA-256 sur des étiquettes `redact/…`), et 15 cas de `redact` seul sur des constats construits (chevauchement, contiguïté, ordre, nommage, contenu non ASCII et hors UTF-8 ; dont le test d'origine `unions overlapping and adjacent spans`). Pour chaque cas : issue, analyses initiale (sauf renvoi : celle du corpus) et finale en octets, taille et SHA-256 du texte de `redact`, et ce texte s'il fait au plus 16 Kio. Seule autre exception de la recherche de secrets (`.gitleaks.toml`).
- `vectors/decision.json` : `levelForScore` et `boundedScore` de chaque score entier de -5 à 105, `decisionForLevel` de chaque niveau.

**Vérification** : `TestRedactParity` (`detect/redact_test.go`) : 619 cas de `RedactAndRescan` et 15 cas d'étendues, aucun écart ; chaque cas du corpus de parité de l'original qui a un constat ou une analyse incomplète y figure (le fichier `rules-personal-data.json`, v0.7.0, est exclu : son masquage est éprouvé par `TestPersonalDataRedaction`). `TestDecisionParity` : 111 scores et 4 niveaux, aucun écart. `TestRedactLeavesNoValue` : dans les 576 textes masqués des cas du corpus qui ont un constat, aucune fenêtre de 8 octets d'une valeur détectée hors des libellés, sauf 30 fenêtres que l'entrée contient aussi hors de toute étendue détectée (`PASSWORD=process.env.PASSWORD` : la valeur contient le nom de la clé). `FuzzRedact` : un masquage réussi est relu sans constat. Le 13 octobre 2026, `npm run vectors:redact -- --upstream <checkout> --check` sur un checkout au commit ci-dessus rend « Vecteurs identiques : 619 cas, 15 cas d’étendues ».

## Expurgation (extension de ce module)

**Licences (v0.6.0)** : la reconnaissance des Substituts et ses primitives restent dans `detect`, sous Apache-2.0 ; l'expurgation qui les assemble est le module `github.com/xsom-consulting/secret-guard/expurgation` (dossier `expurgation/`), sous PolyForm Small Business 1.0.0 (`expurgation/LICENSE`), avec le module WebAssembly qui l'embarque (`expurgation/cmd/secret-guard-wasm`) et l'outil de parité (`expurgation/tools/wasmparity`). Aucune de ces parties n'a d'origine dans Secret Guard : rien de l'œuvre d'origine (Apache-2.0) ne passe sous l'autre licence. Les versions v0.1.0 à v0.5.1 restent entièrement sous Apache-2.0.

**Aucune origine dans Secret Guard** : `expurgation/expurgate.go` (`Expurgate`, `ExpurgateAndRescan`, `Substitution`, `Options`, `SanitizeOrdinal`, `ErrIncomplete`, `ErrSpan`, `ErrEncoding`, `ErrOrdinal`, `ErrLanguage` ; avant la v0.6.0, `detect/expurgate.go`), `detect/secretrange.go` (`SecretRange`, `Rules.FirstLineSecretEnd`) et `detect/substitute.go` (`SubstitutePrefixes`, `SubstituteLabels`, `SubstituteLanguage`, `FindSubstitutes`, `SubstituteSpan`, `SubstituteText`, grammaire des Substituts, `ErrSubstituteOrdinal`, `ErrSubstituteLanguage`) sont écrits pour ce module, sans code ni test d'origine, et `vectors/expurgate.json` est produit par un test Go de ce module (`TestExpurgateVectors`, option `-update`), pas par le générateur TypeScript. Ils réutilisent la fusion des étendues de `Redact` (portée de `redact`, section « Masquage et décisions »), que `Redact` et `RedactAndRescan` gardent inchangée (`TestRedactParity`).

**Fin de ligne gardée, sans effet sur la détection** : un constat d'une règle à format fixe dont l'étendue, fusionnée par `dedupeOverlaps` avec la vue des lignes jointes (`lineWrappedFixedViews`), prend le premier mot de la ligne suivante (`export A=<jeton>\nexport B=x`, fichier `.env`) est, dans l'expurgation seulement, ramené à sa première ligne si elle est à elle seule une valeur exacte de la règle et que l'étendue s'arrête devant `=`, `:`, une espace ou une tabulation, ou (depuis la v0.5.2) que ce qu'elle prend après la fin de ligne n'a pas la forme d'une fin de jeton (`looksLikeWrappedTail` : ni chiffre, ni `+` ou `/`, moins de trois changements de casse hors majuscule initiale, moins de 24 caractères ; `fi`, `done`, `EOF`, `end` seuls sur leur ligne disparaissaient du texte expurgé) (`firstLineSecretEnd`) ; sinon (jeton réellement coupé) l'étendue entière est remplacée. Les étendues des constats, le corpus de parité et les vecteurs du masquage et de la détection sont inchangés. Avec une clé, l'Empreinte locale de chaque `Substitution` est celle des octets d'origine qu'elle remplace exactement (étendue rétrécie, fusionnée ou élargie) ; `Expurgate`, sans clé, ne garde l'Empreinte locale d'un constat que pour son étendue exacte et refuse sinon (`ErrExpurgateSpan`).

**Écarts d'analyse ajoutés (v0.10.0), sans effet sur le corpus** : bruit d'entropie réduit sur du code, mesuré par le banc de bruit `tools/bruit` (`docs/bench.md`, « Bruit sur du code ») sur le dépôt xSOM Fleet à un commit épinglé (4 614 fichiers) : `high_entropy` passe de 868 constats à 371, dont 272 sont le base64 d'images embarquées dans deux pages HTML ; les quatre dépôts ouverts du banc baissent aussi, aucun ne monte. Corpus de bruit `vectors/noise-entropy.json` (19 lignes de code et liens ordinaires : 19 signalés par la v0.9.0, 0 après ; `TestNoiseEntropyCorpus`). Les 299 constats `high_entropy` attendus par le corpus de parité sont inchangés (`TestParity`, 1 639 cas, 0 en écart).

- *Cause établie : pourquoi `isEntropyName` laissait passer des identifiants en casse de chameau.* `isEntropyName` n'admet un mot que si `nameTokenLetters` (`detect/base64words.go`) le reconnaît et que `hasAcronymHump` ne l'écarte pas. Or (1) `isCamelLetters` n'admet une bosse d'une seule minuscule qu'en tête de mot : « Ai », « Id », « Is », « Le » au milieu d'un nom le font refuser (`…ElemAiServiceMistralLeChat`, `…OfferIdChatgptPlus`, `…ListenerIsExclusive`) ; (2) un seul sigle par mot, et `hasAcronymHump` écarte de l'entropie tout mot qui en porte un, même final (`…CurrencyEUR`, `TestFR16…`) ; (3) un chiffre n'est admis qu'entre la fin d'une bosse et le début d'une autre, un ou deux à la fois, ou en fin de mot : « FR16 » (après un sigle), « Ed25519 » (cinq chiffres après une bosse courte) et « A2K » (lettre, chiffre, lettre en fin de mot) le font refuser. Les noms de types générés depuis un schéma et les noms d'essais portent presque toujours l'un de ces morceaux : 486 des 868 constats d'entropie du dépôt mesuré. Les trois identifiants reproduits (une constante générée à bosses courtes, un nom d'essai à sigle et chiffres, une constante à suffixe « A2K ») échouent chacun sur une de ces trois règles.
- *Identifiants générés longs* (`detect/entropynames.go`, `isGeneratedIdentifier`, `generatedWords`) : `nameTokenLetters` et `hasAcronymHump` ne changent pas (les candidats base64 et les mots courts gardent leur règle) ; `isEntropyName` admet en plus un mot fait de mots réguliers (une majuscule puis deux minuscules au moins, ou trois minuscules en tête) et de morceaux irréguliers bornés : bosse courte, sigle de 2 à 5 majuscules, majuscule seule, suite de 1 à 5 chiffres après une lettre. Quatre mots réguliers au moins ; un morceau irrégulier au plus pour deux mots réguliers de 6 lettres en moyenne, ou pour trois de 5 lettres, de 4,5 lettres à partir de sept mots, de 4 lettres à partir de huit. Mesure sur 10 millions de jetons alphanumériques aléatoires par longueur : aucun de 20 ni de 48 caractères n'a cette forme sans avoir déjà celle d'un nom, 16 de 32 caractères (5 pour la forme d'avant ; mesure refaite à la relecture sur 50 millions de suites : 113 et 46, soit 3 pour un million en tout) ; `TestEntropyNameRarelyMatchesTokens` (500 000 tirages de trois suites par longueur) garde les bornes de 1 pour 1 000 à 20 caractères et de 1 pour 100 000 à 32, et borne à 1 pour un million à 48 caractères ce qui était « aucune sur 150 000 ». Restent signalés : les noms de moins de quatre mots réguliers à sigles (`TestFR13HookIPCNearDeadline`), les sigles de plus de 5 majuscules. Pertes acceptées : comme en v0.8.1, l'avertissement d'entropie d'une phrase de passe en casse de chameau, ici d'au moins quatre mots, sans nom sensible devant elle ; et celui d'un jeton aléatoire fait de lettres seules en casse mêlée, sans aucun chiffre, qui a cette forme 3 fois sur 10 000 à 32 et à 40 caractères, où la forme d'avant en laissait passer 31 puis 2 pour un million (1,1 pour 1 000 à 24 caractères, 1,4 pour 10 000 à 48 ; mesure de la relecture sur 5 millions de suites par longueur, bornée par `TestEntropyNameRarelyMatchesLetters`). Un jeton alphanumérique de 40 caractères n'a aucun chiffre qu'une fois sur 1 100 environ, et le seuil de 4,3 bits écarte déjà 12 suites de 32 lettres sur 100. Les branches à sept et à huit mots font plus de la moitié de cette perte à 40 caractères et au-delà, pour 22 des 349 mots d'identifiants réels admis dans le banc : les retirer est une décision ouverte. Essais : `TestGeneratedWords`, `TestIsGeneratedIdentifier`, `TestEntropyIgnoresNames`, `TestEntropyKeepsTokensBesideNames`, `TestEntropyNameRarelyMatchesLetters`.
- *Identifiants publics dans un chemin d'URL* (`detect/entropypath.go`, `isPublicID`, appelé par `isShortWords`) : dans `https://www.legifrance.gouv.fr/codes/article_lc/LEGIARTI…`, la suite d'entropie commence après le dernier point de l'hôte ; un mot de plus de 12 caractères d'un segment n'était admis que fait de lettres seules. Sont admis en plus : des chiffres seuls, 20 au plus (numéro d'article d'un centre d'aide) ; une référence faite de 2 à 12 majuscules puis de 4 à 20 chiffres (référence d'un texte de loi) ; 32, 40 ou 64 chiffres hexadécimaux d'une même casse accolés à un titre en tirets (identifiant de page), longueurs que `entropyExcluded` écarte déjà quand le segment entier en est fait. Un jeton qui mêle majuscules, minuscules et chiffres reste détecté dans le chemin d'une URL, seul ou accolé à un titre, à un numéro ou à une référence (`TestEntropyKeepsTokens`). Ce qui n'est plus signalé : un secret fait de chiffres seuls dans un chemin, et une clé hexadécimale de 32, 40 ou 64 chiffres accolée à des mots par un tiret ou un souligné. Restent signalés, parce que rien ne les distingue d'un jeton : les identifiants alphanumériques opaques de 13 caractères et plus (fiche d'une place de marché, document partagé, fichier d'un réseau de diffusion). Essais : `TestIsPublicID`, `TestEntropyIgnoresPaths`.
- *Non traité, mesuré* : le base64 d'une image embarquée (`data:image/…;base64,`) donne un constat par tranche de 512 caractères (272 des 371 constats d'entropie restants du dépôt mesuré, dans deux fichiers), et un alphabet écrit en clair (`ABC…XYZabc…xyz0123456789`, une quinzaine de constats) reste signalé hors de la valeur exacte `base64Alphabet`.

**Écart d'analyse ajouté (v0.8.1)** : mot de passe annoncé dans une phrase (`detect/passwordphrase.go`). Un indice (« mdp », « mot de passe », « mot-de-passe », « code d'accès », « pass », et les noms anglais que `typeForSensitiveKey` classe « password »), une liaison facultative sur la même ligne (« est », « is », « c'est », « : » ou « = » après un indice que l'affectation ordinaire ne connaît pas), puis un seul mot de 8 à 256 points de code qui mêle trois classes de caractères : constat de `contextual_password` sur la valeur seule. Relevé sur un Poste réel le 2026-11-12 : « … avec mon mdp <valeur> » passait sans constat (affectation ordinaire limitée aux noms anglais reliés par « = » ou « : », entropie limitée à 20 caractères de la classe base64). Un constat qui chevauche un constat de l'affectation ordinaire, des cookies ou de « -u » de la même vue n'est pas ajouté (chemin séquentiel et chemin parallèle, `detectors.go`) : les 823 cas tirés de l'origine sont inchangés. Cas nouveaux : `vectors/detection/rules-password-phrase.json` (27 cas), résultat attendu tiré de la seconde écriture `generator/rule-pack/password-phrase.ts`, le moteur d'origine ne trouvant rien dans ces textes ; exclus des vecteurs du masquage comme les données personnelles. Vérification : `TestPasswordPhraseFindsAnnouncedValue` (en échec avant), `TestPasswordPhraseIgnoresOrdinarySentences`, `TestPasswordPhraseLeavesAssignmentsToOrigin`, `TestPasswordPhraseHintsFollowSensitiveKeys`, `TestPasswordPhraseRedaction`, `TestPasswordPhraseWorstCases`, `TestPasswordPhraseExpurgation` (module `expurgation`) ; `TestParity`, `TestParityWorkers`, `TestRedactParity`, `TestDecisionParity`.

**Écarts d'analyse ajoutés (v0.8.1), sans effet sur le corpus** : bruit réduit, mesuré par l'agent « Bruit » de xSOM Fleet sur un dépôt réel d’environ 4 170 fichiers (high_entropy : 2 008 constats dans 174 fichiers avant, 866 dans 136 après ; fichiers avec au moins un constat : 446 avant, 408 après ; aucune analyse incomplète ni avant ni après) et par le corpus de bruit `vectors/noise.json` (38 textes ordinaires relevés sur des Postes réels : 26 signalés avant, 0 après ; `TestNoiseCorpus`).

- *Noms écartés de l'entropie* (`detect/entropynames.go`, `isEntropyName`) : un candidat sans `+` ni `=` dont chaque mot (séparé par `/`, `-`, `_`) est un mot de nom (`nameTokenLetters`, celui des candidats base64 de la v0.5.1, sans sigle mêlé de minuscules : `hasAcronymHump`) ou un mot hexadécimal d'une même casse de 24 caractères au plus (`isShortHexWord`), avec au moins un mot de nom de 4 lettres qui ne soit pas fait de chiffres hexadécimaux. Couvre les identifiants de types générés en casse de chameau (1 506 des 2 008 constats du dépôt mesuré), le nom d'un fichier de licence (`LICENSE-PolyForm-…`), les chemins dont un dossier porte un identifiant hexadécimal court (dossier d'un agent dans `.claude/worktrees/`, dossiers de rendu d'un dépôt). Un sigle mêlé (`VSCode`) n'est pas admis : le cas de l'origine « does not broadly exempt a path-shaped entropy candidate » garde son constat. Une valeur seulement hexadécimale, ou hexadécimale coupée par des tirets, n'est jamais un nom. Mesure : 24 suites aléatoires de 20 caractères sur 150 000 (alphanumérique, base64, base64url) ont cette forme, aucune à 32 ni à 48 (`TestEntropyNameRarelyMatchesTokens`). Perte acceptée : l'avertissement d'entropie d'une phrase de passe écrite en casse de chameau sans nom sensible devant elle.
- *Identifiants publics d'objets d'un Fournisseur* (`providerObjectID`) : `apikey_01…`, `wrkspc_01…`, `user_01…`, `msg_01…`, `msgbatch_01…` suivis de 20 à 24 caractères alphanumériques (identifiant d'une clé d'API d'Anthropic tel que le montrent la console et l'API d'administration, jamais la clé), sur le modèle de `reToolUseIdentifier` de l'origine ; refusé s'il continue une suite plus longue (`TestIsProviderObjectID`).
- *Comparaison lue comme une affectation* (`afterComparison`, `isComparisonOperand`, `detect/contextual.go`) : avec `ASSIGNMENT`, quand le séparateur `=` est collé à un second `=` (`==`, `===`), la valeur est lue après l'opérateur ; une comparaison à un mot réservé (`undefined`, `null`, `None`…) ou à un nom de code (`expectedToken`, `process.env.TOKEN`) est écartée, une valeur littérale (entre guillemets, ou jeton collé à l'opérateur) reste détectée (`TestComparisonIsNotAssignment`). Avant, une comparaison d'un nom sensible à `undefined` donnait une affectation de secret, et l'expurgation remplaçait cette suite partout dans une session.
- *Plafond de constats compté après la déduplication* (A1-11 du plan d'autoprotection) : `MaxFindings` (2 048) borne les constats gardés et non plus leurs doublons d'une vue à l'autre ; la mémoire reste bornée par `MaxRawFindings` (8 × 2 048) avant déduplication. Avant, un fichier d'environ 1 000 jetons distincts, vus chacun dans plusieurs vues, donnait une analyse incomplète, donc un blocage. Le cas de l'origine « fails closed instead of returning a partial verdict past the finding cap » (2 049 constats distincts) reste incomplet ; le sous-test de `TestScanFailures` est réécrit (2 048 constats gardés sur 4 096 avant déduplication : analyse complète ; 2 049 : incomplète). Pas d'identifiant d'échec nouveau : l'issue reste `scan_error`.

Vérification : `TestParity`, `TestParityWorkers`, `TestRedactParity` inchangés (903 cas, 0 écart) ; `TestWorstCases`, fuzz courts (`FuzzScan`, `FuzzRuleFamilies`, `FuzzRedact`, `FuzzPrefilterParity`).

**Écart d'analyse ajouté (v0.5.2), sans effet sur le corpus** : affectations indirectes (`detect/indirect.go`). Le nom sensible et sa valeur ne sont pas reliés par `=` ou `:` derrière une espace : paire entre guillemets premier élément d'une liste d'arguments, d'un tuple, d'un tableau ou d'un objet (`os.Setenv("…", "…")`, `props.setProperty("…", "…")`, `std::env::set_var("…", "…")`, `os.environ.setdefault("…", "…")`, `INSERT … VALUES ('…', '…')`), nom entre accents graves en Markdown (`` - `NOM` : `valeur` ``, tableau), ligne de diff (`+NOM=valeur`, `-NOM=valeur`, `+export NOM=valeur`), déclaration typée (`const NOM: &str = "…"`, `nom: str = "…"`, `val nom: String = "…"`, `var nom string = "…"`). Relevé sur le banc de lecture d'images du 2026-11-08 (1 100 captures réelles) : ces gabarits étaient ratés à chaque fois pour un mot de passe fort ou une valeur hexadécimale de 40 caractères (88 % et 89 % de détection de ces formes sur le texte vrai). Les cinq motifs passent par la lecture des affectations ordinaires (`scanAssignmentPattern` : noms sensibles, filtres de valeurs, types) ; hors la ligne de diff, la valeur doit être entre guillemets et avoir la forme d'un secret (`indirectValueShape` : 8 unités au moins, sans espace, pas une expression régulière ancrée, trois classes de caractères ou forte entropie), ce qui écarte libellés, valeurs par défaut, constantes d'énumération et documentation de types. Coût borné : les motifs ne sont cherchés que dans les fenêtres de lignes qui contiennent un morceau de nom sensible (`indirectWindows`, linéaire). Mesure sur 5 786 fichiers de dépôts réels : aucun constat nouveau ni perdu ; sur le banc, de 60 % à 100 % de ratés selon le gabarit avant, 0 sur 200 essais par gabarit après. Vérification : `TestIndirectAssignments` (en échec avant), `TestIndirectAssignmentsIgnoreOrdinaryCode`, `TestIndirectValueShape`, `TestIndirectWorstCases` ; `TestParity`, `TestRedactParity`, `TestDecisionParity` inchangés.

**Écart d'analyse ajouté (v0.5.2), sans effet sur le corpus** : jeton fini par un tiret (`detect/dashtail.go`). Les motifs à format fixe finissent par `\b` ; quand leur dernière classe admet `-` (`gitlab_pat`, `google_api_key`, `google_oauth_token`, `openai_key`, `anthropic_key`, `openrouter_key`, `sendgrid_key`, `slack_token`), un jeton dont le dernier caractère est un tiret n'a pas de frontière de mot à sa fin et l'expression revient en arrière : un jeton de longueur fixe (`glpat-` et 20 caractères, `AIza` et 35) ainsi fini n'était pas détecté, environ un sur 64 (relevé sur le banc : `gitlab_pat`). Le moteur cherche aussi, après chaque littéral de la porte de la règle et dans une fenêtre de 512 octets, le motif sans son `\b` final, et retient une correspondance qui finit par un tiret au bout de la suite de caractères du jeton (au plus trois tirets, la moitié au moins de caractères alphanumériques) si le motif d'origine n'a rien trouvé qui la touche ; bornes, valeur fictive et validateur s'appliquent. Le JWT (lecture par segments) n'est pas concerné : détecté, son étendue s'arrête avant un tiret final, comme dans l'origine. Vérification : `TestTokenEndingWithDash` (en échec avant), `TestDashTailRules`, `TestTokenLikeDashTail`, `TestDashTailKeepsOrdinaryMatches`, `TestDashTailWorstCases`, `TestJWTEndingWithDash` ; parité inchangée.

**Écart d'analyse ajouté (v0.5.1), sans effet sur le corpus** : mots longs de nom de dossier écartés de l'entropie. Dans un chemin relatif (`isNameWord`) comme dans la suite d'un chemin après un point ou une barre oblique (`isShortWords`), un mot de 13 à 24 caractères est admis s'il n'est fait que de lettres, en minuscules, avec une majuscule initiale ou tout en majuscules (`isLongNameWord`). Faux positifs relevés sur un Poste réel : un seul mot de plus de 12 lettres (`brainstorming`, `implementation`, `retrospective`) faisait d'un chemin ordinaire un candidat d'entropie, et 7 commandes ordinaires sur 30 d'un dépôt étaient bloquées. Un mot de casse mêlée ou qui porte un chiffre reste soumis à la borne de 12 ; un jeton dans un chemin reste détecté. Vérification : `TestEntropyIgnoresPaths` (cas « mot de 13 lettres » et suivants, en échec avant la correction), `TestEntropyKeepsTokens` (dont « jeton de lettres en casse mêlée dans un chemin »), `TestIsLongNameWord` ; `TestParity`, `TestRedactParity` inchangés.

**Écart d'analyse ajouté (v0.5.1), sans effet sur le corpus** : candidats base64 qui ont la forme d'un nom jamais décodés (`detect/base64words.go`, `isNameCandidate`, appelé par `forEachBase64Candidate`). `BASE64_CANDIDATE` prend tout mot de 20 caractères de l'alphabet base64 ; chaque identifiant de code (`AdminLogEntryViewActorKind`, `refuse_append_only_change`) et chaque empreinte hexadécimale était décodé et débité du budget de l'analyse (`maxDecodeAttempts` = 128, inchangé), et 48 fichiers ordinaires sur 3 849 d'un dépôt réel (dont son `CLAUDE.md`, ses types générés et un manifeste d'empreintes) donnaient une analyse incomplète, donc un blocage. Ne sont plus décodés : une suite de chiffres hexadécimaux d'une même casse avec un chiffre décimal (`isHexCandidate`), et, sans `+` ni `=`, une suite de mots séparés par `/`, `-` ou `_` qui sont chacun un mot de nom (`nameTokenLetters` : chiffres seuls, ou lettres suivies d'au plus quatre chiffres, en minuscules, majuscule initiale suivie de deux minuscules, tout en majuscules, ou casse de chameau à bosses d'au moins deux minuscules, première bosse d'une minuscule admise, un sigle de 2 à 5 majuscules et deux groupes de chiffres entre bosses au plus), dont un mot d'au moins 4 lettres. Le candidat reste analysé tel quel par toutes les règles (entropie comprise) : seul son décodage est omis. Mesure : sur 200 000 encodages base64 d'octets aléatoires, environ 100 ont cette forme à 20 caractères, aucun à 32 ni à 64 (`TestNameCandidateRarelyMatchesBase64`) ; le base64 d'un texte ne l'a jamais. Le nom d'un libellé de masquage (`<REDACTED_règle>`) reste décodé et débité comme dans l'origine (`isRedactLabelAt`), ce qui garde la parité du masquage (un texte masqué de nombreux libellés donne, comme l'origine, une nouvelle analyse incomplète). Sur le même dépôt : 0 analyse incomplète. Vérification : `TestIsNameCandidate`, `TestNamesKeepAnalysisComplete` (en échec avant la correction), `TestBase64SecretStillDecoded` ; `TestParity`, `TestRedactParity`, `TestCustomRedactParity` inchangés.

**Écart d'analyse ajouté (v0.4.4), sans effet sur le corpus** : chemin relatif écarté de l'entropie (`DEV/site/frontend/public`, précédé d'une espace ou en début de texte, que `rePathLike` ne reconnaît pas faute de barre oblique de tête). Écarté seulement si la suite contient une barre oblique, n'a que des caractères de chemin, et si chacun de ses mots (séparés par `/`, `-` ou `_`) a 12 caractères au plus et la casse d'un nom de dossier : minuscules, majuscule initiale ou tout en majuscules, chiffres admis (`isNameWord`). Un jeton dans un chemin relatif reste détecté. Vérification : cas « chemin relatif » de `TestEntropyIgnoresPaths`, « jeton dans un chemin relatif » de `TestEntropyKeepsTokens`.

**Écart d'analyse ajouté (v0.4.3), sans effet sur le corpus** : chemins et noms en tirets écartés de l'entropie (`detect/entropypath.go`), faux positifs relevés sur un Poste réel. La suite de `scanEntropy` ne contient pas le point : dans `~/.claude/projects/…` ou `…/claude-code-2.1.318-darwin-arm64/resources/…`, elle commence après un point et perd la barre oblique de tête que demande `rePathLike`. Elle est écartée quand elle est précédée d'un point ou d'une barre oblique, contient une barre oblique, n'a que des caractères de chemin, et que chacun de ses segments de 16 unités ou plus est fait de mots de 12 caractères au plus séparés par `-` ou `_`, sans mot de 5 caractères ou plus qui mêle majuscules, minuscules et chiffres (`isPathContinuation`). Un nom en tirets d'au moins quatre segments de 2 à 24 caractères, dont la moitié au moins en lettres seules (dossier de projet de Claude Code), est écarté aussi (`isWordSlug`). Un jeton dans le chemin d'une URL reste détecté (cas `slack_webhook/negative/http` du corpus inchangé). Moins de constats d'entropie, jamais moins de constats d'une règle ancrée. Vérification : `TestEntropyIgnoresPaths`, `TestEntropyKeepsTokens`, `TestIsWordSlug` (`detect/entropypath_test.go`) ; `TestParity`, `TestRedactParity` inchangés.

**Écart d'analyse ajouté (v0.4.2), sans effet sur le corpus** : URL à identifiants abîmée (`detect/urlrepair.go`). Quand l'URL lue par `scanCredentialURLs` est exactement `schéma://utilisateur:` (information utilisateur ouverte, sans `@`) et qu'elle s'arrête sur un caractère qui ne peut pas être dans une URL, le moteur saute au plus 4 caractères parasites (espace, tabulation, `<`, `>`, guillemet ; jamais une fin de ligne), lit un seul morceau de queue d'URL (le mot de passe), puis au besoin un second morceau qui commence par `@` (`<motdepasse>@hôte`), et juge l'URL recollée comme les autres (analyse de la norme URL, valeur fictive, Substitut ; un gabarit entre chevrons, `<password>`, se juge avec ses chevrons). L'origine s'arrête au premier parasite et laisse passer `postgres://admin:< motdepasse@hôte` en clair. Constat de la même règle (`database_url_credentials` ou `basic_auth_url`), étendue du schéma à la fin de l'URL recollée ; l'expurgation ne remplace que le mot de passe (`brokenURLPasswordRange`), parasites gardés. Jamais un secret manqué ; un constat de plus possible. Aucun cas du corpus de parité n'a cette forme : `TestParity`, `TestRedactParity` inchangés. Vérification : `TestBrokenCredentialURL`, `TestBrokenCredentialURLRefusals` (`detect/urlrepair_test.go`).

**Forme des Substituts (v0.5.0)** : un Substitut dit lui-même ce qu'il remplace, préfixe public facultatif puis `[secret masqué par xSOM n°<numéro> : <type>, pas la vraie valeur]` (ou, avec `expurgation.Options{SubstituteLanguage: detect.SubstituteEnglish}`, `[secret masked by xSOM #<numéro>: <type>, not the real value]`), le type venant de la table fermée `substituteLabels` (repli `secret`). Il ne porte plus la longueur de la valeur. L'ancienne forme (`^(?:<préfixe>)?X{3,}[0-9]{1,3}$`) n'est plus reconnue : un tel texte est analysé comme tout autre (un jeton GitHub fait de `X` redevient un constat). Le Substitut contient des espaces, une virgule et, en anglais, un dièse : là où la lecture d'une valeur s'arrête à ces caractères (valeur d'affectation sans guillemets, argument de `curl -u` sans guillemets, cookie), la valeur coupée est fictive seulement si un Substitut complet de la grammaire commence la valeur (au plus après un schéma d'authentification) et finit proprement : fin du texte, espace, fin de ligne, guillemet ou fin de valeur (`, ; # } ) ]`), jamais d'autres caractères collés (`isSubstituteFragment`, `isUnquotedSubstitute`). Un texte expurgé est plus long que l'entrée : au-delà de 1 Mio, l'expurgation échoue (`SanitizeIncomplete`, `TestExpurgateRedactResiduals` et `TestExpurgateCorpus` comptent ces refus).

**Écart d'analyse ajouté, sans effet sur le corpus** : un Substitut (grammaire exacte et fermée ci-dessus, préfixe de la table fermée) est une valeur fictive pour le moteur Go, là où l'origine le détecterait : `safeLiteral` (règles à format fixe, JWT, mot de passe d'une URL, entropie, cookie, `curl -u`, Docker), `safeContextualValue` (aussi après un schéma d'authentification `Bearer`, `Basic`, `Token`, et dans un bloc PEM dont le corps est un Substitut), `scanPrivateKeys` (bloc PEM dont le corps est un Substitut) et `scanFixedPattern` dans une vue de lignes jointes (Substitut en fin de ligne suivi d'une ligne de caractères de jeton). Aucun cas du corpus de parité, des vecteurs du masquage ni des vecteurs Unicode n'est dans cette grammaire : `TestParity`, `TestRedactParity` et `TestUnicodeParity` sont inchangés.

**Vérification** : `TestExpurgateMatrix`, `TestSubstituteGrammar`, `TestSubstituteText`, `TestExpurgateLanguage`, `TestFindSubstitutes`, `FuzzFindSubstitutes`, `TestSubstituteNeverDetected` (9 056 textes : sans préfixe, chaque type des deux langues aux numéros 1, 42 et 999 ; chaque préfixe avec le type de sa règle et le repli, numéros 1 et 999, deux langues ; 18 gabarits dont l'en-tête Authorization d'une commande curl, un cookie et une phrase ; corps PEM dans 8 gabarits, deux langues), `TestFakeSubstituteDetected`, `FuzzSubstituteGrammar`, `FuzzExpurgate`, `TestExpurgateCorpus` (626 cas du corpus de parité qui ont un constat, dont 46 de données personnelles depuis la v0.7.0 : 617 expurgés, 7 hors UTF-8 refusés, 2 refusés parce que le texte expurgé dépasse 1 Mio ; les expurgés relus sans constat, chaque Substitut égal à celui de la grammaire pour sa règle et son numéro, aucune fenêtre de 8 octets d'une partie remplacée hors préfixe public dans le texte hors Substituts), `TestExpurgateRedactResiduals` (les 619 cas de `vectors/redact.json` : les 5 résidus du masquage sont expurgés sans résidu ; 4 textes proches de 1 Mio refusés, texte expurgé trop grand), `TestExpurgateLineBreak`, `TestExpurgateSubstitutionFingerprint`, `TestExpurgateVectors` (essais de l'expurgation dans le module `expurgation` depuis la v0.6.0, sur l'API publique de `detect`).

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

## Règles du client

Portage en Go, sans copie de code d'origine dans le dépôt, des règles propres à un client de Secret Guard (même dépôt et même commit que ci-dessus ; fichiers identiques au commit `cefe30a10854432911ec08eba32a15d2400732fc`, où ils ont été lus le 13 octobre 2026) :

| Fichier d'origine | SHA-256 | Portage |
|---|---|---|
| `secret-guard/packages/core/src/custom/schema.ts` | `b6c0cc2521ca2d922f6836116ab4ff474a3b70119e000823cd6a573aa67b5836` | `custom/decode.go` : `isRulesPackPayload` → `isPayload`, lecture des octets du document |
| `secret-guard/packages/core/src/custom/pack.ts` | `2ff85e14461c3ba6b342cebe548c1f12f730ee6a4e63da50f71856d262977285` | `custom/pack.go` : `compileRulesPack` → `Compile`, `compileDetector`, essais (`selfTests`), `SELF_TEST_WORK_BUDGET`, `SELF_TESTS_TOTAL_BUDGET` |
| `secret-guard/packages/core/src/custom/pattern.ts` | `d3f30e83d21546c24462d22bfbbfeb82dc68c81e27cf5e489ca579bf8ce1081f` | `custom/pattern.go` : `Parser`, `validatePattern` → `ValidatePattern`, `findAnchor`, `firstSet`, `minimumLength`, `maximumLength` ; l'automate `run` est remplacé par la traduction RE2 (`translator`) et porté dans les tests seulement, comme oracle (`custom/fuzz_test.go`) |
| `secret-guard/packages/core/src/custom/terms.ts` | `33913b355b3bc94dbfcbe3e8fc3e6c769432817a5ea475b27a076988a06f546f` | `custom/terms.go` : `normalizeWord`, `normalizeTerm` → `NormalizeTerm`, `termDigest` → `TermDigest`, `textWords`, `findTermHits`, `decodeBase64` (sel) |
| `secret-guard/packages/core/src/custom/detect.ts` | `554992f995777cfbb99a19db045f15041202773cbd9e26160b5a7c34293c97c3` | `custom/detect.go` (`TextView`, `contextHolds`, `anyKeyword`, `anchorIntervals`, `shannonEntropy`, `resolveTermCandidates`, `detectAll`), `custom/search.go` (`patternMatches` et `wholeTextMatches` : recherche RE2) |
| `secret-guard/packages/core/src/custom/work.ts` | `a16e01b16f3a89074b42240438ea35db13960253d423684624ce19548b3eed18` | `custom/work.go` : `WorkMeter` → `Meter`, `HASH_BLOCK_COST` |
| `secret-guard/packages/core/src/scanner.ts` (en partie) | `80ba8d74d90bd3fd045542fadfd8792171d5b7beaa2ac1067edbacbaee77cafc` | `collectCustomFindings`, `visibleText` → `custom.(*Pack).Analyze` ; `customFinding`, `CUSTOM_RULES_WORK_BUDGET`, échecs `custom_budget` et `custom_too_many` → `detect/custom.go`, `detect/result.go` ; `displayLabel`, `placeholderName` (règles du client), `redactAndRescan` (libellés neutres) → `detect/custom.go`, `detect/redact.go` |
| `secret-guard/contracts/RULES-PACK.md` | `37c26d75ad98aca155a4adbd32b3ef6c80b36215486a4a46545b25cbf0e782b0` | `docs/custom-pack.md` : contrat réécrit (numéros de sections gardés), sans référence au dépôt d'origine ni aux produits de l'émetteur, section « Exécution par le moteur Go » ajoutée |
| `secret-guard/contracts/rules-pack.schema.json` | `43fb935003d799098c1751894ad9cbd7b150e12756244f4bcb15c01d8c9aa545` | `schema/CustomPack.json` : copie, titre et description seuls changés (test `custom-vectors.test.ts` : SHA-256 de la copie, ces deux champs remis, égal à l'origine ; `TestCustomSchemaCopy` : formes, listes et bornes égales au décodage Go) |
| `secret-guard/contracts/fixtures/rules-pack-vectors.json` | `247d7f1f846649c81267a20a550add4c7cd3663851c4dc77419d26d400f9909b` | cas `fixture/…` de `vectors/custom/` (grammaire, détections, termes, Packs ; la section de signature, hors du moteur, n'est pas reprise) |
| `secret-guard/tests/core/rules-pack-contract.test.ts` | `42a9bed907ff0648f75cae0e27995271236bf338afcbb35c6488c32b3f0c527c` | entrées relevées → cas `upstream/…` |
| `secret-guard/tests/core/rules-pattern.test.ts` | `8150edf919da35dd1074dc85a03b80acc165e61a927a1bf476bd7ee097487780` | entrées relevées → cas `upstream/…` |
| `secret-guard/tests/core/rules-scan.test.ts` | `190fc4fbbd5bcfca88bd983f2668933e48d2ee655e44f7672a19559b5a4bb071` | entrées relevées → cas `upstream/…` |
| `secret-guard/scripts/largest-rules-pack.mjs` | `2c46da7f05386014cc1b7d0abfc3c45b0078deb8c67c59738d45d94ecdb18ace` | exécuté par `rules-scan.test.ts` : le plus grand Pack du contrat (200 détecteurs, 20 000 condensats) figure dans `vectors/custom/packs.json` |

**Licence** : `secret-guard/packages/core/` et `tests/core/rules-pattern.test.ts` sont dans le périmètre ouvert (Apache-2.0) de `LICENSING.md` du dépôt d'origine. Le contrat (`contracts/RULES-PACK.md`, `rules-pack.schema.json`, `fixtures/rules-pack-vectors.json`), `tests/core/rules-pack-contract.test.ts`, `tests/core/rules-scan.test.ts` et `scripts/largest-rules-pack.mjs` sont hors de ce périmètre (licence commerciale par défaut) : xSOM, titulaire des droits, publie ici sous Apache-2.0 (décision de Julian Talou du 13 octobre 2026) le contrat réécrit, la copie du schéma et les vecteurs tirés de ces fichiers ; aucun de ces fichiers n'est copié tel quel, sauf le schéma.

**Modifications (Apache-2.0, §4 b)** : traduction de TypeScript en Go, et :

- **Motifs en RE2.** L'origine exécute un automate à retour arrière compté (et la RegExp de V8 quand la borne d'un essai est petite) ; le portage traduit l'arbre validé en RE2 (`regexp`, temps linéaire, aucun retour arrière), avec la sémantique d'ECMAScript : chaque caractère devient une classe explicite d'octets ASCII (`\xHH`), `caseInsensitive` replie seulement les lettres ASCII (jamais `(?i)`, qui replierait K, ſ et le signe kelvin), et un groupe optionnel (`?` ou `{0,1}`) dont le contenu peut être vide est réécrit en l'alternative ordonnée de ses seuls chemins non vides : ECMAScript refuse l'itération vide d'un quantificateur de minimum 0 (`(?:a?|b)?` reconnaît « b »), RE2 non. Les autres constructions du §3 ont la même sémantique « la plus à gauche, premier choix d'abord ». Mêmes débuts essayés que l'origine (intervalles de l'ancre, ou tout le texte si un mot-clé du contexte y figure), réduits aux octets qui peuvent commencer une correspondance, cherchés par fenêtres fusionnées de la longueur maximale du motif ; deux détecteurs de même motif traduit partagent leurs correspondances (l'origine ne le fait que pour les motifs sans ancre).
- **Budget de travail.** Mêmes budgets (120 000 000 par analyse, 2 000 000 par essai, 150 000 000 pour les essais d'un Pack) et même coût, au pas près, pour les mots, n-grammes (compressions SHA-256 × 80, mémoire des mots et paires), minuscules, contextes, entropie, recherche de l'ancre et texte visible. La recherche d'un motif, elle, compte une unité par position examinée, puis, par fenêtre, sa longueur en octets fois le nombre d'états du motif traduit (borne du travail de RE2), avant de chercher. Les résultats sont ceux de l'origine ; le seuil où le budget s'épuise diffère pour les motifs (écart `backtracking_budget` ci-dessous ; dans l'autre sens, un motif à très grand programme sur un long texte peut épuiser le budget du portage et non celui de l'origine : l'analyse est alors incomplète, jamais un passage).
- **Texte en octets.** Étendues en octets ; fenêtre de contexte en points de code (un octet hors UTF-8 en vaut un, comme U+FFFD) ; longueurs de coût en unités UTF-16 comme l'origine. Texte visible : un octet hors UTF-8 y est écrit U+FFFD, retirer un caractère ignorable ne peut donc pas former une séquence UTF-8 avec ses voisins.
- **Minuscules** : correspondances simples d'Unicode, U+0130 et sigma final de `toLowerCase` (V8, ICU, locale racine : les caractères ignorables de la casse sont sautés même s'ils ont une casse, comme `isFollowedByCasedLetter` d'ICU) ; vérifié sur chaque point de code par le pont `vectors/custom/unicode.json`.
- **Lecture du Pack** : octets du document, JSON strict (`encoding/json/v2`), 16 Mio au plus ; l'origine juge une valeur déjà lue par `JSON.parse`. Nombres jugés comme des nombres JavaScript.
- **Constats** : forme `detect.Finding` (règle `xsom_<détecteur>`, type `custom_rule`, vue `plain`, score 90 ou 40), sans le champ `custom` de l'origine : l'appelant lit le détecteur dans `Pack.Detectors`.
- **Ajouts** : `custom.DecodeSalt`, `custom.DigestTerm` et `secret-guard terms digest` (condensats calculés chez le client), `scan --custom-pack`, `redact --custom-pack`.

**Vecteurs de parité** (`vectors/custom/`, `npm run vectors:custom -- --upstream <checkout> [--check]` dans `generator/`, `generator/custom/`) : le générateur vérifie le SHA-256 de chaque fichier lu (moteur `secret-guard/packages/core/src` et fichiers du tableau), transpile le moteur et les trois tests dans un répertoire temporaire (aucune dépendance d'origine installée), exécute les tests avec le `expect` de Vitest et relève chaque entrée passée au moteur (motifs validés, textes passés à l'automate, Packs compilés, analyses, détections, termes ; identifiant `upstream/<n> #<rang>`, `n` renvoyant à la table `tests` du manifeste). S'y ajoutent les vecteurs du contrat (`fixture/…`) et des cas synthétiques (`generator/custom/synthetic.ts`) : chaque code de validité et de motif, chaque construction admise et refusée, ordre des contrôles, 3 000 couples motif-texte aléatoires (graine fixe), termes et normalisation Unicode, n-grammes à la frontière, contextes et entropie au seuil, texte visible, limite de détections, budget des termes au mot près (`synthetic/scan/budget/terms-within` et `…-exceeded`), libellés des détecteurs pour le masquage, et le pont Unicode. Résultats attendus : sortie du moteur d'origine, positions UTF-16 converties en octets (texte décodé comme Go parcourt les octets). Le 13 octobre 2026 : detection.json 1 659 jeux de détecteurs (9 860 entrées), packs.json 264, pattern-matching.json 1 813 motifs (8 418 entrées), pattern-validation.json 7 681, redact.json 57, scan.json 62, terms.json 89, unicode.json 272 blocs ; `--check` sur un checkout au commit ci-dessus rend « Vecteurs identiques ».

**Écarts déclarés** (champ `divergence` des vecteurs : raison et résultat Go, vérifiés par les tests Go ; test `custom-vectors.test.ts` : chaque cas est cité ici) :

- `json_duplicate_member` (`synthetic/pack/json/duplicate-member`) : membre en double ; `JSON.parse` garde le dernier, le portage refuse le document (`schema`). Une forme canonique signée n'en a jamais.
- `json_lone_surrogate` (`synthetic/pack/json/lone-surrogate`) : échappement `\ud800` isolé ; `JSON.parse` l'accepte, le portage refuse (`schema`).
- `json_invalid_utf8` (`synthetic/pack/json/invalid-utf8`) : octet hors UTF-8 dans le document ; l'origine reçoit un texte déjà décodé (U+FFFD), le portage lit les octets et refuse (`schema`).
- `backtracking_budget` (`synthetic/pack/self_test_incomplete-pattern`, `upstream/108 #2` de `scan.json` et de `redact.json`) : motif à 20 bornes de suite (`ACME[a-z]{0,8}…Z`) sur 160 « a » ; l'automate de l'origine épuise son budget (`self_test_incomplete`, `custom_budget`), RE2 finit en temps linéaire et constate l'absence de correspondance (`positive_not_detected`, analyse complète sans constat, texte rendu tel quel par le masquage). Sur 1 Mio du même genre, les deux épuisent leur budget (`upstream/109 #3`, sans écart).

Sans verdict de l'origine (champ `upstream: json_parse_error`, `JSON.parse` lève avant le moteur ; le portage rend `schema`) : `synthetic/pack/json/trailing-content`, `synthetic/pack/json/byte-order-mark`, `synthetic/pack/json/truncated`. Entrée sans résultat de référence : le texte que `rules-pattern.test.ts > … > stops a pathological but valid pattern at the work budget` passe à l'automate (aucun résultat de l'origine en temps borné ; même motif en analyse : `upstream/108 #2`).

**Vérification** : `TestCustomPackParity`, `TestCustomPatternParity`, `TestCustomDetectionParity`, `TestCustomTermsParity`, `TestCustomUnicodeParity` (paquet `custom`), `TestCustomScanParity` et `TestCustomRedactParity` (paquet `detect`) : 100 % des cas, écarts déclarés compris ; `TestReferenceOracle` (l'oracle des tests, portage de l'automate `run`, rend les 8 418 entrées de correspondance), `FuzzCustomPattern` (traduction RE2 contre cet oracle), `FuzzCustomPackDecode`, `TestWorstCases` (analyses de 1 Mio bornées en temps, dont le plus grand Pack) ; `TestCustomPublicAPI` (liste fermée de l'API publique : aucune valeur détectée, aucun terme).

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

## Règles de données à contexte (v0.9.0)

La technique du mot-clé de contexte obligatoire (une règle ne se déclenche que si un mot qui annonce la donnée est
proche de la valeur) vient du projet Akto (`https://github.com/akto-api-security/akto`, licence MIT), lue au commit
`6b7de940c28037d726776bc5f201fd9e572133a3` dans
`apps/dashboard/src/main/java/com/akto/service/insights/PiiPatterns.java`. Seule l'idée est reprise : les onze règles de `generator/rule-pack/context-data.ts` (adresse électronique, téléphone, passeport,
cryptogramme, code à usage unique, clé d'accès partagé Azure, adresse IP interne, ARN, bucket S3, RDS, DynamoDB) sont
écrites ici en RE2, sans copie de motif, de mot-clé ni de code d'Akto.

## Sortie SARIF (v0.10.0)

`secret-guard scan --format sarif` (`cmd/secret-guard/sarif.go`) écrit le résultat d'une analyse en SARIF 2.1.0 : un résultat par constat, avec la règle, le fichier tel qu'il est nommé sur la ligne de commande, les lignes et colonnes de début et de fin (colonnes en points de code, `columnKind`), l'étendue en octets et le niveau (`error` pour CRITICAL et HIGH, `warning` pour MEDIUM, `note` pour LOW). Extension de ce module, sans origine dans Secret Guard, hors du moteur (la commande seule : `detect` et le module WebAssembly ne changent pas).

- **Idée lue dans ggshield** (GitGuardian, licence MIT, clone de lecture au commit `f3377d9`) : l'outil a une sortie SARIF pour ses constats. Seule l'existence de cette sortie est reprise : son fichier n'a pas été ouvert pour écrire celle-ci, aucune ligne, aucune structure ni aucun texte n'en vient, donc aucun avis dans `NOTICE`. La forme est écrite d'après la spécification OASIS « Static Analysis Results Interchange Format (SARIF) Version 2.1.0 ».
- **Jamais la valeur ni un extrait** : aucune région n'a de `snippet` ni de `contextRegion`, aucun message ne cite le texte analysé ; la liste des propriétés écrites est fermée (`sarifKeys`, `TestScanSARIF`, `TestSARIFNeverCarriesContent`). L'Empreinte locale, quand une clé est donnée, va dans `partialFingerprints` (HMAC sous la clé de l'appelant, comme `localFingerprint` de la sortie JSON).
- **Analyse incomplète** : aucun résultat, `executionSuccessful` faux et une notification d'erreur qui porte l'issue (`scan_limit`, `scan_error`…) ; le code de sortie reste 2. Elle ne se lit jamais comme « rien trouvé ».
- **Limite** : la forme est vérifiée par des essais (document strict, propriétés fermées, contraintes de la norme sur ce qui est écrit), pas par le schéma JSON officiel, que le dépôt n'embarque pas.

## Corpus de rappel du paquet injection (v0.10.0)

`vectors/injection-recall.json` est une donnée d'essai : il n'entre dans aucun programme livré. Il sert à mesurer ce
que `injection.Find` signale (`TestRecallCorpus`, relevé `injection/testdata/recall.json`, chiffres dans
`docs/bench.md`). Ses textes sont copiés sans retouche par `go run ./tools/injectioncorpus construire`, qui épingle
pour chaque source le commit, l'empreinte du fichier de licence et celle des fichiers lus (`tools/injectioncorpus/sources.go`),
et refuse d'écrire au moindre écart. Ce sont des consignes piégées écrites par d'autres : des données, jamais des
instructions ; aucun outil du dépôt n'en affiche le texte.

| Source | Dépôt et commit | Chemin | Licence et droits | Cas |
|---|---|---|---|---:|
| LLM Guard | `protectai/llm-guard`, `168c1034ffdb33837e7ae6fd6a16b80567c1be03` (projet archivé) | `tests/input_scanners/test_prompt_injection.py` | MIT, Copyright (c) Protect AI. All rights reserved. | 60 |
| Promptfoo | `promptfoo/promptfoo`, `5fac53eefdd26141a45c52ab77f533a7d30884e3` | `src/redteam/strategies/promptInjections/data.ts` | MIT, Copyright (c) Promptfoo 2025 ; une partie de ces gabarits est reprise de LLM Guard (MIT, Copyright (c) Protect AI), d'après le `README.md` du même dossier | 106 |
| Akto | `akto-api-security/akto`, `f69427472ebf57cac9dd1b70bbcfb542ba2189d8` | `apps/dashboard/src/main/resources/inbuilt_llm_test_yaml_files/` (55 fichiers) | MIT, Copyright (c) 2023 Akto.io. | 59 |
| Skill Scanner | `cisco-ai-defense/skill-scanner`, `c558c421157c546ec417cf23778ce81a3a8f35fd` | `evals/skills/` | Apache-2.0, Copyright 2026 Cisco Systems, Inc. and its affiliates ; chaque `_expected.json` déclare sa fixture « first-party », Apache-2.0 (vérifié à la construction) ; le dépôt n'a pas de fichier `NOTICE` | 55 |

**Ce qui est copié, et comment.**

- *LLM Guard* : les 60 textes du jeu d'essai du détecteur d'injection, avec l'étiquette de leur auteur (49 injections,
  11 textes sains). Les littéraux Python sont lus sans exécuter le fichier.
- *Promptfoo* : les 106 littéraux du tableau, décodés sans exécuter le fichier. Ce sont des gabarits de
  contournement (jailbreak) qui visent un chatbot, pas un agent de code.
- *Akto* : la charge de chaque gabarit de test LLM embarqué (ligne en pourcentages), décodée. 45 des 55 gabarits
  citent garak (`leondz/garak`, Apache-2.0) en référence. Beaucoup de ces charges demandent du code malveillant et ne
  sont pas des injections. Deux charges sur 61 ne sont pas copiées : elles portent une signature d'essai d'antivirus
  ou d'antispam, qui ferait signaler le corpus, et le module, par les outils de sécurité des postes. Les gabarits du
  dépôt séparé `tests-library` d'Akto ne sont pas repris.
- *Skill Scanner* : chaque fichier des skills d'évaluation (hors `_expected.json`), étiqueté d'après le résultat
  attendu : « consigne » si le résultat porte `prompt_injection` (1 cas), « sain » si le paquet est tenu pour bénin
  (11), « autre » sinon (43 : risques de code ou de dépendance, hors du périmètre du paquet `injection`). La
  catégorie `hardcoded-secrets` n'est pas copiée (une valeur à forme de secret n'a pas sa place dans ce corpus).

**Ce qui n'est pas repris** : les jeux de données que Skill Scanner référence sans les embarquer (dont
MaliciousSkillBench), le paquet de règles ATR de DefenseClaw, les jeux que Giskard charge à l'exécution (dont un sous
licence non commerciale), le classifieur et les modèles de LLM Guard, et tout code de ces projets : aucun motif, aucune
règle, aucune ligne de code du moteur n'en vient.

**Format.** Le fichier est écrit en ASCII seul (tout autre caractère en `\uXXXX`) : il ne porte en clair ni
caractère invisible ni contrôle bidirectionnel, quoi que contiennent les textes. `TestCommittedCorpusIsToolOutput`
vérifie qu'il est, octet pour octet, la sortie de la commande ; `gitleaks` l'analyse comme le reste du dépôt, sans
exception.

**Avis de la licence MIT** (LLM Guard, Promptfoo, Akto ; lignes de droits d'auteur ci-dessus) :

```text
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

Les skills d'évaluation de Skill Scanner sont sous la licence Apache-2.0, celle du fichier `LICENSE` de ce dépôt.

Vérification : `go test ./tools/injectioncorpus ./injection`, et, avec les clones aux commits épinglés,
`go run ./tools/injectioncorpus construire -sources <clones> -verifier`.

## Règles du paquet injection (v0.10.0)

Les sept règles ajoutées au paquet `injection` (`injection_forced_prefix`, `injection_fake_history`,
`injection_refusal_suppression`, `injection_payload_splitting`, `injection_system_prompt_leak`,
`injection_filter_disable`, `injection_role_labels`) sont écrites dans ce dépôt, en RE2 borné, en français et en
anglais. Ce qu'elles doivent à d'autres projets :

- **Familles.** Les noms des techniques (préfixe imposé, suppression du refus, faux historique, découpage de la charge)
  viennent de la nomenclature de Giskard (`Giskard-AI/giskard-oss`, Apache-2.0, commit
  `32fb9cf8e9344e9e2847bc22bdcf985a42f1e06c`, `libs/giskard-scan/`). Aucun gabarit, aucune donnée ni aucun code de
  Giskard n'est repris.
- **Formes reprises et modifiées de DefenseClaw** (`cisco-ai-defense/defenseclaw`, Apache-2.0, Copyright 2026 Cisco
  Systems, Inc. and its affiliates, commit `b68373a1c842486b22f7349a2b6fc74b56e2c941`,
  `internal/scanner/clawshield_injection.go`) : la ligne « system: » suivie d'un ordre d'annulation, le bloc de code
  « system », « --- » puis « system: » et le jeton `</s>` de la règle `injection_role_labels`. Modifications : motifs
  réécrits (début de ligne vérifié hors motif, espaces bornés, mots français, `</s>` écarté quand il ferme un texte
  barré `<s>…</s>` sur la même ligne) ; la ligne « system: you are… » n'est pas reprise (146 fichiers signalés à la
  mesure). Le reste de ce fichier (densité de verbes à l'impératif, décodage base64, paquet de règles ATR) n'est pas
  repris.
- **Formes reprises et modifiées de Skill Scanner** (`cisco-ai-defense/skill-scanner`, Apache-2.0, Copyright 2026
  Cisco Systems, Inc. and its affiliates, commit `c558c421157c546ec417cf23778ce81a3a8f35fd`,
  `skill_scanner/data/packs/core/signatures/prompt_injection.yaml`) : la demande de révéler le message système
  (`injection_system_prompt_leak`) et l'ordre de désactiver les filtres ou d'entrer dans un mode sans restriction
  (`injection_filter_disable`). Modifications : motifs réécrits avec des intervalles bornés, listes de verbes et de
  noms propres à ce dépôt, formes françaises, négation lue avant la correspondance (« never reveal… » n'est pas
  signalé), modes « debug », « developer » et « admin » et mot « security » non repris (courants dans une
  documentation). L'idée d'écarter les citations entre guillemets vient de la même source, qui la mesure sur ses
  propres données ; son motif, à assertions arrière, n'est pas repris : le contrôle est écrit en Go
  (`injection/context.go`).

Les avis de ces deux projets ne portent aucune mention qui concerne les fichiers cités (le fichier `NOTICE` de
DefenseClaw vise ses dossiers `internal/sensor/`, non repris ; Skill Scanner n'a pas de fichier `NOTICE`). Mesures et
critère de garde des motifs : `docs/bench.md`.

## Règles reprises de Betterleaks, vraisemblance et banc de comparaison (v0.10.0)

Trois ajouts de la v0.10.0, aucun dans le moteur d'origine : un contrôle de vraisemblance des valeurs que les règles de fournisseurs signalent, 66 règles reprises de Betterleaks, et un banc de comparaison rejoué à chaque version. Le corpus d'origine (`upstream-*.json`) et les règles du catalogue d'origine ne changent pas.

**Origine.** Betterleaks : dépôt `betterleaks/betterleaks`, commit `b4b1c4455987636400ce693bd9d8a8e2cf375ed9` du 13 novembre 2026, licence MIT, « Copyright (c) 2026 Zachary Rice » (texte reproduit à la fin de cette section, avis dans `NOTICE`). Deux choses en sont reprises : des motifs de règles (`rules/*.go`, champ `Regex`, et le seuil de leur filtre d'entropie), et les cas d'essai que chaque règle porte dans son fichier source (`vectors/comparison/betterleaks.json`). Le code de Betterleaks n'est ni copié, ni compilé, ni exécuté. Les seuils d'entropie des règles reprises de Titus viennent du champ `min_entropy` de ces règles (même commit de Titus que la section « Règles de fournisseurs », Apache-2.0).

### Vraisemblance des règles de fournisseurs

Une règle de fournisseur reconnaît une forme. Une valeur faite d'une lettre répétée, de zéros ou de « X » a la forme et n'est pas un jeton : sur les 931 cas négatifs de Betterleaks, les règles de fournisseurs de la v0.9.0 rendaient 62 constats sur de telles valeurs.

- *Contrôle d'office* (`detect/validators.go`, `plausibleToken`, appliqué par `scanFixedPattern` et par la lecture des jetons finis par un tiret). Pour une règle « motif seul » de type `provider_token` hors du catalogue d'origine, une valeur de moins de 6 octets distincts, ou d'entropie de Shannon inférieure à 3,0 bits par octet, n'est pas un constat. Le contrôle vaut pour les règles de fournisseurs du Pack initial et pour toute règle de ce type ajoutée par un Pack.
- *Règles du catalogue d'origine* (`originCatalogRules` : `github_token`, `github_fine_grained_pat`, `gitlab_pat`, `openrouter_key`, `anthropic_key`, `openai_key`, `stripe_secret_key`, `slack_token`, `slack_webhook`, `sendgrid_key`, `npm_token`, `huggingface_token`, `databricks_pat`, `digitalocean_token`, `shopify_token`) : le contrôle ne s'y applique pas. Les essais du moteur d'origine attendent un constat sur des valeurs sans diversité (un préfixe suivi d'une lettre répétée) : les y soumettre casserait la parité. Il en reste 19 constats sur les négatifs de Betterleaks.
- *Validateurs nommés.* La liste fermée des validateurs reçoit `token_entropy_25` à `token_entropy_45` : au moins 6 octets distincts et une entropie d'au moins NN dixièmes de bit par octet. Le schéma `RulePack` ne change pas (le champ `validator` est une chaîne, la liste est tenue en code). Le contrôle ne décode rien et ne débite aucun budget : à la différence des validateurs à clé de contrôle, il s'exécute aussi dans un texte décodé de base64. Un moteur antérieur à la v0.10.0 refuse en entier un Pack qui porte l'un de ces noms (`unknown_validator`).
- *Seuils du Pack initial.* Les 181 règles à proximité de la v0.9.0 portent un validateur. 79 gardent le seuil `min_entropy` de leur règle de Titus (3,2 à 4,0). 67 portent 3,0 : leur règle de Titus n'a pas de seuil, ou un seuil de 3,0 ou moins. 35 portent un seuil plus bas, pour l'une de deux raisons. *Forme du motif* (22 règles) : le plus haut seuil que 99,95 % de 60 000 valeurs tirées au hasard de la forme du motif passent (alphabet hexadécimal tiré dans une seule casse). Sans ce plafond, un seuil de 3,5 écarterait 19 % des clés de 32 chiffres hexadécimaux, et celui de 4,0 toute clé de 40 chiffres hexadécimaux. Seuils abaissés : `alibaba_access_key_secret` 4,2 → 3,9 ; `asana_oauth_personal_access_token` 3,5 → 2,6 ; `azure_openai_api_key` 3,5 → 3,0 ; `circleci_api_project_token` 3,3 → 3,2 ; `cisco_meraki_api_key` 3,3 → 3,2 ; `clay_api_key` 3 → 2,6 ; `codacy_api_key` 3,5 → 3,4 ; `customer_io_tracking_api_key` 3 → 2,6 ; `deepgram_api_key` 3,5 → 3,2 ; `eventbrite_api_key` 3,5 → 3,4 ; `finicity_api_token` 3,5 → 3,0 ; `finicity_client_secret` 3,5 → 3,4 ; `guardian_api_key` 3,5 → 3,2 ; `honeycomb_api_key` 3,5 → 3,0 ; `larksuite_tenant_access_token` 3,2 → 3,1 ; `mattermost_access_token` 4 → 3,7 ; `mongodb_api_private_key` 3,3 → 3,2 ; `opsgenie_api_key` 3,5 → 3,2 ; `owlbot_api_key` 3,5 → 3,2 ; `packagecloud_api_key` 3,5 → 3,3 ; `sendbird_api_token` 4 → 3,2 ; `weights_and_biases_api_key` 3,5 → 3,2. *Clé publiée hexadécimale* (13 règles, dont deux déjà abaissées de 3,5 à 3,4 pour la forme de leur motif) : le motif admet tout l'alphabet alphanumérique, mais un exemple publié avec la règle de Titus est une clé hexadécimale (après un préfixe littéral pour la clé d'autorité d'origine Cloudflare) ; la forme est alors tirée en hexadécimal, et le seuil plafonné de la même façon. Le seuil d'avant écartait de 0,5 % à 55 % des clés hexadécimales de ces formes (19 % de celles de 32 chiffres au seuil de 3,5), que la v0.9.0 trouvait. Seuils : `baremetrics_api_key` 3,3 → 2,8 ; `cloudflare_ca_key` 4 → 3,9 ; `cloudsight_api_key` 3,5 → 2,6 ; `codecov_access_token` 3,5 → 3,1 ; `datadog_api_key` 3,3 → 3,0 ; `finnhub_api_token` 3 → 2,6 ; `iterable_api_key` 3,5 → 3,0 ; `openweather_map_api_key` 3,5 → 3,0 ; `pagerduty_api_key` 3,5 → 2,8 ; `pdflayer_api_key` 3,5 → 3,0 ; `scraperapi_key` 3,5 → 3,0 ; `snyk_api_key` 3,5 → 3,2 ; `wpengine_api_key` sans seuil → 2,8. Les exemples ne sont pas repris ; la liste des règles est tenue dans `HEX_KEY_RULES` (`generator/test/provider-rules.test.ts`), qui rejoue le tirage. Huit règles descendent ainsi sous le seuil d'office (2,6 à 2,8 : valeurs de 18 à 25 caractères, dont 3 % de celles de 20 chiffres hexadécimaux ont une entropie inférieure à 3,0) ; elles gardent les six octets distincts.
- *Mesure sur les exemples de Titus.* Sur 385 exemples publiés que nos motifs lisent, 13 (10 règles) ont une valeur dont l'entropie est sous le seuil de leur propre règle : c'est ce qui a fait plafonner les seuils plutôt que les reprendre tels quels.
- *Corpus.* `vectors/detection/rules-providers.json` : le résultat attendu vient de la lecture de référence en JavaScript, qui applique une seconde écriture du contrôle (`generator/rule-pack/provider-rules.ts`, `plausibleToken`, même ordre de somme et même logarithme que le moteur Go). Seul le cas positif de `github_app_installation_token` change : sa forme d'essai minimale (un caractère par segment) n'avait pas la diversité d'un jeton. `vectors/noise-providers.json` (`generator/corpus/provider-noise.ts`, `TestNoiseProviders`) : pour chaque règle, la forme de sa valeur où chaque suite de caractères est un seul caractère répété ; le motif la reconnaît, l'analyse ne rend aucun constat. 352 cas pour 360 règles : cinq règles n'en ont pas parce que le texte de leur cas est aussi une affectation à un nom sensible, trois (`slack_workflow_webhook`, `slack_trigger_url`, `devcycle_server_sdk_key`) parce que les littéraux de la valeur portent à eux seuls la diversité exigée.
- *Limites.* Le contrôle porte sur la valeur entière, préfixe compris : un préfixe long et varié suffit à passer le seuil d'office. Il n'écarte pas une valeur d'exemple variée (`abcdef0123456789…`). Les autres règles à proximité dont le motif admet tout l'alphabet alphanumérique gardent le seuil de Titus, qui sépare une clé à casse mêlée d'une empreinte hexadécimale voisine (somme de contrôle d'un fichier de verrouillage, identifiant de commit) : si la clé réelle d'un de ces fournisseurs est hexadécimale sans qu'un exemple publié le montre, un seuil de 3,5 en écarte jusqu'à 19 % (32 chiffres). À revoir fournisseur par fournisseur, sur sa documentation.

### Règles reprises de Betterleaks

Betterleaks a 91 règles « jeton à préfixe » sans règle dédiée complète dans le Pack de la v0.9.0 (mesure du banc, ci-dessous). 83 sont reprises : par 66 règles nouvelles, ajoutées à la fin de `generator/rule-pack/provider-rules.json` (champ `upstream` : `betterleaks.<identifiant>`), et par 8 règles existantes dont le motif est élargi. 8 ne le sont pas.

**Modifications par rapport aux motifs de Betterleaks.**

- *Fin du jeton.* Le délimiteur de fin de Betterleaks (guillemet, espace, `;`, `)`, fin de texte) est remplacé par une limite de mot, ou par « pas un caractère du jeton, ou fin de texte » quand la dernière classe admet autre chose qu'un caractère de mot : un jeton suivi d'une virgule ou d'un point, dans une phrase, est lu.
- *Casse.* Les drapeaux `(?i)` sont retirés : classes écrites dans les deux casses, préfixe dans la casse du jeton réel.
- *Un seul groupe capturant*, la valeur ; porte littérale d'au moins trois octets prouvée pour chaque règle (`TestProviderRules`). `buildkite_service_token` : les sept préfixes et les six longueurs de Betterleaks, sans lier chaque longueur à son préfixe (la porte ne se prouve pas autrement).
- *Nom du fournisseur exigé* (score 80) pour trois règles dont le préfixe est trop court ou absent : `brave_search_api_key` (préfixe `BSA`, exigé après « brave » ou l'en-tête `X-Subscription-Token`), `facebook_access_token` (identifiant d'application, `|`, secret : aucun préfixe), `couchbase_capella_api_key` (comme chez Betterleaks). Les 63 autres sont à préfixe fixe (score 95).
- *Règles réunies.* `vercel_token` lit les cinq préfixes de Vercel (`vck_`, `vca_`, `vcr_`, `vci_`, `vcp_`), `settlemint_access_token` les trois de SettleMint, `slack_other_token` les jetons `xoxc-`, `xoxe-` et `xoxo-`.
- *Complétées.* `datastax_astra_token` lit aussi la seconde moitié du jeton (64 chiffres hexadécimaux après « : »), que le motif d'origine laisse hors de la valeur.
- *Vraisemblance.* Le seuil du filtre d'entropie de la règle d'origine devient le validateur de la règle (`token_entropy_35` pour 45 règles, `token_entropy_40` pour 4, `token_entropy_32` pour une) ; 16 règles gardent le seuil d'office. Quatre règles s'écartent du seuil d'origine : `datastax_astra_token` (4,0 dans Betterleaks, 3,5 ici : 0,13 % des valeurs de la forme la plus courte du motif sont sous 4,0), `square_access_token_eaaa` (2,0, 3,5 ici : le préfixe « EAAA » est court et se lit aussi dans du base64, sans le rapport de jetons de Betterleaks), `slack_other_token` (3,5, seuil d'office ici : 0,6 % des jetons « xoxo- » de la forme la plus courte, des groupes de chiffres puis seize chiffres hexadécimaux, sont sous 3,5) et `huggingface_organization_token` (2,0, seuil d'office ici).
- *Resserrées contre les identifiants de code.* Betterleaks écarte les valeurs faites de mots par un rapport de jetons (`tokenRatio`) que ce moteur n'a pas. Quatre préfixes sont aussi des débuts d'identifiants (`tss_`, `prf_`, `lip_`, `persona_production_`) : la suite du jeton n'y admet pas « _ », et un nom comme `prf_hmac_sha256_expand_label` n'est pas signalé. `devcycle_server_sdk_key` exige un chiffre dans la suite du préfixe, longue de huit caractères au moins comme dans la règle d'origine (`dvc_server_hostname` et `dvc_server_ipv4` ne sont pas des clés). Ces cinq règles ne lisent donc pas un jeton qui porterait un « _ », ou aucun chiffre : sept positifs de Betterleaks, tous de valeurs d'essai à « _ », en sortent.
- *Non repris* : les mots-clés de préfiltre (la porte est déduite du motif), le rapport de jetons (`tokenRatio`), les filtres de forme écrits en expressions (`matchesAny`), les appels de validation au fournisseur, les règles composées.

**Règles existantes complétées** (leur champ `upstream` reste celui de Titus) : `tailscale_api_key` (segment de type facultatif, 20 à 70 caractères : lit les six formes de clé Tailscale) ; `hashicorp_vault_service_token` (`-` et `_` admis après `hvs.`) ; `circleci_api_personal_access_token` (22 à 24 caractères quelconques après `CCIPAT_`, score porté de 80 à 95 : le préfixe est fixe) ; `buildkite_api_key` (40 ou 53 caractères) ; `posthog_personal_api_key` (41 à 49 caractères) ; `nuget_api_key` (structure de la clé : alphabet base32 et bits fixes, dans les deux casses ; le motif d'avant admettait 43 caractères quelconques) ; `scalingo_api_token` (jeton fini par un tiret) ; `slack_app_token` (forme `xapp-1-…-…-…` des jetons actuels, en plus de la forme d'avant). `nylas_api_key` garde son motif ; son cas du corpus devient sa seconde forme (30 caractères après le nom), la forme `nyk_` étant lue par `nylas_api_key_v3`.

**Slack.** Le critère « `slack_token` couvre `xapp-`, `xoxo-`, `xoxc-`, `xoxe-` » est tenu par deux règles de fournisseurs, `slack_other_token` et `slack_app_token`, pas par `slack_token` : cette règle vient du catalogue d'origine, son motif est figé par `rules.ts` et la parité. `xoxo-` suivi de mots ou d'une date (« xoxo-my-dear-… ») n'est pas signalé : la règle reprend les formes exactes de Betterleaks, des groupes de chiffres puis une suite hexadécimale ou alphanumérique. Le cookie de session `xoxd-` et les adresses de webhook que `slack_webhook` ne lit pas ne sont pas repris.

**Correspondance** (règle de Betterleaks, règle du Pack) :

| Betterleaks | Pack initial | Périmètre |
|---|---|---|
| `adobe-client-secret` | `adobe_client_secret` (nouvelle) | liste des 91 |
| `aikido-ci-token` | `aikido_ci_token` (nouvelle) | liste des 91 |
| `atlassian-api-token` | `atlassian_api_token` (nouvelle) | liste des 91 |
| `aws-amazon-bedrock-api-key-long-lived` | `aws_bedrock_api_key` (nouvelle) | liste des 91 |
| `bitbucket-data-center-token` | `bitbucket_data_center_token` (nouvelle) | liste des 91 |
| `brave-search-api-key` | `brave_search_api_key` (nouvelle) | liste des 91 |
| `buildkite-service-token` | `buildkite_service_token` (nouvelle) | liste des 91 |
| `buildkite-user-access-token` | `buildkite_api_key` (complétée) | liste des 91 |
| `cartesia-api-key.1` | `cartesia_api_key` (nouvelle) | liste des 91 |
| `circleci-personal-token` | `circleci_api_personal_access_token` (complétée) | liste des 91 |
| `cloudflare-api-key.2` | `cloudflare_user_api_token` (nouvelle) | liste des 91 |
| `cloudsmith-api-key` | `cloudsmith_api_key` (nouvelle) | liste des 91 |
| `cockroachlabs-cloud-api-key` | `cockroachdb_cloud_api_key` (nouvelle) | liste des 91 |
| `configcat-sdk-key-extended` | `configcat_sdk_key` (nouvelle) | liste des 91 |
| `couchbase-capella-api-key` | `couchbase_capella_api_key` (nouvelle) | liste des 91 |
| `datastax-astra-application-token` | `datastax_astra_token` (nouvelle) | liste des 91 |
| `deno-account-token` | `deno_deploy_token` (nouvelle) | liste des 91 |
| `devcycle-server-sdk-key` | `devcycle_server_sdk_key` (nouvelle) | liste des 91 |
| `devin-personal-api-key` | `devin_personal_api_key` (nouvelle) | liste des 91 |
| `devin-service-api-key` | `devin_service_api_key` (nouvelle) | liste des 91 |
| `devin-service-user-token` | `devin_service_user_token` (nouvelle) | liste des 91 |
| `docker-swarm-join-token` | `docker_swarm_join_token` (nouvelle) | liste des 91 |
| `docker-swarm-unlock-key` | `docker_swarm_unlock_key` (nouvelle) | liste des 91 |
| `dockerhub-organization-access-token` | `docker_hub_organization_access_token` (nouvelle) | liste des 91 |
| `elastic-cloud-api-key` | `elastic_cloud_api_key` (nouvelle) | liste des 91 |
| `facebook-access-token` | `facebook_access_token` (nouvelle) | liste des 91 |
| `facebook-page-access-token` | `facebook_page_access_token` (nouvelle) | liste des 91 |
| `figma-personal-access-token` | `figma_pat` (nouvelle) | liste des 91 |
| `gcp-gemini-api` | `google_gemini_api_key` (nouvelle) | liste des 91 |
| `heroku-api-key-v2` | `heroku_api_key_v2` (nouvelle) | liste des 91 |
| `huggingface-organization-api-token` | `huggingface_organization_token` (nouvelle) | liste des 91 |
| `labelbox-api-key` | `labelbox_api_key` (nouvelle) | liste des 91 |
| `labelbox-recursion-api-key` | `labelbox_recursion_api_key` (nouvelle) | liste des 91 |
| `lichess-personal-access-token` | `lichess_personal_access_token` (nouvelle) | liste des 91 |
| `llama-cloud-api-key.1` | `llama_cloud_api_key` (nouvelle) | liste des 91 |
| `mailersend-api-token` | `mailersend_api_token` (nouvelle) | liste des 91 |
| `mapbox-secret-token` | `mapbox_secret_token` (nouvelle) | liste des 91 |
| `mercury-production-api-token` | `mercury_production_api_token` (nouvelle) | liste des 91 |
| `miro-access-token` | `miro_access_token` (nouvelle) | liste des 91 |
| `neon-api-key` | `neon_api_key` (nouvelle) | liste des 91 |
| `nuget-api-key` | `nuget_api_key` (complétée) | liste des 91 |
| `nylas-api-key.1` | `nylas_api_key_v3` (nouvelle) | liste des 91 |
| `octopus-deploy-api-key` | `octopus_deploy_api_key` (nouvelle) | liste des 91 |
| `onesignal-rich-authentication-token` | `onesignal_rich_authentication_token` (nouvelle) | liste des 91 |
| `openshift-user-token` | `openshift_user_token` (nouvelle) | liste des 91 |
| `paddle-live-api-key` | `paddle_live_api_key` (nouvelle) | liste des 91 |
| `persona-production-api-key` | `persona_production_api_key` (nouvelle) | liste des 91 |
| `pinecone-api-key.2` | `pinecone_api_key_pcsk` (nouvelle) | liste des 91 |
| `pinterest-access-token` | `pinterest_access_token` (nouvelle) | liste des 91 |
| `planetscale-oauth-token` | `planetscale_oauth_token` (nouvelle) | liste des 91 |
| `planetscale-password` | `planetscale_password` (nouvelle) | liste des 91 |
| `polar-oauth-access-token` | `polar_oauth_access_token` (nouvelle) | liste des 91 |
| `polar-organization-access-token` | `polar_organization_access_token` (nouvelle) | liste des 91 |
| `polar-personal-access-token` | `polar_personal_access_token` (nouvelle) | liste des 91 |
| `posthog-personal-api-key` | `posthog_personal_api_key` (complétée) | liste des 91 |
| `proof-full-access-api-key` | `proof_api_key` (nouvelle) | liste des 91 |
| `redirect-pizza-api-token.1` | `redirect_pizza_api_token` (nouvelle) | liste des 91 |
| `render-api-key` | `render_api_key` (nouvelle) | liste des 91 |
| `rootly-api-key.1` | `rootly_api_key` (nouvelle) | liste des 91 |
| `runpod-api-key.1` | `runpod_api_key` (nouvelle) | liste des 91 |
| `samsara-api-token.1` | `samsara_api_token` (nouvelle) | liste des 91 |
| `scalingo-api-token` | `scalingo_api_token` (complétée) | liste des 91 |
| `settlemint-application-access-token` | `settlemint_access_token` (nouvelle) | liste des 91 |
| `settlemint-personal-access-token` | `settlemint_access_token` (nouvelle) | liste des 91 |
| `settlemint-service-access-token` | `settlemint_access_token` (nouvelle) | liste des 91 |
| `slack-app-token` | `slack_app_token` (complétée) | Slack |
| `slack-config-refresh-token` | `slack_other_token` (nouvelle) | Slack |
| `slack-legacy-token` | `slack_other_token` (nouvelle) | Slack |
| `slack-session-token` | `slack_other_token` (nouvelle) | Slack |
| `slack-user-token` | `slack_other_token` (nouvelle) | Slack |
| `square-access-token` | `square_access_token_eaaa` (nouvelle) | liste des 91 |
| `tailscale-api-key.1` | `tailscale_api_key` (complétée) | liste des 91 |
| `tailscale-auth-key` | `tailscale_api_key` (complétée) | liste des 91 |
| `tailscale-key` | `tailscale_api_key` (complétée) | liste des 91 |
| `tailscale-oauth-client-secret` | `tailscale_api_key` (complétée) | liste des 91 |
| `tailscale-scim-key` | `tailscale_api_key` (complétée) | liste des 91 |
| `tailscale-webhook-secret` | `tailscale_api_key` (complétée) | liste des 91 |
| `thunderstore-api-token.1` | `thunderstore_api_token` (nouvelle) | liste des 91 |
| `unkey-root-key.1` | `unkey_root_key` (nouvelle) | liste des 91 |
| `upcloud-api-token` | `upcloud_api_token` (nouvelle) | liste des 91 |
| `val-town-api-token.1` | `val_town_api_token` (nouvelle) | liste des 91 |
| `vault-service-token` | `hashicorp_vault_service_token` (complétée) | liste des 91 |
| `vercel-ai-gateway-key` | `vercel_token` (nouvelle) | liste des 91 |
| `vercel-app-access-token` | `vercel_token` (nouvelle) | liste des 91 |
| `vercel-app-refresh-token` | `vercel_token` (nouvelle) | liste des 91 |
| `vercel-integration-token` | `vercel_token` (nouvelle) | liste des 91 |
| `vercel-personal-access-token` | `vercel_token` (nouvelle) | liste des 91 |
| `xendit-production-api-key.1` | `xendit_production_api_key` (nouvelle) | liste des 91 |

**Non reprises** (8 des 91) :

| Betterleaks | Raison |
|---|---|
| `aws-access-token` | identifiant de clé, pas un secret : la règle aws_access_key_id du catalogue d’origine le signale à 45 (avertissement) |
| `jwt` | le cas manqué est un JWT sans signature (algorithme « none ») ; la règle jwt du catalogue d’origine est figée |
| `sendgrid-api-token` | le cas d’essai n’a pas la forme d’une clé SendGrid (22 puis 43 caractères) que lit sendgrid_key |
| `mapbox-api-token` | jeton public par construction (pk.), écarté comme en v0.8.1 |
| `posthog-project-api-key` | clé de projet publique par construction (phc_), écartée comme en v0.8.1 |
| `devcycle-client-sdk-key` | clé publique par construction (SDK client) |
| `devcycle-mobile-sdk-key` | clé publique par construction (SDK mobile) |
| `stripe-access-token` | les formes live et test sont lues par stripe_secret_key ; la forme « _prod_ », seule manquante, n’est pas un format documenté de Stripe et son motif signalerait des identifiants (rk_prod_environment) |

`vault-service-token` est reprise pour sa forme `hvs.` seulement. Sa forme historique (`s.` et 24 caractères) ne l'est pas : Betterleaks l'entoure d'un filtre « pas que des lettres » que le Pack ne sait pas exprimer, et sans lui la règle signale des appels de méthode (quatre négatifs de Betterleaks sur quatre, à l'essai).

**Corpus.** `vectors/detection/rules-providers.json` : 720 cas (un positif et un presque positif pour chacune des 360 règles), formes minimales des motifs, valeurs synthétiques tirées de SHA-256. Aucune valeur d'essai de Betterleaks n'entre dans le corpus de parité. Le 15 novembre 2026, `npm run vectors:detection -- --upstream <checkout> --check` rend « Corpus identique : 1771 cas, 16 fichiers ».

**Mesures du 15 novembre 2026** (indicatives). Bruit : sur 560 855 lignes de code Go et JavaScript et de prose française et anglaise (25 Mo, 390 morceaux de 64 Kio, dont 8 que l'analyse ne finit pas, avant comme après), les règles de fournisseurs ne rendent aucun constat, avant comme après, et le nombre total de constats ne change pas (1 647). Sur les 931 cas négatifs de Betterleaks, 576 rendent au moins un constat (595 en v0.9.0) et 476 un constat bloquant (485) ; les règles nouvelles ou complétées s'y déclenchent 19 fois (7 fois en v0.9.0 pour les règles complétées), sur des jetons d'une forme voisine : un jeton Vercel d'un autre préfixe, une clé RunPod lue par la règle de redirect.pizza et l'inverse, des jetons Mapbox au contenu mal formé, que Betterleaks écarte par un filtre.

### Banc de comparaison Betterleaks

`vectors/comparison/betterleaks.json` : les 1 880 cas d'essai littéraux des règles de Betterleaks (867 positifs, 858 négatifs, 82 positifs et 73 négatifs de règles « composant »), 464 règles. `generator/corpus/betterleaks.ts` les lit dans le texte des fichiers `rules/*.go` et `rules/generic/*.go` d'un clone (appels `rulebuilder.Match`, `NoMatch`, `MatchComponent`, `NoMatchComponent` dont chaque argument est un littéral de chaîne, ou plusieurs joints par `+`) ; 17 appels à argument non littéral sont comptés, pas repris. Le clone doit être au commit épinglé : l'empreinte SHA-256 de la liste des fichiers lus et de leurs empreintes est vérifiée (`BETTERLEAKS_RULES_DIGEST`), sans exécuter git. Régénération : `node corpus/betterleaks.ts --clone <clone> [--check]` dans `generator/`.

C'est un banc, pas un corpus de parité : le fichier ne porte aucun résultat attendu de ce moteur, et un négatif de Betterleaks veut dire « cette règle de Betterleaks ne doit pas se déclencher ici », pas « rien à signaler ». `TestComparisonBetterleaks` (`detect/comparison_test.go`) mesure quatre chiffres avec les règles que `LoadRules` exécute, et refuse une baisse des trois premiers ou une hausse du quatrième :

| Chiffre | v0.9.0 | Après la vraisemblance | v0.10.0 |
|---|---:|---:|---:|
| Rappel : positifs dont un constat recouvre la valeur attendue | 818 / 867 (94,3 %) | 818 (94,3 %) | 823 (94,9 %) |
| Positifs trouvés par une règle dédiée (ni affectation, ni entropie) | 397 (45,8 %) | 396 (45,7 %) | 554 (63,9 %) |
| Positifs recouverts par un constat que le préréglage bloque | 725 (83,6 %) | 725 (83,6 %) | 772 (89,0 %) |
| Constats de règles `provider_token` sur des négatifs sans diversité | 62 | 19 | 19 |

Le positif perdu par la vraisemblance est la clé age d'essai de Betterleaks, faite de 58 fois la même lettre. Les règles reprises donnaient seules 826 positifs trouvés (95,3 %) et 774 bloqués (89,3 %) ; les valeurs publiques connues (section « Code ordinaire ») en retirent trois, à dessein : un jeton public Mapbox (`mapbox-api-token/1`) et deux clés de projet PostHog (`posthog-project-api-key/1` et `/3`), publics par nature, que seules une affectation ou l'entropie signalaient. Les 41 autres positifs manqués sont hors de ce lot : mots de passe de la règle générique de Betterleaks (9), variables Sidekiq (8), jeton SonarQube (6), identifiant et mot de passe de `curl -u` (4), identifiant Sumo Logic (4), et dix autres dans huit règles. Les 82 cas « composant » (identifiant de client, nom d'utilisateur) ne sont pas mesurés : ce ne sont pas des secrets seuls.

Le fichier du banc porte des jetons d'essai publics : il est exempté de la recherche de secrets par son chemin exact (`.gitleaks.toml`), comme `vectors/noise-providers.json`, dont quatre formes à caractère répété déclenchent une règle de gitleaks ; le générateur, lui, reste analysé.

Vérification : `TestPlausibility`, `TestNoiseProviders`, `TestProviderRules`, `TestComparisonBetterleaks`, `TestParity` (1 771 cas), `generator/test/provider-rules.test.ts` (dont la garde de rappel : 99,5 % au moins de 2 000 valeurs tirées de la forme de chaque règle passent son seuil, et de même 2 000 valeurs hexadécimales pour les treize règles à clé publiée hexadécimale).

### Licence de Betterleaks

```text
MIT License

Copyright (c) 2026 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Code ordinaire (v0.10.0)

Écarts d'analyse ajoutés en v0.10.0 pour que du code ordinaire ne soit plus bloqué (`detect/codenoise.go`,
`detect/publicvalues.go`). Cette section est celle du lot « les affectations ne bloquent plus le code ordinaire ».
Aucun de ces écarts n'a d'origine dans Secret Guard ; le précédent suivi est celui de la v0.8.1 (section
« Expurgation », écarts « sans effet sur le corpus ») : le corpus d'origine ne bouge pas, chaque faux positif relevé
entre dans `vectors/noise.json`, un essai nommé le prouve.

### Ce qui était lu, et ce qui change

Après un nom sensible, l'origine tient pour une valeur à protéger tout ce qui suit le signe deux-points ou le signe
égal, fins de ligne comprises, sauf une liste courte d'exceptions. Relevé sur des Postes réels (xSOM Fleet,
novembre 2026) : un script shell qui passe une variable à une option, une expression de CI, un tableau, un objet, un
appel, un type, la ligne qui suit une clé de section YAML donnaient chacun un constat de score 70, donc un blocage.
Les filtres de `detect/codenoise.go` (`assignmentNoise`) jugent la valeur lue, après les filtres d'origine et avant la
création du constat.

**Palier 1, quel que soit le langage : la valeur n'est pas un littéral.**

- *Référence* (`referenceAt`, `interpolation`) : variable ou paramètre de shell (`$NOM`, `$1`, `$@`), expansion
  (`${NOM}`, `${NOM:?message}`, `${NOM:-$AUTRE}`), substitution de commande (`$(…)`, accents graves dans une ligne de
  shell), expression de CI (`${{ … }}`), gabarit (`{{ … }}`, `#{…}`, `%{…}`), champ de format (`%s`), expression d'un
  gabarit de code (`${f(x)}`, champ `{nom}` d'une chaîne Python `f"…"` ou C# `$"…"`), et chaîne entre guillemets faite
  de références. Suivie d'une autre option de la commande, la référence reste une référence, et la suite de la ligne
  est relue pour elle-même. Partout, dotenv compris.
- *Structure de code* (`structureNoise`, `walkStructure`) : tableau et objet partout hors affectation nue
  d'environnement ; appel, expression entre parenthèses, fonction, type générique, type d'un paramètre, accès indexé à
  une propriété là où l'origine admet déjà une référence de code (`referenceEligible`, dernière condition de
  `safeContextualValue`). La structure est **parcourue**, pas écartée en bloc. Un littéral crédible sur sa première
  ligne garde le constat d'origine, à son étendue d'origine : une chaîne, le seul mot nu de la structure, ou, hors
  d'un code reconnu (au sens du palier 2), tout mot nu de forme stricte d'une liste ou d'un objet, jusqu'à sa
  fermeture, qui n'est ni le nom d'un champ ni un chemin d'identifiants (`i18n.French`) : en YAML, `[a, b]` porte des
  littéraux ; dans du code, des identifiants. Chaque littéral crédible des
  lignes suivantes, jusqu'à la
  fermeture de la structure, a son propre constat, sur son étendue exacte. La recherche d'affectations reprend juste
  après l'ouverture, et un champ au nom sensible est lu pour lui-même. Un littéral est crédible (`credibleLiteral`)
  par une forte entropie, ou par 8 unités au moins sans espace avec un chiffre et trois classes de caractères ; pour un
  mot de passe porté par un tableau ou un objet, 8 unités sans espace suffisent (le corpus d'origine garde l'objet JSON
  qui porte un mot de passe fait de mots) ; pour un mot de passe passé en argument d'un appel ou écrit dans un gabarit,
  8 unités sans espace qui mêlent lettres et chiffres (le défaut d'une lecture d'environnement) ; jamais une adresse
  sans identifiants, un nom de constante ni une date.
- *Valeur sans guillemets lue à la ligne suivante* : écartée si aucun mot de la ligne n'a la forme décrite au palier 2 ;
  la ligne suivante est relue pour elle-même. Sous un nom de mot de passe, seule une ligne qui est elle-même un champ
  (un nom suivi du signe deux-points) est écartée : un scalaire YAML peut s'écrire à la ligne suivante.

**Palier 2, dans du code seulement** (langage de code déclaré, ou, sans langage, ligne qui porte un mot-clé de
déclaration parmi `const`, `let`, `var`, `return`, `readonly`, `public`, `private`, `protected`, `type`, `interface`,
`enum`). Pour une clé d'API, un jeton ou un secret générique, une valeur dont aucun mot n'a la forme attendue
(`secretShaped`) n'est pas un constat. Cette forme demande 8 unités au moins sans espace, et l'une de ces propriétés :
trois classes de caractères ; des lettres et deux chiffres sur 10 unités ; une forte entropie ; une suite de 12 lettres
et chiffres qui n'est pas un mot de nom (`nameTokenLetters`) ; plus de 15 lettres d'une seule casse.

**Option d'utilisateur** (`basicAuthNoise`, dans `scanBasicAuthArguments`). Deux nombres (identifiants d'utilisateur et
de groupe de `docker run`) ou un format de date (signe plus et pourcentage en tête, commande `date` en temps universel)
ne sont pas un couple utilisateur et mot de passe. Le motif `cli_basic_auth` du Pack ne change pas.

**Valeur chiffrée** (`isEncryptedEnvelope`, `isEncryptedBlock`) et **valeur publique connue** (`isPublicValue`,
`detect/publicvalues.go`) : voir « Reprise de Betterleaks » ci-dessous. La valeur publique est aussi écartée de
l'entropie, par un seul appel ajouté à la fin de la condition de `scanEntropy`.

**Garde-fous**, chacun avec son essai (`TestAssignmentNoiseGuards`, `TestCodeValueGuards`,
`TestEncryptedEnvelopeGuards`, `TestBasicAuthKeepsCredentials`) :

- aucun filtre de structure ni palier 2 dans un fichier dotenv ou sur une affectation nue d'environnement
  (`isBareEnvironmentAssignment`) ;
- le défaut littéral d'une expansion de shell reste signalé ;
- le mot de passe, la clé privée, l'identifiant de nuage et l'URL de base ne sont jamais jugés sur leur forme ;
- sous un nom de mot de passe, une chaîne à références ne tombe que si ce qui reste hors références ne porte ni lettre
  ni chiffre, et une variable collée à une lettre (un dollar au milieu d'un mot) n'est pas une référence ;
- une référence prolongée par une concaténation ou un texte collé garde son constat ;
- une valeur qui commence par un Substitut n'est pas un tableau (vecteur `residu/bloc-yaml` de
  `vectors/expurgate.json` : sans cette exclusion, `TestExpurgateVectors` échoue) ;
- une structure fermée sur la ligne et suivie d'un texte collé n'est pas une structure ; une ouverture jamais fermée
  suivie d'un seul mot (`[Xy7…`), un mot-clé de fonction collé à un autre signe (`async-…`), un chevron jamais fermé ou
  suivi d'un texte collé (`Abc<def`, `Abc<def>ghi`) non plus ;
- au palier 2, une chaîne à forme de secret dans la suite de l'expression que couvre le constat d'origine garde ce
  constat (`"essai" if debug else "…"`) ;
- une marque de chiffrement sans texte chiffré derrière elle garde son constat : moins de 64 caractères après
  `{cipher}`, moins de 40 après `vault:vN:` (les plus courts textes que Spring et Vault écrivent), étiquette `!vault`
  suivie d'un autre texte qu'un indicateur de bloc, en-tête `$ANSIBLE_VAULT;` sans numéro de version ;
- aucun marqueur de contournement n'est lu dans le texte.

**Travail borné.** Chaque motif d'affectation dispose, par vue, d'un budget d'octets à relire (`spend`, huit fois la
longueur de la vue plus 64 Kio) et une structure de plus de 4 096 octets n'est pas parcourue. Budget épuisé ou borne
dépassée, le filtre ne s'applique plus et le constat d'origine est gardé ; ce n'est jamais une analyse incomplète
(`TestCodeNoiseWorstCases`, `FuzzCodeNoise`). Le budget est rendu au début de chaque motif : le résultat est le même en
analyse séquentielle et en parallèle (`TestParityWorkers`).

### Corpus

- **Corpus d'origine inchangé** : les 1 639 cas des 16 fichiers antérieurs sont identiques octet pour octet
  (`npm run vectors:detection -- --upstream <checkout> --check`), et le moteur les passe tous (`TestParity`). Les
  vecteurs du masquage et de l'expurgation ne sont pas régénérés (`vectors:redact --check` : identiques ;
  `TestExpurgateVectors`).
- **`vectors/noise.json`** : 157 cas « vecu/ » ajoutés (212 au total), chacun sans langage puis avec le langage de son
  fichier. Sur le code de v0.9.0, 104 d'entre eux donnent un constat ; `TestNoiseCorpus` passe à la fin du lot.
- **`vectors/detection/rules-code-noise.json`** : 91 cas, par voisins, la forme écartée (46 cas sans constat, que le
  moteur d'origine signale tous) et la même forme qui porte un littéral (45 cas dont un constat reste). Le résultat
  attendu vient d'une seconde écriture des filtres en TypeScript (`generator/corpus/code-noise.ts`), qui part des
  constats du moteur d'origine, juge chacun, et fait relire par le moteur d'origine la suite d'une étendue écartée ;
  une forme qu'elle ne lit pas arrête le générateur. Cette seconde écriture a relevé un défaut de la première (le
  palier 2 retirait une structure qui porte un littéral), corrigé avant la fin du lot. Comme les autres lectures
  absentes du moteur d'origine, ces cas restent hors des vecteurs du masquage. Total du corpus : 1 730 cas, 17 fichiers.
- **Relecture indépendante du lot** : quatorze cas ajoutés (liste et objet YAML en ligne à mots nus, identifiants et
  chemin d'identifiants, mot de la suite de la ligne, ouverture jamais fermée, défaut d'un mot de passe en argument
  d'un appel, mot-clé de fonction collé, chevron jamais fermé, suite de l'expression au palier 2, marques de
  chiffrement suivies d'un texte court), et les deux cas de texte chiffré portés à la longueur des vrais. Le cas du chiffrement de transit, à longueur réelle, a montré ce que les textes courts
  cachaient : le constat d'affectation tombe, l'avertissement d'entropie reste (cas
  `chiffre/transit-de-vault-avertissement-d-entropie`).

### Mesures du 15 novembre 2026

Indicatives, sur une seule machine (Apple M2 Pro). Constats d'affectation (`contextual_*`) sur les fichiers suivis par
git de cinq dépôts (code et documentation, corpus et vecteurs écartés), moteur v0.9.0 puis moteur de ce lot, sans
langage (ce que fait xSOM Fleet aujourd'hui) puis avec le langage tiré de l'extension de chaque fichier :

| Dépôt | Fichiers | v0.9.0 sans langage | Ce lot sans langage | v0.9.0 avec langage | Ce lot avec langage |
|---|---:|---:|---:|---:|---:|
| xSOM Fleet | 4 648 | 896 | 354 | 844 | 186 |
| Promptfoo (commit `5fac53e`, échantillon) | 2 498 | 2 933 | 2 456 | 2 788 | 425 |
| LiteLLM (commit `09ce4f50`, échantillon) | 2 496 | 6 022 | 5 110 | 5 793 | 766 |
| ggshield (commit `f3377d9`) | 568 | 471 | 286 | 459 | 119 |
| Gitleaks (commit `5f6ec56`) | 225 | 171 | 145 | 173 | 76 |

Sur xSOM Fleet, `cli_basic_auth` passe de 7 constats à 1. Contrôle de ce qui a été retiré : sur xSOM Fleet
(550 constats retirés sans langage, 665 avec), Promptfoo (2 367) et LiteLLM (5 029), aucune étendue retirée ne porte un
mot de 12 caractères ou plus qui mêle lettres et au moins deux chiffres, hors quatre lignes de xSOM Fleet où ce mot est
le nom d'un champ ; échantillons lus à la main (valeurs d'essai en mots, noms de variables, types, libellés). Cas vécus
(63 lignes de code ordinaire) : 41 signalés avant, 8 après sans langage ; 39 avant, 6 après avec langage. Seuil du
palier 2 et vitesse : `docs/bench.md`, « v0.10.0 : code ordinaire ».

Relecture indépendante du lot, le même jour : les garde-fous ajoutés (voir « Corpus ») ne changent aucun constat sur
ces dépôts. Moteur d'avant la relecture puis moteur relu, mêmes fichiers : xSOM Fleet, 355 constats d'affectation sans
langage et 186 avec, dans les deux cas (le dépôt a reçu des fichiers depuis la première mesure) ; Promptfoo, 2 456 et
425 ; LiteLLM avec langage, 766. Aucun constat ajouté ni retiré.

### Vérification

`TestNoiseCorpus` (en échec sur le code de v0.9.0 avec les cas ajoutés) ; `TestAssignmentValueIsNotALiteral`,
`TestStructureIsWalked`, `TestAssignmentNoiseGuards`, `TestReferenceAt`, `TestSecretShapes` ;
`TestCodeValueWithoutSecretShape`, `TestCodeValueGuards`, `TestSecretShapeThreshold`,
`TestSecretShapeCoversProviderTokens` ; `TestBasicAuthIgnoresDatesAndNumericIDs`, `TestBasicAuthKeepsCredentials` ;
`TestEncryptedEnvelopeIsNotASecret`, `TestEncryptedEnvelopeGuards`, `TestPGPPrivateKeyIsNotAnEnvelope` ;
`TestPublicForms`, `TestPublicValueIsNotAnAssignment`, `TestPublicValueIsNotAnEntropyFinding` ;
`TestCodeNoiseWorstCases`, `FuzzCodeNoise`, `TestStructureHelpers` ; `TestParity` (1 730 cas, 0 écart), `TestParityWorkers`, `TestRedactParity`,
`TestDecisionParity`, et la suite du module `expurgation` ; côté générateur, `generator/test/code-noise.test.ts`.

### Ce qui reste signalé, et ce qui est perdu

- Reste signalé : une valeur courte ou en mots hors d'un code reconnu (sans langage ni mot-clé de déclaration ; YAML,
  JSON, shell, dotenv) ; un mot de passe d'essai banal, où qu'il soit ; le défaut littéral d'une expansion ; une
  annotation de type Python à crochets sous un mot de passe (cas `contextual/optional-type-annotation` du corpus
  d'origine) ; la prose d'un commentaire ou d'un document sous un nom sensible ; une URL de base dont le mot de passe
  est une référence (règle des URL à identifiants) ; l'avertissement d'entropie d'un texte chiffré de longueur réelle
  (chiffrement de transit de Vault, corps d'un bloc Ansible Vault) : l'entropie ne lit pas les enveloppes.
- Perdu, dans du code seulement (palier 2) : le constat d'affectation d'une clé, d'un jeton ou d'un secret générique
  dont la valeur est faite de mots (y compris longs, séparés par des tirets), d'une suite aléatoire de moins de
  12 caractères sans chiffre, ou de moins de 16 lettres d'une seule casse. Une règle à format fixe ou l'entropie
  peuvent encore la trouver.
- Perdu, partout hors dotenv et affectation nue d'environnement : sous un nom de mot de passe, le constat d'un littéral
  de moins de 8 caractères porté par un tableau ou un objet (seuil qui écarte les schémas à type de chaîne), et celui
  d'un mot de passe fait de mots, sans chiffre, passé en argument d'un appel ou écrit dans un gabarit. Sous les autres
  noms, le constat d'un littéral sans chiffre porté par une structure. Dans une liste en ligne de plusieurs éléments,
  le constat d'un mot nu sans forme stricte (`[motdepasse1, autre]`) ; dans du code, celui de tout mot nu.
- Perdu, partout : sous un nom de mot de passe, le constat d'une chaîne faite d'un dollar, d'un nom et de signes
  (`"$Nom2024!"`) : lue comme une variable suivie de ponctuation, y compris hors d'un script shell (l'origine écartait
  déjà la variable seule, `"$Nom2024"`) ; le constat d'un mot enveloppé dans un gabarit (`"#{mot}"`, `"%{mot}"`).
- Perdu, partout : le constat d'une valeur qui a exactement la forme d'une valeur publique de la liste sous un nom de
  clé d'API ou de jeton (pour les formes sans préfixe propre, seulement avec le mot-clé du fournisseur sur la ligne,
  avant la valeur) ; le constat d'une valeur à marque de chiffrement suivie de texte chiffré.

### Reprise de Betterleaks (licence MIT)

Dépôt `https://github.com/betterleaks/betterleaks`, commit `b4b1c4455987636400ce693bd9d8a8e2cf375ed9` du
13 novembre 2026, licence MIT, « Copyright (c) 2026 Zachary Rice ».

| Élément d'origine | Dans ce dépôt | Ce qui est repris | Ce qui change |
|---|---|---|---|
| `rules/generic/filter.go`, `testAndPublicAPIFilters` (65 formes de clés publiques et de clés d'essai : 22 par leur motif seul, 43 avec des mots-clés) | `detect/publicvalues.go`, `publicForms` | les 65 motifs et leurs mots-clés, tels quels (`\@` et `\/` écrits sans barre oblique inverse ; les deux valeurs fixes assemblées par morceaux) | motifs ancrés aux deux bouts et compilés par RE2 ; un mot-clé ne compte que sur la ligne et **avant** la valeur (à l'origine : à proximité) ; les affectations n'appliquent la liste qu'aux noms de clé d'API et de jeton, jamais à un mot de passe ni à un nom qui porte « secret » ; l'entropie l'applique par un seul appel (`scanEntropy`) ; les quatre formes que l’origine garde en commentaire (clés secrètes et jeton d’accès d’essai) ne sont pas reprises |
| `rules/generic/password.go`, `isEncryptedValue` (enveloppes chiffrées) | `detect/codenoise.go`, `isEncryptedEnvelope`, `isEncryptedBlock` | l'idée, et six formes : sops (`ENC[…]`), Spring Cloud Config (`{cipher}…`), Ansible Vault (`$ANSIBLE_VAULT;`, étiquette `!vault`), chiffrement de transit de Vault (`vault:vN:…`), age, PGP (en-têtes d'armure) | aucun motif copié : lecture écrite à la main, resserrée (la marque doit être suivie de texte chiffré : `,data:` et crochet fermant pour sops, 64 caractères de texte chiffré après `{cipher}`, 40 après `vault:vN:`, numéro de version après `$ANSIBLE_VAULT;`, indicateur de bloc ou fin de ligne après `!vault`) ; les autres formes de l'origine (OpenSSL salé, Fernet, JWE, PASETO, DPAPI, `ENCRYPTED PRIVATE KEY`) ne sont pas reprises |

Le code qui applique ces listes est écrit pour ce module ; aucun essai de Betterleaks n'est repris. Rien n'est repris
de TruffleHog (AGPL-3.0). L'idée d'écarter une référence (`$1`, `${NOM}`, `{{ … }}`, `${{ … }}`) vient aussi de la
liste des valeurs ignorées de Gitleaks (`config/gitleaks.toml`, commit `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c`,
licence MIT, « Copyright (c) 2019 Zachary Rice ») : seule l'idée est reprise, sans motif ni code.

Le texte de la licence MIT de Betterleaks n'est reproduit qu'une fois, plus haut : « Licence de Betterleaks ».
