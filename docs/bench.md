# Vitesse de l'analyse

Mesures du 19 octobre 2026 sur une seule machine. Elles sont indicatives : une autre machine, une autre charge ou un
autre texte donnent d'autres chiffres. Le gain se lit en rapport, sur la même machine.

## Ce qui a changé

Deux leviers, sans changer un seul résultat (constats, ordre, étendues, scores, issue) :

1. **Porte littérale exacte** (`detect/prefilter.go`). À la compilation d'une règle (`LoadRules`), l'arbre
   `regexp/syntax` de son motif donne, quand on sait le prouver, des littéraux dont l'un au moins figure dans toute
   correspondance (`ghp_`, `gho_`… pour `github_token`, `AKIA`, `ASIA`… pour `aws_access_key_id`). Une vue qui n'en
   contient aucun ne peut pas correspondre : la règle n'y est pas exécutée. Sinon, le motif s'exécute sur tout le texte
   de la vue, comme avant, sans fenêtre. Un motif qui replie la casse (`(?i)`), une alternance dont une branche n'a
   aucun littéral, ou un littéral de moins de 3 octets : aucune porte, la règle s'exécute toujours.
2. **Exécution en parallèle** (`detect/detectors.go`) des familles qui ne consomment aucun budget partagé (clés
   privées, règles « motif seul » sans validateur, URL à identifiants, six motifs d'affectation, cookies, `-u`,
   entropie). Les familles qui débitent le budget de décodage (`jwt`, clé `auth` de Docker) restent dans le fil de
   l'appelant, dans leur ordre d'origine. Les constats sont concaténés dans l'ordre exact de l'analyse séquentielle.
   `Options.Workers` borne le nombre de fils (0 : 8 au plus ; 1 : analyse séquentielle) ; le moteur ne lit pas le
   nombre de processeurs. Une vue de moins de 1 Kio est toujours analysée en séquentiel.

Preuves : `TestParity` (823 cas) et tous les tests de parité inchangés ; `TestParityWorkers` (corpus entier, chemin
parallèle forcé sur toute vue, `GOMAXPROCS` à 1 puis 8, `Workers` à 1 puis 8 : résultats identiques entre eux et au
corpus) ; `FuzzPrefilterParity` (porte et 8 fils face à l'analyse séquentielle sans porte, Empreintes locales
comprises ; graines : entrées du corpus et des autres fuzz, exécutées par `go test`) ; `TestPrefilterFoldCase`
(U+212A et U+017F avec une règle `(?i)`).

## Conditions

- Machine : Apple M2 Pro (12 cœurs : 8 de performance, 4 d'efficacité), macOS (Darwin 25.1.0), Go 1.27.2,
  `GOMAXPROCS` par défaut (12).
- Texte : `benchText` (`detect/bench_test.go`), déterministe, fait de lignes de code (TypeScript, Go, Python, SQL),
  de journaux, de configuration et de prose en français et en anglais. Variante « secrets » : un secret synthétique
  tous les 8 Kio (jeton GitHub, mot de passe affecté, identifiant AWS, base64 d'une affectation, URL à identifiants),
  construit en morceaux à l'exécution.
- Options : `detect.Options{}` (aucun langage, `Workers` à 0).
- Référence v0.3.0 : le même fichier de banc, sur l'étiquette `v0.3.0` (commit `06a6bae`), sur la même machine le
  même jour.
- Commande : `go test -run XXX -bench 'BenchmarkScan/' -benchtime 20x -count 5 ./detect` (v0.3.0 : `-count 3`) ;
  chiffre retenu : la médiane des passes.

## Résultats

| Taille | Texte | v0.3.0 | Maintenant | Gain |
|---|---|---:|---:|---:|
| 2 Kio | propre | 2,06 ms | 0,31 ms | ×6,5 |
| 2 Kio | secrets | 2,10 ms | 0,32 ms | ×6,5 |
| 16 Kio | propre | 16,6 ms | 2,25 ms | ×7,3 |
| 16 Kio | secrets | 16,7 ms | 2,49 ms | ×6,7 |
| **64 Kio** | **propre** | **67,5 ms** | **9,18 ms** | **×7,4** |
| 64 Kio | secrets | 66,6 ms | 9,80 ms | ×6,8 |
| 256 Kio | propre | 264 ms | 36,9 ms | ×7,2 |
| 256 Kio | secrets | 265 ms | 38,9 ms | ×6,8 |

Porte seule, un fil (`BenchmarkScanSequential`, `Workers` à 1), 64 Kio : 39,9 ms sans secret (×1,7), 43,2 ms avec
secrets (×1,5). C'est l'ordre de gain à attendre là où il n'y a qu'un fil (module WebAssembly : 190 ms médians pour
l'entrée de 64 Kio de `wasm/bench.mjs` le même jour, contre 300 à 360 ms mesurés le 13 octobre).

## Limites de la mesure

- Le gain est celui d'une machine à plusieurs cœurs. Le chemin le plus long reste le motif d'affectation `ASSIGNMENT`
  (environ 8 ms à 64 Kio sur un cœur de performance) : il borne le temps d'une vue, quel que soit le nombre de fils.
  Le prototype du 19 octobre mesurait ×10,6 ; la version livrée, qui garde aussi les affectations et l'entropie
  exactes et en parallèle, mesure ×7,4 à 64 Kio sans secret.
- Sur ce processeur, un fil placé sur un cœur d'efficacité est deux à trois fois plus lent : des passes isolées
  montent jusqu'à 12 ms à 64 Kio (×5,6). Les familles les plus longues partent les premières pour réduire cet écart.
- Sur un poste chargé (compilation, analyse antivirus), le temps dépend des cœurs libres.

## v0.7.0 : règles de données personnelles

Mesure du 10 novembre 2026, même machine, mêmes conditions et même commande (`-benchtime 20x`, une passe), avant et après
l'ajout des cinq règles `iban`, `fr_nir`, `fr_siret`, `fr_siren`, `payment_card` (aucune n'a de porte littérale : leurs
motifs n'ont pas de littéral obligatoire de trois octets) :

| Taille | Texte | Avant | Après |
|---|---|---:|---:|
| 2 Kio | propre | 0,38 ms | 0,58 ms |
| 16 Kio | propre | 2,35 ms | 3,43 ms |
| **64 Kio** | **propre** | **9,10 ms** | **13,70 ms** |
| 64 Kio | secrets | 11,25 ms | 13,88 ms |
| 256 Kio | propre | 39,2 ms | 58,6 ms |

Coût par règle à 64 Kio sans secret : `iban` 2,0 ms, `payment_card` 2,1 ms, `fr_nir` 1,9 ms, `fr_siret` 1,6 ms, `fr_siren`
0,5 ms. Un premier motif d'IBAN par pays (une branche par longueur) coûtait 25 ms à lui seul (64 Kio) : le motif est donc
générique et le moteur raccourcit la correspondance (`detect/personaldata.go`). Mesure indicative, une seule passe.

## v0.10.0 : code ordinaire

Mesures du 15 novembre 2026, même machine (Apple M2 Pro, Go 1.27.2). Elles accompagnent les filtres de
`detect/codenoise.go` et `detect/publicvalues.go` (UPSTREAM.md, « Code ordinaire », où figure le bruit mesuré sur cinq
dépôts).

### Seuil du palier 2

Dans du code, une valeur dont aucun mot n'a la forme attendue n'est plus signalée comme clé d'API, jeton ou secret
générique. Le seuil est la fonction `secretShaped`. Il doit laisser passer les valeurs d'essai en mots et les noms de
variables, et garder ce qui ressemble à un tirage au hasard. Mesure : `TestSecretShapeThreshold`, 20 000 suites tirées
par un générateur déterministe (SplitMix64, graine 46) pour chaque alphabet et chaque longueur ; la table est le journal
de l'essai (`go test -count=1 -v -run '^TestSecretShapeThreshold$' ./detect`), en suites gardées pour mille.

| Alphabet | 8 | 12 | 16 | 20 | 24 | 32 | 40 |
|---|---:|---:|---:|---:|---:|---:|---:|
| hexadécimal | 0 | 999 | 1 000 | 1 000 | 1 000 | 1 000 | 1 000 |
| base32 (majuscules, 2 à 7) | 0 | 895 | 991 | 995 | 998 | 999 | 1 000 |
| minuscules et chiffres | 0 | 972 | 997 | 999 | 999 | 999 | 1 000 |
| base62 | 727 | 990 | 998 | 999 | 1 000 | 1 000 | 1 000 |
| base64url | 785 | 994 | 998 | 999 | 999 | 1 000 | 1 000 |
| minuscules seules | 0 | 0 | 1 000 | 1 000 | 1 000 | 1 000 | 1 000 |

Le seuil du prototype d'étude (trois classes de caractères, ou lettres et deux chiffres sur 10 unités, ou forte
entropie) a été écarté sur ces chiffres : il gardait 833 suites pour mille en base32 à 16 caractères, 939 en base62,
960 en minuscules et chiffres, 963 en base64url, et aucune suite de minuscules seules avant 32 caractères (28 pour
mille à 32, 151 à 40). Deux formes ont donc été ajoutées : une suite de 12 lettres et chiffres qui n'est pas un mot de
nom, et plus de 15 lettres d'une seule casse (les mots courants s'arrêtent à 15 lettres). À 16 caractères et plus, le
seuil retenu garde au moins 991 suites pour mille, quel que soit l'alphabet ; l'essai échoue sous 990.

Ce que le seuil laisse tomber, dans du code seulement : une suite de 8 caractères hexadécimaux ou de 8 minuscules et
chiffres sans deux chiffres, une suite de moins de 12 caractères sans chiffre, moins de 16 lettres d'une seule casse,
et toute valeur faite de mots. Hors d'un code reconnu, dans un fichier dotenv et sur une affectation nue
d'environnement, rien ne change.

Vrais positifs : les 521 étendues détectées par une règle de fournisseur dans le corpus portent toutes un mot de cette
forme (`TestSecretShapeCoversProviderTokens`), et `TestParity` passe sur les 1 639 cas antérieurs.

Effet mesuré sur les 4 648 fichiers de xSOM Fleet, avec le langage de chaque fichier, en constats d'affectation :
844 avec le moteur v0.9.0, 333 après le palier 1 seul (commit `cbcb02c`), 186 à la fin du lot. Les 147 constats
retirés entre les deux sont des valeurs d'essai en mots, des noms de variables et de constantes, des types et des
libellés (échantillon de 34 lus à la main, aucun littéral à forme de secret). Sans langage, le palier 2 n'agit que sur
les lignes à mot-clé de déclaration : 376 constats après le palier 1, 354 à la fin du lot.

### Vitesse

Les filtres ne s'exécutent que sur une affectation qui allait donner un constat, et la comparaison aux valeurs publiques
que sur un candidat qui allait donner un avertissement d'entropie : sur un texte sans constat, le chemin ajouté se
réduit à l'initialisation d'un budget par motif. Le texte du banc (`benchText`, variante « propre ») n'a aucun constat.

`go test -run '^$' -bench 'BenchmarkScan64KiB' -count=3 ./detect`, moteur v0.9.0 (commit `e325ae5`), machine calme :
12,45 ms, 12,26 ms, 11,87 ms. Les passes « après » ont été mesurées sur la machine chargée par d'autres travaux
(charge moyenne de 17 à 34 pour 12 cœurs) : elles ne se comparent pas à ces trois chiffres. Mesurés en alternance sous
cette charge, les deux moteurs donnent des séries qui se recouvrent :

| Banc (64 Kio, propre) | v0.9.0 | Ce lot |
|---|---|---|
| `BenchmarkScan64KiB`, trois séries de trois passes alternées | 15,7 à 43,2 ms (médiane 31,2) | 18,8 à 76,6 ms (médiane 25,1) |
| `BenchmarkScanSequential` (un fil), trois passes alternées | 80,2 ms, 81,5 ms, 88,0 ms | 81,2 ms, 81,7 ms, 83,2 ms |

Lecture honnête : aucun écart mesurable, mais la dispersion sous charge est plus grande que l'écart cherché. Le banc
séquentiel, moins sensible au nombre de cœurs libres, donne la même médiane à 0,2 ms près. À refaire sur une machine
calme avant l'étiquette de version.
