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

## Bruit sur du code : banc `tools/bruit` (lot L04, Stories 27.6 et 27.8)

Mesures du 15 novembre 2026. Le banc compte ce qu'un développeur subit : les constats du moteur sur du code et de la
documentation ordinaires, où presque rien n'est un secret. Ce n'est pas un taux de faux positifs : personne n'a trié
ces constats un à un, et les dépôts de détecteurs de secrets (Gitleaks, ggshield) portent des jetons d'essai voulus.
Le chiffre sert à comparer deux versions du moteur sur les mêmes octets.

### Méthode

- `go run ./tools/bruit <nom>=<chemin>…` lit chaque dépôt dans git, au commit épinglé par le rapport
  (`tools/bruit/rapport.json`), sans toucher au répertoire de travail : la mesure est la même sur toute machine qui a
  ce commit.
- Fichiers analysés : extensions de code et de documentation (`.ts`, `.tsx`, `.mts`, `.mjs`, `.js`, `.go`, `.py`, `.sh`,
  `.yml`, `.yaml`, `.json`, `.toml`, `.tf`, `.md`, `.sql`, `.ps1`, `.html`, `.css`), 1 Mio au plus, hors corpus,
  vecteurs, jeux d'essai, dépendances, fichiers de verrou et instantanés (`skippedPaths`, `tools/bruit/git.go`).
- Analyse sans langage (`detect.Options{}`), comme un hook qui ne connaît pas le fichier, avec les règles que
  `LoadRules` exécute (les règles « à activer » sont éteintes).
- Pour LiteLLM et Promptfoo, 2 500 fichiers tirés de façon déterministe (ordre du SHA-256 du chemin).
- Chaque constat d'affectation (`contextual_…`) et d'entropie (`high_entropy`) est classé par forme de valeur ; le
  rapport ne garde que des décomptes : ni chemin, ni ligne, ni valeur.
- Une hausse du nombre de constats, des constats d'une règle ou des analyses incomplètes face au rapport commité est
  refusée (sortie 1). `-write` enregistre une baisse ; `-baseline` pose une nouvelle base (nouveau dépôt, nouveau
  commit, hausse acceptée et justifiée dans le message du commit).

### Chiffres de départ et effet de la Story 27.6

Moteur v0.9.0 (345 règles, commit `e325ae5`), puis le même avec la correction de l'entropie (Story 27.6).

| Dépôt (commit épinglé) | Fichiers | Constats, v0.9.0 | Constats, après | Entropie, v0.9.0 | Entropie, après | Affectations | Analyses incomplètes |
|---|---:|---:|---:|---:|---:|---:|---:|
| xSOM Fleet (`77fded7`) | 4 614 | 1 959 | 1 462 | 868 | 371 | 896 | 1 |
| LiteLLM (`09ce4f5`, 2 500 fichiers tirés) | 2 500 | 7 071 | 7 026 | 534 | 489 | 6 224 | 15 |
| Promptfoo (`5fac53e`, 2 500 fichiers tirés) | 2 500 | 4 145 | 4 138 | 626 | 619 | 3 214 | 3 |
| ggshield (`f3377d9`) | 568 | 699 | 698 | 193 | 192 | 471 | 0 |
| Gitleaks (`5f6ec56`) | 225 | 584 | 579 | 132 | 127 | 171 | 2 |

Les affectations et les analyses incomplètes ne changent pas dans ce lot : elles sont l'objet du lot « le code n'est
plus bloqué » (section de ce lot).

Constats d'entropie de xSOM Fleet par forme de valeur :

| Forme de la valeur | v0.9.0 | Après |
|---|---:|---:|
| identifiant en casse de chameau | 486 | 37 |
| base64 à signes (`+`, `=`) | 275 | 275 |
| chemin d'URL | 39 | 14 |
| nom à soulignés | 35 | 14 |
| hexadécimal | 13 | 13 |
| autre suite alphanumérique | 9 | 9 |
| chemin | 7 | 5 |
| nom à tirets | 4 | 4 |

### Ce qui reste, et pourquoi

- **Base64 d'images embarquées** (272 des 275 constats de forme « base64 à signes », dans deux pages HTML) :
  `data:image/…;base64,` suivi de dizaines de kilooctets, un constat par tranche de 512 caractères. Non traité dans ce lot (hors du périmètre de la Story 27.6) ;
  c'est désormais la première source de bruit d'entropie de ce dépôt.
- **Identifiants en casse de chameau** (37) : charges utiles base64url d'enveloppes signées (vrais candidats
  d'entropie), noms d'essais de moins de quatre mots réguliers à sigles, sigles de plus de 5 majuscules.
- **Chemins d'URL** (14) : identifiants alphanumériques opaques (fiche d'une place de marché, document partagé), que
  rien ne distingue d'un jeton.
- **Alphabets écrits en clair** (une quinzaine, dans « nom à soulignés » et « autre suite alphanumérique ») : seule la
  valeur exacte de l'alphabet base64 est écartée.
- Dans les quatre dépôts ouverts, l'entropie est faite surtout de jetons d'essai et de charges encodées : la
  correction y change peu, et n'y fait rien monter.

### Limites de la mesure

- Un seul commit par dépôt, une seule machine ; les dépôts ouverts sont des clones de lecture à un commit de novembre
  2026. Le dépôt xSOM Fleet est privé : qui ne l'a pas mesure les quatre autres.
- La forme d'une valeur est une heuristique de classement (`tools/bruit/shape.go`), pas un jugement : « identifiant
  en casse de chameau » prend aussi une charge base64 sans chiffre ni signe.
- Le banc ne dit rien du rappel : ce sont le corpus de parité (`TestParity`) et les essais de jetons aléatoires
  (`TestEntropyKeepsTokens`, `TestEntropyKeepsTokensBesideNames`, `TestEntropyNameRarelyMatchesTokens`) qui prouvent
  qu'un jeton reste détecté. Coût mesuré de la Story 27.6 sur le rappel : un jeton aléatoire fait de lettres seules en
  casse mêlée, sans aucun chiffre, a la forme d'un identifiant généré 3 fois sur 10 000 à 32 et à 40 caractères (31
  puis 2 pour un million avant) et perd alors son avertissement d'entropie ; un jeton alphanumérique, 3 fois sur un
  million à 32 caractères (`TestEntropyNameRarelyMatchesLetters`, détail dans `UPSTREAM.md`).
- Vitesse de l'analyse après la Story 27.6 : aucun écart mesurable. `BenchmarkScan/64KiB/propre`
  (`-benchtime 30x -count 5`, deux passes alternées, médianes) : 19,9 ms puis 16,3 ms avant, 18,0 ms puis 16,0 ms
  après. La machine était partagée et chargée ce jour-là : ces durées sont plus longues que celles du haut de la
  page et ne se comparent qu'entre elles. La forme d'identifiant généré n'est essayée que sur un candidat d'entropie
  déjà refusé comme nom.

### Rejouer

```sh
go run ./tools/bruit xsom-fleet=<chemin> litellm=<chemin> promptfoo=<chemin> ggshield=<chemin> gitleaks=<chemin>
go run ./tools/bruit -write …      # enregistre une baisse
go run ./tools/bruit -list …       # position de chaque constat (fichier, ligne, règle, forme), sans la valeur
```
