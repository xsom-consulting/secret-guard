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
  commit, hausse acceptée et justifiée dans le message du commit). Un dépôt du rapport absent de la ligne de
  commande est nommé « non mesuré » sur la sortie : une passe partielle ne vaut pas pour tout le rapport.

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

## v0.10.0 : consignes adressées à l'agent (paquet `injection`)

Mesures du 15 novembre 2026. Ce sont des relevés, pas des promesses : un taux mesuré sur des textes publics ne dit pas
ce qu'une consigne écrite autrement fera, et l'absence de constat n'est jamais une preuve d'innocuité.

### Rappel de départ

Le rappel du paquet n'avait jamais été mesuré. Le corpus `vectors/injection-recall.json` réunit 280 textes publics
(sources, commits et licences : UPSTREAM.md, « Corpus de rappel du paquet injection ») ; `TestRecallCorpus` y applique
`injection.Find`, publie le taux de textes signalés par source et par règle (`go test -v -run '^TestRecallCorpus$'
./injection`) et échoue au moindre écart avec le relevé commité `injection/testdata/recall.json`, qui liste par
identifiant, jamais par texte, les consignes manquées et les textes sains signalés.

Point de départ, moteur de la v0.9.0 (cinq règles, texte lu tel quel) :

| Source | Étiquette de la source | Textes | Signalés | Taux | Par règle |
|---|---|---:|---:|---:|---|
| LLM Guard | injection | 49 | 21 | 43 % | `instruction_override` 20, `role_switch` 1 |
| LLM Guard | sain | 11 | 0 | 0 % | |
| Promptfoo | gabarit de contournement | 106 | 25 | 24 % | `instruction_override` 21, `role_switch` 4, `concealment` 1 |
| Akto | charge de test LLM | 59 | 31 | 53 % | `instruction_override` 31 |
| Skill Scanner | consigne (`prompt_injection`) | 1 | 0 | 0 % | |
| Skill Scanner | sain | 11 | 0 | 0 % | |
| Skill Scanner | autre risque (code, dépendance) | 43 | 0 | 0 % | |

Lecture :

- Akto : 31 sur 61 (51 %) avec les deux charges qui portent une signature d'essai d'antivirus, non copiées dans le
  corpus (UPSTREAM.md) ; 31 sur 59 sur le corpus commité.
- Presque tous les constats viennent d'une seule règle, `injection_instruction_override`.
- Ces corpus visent un chatbot. Un gabarit de persona n'est pas la même menace qu'une consigne glissée dans un fichier
  lu par un agent de code, qui est le périmètre du paquet ; beaucoup de charges d'Akto demandent du code malveillant
  et ne sont pas des injections. Ces taux sont un point de départ, pas une note.

### Lectures du moteur (Story 27.47)

`injection.Find` lisait le texte tel quel : un encodage suffisait à faire disparaître une consigne. Il lit maintenant
aussi le texte normalisé et déplié, puis décodé une fois (`injection/views.go`), et ramène chaque constat aux octets
du texte reçu. `TestPositiveCasesSurviveTransformations` réécrit les 27 cas positifs de `vectors/injection.json` et
exige d'y retrouver chaque règle attendue :

| Transformation des 27 cas positifs | Avant | Après |
|---|---:|---:|
| Base64 (standard ; URL sans remplissage ; au milieu d'une phrase ; replié à 76 colonnes) | 0 | 27 |
| Base64 replié entre une ligne de titre et un mot final | non mesuré | 27 |
| Pourcentages (`%20`…) | 0 | 27 |
| Échappements JSON (`\uXXXX`, `\n`) | 0 | 27 |
| Pleine chasse | 0 | 27 |
| Espace insécable, espace fine insécable | 12 | 27 |
| Texte replié (fin de ligne, retrait) | 7 | 27 |
| Texte replié et espaces insécables | non mesuré | 27 |

« Avant » : relevé du 15 novembre sur le moteur de la v0.9.0 (étude de veille, mêmes cas). Ce qui reste hors de
portée : base64 de base64, hexadécimal, ROT13, entités HTML, homoglyphes, leetspeak, lettres espacées (repli reporté).
Sur le corpus de rappel, ces lectures ne changent aucun compte : ses textes sont écrits en clair.

**Porte littérale.** Les motifs étaient exécutés un à un sur tout le texte. Chacun commence par des mots
obligatoires : une seule lecture du texte relève ces mots, et le motif n'est exécuté qu'à ces endroits, sur une fenêtre
bornée (`injection/gate.go`). Preuves que rien n'est perdu : `TestGateFindsEveryMatch` (chaque correspondance d'un
motif cherché sans porte est rendue à la même étendue), `TestFindEqualsUngatedSearch` (même rapport qu'une recherche
sans porte à chaque position de chaque lecture), `FuzzGateParity`. La relecture du lot a trouvé un texte où cette
égalité était fausse (un point-virgule écrit en pourcentage, 48 espaces ou plus, une fin de ligne, puis un faux
historique à ligne repliée : aucune lecture ne le trouvait) ; il est corrigé et gardé par
`TestSeenWindowCoversUnwrapDecision`. Ces essais comparent des textes choisis et tirés au hasard : ils ne sont pas une
preuve pour tout texte.

**Durée.** `go test -run XXX -bench 'BenchmarkFind/' -benchtime 20x -count 5 ./injection`, médiane des cinq passes,
Apple M2 Pro, Go 1.27.2. Texte de banc (`injection/bench_test.go`) : lignes de code, de journal, de configuration et
de prose en français et en anglais, qui portent à chaque ligne les mots obligatoires de plusieurs motifs sans former de
consigne (cas défavorable à la porte) ; variante « consignes » : une consigne tous les 8 Kio ; « prose repliée » :
paragraphes français repliés, avec espaces insécables. « Avant » : le même fichier de banc sur le paquet de la v0.9.0
(commit `e325ae5`), les deux séries l'une après l'autre. La machine était partagée avec d'autres travaux (charge
moyenne de 15 à 19 pendant la mesure) : les durées sont indicatives, le rapport se lit sur la même série.

| Taille | Texte | Avant (v0.9.0, une lecture) | Après (toutes les lectures) | Gain |
|---|---|---:|---:|---:|
| 2 Kio | propre | 1,56 ms | 0,16 ms | ×9,5 |
| 16 Kio | propre | 12,6 ms | 1,50 ms | ×8,4 |
| **64 Kio** | **propre** | **66,3 ms** | **5,07 ms** | **×13** |
| 64 Kio | consignes | 55,6 ms | 5,19 ms | ×11 |
| 64 Kio | prose repliée | 55,9 ms | 3,85 ms | ×15 |
| 256 Kio | propre | 229 ms | 22,0 ms | ×10 |

Pire cas (`TestWorstCasesAreLinear`, entrées de 1 Mio choisies contre les motifs et contre chaque lecture) : 3 s pour
« send token » répété, comme avant ; moins de 150 ms pour les autres. Un texte écrit contre plusieurs lectures à la
fois coûte davantage : voir « Durée, état final ».

**Faux positifs.** `go run ./tools/injectioncorpus fichiers -racine <clones>` sur les 34 dépôts publics épinglés de
l'étude des consignes en clair de xSOM Fleet (22 octobre 2026) : 151 392 fichiers texte analysés (586 de plus de 1 Mio,
3 927 binaires et 70 liens écartés), un fichier comptant une fois. 15 de ces dépôts sont des cadres d'agents, des
collections de prompts et des outils d'équipe rouge : un fichier signalé y est souvent une vraie consigne, citée ou
employée.

| Fichiers signalés | Avant (v0.9.0) | Avec les lectures |
|---|---:|---:|
| Tous | 464 (0,306 %) | 478 (0,316 %) |
| `injection_instruction_override` | 280 | 288 |
| `injection_role_switch` | 42 | 42 |
| `injection_exfiltration` | 13 | 20 |
| `injection_concealment` | 16 | 16 |
| `injection_message_markers` | 153 | 153 |

Aucun fichier signalé avant ne cesse de l'être. Les 14 fichiers de plus viennent tous du texte déplié : une phrase
qui continue à la ligne suivante (journal des modifications, commentaire de documentation, prompt d'agent). Une
première version, qui dépliait aussi les lignes de code, en ajoutait 22 : une fin de ligne après `{`, `}`, `(`, `[`,
`;`, `=` ou `\`, ou devant `}`, `)`, `]`, n'est donc pas dépliée. Depuis la relecture du lot, une fin de ligne bordée
de plus de 32 octets d'espaces ne l'est pas non plus (aucun fichier signalé ne change sur les 34 dépôts). La durée de la mesure entière est passée de 865 s à
52 s de processeur.

### Règles des familles manquées et citations (Story 27.48b)

Sept règles s'ajoutent aux cinq d'origine, en français et en anglais : `injection_forced_prefix`,
`injection_fake_history`, `injection_refusal_suppression`, `injection_payload_splitting`,
`injection_system_prompt_leak`, `injection_filter_disable`, `injection_role_labels` ; `injection_concealment` reçoit la
forme « cacher une action à l'utilisateur ». Origine des formes : UPSTREAM.md, « Règles du paquet injection ».

**Rappel d'arrivée** (`TestRecallCorpus`, relevé `injection/testdata/recall.json`) :

| Source | Étiquette de la source | Textes | Départ | Arrivée | Par règle à l'arrivée |
|---|---|---:|---:|---:|---|
| LLM Guard | injection | 49 | 21 (43 %) | 22 (45 %) | `instruction_override` 20, `role_switch` 1, `system_prompt_leak` 3 |
| LLM Guard | sain | 11 | 0 | 0 | |
| Promptfoo | gabarit de contournement | 106 | 25 (24 %) | 49 (46 %) | `instruction_override` 21, `role_switch` 4, `concealment` 1, `forced_prefix` 9, `refusal_suppression` 15, `filter_disable` 13 |
| Akto | charge de test LLM | 59 | 31 (53 %) | 32 (54 %) | `instruction_override` 31, `system_prompt_leak` 1, `filter_disable` 11 |
| Skill Scanner | consigne (`prompt_injection`) | 1 | 0 | 1 | `concealment` 1 |
| Skill Scanner | sain | 11 | 0 | 0 | |
| Skill Scanner | autre risque | 43 | 0 | 0 | |

Ce que cela dit, et ne dit pas :

- Le gain vient de trois familles : suppression du refus, préfixe imposé, désactivation des filtres. Le faux
  historique, le découpage et toutes les formes françaises n'ont **aucun gain mesuré** : ces corpus sont en anglais et
  n'en contiennent pas. Ces règles ne sont tenues que par les cas de `vectors/injection.json` (117 cas, dont 62
  positifs et 55 de bruit).
- Restent manqués : 27 textes de LLM Guard, 57 de Promptfoo, 27 d'Akto (identifiants dans le relevé). Chez Promptfoo ce
  sont surtout des gabarits de persona (« DAN », jeu de rôle, mode développeur) : ils visent un chatbot, et aucune règle
  ne les prend pour cible. Chez Akto, des demandes de code malveillant et des textes encodés deux fois.
- Aucun texte tenu pour sain par sa source n'est signalé (22 textes).

Les transformations de la Story 27.47 s'appliquent aux règles nouvelles : `TestPositiveCasesSurviveTransformations`
retrouve les 62 cas positifs du corpus dans les quatorze transformations (60 pour les deux formes de texte replié :
un faux historique dont on replie les lignes n'en est plus un). Pour cela la forme normalisée est lue aussi sans
dépliage : une règle définie par ses lignes (faux historique, étiquette en début de ligne) ne se retrouve que là.

**Critère de garde d'un motif.** Chaque motif nouveau est mesuré seul sur les 151 392 fichiers des 34 dépôts. Il est
gardé s'il signale au plus 75 fichiers en tout (0,05 %) et au plus 5 dans les 19 dépôts qui ne sont ni un cadre
d'agents, ni une collection de prompts, ni un outil d'équipe rouge. Seuils posés pour cette mesure ; ils se discutent.
Les motifs ont été mesurés un à un avant que les citations ne soient limitées à trois règles (voir plus bas) ; cette
limite ajoute un fichier au premier motif de suppression du refus (21 au lieu de 20, dans un dépôt d'agents) et ne
change aucune décision de garde.

| Motif nouveau | Fichiers | Dont hors dépôts d'agents | Gardé |
|---|---:|---:|---|
| Préfixe imposé, anglais | 38 | 2 | oui |
| Préfixe imposé, français | 0 | 0 | oui |
| Faux historique (trois tours en début de ligne) | 45 | 2 | oui |
| Suppression du refus : « never refuse / decline / apologize » | 21 | 1 | oui |
| Suppression du refus : « answer… without disclaimers » | 2 | 0 | oui |
| Suppression du refus : « do not include warnings » | 6 | 2 | oui |
| Suppression du refus, français (deux motifs) | 0 | 0 | oui |
| Découpage, anglais ; français | 1 ; 0 | 0 | oui |
| Message système : « reveal… your system prompt » | 46 | 0 | oui |
| Message système : « what are your instructions », « repeat everything above » | 8 ; 5 | 0 | oui |
| Message système, français (deux motifs) | 2 ; 0 | 0 | oui |
| Filtres : « disable… safety filters » | 43 | 0 | oui |
| Filtres : mode sans restriction ; « not bound by the content policy » | 1 ; 5 | 0 | oui |
| Filtres, français (deux motifs) | 3 ; 0 | 0 | oui |
| Étiquette « system: » suivie d'un ordre d'annulation | 2 | 0 | oui |
| Bloc « ```system » ; « --- » puis « system: » ; `</s>` | 20 ; 39 ; 32 | 0 | oui |
| Dissimulation : « hide this step from the user », anglais ; français | 0 ; 0 | 0 | oui |
| Message système, première forme (« show / print / return… the system prompt ») | 271 | 1 | non : resserrée à « your… » |
| Étiquette « system: you are… » | 146 | 0 | non |
| Balise `<system>` | 108 | 2 | non |
| Jetons de Llama 3 et de Gemma (`<\|start_header_id\|>`, `<start_of_turn>`…) | 332 | 0 | non |

Non mesurés et non retenus : les modes « debug », « developer » et « admin » (« enable debug mode » est une phrase
ordinaire de documentation) ; la forme large « hide… from users » (un seul fichier à la mesure, mais c'est une phrase
courante des documentations d'interface : la forme gardée exige un objet, action, étape ou instruction).

**Citations.** Une formule courte entre guillemets au milieu d'une phrase n'est plus signalée
(`injection/context.go`, contrôle écrit en Go : RE2 n'a pas d'assertion arrière). Cela ne vaut que pour trois règles :
`injection_instruction_override`, la formule la plus citée des documentations, et les deux règles de jetons de
modèles, `injection_message_markers` et `injection_role_labels`. Effet sur les 34 dépôts : 8 fichiers cessent d'être
signalés (6 pour `injection_instruction_override`, 2 pour `injection_message_markers`) et 2 ne le deviennent pas pour
`injection_role_labels` ; un fichier qui cite une formule en porte souvent d'autres, hors guillemets. Sur le corpus de
rappel, aucune consigne signalée ne cesse de l'être. Limite assumée : pour ces trois règles, une consigne écrite entre
guillemets au milieu d'une phrase passe.

Les neuf autres règles signalent une consigne citée comme une autre : un ordre d'envoyer des secrets ou de cacher une
action à l'utilisateur, signalé entre guillemets par la v0.9.0, le reste. Leur appliquer la citation aussi n'aurait
retiré qu'un fichier sur 151 392 (`injection_refusal_suppression`, dans un dépôt d'agents) : le bruit mesuré ne
justifie pas d'ouvrir ce passage.

**Faux positifs, par règle** (mêmes 151 392 fichiers) :

| Fichiers signalés | v0.9.0 | Lectures (27.47) | Règles et citations (27.48b) |
|---|---:|---:|---:|
| Tous | 464 (0,306 %) | 478 (0,316 %) | 663 (0,438 %) |
| `injection_instruction_override` | 280 | 288 | 282 |
| `injection_role_switch` | 42 | 42 | 42 |
| `injection_exfiltration` | 13 | 20 | 20 |
| `injection_concealment` | 16 | 16 | 16 |
| `injection_message_markers` | 153 | 153 | 151 |
| `injection_forced_prefix` | | | 38 |
| `injection_fake_history` | | | 45 |
| `injection_refusal_suppression` | | | 26 |
| `injection_payload_splitting` | | | 1 |
| `injection_system_prompt_leak` | | | 53 |
| `injection_filter_disable` | | | 51 |
| `injection_role_labels` | | | 92 |

Depuis la v0.9.0, 207 fichiers sont nouvellement signalés et 8 cessent de l'être. 190 de ces 207 sont dans les 15
dépôts d'agents et de prompts, où ce sont des consignes employées pour de bon (prompts d'application, gabarits de
conversation, jeux d'essai d'équipe rouge) ; 17 sont dans les 19 autres dépôts, qui passent de 37 fichiers signalés à
54. Un Groupe qui développe des applications à base de modèles de langage verra donc ces règles plus souvent qu'un
autre ; « avertir » reste la décision prudente.

**Durée, état final** (46 motifs, toutes les lectures ; mêmes commande et texte de banc que plus haut, les deux séries
l'une après l'autre, charge moyenne de 32 à 38 : durées indicatives, plus hautes que celles du tableau précédent pour
la seule raison de la charge) :

| Taille | Texte | Avant (v0.9.0) | État final | Gain |
|---|---|---:|---:|---:|
| 2 Kio | propre | 1,72 ms | 0,21 ms | ×8 |
| 16 Kio | propre | 18,3 ms | 1,69 ms | ×11 |
| **64 Kio** | **propre** | **75,6 ms** | **8,17 ms** | **×9** |
| 64 Kio | consignes | 90,2 ms | 7,21 ms | ×12 |
| 64 Kio | prose repliée | 74,5 ms | 9,33 ms | ×8 |

La mesure entière des 34 dépôts prend 67 à 75 s de processeur à l'état final (865 s avant, 52 s avec les seules
lectures).

Pire cas d'une lecture : « send token @ » répété sur 1 Mio, où la porte du motif d'exfiltration s'ouvre à chaque mot,
prend 3,3 s (charge moyenne de 26) à 5,8 s (charge de 58) ; c'est l'ordre de grandeur du pire cas de la v0.9.0 (« send
token » répété : 2,7 s). `TestWorstCasesAreLinear` le garde à un quart de cette taille, et les autres entrées de
1 Mio, une contre chaque lecture, prennent moins de 0,3 s.

Pire cas connu, toutes lectures : le même texte écrit avec des espaces insécables, un pourcentage à chaque mot et une
fin de ligne de loin en loin. Chaque lecture (texte reçu, normalisé, décodé, décodé puis normalisé, et leurs formes
dépliées) est alors un texte différent, relu en entier : 3,5 fois la durée par octet du pire cas d'une lecture à la
relecture du 15 novembre (0,87 s pour 128 Kio contre 0,49 s pour 256 Kio, charge moyenne de 8 à 17), soit de l'ordre
de 7 s pour 1 Mio sur la même machine. La durée reste linéaire, mais ce pire cas est plus long que celui de la
v0.9.0 : un appelant qui a un budget de durée doit le faire respecter lui-même et tenir un dépassement pour un texte
non lu. `TestWorstCasesAreLinear` garde ce cas à un seizième de la borne.

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

Au dernier commit du lot, trois paires alternées du banc séquentiel (25 passes chacune), toujours sous charge :
82,6 ms, 113,1 ms et 129,3 ms avant ; 66,4 ms, 98,1 ms et 101,0 ms après.

Lecture honnête : aucun écart mesurable, mais la dispersion sous charge est plus grande que l'écart cherché. Le banc
séquentiel, moins sensible au nombre de cœurs libres, donne la même médiane à 0,2 ms près dans la première série. À
refaire sur une machine calme avant l'étiquette de version.

Relecture du lot, même jour, machine toujours chargée (charge moyenne au-delà de 100) : le temps écoulé ne dit rien, la
mesure retenue est le nombre d'instructions exécutées par le processus du banc, peu sensible à la charge
(`/usr/bin/time -l`, binaires de `go test -c` du moteur v0.9.0 et du moteur relu, `-test.benchtime=40x`, passes
alternées) :

| Banc | v0.9.0 | Ce lot, relu | Écart |
|---|---|---|---|
| `BenchmarkScanSequential` (un fil), 5 paires | 67,33 à 67,56 milliards (moyenne 67,45) | 67,62 à 67,92 milliards (moyenne 67,70) | + 0,4 % |
| `BenchmarkScan64KiB`, 3 paires | 36,56 à 38,41 milliards | 36,78 à 38,88 milliards | séries qui se recouvrent |

Sur le banc à un fil, le lot exécute 0,4 % d'instructions de plus que le moteur v0.9.0 : l'écart existe, il est petit.
Le temps écoulé reste à mesurer sur une machine calme avant l'étiquette de version.
