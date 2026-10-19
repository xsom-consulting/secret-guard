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
