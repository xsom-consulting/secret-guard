# Secret Guard, Betterleaks, Gitleaks : comparaison chiffrée

> **Brouillon du 15 novembre 2026, non relu.** Cette page réunit des chiffres déjà présents dans le dépôt. Elle n'est
> liée depuis aucune autre page ; sa publication (site, README) est une décision du mainteneur.

Betterleaks et Gitleaks cherchent des secrets dans des dépôts de code. Secret Guard est un moteur embarqué : il juge un
texte avant qu'il ne parte vers un assistant, sur le poste, sans réseau. Les trois outils ne répondent donc pas au même
besoin, et cette page ne classe personne. Elle dit ce qui a été mesuré, sur quoi, et où trouver le chiffre.

## Règles de lecture

- **« Mesuré »** : un essai ou un outil de ce dépôt donne le chiffre, et le fichier cité permet de le rejouer.
- **« Lu »** : relevé dans le code de l'autre outil, à un commit nommé, sans l'exécuter. Un relevé de lecture peut être
  faux ; il reste à confirmer par une exécution.
- Betterleaks : dépôt `betterleaks/betterleaks`, commit `b4b1c44`, licence MIT. Gitleaks : dépôt `gitleaks/gitleaks`,
  commit `5f6ec56`, licence MIT. Secret Guard : v0.10.0, Pack initial de 426 règles (`pack/initial/pack.json`).
- Aucun des deux outils n'a été exécuté pour cette page. Aucune vitesse n'est comparée.

## 1. Les cas d'essai de Betterleaks, rejoués par Secret Guard

Mesuré. `vectors/comparison/betterleaks.json` (généré en local par `node corpus/betterleaks.ts --clone <clone>` depuis `generator/`, ignoré par git : ses valeurs d'essai ont la forme de vraies clés, que la protection de GitHub refuse) reprend les 1 880 cas d'essai littéraux des règles de Betterleaks
(464 règles), dont 867 positifs. `TestComparisonBetterleaks` (`detect/comparison_test.go`) y applique les règles que
`LoadRules` exécute, et échoue si un chiffre recule.

| Sur les 867 positifs de Betterleaks | v0.9.0 | v0.10.0 |
|---|---:|---:|
| Un constat recouvre la valeur attendue | 818 (94,3 %) | 823 (94,9 %) |
| … par une règle dédiée (ni affectation, ni entropie) | 397 (45,8 %) | 554 (63,9 %) |
| … par un constat que le préréglage bloque | 725 (83,6 %) | 772 (89,0 %) |

Ce que ce tableau ne dit pas :

- 44 positifs sont manqués. Trois le sont à dessein (un jeton public Mapbox, deux clés de projet PostHog, publics par
  nature) ; les 41 autres sont listés par famille dans UPSTREAM.md, « Banc de comparaison Betterleaks ».
- C'est leur corpus, écrit pour leurs règles : il ne mesure pas ce que Betterleaks manquerait sur le nôtre. Le sens
  inverse (nos 1 991 cas rejoués par Betterleaks) n'a pas été mesuré.
- Les 82 cas « composant » (identifiant de client, nom d'utilisateur) ne sont pas comptés.

Rejouer : `go test -count=1 -v -run '^TestComparisonBetterleaks$' ./detect`.

## 2. Bruit sur du code ordinaire

Mesuré, pour Secret Guard seul. Le banc `tools/bruit` compte les constats du moteur sur cinq dépôts lus à un commit
épinglé, sans langage (`tools/bruit/rapport.json`, méthode dans `docs/bench.md`, « Bruit sur du code »). Ce n'est pas un
taux de faux positifs : personne n'a trié ces constats un à un, et deux de ces dépôts sont des détecteurs de secrets
qui portent des jetons d'essai voulus.

| Dépôt (commit) | Fichiers | Constats, v0.9.0 | Constats, rapport commité | Analyses incomplètes |
|---|---:|---:|---:|---:|
| xSOM Fleet (`77fded7`) | 4 614 | 1 959 | 1 462 | 1 |
| LiteLLM (`09ce4f5`, 2 500 fichiers tirés) | 2 500 | 7 071 | 7 026 | 15 |
| Promptfoo (`5fac53e`, 2 500 fichiers tirés) | 2 500 | 4 145 | 4 138 | 3 |
| ggshield (`f3377d9`) | 568 | 699 | 698 | 0 |
| Gitleaks (`5f6ec56`) | 225 | 584 | 579 | 2 |

Le rapport commité date de la correction de l'entropie (345 règles). Il n'a pas été relancé depuis les filtres du code
ordinaire, les règles reprises, le décodage à plusieurs couches et les identifiants européens : **à relancer avant
toute publication** (`go run ./tools/bruit <nom>=<chemin>…`).

Constats d'affectation seuls, mesurés à part sur les mêmes dépôts (UPSTREAM.md, « Code ordinaire », mesures du
15 novembre 2026) :

| Dépôt | Fichiers | v0.9.0, sans langage | v0.10.0, sans langage | v0.9.0, avec langage | v0.10.0, avec langage |
|---|---:|---:|---:|---:|---:|
| xSOM Fleet | 4 648 | 896 | 354 | 844 | 186 |
| Promptfoo | 2 498 | 2 933 | 2 456 | 2 788 | 425 |
| LiteLLM | 2 496 | 6 022 | 5 110 | 5 793 | 766 |
| ggshield | 568 | 471 | 286 | 459 | 119 |
| Gitleaks | 225 | 171 | 145 | 173 | 76 |

Betterleaks et Gitleaks n'ont pas été lancés sur ces dépôts : il n'y a pas de chiffre de bruit à mettre en face. Le
bruit de Secret Guard sans langage reste élevé sur du code ; c'est avec le langage du fichier, ou celui d'un bloc de
code dans un prompt, que les filtres agissent.

## 3. Consignes adressées à un agent

Mesuré, pour Secret Guard seul. Le paquet `injection` relève les phrases écrites pour l'agent dans un texte lu.
`TestRecallCorpus` l'applique à 280 textes publics (`vectors/injection-recall.json`, sources et licences dans
UPSTREAM.md) et compare au relevé commité `injection/testdata/recall.json`.

| Source | Étiquette de la source | Textes | Signalés, v0.9.0 | Signalés, v0.10.0 |
|---|---|---:|---:|---:|
| LLM Guard | injection | 49 | 21 (43 %) | 22 (45 %) |
| Promptfoo | gabarit de contournement | 106 | 25 (24 %) | 49 (46 %) |
| Akto | charge de test LLM | 59 | 31 (53 %) | 32 (54 %) |
| Skill Scanner | consigne | 1 | 0 | 1 |
| LLM Guard, Skill Scanner | sain | 22 | 0 | 0 |

Plus de la moitié des consignes de ces corpus ne sont pas signalées. Ils visent un chatbot (gabarits de persona, jeu de
rôle), pas une consigne glissée dans un fichier lu par un agent de code, qui est le périmètre du paquet ; le détail est
dans `docs/bench.md`, « consignes adressées à l'agent ». Lu : ni Betterleaks ni Gitleaks n'ont de règle de cette nature.

## 4. Secrets encodés

Mesuré pour Secret Guard : 21 écritures d'un même jeton (`docs/encodages.md`, vecteurs
`vectors/detection/views-encodings.json`).

| Sur 21 écritures | v0.9.0 | v0.10.0 |
|---|---:|---:|
| Lues par la règle du jeton | 7 | 12 |
| Avertissement d'entropie seul | 6 | 5 |
| Aucun constat | 8 | 4 |

Lu, non exécuté : Betterleaks et Gitleaks partagent un décodeur à quatre encodages (pourcentage, échappements Unicode,
hexadécimal, base64), répété jusqu'à une profondeur de 5 par défaut. D'après leur code, ils lisent l'hexadécimal, que
Secret Guard ne lit pas. Aucun budget d'octets ni de tentatives n'y a été relevé. Secret Guard lit en plus les fichiers
UTF-16, les caractères invisibles intercalés et un jeton coupé par un retour à la ligne, dans des budgets fixes
(128 décodages, 262 144 octets décodés, trois couches) dont l'épuisement rend l'analyse incomplète.

## 5. Ce que le moteur rend, et ne rend pas

| Sujet | Secret Guard (mesuré ou lu dans ce dépôt) | Betterleaks et Gitleaks (lu) |
|---|---|---|
| Valeur détectée dans le résultat | jamais : règle, type, score, étendue en octets (`detect/result.go`) | le constat porte la valeur et son contexte ; masquage du rapport en option |
| Analyse qui ne va pas au bout | issue typée, sans constat partiel, à traiter comme un blocage (`detect/result.go`) | une annulation rend les constats déjà trouvés |
| Travail borné | 1 Mio d'entrée, 2 048 constats, budgets de décodage et de vues (`internal/limits/limits.go`, `detect/encoding.go`) | profondeur de décodage |
| Réseau | aucun import réseau dans le moteur, contrôlé par `go run ./tools/depguardcheck` | validation du secret par appel au fournisseur, sur option |
| Exclusion écrite dans le texte analysé | aucune | marqueur d'exclusion sur la ligne |
| Règles | Pack fermé (chaînes et entiers), décodage strict (`docs/rule-pack.md`) | fichier TOML ; chez Betterleaks, langage d'expressions exécuté à l'analyse |
| Texte rendu sans secret | masquage puis nouvelle analyse, Substituts typés (`README.md`) | masquage du rapport |
| WebAssembly | module WASI, mêmes vecteurs que le moteur Go (`wasm/parity.test.mjs`) | aucun relevé |
| Données personnelles | IBAN, identifiants français et européens à clé de contrôle (`docs/rule-pack.md`) | aucune règle relevée |
| Dépendances directes du module | 1 (`go.mod`) | 23 (Betterleaks), 14 (Gitleaks) |

## 6. Là où ils font mieux

- **Nombre de règles et rythme d'ajout.** Lu : 476 règles chez Betterleaks, 222 chez Gitleaks, contre 426 ici, dont
  66 reprises de Betterleaks dans cette version (UPSTREAM.md, « Règles reprises de Betterleaks »).
- **Décodage en profondeur**, hexadécimal compris (section 4).
- **Filtres de faux positifs mûris sur des années de dépôts publics.** Notre bruit sur du code sans langage reste
  élevé (section 2).
- **Validation du secret** auprès du fournisseur. Secret Guard ne le fera pas dans le moteur, qui n'ouvre aucune
  connexion.
- **Analyse d'un historique git entier**, leur métier d'origine. Secret Guard juge un texte, pas un dépôt.

## Limites de cette page

- Une seule machine, un seul jour, un commit par dépôt.
- Aucun chiffre ne vient d'une exécution de Betterleaks ou de Gitleaks : tout ce qui les concerne est lu.
- Le rappel est mesuré sur des cas d'essai et des textes publics, pas sur des fuites réelles.
- Le banc de bruit n'a pas été relancé sur la v0.10.0 complète (section 2).
- Un taux mesuré ne dit pas ce que fera un texte écrit autrement, et l'absence de constat n'est pas une preuve.
