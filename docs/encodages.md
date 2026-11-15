# Ce que le moteur voit : matrice d'encodages

Relevé du 15 novembre 2026, moteur v0.10.0 (Pack initial de 426 règles). Un même jeton synthétique, de la forme d'un
jeton GitHub, est écrit en clair puis sous vingt écritures qu'un texte collé ou un fichier peut lui donner. Le tableau
dit ce que l'analyse rend pour chacune, y compris ce que le moteur ne voit pas encore.

Ce sont des relevés sur 21 textes, pas une promesse : une écriture absente de ce tableau n'a pas été essayée, et
l'absence de constat n'est jamais une preuve qu'un texte ne porte rien.

## D'où viennent ces lignes

- Les 21 cas sont des vecteurs du corpus de parité : `vectors/detection/views-encodings.json`, écrits par
  `generator/corpus/encodings.ts`. Ils sont rejoués à chaque version par `TestParity` (moteur Go) et par
  `wasm/parity.test.mjs` (module WebAssembly), qui lisent tous les fichiers du manifeste.
- Le résultat attendu de 16 cas vient du moteur d'origine. Celui des 5 cas que la v0.10.0 lit en plus (lignes 3 à 7)
  vient d'une seconde écriture du générateur, qui décode le texte elle-même et fait juger le texte clair par le moteur
  d'origine (UPSTREAM.md, « Décodage à plusieurs couches et vue UTF-16 »).
- Rejouer : `go test -count=1 -v -run '^TestParity$' ./detect`. Régénérer :
  `npm run vectors:detection -- --upstream <checkout>` dans `generator/`.

## Le tableau

Lecture des colonnes : « règle » veut dire que la règle du jeton (`github_token`) le signale ; « entropie seule », que
seul l'avertissement `high_entropy` (score 35, niveau MEDIUM) relève une suite de caractères sans savoir ce qu'elle
est ; « rien », que l'analyse est complète et sans constat. Le champ `encoding` du constat est donné entre parenthèses.

| N° | Écriture du jeton | v0.10.0 | Score, niveau | v0.9.0 |
|---:|---|---|---|---|
| 1 | En clair, dans une affectation d'environnement | règle (`plain`) | 95, CRITICAL | règle |
| 2 | Base64, une couche | règle (`base64`) | 90, CRITICAL | règle |
| 3 | Base64 de base64 (deux couches) | règle (`base64`) | 85, CRITICAL | entropie seule |
| 4 | Fichier UTF-16 petit-boutien, avec marque d'ordre | règle (`normalized`) | 95, CRITICAL | rien |
| 5 | Fichier UTF-16 petit-boutien, sans marque | règle (`normalized`) | 95, CRITICAL | rien |
| 6 | Fichier UTF-16 gros-boutien, avec marque d'ordre | règle (`normalized`) | 95, CRITICAL | rien |
| 7 | Commande PowerShell encodée (base64 d'UTF-16) | règle (`base64`) | 90, CRITICAL | rien |
| 8 | Hexadécimal continu | entropie seule | 35, MEDIUM | entropie seule |
| 9 | Échappements à deux chiffres (`\xNN`) | **rien** | | rien |
| 10 | Échappements à quatre chiffres (`\uXXXX`, JSON) | règle (`json-escaped`) | 90, CRITICAL | règle |
| 11 | Échappements entre accolades (`\u{X}`) | **rien** | | rien |
| 12 | Entités HTML hexadécimales (`&#xNN;`) | **rien** | | rien |
| 13 | Entités HTML décimales (`&#NN;`) | **rien** | | rien |
| 14 | Encodage pourcentage (URL) | règle (`percent`) | 90, CRITICAL | règle |
| 15 | Jeton coupé par un retour à la ligne | règle (`whitespace-joined`) | 90, CRITICAL | règle |
| 16 | Base32 | entropie seule | 35, MEDIUM | entropie seule |
| 17 | Deux chaînes concaténées (`"…" + "…"`) | entropie seule | 35, MEDIUM | entropie seule |
| 18 | Caractère de largeur nulle intercalé | règle (`normalized`) | 95, CRITICAL | règle |
| 19 | Jeton écrit à l'envers | entropie seule | 35, MEDIUM | entropie seule |
| 20 | Archive gzip, puis base64 | entropie seule | 35, MEDIUM | entropie seule |
| 21 | Jeton seul dans une phrase | règle (`plain`) | 95, CRITICAL | règle |

Bilan de la v0.10.0 : 12 écritures sur 21 sont lues par la règle du jeton, 5 ne laissent que l'avertissement
d'entropie, 4 ne donnent aucun constat. La colonne v0.9.0 est un relevé du même jour sur le binaire de la v0.9.0, avec
un jeton de même forme : 7 écritures lues par la règle, 6 à l'entropie seule, 8 sans constat (la ligne 21 n'a pas été
relevée ce jour-là : elle est lue par la même règle que la ligne 1, sans décodage). Cette colonne n'est pas rejouée par
un essai du dépôt.

## Ce que le moteur ne voit pas encore

- **Hexadécimal** (ligne 8) : il n'y a pas de vue hexadécimale. Une suite hexadécimale longue reste un avertissement
  d'entropie ; la règle du jeton ne la lit pas. Non retenue dans la v0.10.0.
- **Échappements à deux chiffres et entre accolades, entités HTML** (lignes 9, 11, 12, 13) : la vue des échappements
  ne connaît que la forme à quatre chiffres. Ces quatre écritures ne donnent aucun constat, pas même d'entropie :
  chaque caractère y est séparé du suivant par une barre oblique, une esperluette ou un point-virgule.
- **Base32, chaînes concaténées, jeton à l'envers, archive compressée** (lignes 16, 17, 19, 20) : aucune lecture
  prévue. L'avertissement d'entropie reste, au niveau MEDIUM.
- **Au-delà de trois couches** d'un même encodage : une quatrième couche de base64 n'est pas décodée, et l'analyse reste
  complète (`maxDecodeLayers`, `detect/encoding.go`).
- **UTF-16 sans marque d'ordre fait surtout de caractères hors Latin-1**, passage UTF-16 au milieu d'un fichier d'un
  autre encodage, UTF-32 : non lus (UPSTREAM.md, « Vue UTF-16 »).
- **Une seule valeur.** Les 21 cas portent un jeton à préfixe fixe. Un mot de passe dans une affectation n'a pas la
  même lecture sous chaque encodage, et n'a pas encore ses vecteurs ici. Les condensats (un secret haché) et le mot de
  passe banal rétrogradé ne sont pas dans la v0.10.0.

## Ce qui borne le travail

Chaque décodage est compté : 128 décodages et 262 144 octets décodés par analyse, 16 Mio de vues, trois couches par
encodage. Un budget épuisé rend l'analyse incomplète, ce qui vaut blocage, jamais un candidat ignoré en silence
(`detect/encoding.go`, `detect/views.go`). Chaque couche décodée retire 5 points au score : c'est l'écart entre les
lignes 2 et 3.
