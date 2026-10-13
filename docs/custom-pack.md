# Pack de règles du client — contrat (v1)

Un Pack de règles du client ajoute aux règles intégrées de Secret Guard des détecteurs propres à un client : identifiants internes, numéros d'un format maison, noms de code de projets. **L'émetteur** (celui qui distribue les Packs) compose, valide, signe et distribue un Pack propre à un client ; **le moteur** (paquet Go `custom`, ce dépôt) le juge et l'applique localement, sans réseau ni modèle de langage sur le chemin de détection.

Sources normatives, dans cet ordre : ce document, `schema/CustomPack.json` (JSON Schema), puis les vecteurs `vectors/custom/` (résultats du moteur TypeScript d'origine, `UPSTREAM.md`). Le contrat est figé en v1 : une évolution change `schemaVersion` et ajoute des vecteurs, elle ne modifie pas les existants. Les sections 1 à 7 gardent la numérotation du contrat d'origine.

## 1. Forme transportée

```json
{ "payload": { …Pack… }, "keyId": "<sha256 hex de la clé publique brute>", "signature": "<base64 Ed25519>" }
```

- **Forme canonique** de `payload` : JSON UTF-8, clés d'objet triées, aucune espace, caractères non ASCII écrits tels quels (équivalent de `JSON.stringify` à clés triées et de `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`). Aucun nombre à virgule n'existe dans le Pack.
- **Signature** : Ed25519 sur les octets de la forme canonique. **`keyId`** : SHA-256 hexadécimal de la clé publique Ed25519 brute (32 octets). **Empreinte du Pack** (`payloadDigest`) : SHA-256 hexadécimal de la forme canonique.

La signature n'est pas l'affaire du moteur : le programme qui reçoit l'enveloppe cherche `keyId` dans ses clés d'autorité (jamais une clé fournie par l'enveloppe), vérifie la signature, puis passe les octets de `payload` à `custom.Compile`. Un programme sans clé d'autorité refuse tout Pack.

## 2. Validité d'un Pack

Un Pack est valide si et seulement si, dans cet ordre (code du refus entre parenthèses) :

1. il respecte `schema/CustomPack.json` (`schema`) ;
2. les `id` de détecteurs sont uniques (`duplicate_detector`) ;
3. `expiresAt` est strictement postérieur à `issuedAt` (`validity_window`), comparaison des chaînes `AAAA-MM-JJTHH:MM:SSZ` ;
4. le total des condensats de tous les détecteurs `terms` est ≤ 20 000 (`too_many_digests`) ;
5. chaque motif est valide selon le §3, compte tenu de la présence de `context` (`invalid_pattern`) ;
6. chaque essai positif nomme un détecteur existant (`unknown_test_detector`) ;
7. chaque détecteur `pattern` a au moins un essai positif (`missing_positive`). Un détecteur `terms` n'en exige pas : un positif révélerait un terme confidentiel en clair ;
8. chaque positif produit au moins une détection de **son** détecteur (`positive_not_detected`) ;
9. aucun négatif ne produit de détection d'**aucun** détecteur du Pack (`negative_detected`).

Le moteur ajoute un code : `self_test_incomplete`, un essai qui dépasse son budget de travail (2 000 000 unités par texte, 150 000 000 pour tous les essais d'un Pack) ; la validité n'a pas pu être établie en un temps borné.

L'émetteur refuse de signer un Pack invalide ; le moteur refuse de charger un Pack invalide, même correctement signé. Un Pack ne fait qu'**ajouter** des détections : il ne désactive, n'affaiblit ni ne remplace aucune règle intégrée.

## 3. Grammaire des motifs (`match.type = "pattern"`)

Sous-ensemble sûr d'expressions régulières, en ASCII imprimable (0x20–0x7E) uniquement, 256 caractères au plus.

```
motif       := alternative ('|' alternative)*
alternative := terme+                      (vide interdit : empty_alternative)
terme       := atome quantificateur?
atome       := littéral | échappement | classe | groupe
groupe      := '(?:' motif ')'             (profondeur de groupes ≤ 4 : too_deep)
classe      := '[' élément+ ']'            (vide : empty_class ; '[^' : negated_class)
élément     := car ('-' car)? | '\d' | '\w' | '\s'
quantificateur := '?' | '{' n '}' | '{' n ',' m '}'
n, m        := 0 | [1-9][0-9]{0,2}         avec 1 ≤ m ≤ 64, n ≤ m ; '{n}' exige n ≥ 1
```

- **Littéral** : tout caractère ASCII imprimable sauf `\ ^ $ . | ? * + ( ) [ ] { }`.
- **Échappement** : `\` suivi de l'un de `\ ^ $ . | ? * + ( ) [ ] { } - /` (littéral), ou `\d` = `[0-9]`, `\w` = `[A-Za-z0-9_]`, `\s` = `[ \t\n\r\f\v]`. Ces classes sont **ASCII uniquement** (en JavaScript, `\s` natif accepte l'espace insécable ; c'est faux ici). Tout autre échappement est refusé (`bad_escape` : `\b`, `\n`, `\x41`, `\1`, `\D`, `\p{…}`…).
- **Dans une classe** : `[`, `-` et `^` doivent être échappés, sauf `-` entre deux bornes d'un intervalle (`bad_class_char`) ; un intervalle est croissant (`bad_range`) ; les autres métacaractères y sont littéraux.
- **Interdits** : `.` (`dot_not_allowed`), `^`/`$` (`anchor_not_allowed`), groupes capturants, nommés ou assertions (`group_not_allowed`), `*`, `+`, `{n,}` (`unbounded_quantifier`), quantificateur sans atome (`dangling_quantifier`) ou suivi d'un autre, y compris paresseux (`stacked_quantifier`), borne hors limites ou mal écrite (`bad_quantifier`), classe ou groupe non fermés (`unbalanced_class`, `unbalanced_group`), `]` ou `}` isolés (`bad_literal`), caractère hors ASCII imprimable (`invalid_character`), longueur (`length`).
- **Répétition imbriquée** : un groupe quantifié avec une borne haute > 1 ne peut contenir ni quantificateur ni alternative (`nested_repetition`). `(?:…)?` peut en contenir.
- **Longueurs** : longueur minimale d'une correspondance ≥ 3 (`too_short`), maximale ≤ 256 (`too_long`), calculées sur l'arbre.
- **Ancre** : le motif doit contenir, au premier niveau (hors groupe, hors alternative), une suite d'au moins 3 littéraux consécutifs non quantifiés ; sinon le détecteur doit porter un `context` (`no_anchor`). Cette ancre ou les mots-clés du contexte servent de préfiltre littéral.

Ordre des contrôles, pour les codes d'erreur : longueur et caractères, puis syntaxe de gauche à droite (dont `nested_repetition` au moment où le quantificateur du groupe est lu), puis `too_short`, `too_long`, `no_anchor`.

## 4. Sémantique de détection

Une détection est une étendue du texte, jamais son contenu.

**`pattern`** — toutes les correspondances **les plus à gauche, premier choix d'abord** (sémantique d'ECMAScript, pas « la plus longue »), sans chevauchement, parcourues sur tout le texte : ce que rend `matchAll` sans drapeau `u`. `caseInsensitive` ne replie que les lettres ASCII. Puis, pour chaque correspondance :

- si `minEntropyTenths` est présent, elle est gardée si son entropie de Shannon, en bits par caractère, est ≥ `minEntropyTenths / 10` ;
- si `context` est présent, elle est gardée si l'un des mots-clés apparaît, en comparaison insensible à la casse ASCII seulement, **entièrement** dans la fenêtre `[début − window, fin + window)`, bornée au texte, comptée en **points de code**.

**`terms`** — le Pack ne contient que des condensats, jamais les termes :

- un **mot** est une suite maximale de points de code de catégorie Unicode L, N ou M ; tout autre caractère (espace, ponctuation, `_`, `-`…) sépare ;
- **normalisation d'un mot** : NFKD, suppression des marques (catégorie M), minuscules Unicode par défaut (`toLowerCase` de JavaScript, sigma final compris) ; un mot devenu vide est ignoré ;
- pour chaque mot et chaque longueur `k` de 1 à `maxWords`, le n-gramme est la jonction par une espace des `k` mots normalisés consécutifs ; il correspond si `hex(SHA-256(sel ‖ UTF-8(n-gramme)))` figure dans `digests` (`sel` = octets décodés de `salt`) ;
- candidats filtrés par `context` s'il existe, puis triés par début croissant et, à début égal, par longueur décroissante ; chaque candidat qui ne chevauche pas le précédent retenu est gardé.

Le condensat d'un terme se calcule sur sa forme normalisée (mots normalisés joints par une espace). Chez le client, `secret-guard terms digest --salt <sel> [fichier|-]` le calcule pour une liste de termes, un par ligne : seuls les condensats sortent, jamais un terme.

## 5. Obligations du moteur et de son intégrateur

- L'intégrateur vérifie la signature avec une clé d'autorité (§1) avant `custom.Compile`, refuse un Pack dont `tenantId` diffère du client enrôlé, et n'accepte jamais une `version` inférieure à la plus haute déjà acceptée pour le même `packId` (anti-retour).
- Un Pack expiré reste appliqué (il n'ajoute que des protections) ; l'intégrateur le signale. Un Pack refusé ou absent laisse les règles intégrées intactes.
- Temps borné : préfiltre littéral et budget de travail par analyse (§ « Exécution par le moteur Go ») ; un budget dépassé donne une analyse incomplète (`custom_budget`), jamais un passage.
- Ni journal ni résultat ne porte la valeur détectée : l'identifiant du détecteur (et son libellé, lu dans le Pack) suffit à l'interface et à l'audit.

## 6. Obligations de l'émetteur

- Seul l'émetteur compose et signe ; le client lit son réglage, il ne le modifie pas. La clé privée de signature ne quitte pas l'émetteur et n'entre dans aucun dépôt ni journal.
- Les termes confidentiels saisis en clair ne servent qu'au calcul des condensats et à la vérification qu'ils sont tous détectés, puis sont oubliés. Le client peut calculer lui-même les condensats (`secret-guard terms digest`) pour que les termes ne quittent jamais ses postes.
- Versions strictement croissantes par client et `packId` ; chaque publication est tracée (métadonnées et empreinte, pas de contenu).

## 7. Distribution et posture

La distribution des Packs et l'état rapporté par un poste sont définis par le programme qui distribue les Packs, hors de ce dépôt. Le moteur offre ce qu'il faut pour les rapporter sans contenu : `PackID`, `Version`, `ExpiresAt`, `TenantID` du Pack chargé, identifiants des détecteurs qui ont détecté (constats `xsom_<id>`).

## Exécution par le moteur Go

```go
p, err := custom.Compile(charge)                                  // §2 ; refus *custom.PackError (Code)
result := detect.Scan(content, rules, detect.Options{Custom: p})  // détections ajoutées aux constats intégrés
```

- **Constats** : chaque détection devient un `detect.Finding` : `RuleID` = `xsom_` + identifiant du détecteur, `SecretType` = `custom_rule`, `Encoding` = `plain`, `Score` = 90 (`block`) ou 40 (`warn`), niveau déduit du score, étendue en octets. Jamais la valeur. Les constats sont triés par étendue ; à étendue égale, les constats intégrés d'abord.
- **Texte visible** : si le contenu contient des caractères ignorables par défaut (trait d'union conditionnel, espace sans chasse…), le Pack est aussi appliqué au texte sans eux, positions ramenées au contenu, doublons retirés.
- **Issues** (`detect.Failure`) : `custom_budget` (budget de 120 000 000 unités épuisé), `custom_too_many` (plus de détections que `MaxFindings` moins les constats intégrés). Une analyse incomplète n'a aucun constat.
- **Motifs** : validés en arbre avec les codes du §3, puis traduits en RE2 (`regexp` de Go, temps linéaire, aucun retour arrière). Chaque classe devient une classe explicite d'octets ASCII ; `caseInsensitive` replie seulement les lettres ASCII (jamais `(?i)` de RE2, qui replie aussi K, ſ et le signe kelvin) ; un groupe optionnel dont le contenu peut être vide est réécrit en l'alternative ordonnée de ses seuls chemins non vides, car ECMAScript refuse l'itération vide d'un quantificateur de minimum 0 (`(?:a?|b)?` reconnaît « b » en ECMAScript, rien en RE2 tel quel).
- **Recherche** : seuls les débuts possibles sont essayés (intervalles autour de l'ancre, ou tout le texte si un mot-clé du contexte y figure), réduits aux octets qui peuvent commencer une correspondance ; chaque début ouvre une fenêtre de la longueur maximale du motif, les fenêtres qui se chevauchent sont fusionnées et RE2 y cherche les correspondances successives. Deux détecteurs de même motif partagent leurs correspondances.
- **Budget** : une unité est un test de caractère, une compression SHA-256 en vaut 80. Le coût des mots, n-grammes, minuscules, contextes, entropie, recherche de l'ancre et texte visible est celui de l'origine, au pas près (les cas de budget des termes des vecteurs tombent au même mot). La recherche d'un motif compte une unité par position examinée, puis, par fenêtre, sa longueur en octets fois le nombre d'états du motif traduit (borne du travail de RE2), avant la recherche : le résultat est le même que celui de l'origine, mais le seuil où le budget s'épuise diffère (écart déclaré `backtracking_budget` dans `UPSTREAM.md`).
- **Lecture du Pack** : octets du document, JSON strict (UTF-8 valide, aucun membre en double, aucun substitut isolé, rien après le document), 16 Mio au plus ; nombres jugés comme des nombres JavaScript (`1.0`, `1e0` et `-0` sont des entiers).
- **Termes chez le client** : `custom.DecodeSalt`, `custom.DigestTerm`, `custom.NormalizeTerm`, `custom.TermDigest`, et `secret-guard terms digest`.

Écarts avec le moteur d'origine, chacun déclaré dans les vecteurs et vérifié par les tests Go : voir `UPSTREAM.md`, section « Règles du client ».
