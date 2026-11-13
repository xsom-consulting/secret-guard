# Secret Guard

[Français](#français) · [English](#english)

## Français

Secret Guard est un moteur de détection de secrets (clés d'API, jetons, clés privées, mots de passe, URL à identifiants…) dans un texte, écrit en Go. Il analyse localement, dans le processus qui l'appelle : c'est la brique qui lit un prompt ou un fichier avant qu'il ne parte vers un assistant de code, et ce dépôt est public pour que chacun puisse le vérifier.

C'est le portage en Go du moteur TypeScript de Secret Guard (origine, licence et modifications : [UPSTREAM.md](UPSTREAM.md)). Le portage rend exactement les résultats de l'original sur un corpus figé de 823 cas (`TestParity`) ; depuis la v0.7.0, le corpus compte 80 cas de plus pour les règles de données personnelles, qui n'existent pas dans l'original (voir « Données personnelles »), et depuis la v0.8.1 27 cas du mot de passe annoncé dans une phrase (voir cette section).

Deux paquets l'accompagnent, portés de la même origine : `hidden` (instructions cachées dans un texte) et `mentions` (fichiers cités par « @ » dans un prompt).

### Ce que fait le moteur

- 40 règles (Pack initial, `pack/initial/pack.json`) : les 35 du catalogue d'origine (formats fixes de jetons connus, clés privées PEM, URL à identifiants, affectations sensibles (`password = …`, en-têtes, cookies, `curl -u`, `auth` de Docker), entropie) et, depuis la v0.7.0, 5 règles de données personnelles à clé de contrôle (IBAN, numéro de sécurité sociale, SIRET, SIREN, carte bancaire).
- Plusieurs lectures du même texte : telle quelle, normalisée (NFKC, caractères invisibles retirés), décodée une fois (pourcentage, échappements JSON, base64), lignes coupées rejointes.
- Expressions régulières RE2 seulement (`regexp` de Go) : temps linéaire, aucun retour arrière.
- Travail borné : entrée de 1 Mio au plus, budgets de décodages, de fenêtres et de vues ; au-delà, l'analyse est déclarée incomplète.
- Vitesse : le 19 octobre 2026, sur un Apple M2 Pro, 64 Kio de code sans secret sont analysés en 9,2 ms (67,5 ms en v0.3.0, ×7,4), grâce à une porte littérale exacte et à l'exécution en parallèle des familles de règles sans budget partagé, sans changer un seul résultat ([docs/bench.md](docs/bench.md)).

### Ce qu'il ne fait jamais

- **Aucun réseau, aucune télémétrie, aucun modèle de langage.** Le moteur (`detect`, `pack`, `custom`, `hidden`, `injection`, `mentions`) n'importe ni réseau, ni fichier, ni horloge, ni hasard, ni journal : règle `depguard` de [.golangci.yml](.golangci.yml), prouvée import par import par `go run ./tools/depguardcheck`. Le module WebAssembly n'importe qu'une liste fermée de fonctions WASI, sans fonction réseau (`sock_*`) ni d'ouverture de fichier (`path_*`) : test `wasm/secret-guard.test.mjs`.
- **Aucune valeur détectée en sortie.** Un constat porte la règle, le type de secret, la lecture, le score, le niveau et l'étendue en octets : jamais la valeur, un extrait, un masque ni un condensat non salé. Des tests par réflexion et par arbre syntaxique relèvent la liste fermée de l'API exportée.
- **Jamais « rien trouvé » par défaut.** Une analyse incomplète (entrée trop grande, budget épuisé, panique rattrapée) rend `complete: false` et aucun constat : l'appelant décide (bloquer), jamais sur le seul nombre de constats.

Le moteur ne trouve que ce que ses règles décrivent : il réduit le risque, il ne le supprime pas.

### API Go

```go
import (
	"github.com/xsom-consulting/secret-guard/detect"
	"github.com/xsom-consulting/secret-guard/pack"
)

p, err := pack.Initial()             // ou pack.Decode(octets) : décodage strict du schéma RulePack
rules, err := detect.LoadRules(p)    // refus typé (*detect.PackError) d'un Pack inexploitable
result := detect.Scan(content, rules, detect.Options{LanguageID: "typescript"})
if !result.Complete {
	// result.Failure : scan_limit (plus de 1 Mio) ou scan_error ; aucun constat : bloquer.
}
for _, f := range result.Findings {
	// f.RuleID, f.SecretType, f.Encoding, f.Score, f.Level, f.ByteStart, f.ByteEnd
}
```

`detect.Options{Workers: n}` borne le nombre de fils d'une analyse (0, par défaut : 8 au plus ; 1 : analyse séquentielle, sur un seul fil) ; le résultat est le même quel que soit `Workers`, et le moteur ne lit pas le nombre de processeurs.

`detect.ScanWithFingerprint(content, rules, key)` ajoute à chaque constat une Empreinte locale : HMAC-SHA256 de la valeur, tronqué à 16 octets, sous une clé de 32 octets fournie par l'appelant (`detect.NewFingerprintKey`). Elle permet de reconnaître qu'une même valeur revient sans la garder ; sans la clé, rien ne la relie à la valeur.

### Masquage

```go
redacted, outcome := detect.RedactAndRescan(content, rules, detect.Options{}, detect.RedactOptions{})
if outcome.Failure != detect.SanitizeNone {
	// SanitizeIncomplete (analyse incomplète, texte masqué de plus de 1 Mio compris) ou SanitizeResidual (un secret
	// subsiste après masquage) : redacted vaut nil, rien n'est à envoyer.
}
```

`detect.RedactAndRescan` remplace chaque secret détecté par un libellé `<REDACTED_règle>` (étendues qui se chevauchent ou se touchent fusionnées, octets hors des étendues gardés tels quels), puis analyse de nouveau le texte masqué avec les mêmes règles. Il ne rend le texte que si les deux analyses sont complètes et que la seconde ne trouve rien ; sinon aucun texte, et la copie masquée est effacée. `outcome.Initial` et `outcome.Final` sont les deux analyses, sans aucun texte. `detect.Redact(content, result, options)` masque selon un résultat donné, sans nouvelle analyse, et refuse une analyse incomplète ou une étendue hors du contenu. Le texte rendu est celui de l'appelant sans les valeurs détectées : un libellé ne dépend que de l'identifiant de règle.

Le masquage sert quand l'utilisateur choisit d'envoyer une version expurgée de son texte (presse-papiers, message d'un chat). Un hook ne réécrit pas : il autorise ou bloque l'envoi tel quel. Un mod de Claude Code peut réécrire le prompt : `Expurgate` (section suivante). Comme la détection, le masquage réduit le risque, il ne le supprime pas.

### Expurgation

L'expurgation est le module `github.com/xsom-consulting/secret-guard/expurgation` (dossier `expurgation/`), sous licence PolyForm Small Business 1.0.0, source disponible (voir [Licences](#licences)). Le moteur, sous Apache-2.0, reconnaît les Substituts (grammaire, `detect.SubstituteText`, `detect.SecretRange`, `detect.FindSubstitutes`) sans les poser.

```go
import "github.com/xsom-consulting/secret-guard/expurgation"

expurgated, substitutions, outcome := expurgation.ExpurgateAndRescan(content, rules, &key, expurgation.Options{}, ordinal)
if outcome.Failure != detect.SanitizeNone {
	// detect.SanitizeIncomplete, detect.SanitizeResidual (un secret subsiste après l'élargissement à la ligne) ou
	// expurgation.SanitizeOrdinal (numéro refusé) : expurgated et substitutions valent nil, rien n'est à envoyer.
}
```

`expurgation.ExpurgateAndRescan` remplace la **partie secrète** de chaque constat par un **Substitut** typé : le préfixe public de la règle du constat (table fermée `detect.SubstitutePrefixes()`, chaque préfixe tiré du motif d'une règle à format fixe du Pack initial : `ghp_`, `AKIA`, `sk-ant-`… ; un mot de passe, une valeur d'entropie, d'URL, de cookie ou du Pack du client n'en reçoit aucun, même s'il commence par ces caractères), puis, entre crochets, le numéro de 1 à 999 donné par l'appelant (`ordinal`) et le type de secret de la règle (table fermée `detect.SubstituteLabels()`, repli `secret`), en français par défaut `[secret masqué par xSOM n°<numéro> : <type>, pas la vraie valeur]` ou en anglais avec `expurgation.Options{SubstituteLanguage: detect.SubstituteEnglish}` (`[secret masked by xSOM #<number>: <type>, not the real value]`). Le Substitut ne porte rien d'autre de la valeur : ni sa longueur, ni un de ses caractères. `detect.FindSubstitutes(text)` rend l'étendue et le numéro de chaque Substitut exact d'un texte (pour juger une commande comme si chaque Substitut était un mot opaque). Exemple : `postgres://admin:<mot de passe>@db.exemple.fr:5432/prod` devient `postgres://admin:[secret masqué par xSOM n°1 : mot de passe de base de données, pas la vraie valeur]@db.exemple.fr:5432/prod`, et un jeton GitHub `ghp_…` devient `ghp_[secret masqué par xSOM n°2 : jeton GitHub, pas la vraie valeur]`. Seule la partie secrète est remplacée : le mot de passe d'une URL à identifiants ou de `curl -u` (avec le nom d'utilisateur s'il n'est pas un nom ordinaire de 16 caractères au plus de `[a-z0-9._-]` : un jeton passé comme utilisateur), ce qui suit `Bearer `, `Basic ` ou `Token ` dans un en-tête Authorization jusqu'au premier guillemet, le corps d'une clé PEM entre ses lignes `BEGIN` et `END` ; toute autre étendue, ou une étendue née de la fusion de plusieurs règles, est remplacée en entier, sauf un jeton complet en fin de ligne dont l'étendue prend le premier mot de la ligne suivante (`export A=<jeton>` puis `export B=x`, fichier `.env`) : seule la première ligne est remplacée, la fin de ligne et la ligne suivante restent (un jeton réellement coupé par un retour à la ligne est remplacé en entier). Le texte garde sa syntaxe (shell, JSON, YAML, `.env`) ; aucun libellé `<…>` que le shell lirait comme une redirection.

Le moteur reconnaît un Substitut comme une valeur fictive, selon une grammaire exacte et fermée (préfixe de la table ou aucun, l'une des deux formes octet pour octet, numéro de 1 à 999 sans zéro de tête, type de la table dans la même langue) : le texte expurgé, analysé de nouveau, ne bloque pas sur ses Substituts, seuls ou dans un gabarit (shell, JSON, YAML, `.env`, URL, `Authorization: Bearer`, `curl -u`, cookie, corps PEM), même quand la lecture d'une valeur sans guillemets s'arrête à son espace, à sa virgule ou à son dièse (le Substitut complet doit alors commencer la valeur et finir proprement). Un texte qui ne suit pas exactement la grammaire (autre type, autre langue, numéro 0 ou 1000, caractères collés après le crochet) reste analysé et détecté. L'ancienne forme (des `X` puis un numéro) n'est plus reconnue depuis la v0.5.0. Le texte expurgé est plus long que le texte d'origine : au-delà de 1 Mio, l'expurgation échoue (`SanitizeIncomplete`), jamais un texte non analysé. S'il reste un constat, son étendue est élargie au jeton qui la contient, puis à sa ligne ; au-delà, l'expurgation échoue (aucun texte, copies effacées). Chaque `Substitution` donne la règle, le type de secret, l'étendue remplacée dans le texte d'origine (octets et unités UTF-16), l'Empreinte locale (avec une clé : celle des octets d'origine remplacés exactement, d'où le même Substitut pour la même valeur), le numéro et le Substitut écrit, jamais la valeur : l'appelant, qui détient le texte d'origine, la lit lui-même à ces positions. `expurgation.Expurgate(content, result, ordinal)` expurge selon un résultat donné, sans nouvelle analyse ni clé : il garde l'Empreinte locale d'un constat seulement si l'étendue remplacée est exactement la sienne, et refuse sinon (`expurgation.ErrSpan`). Un contenu hors UTF-8 est refusé (ses positions UTF-16 seraient fausses). Vecteurs : `vectors/expurgate.json` (`cd expurgation && go test . -run '^TestExpurgateVectors$' -update`).

L'expurgation apprend au Fournisseur le type de chaque secret et, pour une règle à format fixe, son préfixe public ; plus sa longueur. Comme la détection, elle réduit le risque, elle ne le supprime pas.

### Niveaux et décisions

Chaque constat a un niveau tiré de son score : LOW (moins de 25), MEDIUM (25 à 49), HIGH (50 à 74), CRITICAL (75 et plus). `detect.DecisionForLevel(level)` rend la décision que Secret Guard associe par défaut à un niveau : `ALLOW` pour LOW, `WARN` pour MEDIUM, `BLOCK` pour HIGH, CRITICAL et tout niveau hors de cette liste. C'est un préréglage, pas une politique : le produit qui embarque le moteur décide. xSOM Fleet, par exemple, associe niveaux et décisions par sa Politique publiée et, sans association publiée, bloque quel que soit le niveau. Une analyse incomplète n'a pas de niveau : elle bloque toujours.

Le schéma du Pack (`schema/RulePack.json`, [docs/rule-pack.md](docs/rule-pack.md)) est une copie : le programme qui signe et distribue des Packs (xSOM Fleet) reste la source du contrat signé. Le test `TestSchemaCopy` compare le type `pack.Pack` à cette copie. Le moteur ne vérifie aucune signature : vérifier un Pack signé est l'affaire de celui qui le distribue, avant `pack.Decode`.

### Instructions cachées (`hidden`)

Des caractères qu'une personne ne voit pas mais qu'un modèle lit peuvent porter des consignes : dans un fichier d'instructions d'assistant, un prompt collé, un fichier cité. Le paquet `hidden` en relève quatre porteurs :

- caractères d'étiquette Unicode (U+E0000 à U+E007F), « ASCII smuggling » ;
- plongements, forçages et isolats bidirectionnels, « Trojan Source » (CVE-2021-42574) ;
- suites de caractères invisibles de largeur nulle (et autres caractères ignorables par défaut) ;
- suites de sélecteurs de variante après un caractère.

Les usages légitimes restent silencieux : drapeau de subdivision (Angleterre, Écosse, pays de Galles), liant dans un emoji, liants des écritures qui joignent leurs lettres (persan, devanagari…), un sélecteur de variante après sa base, sélecteurs de forme du mongol, césure conditionnelle entre deux lettres, marque d'ordre des octets en tête, marques de direction. Moins de quatre caractères invisibles isolés dans un texte sont tenus pour du bruit.

```go
report := hidden.Find(text)   // texte en octets, 1 Mio au plus
if !report.Complete {
	// plus de 1 Mio : rien n'est lu, ne jamais tenir le texte pour propre
}
for _, f := range report.Findings { // 50 suites au plus ; report.Hidden reste exact
	// f.Kind, f.Line, f.Column, f.Count, f.ByteStart, f.ByteEnd : jamais ce que les caractères écrivent
}
clean := hidden.Strip(text)   // retire exactement ce que Find signale ; rend toujours de l'UTF-8 valide
```

Un octet hors UTF-8 se lit comme U+FFFD (un par octet) : jamais signalé, il compte comme un caractère. `Strip` l'écrit U+FFFD : garder l'octet pourrait, une fois retiré un caractère voisin, former avec d'autres octets un caractère qui n'était pas là (U+202E par exemple). Comme à l'origine, `Strip` fait une seule passe : deux caractères invisibles que le retrait rapproche peuvent être signalés par un nouvel appel de `Find`. Parité : 152 cas produits par le `hidden.ts` d'origine (`vectors/hidden.json`, `TestHiddenParity`).

### Consignes adressées à l’agent (`injection`, v0.8.0)

Une page lue, un résultat d'outil ou un fichier cité peut porter, en texte visible, des phrases écrites pour l'agent et non pour la personne : « ignore les instructions précédentes », un changement de rôle, la demande d'envoyer des clés à une adresse, l'ordre de ne rien dire à l'utilisateur, des balises de tours de parole de modèles. Le paquet `injection` les relève, en français et en anglais, sous cinq règles : `injection_instruction_override`, `injection_role_switch`, `injection_exfiltration`, `injection_concealment` et `injection_message_markers`.

```go
report := injection.Find(text)   // texte en octets, 1 Mio au plus
if !report.Complete {
	// plus de 1 Mio : rien n'est lu, ne jamais tenir le texte pour propre
}
for _, f := range report.Findings { // 50 constats au plus ; report.Total reste exact
	// f.Rule, f.Line, f.Column, f.ByteStart, f.ByteEnd : jamais le texte trouvé
}
```

C'est un détecteur de constat : il ne masque ni n'expurge rien (le texte d'une page lue n'est pas à réécrire) et il ne juge pas. Un texte qui cite ces phrases pour les expliquer, une documentation sur l'injection de prompt par exemple, est signalé comme celui qui les emploie : l'appelant choisit la décision (avertir est le choix sûr pour un texte lu). Il ne couvre que les formes ci-dessus ; une consigne écrite autrement passe, et l'absence de constat n'est pas une preuve d'innocuité. Les motifs sont des expressions RE2 (temps linéaire) et chaque règle est contrainte par un corpus de bruit (`vectors/injection.json` : textes ordinaires qui ne doivent rien signaler) : une règle ne s'ajoute pas sans cas de bruit. Pas de portage d'origine : le corpus est écrit pour ce paquet. La ligne de commande et le module WebAssembly ne l'exposent pas encore.

### Fichiers cités par « @ » (`mentions`)

Claude Code ajoute au contexte le contenu d'un fichier cité par `@` dans un prompt sans appel d'outil : aucun hook `PreToolUse` ne se déclenche pour lui, pas même ceux qui visent `Read` ([documentation des hooks](https://code.claude.com/docs/en/hooks)). Un hook `UserPromptSubmit` doit donc retrouver ces fichiers lui-même pour les analyser avant l'envoi ; `mentions.Parse` les relève, sans lire ni résoudre aucun fichier : l'appelant résout chaque chemin (répertoire de travail de l'assistant) et lit le fichier sous l'identité de la personne, puis l'analyse (`detect`, `hidden`).

```go
for _, m := range mentions.Parse(prompt) {
	// m.Path : chemin tel qu'écrit (sans guillemets, suffixe « #L10-20 » ni ponctuation finale)
	// m.Lines : « 10-20 » ou vide ; m.LineRange() pour les nombres ; m.ByteStart, m.ByteEnd : position de la mention
}
```

Règles de l'origine (`mentionedPaths`) : une mention commence le prompt ou suit un espacement (une adresse électronique n'en est pas une) ; formes `@chemin`, `@"chemin avec espaces"`, `@chemin#L10-20` ; ponctuation finale `, ; : ! ? )` retirée ; doublons fusionnés. Sans résolution, la fusion porte sur le chemin tel qu'écrit (`@a.md` et `@./a.md` restent deux mentions, à fusionner après résolution). Parité : 122 cas produits par `mentionedPaths` d'origine (`vectors/mentions.json`, `TestMentionsParity`).

### Pack de règles du client (`custom`)

Un Pack de règles du client ajoute aux règles intégrées des détecteurs propres à un client : identifiants internes, numéros d'un format maison (motifs), noms de code de projets (termes confidentiels). Il est calibré et signé par celui qui le distribue ; le moteur le juge et l'applique localement. Contrat : [docs/custom-pack.md](docs/custom-pack.md), schéma `schema/CustomPack.json`.

```go
p, err := custom.Compile(charge)   // charge JSON du Pack, signature déjà vérifiée par l'appelant ; refus *custom.PackError
result := detect.Scan(content, rules, detect.Options{Custom: p})
```

- **Motifs** : sous-ensemble sûr d'expressions régulières (bornes ≤ 64, ni `*`, ni `+`, ni `.`, ni groupes capturants, ancre littérale ou mots-clés de contexte), validé avec les codes du contrat, puis traduit en RE2 avec la sémantique d'ECMAScript (repliement de casse ASCII seulement, itération vide d'un groupe optionnel refusée).
- **Termes confidentiels** : le Pack ne porte que des condensats SHA-256 salés de n-grammes normalisés (NFKD, marques retirées, minuscules) ; le moteur hache les n-grammes du texte et compare. Aucun terme n'est dans le Pack ni dans un résultat. Chez le client, `secret-guard terms digest --salt <sel> termes.txt` calcule les condensats d'une liste de termes (un par ligne) : seuls les condensats sortent.
- **Constats** : `ruleId` `xsom_<détecteur>`, `secretType` `custom_rule`, score 90 (`block`) ou 40 (`warn`), étendue en octets, jamais la valeur ; ils s'ajoutent aux constats intégrés sans en retirer aucun. Le libellé, la catégorie et l'action d'un détecteur se lisent dans `Pack.Detectors()`.
- **Bornes** : préfiltre littéral et budget de travail ; `Failure` `custom_budget` (budget épuisé) ou `custom_too_many` (trop de détections) : analyse incomplète, aucun constat.
- **Masquage** : `RedactAndRescan` nomme une détection du Pack d'après le libellé de son détecteur (`<REDACTED_Identifiant_client>`), puis, si un secret subsiste, recommence avec `<REDACTED_custom_rule>` (`RedactOptions.NeutralCustomNames`).

Parité avec le moteur d'origine : vecteurs `vectors/custom/` (contrat, entrées des tests d'origine, cas synthétiques, pont Unicode), écarts déclarés et vérifiés dans [UPSTREAM.md](UPSTREAM.md) (`TestCustomPackParity`, `TestCustomScanParity`, `TestCustomRedactParity`…).

### Ligne de commande

```sh
go install github.com/xsom-consulting/secret-guard/cmd/secret-guard@latest
secret-guard scan fichier.env          # ou : cat fichier | secret-guard scan -
secret-guard scan --pack autre-pack.json --language dotenv fichier.env
secret-guard scan --fingerprint-key cle.hex fichier.env   # cle.hex : 64 caractères hexadécimaux, lue, jamais écrite
secret-guard scan --custom-pack pack-client.json fichier.env   # avec un Pack de règles du client
secret-guard terms digest --salt <sel> termes.txt          # condensats de termes confidentiels, jamais les termes
secret-guard redact fichier.env > fichier.masque.env       # code 2 : rien n'est écrit (fichier vide)
secret-guard hidden AGENTS.md          # rapport JSON des instructions cachées
secret-guard hidden --strip AGENTS.md > AGENTS.propre.md   # texte sans les caractères signalés
secret-guard mentions prompt.txt       # fichiers cités par « @ », sans rien lire
secret-guard version
```

Sortie : un document JSON sur une ligne, `{"complete":true,"failure":"none","findings":[{"ruleId":"github_token","secretType":"provider_token","encoding":"plain","score":95,"level":"CRITICAL","byteStart":6,"byteEnd":46}]}`.

| Code de sortie | Sens |
|---|---|
| 0 | analyse complète, aucun constat |
| 1 | analyse complète, au moins un constat |
| 2 | erreur (usage, lecture, Pack refusé) ou analyse incomplète, qui ne vaut jamais « rien trouvé » |

`secret-guard redact [--pack <fichier>] [--custom-pack <fichier>] [--language <id>] [fichier|-]` écrit sur la sortie standard le texte masqué (voir « Masquage »), et seulement lui :

| Code de sortie de `redact` | Sens |
|---|---|
| 0 | rien à masquer : le texte est recopié tel quel |
| 1 | au moins un secret masqué |
| 2 | erreur, analyse incomplète ou secret qui subsiste après masquage : rien sur la sortie standard, la raison sur la sortie d'erreur |

`secret-guard hidden` écrit `{"complete":true,"hidden":21,"findings":[{"kind":"tag_characters","line":1,"column":16,"count":21,"byteStart":15,"byteEnd":99}]}` ; mêmes codes de sortie (1 : au moins un caractère signalé ; 2 : erreur ou texte de plus de 1 Mio). Avec `--strip`, il écrit le texte nettoyé à la place, et rien au-delà de 1 Mio. `secret-guard mentions` écrit `{"mentions":[{"path":"src/x.ts","lines":"10-20","byteStart":30,"byteEnd":46}]}` ; code 0, ou 2 en cas d'erreur ou de prompt de plus de 1 Mio.

### WebAssembly

Le module WebAssembly embarque l'expurgation : son code Go est dans `expurgation/cmd/secret-guard-wasm` (module `expurgation`, PolyForm Small Business 1.0.0) ; le module construit et le paquet npm sont sous `(Apache-2.0 AND PolyForm-Small-Business-1.0.0)`. Les chargeurs JavaScript de `wasm/` restent sous Apache-2.0.

```sh
(cd expurgation && GOOS=wasip1 GOARCH=wasm go build -trimpath -buildvcs=false -ldflags="-s -w" -buildmode=c-shared -o ../dist/secret-guard.wasm ./cmd/secret-guard-wasm)
node --test wasm/secret-guard.test.mjs   # deux chargeurs, importations et exportations en liste fermée
node --test wasm/parity.test.mjs         # parité avec le moteur Go natif sur tout le corpus (Go requis, quelques minutes)
node --test wasm/package.test.mjs        # paquet npm préparé dans un dossier temporaire
node --no-warnings wasm/bench.mjs
```

Module WASI preview 1 en mode bibliothèque : instancié une fois, il garde ses règles chargées et analyse, masque ou expurge à la demande (`scan`, `scanWithFingerprint`, `findHidden`, le rapport de `secret-guard hidden`, `redact`, qui rend `{ failure, initial, final, redacted }`, `redacted` valant `null` si le masquage échoue, et `expurgate`, qui remplace chaque secret par un Substitut typé numéroté par Empreinte locale et rend `{ failure, initial, final, substitutions, text }`, `text` valant `null` en échec ; il exige `setFingerprintKey`). `wasm/secret-guard.mjs` est un chargeur sans dépendance, qui n'ouvre ni fichier ni connexion ; `wasm/node.mjs` l'assemble avec `node:wasi` (aucun répertoire ouvert), `wasm/browser.mjs` avec la couche WASI minimale `wasm/wasi.mjs` (navigateur, extension, service worker). Une erreur du module rend l'instance inutilisable (`broken`) ; un module d'une autre version (fonction absente ou autre signature) est refusé à la construction.

Construction reproductible : `-trimpath -buildvcs=false` (ni chemin ni état git dans le module), même empreinte pour les mêmes sources et la même version de Go (`go.mod`).

Le dossier `wasm/` est aussi le paquet npm `@xsom/secret-guard-wasm` (points d'entrée `.`, `./node`, `./browser`, `./wasi`, types `.d.mts`, aucune dépendance ni script) : `node wasm/stage.mjs` le prépare dans `dist/npm/`. Le workflow `.github/workflows/release.yml`, lancé par la poussée d'une étiquette `vX.Y.Z` égale à la version de `wasm/package.json`, construit le module, rejoue les essais et la parité, publie une Release GitHub (`secret-guard.wasm`, archive npm, `SHA256SUMS`) avec une attestation de provenance signée (`gh attestation verify secret-guard.wasm -R xsom-consulting/secret-guard`), puis, après approbation dans l'environnement `npm`, publie l'archive sur npm avec la provenance npm. Choix de `wasip1` plutôt que `js/wasm` : interface WASI standard sans colle JavaScript liée à une version exacte de Go (`wasm_exec.js`), exécutable par Node, Wasmtime ou une couche WASI de navigateur, et la liste des fonctions importées montre ce que le module peut faire (ni réseau, ni ouverture de fichier). La ligne de commande se construit aussi pour WASI (`GOOS=wasip1 GOARCH=wasm go build ./cmd/secret-guard`).

Mesures du 13 octobre 2026 sur une seule machine (Apple M2 Pro, Node 26.0.0, Go 1.27.2, `node wasm/bench.mjs`, trois séries), indicatives :

| Mesure | Valeur |
|---|---|
| Taille du `.wasm` (avec `findHidden` et `redact`) | 6,02 Mo brut ; 1,65 Mo gzip -9 ; 1,21 Mo brotli |
| Démarrage (compilation, instanciation, Pack initial chargé), médiane de 10 | 20 ms (première instance du processus : 70 à 90 ms) |
| Première analyse d'un texte court | 9 ms |
| Analyse de 64 Kio (entrée de `BenchmarkScan64KiB`), médiane de 20 | 300 à 360 ms selon la série, minimum 304 ms (Go natif : 66 ms) |

### Régénérer le Pack initial et le corpus

Le générateur TypeScript est dans `generator/` (Node 26, `npm ci`). Il n'est pas dans le moteur livré.

```sh
cd generator
npm ci
npm test                                   # Pack, motifs du moteur, corpus, Unicode, Empreintes locales, vecteurs hidden et mentions
npm run pack:initial                       # pack/initial/pack.json et detect/engine_patterns.go
npm run vectors:detection -- --upstream <checkout> --check   # corpus : réservé à xSOM (checkout du dépôt d'origine privé, voir UPSTREAM.md)
npm run vectors:redact -- --upstream <checkout> --check      # vecteurs du masquage et des décisions (même checkout)
npm run vectors:hidden -- --upstream <checkout> --check      # vectors/hidden.json et vectors/mentions.json (même checkout)
npm run vectors:custom -- --upstream <checkout> --check      # vectors/custom/ : Pack de règles du client (même checkout)
npm run hidden:tables -- --check           # hidden/unicode_tables.go, calculé par Node
npm run vectors:unicode                    # vectors/unicode-parity.json (montée de version Unicode seulement)
```

Ne jamais éditer `pack.json`, `engine_patterns.go`, `hidden/unicode_tables.go`, le corpus ni les vecteurs (dont `vectors/redact.json` et `vectors/decision.json`) à la main. Toute évolution des règles ajoute ses cas au corpus.

### Vérifier

```sh
go vet ./... && golangci-lint run && go test -count=1 -coverprofile=coverage.out ./...
(cd expurgation && go vet ./... && golangci-lint run && go test -count=1 -coverprofile=coverage.out ./...)   # module expurgation
go test -count=1 -v -run '^TestParity$' ./detect
go test -count=1 -v -run '^TestNoiseCorpus$' ./detect   # corpus de bruit (vectors/noise.json) : aucun constat
go test -count=1 -v -run '^(TestRedactParity|TestDecisionParity|TestRedactLeavesNoValue)$' ./detect   # masquage et décisions
go test -count=1 -v -run '^TestHiddenParity$' ./hidden
go test -count=1 -v -run '^TestMentionsParity$' ./mentions
go test -count=1 -v -run '^TestCustom' ./custom ./detect      # Pack de règles du client
go run ./tools/covercheck coverage.out     # detect, pack, custom, hidden, mentions, internal ≥ 80 %
go run ./tools/covercheck -module expurgation expurgation/coverage.out   # expurgation, internal ≥ 80 %
go run ./tools/depguardcheck                # chaque import interdit est refusé (deux modules)
go run ./tools/spdxcheck                    # identifiant SPDX de chaque fichier source, selon son module
gitleaks dir . && gitleaks git .
```

Fuzz : `go test ./detect -run '^$' -fuzz '^FuzzScan$' -fuzztime=60s` (autres cibles : `FuzzRedact`, `FuzzSubstituteGrammar`, `FuzzTextViews`, `FuzzBase64Candidates`, `FuzzDecodeBase64`, `FuzzJWT`, `FuzzRuleFamilies`…, et `FuzzHiddenFind` dans `./hidden`, `FuzzMentions` dans `./mentions`, `FuzzCustomPattern` et `FuzzCustomPackDecode` dans `./custom`, `FuzzExpurgate` dans le module `expurgation`, depuis son dossier).

### Sécurité

Signaler une vulnérabilité selon [SECURITY.md](SECURITY.md) : avis de sécurité privé GitHub (onglet « Security » du dépôt), jamais un ticket public. Le temps d'une analyse est borné par des budgets de travail, pas par une horloge : le pire cas mesuré (1 Mio d'expansion NFKC maximale) prend quelques secondes en Go natif ; l'appelant fixe son échéance. Les fichiers de cas du corpus `vectors/detection/` et les vecteurs du masquage `vectors/redact.json` contiennent des valeurs synthétiques à la forme de jetons : ce sont les seules exceptions de la recherche de secrets ([.gitleaks.toml](.gitleaks.toml)).

### Données personnelles (v0.7.0)

Le Pack initial détecte aussi des données personnelles françaises et bancaires, par des règles « motif seul » dont un **validateur** contrôle la clé du format : un numéro de même longueur sans clé valide (téléphone, commande, horodatage) n'est pas un constat.

| `ruleId` | `secretType` | Validateur | Score (niveau) | Ce qui est reconnu |
|---|---|---|---:|---|
| `iban` | `iban` | `iban_mod97` | 45 (MEDIUM) | IBAN de tout pays (ISO 13616, modulo 97, chiffres de contrôle 02 à 98), écrit d'un bloc ou par groupes de quatre ; longueur du pays imposée pour 52 pays d'Europe et du pourtour, 15 à 34 caractères ailleurs ; lettres majuscules ou minuscules |
| `fr_nir` | `fr_social_security_number` | `fr_nir_key` | 60 (HIGH) | numéro de sécurité sociale (NIR) de 13 caractères et sa clé de 2 chiffres (97 − nombre mod 97 ; Corse `2A` = 19, `2B` = 18), avec ou sans espaces ; ni département, ni commune, ni numéro d'ordre nul |
| `fr_siret` | `fr_siret` | `fr_siret_luhn` | 35 (MEDIUM) | SIRET de 14 chiffres (Luhn ; exception de La Poste, SIREN 356000000 : somme des chiffres multiple de 5), en groupes de 3-3-3-5 ou non ; un nombre qui se lit AAAAMMJJHHMMSS (horodatage) ou fait d'un seul chiffre n'en est pas un |
| `fr_siren` | `fr_siren` | `fr_siren_luhn` | 35 (MEDIUM) | SIREN de 9 chiffres (Luhn), **seulement après le mot « SIREN »** (« SIREN : », `siren=`, « SIREN n° », guillemets de JSON) ; le mot n'est pas dans l'étendue du constat. Règle « motif seul » dont le motif porte le contexte : la valeur est le premier groupe capturant |
| `payment_card` | `payment_card_number` | `payment_card_luhn` | 70 (HIGH) | carte bancaire de 13 à 19 chiffres (Luhn) d'un réseau courant (Visa 16 et 19, Mastercard, American Express, Discover, Diners, JCB, UnionPay, Maestro), d'un bloc ou par groupes 4-4-4-4 / 4-6-5 / 4-6-4 séparés d'une espace ou d'un tiret (un seul des deux) ; les numéros de 19 chiffres s'écrivent d'un bloc |

À savoir :

- Les validateurs sont actifs dans la lecture telle quelle, normalisée, en pourcentage et en échappements JSON (score diminué de 5), pas dans un texte décodé de base64 (comme `jwt`).
- Le motif de l'IBAN est volontairement générique ; le moteur retient, parmi les fins de groupe de la correspondance, la plus longue dont la clé est valide, pour qu'un IBAN suivi d'un mot ou d'un nombre de quatre caractères (« … 1332 pour ») soit trouvé sans ce mot.
- Une carte d'essai publique (`4111 1111 1111 1111`) est une carte : le moteur ne garde pas de liste d'exemples. Un produit qui l'embarque choisit, par règle (`ruleId`), de bloquer, d'avertir ou de laisser passer.
- Coût : sur le banc de `docs/bench.md` (64 Kio sans secret, même machine), l'analyse passe de 9,1 à 13,7 ms avec les 5 règles.
- Substituts : un type par règle dans les deux langues (« IBAN », « numéro de sécurité sociale », « numéro SIRET », « numéro SIREN », « numéro de carte bancaire » ; `SubstituteLabels()`). Un programme qui tient sa propre table de types de Substituts la complète.
- Liste fermée du schéma `RulePack` : 5 valeurs de `secretType` et 5 `validator` de plus. Un moteur antérieur à la v0.7.0 refuse un Pack qui les emploie (`unknown_secret_type`, `unknown_validator`).
- Corpus : `vectors/detection/rules-personal-data.json` (80 cas : 45 positifs, 35 négatifs, tous calculés), dont le résultat attendu vient d'une seconde écriture indépendante des contrôles (`generator/rule-pack/personal-data.ts`), pas du moteur d'origine. Les vecteurs du masquage et du Pack du client restent ceux du moteur d'origine.
- Limites : numéros de 19 chiffres de carte groupés, IBAN écrits avec d'autres séparateurs que l'espace, NIR sans clé (13 chiffres), SIREN hors contexte, numéros dans un texte décodé de base64 : non reconnus. Le moteur réduit le risque, il ne le supprime pas.

### Mot de passe annoncé dans une phrase (v0.8.1)

La règle `contextual_password` (type `password`, score 70, niveau HIGH) lit aussi un mot de passe annoncé en langage naturel, en français ou en anglais : « check mon api avec mon mdp <valeur> », « mot de passe : <valeur> », « le mot de passe est <valeur> », « my password is <valeur> ». Aucune règle nouvelle, aucun changement du schéma `RulePack` ni du Pack initial : un Pack qui contient `contextual_password` en profite tel quel.

- Indices, sans la casse : `mdp`, `mot de passe`, `mot-de-passe`, `code d'accès` (apostrophe droite ou typographique), `pass`, et les noms que l'affectation ordinaire classe « password » (`password`, `passwd`, `pwd`, `passphrase`). Un mot entier, ni dans un nom de variable, une option ou une propriété (`user.password`, `--password-file`).
- Liaison facultative sur la même ligne : `est`, `is`, `c'est`, et `:` ou `=` après un indice français ou `pass` ; `password: …` et `password = …` restent à l'affectation ordinaire et à ses filtres. `pass` exige une liaison.
- Valeur : un seul mot, guillemets retirés, ponctuation finale `. , ; : ?` retirée, de 8 à 256 points de code, au moins trois classes parmi minuscules, majuscules (lettres de toute écriture, par leur casse), chiffres et autres caractères ; ni valeur fictive, ni Substitut, ni référence de code ou d'environnement (`${…}`, `$(…)`, `process.env.X`, `getPassword(…)`), ni adresse `://`.
- L'étendue du constat est la valeur seule : l'expurgation garde la phrase. « mon mdp est trop court », « le mot de passe Administrateur », « mot de passe oublié », « password reset link » ne donnent rien.
- Limites : une valeur de deux classes seulement (`azerty123`), écrite en plusieurs mots, sur la ligne suivante, ou annoncée sans indice (« le code c'est … » sans « d'accès ») n'est pas lue ; un mot ordinaire de trois classes juste après un indice (« mon mdp Windows11 ») est un constat. L'entropie (20 caractères de la classe base64) est inchangée.
- Corpus : `vectors/detection/rules-password-phrase.json` (27 cas : 14 positifs, 13 négatifs), résultat attendu tiré d'une seconde écriture de la lecture (`generator/rule-pack/password-phrase.ts`), le moteur d'origine ne trouvant rien dans ces textes. Les cas de l'origine sont inchangés.

### Migration vers la v0.6.0

L'expurgation quitte le paquet `detect` pour le module `github.com/xsom-consulting/secret-guard/expurgation`, à exiger à la même version que la racine :

- `detect.Expurgate`, `detect.ExpurgateAndRescan`, `detect.Substitution`, `detect.SanitizeOrdinal` → `expurgation.Expurgate`, `expurgation.ExpurgateAndRescan`, `expurgation.Substitution`, `expurgation.SanitizeOrdinal` ;
- `detect.ErrExpurgateIncomplete`, `ErrExpurgateSpan`, `ErrExpurgateEncoding`, `ErrExpurgateOrdinal`, `ErrExpurgateLanguage` → `expurgation.ErrIncomplete`, `ErrSpan`, `ErrEncoding`, `ErrOrdinal`, `ErrLanguage` ;
- `detect.Options{…, SubstituteLanguage: l}` → `expurgation.Options{Options: detect.Options{…}, SubstituteLanguage: l}` ;
- nouvelles primitives publiques de `detect` : `ScanWith`, `Fingerprint`, `FingerprintKey.Usable`, `SecretRange`, `Rules.FirstLineSecretEnd`, `SubstituteText`, `SubstituteLanguage.Valid`, `ErrSubstituteOrdinal`, `ErrSubstituteLanguage`. Textes, Substituts et refus de l'expurgation sont inchangés (`vectors/expurgate.json`).

### Licences

Ce dépôt contient deux modules Go, sous deux licences.

| Partie | Module (dossier) | Licence |
|---|---|---|
| Détection (`detect`, `pack`, `custom`, `hidden`, `mentions`), masquage, reconnaissance des Substituts, formats (`schema/`, `docs/`), corpus et vecteurs (`vectors/`), ligne de commande, chargeurs JavaScript (`wasm/`), générateur | `github.com/xsom-consulting/secret-guard` (racine) | Apache-2.0, licence open source ([LICENSE](LICENSE), [NOTICE](NOTICE)) |
| Expurgation (`expurgation`), module WebAssembly qui l'embarque (`expurgation/cmd/secret-guard-wasm`), outil de parité | `github.com/xsom-consulting/secret-guard/expurgation` (`expurgation/`) | PolyForm Small Business 1.0.0, source disponible ([expurgation/LICENSE](expurgation/LICENSE)) |

- Importer la racine (`go get github.com/xsom-consulting/secret-guard`) ne compile aucun code sous PolyForm : `expurgation/` est un module à part.
- PolyForm Small Business 1.0.0 : le code est public ; son usage est gratuit pour une entreprise de moins de 100 personnes (salariés et indépendants) et de moins de 1 000 000 USD de chiffre d'affaires sur l'exercice précédent, sociétés qu'elle contrôle, qui la contrôlent ou sous contrôle commun avec elle comprises (texte de la licence). Au-delà, y compris pour une évaluation, une licence écrite de xSOM Consulting : [COMMERCIAL.md](COMMERCIAL.md). Les clients de xSOM Fleet la reçoivent avec leur contrat.
- Le paquet npm `@xsom/secret-guard-wasm` embarque l'expurgation : `(Apache-2.0 AND PolyForm-Small-Business-1.0.0)`. Il est publié sur npm depuis la v0.6.1 ; le nom `@xsom-consulting/secret-guard-wasm` des versions précédentes n'a jamais été publié (archives des Releases GitHub seulement).
- Les versions v0.1.0 à v0.5.1 restent entièrement sous Apache-2.0.
- Versions : le module `expurgation` lit la partie `internal/` de la racine, il ne vaut donc qu'avec la racine de la même version. Les deux modules s'étiquettent ensemble, sur le même commit (`vX.Y.Z` et `expurgation/vX.Y.Z`, poussées ensemble : `git push --atomic origin vX.Y.Z expurgation/vX.Y.Z`), `expurgation/go.mod` exige la racine à cette version (contrôlé par `release.yml`), et un consommateur exige la même version des deux modules.
- Chaque fichier source porte l'identifiant SPDX de son module (`go run ./tools/spdxcheck`).

Composants tiers et origine : [UPSTREAM.md](UPSTREAM.md). Contribuer : [CONTRIBUTING.md](CONTRIBUTING.md).

## English

Secret Guard is a secret detection engine (API keys, tokens, private keys, passwords, URLs with credentials…) for text, written in Go. It runs locally, inside the calling process: it is the piece that reads a prompt or a file before it goes to a coding assistant, and this repository is public so that anyone can check it.

It is the Go port of the Secret Guard TypeScript engine (origin, license and changes: [UPSTREAM.md](UPSTREAM.md)). The port returns exactly the original results on a frozen corpus of 823 cases (`TestParity`); since v0.7.0 the corpus has 80 more cases for the personal-data rules, which do not exist in the original, and since v0.8.1 27 cases of passwords announced in a sentence.

**What it does**: 40 rules (initial Pack: the 35 of the original catalog and, since v0.7.0, 5 personal-data rules with a check key: IBAN, French social security number, SIRET, SIREN, payment card number), several readings of the same text (as is, NFKC-normalized, decoded once from percent, JSON escapes and base64, wrapped lines joined), RE2 regular expressions only (linear time), bounded work (1 MiB input, decoding, window and view budgets). Speed: on 19 October 2026, on an Apple M2 Pro, 64 KiB of code without secrets is scanned in 9.2 ms (67.5 ms in v0.3.0, ×7.4), thanks to an exact literal gate and to running the rule families without shared budget in parallel, with no result changed ([docs/bench.md](docs/bench.md)).

**What it never does**: no network, no telemetry, no language model (the engine, `custom`, `hidden` and `mentions` import no network, file, clock, randomness or logging package: `depguard` rule proven by `tools/depguardcheck`; the WebAssembly module imports no `sock_*` or `path_open`); no detected value in the output (a finding carries rule, secret type, reading, score, level and byte span, never the value, an excerpt, a mask or an unsalted hash); never "nothing found" by default (an incomplete scan returns `complete: false` and no finding, so the caller blocks). The engine only finds what its rules describe: it lowers the risk, it does not remove it.

**Hidden instructions** (`hidden`): `hidden.Find(text)` reports characters a person cannot see but a model reads: Unicode tag characters ("ASCII smuggling"), bidirectional embeddings, overrides and isolates ("Trojan Source", CVE-2021-42574), runs of zero-width and other default-ignorable characters, runs of variation selectors. Legitimate uses stay silent (subdivision flags, joiners in emoji and in joining scripts, one variation selector after its base, Mongolian variation selectors, soft hyphens between letters, a leading byte-order mark, directional marks). Each finding carries kind, line, column, count and byte span, never what the characters spell; `Complete` is false beyond 1 MiB. `hidden.Strip(text)` removes exactly what `Find` reports and always returns valid UTF-8 (an invalid byte becomes U+FFFD, so that removing a neighbour cannot form a new character). Parity: 152 cases produced by the original `hidden.ts` (`TestHiddenParity`).

**@-mentioned files** (`mentions`): Claude Code adds the content of a file referenced with `@` in a prompt without any tool call, so no `PreToolUse` hook fires for it, not even one matching `Read` ([hooks documentation](https://code.claude.com/docs/en/hooks)). `mentions.Parse(prompt)` finds these files (`@path`, `@"path with spaces"`, `@path#L10-20`, trailing `, ; : ! ? )` removed, e-mail addresses ignored, duplicates merged) without reading or resolving anything, so that a `UserPromptSubmit` hook can resolve, read (as the user) and scan them itself. Parity: 122 cases produced by the original `mentionedPaths` (`TestMentionsParity`).

**Go API**: `pack.Initial()` or `pack.Decode(bytes)` (strict RulePack decoding), `detect.LoadRules(pack)`, `detect.Scan(content, rules, detect.Options{LanguageID: …})`, `detect.ScanWithFingerprint(content, rules, key)` (local fingerprint: HMAC-SHA256 truncated to 16 bytes under a 32-byte caller key). `detect.Options{Workers: n}` bounds the number of threads of a scan (0, the default: at most 8; 1: sequential, single thread); the result is the same whatever `Workers` is, and the engine never reads the number of processors. Decide on `Result.Complete` and `Result.Failure`, never on the number of findings. The Pack schema is a copy; the program that signs and distributes Packs (xSOM Fleet) remains the source of the signed contract, and `TestSchemaCopy` checks the copy.

**Redaction**: `detect.RedactAndRescan(content, rules, options, detect.RedactOptions{})` replaces each detected secret with a `<REDACTED_rule>` label (overlapping or touching spans merged, bytes outside spans kept as is), then scans the redacted text again; it returns the text only when both scans are complete and the second finds nothing (`SanitizeNone`), otherwise no text (`SanitizeIncomplete`, `SanitizeResidual`) and the redacted copy is wiped. `detect.Redact(content, result, options)` redacts from a given result without a rescan and refuses an incomplete scan. Redaction is for a user who chooses to send a redacted version of their text (clipboard, chat message). A hook does not rewrite: it allows or blocks the text as is. A Claude Code mod can rewrite the prompt: `Expurgate` (below). Like detection, it lowers the risk, it does not remove it.

**Expurgation** (module `github.com/xsom-consulting/secret-guard/expurgation`, folder `expurgation/`, PolyForm Small Business 1.0.0, source-available: see License; the engine only recognises substitutes, with `detect.SubstituteText`, `detect.SecretRange` and `detect.FindSubstitutes`): `expurgation.ExpurgateAndRescan(content, rules, key, options, ordinal)` replaces only the secret part of each finding (the password of a URL or of `curl -u`, what follows `Bearer `, `Basic ` or `Token `, the body of a PEM key between its `BEGIN` and `END` lines; any other span, or a span merged from several rules, entirely, except that a complete token at the end of a line whose span takes the first word of the next line keeps the line break and the next line) with a typed substitute: the public prefix of the finding's rule (closed table `detect.SubstitutePrefixes()`, each prefix taken from a fixed-format rule of the initial Pack; passwords, entropy, URL, cookie and client-pack values get none), then, in brackets, the number from 1 to 999 given by the caller and the secret type of the rule (closed table `detect.SubstituteLabels()`, fallback `secret`), in French by default (`[secret masqué par xSOM n°1 : mot de passe, pas la vraie valeur]`) or in English with `expurgation.Options{SubstituteLanguage: detect.SubstituteEnglish}` (`[secret masked by xSOM #1: password, not the real value]`); nothing else of the value, neither its length nor any character. The engine recognises a substitute by an exact, closed grammar as a placeholder, so the expurgated text does not block on it (alone, or in shell, JSON, YAML, `.env`, URL, `Authorization: Bearer`, `curl -u`, cookie or PEM templates, also when an unquoted value is cut at its space, comma or hash sign); any text that does not follow the grammar exactly is still scanned. The former form (`X` then a number) is no longer recognised since v0.5.0. An expurgated text above 1 MiB fails (`SanitizeIncomplete`). A remaining finding is widened to its token, then to its line; beyond that, expurgation fails (no text, copies wiped). Each `Substitution` gives rule, secret type, replaced span in the original text (bytes and UTF-16 units), local fingerprint (with a key: that of exactly the original bytes replaced), number and substitute, never the value; `expurgation.Expurgate`, which has no key, keeps a finding's fingerprint only for its exact span and refuses otherwise (`expurgation.ErrSpan`). Vectors: `vectors/expurgate.json`. The provider learns the type of each secret and, for a fixed-format rule, its public prefix; no longer its length.

**Levels and decisions**: a finding's level comes from its score (LOW < 25 ≤ MEDIUM < 50 ≤ HIGH < 75 ≤ CRITICAL). `detect.DecisionForLevel(level)` returns Secret Guard's default decision (`ALLOW` for LOW, `WARN` for MEDIUM, `BLOCK` for HIGH, CRITICAL and any level outside this list): a preset, not a policy. The product that embeds the engine decides; xSOM Fleet maps levels to decisions through its published Policy and, with no published mapping, blocks whatever the level. An incomplete scan always blocks.

**Client rules pack** (`custom`): a client rules pack adds client-specific detectors to the built-in rules (internal identifiers and in-house number formats as patterns, project code names as confidential terms), calibrated and signed by whoever distributes it, judged and applied locally by the engine (contract: [docs/custom-pack.md](docs/custom-pack.md), schema `schema/CustomPack.json`). `custom.Compile(payload)` (signature already checked by the caller), then `detect.Scan(content, rules, detect.Options{Custom: p})`. Patterns are a safe regular expression subset validated with the contract's error codes and translated to RE2 with ECMAScript semantics; confidential terms exist in the pack only as salted SHA-256 digests of normalized n-grams (`secret-guard terms digest --salt <salt> terms.txt` computes them at the client, writing digests only). Findings are `xsom_<detector>`, `custom_rule`, score 90 or 40, byte span, never the value; bounded work with `custom_budget` and `custom_too_many` failures (incomplete scan, no finding); redaction names them after their detector label, then `<REDACTED_custom_rule>` if a secret remains. Parity with the original engine: `vectors/custom/`, declared and checked divergences in [UPSTREAM.md](UPSTREAM.md).

**Command line**: `secret-guard scan [--pack <file>] [--custom-pack <file>] [--language <id>] [--fingerprint-key <file>] [file|-]`, one-line JSON output; exit codes 0 (no finding), 1 (findings), 2 (error or incomplete scan, never "nothing found"). `secret-guard redact [--pack <file>] [--custom-pack <file>] [--language <id>] [file|-]` writes the redacted text on standard output; exit codes 0 (nothing to redact, text copied), 1 (redacted), 2 (error, incomplete scan or residual secret, nothing on standard output). `secret-guard hidden [--strip] [file|-]`: JSON report of hidden characters (same exit codes), or the cleaned text with `--strip`. `secret-guard mentions [file|-]`: JSON list of `@` mentions (exit code 0, or 2 on error). `secret-guard terms digest --salt <salt> [file|-]`: the `match` field of a terms detector, digests only.

**WebAssembly**: `cd expurgation && GOOS=wasip1 GOARCH=wasm go build -trimpath -buildvcs=false -ldflags="-s -w" -buildmode=c-shared -o ../dist/secret-guard.wasm ./cmd/secret-guard-wasm` (the module embeds expurgation: its Go code is in `expurgation/cmd/secret-guard-wasm`, and the built module and the npm package are `(Apache-2.0 AND PolyForm-Small-Business-1.0.0)`; the JavaScript loaders of `wasm/` stay Apache-2.0); WASI preview 1 reactor module (`scan`, `scanWithFingerprint`, `findHidden`, `redact`, `expurgate`) with dependency-free JavaScript loaders that open no file and no connection (`wasm/node.mjs` with `node:wasi`, `wasm/browser.mjs` with the minimal WASI layer `wasm/wasi.mjs`), tested under Node, with parity against the native Go engine on the whole corpus (`node --test wasm/parity.test.mjs`). The `wasm/` folder is the npm package `@xsom/secret-guard-wasm`; pushing a `vX.Y.Z` tag runs `.github/workflows/release.yml`: GitHub Release with `SHA256SUMS` and a signed build provenance attestation, then npm publication with provenance after approval. Measured on 13 October 2026 on one machine (Apple M2 Pro, Node 26.0.0, Go 1.27.2), indicative: 6.02 MB raw, 1.65 MB gzip, 1.21 MB brotli (with `findHidden` and `redact`); 20 ms startup (median of 10; 70 to 90 ms for the first instance of the process); 300 to 360 ms to scan 64 KiB depending on the run (native Go: 66 ms).

**Regenerating**: the TypeScript generator in `generator/` (Node 26) rebuilds the initial Pack, the engine patterns, the parity corpus, the redaction and decision vectors, the hidden and mention vectors and the Unicode tables of `hidden` (`npm run pack:initial`, `npm run vectors:detection -- --upstream <checkout> --check`, `npm run vectors:redact -- --upstream <checkout> --check`, `npm run vectors:hidden -- --upstream <checkout> --check`, `npm run vectors:custom -- --upstream <checkout> --check`, `npm run hidden:tables -- --check`). Never edit these files by hand.

**Security**: report vulnerabilities as described in [SECURITY.md](SECURITY.md) (private GitHub security advisory, never a public issue). Scan time is bounded by work budgets, not a clock: the caller sets its deadline.

**Personal data (v0.7.0)**: the initial Pack also detects IBANs (`iban`, ISO 13616 mod 97), French social security numbers (`fr_nir`, 97 − number mod 97 key, Corsican `2A`/`2B`), SIRET (`fr_siret`, Luhn and the La Poste sum rule), SIREN (`fr_siren`, Luhn, only after the word "SIREN") and payment card numbers (`payment_card`, Luhn and a network prefix), as fixed-pattern rules whose named validator checks the format's key (`iban_mod97`, `fr_nir_key`, `fr_siret_luhn`, `fr_siren_luhn`, `payment_card_luhn`), so phone, order and timestamp numbers of the same length are not findings. Secret types `iban`, `fr_social_security_number`, `fr_siret`, `fr_siren`, `payment_card_number` (levels: card HIGH, social security number HIGH, others MEDIUM). Validators run on the plain, normalized, percent and JSON-escaped readings, not on base64-decoded text. The IBAN pattern is generic and the engine keeps the longest group end whose key is valid, so a trailing four-character word is not absorbed. Cost: 64 KiB without secrets goes from 9.1 to 13.7 ms. Substitute types are added for the five rules (`SubstituteLabels()`). New parity cases: `vectors/detection/rules-personal-data.json` (80 cases, expected results from an independent second implementation of the checks, not from the original engine). The `RulePack` schema gains 5 secret types and 5 validators; an engine older than v0.7.0 refuses a Pack that uses them. Details: [docs/rule-pack.md](docs/rule-pack.md).

**Password announced in a sentence (v0.8.1)**: the `contextual_password` rule (type `password`, score 70, HIGH) also reads a password announced in plain French or English ("mon mdp <value>", "mot de passe : <value>", "le mot de passe est <value>", "my password is <value>"). Hints: `mdp`, `mot de passe`, `mot-de-passe`, `code d'accès`, `pass` (needs a link word or `:`/`=`), and the names the ordinary assignment classes as "password". Optional link on the same line: `est`, `is`, `c'est`, and `:`/`=` after a French hint or `pass` (English `password: …` stays with the ordinary assignment). Value: one word, quotes and final `. , ; : ?` removed, 8 to 256 code points, at least three classes among lowercase, uppercase, digits and other characters, not a placeholder, substitute, code or environment reference or URL. The finding covers the value only, so expurgation keeps the sentence. No new rule, no change to the `RulePack` schema or the initial Pack. New parity cases: `vectors/detection/rules-password-phrase.json` (27 cases, expected results from an independent second implementation).

**Migrating to v0.6.0**: expurgation leaves `detect` for the module `github.com/xsom-consulting/secret-guard/expurgation` (require it at the same version as the root): `detect.Expurgate`, `ExpurgateAndRescan`, `Substitution`, `SanitizeOrdinal` → `expurgation.Expurgate`, `ExpurgateAndRescan`, `Substitution`, `SanitizeOrdinal`; `detect.ErrExpurgate*` → `expurgation.ErrIncomplete`, `ErrSpan`, `ErrEncoding`, `ErrOrdinal`, `ErrLanguage`; `Options.SubstituteLanguage` → `expurgation.Options{Options: detect.Options{…}, SubstituteLanguage: …}`; new public primitives of `detect`: `ScanWith`, `Fingerprint`, `FingerprintKey.Usable`, `SecretRange`, `Rules.FirstLineSecretEnd`, `SubstituteText`, `SubstituteLanguage.Valid`, `ErrSubstituteOrdinal`, `ErrSubstituteLanguage`. Expurgated texts, substitutes and refusals are unchanged (`vectors/expurgate.json`).

**License**: two Go modules, two licenses.

- Detection (`detect`, `pack`, `custom`, `hidden`, `mentions`), redaction, substitute recognition, formats, corpus and vectors, command line, JavaScript loaders and generator: module `github.com/xsom-consulting/secret-guard` (root), Apache-2.0, an open source license ([LICENSE](LICENSE), [NOTICE](NOTICE)). Importing the root compiles no PolyForm code.
- Expurgation, the WebAssembly module that embeds it and its parity tool: module `github.com/xsom-consulting/secret-guard/expurgation` (`expurgation/`), PolyForm Small Business 1.0.0, source-available ([expurgation/LICENSE](expurgation/LICENSE)): free for a company with fewer than 100 people (employees and contractors) and less than 1,000,000 USD revenue in the prior tax year, including the organizations that control it, that it controls or under common control with it (see the license text); beyond that, including for an evaluation, a written license from xSOM Consulting ([COMMERCIAL.md](COMMERCIAL.md)). xSOM Fleet customers receive it with their contract. The npm package is `(Apache-2.0 AND PolyForm-Small-Business-1.0.0)`.
- Versioning: the `expurgation` module reads the root's `internal/` packages, so it is only valid with the root at the same version. Both modules are tagged together on the same commit (`vX.Y.Z` and `expurgation/vX.Y.Z`, pushed with `git push --atomic`), `expurgation/go.mod` requires the root at that version (checked by `release.yml`), and a consumer requires the same version of both modules.
- Versions v0.1.0 to v0.5.1 remain entirely Apache-2.0. Each source file carries the SPDX identifier of its module (`go run ./tools/spdxcheck`). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).
