# Secret Guard

[Français](#français) · [English](#english)

## Français

Secret Guard est un moteur de détection de secrets (clés d'API, jetons, clés privées, mots de passe, URL à identifiants…) dans un texte, écrit en Go. Il analyse localement, dans le processus qui l'appelle : c'est la brique qui lit un prompt ou un fichier avant qu'il ne parte vers un assistant de code, et ce dépôt est public pour que chacun puisse le vérifier.

C'est le portage en Go du moteur TypeScript de Secret Guard (origine, licence et modifications : [UPSTREAM.md](UPSTREAM.md)). Le portage rend exactement les résultats de l'original sur un corpus figé de 823 cas (`TestParity`).

Deux paquets l'accompagnent, portés de la même origine : `hidden` (instructions cachées dans un texte) et `mentions` (fichiers cités par « @ » dans un prompt).

### Ce que fait le moteur

- 35 règles (Pack initial, `pack/initial/pack.json`) : formats fixes de jetons connus, clés privées PEM, URL à identifiants, affectations sensibles (`password = …`, en-têtes, cookies, `curl -u`, `auth` de Docker), entropie.
- Plusieurs lectures du même texte : telle quelle, normalisée (NFKC, caractères invisibles retirés), décodée une fois (pourcentage, échappements JSON, base64), lignes coupées rejointes.
- Expressions régulières RE2 seulement (`regexp` de Go) : temps linéaire, aucun retour arrière.
- Travail borné : entrée de 1 Mio au plus, budgets de décodages, de fenêtres et de vues ; au-delà, l'analyse est déclarée incomplète.
- Vitesse : le 19 octobre 2026, sur un Apple M2 Pro, 64 Kio de code sans secret sont analysés en 9,2 ms (67,5 ms en v0.3.0, ×7,4), grâce à une porte littérale exacte et à l'exécution en parallèle des familles de règles sans budget partagé, sans changer un seul résultat ([docs/bench.md](docs/bench.md)).

### Ce qu'il ne fait jamais

- **Aucun réseau, aucune télémétrie, aucun modèle de langage.** Le moteur (`detect`, `pack`, `custom`, `hidden`, `mentions`) n'importe ni réseau, ni fichier, ni horloge, ni hasard, ni journal : règle `depguard` de [.golangci.yml](.golangci.yml), prouvée import par import par `go run ./tools/depguardcheck`. Le module WebAssembly n'importe aucune fonction réseau (`sock_*`) ni d'ouverture de fichier (`path_open`) : test `wasm/secret-guard.test.mjs`.
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

Le masquage sert quand l'utilisateur choisit d'envoyer une version expurgée de son texte (presse-papiers, message d'un chat). Il ne sert pas à un hook d'assistant de code : un hook ne peut qu'autoriser ou bloquer l'envoi tel quel, il ne réécrit pas le prompt. Comme la détection, le masquage réduit le risque, il ne le supprime pas.

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

```sh
GOOS=wasip1 GOARCH=wasm go build -trimpath -ldflags="-s -w" -buildmode=c-shared -o dist/secret-guard.wasm ./cmd/secret-guard-wasm
node --test wasm/secret-guard.test.mjs
node --no-warnings wasm/bench.mjs
```

Module WASI preview 1 en mode bibliothèque : instancié une fois, il garde ses règles chargées et analyse ou masque à la demande (`scan`, `scanWithFingerprint`, `findHidden`, le rapport de `secret-guard hidden`, et `redact`, qui rend `{ failure, initial, final, redacted }`, `redacted` valant `null` si le masquage échoue) ; `wasm/secret-guard.mjs` est un chargeur sans dépendance (`node:wasi` sous Node, une couche WASI ailleurs). Choix de `wasip1` plutôt que `js/wasm` : interface WASI standard sans colle JavaScript liée à une version exacte de Go (`wasm_exec.js`), exécutable par Node, Wasmtime ou une couche WASI de navigateur, et la liste des fonctions importées montre ce que le module peut faire (ni réseau, ni ouverture de fichier). La ligne de commande se construit aussi pour WASI (`GOOS=wasip1 GOARCH=wasm go build ./cmd/secret-guard`).

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
go test -count=1 -v -run '^TestParity$' ./detect
go test -count=1 -v -run '^(TestRedactParity|TestDecisionParity|TestRedactLeavesNoValue)$' ./detect   # masquage et décisions
go test -count=1 -v -run '^TestHiddenParity$' ./hidden
go test -count=1 -v -run '^TestMentionsParity$' ./mentions
go test -count=1 -v -run '^TestCustom' ./custom ./detect      # Pack de règles du client
go run ./tools/covercheck coverage.out     # detect, pack, custom, hidden, mentions, internal ≥ 80 %
go run ./tools/depguardcheck                # chaque import interdit est refusé
gitleaks dir . && gitleaks git .
```

Fuzz : `go test ./detect -run '^$' -fuzz '^FuzzScan$' -fuzztime=60s` (autres cibles : `FuzzRedact`, `FuzzTextViews`, `FuzzBase64Candidates`, `FuzzDecodeBase64`, `FuzzJWT`, `FuzzRuleFamilies`…, et `FuzzHiddenFind` dans `./hidden`, `FuzzMentions` dans `./mentions`, `FuzzCustomPattern` et `FuzzCustomPackDecode` dans `./custom`).

### Sécurité

Signaler une vulnérabilité par un avis de sécurité privé GitHub (onglet « Security » du dépôt), jamais par un ticket public. Le temps d'une analyse est borné par des budgets de travail, pas par une horloge : le pire cas mesuré (1 Mio d'expansion NFKC maximale) prend quelques secondes en Go natif ; l'appelant fixe son échéance. Les fichiers de cas du corpus `vectors/detection/` et les vecteurs du masquage `vectors/redact.json` contiennent des valeurs synthétiques à la forme de jetons : ce sont les seules exceptions de la recherche de secrets ([.gitleaks.toml](.gitleaks.toml)).

### Licence

Apache 2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)). Composants tiers et origine : [UPSTREAM.md](UPSTREAM.md).

## English

Secret Guard is a secret detection engine (API keys, tokens, private keys, passwords, URLs with credentials…) for text, written in Go. It runs locally, inside the calling process: it is the piece that reads a prompt or a file before it goes to a coding assistant, and this repository is public so that anyone can check it.

It is the Go port of the Secret Guard TypeScript engine (origin, license and changes: [UPSTREAM.md](UPSTREAM.md)). The port returns exactly the original results on a frozen corpus of 823 cases (`TestParity`).

**What it does**: 35 rules (initial Pack), several readings of the same text (as is, NFKC-normalized, decoded once from percent, JSON escapes and base64, wrapped lines joined), RE2 regular expressions only (linear time), bounded work (1 MiB input, decoding, window and view budgets). Speed: on 19 October 2026, on an Apple M2 Pro, 64 KiB of code without secrets is scanned in 9.2 ms (67.5 ms in v0.3.0, ×7.4), thanks to an exact literal gate and to running the rule families without shared budget in parallel, with no result changed ([docs/bench.md](docs/bench.md)).

**What it never does**: no network, no telemetry, no language model (the engine, `custom`, `hidden` and `mentions` import no network, file, clock, randomness or logging package: `depguard` rule proven by `tools/depguardcheck`; the WebAssembly module imports no `sock_*` or `path_open`); no detected value in the output (a finding carries rule, secret type, reading, score, level and byte span, never the value, an excerpt, a mask or an unsalted hash); never "nothing found" by default (an incomplete scan returns `complete: false` and no finding, so the caller blocks). The engine only finds what its rules describe: it lowers the risk, it does not remove it.

**Hidden instructions** (`hidden`): `hidden.Find(text)` reports characters a person cannot see but a model reads: Unicode tag characters ("ASCII smuggling"), bidirectional embeddings, overrides and isolates ("Trojan Source", CVE-2021-42574), runs of zero-width and other default-ignorable characters, runs of variation selectors. Legitimate uses stay silent (subdivision flags, joiners in emoji and in joining scripts, one variation selector after its base, Mongolian variation selectors, soft hyphens between letters, a leading byte-order mark, directional marks). Each finding carries kind, line, column, count and byte span, never what the characters spell; `Complete` is false beyond 1 MiB. `hidden.Strip(text)` removes exactly what `Find` reports and always returns valid UTF-8 (an invalid byte becomes U+FFFD, so that removing a neighbour cannot form a new character). Parity: 152 cases produced by the original `hidden.ts` (`TestHiddenParity`).

**@-mentioned files** (`mentions`): Claude Code adds the content of a file referenced with `@` in a prompt without any tool call, so no `PreToolUse` hook fires for it, not even one matching `Read` ([hooks documentation](https://code.claude.com/docs/en/hooks)). `mentions.Parse(prompt)` finds these files (`@path`, `@"path with spaces"`, `@path#L10-20`, trailing `, ; : ! ? )` removed, e-mail addresses ignored, duplicates merged) without reading or resolving anything, so that a `UserPromptSubmit` hook can resolve, read (as the user) and scan them itself. Parity: 122 cases produced by the original `mentionedPaths` (`TestMentionsParity`).

**Go API**: `pack.Initial()` or `pack.Decode(bytes)` (strict RulePack decoding), `detect.LoadRules(pack)`, `detect.Scan(content, rules, detect.Options{LanguageID: …})`, `detect.ScanWithFingerprint(content, rules, key)` (local fingerprint: HMAC-SHA256 truncated to 16 bytes under a 32-byte caller key). `detect.Options{Workers: n}` bounds the number of threads of a scan (0, the default: at most 8; 1: sequential, single thread); the result is the same whatever `Workers` is, and the engine never reads the number of processors. Decide on `Result.Complete` and `Result.Failure`, never on the number of findings. The Pack schema is a copy; the program that signs and distributes Packs (xSOM Fleet) remains the source of the signed contract, and `TestSchemaCopy` checks the copy.

**Redaction**: `detect.RedactAndRescan(content, rules, options, detect.RedactOptions{})` replaces each detected secret with a `<REDACTED_rule>` label (overlapping or touching spans merged, bytes outside spans kept as is), then scans the redacted text again; it returns the text only when both scans are complete and the second finds nothing (`SanitizeNone`), otherwise no text (`SanitizeIncomplete`, `SanitizeResidual`) and the redacted copy is wiped. `detect.Redact(content, result, options)` redacts from a given result without a rescan and refuses an incomplete scan. Redaction is for a user who chooses to send a redacted version of their text (clipboard, chat message); it is not for a coding assistant hook, which can only allow or block the text as is. Like detection, it lowers the risk, it does not remove it.

**Levels and decisions**: a finding's level comes from its score (LOW < 25 ≤ MEDIUM < 50 ≤ HIGH < 75 ≤ CRITICAL). `detect.DecisionForLevel(level)` returns Secret Guard's default decision (`ALLOW` for LOW, `WARN` for MEDIUM, `BLOCK` for HIGH, CRITICAL and any level outside this list): a preset, not a policy. The product that embeds the engine decides; xSOM Fleet maps levels to decisions through its published Policy and, with no published mapping, blocks whatever the level. An incomplete scan always blocks.

**Client rules pack** (`custom`): a client rules pack adds client-specific detectors to the built-in rules (internal identifiers and in-house number formats as patterns, project code names as confidential terms), calibrated and signed by whoever distributes it, judged and applied locally by the engine (contract: [docs/custom-pack.md](docs/custom-pack.md), schema `schema/CustomPack.json`). `custom.Compile(payload)` (signature already checked by the caller), then `detect.Scan(content, rules, detect.Options{Custom: p})`. Patterns are a safe regular expression subset validated with the contract's error codes and translated to RE2 with ECMAScript semantics; confidential terms exist in the pack only as salted SHA-256 digests of normalized n-grams (`secret-guard terms digest --salt <salt> terms.txt` computes them at the client, writing digests only). Findings are `xsom_<detector>`, `custom_rule`, score 90 or 40, byte span, never the value; bounded work with `custom_budget` and `custom_too_many` failures (incomplete scan, no finding); redaction names them after their detector label, then `<REDACTED_custom_rule>` if a secret remains. Parity with the original engine: `vectors/custom/`, declared and checked divergences in [UPSTREAM.md](UPSTREAM.md).

**Command line**: `secret-guard scan [--pack <file>] [--custom-pack <file>] [--language <id>] [--fingerprint-key <file>] [file|-]`, one-line JSON output; exit codes 0 (no finding), 1 (findings), 2 (error or incomplete scan, never "nothing found"). `secret-guard redact [--pack <file>] [--custom-pack <file>] [--language <id>] [file|-]` writes the redacted text on standard output; exit codes 0 (nothing to redact, text copied), 1 (redacted), 2 (error, incomplete scan or residual secret, nothing on standard output). `secret-guard hidden [--strip] [file|-]`: JSON report of hidden characters (same exit codes), or the cleaned text with `--strip`. `secret-guard mentions [file|-]`: JSON list of `@` mentions (exit code 0, or 2 on error). `secret-guard terms digest --salt <salt> [file|-]`: the `match` field of a terms detector, digests only.

**WebAssembly**: `GOOS=wasip1 GOARCH=wasm go build -trimpath -ldflags="-s -w" -buildmode=c-shared -o dist/secret-guard.wasm ./cmd/secret-guard-wasm`; WASI preview 1 reactor module (`scan`, `scanWithFingerprint`, `findHidden`, `redact`) with a dependency-free JavaScript loader (`wasm/secret-guard.mjs`), tested under Node (`node --test wasm/secret-guard.test.mjs`). Measured on 13 October 2026 on one machine (Apple M2 Pro, Node 26.0.0, Go 1.27.2), indicative: 6.02 MB raw, 1.65 MB gzip, 1.21 MB brotli (with `findHidden` and `redact`); 20 ms startup (median of 10; 70 to 90 ms for the first instance of the process); 300 to 360 ms to scan 64 KiB depending on the run (native Go: 66 ms).

**Regenerating**: the TypeScript generator in `generator/` (Node 26) rebuilds the initial Pack, the engine patterns, the parity corpus, the redaction and decision vectors, the hidden and mention vectors and the Unicode tables of `hidden` (`npm run pack:initial`, `npm run vectors:detection -- --upstream <checkout> --check`, `npm run vectors:redact -- --upstream <checkout> --check`, `npm run vectors:hidden -- --upstream <checkout> --check`, `npm run vectors:custom -- --upstream <checkout> --check`, `npm run hidden:tables -- --check`). Never edit these files by hand.

**Security**: report vulnerabilities through a private GitHub security advisory, never a public issue. Scan time is bounded by work budgets, not a clock: the caller sets its deadline.

**License**: Apache 2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)).
