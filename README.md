# Secret Guard

[Français](#français) · [English](#english)

## Français

Secret Guard est un moteur de détection de secrets (clés d'API, jetons, clés privées, mots de passe, URL à identifiants…) dans un texte, écrit en Go. Il analyse localement, dans le processus qui l'appelle : c'est la brique qui lit un prompt ou un fichier avant qu'il ne parte vers un assistant de code, et ce dépôt est public pour que chacun puisse le vérifier.

C'est le portage en Go du moteur TypeScript de Secret Guard (origine, licence et modifications : [UPSTREAM.md](UPSTREAM.md)). Le portage rend exactement les résultats de l'original sur un corpus figé de 823 cas (`TestParity`).

### Ce que fait le moteur

- 35 règles (Pack initial, `pack/initial/pack.json`) : formats fixes de jetons connus, clés privées PEM, URL à identifiants, affectations sensibles (`password = …`, en-têtes, cookies, `curl -u`, `auth` de Docker), entropie.
- Plusieurs lectures du même texte : telle quelle, normalisée (NFKC, caractères invisibles retirés), décodée une fois (pourcentage, échappements JSON, base64), lignes coupées rejointes.
- Expressions régulières RE2 seulement (`regexp` de Go) : temps linéaire, aucun retour arrière.
- Travail borné : entrée de 1 Mio au plus, budgets de décodages, de fenêtres et de vues ; au-delà, l'analyse est déclarée incomplète.

### Ce qu'il ne fait jamais

- **Aucun réseau, aucune télémétrie, aucun modèle de langage.** Le moteur (`detect`, `pack`) n'importe ni réseau, ni fichier, ni horloge, ni hasard, ni journal : règle `depguard` de [.golangci.yml](.golangci.yml), prouvée import par import par `go run ./tools/depguardcheck`. Le module WebAssembly n'importe aucune fonction réseau (`sock_*`) ni d'ouverture de fichier (`path_open`) : test `wasm/secret-guard.test.mjs`.
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

### Ligne de commande

```sh
go install github.com/xsom-consulting/secret-guard/cmd/secret-guard@latest
secret-guard scan fichier.env          # ou : cat fichier | secret-guard scan -
secret-guard scan --pack autre-pack.json --language dotenv fichier.env
secret-guard scan --fingerprint-key cle.hex fichier.env   # cle.hex : 64 caractères hexadécimaux, lue, jamais écrite
secret-guard redact fichier.env > fichier.masque.env       # code 2 : rien n'est écrit (fichier vide)
secret-guard version
```

Sortie : un document JSON sur une ligne, `{"complete":true,"failure":"none","findings":[{"ruleId":"github_token","secretType":"provider_token","encoding":"plain","score":95,"level":"CRITICAL","byteStart":6,"byteEnd":46}]}`.

| Code de sortie | Sens |
|---|---|
| 0 | analyse complète, aucun constat |
| 1 | analyse complète, au moins un constat |
| 2 | erreur (usage, lecture, Pack refusé) ou analyse incomplète, qui ne vaut jamais « rien trouvé » |

`secret-guard redact [--pack <fichier>] [--language <id>] [fichier|-]` écrit sur la sortie standard le texte masqué (voir « Masquage »), et seulement lui :

| Code de sortie de `redact` | Sens |
|---|---|
| 0 | rien à masquer : le texte est recopié tel quel |
| 1 | au moins un secret masqué |
| 2 | erreur, analyse incomplète ou secret qui subsiste après masquage : rien sur la sortie standard, la raison sur la sortie d'erreur |

### WebAssembly

```sh
GOOS=wasip1 GOARCH=wasm go build -trimpath -ldflags="-s -w" -buildmode=c-shared -o dist/secret-guard.wasm ./cmd/secret-guard-wasm
node --test wasm/secret-guard.test.mjs
node --no-warnings wasm/bench.mjs
```

Module WASI preview 1 en mode bibliothèque : instancié une fois, il garde ses règles chargées et analyse ou masque à la demande (`guard.scan(octets)`, `guard.redact(octets)`, qui rend `{ failure, initial, final, redacted }`, `redacted` valant `null` si le masquage échoue) ; `wasm/secret-guard.mjs` est un chargeur sans dépendance (`node:wasi` sous Node, une couche WASI ailleurs). Choix de `wasip1` plutôt que `js/wasm` : interface WASI standard sans colle JavaScript liée à une version exacte de Go (`wasm_exec.js`), exécutable par Node, Wasmtime ou une couche WASI de navigateur, et la liste des fonctions importées montre ce que le module peut faire (ni réseau, ni ouverture de fichier). La ligne de commande se construit aussi pour WASI (`GOOS=wasip1 GOARCH=wasm go build ./cmd/secret-guard`).

Mesures du 13 octobre 2026 sur une seule machine (Apple M2 Pro, Node 26.0.0, Go 1.27.2, `node wasm/bench.mjs`, trois séries), indicatives :

| Mesure | Valeur |
|---|---|
| Taille du `.wasm` (masquage compris) | 5,99 Mo brut ; 1,64 Mo gzip -9 ; 1,21 Mo brotli |
| Démarrage (compilation, instanciation, Pack initial chargé), médiane de 10 | 20 ms (première instance du processus : 70 à 90 ms) |
| Première analyse d'un texte court | 9 ms |
| Analyse de 64 Kio (entrée de `BenchmarkScan64KiB`), médiane de 20 | 300 à 360 ms selon la série, minimum 304 ms (Go natif : 66 ms) |

### Régénérer le Pack initial et le corpus

Le générateur TypeScript est dans `generator/` (Node 26, `npm ci`). Il n'est pas dans le moteur livré.

```sh
cd generator
npm ci
npm test                                   # Pack, motifs du moteur, corpus, Unicode, Empreintes locales
npm run pack:initial                       # pack/initial/pack.json et detect/engine_patterns.go
npm run vectors:detection -- --upstream <checkout> --check   # corpus : réservé à xSOM (checkout du dépôt d'origine privé, voir UPSTREAM.md)
npm run vectors:redact -- --upstream <checkout> --check      # vecteurs du masquage et des décisions (même checkout)
npm run vectors:unicode                    # vectors/unicode-parity.json (montée de version Unicode seulement)
```

Ne jamais éditer `pack.json`, `engine_patterns.go`, le corpus ni les vecteurs du masquage (`vectors/redact.json`, `vectors/decision.json`) à la main. Toute évolution des règles ajoute ses cas au corpus.

### Vérifier

```sh
go vet ./... && golangci-lint run && go test -count=1 -coverprofile=coverage.out ./...
go test -count=1 -v -run '^TestParity$' ./detect
go test -count=1 -v -run '^(TestRedactParity|TestDecisionParity|TestRedactLeavesNoValue)$' ./detect   # masquage et décisions
go run ./tools/covercheck coverage.out     # detect, pack, internal ≥ 80 %
go run ./tools/depguardcheck                # chaque import interdit est refusé
gitleaks dir . && gitleaks git .
```

Fuzz : `go test ./detect -run '^$' -fuzz '^FuzzScan$' -fuzztime=60s` (autres cibles : `FuzzRedact`, `FuzzTextViews`, `FuzzBase64Candidates`, `FuzzDecodeBase64`, `FuzzJWT`, `FuzzRuleFamilies`…).

### Sécurité

Signaler une vulnérabilité par un avis de sécurité privé GitHub (onglet « Security » du dépôt), jamais par un ticket public. Le temps d'une analyse est borné par des budgets de travail, pas par une horloge : le pire cas mesuré (1 Mio d'expansion NFKC maximale) prend quelques secondes en Go natif ; l'appelant fixe son échéance. Les fichiers de cas du corpus `vectors/detection/` et les vecteurs du masquage `vectors/redact.json` contiennent des valeurs synthétiques à la forme de jetons : ce sont les seules exceptions de la recherche de secrets ([.gitleaks.toml](.gitleaks.toml)).

### Licence

Apache 2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)). Composants tiers et origine : [UPSTREAM.md](UPSTREAM.md).

## English

Secret Guard is a secret detection engine (API keys, tokens, private keys, passwords, URLs with credentials…) for text, written in Go. It runs locally, inside the calling process: it is the piece that reads a prompt or a file before it goes to a coding assistant, and this repository is public so that anyone can check it.

It is the Go port of the Secret Guard TypeScript engine (origin, license and changes: [UPSTREAM.md](UPSTREAM.md)). The port returns exactly the original results on a frozen corpus of 823 cases (`TestParity`).

**What it does**: 35 rules (initial Pack), several readings of the same text (as is, NFKC-normalized, decoded once from percent, JSON escapes and base64, wrapped lines joined), RE2 regular expressions only (linear time), bounded work (1 MiB input, decoding, window and view budgets).

**What it never does**: no network, no telemetry, no language model (the engine imports no network, file, clock, randomness or logging package: `depguard` rule proven by `tools/depguardcheck`; the WebAssembly module imports no `sock_*` or `path_open`); no detected value in the output (a finding carries rule, secret type, reading, score, level and byte span, never the value, an excerpt, a mask or an unsalted hash); never "nothing found" by default (an incomplete scan returns `complete: false` and no finding, so the caller blocks). The engine only finds what its rules describe: it lowers the risk, it does not remove it.

**Go API**: `pack.Initial()` or `pack.Decode(bytes)` (strict RulePack decoding), `detect.LoadRules(pack)`, `detect.Scan(content, rules, detect.Options{LanguageID: …})`, `detect.ScanWithFingerprint(content, rules, key)` (local fingerprint: HMAC-SHA256 truncated to 16 bytes under a 32-byte caller key). Decide on `Result.Complete` and `Result.Failure`, never on the number of findings. The Pack schema is a copy; the program that signs and distributes Packs (xSOM Fleet) remains the source of the signed contract, and `TestSchemaCopy` checks the copy.

**Redaction**: `detect.RedactAndRescan(content, rules, options, detect.RedactOptions{})` replaces each detected secret with a `<REDACTED_rule>` label (overlapping or touching spans merged, bytes outside spans kept as is), then scans the redacted text again; it returns the text only when both scans are complete and the second finds nothing (`SanitizeNone`), otherwise no text (`SanitizeIncomplete`, `SanitizeResidual`) and the redacted copy is wiped. `detect.Redact(content, result, options)` redacts from a given result without a rescan and refuses an incomplete scan. Redaction is for a user who chooses to send a redacted version of their text (clipboard, chat message); it is not for a coding assistant hook, which can only allow or block the text as is. Like detection, it lowers the risk, it does not remove it.

**Levels and decisions**: a finding's level comes from its score (LOW < 25 ≤ MEDIUM < 50 ≤ HIGH < 75 ≤ CRITICAL). `detect.DecisionForLevel(level)` returns Secret Guard's default decision (`ALLOW` for LOW, `WARN` for MEDIUM, `BLOCK` for HIGH, CRITICAL and any level outside this list): a preset, not a policy. The product that embeds the engine decides; xSOM Fleet maps levels to decisions through its published Policy and, with no published mapping, blocks whatever the level. An incomplete scan always blocks.

**Command line**: `secret-guard scan [--pack <file>] [--language <id>] [--fingerprint-key <file>] [file|-]`, one-line JSON output; exit codes 0 (no finding), 1 (findings), 2 (error or incomplete scan, never "nothing found"). `secret-guard redact [--pack <file>] [--language <id>] [file|-]` writes the redacted text on standard output; exit codes 0 (nothing to redact, text copied), 1 (redacted), 2 (error, incomplete scan or residual secret, nothing on standard output).

**WebAssembly**: `GOOS=wasip1 GOARCH=wasm go build -trimpath -ldflags="-s -w" -buildmode=c-shared -o dist/secret-guard.wasm ./cmd/secret-guard-wasm`; WASI preview 1 reactor module with a dependency-free JavaScript loader (`wasm/secret-guard.mjs`: `scan(bytes)`, `redact(bytes)`), tested under Node (`node --test wasm/secret-guard.test.mjs`). Measured on 13 October 2026 on one machine (Apple M2 Pro, Node 26.0.0, Go 1.27.2), indicative: 5.99 MB raw (redaction included), 1.64 MB gzip, 1.21 MB brotli; 20 ms startup (median of 10; 70 to 90 ms for the first instance of the process); 300 to 360 ms to scan 64 KiB depending on the run (native Go: 66 ms).

**Regenerating**: the TypeScript generator in `generator/` (Node 26) rebuilds the initial Pack, the engine patterns, the parity corpus and the redaction and decision vectors (`npm run pack:initial`, `npm run vectors:detection -- --upstream <checkout> --check`, `npm run vectors:redact -- --upstream <checkout> --check`). Never edit these files by hand.

**Security**: report vulnerabilities through a private GitHub security advisory, never a public issue. Scan time is bounded by work budgets, not a clock: the caller sets its deadline.

**License**: Apache 2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)).
