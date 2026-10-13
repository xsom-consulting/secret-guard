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

Le schéma du Pack (`schema/RulePack.json`, [docs/rule-pack.md](docs/rule-pack.md)) est une copie : le programme qui signe et distribue des Packs (xSOM Fleet) reste la source du contrat signé. Le test `TestSchemaCopy` compare le type `pack.Pack` à cette copie. Le moteur ne vérifie aucune signature : vérifier un Pack signé est l'affaire de celui qui le distribue, avant `pack.Decode`.

### Ligne de commande

```sh
go install github.com/xsom-consulting/secret-guard/cmd/secret-guard@latest
secret-guard scan fichier.env          # ou : cat fichier | secret-guard scan -
secret-guard scan --pack autre-pack.json --language dotenv fichier.env
secret-guard scan --fingerprint-key cle.hex fichier.env   # cle.hex : 64 caractères hexadécimaux, lue, jamais écrite
secret-guard version
```

Sortie : un document JSON sur une ligne, `{"complete":true,"failure":"none","findings":[{"ruleId":"github_token","secretType":"provider_token","encoding":"plain","score":95,"level":"CRITICAL","byteStart":6,"byteEnd":46}]}`.

| Code de sortie | Sens |
|---|---|
| 0 | analyse complète, aucun constat |
| 1 | analyse complète, au moins un constat |
| 2 | erreur (usage, lecture, Pack refusé) ou analyse incomplète, qui ne vaut jamais « rien trouvé » |

### WebAssembly

```sh
GOOS=wasip1 GOARCH=wasm go build -trimpath -ldflags="-s -w" -buildmode=c-shared -o dist/secret-guard.wasm ./cmd/secret-guard-wasm
node --test wasm/secret-guard.test.mjs
node --no-warnings wasm/bench.mjs
```

Module WASI preview 1 en mode bibliothèque : instancié une fois, il garde ses règles chargées et analyse à la demande ; `wasm/secret-guard.mjs` est un chargeur sans dépendance (`node:wasi` sous Node, une couche WASI ailleurs). Choix de `wasip1` plutôt que `js/wasm` : interface WASI standard sans colle JavaScript liée à une version exacte de Go (`wasm_exec.js`), exécutable par Node, Wasmtime ou une couche WASI de navigateur, et la liste des fonctions importées montre ce que le module peut faire (ni réseau, ni ouverture de fichier). La ligne de commande se construit aussi pour WASI (`GOOS=wasip1 GOARCH=wasm go build ./cmd/secret-guard`).

Mesures du 13 octobre 2026 sur une seule machine (Apple M2 Pro, Node 26.0.0, Go 1.27.2, `node wasm/bench.mjs`, trois séries), indicatives :

| Mesure | Valeur |
|---|---|
| Taille du `.wasm` | 5,97 Mo brut ; 1,64 Mo gzip -9 ; 1,20 Mo brotli |
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
npm run vectors:detection -- --upstream <checkout> --check   # corpus, checkout de jt33120/poc-AI_guard au commit d'UPSTREAM.md
npm run vectors:unicode                    # vectors/unicode-parity.json (montée de version Unicode seulement)
```

Ne jamais éditer `pack.json`, `engine_patterns.go` ni le corpus à la main. Toute évolution des règles ajoute ses cas au corpus.

### Vérifier

```sh
go vet ./... && golangci-lint run && go test -count=1 -coverprofile=coverage.out ./...
go test -count=1 -v -run '^TestParity$' ./detect
go run ./tools/covercheck coverage.out     # detect, pack, internal ≥ 80 %
go run ./tools/depguardcheck                # chaque import interdit est refusé
gitleaks dir . && gitleaks git .
```

Fuzz : `go test ./detect -run '^$' -fuzz '^FuzzScan$' -fuzztime=60s` (autres cibles : `FuzzTextViews`, `FuzzBase64Candidates`, `FuzzDecodeBase64`, `FuzzJWT`, `FuzzRuleFamilies`…).

### Sécurité

Signaler une vulnérabilité par un avis de sécurité privé GitHub (onglet « Security » du dépôt), jamais par un ticket public. Le temps d'une analyse est borné par des budgets de travail, pas par une horloge : le pire cas mesuré (1 Mio d'expansion NFKC maximale) prend quelques secondes en Go natif ; l'appelant fixe son échéance. Le fichier de corpus `vectors/detection/` contient des valeurs synthétiques à la forme de jetons : c'est la seule exception de la recherche de secrets ([.gitleaks.toml](.gitleaks.toml)).

### Licence

Apache 2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)). Composants tiers et origine : [UPSTREAM.md](UPSTREAM.md).

## English

Secret Guard is a secret detection engine (API keys, tokens, private keys, passwords, URLs with credentials…) for text, written in Go. It runs locally, inside the calling process: it is the piece that reads a prompt or a file before it goes to a coding assistant, and this repository is public so that anyone can check it.

It is the Go port of the Secret Guard TypeScript engine (origin, license and changes: [UPSTREAM.md](UPSTREAM.md)). The port returns exactly the original results on a frozen corpus of 823 cases (`TestParity`).

**What it does**: 35 rules (initial Pack), several readings of the same text (as is, NFKC-normalized, decoded once from percent, JSON escapes and base64, wrapped lines joined), RE2 regular expressions only (linear time), bounded work (1 MiB input, decoding, window and view budgets).

**What it never does**: no network, no telemetry, no language model (the engine imports no network, file, clock, randomness or logging package: `depguard` rule proven by `tools/depguardcheck`; the WebAssembly module imports no `sock_*` or `path_open`); no detected value in the output (a finding carries rule, secret type, reading, score, level and byte span, never the value, an excerpt, a mask or an unsalted hash); never "nothing found" by default (an incomplete scan returns `complete: false` and no finding, so the caller blocks). The engine only finds what its rules describe: it lowers the risk, it does not remove it.

**Go API**: `pack.Initial()` or `pack.Decode(bytes)` (strict RulePack decoding), `detect.LoadRules(pack)`, `detect.Scan(content, rules, detect.Options{LanguageID: …})`, `detect.ScanWithFingerprint(content, rules, key)` (local fingerprint: HMAC-SHA256 truncated to 16 bytes under a 32-byte caller key). Decide on `Result.Complete` and `Result.Failure`, never on the number of findings. The Pack schema is a copy; the program that signs and distributes Packs (xSOM Fleet) remains the source of the signed contract, and `TestSchemaCopy` checks the copy.

**Command line**: `secret-guard scan [--pack <file>] [--language <id>] [--fingerprint-key <file>] [file|-]`, one-line JSON output; exit codes 0 (no finding), 1 (findings), 2 (error or incomplete scan, never "nothing found").

**WebAssembly**: `GOOS=wasip1 GOARCH=wasm go build -trimpath -ldflags="-s -w" -buildmode=c-shared -o dist/secret-guard.wasm ./cmd/secret-guard-wasm`; WASI preview 1 reactor module with a dependency-free JavaScript loader (`wasm/secret-guard.mjs`), tested under Node (`node --test wasm/secret-guard.test.mjs`). Measured on 13 October 2026 on one machine (Apple M2 Pro, Node 26.0.0, Go 1.27.2), indicative: 5.97 MB raw, 1.64 MB gzip, 1.20 MB brotli; 20 ms startup (median of 10; 70 to 90 ms for the first instance of the process); 300 to 360 ms to scan 64 KiB depending on the run (native Go: 66 ms).

**Regenerating**: the TypeScript generator in `generator/` (Node 26) rebuilds the initial Pack, the engine patterns and the parity corpus (`npm run pack:initial`, `npm run vectors:detection -- --upstream <checkout> --check`). Never edit these files by hand.

**Security**: report vulnerabilities through a private GitHub security advisory, never a public issue. Scan time is bounded by work budgets, not a clock: the caller sets its deadline.

**License**: Apache 2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)).
