package detect

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// syntheticGitHubToken est une valeur synthétique de la règle github_token, construite à l'exécution (jamais écrite
// en clair dans le dépôt).
func syntheticGitHubToken() string { return "gh" + "p_" + strings.Repeat("aB3d", 9) }

// TestParity est le test de parité : chaque cas de chaque fichier du manifeste du corpus (vectors/detection/),
// analysé par Scan avec le Pack initial, donne exactement l'issue et les
// constats que le moteur TypeScript de Secret Guard a produits. Le nombre de cas lus doit être celui du manifeste
// (aucun cas ignoré) ; un échec n'affiche que l'identifiant du cas, jamais son entrée.
func TestParity(t *testing.T) {
	t.Run("parité à 100 % avec Secret Guard", func(t *testing.T) {
		rules := loadInitialRules(t)
		data, err := os.ReadFile(corpusDir + "manifest.json")
		if err != nil {
			t.Fatal(err)
		}
		var manifest struct {
			FormatVersion int `json:"formatVersion"`
			Files         []struct {
				File  string `json:"file"`
				Cases int    `json:"cases"`
			} `json:"files"`
		}
		if err := json.Unmarshal(data, &manifest); err != nil || manifest.FormatVersion != 1 || len(manifest.Files) == 0 {
			t.Fatalf("manifeste illisible ou de format inconnu : %v", err)
		}
		listed, read, failed := 0, 0, 0
		ids := map[string]bool{}
		for _, file := range manifest.Files {
			listed += file.Cases
			for _, c := range loadCorpusFile(t, file.File) {
				read++
				if ids[c.ID] {
					t.Errorf("identifiant de cas en double : %s", c.ID)
				}
				ids[c.ID] = true
				if diff := parityDifference(t, rules, c); diff != "" {
					failed++
					t.Errorf("%s : %s", c.ID, diff)
				}
			}
		}
		// Chaque fichier du dossier est au manifeste (aucun fichier de cas oublié).
		entries, err := os.ReadDir(corpusDir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || name == "manifest.json" || !strings.HasSuffix(name, ".json") {
				continue
			}
			if !slices.ContainsFunc(manifest.Files, func(f struct {
				File  string `json:"file"`
				Cases int    `json:"cases"`
			}) bool {
				return f.File == name
			}) {
				t.Errorf("fichier de cas absent du manifeste : %s", name)
			}
		}
		if read != listed || read == 0 {
			t.Fatalf("%d cas lus, manifeste %d", read, listed)
		}
		t.Logf("%d cas, %d en écart", read, failed)
	})
}

func TestScanLimit(t *testing.T) {
	rules := loadInitialRules(t)
	token := syntheticGitHubToken()

	t.Run("une entrée de plus de 1 Mio n'est jamais analysée en partie", func(t *testing.T) {
		for _, content := range [][]byte{
			append([]byte(token+" "), bytes.Repeat([]byte("a"), MaxInputBytes+1-len(token)-1)...),
			append(bytes.Repeat([]byte("\xff"), MaxInputBytes-len(token)), []byte(token+" ")...),
			bytes.Repeat([]byte("a"), 4*MaxInputBytes),
		} {
			if len(content) <= MaxInputBytes {
				t.Fatalf("entrée de %d octets", len(content))
			}
			result := Scan(content, rules, Options{})
			if result.Complete || result.Failure != FailureScanLimit || result.Findings != nil {
				t.Fatalf("%d octets : %+v", len(content), result)
			}
		}
		// Aucun préfixe analysé : des règles qui paniquent à la moindre correspondance ne sont jamais appelées.
		content := append([]byte(token+" "), bytes.Repeat([]byte("zz_q7k2m "), MaxInputBytes/9+1)...)
		if result := Scan(content, panickingRules(), Options{}); result.Failure != FailureScanLimit {
			t.Fatalf("préfixe analysé : %+v", result)
		}
	})

	t.Run("une entrée de 1 Mio exactement est analysée en entier, limite mesurée en octets", func(t *testing.T) {
		content := append(bytes.Repeat([]byte("é"), (MaxInputBytes-len(token)-1)/2), ' ')
		content = append(content, bytes.Repeat([]byte(" "), MaxInputBytes-len(token)-len(content))...)
		content = append(content, token...)
		if len(content) != MaxInputBytes {
			t.Fatalf("entrée de %d octets", len(content))
		}
		result := Scan(content, rules, Options{})
		if !result.Complete || result.Failure != FailureNone || len(result.Findings) != 1 ||
			result.Findings[0].RuleID != "github_token" || result.Findings[0].ByteEnd != MaxInputBytes {
			t.Fatalf("%+v", result)
		}
	})
}

// panickingRules rend des règles dont l'unique règle « motif seul » panique sur chaque correspondance (faute injectée
// par le test : le Pack ne peut pas désigner un validateur hors de la liste fermée).
func panickingRules() *Rules {
	return &Rules{
		fixed: []*rule{{
			id: "injected_fault", family: familyFixedPattern, secretType: "api_key", score: 90,
			validator: func(string, *decodeBudget) (bool, error) { panic("faute injectée") },
			pattern:   regexp.MustCompile(`\bzz_[a-z0-9]{5}\b`),
		}},
		engine: map[string]*rule{},
		loaded: true,
	}
}

func TestScanFailures(t *testing.T) {
	t.Run("une panique dans une règle rend scan_error, sans propager la panique", func(t *testing.T) {
		for _, content := range []string{"zz_q7k2m", "x\nzz_q7k2m y", "p\u0061ss zz%5Fq7k2m"} {
			result := Scan([]byte(content), panickingRules(), Options{})
			if result.Complete || result.Failure != FailureScanError || result.Findings != nil {
				t.Fatalf("%+v", result)
			}
		}
		if result := Scan([]byte("rien"), panickingRules(), Options{}); !result.Complete {
			t.Fatalf("sans correspondance : %+v", result)
		}
	})

	t.Run("sans règles chargées par LoadRules (nil ou valeur zéro), l'analyse est incomplète", func(t *testing.T) {
		content := []byte("x " + syntheticGitHubToken() + " y")
		for name, rules := range map[string]*Rules{"nil": nil, "valeur zéro": {}} {
			if result := Scan(content, rules, Options{}); result.Complete || result.Failure != FailureScanError || result.Findings != nil {
				t.Fatalf("%s : %+v", name, result)
			}
		}
	})

	t.Run("2 048 constats au plus avant la déduplication (même jeton vu dans plusieurs vues)", func(t *testing.T) {
		rules := loadInitialRules(t)
		slackToken := "xo" + "xb-" + "7Kq2Xw9Lm4"
		// Chaque jeton est vu dans la vue d'identité et dans la vue pourcentage (« %41 » la fait exister) : deux
		// constats avant déduplication, un seul après.
		within := strings.Repeat(slackToken+" %41 ", MaxFindings/2)
		if result := Scan([]byte(within), rules, Options{}); !result.Complete || len(result.Findings) != MaxFindings/2 {
			t.Fatalf("%v, %d constats", result.Failure, len(result.Findings))
		}
		beyond := strings.Repeat(slackToken+" %41 ", MaxFindings/2+1)
		if result := Scan([]byte(beyond), rules, Options{}); result.Failure != FailureScanError {
			t.Fatalf("%d constats après déduplication, issue %v", MaxFindings/2+1, result.Failure)
		}
	})

	t.Run("la déduplication mesure chaque étendue une seule fois (linéaire en la taille des étendues)", func(t *testing.T) {
		// 2 048 constats de même rang sur des étendues de 32 Kio et plus.
		// Étendues de longueurs croissantes : le tri (plus longue d'abord) les compare toutes, à rebours.
		content := bytes.Repeat([]byte("a"), 3*MaxFindings+32<<10)
		findings := make([]finding, MaxFindings)
		for i := range findings {
			findings[i] = finding{ruleID: "github_token", start: i, end: 2*i + 32<<10, score: 90, encoding: EncodingPlain}
		}
		// Référence : une seule mesure de chaque étendue. Relire chaque étendue à chaque comparaison (≈ 2 log2 2 048
		// = 22 fois) dépasserait largement six fois cette référence ; la meilleure de trois mesures écarte le bruit.
		best := func(run func()) time.Duration {
			least := time.Duration(1 << 62)
			for range 3 {
				start := time.Now()
				run()
				least = min(least, time.Since(start))
			}
			return least
		}
		total := 0
		reference := best(func() {
			for _, f := range findings {
				total += utf16Units(content[f.start:f.end])
			}
		})
		var kept []finding
		elapsed := best(func() { kept = dedupeOverlaps(content, findings) })
		if len(kept) != 1 || total == 0 {
			t.Fatalf("%d constats", len(kept))
		}
		if elapsed > 6*reference+10*time.Millisecond {
			t.Fatalf("%v pour une référence de %v", elapsed, reference)
		}
	})

	t.Run("un budget épuisé ou plus de 2 048 constats rendent scan_error, sans constat partiel", func(t *testing.T) {
		rules := loadInitialRules(t)
		slackToken := "xo" + "xb-" + "7Kq2Xw9Lm4"
		password := "PASS" + "WORD=" + "hunter" + "2"
		for name, content := range map[string]string{
			"budget de décodage": strings.Repeat(b64(password)+"\n", 129),
			"constats":           strings.Repeat(slackToken+" ", MaxFindings+1),
		} {
			result := Scan([]byte(content), rules, Options{})
			if result.Complete || result.Failure != FailureScanError || result.Findings != nil {
				t.Fatalf("%s : %+v", name, result)
			}
		}
		// Un jeton slack_token de 15 caractères : un seul constat, ni candidat base64 ni entropie (moins de 20).
		if result := Scan([]byte(strings.Repeat(slackToken+" ", MaxFindings)), rules, Options{}); !result.Complete || len(result.Findings) != MaxFindings {
			t.Fatalf("2 048 constats : %v, %d", result.Failure, len(result.Findings))
		}
	})
}

func TestScanBinary(t *testing.T) {
	t.Run("un contenu binaire (NUL, UTF-8 invalide) qui contient une clé synthétique déclenche sa règle", func(t *testing.T) {
		rules := loadInitialRules(t)
		token := syntheticGitHubToken()
		prefix := "\x00\x00\xff\xfe\xc3\x28 \x00PK\x03\x04\xed\xa0\x80 "
		content := []byte(prefix + token + " \x00\xff\x80\xf0\x9f\x98")
		result := Scan(content, rules, Options{})
		if !result.Complete || len(result.Findings) != 1 {
			t.Fatalf("%+v", result)
		}
		f := result.Findings[0]
		if f.RuleID != "github_token" || f.Encoding != EncodingPlain || f.ByteStart != len(prefix) || f.ByteEnd != len(prefix)+len(token) ||
			f.Level != LevelCritical || f.Score != 95 {
			t.Fatalf("%+v", f)
		}
	})
}

func TestScanDeterministic(t *testing.T) {
	rules := loadInitialRules(t)
	password := "pass" + "word"
	content := []byte(strings.Join([]string{
		syntheticGitHubToken(), password + " = hunter2", "https://u:" + password + "@db.example/x",
		b64(password + "=s3cr3tValue!"), "g\n    hp_" + strings.Repeat("aB3d", 9), entropyValue(32), "%41%42",
		`ghp_` + strings.Repeat("aB3d", 9),
	}, "\n"))

	t.Run("le même contenu analysé deux fois donne le même résultat", func(t *testing.T) {
		first := Scan(content, rules, Options{LanguageID: "typescript"})
		if !first.Complete || len(first.Findings) < 4 {
			t.Fatalf("%+v", first)
		}
		if second := Scan(content, rules, Options{LanguageID: "typescript"}); !reflect.DeepEqual(first, second) {
			t.Fatalf("%+v\n%+v", first, second)
		}
		var wg sync.WaitGroup
		results := make([]Result, 8)
		for i := range results {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results[i] = Scan(content, rules, Options{LanguageID: "typescript"})
			}()
		}
		wg.Wait()
		for _, r := range results {
			if !reflect.DeepEqual(first, r) {
				t.Fatal("analyses concurrentes différentes")
			}
		}
	})

	t.Run("le contenu analysé n'est pas modifié", func(t *testing.T) {
		before := append([]byte(nil), content...)
		Scan(content, rules, Options{})
		if !bytes.Equal(before, content) {
			t.Fatal("contenu modifié")
		}
	})
}

// allowedExported : seuls types exportés du paquet et, pour une structure, ses seuls champs exportés. Aucun ne porte
// la valeur détectée, un extrait, un masque ni un condensat.
var allowedExported = map[string][]string{
	"Encoding":    nil,
	"Failure":     nil,
	"Level":       nil,
	"Finding":     {"RuleID", "SecretType", "Encoding", "Score", "Level", "ByteStart", "ByteEnd", "LocalFingerprint"},
	"Result":      {"Complete", "Failure", "Findings"},
	"Options":     {"LanguageID"},
	"Rules":       {},
	"PackRefusal": nil,
	"PackError":   {"RuleID", "Reason"},
	// Clé d'Empreinte locale, sans champ exporté (octets derrière un pointeur non exporté).
	"FingerprintKey": {},
}

// allowedFingerprintField est le seul champ dont le nom évoque un condensat : l'Empreinte locale, HMAC sous la clé de
// l'appelant, jamais un condensat non salé (TestLocalFingerprintNeverUnsaltedHash).
const allowedFingerprintField = "Finding.LocalFingerprint"

var forbiddenFieldWords = regexp.MustCompile(`(?i)value|excerpt|snippet|mask|redact|hash|digest|sha\d|fingerprint|preview|match|text|content|^secret$|^raw|data$`)

func TestFindingNeverCarriesValue(t *testing.T) {
	t.Run("un constat ne porte jamais la valeur", func(t *testing.T) {
		// Types exportés relevés dans les fichiers du paquet (hors tests) : liste fermée.
		entries, err := os.ReadDir(".")
		if err != nil {
			t.Fatal(err)
		}
		found := map[string]bool{}
		var funcs, values []string
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, decl := range file.Decls {
				switch d := decl.(type) {
				case *ast.GenDecl:
					for _, spec := range d.Specs {
						switch sp := spec.(type) {
						case *ast.TypeSpec:
							if sp.Name.IsExported() {
								found[sp.Name.Name] = true
							}
						case *ast.ValueSpec:
							for _, n := range sp.Names {
								if n.IsExported() && d.Tok == token.VAR {
									values = append(values, n.Name)
								}
							}
						}
					}
				case *ast.FuncDecl:
					if d.Name.IsExported() {
						name := d.Name.Name
						if d.Recv != nil {
							name = "méthode " + name
						}
						funcs = append(funcs, name)
					}
				}
			}
		}
		for name := range found {
			if _, ok := allowedExported[name]; !ok {
				t.Errorf("type exporté hors de la liste fermée : %s", name)
			}
		}
		// Variables exportées : liste fermée (constantes : types de la liste fermée ou entiers, vérifiés par le
		// compilateur et par les types ci-dessous).
		slices.Sort(values)
		if want := []string{"ErrFingerprintKeyInvalid", "ErrPackUnusable"}; !slices.Equal(values, want) {
			t.Errorf("variables exportées %v, attendu %v", values, want)
		}
		slices.Sort(funcs)
		if want := []string{
			// méthode Has : Rules.Has, rend un booléen, jamais une valeur.
			"LoadRules", "NewFingerprintKey", "Scan", "ScanWithFingerprint", "méthode Error", "méthode GoString",
			"méthode Has", "méthode String", "méthode Unwrap", "méthode Wipe",
		}; !slices.Equal(funcs, want) {
			t.Errorf("fonctions exportées %v, attendu %v", funcs, want)
		}
		// Champs par réflexion : liste fermée par type, aucune tranche d'octets, fonction, interface ni table, aucun
		// nom de valeur, d'extrait, de masque ou de condensat.
		for _, typ := range []reflect.Type{
			reflect.TypeFor[Encoding](), reflect.TypeFor[Failure](), reflect.TypeFor[Level](), reflect.TypeFor[Finding](),
			reflect.TypeFor[Result](), reflect.TypeFor[Options](), reflect.TypeFor[Rules](), reflect.TypeFor[PackRefusal](),
			reflect.TypeFor[PackError](), reflect.TypeFor[FingerprintKey](),
		} {
			if !found[typ.Name()] {
				t.Errorf("type %s absent du relevé", typ.Name())
			}
			checkExportedType(t, typ, allowedExported[typ.Name()])
		}
		if len(found) != len(allowedExported) {
			t.Errorf("%d types exportés, %d attendus", len(found), len(allowedExported))
		}
	})
}

func checkExportedType(t *testing.T, typ reflect.Type, allowed []string) {
	t.Helper()
	if typ.Kind() != reflect.Struct {
		if typ.Kind() != reflect.String {
			t.Errorf("%s : genre %s", typ.Name(), typ.Kind())
		}
		return
	}
	var exported []string
	for i := range typ.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		exported = append(exported, field.Name)
		if forbiddenFieldWords.MatchString(field.Name) && typ.Name()+"."+field.Name != allowedFingerprintField {
			t.Errorf("%s.%s : nom de champ interdit", typ.Name(), field.Name)
		}
		kind := field.Type.Kind()
		if kind == reflect.Slice {
			if field.Type.Elem() != reflect.TypeFor[Finding]() {
				t.Errorf("%s.%s : tranche de %s", typ.Name(), field.Name, field.Type.Elem())
			}
			continue
		}
		if kind != reflect.String && kind != reflect.Int && kind != reflect.Bool {
			t.Errorf("%s.%s : genre %s", typ.Name(), field.Name, kind)
		}
	}
	if !slices.Equal(exported, allowed) {
		t.Errorf("%s : champs exportés %v, attendu %v", typ.Name(), exported, allowed)
	}
}

// TestScanWorstCases : pires cas des vues et décodages par l'analyse complète (règles sur chaque vue, fenêtres,
// textes décodés), à 256 Kio, dans la borne de temps des pires cas ; issue complète ou scan_error, jamais de constat
// partiel. L'expansion NFKC maximale (×11 sur 1 Mio, les vues les plus grandes que le budget admet) est analysée en
// entier dans une borne plus large  : environ 6 s mesurées sur un Apple M2 Pro.
func TestScanWorstCases(t *testing.T) {
	rules := loadInitialRules(t)
	for _, c := range worstCaseInputs(ruleFill, ruleWorstCaseBytes) {
		t.Run("pire cas de Scan borné en temps — "+c.name, func(t *testing.T) {
			start := time.Now()
			result := Scan(c.content, rules, Options{LanguageID: "typescript"})
			elapsed := time.Since(start)
			if !result.Complete {
				if result.Failure != FailureScanError || result.Findings != nil {
					t.Fatalf("%+v", result)
				}
				// Cause de l'analyse incomplète : seulement une erreur admise pour ce cas (aucune s'il doit finir).
				_, err := collect(rules, c.content, language{id: "typescript", set: true})
				if !slices.ContainsFunc(c.allowed, func(allowed error) bool { return errors.Is(err, allowed) }) {
					t.Fatalf("analyse incomplète : %v", err)
				}
			}
			if elapsed > worstCaseTimeLimit {
				t.Fatalf("%v pour %d octets", elapsed, len(c.content))
			}
		})
	}
	t.Run("pire cas de Scan borné en temps — expansion NFKC maximale sur 1 Mio", func(t *testing.T) {
		start := time.Now()
		result := Scan(fill("\xef\xb7\xba"), rules, Options{})
		if elapsed := time.Since(start); elapsed > scanMaxExpansionTimeLimit {
			t.Fatalf("%v", elapsed)
		}
		if !result.Complete {
			t.Fatalf("%+v", result)
		}
	})
}

// scanMaxExpansionTimeLimit est large (machine de CI chargée) : une lecture quadratique de 11 Mio de vues prendrait
// des heures.
const scanMaxExpansionTimeLimit = 30 * time.Second

// isAdmittedScanError : erreurs qui rendent une analyse incomplète sur une entrée quelconque (budgets épuisés,
// trop de constats) ; toute autre est un défaut.
func isAdmittedScanError(err error) bool {
	return errors.Is(err, errDecodeBudgetExhausted) || errors.Is(err, errJoinedWindowBudgetExhausted) ||
		errors.Is(err, errViewBudgetExhausted) || errors.Is(err, errTooManyFindings)
}

// FuzzScan : toute entrée, tout langage : l'assemblage ne panique pas (appelé sans le rattrapage de Scan), ne rend
// pas d'autre erreur qu'un budget épuisé ou trop de constats, et Scan rend des constats triés, disjoints, dans
// l'entrée, de règles du Pack, avec le niveau qui correspond au score, identiques à la seconde exécution.
func FuzzScan(f *testing.F) {
	for _, seed := range append(append([]string{}, fuzzSeeds...), ruleFuzzSeeds...) {
		f.Add([]byte(seed), uint8(0))
	}
	f.Add([]byte(syntheticGitHubToken()+"\x00\xff password=hunter2 "+b64("to"+"ken: "+entropyValue(16))), uint8(1))
	rules := loadInitialRules(f)
	p := loadInitialPack(f)
	known := map[string]bool{}
	for _, r := range p.Rules {
		known[r.RuleID] = true
	}
	languages := []string{"", "typescript", "json", "dotenv", "yaml", "shellscript", "python"}
	f.Fuzz(func(t *testing.T, content []byte, choice uint8) {
		if len(content) > 8192 {
			return
		}
		options := Options{LanguageID: languages[int(choice)%len(languages)]}
		_, err := collect(rules, content, options.language())
		if err != nil && !isAdmittedScanError(err) {
			t.Fatalf("erreur %v", err)
		}
		result := Scan(content, rules, options)
		if result.Complete != (result.Failure == FailureNone) || (!result.Complete && result.Findings != nil) ||
			(err == nil) != result.Complete {
			t.Fatalf("issue %+v, assemblage %v", result.Failure, err)
		}
		previousEnd := 0
		for _, f := range result.Findings {
			if f.ByteStart < previousEnd || f.ByteStart >= f.ByteEnd || f.ByteEnd > len(content) {
				t.Fatalf("étendue [%d, %d) après %d, entrée de %d octets", f.ByteStart, f.ByteEnd, previousEnd, len(content))
			}
			previousEnd = f.ByteEnd
			if !known[f.RuleID] || f.Score < 0 || f.Score > 100 || f.Level != levelForScore(f.Score) {
				t.Fatalf("constat %+v", f)
			}
		}
		if again := Scan(content, rules, options); !reflect.DeepEqual(result, again) {
			t.Fatal("résultat différent à la seconde exécution")
		}
	})
}

// BenchmarkScan64KiB mesure l'analyse d'une entrée de 64 Kio : code, configuration, journaux et quelques secrets
// synthétiques (go test -run '^$' -bench BenchmarkScan64KiB ./detect).
func BenchmarkScan64KiB(b *testing.B) {
	rules := loadInitialRules(b)
	password := "pass" + "word"
	unit := strings.Join([]string{
		`import { readFile } from "node:fs/promises";`,
		`export async function load(path: string): Promise<Config> {`,
		`  const text = await readFile(path, "utf8"); // lecture`,
		`  return JSON.parse(text) as Config;`,
		`}`,
		`const url = "https://api.example.com/v1/items?limit=50&offset=100";`,
		`2026-10-11T08:15:42.123Z INFO request completed method=GET status=200 duration=12ms`,
		`DATABASE_HOST=db.internal`,
		`{"name": "demo", "version": "1.2.3", "dependencies": {"zod": "^4.0.0"}}`,
		`    for (let i = 0; i < items.length; i++) { total += items[i].price * items[i].quantity; }`,
	}, "\n") + "\n"
	var content []byte
	for len(content) < 64<<10 {
		content = append(content, unit...)
	}
	secrets := []string{syntheticGitHubToken(), password + " = \"hunter2-" + entropyValue(12) + "\"", b64(password + "=" + entropyValue(16))}
	for i, s := range secrets {
		at := (i + 1) * len(content) / (len(secrets) + 1)
		at = bytes.IndexByte(content[at:], '\n') + at + 1
		content = append(content[:at], append([]byte(s+"\n"), content[at:]...)...)
	}
	content = content[:64<<10]
	if result := Scan(content, rules, Options{LanguageID: "typescript"}); !result.Complete || len(result.Findings) == 0 {
		b.Fatalf("%+v", result.Failure)
	}
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for b.Loop() {
		Scan(content, rules, Options{LanguageID: "typescript"})
	}
}
