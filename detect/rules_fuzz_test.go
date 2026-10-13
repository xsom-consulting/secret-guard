// Apache-2.0 : les oracles sont les motifs de secret-guard/packages/core/src/rules.ts, traduits ; origine, avis et
// modifications dans UPSTREAM.md.

package detect

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"regexp"
	"testing"
	"unicode/utf8"
)

// Oracles : les motifs d'origine traduits (engine_patterns.go, constantes ref…), que le moteur lit à la main pour rester
// linéaire et compter en unités UTF-16. Sur des entrées courtes (sous les bornes de 512 à 2 048 unités) et sans point
// de code hors du plan multilingue de base, l'expression traduite et la lecture à la main doivent donner le même
// résultat.

const fuzzMaxInput = 600

var ruleFuzzSeeds = []string{
	"password=<<EOF\nsecret\nEOF\n",
	"x = <<-'END' trailing\n\tbody\n\tEND\r\nafter",
	"a <<\"M\"\r\nM \n",
	"<<EOF",
	"pwd=<<,pwd=<<1 <<_x\n",
	"export FOO = \n",
	"  set A_B=\t",
	"key.name := value",
	"const enum type return interface final let mut static readonly var public private protected",
	"enumx enum_ xenum enum",
	"std::string a = ",
	"Map<String, String> m = ",
	"int *p = ",
	"/a[/]b/gi",
	"/a\\/b",
	"/[a\\]/]/x",
	"$(echo hi)",
	"`whoami`",
	"eyJhbGci.eyJzdWIi.abcdefgh",
	"eyJ-eyJabcd.eyJabcd.abcdefgh-",
	"\r\n  x=1",
}

func fuzzInput(input []byte) bool { return len(input) <= fuzzMaxInput }

func lineStarts(text []byte) []int {
	starts := []int{0}
	for i, c := range text {
		if c == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// runeBoundary : les fins de tranche que lit le moteur (fins de correspondance) sont toujours entre deux caractères.
func runeBoundary(text []byte, i int) bool { return i == len(text) || utf8.RuneStart(text[i]) }

func hasAstral(text []byte) bool {
	for _, c := range text {
		if c >= 0xF0 {
			return true
		}
	}
	return false
}

func FuzzHeredoc(f *testing.F) {
	for _, s := range ruleFuzzSeeds {
		f.Add([]byte(s))
	}
	start := regexp.MustCompile(refHeredocStart)
	f.Fuzz(func(t *testing.T, text []byte) {
		if !fuzzInput(text) || !utf8.Valid(text) {
			return
		}
		ctx := newContextualText(text)
		for from := 0; from < len(text); from++ {
			end, ok := ctx.heredoc(from)
			m := start.FindSubmatchIndex(text[from:])
			if (m != nil) != ok {
				t.Fatalf("heredoc en %d : %v, oracle %v", from, ok, m != nil)
			}
			if m == nil {
				continue
			}
			bodyStart := from + m[1]
			marker := regexp.QuoteMeta(string(text[from+m[2] : from+m[3]]))
			terminator := regexp.MustCompile(`\n[\t ]*` + marker + `[\t ]*(?:\r?\n|\z)`)
			want := len(text)
			if t := terminator.FindIndex(text[bodyStart:]); t != nil {
				want = bodyStart + t[1]
			}
			if end != want {
				t.Fatalf("heredoc en %d : fin %d, oracle %d", from, end, want)
			}
		}
	})
}

func FuzzAssignmentPrefix(f *testing.F) {
	for _, s := range ruleFuzzSeeds {
		f.Add([]byte(s))
	}
	oracles := map[prefixKind]*regexp.Regexp{
		prefixBareEnvironment: regexp.MustCompile(refBareEnvironmentAssignment),
		prefixShell:           regexp.MustCompile(refInferredShellAssignment),
		prefixStructured:      regexp.MustCompile(refInferredStructuredAssignment),
	}
	f.Fuzz(func(t *testing.T, text []byte) {
		if !fuzzInput(text) {
			return
		}
		ctx := newContextualText(text)
		for kind, oracle := range oracles {
			for _, lineStart := range lineStarts(text) {
				for end := lineStart; end <= len(text); end++ {
					if !runeBoundary(text, end) {
						continue
					}
					if got, want := ctx.prefixAssignment(kind, lineStart, end), oracle.Match(text[lineStart:end]); got != want {
						t.Fatalf("préfixe %d [%d, %d) : %v, oracle %v", kind, lineStart, end, got, want)
					}
				}
			}
		}
	})
}

func FuzzKeywords(f *testing.F) {
	for _, s := range ruleFuzzSeeds {
		f.Add([]byte(s))
	}
	oracles := map[keywordSet]*regexp.Regexp{
		keywordsInferredCode: regexp.MustCompile(refInferredCodeKeyword),
		keywordsExternalCode: regexp.MustCompile(refExternalCodeKeyword),
		keywordsDeclaration:  regexp.MustCompile(refDeclarationKeyword),
		keywordsStatement:    regexp.MustCompile(refStatementKeyword),
		keywordsEnum:         regexp.MustCompile(refEnumKeyword),
	}
	f.Fuzz(func(t *testing.T, text []byte) {
		if !fuzzInput(text) {
			return
		}
		ctx := newContextualText(text)
		for set, oracle := range oracles {
			index := ctx.keywords(set)
			for _, lineStart := range lineStarts(text) {
				for end := lineStart; end <= len(text); end++ {
					if !runeBoundary(text, end) {
						continue
					}
					if got, want := index.inSlice(text, lineStart, end), oracle.Match(text[lineStart:end]); got != want {
						t.Fatalf("mots-clés %d [%d, %d) : %v, oracle %v", set, lineStart, end, got, want)
					}
				}
			}
		}
	})
}

func FuzzCodeDeclaration(f *testing.F) {
	for _, s := range ruleFuzzSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, text []byte) {
		if !fuzzInput(text) || hasAstral(text) {
			return
		}
		ctx := newContextualText(text)
		for _, lineStart := range lineStarts(text) {
			for end := lineStart; end <= len(text); end++ {
				if !runeBoundary(text, end) {
					continue
				}
				if got, want := ctx.codeDeclaration(lineStart, end), codeDeclaration.Match(text[lineStart:end]); got != want {
					t.Fatalf("déclaration [%d, %d) : %v, oracle %v", lineStart, end, got, want)
				}
			}
		}
	})
}

// regexLiteralLoop est la lecture d'un littéral d'expression régulière de parseAssignmentValue, recopiée telle quelle.
func regexLiteralLoop(text []byte, start int) (int, bool) {
	escaped, inClass := false, false
	for end := start + 1; end < len(text); end++ {
		c := text[end]
		if !escaped {
			switch {
			case c == '[':
				inClass = true
			case c == ']':
				inClass = false
			case c == '/' && !inClass:
				return end, true
			}
		}
		escaped = c == '\\' && !escaped
		if c == '\r' || c == '\n' {
			break
		}
	}
	return 0, false
}

func FuzzRegexLiteral(f *testing.F) {
	for _, s := range ruleFuzzSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, text []byte) {
		if !fuzzInput(text) {
			return
		}
		ctx := newContextualText(text)
		for start := 0; start < len(text); start++ {
			if text[start] != '/' {
				continue
			}
			got, gotOK := ctx.regexLiteralClose(start)
			want, wantOK := regexLiteralLoop(text, start)
			if gotOK != wantOK || got != want {
				t.Fatalf("littéral en %d : (%d, %v), boucle d'origine (%d, %v)", start, got, gotOK, want, wantOK)
			}
		}
	})
}

func FuzzShellSubstitution(f *testing.F) {
	for _, s := range ruleFuzzSeeds {
		f.Add([]byte(s))
	}
	dollar, backtick := regexp.MustCompile(refShellDollarSubstitution), regexp.MustCompile(refShellBacktickSubstitution)
	f.Fuzz(func(t *testing.T, value []byte) {
		if !fuzzInput(value) || hasAstral(value) {
			return
		}
		trimmed := jsTrim(value)
		if got, want := isShellCommandSubstitution(value), dollar.Match(trimmed) || backtick.Match(trimmed); got != want {
			t.Fatalf("substitution : %v, oracle %v", got, want)
		}
	})
}

func FuzzJWT(f *testing.F) {
	for _, s := range ruleFuzzSeeds {
		f.Add([]byte(s))
	}
	// Motif d'origine, bornes ramenées sous la limite de RE2 : équivalent sur des entrées plus courtes que ces bornes.
	oracle := regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{4,1000}\.eyJ[A-Za-z0-9_-]{4,1000}\.[A-Za-z0-9_-]{8,1000}\b`)
	f.Fuzz(func(t *testing.T, text []byte) {
		if !fuzzInput(text) {
			return
		}
		var got [][]int
		matcher := newJWTMatcher(text)
		for pos := 0; ; {
			c, end, ok := nextJWT(matcher, pos)
			if !ok {
				break
			}
			got = append(got, []int{c, end})
			pos = end
		}
		want := oracle.FindAllIndex(text, -1)
		if len(got) != len(want) {
			t.Fatalf("%d JWT, oracle %d", len(got), len(want))
		}
		for i := range got {
			if got[i][0] != want[i][0] || got[i][1] != want[i][1] {
				t.Fatalf("JWT %d : %v, oracle %v", i, got[i], want[i])
			}
		}
	})
}

// FuzzRuleFamilies : toute entrée, toute vue, tout langage : aucune panique, aucune erreur autre qu'un budget de
// décodage épuisé, étendues dans la source, résultat identique à la seconde exécution.
func FuzzRuleFamilies(f *testing.F) {
	for _, s := range ruleFuzzSeeds {
		f.Add([]byte(s), uint8(0))
	}
	f.Add([]byte("Cookie: sid=a;token=b\n -u \"a:b\" {\"auth\":\"YTpi\"} postgres://u:p@[::1]:5432/x"), uint8(1))
	p := loadInitialPack(f)
	rules, err := LoadRules(&p)
	if err != nil {
		f.Fatal(err)
	}
	languages := []language{{}, {id: "typescript", set: true}, {id: "json", set: true}, {id: "dotenv", set: true}, {id: "yaml", set: true}}
	f.Fuzz(func(t *testing.T, content []byte, choice uint8) {
		if len(content) > 4096 {
			return
		}
		lang := languages[int(choice)%len(languages)]
		text, err := buildTextViews(content, newViewBudget())
		if err != nil {
			return
		}
		views := []*view{text.identity}
		if text.normalized != nil {
			views = append(views, text.normalized)
		}
		views = append(views, text.transformed...)
		for _, v := range views {
			run := func() ([]finding, error) {
				budget := &decodeBudget{}
				fixed, err := rules.scanFixedRules(v, budget, true)
				if err != nil {
					return nil, err
				}
				contextual, err := rules.scanContextualAssignments(v, budget, lang, true)
				if err != nil {
					return nil, err
				}
				out := append(fixed, rules.scanCredentialURLs(v)...)
				out = append(out, contextual...)
				return append(out, rules.scanEntropy(v)...), nil
			}
			first, firstErr := run()
			second, secondErr := run()
			if firstErr != nil && !errors.Is(firstErr, errDecodeBudgetExhausted) {
				t.Fatalf("erreur inattendue : %v", firstErr)
			}
			if !errors.Is(secondErr, firstErr) && secondErr != firstErr {
				t.Fatal("issue non déterministe")
			}
			if len(first) != len(second) {
				t.Fatal("résultat non déterministe")
			}
			for i, f := range first {
				if f.start < 0 || f.end > len(content) || f.start > f.end {
					t.Fatalf("étendue [%d, %d) hors de la source (%d octets)", f.start, f.end, len(content))
				}
				if f.ruleID != second[i].ruleID || f.start != second[i].start || f.end != second[i].end {
					t.Fatal("résultat non déterministe")
				}
			}
		}
	})
}

// TestJSLog2 : jsLog2 rend, au bit près, Math.log2 de V8 pour chaque probabilité c/n (1 ≤ c ≤ n ≤ 1 024), comme
// shannonEntropy les calcule : empreinte SHA-256 des 524 800 résultats (doubles gros-boutistes), calculée par Node 26
// (`Math.log2(c / n)`, Buffer.writeDoubleBE). math.Log2 de Go en diffère.
func TestJSLog2(t *testing.T) {
	const nodeDigest = "8691e517bb44367b65ad80d1c5f719b443aa9de90d91e9364fbf17b0d46d3482"
	t.Run("le logarithme de l'entropie est celui de JavaScript, au bit près", func(t *testing.T) {
		digest := sha256.New()
		var buffer [8]byte
		for n := 1; n <= 1024; n++ {
			for c := 1; c <= n; c++ {
				binary.BigEndian.PutUint64(buffer[:], math.Float64bits(jsLog2(float64(c)/float64(n))))
				digest.Write(buffer[:])
			}
		}
		if got := hex.EncodeToString(digest.Sum(nil)); got != nodeDigest {
			t.Fatalf("empreinte %s, Node %s", got, nodeDigest)
		}
		for _, x := range []float64{0, -1, math.Inf(1), math.NaN(), 1, 2, 0x1p-1074} {
			got, want := jsLog2(x), math.Log2(x)
			if !(got == want || (math.IsNaN(got) && math.IsNaN(want))) {
				t.Errorf("log2(%v) = %v, attendu %v", x, got, want)
			}
		}
	})
}

// TestSurrogateWidened : une répétition bornée de reInferredCodeDeclaration compte des unités UTF-16.
func TestSurrogateWidened(t *testing.T) {
	t.Run("« <…>{1,128} » compte un point de code hors du plan de base pour deux unités", func(t *testing.T) {
		astral := "\U0001F600"
		fits := []byte("Map<" + string(bytes.Repeat([]byte(astral), 64)) + "> m = ")
		over := []byte("Map<" + string(bytes.Repeat([]byte(astral), 65)) + "> m = ")
		if !newContextualText(fits).codeDeclaration(0, len(fits)) {
			t.Fatal("128 unités refusées")
		}
		if newContextualText(over).codeDeclaration(0, len(over)) {
			t.Fatal("130 unités admises")
		}
	})
}
