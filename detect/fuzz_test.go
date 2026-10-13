package detect

import (
	"bytes"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// Tests de fuzz courts (graines exécutées par go test ; exploration : go test -fuzz=FuzzTextViews -fuzztime=30s).

var fuzzSeeds = []string{
	"",
	"token ghp%5Fabc",
	`\ud83d\u200b\ude00 \ude00\ud83d %5Cu0041 \u0025\u0034\u0031 \/`,
	"a\r\n\xe2\x80\x8bb\xef\xbd\x87\xef\xb7\xba\xff\x00\xe2\x80",
	"g\n    hp_aB3aB3aB3aB3aB3aB3aB3aB3aB3aB3aB3aB3\nQUJDREVGR0hJ\nSktMTU5PUFFS==",
	"%F0%9F%98%80%C3%28%ED%A0%80%E2%82%41",
	"sha512-Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab==",
}

// checkView vérifie les invariants d'une vue dérivée : correspondance pour chaque octet, dans la source, débuts
// croissants ; texte UTF-8 valide ; substituts isolés à leur place.
func checkView(t *testing.T, v *view, sourceLength int) {
	t.Helper()
	if v.starts == nil {
		return
	}
	if len(v.starts) != len(v.text) || len(v.ends) != len(v.text) {
		t.Fatalf("%s : correspondance de %d/%d octets pour %d", v.encoding, len(v.starts), len(v.ends), len(v.text))
	}
	if !utf8.Valid(v.text) {
		t.Fatalf("%s : vue dérivée hors UTF-8", v.encoding)
	}
	for i := range v.starts {
		if v.starts[i] < 0 || v.starts[i] > v.ends[i] || int(v.ends[i]) > sourceLength || (i > 0 && v.starts[i] < v.starts[i-1]) {
			t.Fatalf("%s : correspondance de l'octet %d hors source", v.encoding, i)
		}
	}
	for k, lone := range v.lone {
		if !bytes.HasPrefix(v.text[lone.pos:], replacement) || (k > 0 && lone.pos <= v.lone[k-1].pos) {
			t.Fatalf("%s : substitut isolé %d mal placé", v.encoding, k)
		}
	}
}

func FuzzTextViews(f *testing.F) {
	for _, seed := range fuzzSeeds {
		f.Add([]byte(seed))
	}
	rules := loadInitialRules(f)
	f.Fuzz(func(t *testing.T, content []byte) {
		budget := newViewBudget()
		views, err := buildTextViews(content, budget)
		if err != nil {
			t.Fatalf("vues refusées : %v", err)
		}
		if !bytes.Equal(views.identity.text, content) {
			t.Fatal("identité modifiée")
		}
		all := append([]*view{}, views.transformed...)
		if views.normalized != nil {
			all = append(all, views.normalized)
		}
		windows := &windowBudget{}
		for _, v := range append([]*view{views.canonical}, views.transformed...) {
			fixed, err := lineWrappedFixedViews(v, windows, budget)
			if err != nil && !errors.Is(err, errJoinedWindowBudgetExhausted) {
				t.Fatal(err)
			}
			wrapped, err := lineWrappedBase64Views(v, windows, budget)
			if err != nil && !errors.Is(err, errJoinedWindowBudgetExhausted) {
				t.Fatal(err)
			}
			all = append(all, fixed...)
			all = append(all, wrapped...)
		}
		for _, v := range all {
			checkView(t, v, len(content))
		}
		if _, err := collect(rules, content, language{}); err != nil && !isAdmittedScanError(err) {
			t.Fatal(err)
		}
	})
}

// splitTokenPrefixRegexp est SPLIT_TOKEN_PREFIX de Secret Guard écrit en RE2, référence du lecteur à la main.
var splitTokenPrefixRegexp = func() *regexp.Regexp {
	alternatives := make([]string, len(tokenPrefixes))
	for i, prefix := range tokenPrefixes {
		characters := make([]string, len(prefix))
		for k := range prefix {
			characters[k] = regexp.QuoteMeta(prefix[k : k+1])
		}
		alternatives[i] = strings.Join(characters, `(?:\r?\n[ \t]{0,4})?`)
	}
	return regexp.MustCompile(strings.Join(alternatives, "|"))
}()

func manualPrefixMatches(text []byte) [][]int {
	var matches [][]int
	for i := 0; i < len(text); {
		if end, ok := matchPrefixAt(text, i); ok {
			matches = append(matches, []int{i, end})
			i = end
			continue
		}
		i++
	}
	return matches
}

func FuzzTokenPrefixMatcher(f *testing.F) {
	for _, seed := range append(fuzzSeeds, "sk_live_x sk-x g\r\n\t\thp_ ghp\n_ xox\nb- https:/\n/hooks.slack.com/services/ AccountKey\n=") {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, text []byte) {
		want := splitTokenPrefixRegexp.FindAllIndex(text, -1)
		got := manualPrefixMatches(text)
		if len(want) != len(got) {
			t.Fatalf("%d correspondances, attendu %d", len(got), len(want))
		}
		for i := range want {
			if want[i][0] != got[i][0] || want[i][1] != got[i][1] {
				t.Fatalf("correspondance %d : %v, attendu %v", i, got[i], want[i])
			}
		}
	})
}

func FuzzBase64Candidates(f *testing.F) {
	for _, seed := range fuzzSeeds {
		f.Add([]byte(seed))
	}
	// BASE64_CANDIDATE en RE2 avec une borne de 1 000 : identique tant qu'aucune suite ne dépasse 1 000 caractères.
	reference := regexp.MustCompile(`[A-Za-z0-9+/_-]{20,1000}={0,2}`)
	f.Fuzz(func(t *testing.T, text []byte) {
		run := 0
		for _, c := range text {
			if isBase64Character(c) {
				run++
				if run > 1000 {
					t.Skip()
				}
			} else {
				run = 0
			}
		}
		want := reference.FindAllIndex(text, -1)
		got := collectCandidates(string(text))
		if len(want) != len(got) {
			t.Fatalf("%d candidats, attendu %d", len(got), len(want))
		}
		for i := range want {
			if want[i][0] != got[i][0] || want[i][1] != got[i][1] {
				t.Fatalf("candidat %d : %v, attendu %v", i, got[i], want[i])
			}
		}
	})
}

func FuzzDecodeBase64(f *testing.F) {
	for _, seed := range []string{"aGVsbG8=", "YQ", "Pz8_Pj4-", "A===", "AAA==", "/w==", "77u/aGk="} {
		f.Add(seed, 16)
	}
	f.Fuzz(func(t *testing.T, value string, maxDecoded int) {
		maxDecoded = max(0, maxDecoded%64)
		text, ok := decodeBase64(value, maxDecoded)
		// Référence : décodage de la bibliothèque standard après les mêmes contrôles de forme.
		normalized := strings.NewReplacer("-", "+", "_", "/").Replace(value)
		body := strings.TrimRight(normalized, "=")
		padding := len(normalized) - len(body)
		decoded, err := base64.RawStdEncoding.DecodeString(body)
		wellFormed := padding <= 2 && len(value)%4 != 1 && err == nil && !strings.ContainsAny(body, "=\r\n") && len(decoded) <= maxDecoded
		if !wellFormed {
			if ok {
				t.Fatalf("%q décodé malgré une forme refusée", value)
			}
			return
		}
		// Texte rendu ssi UTF-8 valide, sans NUL, non vide après la marque d'ordre d'octets, imprimable à 90 %.
		want := strings.TrimPrefix(string(decoded), "\xef\xbb\xbf")
		total, printable := 0, 0
		for _, r := range want {
			total++
			if r == '\n' || r == '\r' || r == '\t' || r >= ' ' {
				printable++
			}
		}
		accepted := utf8.Valid(decoded) && want != "" && !strings.Contains(want, "\x00") && 10*printable >= 9*total
		if ok != accepted || (ok && text != want) {
			t.Fatalf("%q → %q (%v), attendu %q (%v)", value, text, ok, want, accepted)
		}
	})
}
