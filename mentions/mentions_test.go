package mentions

import (
	"bytes"
	"math"
	"math/rand/v2"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// isJSSpace est \s de JavaScript, écrit à la main : l'oracle des tests ne lit pas jsSpace.
func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', 0xFEFF, 0x2028, 0x2029:
		return true
	}
	return unicode.Is(unicode.Zs, r)
}

// oracle relève les mentions par un parcours écrit à la main (sémantique de matchAll en JavaScript : tentative à
// chaque point de code, alternative entre guillemets d'abord, reprise après la fin d'une correspondance), sans les
// expressions du paquet.
func oracle(prompt []byte) []Mention {
	var all []Mention
	runAt := func(i int) (rune, int) { return utf8.DecodeRune(prompt[i:]) }
	for i := 0; i < len(prompt); {
		r, w := runAt(i)
		at := -1
		switch {
		case i == 0 && r == '@':
			at = 0
		case isJSSpace(r) && i+w < len(prompt) && prompt[i+w] == '@':
			at = i + w
		}
		if at < 0 {
			i += w
			continue
		}
		start, end, matchEnd := -1, -1, -1
		if at+1 < len(prompt) && prompt[at+1] == '"' {
			if q := bytes.IndexByte(prompt[at+2:], '"'); q > 0 {
				start, end, matchEnd = at+2, at+2+q, at+3+q
			}
		}
		if start < 0 {
			j := at + 1
			for j < len(prompt) {
				r, w := runAt(j)
				if isJSSpace(r) {
					break
				}
				j += w
			}
			if j > at+1 {
				start, end, matchEnd = at+1, j, j
			}
		}
		if start < 0 {
			i += w
			continue
		}
		token := string(prompt[start:end])
		lines := ""
		// Suffixe « #L<chiffres>[-<chiffres>] » final.
		trimDigits := func(s string) (string, bool) {
			k := len(s)
			for k > 0 && s[k-1] >= '0' && s[k-1] <= '9' {
				k--
			}
			return s[:k], k < len(s)
		}
		if rest, ok := trimDigits(token); ok {
			if strings.HasSuffix(rest, "#L") {
				lines, token = token[len(rest):], rest[:len(rest)-2]
			} else if strings.HasSuffix(rest, "-") {
				if head, ok := trimDigits(rest[:len(rest)-1]); ok && strings.HasSuffix(head, "#L") {
					lines, token = token[len(head):], head[:len(head)-2]
				}
			}
		}
		token = strings.TrimRight(token, ",;:!?)")
		if token != "" {
			all = append(all, Mention{Path: token, Lines: lines, ByteStart: at, ByteEnd: matchEnd})
		}
		i = matchEnd
	}
	var out []Mention
	for _, m := range all {
		if k := slices.IndexFunc(out, func(o Mention) bool { return o.Path == m.Path }); k >= 0 {
			if out[k].Lines != m.Lines {
				out[k].Lines = ""
			}
			continue
		}
		out = append(out, m)
	}
	return out
}

func TestParse(t *testing.T) {
	t.Run("les trois formes, ponctuation finale, adresse électronique ignorée", func(t *testing.T) {
		got := Parse([]byte(`voir @docs/a.md, @"b c.md" et @src/x.ts#L10-20 et dev@example.org`))
		want := []Mention{
			{Path: "docs/a.md", ByteStart: 5, ByteEnd: 16},
			{Path: "b c.md", ByteStart: 17, ByteEnd: 26},
			{Path: "src/x.ts", Lines: "10-20", ByteStart: 30, ByteEnd: 46},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("rien : nil", func(t *testing.T) {
		for _, prompt := range []string{"", "plain", "a@b.c", "@", "@ ", "@,", "@#L5"} {
			if got := Parse([]byte(prompt)); got != nil {
				t.Fatalf("%q : %+v", prompt, got)
			}
		}
	})
	t.Run("le prompt n'est pas modifié ; le chemin ne partage pas sa mémoire", func(t *testing.T) {
		prompt := []byte("see @a.md")
		got := Parse(prompt)
		prompt[5] = 'X'
		if got[0].Path != "a.md" {
			t.Fatal(got[0].Path)
		}
	})
}

func TestLineRange(t *testing.T) {
	for _, c := range []struct {
		lines       string
		first, last int
		ok          bool
	}{
		{"", 0, 0, false}, {"7", 7, 7, true}, {"10-20", 10, 20, true}, {"20-10", 20, 10, true}, {"0", 0, 0, true},
		{"007-010", 7, 10, true}, {strconv.Itoa(math.MaxInt), math.MaxInt, math.MaxInt, true},
		{"99999999999999999999999", 0, 0, false}, {"1-99999999999999999999999", 0, 0, false}, {"1-", 0, 0, false},
		{"-1", 0, 0, false}, {"1x", 0, 0, false}, {"1-2x", 0, 0, false},
	} {
		first, last, ok := Mention{Lines: c.lines}.LineRange()
		if first != c.first || last != c.last || ok != c.ok {
			t.Fatalf("%q : %d, %d, %v", c.lines, first, last, ok)
		}
	}
}

func TestJSSpace(t *testing.T) {
	t.Run("la classe jsSpace est exactement \\s de JavaScript", func(t *testing.T) {
		for r := rune(0); r <= unicode.MaxRune; r++ {
			if r >= 0xD800 && r <= 0xDFFF {
				continue
			}
			prompt := []byte("x" + string(r) + "@a")
			if got := len(Parse(prompt)) == 1; got != isJSSpace(r) {
				t.Fatalf("U+%04X", r)
			}
		}
	})
}

var mentionAlphabet = []string{
	"@", "@", "@", "\"", "\"", " ", "\t", "\n", "\u00A0", "\u2028", "\uFEFF", "\u0085", "\u200B", "a", "b.md", "/",
	"#L", "#L", "1", "23", "-", ",", ";", ":", "!", "?", ")", "(", ".", "\xff", "\xe2\x80", "\U0001F600", "x@y",
}

func TestParseMatchesOracle(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 6))
	for i := range 50_000 {
		var b []byte
		for range 1 + rng.IntN(24) {
			b = append(b, mentionAlphabet[rng.IntN(len(mentionAlphabet))]...)
		}
		if got, want := Parse(b), oracle(b); !reflect.DeepEqual(got, want) {
			t.Fatalf("prompt %d %q : %+v, oracle %+v", i, b, got, want)
		}
	}
}

// FuzzMentions : tout prompt : Parse égal à l'oracle ; chaque mention commence par « @ » au début du prompt ou après
// un espacement, son chemin est non vide, présent dans son étendue, unique ; étendues croissantes et disjointes.
func FuzzMentions(f *testing.F) {
	for _, seed := range []string{
		"", "@a", `voir @docs/a.md, @"b c.md" et @src/x.ts#L10-20 — dev@example.org`, `@"a @b" @c`, `@"x`,
		"@a.ts#L1-2,", "@a#L1 @a#L2", "x\u00A0@a\u2028@b\uFEFF@c", "\xff@a @\xff", "@@@", `@"" @")"`,
	} {
		f.Add([]byte(seed))
	}
	for _, c := range loadVectors(f).Cases {
		f.Add(caseInput(f, c))
	}
	f.Fuzz(func(t *testing.T, prompt []byte) {
		if len(prompt) > 1<<16 {
			return
		}
		got := Parse(prompt)
		if want := oracle(prompt); !reflect.DeepEqual(got, want) {
			t.Fatalf("%+v, oracle %+v", got, want)
		}
		previous := 0
		seen := map[string]bool{}
		for _, m := range got {
			if m.ByteStart < previous || m.ByteEnd <= m.ByteStart || m.ByteEnd > len(prompt) || prompt[m.ByteStart] != '@' {
				t.Fatalf("étendue %+v après %d", m, previous)
			}
			if m.ByteStart > 0 {
				r, _ := utf8.DecodeLastRune(prompt[:m.ByteStart])
				if !isJSSpace(r) {
					t.Fatalf("mention sans espacement avant : %+v", m)
				}
			}
			if m.Path == "" || seen[m.Path] || !bytes.Contains(prompt[m.ByteStart:m.ByteEnd], []byte(m.Path)) {
				t.Fatalf("chemin %+v", m)
			}
			seen[m.Path] = true
			previous = m.ByteEnd
		}
	})
}

// TestParseWorstCases : 1 Mio de prompts hostiles, en temps linéaire (expressions RE2).
func TestParseWorstCases(t *testing.T) {
	const size = 1 << 20
	fill := func(unit string) []byte { return []byte(strings.Repeat(unit, size/len(unit))) }
	for _, c := range []struct {
		name   string
		prompt []byte
	}{
		{"mentions courtes", fill("@a ")},
		{"guillemets ouverts sans fermeture", append([]byte(`@"`), fill("a ")...)},
		{"guillemets ouverts répétés", fill(`@"a `)},
		{"arobases", fill("@")},
		{"ponctuation finale", append([]byte("@a"), fill(",")...)},
		{"suffixes de lignes", fill("@a#L1-2 ")},
		{"chiffres sans suffixe", append([]byte("@a"), fill("1")...)},
		{"espacements", fill("\u3000")},
		{"octets invalides", fill("\xff @")},
		{"un seul chemin de 1 Mio", append([]byte("@"), fill("a")...)},
		{"doublons", fill("@a.md ")},
	} {
		t.Run("pire cas borné — "+c.name, func(t *testing.T) {
			start := time.Now()
			Parse(c.prompt)
			if elapsed := time.Since(start); elapsed > 3*time.Second {
				t.Fatalf("%v", elapsed)
			}
		})
	}
}
