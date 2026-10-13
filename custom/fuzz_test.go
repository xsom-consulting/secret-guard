package custom

// Cibles de fuzz. Oracle des correspondances : portage dans les tests seulement de l'automate à retour arrière de
// l'origine (run de pattern.ts, sémantique d'ECMAScript : itération vide refusée), borné en pas ; la traduction RE2
// doit rendre exactement ses correspondances.
//
//	go test ./custom -run '^$' -fuzz '^FuzzCustomPattern$' -fuzztime=60s
//	go test ./custom -run '^$' -fuzz '^FuzzCustomPackDecode$' -fuzztime=60s

import (
	"errors"
	"reflect"
	"slices"
	"testing"
)

// errOracleBudget arrête l'oracle au-delà de son budget de pas (motif pathologique : aucune référence).
var errOracleBudget = errors.New("oracle : budget épuisé")

type oracle struct {
	text            []byte
	caseInsensitive bool
	steps           int
}

func (o *oracle) step() {
	o.steps--
	if o.steps < 0 {
		panic(errOracleBudget)
	}
}

func (o *oracle) accepts(codes []byte, at int) bool {
	if at >= len(o.text) || o.text[at] >= 128 {
		return false
	}
	set := foldedCodes(codes, o.caseInsensitive)
	return set[o.text[at]]
}

// flatten rend les caractères d'un groupe répété (une seule branche sans quantificateur).
func flatten(alternatives [][]term) [][]byte {
	var out [][]byte
	for _, t := range alternatives[0] {
		if t.atom.isGroup() {
			out = append(out, flatten(t.atom.group)...)
		} else {
			out = append(out, t.atom.codes)
		}
	}
	return out
}

// sequence suit run de l'origine : premier choix d'abord, retour arrière, continuation k.
func (o *oracle) sequence(terms []term, position int, k func(int) int) int {
	if len(terms) == 0 {
		return k(position)
	}
	o.step()
	t, rest := terms[0], terms[1:]
	next := func(end int) int { return o.sequence(rest, end, k) }
	switch {
	case !t.atom.isGroup():
		count := 0
		for count < t.max && o.accepts(t.atom.codes, position+count) {
			count++
		}
		for ; count >= t.min; count-- {
			if end := next(position + count); end >= 0 {
				return end
			}
			o.step()
		}
		return -1
	case t.max > 1:
		sets := flatten(t.atom.group)
		count := 0
		for count < t.max {
			at := position + count*len(sets)
			matched := true
			for i, codes := range sets {
				if !o.accepts(codes, at+i) {
					matched = false
					break
				}
			}
			if !matched {
				break
			}
			count++
		}
		for ; count >= t.min; count-- {
			if end := next(position + count*len(sets)); end >= 0 {
				return end
			}
			o.step()
		}
		return -1
	}
	iteration := next
	if t.min == 0 {
		// RepeatMatcher d'ECMAScript : une itération optionnelle qui n'a rien consommé échoue.
		iteration = func(end int) int {
			if end == position {
				return -1
			}
			return next(end)
		}
	}
	for _, alternative := range t.atom.group {
		if end := o.sequence(alternative, position, iteration); end >= 0 {
			return end
		}
	}
	if t.min == 0 {
		return next(position)
	}
	return -1
}

// referenceMatches rend les correspondances de matchAll par l'oracle, ou une erreur au-delà de son budget.
func referenceMatches(source string, caseInsensitive bool, text []byte) (matches [][2]int, err error) {
	alternatives, failure := parsePattern(source)
	if failure != "" {
		return nil, errors.New(string(failure))
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			if recovered != errOracleBudget {
				panic(recovered)
			}
			matches, err = nil, errOracleBudget
		}
	}()
	o := &oracle{text: text, caseInsensitive: caseInsensitive, steps: 2_000_000}
	matches = [][2]int{}
	for position := 0; position < len(text); {
		end := o.sequence([]term{{atom: atom{group: alternatives}, min: 1, max: 1}}, position, func(end int) int { return end })
		if end < 0 {
			position++
			continue
		}
		matches = append(matches, [2]int{position, end})
		position = end
	}
	return matches, nil
}

func re2Matches(p *safePattern, text []byte) [][2]int {
	out := [][2]int{}
	for _, loc := range p.re.FindAllIndex(text, -1) {
		out = append(out, [2]int{loc[0], loc[1]})
	}
	return out
}

func FuzzCustomPattern(f *testing.F) {
	for _, seed := range []struct {
		pattern string
		text    string
		ci      bool
	}{
		{"XYZ(?:a?|b)?", "XYZb XYZ XYZab", false},
		{"XYZ(?:(?:a?)?b?|c)?d", "XYZcd XYZd XYZabd", false},
		{"acme-(?:prod|staging)-db[0-9]{1,2}", "ACME-Prod-DB7 acme-staging-db12x Kcme", true},
		{"ABC[Z-a]{2}", "abcz` ABC[\\", true},
		{"(?:a|b){2}", "abab", false},
		{"[\\d\\s]{0,64}x", "12 34\t x", false},
		{"ABC(?:xy){0,3}z", "ABCxyxyz ABCz", false},
		{"\\.{1,2}\\s{2}[Z-a]{3}", "..  Z[a", false},
		{"ab", "ab", false},
	} {
		f.Add(seed.pattern, []byte(seed.text), seed.ci)
	}
	f.Fuzz(func(t *testing.T, pattern string, text []byte, caseInsensitive bool) {
		if len(text) > 512 {
			text = text[:512]
		}
		for _, hasContext := range []bool{false, true} {
			err := ValidatePattern(pattern, hasContext, caseInsensitive)
			var refusal *PatternError
			if err != nil && (!errors.As(err, &refusal) || !slices.Contains(PatternErrorCodes(), refusal.Code)) {
				t.Fatalf("refus hors liste fermée : %v", err)
			}
		}
		p, failure := compilePattern(pattern, true, caseInsensitive)
		if failure != "" {
			return
		}
		got := re2Matches(p, text)
		for _, m := range got {
			length := m[1] - m[0]
			if length < minMatchLength || length > p.maxLength || !p.first[text[m[0]]] {
				t.Fatalf("%q : correspondance %v hors des bornes du motif", pattern, m)
			}
			for _, c := range text[m[0]:m[1]] {
				if c >= 128 {
					t.Fatalf("%q : correspondance non ASCII", pattern)
				}
			}
		}
		want, err := referenceMatches(pattern, caseInsensitive, text)
		if err != nil {
			return // motif pathologique pour l'automate à retour arrière : aucune référence en temps borné
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%q (casse ignorée %v) sur %q : RE2 %v, ECMAScript %v (traduction %s)", pattern, caseInsensitive, text, got, want, p.key)
		}
	})
}

func FuzzCustomPackDecode(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schemaVersion":1,"kind":"xsom.secret-guard.rules-pack","packId":"p","tenantId":"t","version":1,` +
		`"issuedAt":"2026-01-01T00:00:00Z","expiresAt":"2027-01-01T00:00:00Z","issuer":"i","detectors":[{"id":"d",` +
		`"label":"l","category":"project","action":"block","match":{"type":"pattern","pattern":"CLI-[0-9]{8}"}}],` +
		`"tests":{"positives":[{"detector":"d","text":"CLI-12345678"}],"negatives":["x"]}}`))
	f.Add([]byte(`{"schemaVersion":1,"kind":"xsom.secret-guard.rules-pack","packId":"p","tenantId":"t","version":1,` +
		`"issuedAt":"2026-01-01T00:00:00Z","expiresAt":"2027-01-01T00:00:00Z","issuer":"i","detectors":[{"id":"t",` +
		`"label":"l","category":"project","action":"warn","match":{"type":"terms","salt":"ZGVmZ2hpamtsbW5vcHFycw==",` +
		`"digests":["b4a2b9d27b63501a1148ceb60b447e15ac46aa264fbfafc78efdebe48a3963fa"],"maxWords":2},` +
		`"context":{"keywords":["code"],"window":8}}],"tests":{"positives":[],"negatives":[]}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Compile(data)
		if err != nil {
			var refusal *PackError
			if !errors.As(err, &refusal) || !slices.Contains(PackErrorCodes(), refusal.Code) || p != nil {
				t.Fatalf("refus hors liste fermée : %v", err)
			}
			return
		}
		matches, err := p.Analyze(data, NewMeter(5_000_000, nil), 100)
		if err != nil && !errors.Is(err, ErrWorkBudget) && !errors.Is(err, ErrTooManyMatches) {
			t.Fatalf("%v", err)
		}
		for _, m := range matches {
			if m.Detector < 0 || m.Detector >= len(p.Detectors()) || m.ByteStart < 0 || m.ByteEnd <= m.ByteStart || m.ByteEnd > len(data) {
				t.Fatalf("détection hors du contenu : %+v", m)
			}
		}
	})
}

// TestReferenceOracle : l'oracle des tests suit les vecteurs de correspondance (même source que la traduction).
func TestReferenceOracle(t *testing.T) {
	cases := readCases[patternMatchingCase](t, "pattern-matching.json")
	checked := 0
	for _, c := range cases {
		for _, input := range c.Inputs {
			got, err := referenceMatches(c.Pattern, c.CaseInsensitive, input.bytes(t))
			if err != nil {
				continue
			}
			checked++
			if !reflect.DeepEqual(got, input.Expected) && (len(got) != 0 || len(input.Expected) != 0) {
				t.Fatalf("%s : oracle %v, attendu %v", c.ID, got, input.Expected)
			}
		}
	}
	if checked < 8000 {
		t.Fatalf("%d entrées vérifiées", checked)
	}
}
