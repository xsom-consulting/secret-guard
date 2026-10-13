package custom

// Parité avec le moteur TypeScript d'origine : vecteurs vectors/custom/ (generator/custom/), produits par l'origine
// sur les vecteurs du contrat, les entrées de ses tests et des cas synthétiques. Un écart déclaré (champ divergence,
// liste de UPSTREAM.md) est vérifié contre le résultat Go qu'il annonce ; aucun autre écart n'est admis.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	stdjson "encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"encoding/json/v2"
)

const vectorsDir = "../vectors/custom/"

type vectorManifest struct {
	FormatVersion  int    `json:"formatVersion"`
	UpstreamCommit string `json:"upstreamCommit"`
	Files          []struct {
		File  string `json:"file"`
		Cases int    `json:"cases"`
	} `json:"files"`
	Tests []string `json:"tests"`
}

func readManifest(t *testing.T) vectorManifest {
	t.Helper()
	data, err := os.ReadFile(vectorsDir + "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m vectorManifest
	if err := stdjson.Unmarshal(data, &m); err != nil {
		t.Fatalf("manifeste illisible : %v", err)
	}
	return m
}

// readCases lit un fichier de cas et vérifie leur nombre contre le manifeste.
func readCases[T any](t *testing.T, name string) []T {
	t.Helper()
	data, err := os.ReadFile(vectorsDir + name)
	if err != nil {
		t.Fatal(err)
	}
	var cases []T
	if err := stdjson.Unmarshal(data, &cases); err != nil {
		t.Fatalf("%s illisible : %v", name, err)
	}
	for _, f := range readManifest(t).Files {
		if f.File == name {
			if f.Cases != len(cases) || len(cases) == 0 {
				t.Fatalf("%s : %d cas, %d au manifeste", name, len(cases), f.Cases)
			}
			return cases
		}
	}
	t.Fatalf("%s absent du manifeste", name)
	return nil
}

// vectorInput est une entrée écrite en texte UTF-8, en base64 ou en répétitions [[texte, fois], …].
type vectorInput struct {
	Input         stdjson.RawMessage `json:"input"`
	InputEncoding string             `json:"inputEncoding"`
}

func (v vectorInput) bytes(t *testing.T) []byte {
	t.Helper()
	return decodeVectorInput(t, v.Input, v.InputEncoding)
}

func decodeVectorInput(t *testing.T, raw stdjson.RawMessage, encoding string) []byte {
	t.Helper()
	switch encoding {
	case "utf8", "base64":
		var text string
		if err := stdjson.Unmarshal(raw, &text); err != nil {
			t.Fatal(err)
		}
		if encoding == "utf8" {
			return []byte(text)
		}
		out, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		return out
	case "runs":
		var runs [][2]stdjson.RawMessage
		if err := stdjson.Unmarshal(raw, &runs); err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		for _, run := range runs {
			var text string
			var times int
			if stdjson.Unmarshal(run[0], &text) != nil || stdjson.Unmarshal(run[1], &times) != nil || times < 1 {
				t.Fatal("répétition illisible")
			}
			b.WriteString(strings.Repeat(text, times))
		}
		return []byte(b.String())
	}
	t.Fatalf("encodage d'entrée inconnu %q", encoding)
	return nil
}

type packCase struct {
	ID           string             `json:"id"`
	Pack         stdjson.RawMessage `json:"pack"`
	PackEncoding string             `json:"packEncoding"`
	Upstream     string             `json:"upstream"`
	Expected     packExpected       `json:"expected"`
	Divergence   *struct {
		Reason string       `json:"reason"`
		Go     packExpected `json:"go"`
	} `json:"divergence"`
}

type packExpected struct {
	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

func compileOutcome(data []byte) packExpected {
	_, err := Compile(data)
	if err == nil {
		return packExpected{Valid: true}
	}
	refusal, ok := err.(*PackError)
	if !ok {
		return packExpected{Error: "?"}
	}
	return packExpected{Error: string(refusal.Code)}
}

// declaredDivergences : raisons d'écart admises (UPSTREAM.md, « Écarts déclarés »).
var declaredDivergences = map[string]bool{
	"json_duplicate_member": true, "json_lone_surrogate": true, "json_invalid_utf8": true, "backtracking_budget": true,
}

func TestCustomPackParity(t *testing.T) {
	cases := readCases[packCase](t, "packs.json")
	codes := map[string]bool{}
	for _, c := range cases {
		got := compileOutcome(decodeVectorInput(t, c.Pack, c.PackEncoding))
		want := c.Expected
		if c.Divergence != nil {
			if !declaredDivergences[c.Divergence.Reason] {
				t.Errorf("%s : raison d'écart non déclarée %q", c.ID, c.Divergence.Reason)
			}
			want = c.Divergence.Go
		}
		if got != want {
			t.Errorf("%s : %+v, attendu %+v", c.ID, got, want)
		}
		codes[want.Error] = true
	}
	for _, code := range PackErrorCodes() {
		if !codes[string(code)] {
			t.Errorf("aucun vecteur pour le code %s", code)
		}
	}
	t.Logf("parité des Packs : %d cas", len(cases))
}

type patternValidationCase struct {
	ID              string `json:"id"`
	Pattern         string `json:"pattern"`
	HasContext      bool   `json:"hasContext"`
	CaseInsensitive bool   `json:"caseInsensitive"`
	Expected        struct {
		Valid bool   `json:"valid"`
		Error string `json:"error"`
	} `json:"expected"`
}

type patternMatchingCase struct {
	ID              string `json:"id"`
	Pattern         string `json:"pattern"`
	CaseInsensitive bool   `json:"caseInsensitive"`
	Inputs          []struct {
		vectorInput
		Expected [][2]int `json:"expected"`
	} `json:"inputs"`
}

func TestCustomPatternParity(t *testing.T) {
	t.Run("validité des motifs : codes du contrat dans l'ordre de l'origine", func(t *testing.T) {
		codes := map[string]bool{}
		cases := readCases[patternValidationCase](t, "pattern-validation.json")
		for _, c := range cases {
			err := ValidatePattern(c.Pattern, c.HasContext, c.CaseInsensitive)
			code := ""
			if err != nil {
				code = string(err.(*PatternError).Code)
			}
			if (err == nil) != c.Expected.Valid || code != c.Expected.Error {
				t.Errorf("%s : %q → %q, attendu %q", c.ID, c.Pattern, code, c.Expected.Error)
			}
			codes[c.Expected.Error] = true
		}
		for _, code := range PatternErrorCodes() {
			if !codes[string(code)] {
				t.Errorf("aucun vecteur pour le code %s", code)
			}
		}
		t.Logf("validité des motifs : %d cas", len(cases))
	})
	t.Run("correspondances RE2 égales à matchAll d'ECMAScript", func(t *testing.T) {
		cases := readCases[patternMatchingCase](t, "pattern-matching.json")
		inputs := 0
		for _, c := range cases {
			p, failure := compilePattern(c.Pattern, true, c.CaseInsensitive)
			if failure != "" {
				t.Errorf("%s : motif refusé (%s)", c.ID, failure)
				continue
			}
			for i, input := range c.Inputs {
				inputs++
				got := [][2]int{}
				for _, loc := range p.re.FindAllIndex(input.bytes(t), -1) {
					got = append(got, [2]int{loc[0], loc[1]})
				}
				if !reflect.DeepEqual(got, input.Expected) && (len(got) != 0 || len(input.Expected) != 0) {
					t.Errorf("%s [%d] : %q → %v, attendu %v (RE2 %s)", c.ID, i, c.Pattern, got, input.Expected, p.key)
				}
			}
		}
		t.Logf("correspondances : %d motifs, %d entrées", len(cases), inputs)
	})
}

type detectionCase struct {
	ID        string             `json:"id"`
	Detectors stdjson.RawMessage `json:"detectors"`
	Inputs    []struct {
		vectorInput
		Expected [][3]int `json:"expected"`
	} `json:"inputs"`
}

// packOfDetectors compile des détecteurs seuls, sans essais ni contrôle des positifs (comme les vecteurs
// « detection » du contrat).
func packOfDetectors(t *testing.T, raw []byte) *Pack {
	t.Helper()
	var values []any
	if err := json.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	p := &Pack{}
	for _, value := range values {
		if !isDetector(value) {
			t.Fatalf("détecteur hors schéma")
		}
		d := compileDetector(detectorSpecOf(value.(object)))
		if d == nil {
			t.Fatalf("motif refusé")
		}
		p.detectors = append(p.detectors, d)
	}
	p.groups = termGroups(p.detectors)
	return p
}

func TestCustomDetectionParity(t *testing.T) {
	cases := readCases[detectionCase](t, "detection.json")
	inputs := 0
	for _, c := range cases {
		p := packOfDetectors(t, c.Detectors)
		for i, input := range c.Inputs {
			inputs++
			results, err := p.detect(input.bytes(t), NewMeter(1<<62, nil), -1, nil)
			if err != nil {
				t.Errorf("%s [%d] : %v", c.ID, i, err)
				continue
			}
			got := [][3]int{}
			for index, spans := range results {
				for _, s := range spans {
					got = append(got, [3]int{index, s.start, s.end})
				}
			}
			if !reflect.DeepEqual(got, input.Expected) && (len(got) != 0 || len(input.Expected) != 0) {
				t.Errorf("%s [%d] : %v, attendu %v", c.ID, i, got, input.Expected)
			}
		}
	}
	t.Logf("détections : %d jeux de détecteurs, %d entrées", len(cases), inputs)
}

type termCase struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Input    string `json:"input"`
	Salt     string `json:"salt"`
	Expected struct {
		Normalized string `json:"normalized"`
		Digest     string `json:"digest"`
	} `json:"expected"`
}

func TestCustomTermsParity(t *testing.T) {
	cases := readCases[termCase](t, "terms.json")
	for _, c := range cases {
		normalized := c.Input
		if c.Kind == "term" {
			normalized = NormalizeTerm(c.Input)
		}
		if normalized != c.Expected.Normalized {
			t.Errorf("%s : %q → %q, attendu %q", c.ID, c.Input, normalized, c.Expected.Normalized)
		}
		if c.Salt == "" {
			continue
		}
		if digest := TermDigest(decodeSalt(c.Salt), normalized); digest != c.Expected.Digest {
			t.Errorf("%s : condensat %s, attendu %s", c.ID, digest, c.Expected.Digest)
		}
	}
}

type unicodeCase struct {
	ID     string `json:"id"`
	From   int    `json:"from"`
	To     int    `json:"to"`
	SHA256 string `json:"sha256"`
}

// unicodeBlockLines suit unicodeBlockLines de generator/custom/unicode.ts.
func unicodeBlockLines(from, to int) []byte {
	var b strings.Builder
	for cp := from; cp <= to; cp++ {
		if cp >= 0xD800 && cp <= 0xDFFF {
			continue
		}
		r := rune(cp)
		character := string(r)
		if isWordRune(r) {
			fmt.Fprintf(&b, "%d:%s\n", cp, hex.EncodeToString([]byte(normalizeWord(character))))
		}
		fmt.Fprintf(&b, "%d~%s~%s\n", cp, hex.EncodeToString([]byte(jsToLower("AΣ"+character))),
			hex.EncodeToString([]byte(jsToLower("A"+character+"Σ"))))
	}
	return []byte(b.String())
}

func TestCustomUnicodeParity(t *testing.T) {
	cases := readCases[unicodeCase](t, "unicode.json")
	if cases[len(cases)-1].To != utf8.MaxRune {
		t.Fatal("blocs incomplets")
	}
	for _, c := range cases {
		sum := sha256.Sum256(unicodeBlockLines(c.From, c.To))
		if got := hex.EncodeToString(sum[:]); got != c.SHA256 {
			t.Errorf("%s : bloc différent de Node (mots normalisés ou minuscules de toLowerCase)", c.ID)
		}
	}
}

func TestCustomVectorsManifest(t *testing.T) {
	m := readManifest(t)
	if m.FormatVersion != 1 || len(m.UpstreamCommit) != 40 || len(m.Tests) == 0 {
		t.Fatalf("%+v", m)
	}
	// Chaque identifiant upstream/<n> désigne un test de la table.
	for _, name := range []string{"pattern-validation.json", "packs.json", "scan.json", "detection.json", "pattern-matching.json"} {
		var cases []struct {
			ID string `json:"id"`
		}
		data, err := os.ReadFile(vectorsDir + name)
		if err != nil || stdjson.Unmarshal(data, &cases) != nil {
			t.Fatal(name)
		}
		for _, c := range cases {
			rest, ok := strings.CutPrefix(c.ID, "upstream/")
			if !ok {
				continue
			}
			number, _, _ := strings.Cut(rest, " ")
			n, err := strconv.Atoi(number)
			if err != nil || n < 0 || n >= len(m.Tests) {
				t.Errorf("%s : test inconnu", c.ID)
			}
		}
	}
}
