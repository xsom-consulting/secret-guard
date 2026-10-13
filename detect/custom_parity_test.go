package detect_test

// Parité de l'analyse avec un Pack de règles du client (Options.Custom) : vecteurs vectors/custom/scan.json, produits
// par le moteur TypeScript d'origine (generator/custom/). Un écart déclaré (champ divergence, liste de UPSTREAM.md)
// est vérifié contre le résultat Go qu'il annonce ; aucun autre écart n'est admis.

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/custom"
	"github.com/xsom-consulting/secret-guard/detect"
	"github.com/xsom-consulting/secret-guard/pack"
)

const customVectors = "../vectors/custom/"

type customScanExpected struct {
	Complete bool            `json:"complete"`
	Failure  string          `json:"failure"`
	Findings []publicFinding `json:"findings"`
}

type customScanCase struct {
	ID            string             `json:"id"`
	Pack          *string            `json:"pack"`
	Input         json.RawMessage    `json:"input"`
	InputEncoding string             `json:"inputEncoding"`
	Expected      customScanExpected `json:"expected"`
	Divergence    *struct {
		Reason string             `json:"reason"`
		Go     customScanExpected `json:"go"`
	} `json:"divergence"`
}

type customPackCase struct {
	ID           string          `json:"id"`
	Pack         json.RawMessage `json:"pack"`
	PackEncoding string          `json:"packEncoding"`
}

// customInput décode une entrée des vecteurs : texte UTF-8, base64 ou répétitions [[texte, fois], …].
func customInput(t *testing.T, raw json.RawMessage, encoding string) []byte {
	t.Helper()
	switch encoding {
	case "utf8", "base64":
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
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
		var runs [][2]json.RawMessage
		if err := json.Unmarshal(raw, &runs); err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		for _, run := range runs {
			var text string
			var times int
			if json.Unmarshal(run[0], &text) != nil || json.Unmarshal(run[1], &times) != nil || times < 1 {
				t.Fatal("répétition illisible")
			}
			b.WriteString(strings.Repeat(text, times))
		}
		return []byte(b.String())
	}
	t.Fatalf("encodage d'entrée inconnu %q", encoding)
	return nil
}

func readJSON(t *testing.T, path string, into any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatalf("%s illisible : %v", path, err)
	}
}

func TestCustomScanParity(t *testing.T) {
	var manifest struct {
		Files []struct {
			File  string `json:"file"`
			Cases int    `json:"cases"`
		} `json:"files"`
	}
	readJSON(t, customVectors+"manifest.json", &manifest)
	var cases []customScanCase
	readJSON(t, customVectors+"scan.json", &cases)
	var packCases []customPackCase
	readJSON(t, customVectors+"packs.json", &packCases)
	for _, f := range manifest.Files {
		if f.File == "scan.json" && f.Cases != len(cases) {
			t.Fatalf("%d cas, %d au manifeste", len(cases), f.Cases)
		}
	}
	initial, err := pack.Initial()
	if err != nil {
		t.Fatal(err)
	}
	rules, err := detect.LoadRules(initial)
	if err != nil {
		t.Fatal(err)
	}
	packs := map[string]*custom.Pack{}
	for _, p := range packCases {
		packs[p.ID] = nil
		if compiled, err := custom.Compile(customInput(t, p.Pack, p.PackEncoding)); err == nil {
			packs[p.ID] = compiled
		}
	}
	order := func(f []publicFinding) {
		sort.SliceStable(f, func(i, j int) bool {
			if f[i].ByteStart != f[j].ByteStart {
				return f[i].ByteStart < f[j].ByteStart
			}
			if f[i].RuleID != f[j].RuleID {
				return f[i].RuleID < f[j].RuleID
			}
			return f[i].ByteEnd < f[j].ByteEnd
		})
	}
	failures := map[string]bool{}
	divergences := 0
	for _, c := range cases {
		var options detect.Options
		if c.Pack != nil {
			compiled, ok := packs[*c.Pack]
			if !ok || compiled == nil {
				t.Fatalf("%s : Pack %s absent ou refusé", c.ID, *c.Pack)
			}
			options.Custom = compiled
		}
		result := detect.Scan(customInput(t, c.Input, c.InputEncoding), rules, options)
		want := c.Expected
		if c.Divergence != nil {
			if c.Divergence.Reason != "backtracking_budget" {
				t.Errorf("%s : raison d'écart non déclarée %q", c.ID, c.Divergence.Reason)
			}
			want = c.Divergence.Go
			divergences++
		}
		failures[want.Failure] = true
		if result.Complete != want.Complete || string(result.Failure) != want.Failure {
			t.Errorf("%s : issue %s, attendu %s", c.ID, result.Failure, want.Failure)
			continue
		}
		if !result.Complete && result.Findings != nil {
			t.Errorf("%s : constats d'une analyse incomplète", c.ID)
		}
		got := make([]publicFinding, 0, len(result.Findings))
		for i, f := range result.Findings {
			if i > 0 && (f.ByteStart < result.Findings[i-1].ByteStart ||
				(f.ByteStart == result.Findings[i-1].ByteStart && f.ByteEnd < result.Findings[i-1].ByteEnd)) {
				t.Errorf("%s : constats non triés par étendue", c.ID)
			}
			got = append(got, publicFinding{
				RuleID: f.RuleID, SecretType: f.SecretType, Encoding: f.Encoding, Score: f.Score, Level: f.Level,
				ByteStart: f.ByteStart, ByteEnd: f.ByteEnd,
			})
		}
		expected := append([]publicFinding{}, want.Findings...)
		order(got)
		order(expected)
		if !reflect.DeepEqual(got, expected) && (len(got) != 0 || len(expected) != 0) {
			t.Errorf("%s : constats %+v, attendu %+v", c.ID, got, expected)
		}
	}
	for _, failure := range []string{"none", "custom_budget", "custom_too_many"} {
		if !failures[failure] {
			t.Errorf("aucun vecteur d'issue %s", failure)
		}
	}
	t.Logf("parité de l'analyse avec un Pack de règles du client : %d cas, dont %d écarts déclarés", len(cases), divergences)
}
