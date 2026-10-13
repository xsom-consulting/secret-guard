package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// corpusFiles rend les fichiers du manifeste du corpus de parité.
func corpusFiles(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(corpusDir + "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Files []struct {
			File string `json:"file"`
		} `json:"files"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil || len(manifest.Files) == 0 {
		t.Fatalf("manifeste illisible : %v", err)
	}
	files := make([]string, 0, len(manifest.Files))
	for _, f := range manifest.Files {
		files = append(files, f.File)
	}
	return files
}

// options rend les options d'analyse du cas (languageId absent : Options vide) ; faux pour un languageId vide mais
// présent, que Options ne représente pas.
func (c corpusCase) options() (Options, bool) {
	if c.LanguageID == nil {
		return Options{}, true
	}
	return Options{LanguageID: *c.LanguageID}, *c.LanguageID != ""
}

// parityDifference compare le résultat de Scan au résultat attendu du corpus ; vide s'ils sont égaux. Le message ne
// porte que l'issue, les règles et les positions, jamais l'entrée.
func parityDifference(t *testing.T, rules *Rules, c corpusCase) string {
	options, ok := c.options()
	if !ok {
		return "languageId vide, non représentable par Options"
	}
	result := Scan(c.bytes(t), rules, options)
	if result.Failure != Failure(c.Expected.Failure) || result.Complete != c.Expected.Complete {
		return fmt.Sprintf("issue %q (complete %v), attendu %q (complete %v)", result.Failure, result.Complete,
			c.Expected.Failure, c.Expected.Complete)
	}
	got := corpusForm(result.Findings)
	want := append([]corpusFinding(nil), c.Expected.Findings...)
	sortCorpusFindings(want)
	if len(got) != len(want) {
		return fmt.Sprintf("%d constats, attendu %d\nobtenus : %+v\nattendus : %+v", len(got), len(want), got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			return fmt.Sprintf("constat %d : %+v, attendu %+v", i, got[i], want[i])
		}
	}
	return ""
}

// TestRuleCorpus rejoue, règle par règle du Pack initial, ses cas du corpus de parité (« <ruleId>/… » des
// fichiers rules-*.json) par Scan : mêmes constats (règle, type de secret, vue, score, niveau, octets) et
// même issue que le moteur TypeScript de Secret Guard ; chaque règle a au moins un cas. Tout le corpus, fichier par
// fichier, est rejoué par TestParity.
func TestRuleCorpus(t *testing.T) {
	rules := loadInitialRules(t)
	p := loadInitialPack(t)
	files := corpusFiles(t)
	type loaded struct {
		file string
		c    corpusCase
	}
	var all []loaded
	for _, file := range files {
		for _, c := range loadCorpusFile(t, file) {
			all = append(all, loaded{file, c})
		}
	}
	for _, rule := range p.Rules {
		t.Run("règle "+rule.RuleID+" : même résultat que Secret Guard sur ses cas du corpus", func(t *testing.T) {
			checked := 0
			for _, l := range all {
				if !strings.HasPrefix(l.file, "rules-") || !strings.HasPrefix(l.c.ID, rule.RuleID+"/") {
					continue
				}
				checked++
				if diff := parityDifference(t, rules, l.c); diff != "" {
					t.Errorf("%s : %s", l.c.ID, diff)
				}
			}
			if checked == 0 {
				t.Fatal("aucun cas du corpus pour cette règle")
			}
		})
	}
}

// TestDifferentialCases rejoue un fichier de cas au format du corpus produit hors du dépôt par le moteur
// TypeScript de Secret Guard (comparaison différentielle sur entrées aléatoires, checkout au commit épinglé) :
// SECRET_GUARD_DIFFERENTIAL_CASES=<fichier>. Sauté sans cette variable. N'affiche que l'identifiant et les positions d'un cas
// en écart, jamais son entrée.
func TestDifferentialCases(t *testing.T) {
	path := os.Getenv("SECRET_GUARD_DIFFERENTIAL_CASES")
	if path == "" {
		t.Skip("SECRET_GUARD_DIFFERENTIAL_CASES absent : comparaison différentielle manuelle")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cases []corpusCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	rules := loadInitialRules(t)
	failed := 0
	for _, c := range cases {
		if diff := parityDifference(t, rules, c); diff != "" {
			failed++
			if failed <= 20 {
				t.Errorf("%s : %s", c.ID, diff)
			}
		}
	}
	t.Logf("%d cas, %d en écart", len(cases), failed)
}

// TestHandReadBounds : bornes lues à la main (au-delà de la limite de RE2), à leur valeur, une de moins et une de
// plus. Résultats attendus relevés sur le moteur TypeScript de Secret Guard (commit de UPSTREAM.md) par l'analyse
// complète : règle, octet de début, octet de fin.
func TestHandReadBounds(t *testing.T) {
	rules := loadInitialRules(t)
	value := func(n int) string { return strings.Repeat("aB3d", n/4+1)[:n] }
	smiley := string(rune(0x1F600))
	client := "c" + "md -u "
	type span struct {
		rule       string
		start, end int
	}
	cases := []struct {
		name  string
		input string
		want  []span
	}{
		{"queue d'URL de 2 047 unités", "x https://u:p@h/" + value(2047-6) + " end", []span{{"basic_auth_url", 2, 2057}}},
		{"queue d'URL de 2 048 unités", "x https://u:p@h/" + value(2048-6) + " end", []span{{"basic_auth_url", 2, 2058}}},
		{"queue d'URL de 2 049 unités, coupée à 2 048", "x https://u:p@h/" + value(2049-6) + " end", []span{{"basic_auth_url", 2, 2058}}},
		{"identifiants au-delà de la queue de 2 048 unités", "x https://h/" + value(2100) + "@x:p@h ok", nil},
		{"-u entre guillemets, mot de passe de 1 024 unités", client + `"alice:` + value(1024) + `" end`, []span{{"cli_basic_auth", 8, 1038}}},
		{"-u entre guillemets, mot de passe de 1 025 unités", client + `"alice:` + value(1025) + `" end`, nil},
		{"-u sans guillemets, mot de passe de 1 024 unités", client + "alice:" + value(1024) + " end", []span{{"cli_basic_auth", 7, 1037}}},
		{"-u sans guillemets, mot de passe de 1 100 unités, coupé à 1 024", client + "alice:" + value(1100) + " end", []span{{"cli_basic_auth", 7, 1037}}},
		{"-u, utilisateur de 257 unités", client + value(257) + ":pw end", nil},
		{"-u, utilisateur de 129 points de code hors du plan de base (258 unités)", client + strings.Repeat(smiley, 129) + ":pw end", nil},
		{"heredoc à 2 048 unités du début de la valeur", "pwd=" + strings.Repeat("a", 2048) + "<<EOF\nvalue\nEOF\n", []span{{"contextual_password", 4, 2068}}},
		{"heredoc à 2 049 unités du début de la valeur", "pwd=" + strings.Repeat("a", 2049) + "<<EOF\nvalue\nEOF\n", []span{{"contextual_password", 4, 2058}}},
	}
	for _, c := range cases {
		t.Run("borne lue à la main comme JavaScript — "+c.name, func(t *testing.T) {
			result := Scan([]byte(c.input), rules, Options{})
			if !result.Complete {
				t.Fatalf("analyse %s", result.Failure)
			}
			var got []span
			for _, f := range result.Findings {
				got = append(got, span{f.RuleID, f.ByteStart, f.ByteEnd})
			}
			if len(got) != len(c.want) {
				t.Fatalf("constats %v, attendu %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("constats %v, attendu %v", got, c.want)
				}
			}
		})
	}
}
