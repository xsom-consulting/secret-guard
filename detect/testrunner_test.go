// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"strings"
	"testing"
)

// TestTestRunnerResultIsNotPassword : la marque de résultat d'un lanceur de tests n'est pas une affectation de mot de
// passe ; chaque forme voisine (minuscules, sans « --- », texte après la durée, autre séparateur, sans durée, mot
// avant la marque) reste un constat contextual_password. Les textes sont assemblés à l'exécution.
func TestTestRunnerResultIsNotPassword(t *testing.T) {
	rules := loadInitialRules(t)
	mark := strings.Join([]string{"PA", "SS"}, "")
	lower := strings.ToLower(mark)
	name := "TestFR111WriteBesideOwnership"
	cases := []struct {
		id     string
		input  string
		silent bool
	}{
		{"marque", "--- " + mark + ": " + name + " (0.20s)\n", true},
		{"sous-test", "    --- " + mark + ": " + name + "/sous_cas#01 (0.00s)\n", true},
		{"sous-test-parentheses", "    --- " + mark + ": " + name + "/FR-112:_cause,_v2,_mod-007_(essai1) (0.00s)\n", true},
		{"sous-test-vide", "--- " + mark + ": " + name + "/ (0.00s)\n", false},
		{"tabulation-et-retour", "\t--- " + mark + ": " + name + " (12s)\r\n", true},
		{"minuscules", "--- " + lower + ": " + name + " (0.20s)\n", false},
		{"sans-marqueur", mark + ": " + name + " (0.20s)\n", false},
		{"texte-apres", "--- " + mark + ": " + name + " (0.20s) suite\n", false},
		{"egal", "--- " + mark + "= " + name + " (0.20s)\n", false},
		{"sans-duree", "--- " + mark + ": " + name + "\n", false},
		{"mot-avant", "x --- " + mark + ": " + name + " (0.20s)\n", false},
	}
	for _, c := range cases {
		for _, lang := range []string{"", "shellscript"} {
			result := Scan([]byte(c.input), rules, Options{LanguageID: lang})
			if !result.Complete {
				t.Fatalf("%s/%s : analyse incomplète", c.id, lang)
			}
			found := false
			for _, f := range result.Findings {
				if f.RuleID == "contextual_password" {
					found = true
				}
			}
			if found == c.silent {
				t.Errorf("%s/%s : constat contextual_password %v, attendu %v", c.id, lang, found, !c.silent)
			}
		}
	}
}
