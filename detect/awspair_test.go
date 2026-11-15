// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"strings"
	"testing"
)

// TestAWSKeyPair : règle composée AWS (awspair.go). Les valeurs d'essai sont assemblées par morceaux ; les cas du
// corpus (vectors/detection/rules-context-data.json, aws_access_key_pair/…) viennent d'une seconde écriture.
func TestAWSKeyPair(t *testing.T) {
	rules := loadInitialRules(t)
	keyID := strings.Join([]string{"AK", "IA", strings.Repeat("Q7", 8)}, "")
	forty := strings.Repeat(strings.Join([]string{"aB", "3d", "/"}, ""), 8)
	t.Run("un identifiant et une valeur de 40 caractères côte à côte, sans nom de variable : un seul constat critique, de l'un à l'autre", func(t *testing.T) {
		for _, input := range []string{keyID + "," + forty + "\n", forty + " " + keyID + "\n"} {
			result := Scan([]byte(input), rules, Options{})
			if !result.Complete || len(result.Findings) != 1 {
				t.Fatalf("constats %+v", result.Findings)
			}
			f := result.Findings[0]
			if f.RuleID != ruleAWSKeyPair || f.Level != LevelCritical || f.ByteStart != 0 || f.ByteEnd != len(input)-1 {
				t.Fatalf("constat %+v", f)
			}
		}
	})
	t.Run("l'identifiant seul, ou suivi d'une empreinte hexadécimale, reste un constat moyen de aws_access_key_id", func(t *testing.T) {
		for _, input := range []string{"compte " + keyID + "\n", keyID + " " + strings.Repeat("0a1B", 10) + "\n"} {
			result := Scan([]byte(input), rules, Options{})
			if !result.Complete || len(result.Findings) != 1 || result.Findings[0].RuleID != "aws_access_key_id" ||
				result.Findings[0].Level != LevelMedium {
				t.Fatalf("constats %+v", result.Findings)
			}
		}
	})
	t.Run("la paire d'exemple de la documentation d'AWS n'est pas un constat", func(t *testing.T) {
		var example []string
		for value := range publicExamples {
			if strings.HasPrefix(value, keyID[:4]) || len(value) == awsSecretLength {
				example = append(example, value)
			}
		}
		if len(example) != 2 {
			t.Fatalf("%d valeurs d'exemple", len(example))
		}
		if result := Scan([]byte(strings.Join(example, ",")+"\n"), rules, Options{}); !result.Complete || len(result.Findings) != 0 {
			t.Fatalf("constats %+v", result.Findings)
		}
	})
}
