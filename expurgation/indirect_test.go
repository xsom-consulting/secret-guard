// SPDX-License-Identifier: PolyForm-Small-Business-1.0.0

package expurgation

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // valeur fictive de forme hexadécimale, aucune sécurité
	"encoding/hex"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/detect"
)

// Valeurs fictives assemblées à l'exécution : mot de passe fort et valeur hexadécimale de 40 caractères (formes que
// l'entropie ne suffit pas toujours à trouver).
func syntheticStrongPassword() string { return "Kx7" + "#mQ2" + "!vR9" + "pL4~" }

func syntheticHex40() string {
	sum := sha1.Sum([]byte("valeur fictive du banc"))
	return hex.EncodeToString(sum[:])
}

// TestIndirectAssignments : chaque gabarit d'affectation indirecte du banc du 2026-11-08 est détecté par une règle
// contextuelle, et l'expurgation ne laisse rien. En échec avant v0.5.2 (aucun constat).
func TestIndirectAssignments(t *testing.T) {
	rules := loadInitialRules(t)
	name := "DB_PASS" + "WORD"
	lower := strings.ToLower(name)
	dotted := "db." + "pass" + "word"
	for _, value := range []string{syntheticStrongPassword(), syntheticHex40()} {
		for _, c := range []struct{ name, before, after string }{
			{"Go os.Setenv", "\tos.Setenv(\"" + name + "\", \"", "\")"},
			{"Java setProperty", "        props.setProperty(\"" + dotted + "\", \"", "\");"},
			{"Rust set_var", "    std::env::set_var(\"" + name + "\", \"", "\");"},
			{"Python setdefault", "os.environ.setdefault(\"" + name + "\", \"", "\")"},
			{"SQL VALUES", "INSERT INTO settings (name, value) VALUES ('" + lower + "', '", "');"},
			{"tuple", "pairs = [(\"" + lower + "\", \"", "\")]"},
			{"Markdown liste", "- `" + name + "` : `", "`"},
			{"Markdown tableau", "| `" + name + "` | `", "` |"},
			{"diff ajout", "+" + name + "=", ""},
			{"diff retrait", "-" + name + "=", ""},
			{"diff export", "+export " + name + "=", ""},
			{"Rust const typée", "const " + name + ": &str = \"", "\";"},
			{"Kotlin val typée", "val " + lower + ": String = \"", "\""},
			{"Python annotation", lower + ": str = \"", "\""},
			{"Go var typée", "var " + lower + " string = \"", "\""},
		} {
			t.Run(c.name, func(t *testing.T) {
				input := c.before + value + c.after
				result := detect.Scan([]byte(input), rules, detect.Options{})
				start, end := len(c.before), len(c.before)+len(value)
				found := false
				for _, f := range result.Findings {
					if strings.HasPrefix(f.RuleID, contextualRulePrefix) && f.ByteStart <= start && f.ByteEnd >= end {
						found = true
					}
				}
				if !result.Complete || !found {
					t.Fatalf("aucun constat contextuel sur la valeur : %+v", result.Findings)
				}
				text, _, sanitized := expurgateBoth(t, []byte(input), rules, nil, Options{}, func() func(detect.Finding) (int, bool) { return fixedOrdinal(1) })
				if sanitized.Failure != detect.SanitizeNone || bytes.Contains(text, []byte(value)) {
					t.Fatalf("expurgation : %s", sanitized.Failure)
				}
			})
		}
	}
}
