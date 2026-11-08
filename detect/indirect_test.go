package detect

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // valeur fictive de forme hexadécimale, aucune sécurité
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
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
				result := Scan([]byte(input), rules, Options{})
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
				text, _, sanitized := expurgateBoth(t, []byte(input), rules, nil, Options{}, func() func(Finding) (int, bool) { return fixedOrdinal(1) })
				if sanitized.Failure != SanitizeNone || bytes.Contains(text, []byte(value)) {
					t.Fatalf("expurgation : %s", sanitized.Failure)
				}
			})
		}
	}
}

// TestIndirectAssignmentsIgnoreOrdinaryCode : libellés, valeurs par défaut, constantes d'énumération, documentation
// de types et expressions régulières ne sont pas des affectations indirectes (relevé sur 5 786 fichiers de dépôts
// réels : aucun constat nouveau).
func TestIndirectAssignmentsIgnoreOrdinaryCode(t *testing.T) {
	rules := loadInitialRules(t)
	word := "pass" + "word"
	tok := "To" + "ken"
	for _, input := range []string{
		"label := t(\"" + word + "\", \"Mot de passe\")",
		"form.field(\"" + word + "\", \"required\")",
		"os.environ.get(\"API_" + strings.ToUpper(tok) + "\", \"default-value\")",
		"return fmt.Errorf(\"field %s pattern match: must match %s\", \"" + tok + "\", `^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$`)",
		"const RulePackSecretTypeApiKey RulePackSecretType = \"api_key\"",
		"const AdminLogObjectTypeAgent" + tok + " AdminLogObjectType = \"agent_" + strings.ToLower(tok) + "\"",
		"- `" + word + "` : `string`",
		"| `" + word + "` | `optionnel` |",
		"let " + word + ": String = \"\"",
	} {
		result := Scan([]byte(input), rules, Options{})
		for _, f := range result.Findings {
			if strings.HasPrefix(f.RuleID, contextualRulePrefix) {
				t.Errorf("%q : constat %s", input, f.RuleID)
			}
		}
	}
}

func TestIndirectValueShape(t *testing.T) {
	for value, want := range map[string]bool{
		syntheticStrongPassword(): true, syntheticHex40(): true, "Abc123xyz": true,
		"required": false, "default-value": false, "api_key": false, "Mot de passe": false, "short1A": false,
		"^[a-z0-9]{16}$": false,
	} {
		text := []byte("\"" + value + "\"")
		v := identityView(text)
		p := &parsedValue{start: 1, end: len(text) - 1, valueEnd: len(text) - 1, kind: kindQuoted}
		if got := indirectValueShape(v, p); got != want {
			t.Errorf("%q : %v, attendu %v", value, got, want)
		}
	}
	unquoted := identityView([]byte(syntheticHex40()))
	if indirectValueShape(unquoted, &parsedValue{start: 0, end: 40, valueEnd: 40, kind: kindUnquoted}) {
		t.Error("valeur sans guillemets admise")
	}
}

// TestIndirectWorstCases : entrées qui feraient relire les fenêtres ou les motifs des affectations indirectes à chaque
// correspondance ; chacune finit dans la borne de temps des pires cas.
func TestIndirectWorstCases(t *testing.T) {
	rules := loadInitialRules(t)
	word := "pass" + "word"
	for name, content := range map[string][]byte{
		"paires ouvertes sur une ligne":    ruleFill("(\"" + word + "\", \""),
		"accents graves ouverts":           ruleFill("`" + word + "` : `"),
		"lignes de diff":                   ruleFill("\n+" + word + "="),
		"déclarations typées sans valeur":  ruleFill(word + ": &str = "),
		"Go var sans valeur":               ruleFill("var " + word + " string = "),
		"morceaux de nom sans affectation": ruleFill("key "),
	} {
		t.Run(name, func(t *testing.T) {
			v := identityView(content)
			start := time.Now()
			if _, err := rules.scanContextualAssignments(v, &decodeBudget{}, language{}, true); err != nil && !errors.Is(err, errDecodeBudgetExhausted) {
				t.Fatalf("affectations : %v", err)
			}
			if elapsed := time.Since(start); elapsed > worstCaseTimeLimit {
				t.Fatalf("%v pour %d octets", elapsed, len(content))
			}
		})
	}
}
