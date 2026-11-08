// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"crypto/rand"
	"strings"
	"testing"
)

// brokenURLPassword tire un mot de passe de 12 caractères alphanumériques à l'exécution.
func brokenURLPassword(t *testing.T) string {
	t.Helper()
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = alphabet[int(raw[i])%len(alphabet)]
	}
	// Une majuscule, une minuscule et un chiffre au moins : jamais une valeur fictive.
	raw[0], raw[1], raw[2] = 'Q', 'm', '7'
	return string(raw)
}

func TestBrokenCredentialURL(t *testing.T) {
	rules := loadInitialRules(t)
	pw := brokenURLPassword(t)
	cases := []struct {
		name, before, after, rule string
	}{
		{"chevron et espace", "Voici ma base : postgres://admin:< ", "@db.exemple.fr:5432/prod. Recopie-la.", ruleDatabaseURL},
		{"espace seule", "postgres://admin: ", "@db.exemple.fr/prod", ruleDatabaseURL},
		{"mot de passe entre chevrons", "postgres://admin:<", ">@db.exemple.fr:5432/prod", ruleDatabaseURL},
		{"guillemets", "url = https://deploy:\"", "\"@git.exemple.fr/depot.git", ruleBasicAuthURL},
		{"tabulation", "mysql://root:\t", "@127.0.0.1:3306/app", ruleDatabaseURL},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			content := []byte(c.before + pw + c.after)
			result := Scan(content, rules, Options{})
			if !result.Complete {
				t.Fatalf("analyse incomplète : %v", result.Failure)
			}
			var found *Finding
			for i := range result.Findings {
				if result.Findings[i].RuleID == c.rule {
					found = &result.Findings[i]
				}
			}
			if found == nil {
				t.Fatalf("règle %s non trouvée", c.rule)
			}
			start, end := SecretRange(content, *found)
			if string(content[start:end]) != pw {
				t.Fatalf("partie secrète %d..%d différente du mot de passe", start, end)
			}
		})
	}
}

func TestBrokenCredentialURLRefusals(t *testing.T) {
	rules := loadInitialRules(t)
	pw := brokenURLPassword(t)
	cases := map[string]string{
		"fin de ligne":            "postgres://admin:\n" + pw + "@db.exemple.fr/prod",
		"trop de parasites":       "postgres://admin:<<<<< " + pw + "@db.exemple.fr/prod",
		"phrase sans @":           "postgres://admin: voir la documentation interne",
		"phrase recollée":         "postgres://admin: voir " + pw + "@db.exemple.fr",
		"sans utilisateur":        "postgres://:< " + pw + "@db.exemple.fr/prod",
		"utilisateur déjà fermé":  "postgres://admin@db:< " + pw + "@autre.fr",
		"valeur fictive":          "postgres://admin:< example@db.exemple.fr/prod",
		"gabarit <password>":      "postgres://admin:<password>@db.exemple.fr/prod",
		"gabarit <your_password>": "postgres://admin:<your_password>@db.exemple.fr/prod",
		"gabarit <db-secret>":     "postgres://admin:<db-secret>@db.exemple.fr/prod",
		"hôte absent":             "postgres://admin:< " + pw + "@",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			result := Scan([]byte(content), rules, Options{})
			for _, f := range result.Findings {
				if (f.RuleID == ruleDatabaseURL || f.RuleID == ruleBasicAuthURL) && strings.Contains(content[f.ByteStart:f.ByteEnd], "<") {
					t.Fatalf("URL abîmée recollée à tort (%s)", f.RuleID)
				}
				if (f.RuleID == ruleDatabaseURL || f.RuleID == ruleBasicAuthURL) && name != "utilisateur déjà fermé" {
					t.Fatalf("constat %s inattendu", f.RuleID)
				}
			}
		})
	}
}
