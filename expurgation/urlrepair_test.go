// SPDX-License-Identifier: PolyForm-Small-Business-1.0.0

package expurgation

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/xsom-consulting/secret-guard/detect"
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
			result := detect.Scan(content, rules, detect.Options{})
			if !result.Complete {
				t.Fatalf("analyse incomplète : %v", result.Failure)
			}
			var found *detect.Finding
			for i := range result.Findings {
				if result.Findings[i].RuleID == c.rule {
					found = &result.Findings[i]
				}
			}
			if found == nil {
				t.Fatalf("règle %s non trouvée", c.rule)
			}
			start, end := secretPart(content, *found)
			if string(content[start:end]) != pw {
				t.Fatalf("partie secrète %d..%d différente du mot de passe", start, end)
			}
			text, subs, sanitized := ExpurgateAndRescan(content, rules, nil, Options{}, fixedOrdinal(1))
			if sanitized.Failure != detect.SanitizeNone {
				t.Fatalf("expurgation en échec : %v", sanitized.Failure)
			}
			if bytes.Contains(text, []byte(pw)) {
				t.Fatal("mot de passe encore présent après expurgation")
			}
			if len(subs) != 1 {
				t.Fatalf("%d Substituts, un attendu", len(subs))
			}
			want := c.before + subs[0].Replacement + c.after
			if string(text) != want {
				t.Fatalf("texte expurgé inattendu : seul le mot de passe doit être remplacé")
			}
		})
	}
}
