package detect

import (
	"regexp"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/pack"
)

// loadInitialPack lit le Pack initial embarqué par le décodage strict du schéma RulePack (pack.Decode).
func loadInitialPack(t testing.TB) pack.Pack {
	t.Helper()
	initial, err := pack.Initial()
	if err != nil {
		t.Fatalf("Pack initial hors du schéma RulePack : %v", err)
	}
	if len(initial.Rules) == 0 {
		t.Fatal("Pack initial sans règle")
	}
	return *initial
}

// lengthBoundsValid applique la règle des bornes de docs/rule-pack.md : 0 = borne absente, indépendamment l'une de
// l'autre ; deux bornes présentes : minLength ≤ maxLength.
func lengthBoundsValid(minLength, maxLength int) bool {
	return minLength == 0 || maxLength == 0 || minLength <= maxLength
}

func TestLengthBounds(t *testing.T) {
	t.Run("0 = borne absente, indépendamment l'une de l'autre", func(t *testing.T) {
		cases := []struct {
			minLength, maxLength int
			valid                bool
		}{
			{0, 0, true},
			{5, 0, true},
			{0, 5, true},
			{5, 5, true},
			{3, 1281, true},
			{10, 5, false},
		}
		for _, c := range cases {
			if got := lengthBoundsValid(c.minLength, c.maxLength); got != c.valid {
				t.Errorf("{minLength: %d, maxLength: %d} : %v, attendu %v", c.minLength, c.maxLength, got, c.valid)
			}
		}
	})
}

func TestInitialPackCompilesInRE2(t *testing.T) {
	t.Run("chaque règle du Pack initial compile en RE2", func(t *testing.T) {
		p := loadInitialPack(t)
		withPattern := 0
		for _, rule := range p.Rules {
			if rule.Pattern == "" {
				continue
			}
			withPattern++
			if _, err := regexp.Compile(rule.Pattern); err != nil {
				t.Errorf("règle %s : motif refusé par RE2 : %v", rule.RuleID, err)
			}
		}
		for _, rule := range p.Rules {
			if !lengthBoundsValid(rule.MinLength, rule.MaxLength) {
				t.Errorf("règle %s : minLength %d > maxLength %d", rule.RuleID, rule.MinLength, rule.MaxLength)
			}
		}
		if withPattern == 0 {
			t.Fatal("aucun motif à compiler")
		}
	})
}

func TestBasicAuthWithoutBackreference(t *testing.T) {
	t.Run("la règle -u user:motdepasse reconnaît les trois formes sans rétro-référence", func(t *testing.T) {
		p := loadInitialPack(t)
		var pattern string
		for _, rule := range p.Rules {
			if rule.RuleID == "cli_basic_auth" {
				pattern = rule.Pattern
			}
		}
		if pattern == "" || strings.Contains(pattern, `\1`) {
			t.Fatalf("motif cli_basic_auth absent ou avec rétro-référence : %q", pattern)
		}
		re := regexp.MustCompile(pattern)
		// Entrées assemblées à l'exécution : écrites telles quelles, la recherche de secrets du dépôt les prendrait
		// pour des identifiants (règle curl-auth-user de gitleaks).
		credentials := "alice" + ":" + "s3cr3t"
		cases := []struct {
			input string
			match bool
		}{
			{`curl -u "` + credentials + `" https://x`, true},
			{`curl -u '` + credentials + `' https://x`, true},
			{`curl -u ` + credentials + ` https://x`, true},
			{`curl --user=` + credentials, true},
			{`curl -u '` + credentials + `" https://x`, false},
			{`curl -u "` + credentials + `' https://x`, false},
		}
		for _, c := range cases {
			if got := re.MatchString(c.input); got != c.match {
				t.Errorf("%q : correspondance %v, attendu %v", c.input, got, c.match)
			}
		}
	})
}
