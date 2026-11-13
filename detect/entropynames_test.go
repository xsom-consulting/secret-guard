// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestIsEntropyName(t *testing.T) {
	for value, want := range map[string]bool{
		"SubscriptionOverviewLinesElemVerificationsElem":          true,
		"AdminLogPageEntriesElem_ActorKindUser":                   true,
		"LICENSE-PolyForm-Small-Business-1":                       true,
		"claude/worktrees/agent-a3f9c2e1b7d40568e/agent":          true,
		"exemple-fleet-4e7b19a0c2d5/9b31f04e6c87d2a5e01f/step-01": true,
		"USERPROFILE/Downloads/Install-VSCode-1":                  false, // sigle dans un mot : cas de l'origine
		"deadbeef-0123456789abcdef01234567":                       false, // hexadécimal coupé : aucun mot de nom
		"0123456789abcdef0123456789abcdef01":                      false, // hexadécimal seul
		"secrets/0123456789abcdef0123456789abcdef":                false, // hexadécimal de 32 : trop long
		"cp-out/Zq8Lr2Vx9Mn4Kp7Tw3Yb6Hc1Jd5":                      false,
		"aGVsbG8gd29ybGQgaGVsbG8gd29ybGQ":                         false,
		"PolyForm+Small":                                          false,
	} {
		if got := isEntropyName([]byte(value)); got != want {
			t.Errorf("isEntropyName(%q) = %v, attendu %v", value, got, want)
		}
	}
}

// TestEntropyNameRarelyMatchesTokens : une suite aléatoire (jeton alphanumérique, base64, base64url) n'a presque
// jamais la forme d'un nom ; un tel jeton garde son constat d'entropie.
func TestEntropyNameRarelyMatchesTokens(t *testing.T) {
	const samples = 50_000
	for _, n := range []int{20, 32, 48} {
		matched := 0
		for i := 0; i < samples; i++ {
			if isEntropyName([]byte(randomToken(t, n))) {
				matched++
			}
			raw := make([]byte, n*3/4)
			if _, err := rand.Read(raw); err != nil {
				t.Fatal(err)
			}
			for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
				if isEntropyName([]byte(encoding.EncodeToString(raw))) {
					matched++
				}
			}
		}
		t.Logf("%d caractères : %d suites aléatoires sur %d ont la forme d'un nom", n, matched, 3*samples)
		// Au plus 1 pour 1 000 à 20 caractères, aucune au-delà.
		if limit := map[int]int{20: 3 * samples / 1000, 32: 3 * samples / 100_000, 48: 0}[n]; matched > limit {
			t.Fatalf("%d caractères : %d suites aléatoires sur %d ont la forme d'un nom", n, matched, 3*samples)
		}
	}
}

func TestEntropyIgnoresNames(t *testing.T) {
	rules := loadInitialRules(t)
	for name, content := range map[string]string{
		"type généré":                    "type SubscriptionOverviewLinesElemVerificationsElem struct {",
		"nom de fichier de licence":      "cp expurgation/LICENSE-PolyForm-Small-Business-1.0.0 deploy/licenses/",
		"dossier d'un agent de worktree": ".claude/worktrees/agent-a3f9c2e1b7d40568e/agent/internal/domain/hook/tool.go",
		"identifiant de clé d'API":       "apikey_01Xk7Pq2Rm9Tz4Lw8Nb3Vc6H",
	} {
		if n := entropyFindings(t, rules, content); n != 0 {
			t.Errorf("%s : %d constat(s) d'entropie", name, n)
		}
	}
}

func TestEntropyKeepsTokensBesideNames(t *testing.T) {
	rules := loadInitialRules(t)
	for i := 0; i < 20; i++ {
		token := randomToken(t, 40)
		hex := strings.Repeat("0123456789abcdef", 3)[:40]
		for name, content := range map[string]string{
			"jeton dans un chemin de worktree":           ".claude/worktrees/agent-" + token + "/agent",
			"jeton après un nom de licence":              "LICENSE-PolyForm-" + token,
			"jeton préfixé comme un identifiant d'objet": "apikey_01" + token,
			"hexadécimal de 40 dans un chemin":           "secrets/" + hex + "/" + token,
		} {
			if n := entropyFindings(t, rules, content); n == 0 {
				t.Fatalf("%s : jeton non détecté", name)
			}
		}
	}
}

func TestIsProviderObjectID(t *testing.T) {
	id := "apikey_01" + strings.Repeat("Xk7Pq2Rm9T", 3)[:22]
	for _, c := range []struct {
		text  string
		start int
		want  bool
	}{
		{id, 0, true},
		{"id: " + id, 4, true},
		{"x" + id, 1, false},   // fin d'un mot plus long
		{"_" + id, 1, false},   // suite d'entropie coupée
		{id + "Zz9", 0, false}, // 25 caractères après « 01 »
		{"apikey_02" + id[9:], 0, false},
		{"sk_live_01" + id[9:], 0, false},
	} {
		value := []byte(c.text[c.start:])
		if got := isProviderObjectID([]byte(c.text), c.start, value); got != c.want {
			t.Errorf("isProviderObjectID(%q) = %v, attendu %v", c.text, got, c.want)
		}
	}
}

func TestComparisonIsNotAssignment(t *testing.T) {
	rules := loadInitialRules(t)
	count := func(content, language string) int {
		result := Scan([]byte(content), rules, Options{LanguageID: language})
		if !result.Complete {
			t.Fatalf("analyse incomplète : %v", result.Failure)
		}
		return len(result.Findings)
	}
	for _, content := range []string{"token === undefined", "token==undefined", "apiKey == null", "token === expectedToken", "x && secret === undefined"} {
		for _, language := range []string{"", "typescript"} {
			if n := count(content, language); n != 0 {
				t.Errorf("comparaison %q (%q) : %d constat(s)", content, language, n)
			}
		}
	}
	// Une valeur littérale comparée, ou collée à l'opérateur, reste détectée.
	for i := 0; i < 10; i++ {
		token := randomToken(t, 32)
		for _, content := range []string{"token === \"" + token + "\"", "TOKEN==" + token, "if (x && token == '" + token + "')"} {
			if count(content, "") == 0 {
				t.Fatalf("littéral comparé non détecté")
			}
		}
	}
}

func TestAfterComparison(t *testing.T) {
	for _, c := range []struct {
		text       string
		end, want  int
		comparison bool
	}{
		{"t ===x", 3, 5, true},
		{"t ==x", 3, 4, true},
		{"t ====x", 3, 5, true},
		{"t =x", 3, 3, false},
		{"t := =x", 5, 5, false},
		{"t :==x", 4, 4, false},
		{"t =", 3, 3, false},
	} {
		got, comparison := afterComparison([]byte(c.text), 0, c.end)
		if got != c.want || comparison != c.comparison {
			t.Errorf("afterComparison(%q, %d) = %d, %v ; attendu %d, %v", c.text, c.end, got, comparison, c.want, c.comparison)
		}
	}
}
