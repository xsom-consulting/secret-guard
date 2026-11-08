// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"encoding/base64"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestDashTailRules : motifs du Pack initial dont la dernière classe admet « - » avant le « \b » final.
func TestDashTailRules(t *testing.T) {
	rules := loadInitialRules(t)
	var got []string
	for _, r := range rules.fixed {
		if r.dashTail != nil {
			got = append(got, r.id)
		}
	}
	sort.Strings(got)
	want := []string{"anthropic_key", "gitlab_pat", "google_api_key", "google_oauth_token", "openai_key", "openrouter_key", "sendgrid_key", "slack_token"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%v, attendu %v", got, want)
	}
	for pattern, want := range map[string]bool{
		`\bab-[A-Za-z0-9_-]{20}\b`: true, `\bab_[A-Za-z0-9]{20}\b`: false, `\bab-[A-Z-]{2,}\b`: true,
		`\bab-[A-Z-]+\b`: false, `ab-[A-Z-]{2}`: false, `\b(?:a|b)\b`: false,
	} {
		if got := dashTailPattern(pattern) != nil; got != want {
			t.Errorf("%s : %v, attendu %v", pattern, got, want)
		}
	}
}

// TestTokenEndingWithDash : un jeton de longueur fixe dont le dernier caractère est un tiret est détecté, sur toute
// son étendue. En échec avant v0.5.2 (aucun constat : « \b » n'a pas de frontière après « - »).
func TestTokenEndingWithDash(t *testing.T) {
	rules := loadInitialRules(t)
	for _, c := range []struct{ rule, value string }{
		{"gitlab" + "_pat", "gl" + "pat-" + strings.Repeat("aB3d", 4) + "xY9-"},
		{"google" + "_api_key", "AI" + "za" + strings.Repeat("aB3d", 8) + "Q7-"},
	} {
		for _, around := range [][2]string{{"", ""}, {"key=\"", "\""}, {"x ", " y"}, {"'", "',"}} {
			input := around[0] + c.value + around[1]
			result := Scan([]byte(input), rules, Options{})
			if !result.Complete || len(result.Findings) == 0 {
				t.Fatalf("%s %q : aucun constat", c.rule, around)
			}
			f := result.Findings[0]
			if f.RuleID != c.rule || f.ByteStart != len(around[0]) || f.ByteEnd != len(around[0])+len(c.value) {
				t.Errorf("%s %q : %+v", c.rule, around, result.Findings)
			}
		}
	}
}

// TestJWTEndingWithDash : le JWT a sa propre lecture (scanJWT, segments de longueur ouverte) : fini par un tiret, il
// est détecté sans dashTail, son étendue s'arrêtant avant ce tiret (comportement d'origine gardé ; le tiret reste dans
// le texte expurgé et la réinjection rend le jeton entier).
func TestJWTEndingWithDash(t *testing.T) {
	rules := loadInitialRules(t)
	encode := base64.RawURLEncoding.EncodeToString
	value := encode([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + encode([]byte(`{"sub":"1234567890"}`)) + "." +
		strings.Repeat("aB3d", 10) + "Q7-"
	for _, f := range Scan([]byte("Bearer "+strings.TrimSuffix(value, "-")+"Z fin"), rules, Options{}).Findings {
		if f.RuleID != "jwt" {
			t.Fatalf("JWT témoin non détecté : %+v", f)
		}
	}
	result := Scan([]byte("Bearer "+value+" fin"), rules, Options{})
	if len(result.Findings) == 0 || result.Findings[0].RuleID != "jwt" || result.Findings[0].ByteEnd < 7+len(value)-1 {
		t.Fatalf("%+v", result.Findings)
	}
}

func TestTokenLikeDashTail(t *testing.T) {
	for match, want := range map[string]bool{
		"gl" + "pat-" + strings.Repeat("aB3d", 4) + "xY9-": true, "ab3-": true, "ab3---": true,
		"ab3----": false, "sk-" + strings.Repeat("-", 30): false, "a-b-c-d-e-f-": true, "a--b--c--d--": false,
	} {
		if got := tokenLikeDashTail([]byte(match)); got != want {
			t.Errorf("%q : %v, attendu %v", match, got, want)
		}
	}
	rules := loadInitialRules(t)
	for _, f := range Scan([]byte("sk"+"-"+strings.Repeat("-", 30)+" "), rules, Options{}).Findings {
		t.Errorf("suite de tirets détectée : %+v", f)
	}
}

// TestDashTailKeepsOrdinaryMatches : un jeton qui ne finit pas par un tiret garde le constat du motif d'origine, et
// une suite trop courte reste sans constat.
func TestDashTailKeepsOrdinaryMatches(t *testing.T) {
	rules := loadInitialRules(t)
	value := "gl" + "pat-" + strings.Repeat("aB3d", 5)
	result := Scan([]byte(value+" fin"), rules, Options{})
	if len(result.Findings) != 1 || result.Findings[0].ByteEnd != len(value) {
		t.Fatalf("%+v", result.Findings)
	}
	short := "gl" + "pat-" + strings.Repeat("aB3d", 3) + "-"
	for _, f := range Scan([]byte(short+" fin"), rules, Options{}).Findings {
		if f.RuleID == "gitlab"+"_pat" {
			t.Fatalf("suite trop courte détectée : %+v", f)
		}
	}
}

// TestDashTailWorstCases : préfixes répétés collés les uns aux autres ou suivis de tirets ; chaque fenêtre est bornée
// à dashTailWindow octets, l'analyse finit dans la borne de temps des pires cas.
func TestDashTailWorstCases(t *testing.T) {
	rules := loadInitialRules(t)
	prefix := "gl" + "pat-"
	for name, content := range map[string][]byte{
		"préfixes collés":           ruleFill(prefix),
		"préfixes et tirets":        ruleFill(prefix + strings.Repeat("a-", 10) + " "),
		"préfixe puis longue suite": []byte(prefix + strings.Repeat("aB3d-", ruleWorstCaseBytes/5-2)),
		"préfixes OpenAI":           ruleFill("sk" + "-" + strings.Repeat("-", 30) + " "),
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			if result := Scan(content, rules, Options{}); !result.Complete && result.Failure != FailureScanLimit {
				t.Logf("analyse incomplète : %s", result.Failure)
			}
			if elapsed := time.Since(start); elapsed > worstCaseTimeLimit {
				t.Fatalf("%v pour %d octets", elapsed, len(content))
			}
		})
	}
}
