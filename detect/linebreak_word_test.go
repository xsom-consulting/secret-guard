package detect

import (
	"bytes"
	"strings"
	"testing"
)

// Jetons fictifs et nom de variable assemblés par morceaux : aucune valeur en forme de jeton dans la source.
func syntheticOpenAIKey() string { return "sk" + "-proj-" + strings.Repeat("aB3d", 6) }

func syntheticSlackToken() string { return "xo" + "xb-" + "1234567890-" + strings.Repeat("aB3d", 4) }

func variableName() string { return "TOK" + "EN" }

// TestExpurgateKeepsWordAfterToken : un jeton complet en fin de ligne, suivi d'une ligne faite d'un seul mot, ne doit
// pas emporter ce mot dans l'expurgation (la vue jointe des jetons coupés le recolle au jeton). En échec avant v0.5.2 :
// « fi », « done », « EOF » disparaissaient du texte expurgé.
func TestExpurgateKeepsWordAfterToken(t *testing.T) {
	rules := loadInitialRules(t)
	name := variableName()
	for _, sample := range []struct{ rule, value string }{
		{"github" + "_token", syntheticGitHubToken()}, {"openai" + "_key", syntheticOpenAIKey()}, {"slack" + "_token", syntheticSlackToken()},
	} {
		for _, c := range []struct{ name, before, after string }{
			{"fi en fin de texte", name + "=", "\nfi"},
			{"done indenté puis une ligne", "export " + name + "=", "\n  done\necho ok"},
			{"EOF de heredoc", name + "=", "\nEOF\n"},
			{"end, CRLF", strings.ToLower(name) + ": ", "\r\nend"},
			{"mot à majuscule initiale", name + "=", "\nSuite"},
			{"un seul caractère", name + "=", "\nx"},
			{"mot en tirets", name + "=", "\nmy-task"},
		} {
			t.Run(sample.rule+"/"+c.name, func(t *testing.T) {
				input := c.before + sample.value + c.after
				initial := Scan([]byte(input), rules, Options{})
				if !initial.Complete || len(initial.Findings) != 1 || initial.Findings[0].RuleID != sample.rule {
					t.Fatalf("%+v", initial.Findings)
				}
				text, subs, result := expurgateBoth(t, []byte(input), rules, nil, Options{}, func() func(Finding) (int, bool) { return fixedOrdinal(1) })
				if result.Failure != SanitizeNone || len(subs) != 1 {
					t.Fatalf("%s : %+v", result.Failure, subs)
				}
				if subs[0].ByteStart != len(c.before) || subs[0].ByteEnd != len(c.before)+len(sample.value) {
					t.Errorf("étendue remplacée %d..%d, attendue %d..%d", subs[0].ByteStart, subs[0].ByteEnd, len(c.before), len(c.before)+len(sample.value))
				}
				if !bytes.HasSuffix(text, []byte(c.after)) || bytes.Contains(text, []byte("aB3d")) {
					t.Errorf("texte expurgé %q : la ligne suivante %q doit être gardée, le jeton retiré", text, c.after)
				}
			})
		}
	}
}

// TestExpurgateStillJoinsWrappedTail : la suite d'un jeton coupé (chiffres, casse mêlée, base64) reste remplacée avec
// lui, même quand la première ligne est à elle seule un jeton complet.
func TestExpurgateStillJoinsWrappedTail(t *testing.T) {
	rules := loadInitialRules(t)
	value := syntheticGitHubToken()
	for _, tail := range []string{"aB3d", "Q7", "xYzW", strings.Repeat("abcd", 6)} {
		input := variableName() + "=" + value + "\n" + tail
		text, subs, result := expurgateBoth(t, []byte(input), rules, nil, Options{}, func() func(Finding) (int, bool) { return fixedOrdinal(1) })
		if result.Failure != SanitizeNone || len(subs) != 1 || bytes.Contains(text, []byte(tail)) {
			t.Errorf("suite %q : %s %q %+v", tail, result.Failure, text, subs)
		}
	}
}

func TestLooksLikeWrappedTail(t *testing.T) {
	for tail, want := range map[string]bool{
		"": false, "fi": false, "done": false, "EOF": false, "End": false, "x": false, "my-task": false,
		"snake_case": false, "camelCase": false, "iPhone": false, "aBc": false, "internationalization": false,
		"v2": true, "aB3d": true, "xYzW": true, "ab/c": true, "a+b": true, strings.Repeat("abcd", 6): true, "fooBarBaz": true,
	} {
		if got := looksLikeWrappedTail([]byte(tail)); got != want {
			t.Errorf("%q : %v, attendu %v", tail, got, want)
		}
	}
}
