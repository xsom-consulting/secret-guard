// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
)

// sampleOf rend une chaîne que le motif reconnaît, lue dans son arbre : aucune valeur d'essai n'est écrite dans ce
// fichier. Chaque classe donne ses caractères à tour de rôle (turn), pour une valeur variée et déterministe.
func sampleOf(t *testing.T, pattern string) string {
	t.Helper()
	tree, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		t.Fatalf("motif illisible : %v", err)
	}
	var b strings.Builder
	turn := 0
	var walk func(re *syntax.Regexp)
	walk = func(re *syntax.Regexp) {
		switch re.Op {
		case syntax.OpLiteral:
			b.WriteString(string(re.Rune))
		case syntax.OpCharClass:
			var runes []rune
			for i := 0; i+1 < len(re.Rune); i += 2 {
				for r := re.Rune[i]; r <= re.Rune[i+1] && len(runes) < 64; r++ {
					runes = append(runes, r)
				}
			}
			b.WriteRune(runes[(turn*7)%len(runes)])
			turn++
		case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
			b.WriteByte('.')
		case syntax.OpConcat, syntax.OpCapture:
			for _, sub := range re.Sub {
				walk(sub)
			}
		case syntax.OpAlternate:
			walk(re.Sub[0])
		case syntax.OpRepeat:
			for i := 0; i < max(re.Min, 1); i++ {
				walk(re.Sub[0])
			}
		case syntax.OpPlus:
			for i := 0; i < 24; i++ {
				walk(re.Sub[0])
			}
		case syntax.OpQuest, syntax.OpStar, syntax.OpEmptyMatch:
		default:
			t.Fatalf("opération non prévue dans %q : %v", pattern, re.Op)
		}
	}
	walk(tree)
	return b.String()
}

// TestPublicForms : la liste reprise de Betterleaks est entière (65 formes : 22 sans mot-clé, 43 avec), chaque motif
// reconnaît une valeur tirée de son arbre, et isPublicValue la reconnaît : seule pour une forme sans mot-clé ; avec
// l'un de ses mots-clés sur la ligne avant elle, et jamais sans, pour une forme à mot-clé.
func TestPublicForms(t *testing.T) {
	plain, keyed := 0, 0
	for _, form := range publicForms {
		sample := sampleOf(t, form.pattern)
		if !regexp.MustCompile(`^(?:` + form.pattern + `)$`).MatchString(sample) {
			t.Fatalf("%q : la valeur tirée du motif ne lui correspond pas", form.pattern)
		}
		alone := []byte(sample)
		if len(form.keywords) == 0 {
			plain++
			if !isPublicValue(alone, 0, len(alone)) {
				t.Errorf("%q : forme sans mot-clé non reconnue", form.pattern)
			}
			continue
		}
		keyed++
		// Sans mot-clé : reconnue seulement si une autre forme, sans mot-clé, a le même motif.
		if isPublicValue(alone, 0, len(alone)) {
			t.Errorf("%q : forme à mot-clé reconnue sans mot-clé", form.pattern)
		}
		for _, keyword := range form.keywords {
			before := strings.ToUpper(keyword) + "_ID = "
			line := []byte(before + sample)
			if !isPublicValue(line, len(before), len(line)) {
				t.Errorf("%q : non reconnue avec « %s » avant elle", form.pattern, keyword)
			}
			after := []byte(sample + " # " + keyword)
			if isPublicValue(after, 0, len(sample)) {
				t.Errorf("%q : reconnue avec « %s » après elle", form.pattern, keyword)
			}
			other := []byte(keyword + "\nid = " + sample)
			if isPublicValue(other, len(other)-len(sample), len(other)) {
				t.Errorf("%q : reconnue avec « %s » sur une autre ligne", form.pattern, keyword)
			}
		}
	}
	if plain != 22 || keyed != 43 {
		t.Fatalf("%d formes sans mot-clé et %d avec, attendu 22 et 43", plain, keyed)
	}
}

// TestPublicValueIsNotAnAssignment : sous un nom de clé d'API ou de jeton, une valeur publique n'est pas un constat ;
// sous un mot de passe ou un nom qui porte « secret », elle le reste, comme une valeur de même longueur sans la forme.
func TestPublicValueIsNotAnAssignment(t *testing.T) {
	posthog := sampleOf(t, `phc_[A-Za-z0-9_-]{43,44}`)
	supabase := sampleOf(t, `sb_publishable_[A-Za-z0-9_-]{31}`)
	bugsnag := sampleOf(t, `[A-Za-z0-9]{32}`)
	stripe := sampleOf(t, `pk_live_[A-Za-z0-9]{24}`)
	quiet := map[string]string{
		"clé de projet":                     `posthog.init({ ` + nameAPIKey + `: "` + posthog + `" })`,
		"clé publiable":                     `const ` + nameAPIKey + ` = "` + supabase + `";`,
		"clé du SDK, mot-clé sur la ligne":  `Bugsnag.start({ ` + nameAPIKey + `: '` + bugsnag + `' })`,
		"jeton public, mot-clé dans le nom": `STRIPE_PUBLIC_` + strings.ToUpper(nameToken) + `=` + stripe,
	}
	for name, text := range quiet {
		if got := assignmentFindings(t, text+"\n", ""); len(got) != 0 {
			t.Errorf("%s : %d constat(s) d'affectation, règle %s", name, len(got), got[0].RuleID)
		}
	}
	kept := map[string]string{
		"mot de passe":                    namePassword + `: "` + posthog + `"`,
		"nom qui porte secret":            `posthog_` + nameSecret + `: "` + posthog + `"`,
		"forme à mot-clé sans le mot-clé": `client.start({ ` + nameAPIKey + `: '` + bugsnag + `' })`,
		"mot-clé après la valeur":         nameAPIKey + `: '` + bugsnag + `' # bugsnag`,
		"préfixe suivi d'autre chose":     `const ` + nameAPIKey + ` = "` + supabase + `x9";`,
	}
	for name, text := range kept {
		if got := assignmentFindings(t, text+"\n", ""); len(got) == 0 {
			t.Errorf("%s : aucun constat d'affectation", name)
		}
	}
}

// TestPublicValueIsNotAnEntropyFinding : une valeur publique ne donne pas d'avertissement d'entropie ; une suite de
// même longueur sans la forme le garde.
func TestPublicValueIsNotAnEntropyFinding(t *testing.T) {
	entropy := func(text string) int {
		result := Scan([]byte(text), loadInitialRules(t), Options{})
		if !result.Complete {
			t.Fatalf("analyse incomplète : %v", result.Failure)
		}
		count := 0
		for _, f := range result.Findings {
			if f.RuleID == ruleHighEntropy {
				count++
			}
		}
		return count
	}
	generator := splitmix(27)
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	random := func(n int) string { return string(generator.token(letters, n)) }
	posthog := "phc_" + random(43)
	if got := entropy("posthog.init('" + posthog + "')\n"); got != 0 {
		t.Errorf("clé de projet : %d constat(s) d'entropie", got)
	}
	if got := entropy("posthog.init('xyz_" + random(43) + "')\n"); got != 1 {
		t.Errorf("même longueur sans la forme : %d constat(s) d'entropie, attendu 1", got)
	}
	// Jeton à points : chaque candidat d'entropie n'en est qu'un morceau.
	mapbox := "pk.eyJ1Ijoi" + random(40) + "." + random(22)
	if got := entropy("mapboxgl.accessValue = '" + mapbox + "';\n"); got != 0 {
		t.Errorf("jeton public à points : %d constat(s) d'entropie", got)
	}
	if got := entropy("client.accessValue = '" + mapbox + "';\n"); got == 0 {
		t.Errorf("jeton à points sans mot-clé : aucun constat d'entropie")
	}
	// Clé d'un DSN, reconnue à l'hôte qui la suit.
	dsn := random(32)
	if got := entropy("dsn: " + dsn + "@sentry.io/42\n"); got != 0 {
		t.Errorf("clé d'un DSN : %d constat(s) d'entropie", got)
	}
	if got := entropy("dsn: " + dsn + "@example.test/42\n"); got != 1 {
		t.Errorf("même clé devant un autre hôte : %d constat(s) d'entropie, attendu 1", got)
	}
}
