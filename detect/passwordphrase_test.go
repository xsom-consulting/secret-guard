// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Valeurs synthétiques assemblées à l'exécution (CONTRIBUTING : aucune valeur à forme de secret écrite d'un bloc).
var (
	phraseSymbols = "Qv" + "7&" + "\"'" + "$*°" + "zé" // symboles et accent, 11 points de code
	phraseSimple  = "Tr0" + "pique" + "-42"            // minuscules, majuscule, chiffres, tiret
	phraseAccents = "Éte" + "rnel" + "_" + "ça" + "9x" // majuscule accentuée, minuscules, chiffre, « _ »
)

func TestPasswordPhraseFindsAnnouncedValue(t *testing.T) {
	rules := loadInitialRules(t)
	mdp := "m" + "dp"
	cases := []struct{ name, before, value, after string }{
		{"mon mdp", "check mon api avec mon " + mdp + " ", phraseSymbols, ""},
		{"mon mdp suivi d'un mot", "voici mon " + mdp + " ", phraseSimple, " merci"},
		{"MDP majuscules deux-points collés", strings.ToUpper(mdp) + ": ", phraseSimple, ""},
		{"mdp égal collé", mdp + "=", phraseSimple, ""},
		{"mot de passe deux-points", "mot de passe : ", phraseSymbols, ""},
		{"le mot de passe est", "Le mot de passe est ", phraseAccents, "."},
		{"mot-de-passe c'est", "mot-de-passe c'est ", phraseSimple, ""},
		{"code d'accès typographique", "le code d’accès : ", phraseSimple, ""},
		{"code d'accès droit", "code d'accès ", phraseSimple, ","},
		{"my password is", "my pass" + "word is ", phraseSimple, ""},
		{"passphrase", "the pass" + "phrase ", phraseSimple, ""},
		{"pwd is", "pwd is ", phraseSimple, ""},
		{"pass deux-points", "pass: ", phraseSimple, ""},
		{"pass est", "le pass est ", phraseSimple, ""},
		{"guillemets doubles", "mon " + mdp + " est \"", phraseSimple, "\""},
		{"guillemets français", "mot de passe « ", phraseSimple, " »"},
		{"apostrophes", "pass" + "word is '", phraseSimple, "'."},
		{"ligne suivante", "salut\nmon " + mdp + " ", phraseSimple, "\nfin"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			input := c.before + c.value + c.after
			result := Scan([]byte(input), rules, Options{})
			start, end := len(c.before), len(c.before)+len(c.value)
			if !result.Complete || len(result.Findings) != 1 {
				t.Fatalf("constats : %+v (complet %v)", result.Findings, result.Complete)
			}
			f := result.Findings[0]
			if f.RuleID != "contextual_password" || f.SecretType != "password" || f.ByteStart != start || f.ByteEnd != end ||
				f.Level != LevelHigh {
				t.Fatalf("constat %+v, étendue attendue [%d, %d)", f, start, end)
			}
		})
	}
}

func TestPasswordPhraseIgnoresOrdinarySentences(t *testing.T) {
	rules := loadInitialRules(t)
	word := "pass" + "word"
	substitute, err := SubstituteText([]byte(phraseSimple), "contextual_password", 1, SubstituteFrench)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		"mon mdp est trop court",
		"le mot de passe Administrateur",
		"mot de passe oublié",
		"le mot de passe est réinitialisé",
		"Le mot de passe est Réinitialisé.",
		word + " reset link",
		"click the " + word + " reset link https://example.com/Reset?id=42",
		"mon mdp est azerty123",           // deux classes
		"mot de passe : abcdefghijklmn",   // une classe
		"mdp: Ab1",                        // trop court
		"we pass Config-V2 to the parser", // « pass » sans liaison
		"passe Config-V2 à la suite",      // « passe » n'est pas un indice
		"passwords Hunter2-Xy",            // pluriel
		"user." + word + " Hunter2-Xy",    // propriété
		"--" + word + "-file Hunter2-Xy",  // option
		"mdp\nHunter2-Xy",                 // autre ligne
		"mon mdp est ${DB_Pass1}",
		"mon mdp est $(cat Secret1)",
		"mot de passe : process.env.DB_Pass1",
		"mot de passe : getPassword(Db1)",
		"mon mdp https://Example.com/x1",
		"mon mdp est %Db_Pass1%",
		"mon mdp est " + substitute,
		"mon mdp est " + strings.Repeat("Ab1&", 70), // plus de 256 points de code
		"the " + word + " = getPassword(Db1)",       // affectation laissée à l'origine
		"the " + word + ": ${DB_Pass1}",
	} {
		t.Run(input, func(t *testing.T) {
			result := Scan([]byte(input), rules, Options{})
			if !result.Complete || len(result.Findings) != 0 {
				t.Fatalf("constats inattendus : %+v", result.Findings)
			}
		})
	}
}

// Une affectation que l'origine détecte garde son constat et son étendue ; aucun constat de phrase n'est ajouté.
func TestPasswordPhraseLeavesAssignmentsToOrigin(t *testing.T) {
	rules := loadInitialRules(t)
	for _, input := range []string{
		"pwd=" + phraseSimple,
		"my pass" + "word: " + phraseSimple,
		"export PASS" + "WORD=\"" + phraseSimple + "\"",
		"curl --pass" + "word " + phraseSimple,
	} {
		t.Run(input, func(t *testing.T) {
			result := Scan([]byte(input), rules, Options{})
			if !result.Complete || len(result.Findings) != 1 {
				t.Fatalf("constats : %+v", result.Findings)
			}
			findings, err := rules.scanContextualAssignments(identityView([]byte(input)), &decodeBudget{}, language{}, true)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range findings {
				for _, reason := range f.reasons {
					if reason == "password_in_sentence" {
						t.Fatalf("constat de phrase ajouté sur une affectation : %+v", f)
					}
				}
			}
		})
	}
}

// Les noms anglais des indices sont ceux que typeForSensitiveKey classe « password » (pas de liste en double qui
// divergerait) ; les indices français et « pass » ne sont pas des noms de variables de l'origine.
func TestPasswordPhraseHintsFollowSensitiveKeys(t *testing.T) {
	whole := func(hint string) bool {
		loc := passwordHint.FindStringIndex(hint)
		return loc != nil && loc[0] == 0 && loc[1] == len(hint)
	}
	for hint := range englishPasswordHints {
		if secretType, ok := typeForSensitiveKey([]byte(hint)); !ok || secretType != "password" || !whole(hint) {
			t.Fatalf("%s : %q, %v", hint, secretType, ok)
		}
	}
	for _, hint := range []string{"mdp", "mot de passe", "mot-de-passe", "code d'accès", "code d’accès", "pass"} {
		if _, ok := typeForSensitiveKey([]byte(hint)); ok || !whole(hint) {
			t.Fatalf("%s : déjà un nom sensible de l'origine, ou indice non reconnu en entier", hint)
		}
	}
}

// Sans la règle contextual_password dans le Pack, aucune annonce n'est lue.
func TestPasswordPhraseNeedsContextualPassword(t *testing.T) {
	rules := loadInitialRules(t)
	reduced := &Rules{fixed: rules.fixed, engine: map[string]*rule{}, ids: rules.ids, loaded: true}
	for id, r := range rules.engine {
		if id != "contextual_password" {
			reduced.engine[id] = r
		}
	}
	v := identityView([]byte("mon m" + "dp " + phraseSimple))
	if got := reduced.scanPasswordPhrases(v, nil, nil); len(got) != 0 {
		t.Fatalf("constats sans la règle : %d", len(got))
	}
	if got := rules.scanPasswordPhrases(v, nil, nil); len(got) != 1 {
		t.Fatalf("constats avec la règle : %d", len(got))
	}
}

func TestPasswordPhraseWorstCases(t *testing.T) {
	rules := loadInitialRules(t)
	for name, content := range map[string][]byte{
		"indices sans valeur":         ruleFill("mdp "),
		"indices et liaisons":         ruleFill("mot de passe est : "),
		"indices collés":              ruleFill("mdpmdp"),
		"indice et mot long":          ruleFill("mdp " + strings.Repeat("Ab1&", 80) + " "),
		"guillemets ouverts":          ruleFill("mdp « "),
		"indices anglais affectation": ruleFill("pass" + "word="),
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

// Le masquage remplace la seule valeur et garde la phrase ; le texte masqué est relu sans constat.
func TestPasswordPhraseRedaction(t *testing.T) {
	rules := loadInitialRules(t)
	before := "check mon api avec mon m" + "dp "
	text, outcome := RedactAndRescan([]byte(before+phraseSymbols+" stp"), rules, Options{}, RedactOptions{})
	if outcome.Failure != SanitizeNone || len(outcome.Final.Findings) != 0 {
		t.Fatalf("issue %q, constats après masquage %+v", outcome.Failure, outcome.Final.Findings)
	}
	if !strings.HasPrefix(string(text), before) || !strings.HasSuffix(string(text), " stp") ||
		strings.Contains(string(text), phraseSymbols) {
		t.Fatalf("texte masqué %q", text)
	}
}

// FuzzPasswordPhrase : toute valeur lue est dans le texte, a la forme d'un mot de passe annoncé et suit son indice sur
// la même ligne ; aucune panique.
func FuzzPasswordPhrase(f *testing.F) {
	hint := "m" + "dp"
	for _, seed := range []string{
		"mon " + hint + " " + phraseSimple,
		"mot de passe : « " + phraseSymbols + " »",
		"le pass est " + phraseAccents + ".",
		hint + "\n",
		"code d’accès c'est " + phraseSimple,
		hint + " " + strings.Repeat("Ab1&", 70),
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, text []byte) {
		for _, m := range passwordHint.FindAllIndex(text, -1) {
			start, end, ok := passwordPhraseValue(text, m[0], m[1])
			if !ok {
				continue
			}
			if start < m[1] || end <= start || end > len(text) || !passwordPhraseShape(text[start:end]) {
				t.Fatalf("étendue [%d, %d) après l'indice [%d, %d)", start, end, m[0], m[1])
			}
			for _, r := range string(text[m[1]:start]) {
				if isJSLineTerminator(r) {
					t.Fatalf("fin de ligne entre l'indice et la valeur")
				}
			}
		}
	})
}
