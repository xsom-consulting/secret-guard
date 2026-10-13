package detect

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// ruleWorstCaseBytes : taille des pires cas des règles. Une lecture quadratique y prendrait des dizaines de secondes
// (plus de 3·10^10 pas) ; la lecture linéaire du moteur, environ un quart de seconde par vue (une seconde à 1 Mio).
const ruleWorstCaseBytes = 256 << 10

// ruleFill répète unit jusqu'à ruleWorstCaseBytes octets au plus.
func ruleFill(unit string) []byte { return []byte(strings.Repeat(unit, ruleWorstCaseBytes/len(unit))) }

// ruleWorstCases : entrées qui font relire un préfixe de ligne, un littéral, un heredoc, une queue d'URL ou un
// segment de JWT à chaque correspondance dans une lecture naïve (quadratique) ; chacune finit dans la borne de temps.
func ruleWorstCases() []struct {
	name    string
	content []byte
	lang    language
} {
	ts := language{id: "typescript", set: true}
	none := language{}
	long := func(unit string) string { return strings.Repeat(unit, ruleWorstCaseBytes/2/len(unit)) }
	key := "pass" + "word"
	return []struct {
		name    string
		content []byte
		lang    language
	}{
		{"littéraux d'expression régulière ouverts sur une ligne", ruleFill(key + "=/[a, "), ts},
		{"littéraux d'expression régulière fermés tard", ruleFill(key + "=/a\\/[/, "), ts},
		{"long nom en majuscules puis affectations entre guillemets", []byte(long("A") + " " + strings.Repeat(key+"=\"x\" ", ruleWorstCaseBytes/2/12)), none},
		{"affectations entre guillemets après des mots-clés", ruleFill("const " + key + "=\"x\" "), none},
		{"enum et valeurs entre guillemets", ruleFill("enum " + key + "=\"x\", "), none},
		{"déclarations de code sans fin", []byte(long("std::string a ") + key + "=\"x\" "), none},
		{"heredoc sans marqueur", ruleFill(key + "=<<,"), ts},
		{"heredoc sur une ligne sans fin", ruleFill(key + "=a<<B "), ts},
		{"heredoc lointain", []byte(strings.Repeat(key+"=x,", ruleWorstCaseBytes/2/10) + long("é") + "<<EOF"), ts},
		{"blocs YAML sans fin de ligne", ruleFill(key + ": |#a "), ts},
		{"gabarits non fermés", ruleFill(key + "=${ "), ts},
		{"gabarits doubles non fermés", ruleFill(key + "={{ "), none},
		{"chevrons non fermés", ruleFill(key + "=<a "), ts},
		{"affectation suivie d'espaces", ruleFill("a=" + strings.Repeat(" ", 200)), none},
		{"espaces puis _authToken", []byte(long(" ") + "_authToken=x"), none},
		{"_authToken répétés", ruleFill("\n_authToken=x"), none},
		{"Cookie répétés", ruleFill("\nCookie: sid=a;token=b"), none},
		{"-u entre guillemets au mot de passe trop long", ruleFill(" -u \"a:" + strings.Repeat("b", 1100) + "\""), none},
		{"-u sans guillemets au mot de passe trop long", ruleFill(" -u a:" + strings.Repeat("b", 1100)), none},
		{"URL à queue longue", ruleFill("http://" + strings.Repeat("a", 3000) + " "), none},
		{"URL enchaînées dans une queue", ruleFill("http://u:p@h"), none},
		{"débuts de JWT enchaînés", ruleFill("eyJ-"), none},
		{"JWT à signature longue", []byte("eyJhbGci.eyJzdWIi." + long("a")), none},
		{"JWT en tête trop longue", ruleFill("eyJ-eyJ" + strings.Repeat("a", 2100) + ".eyJabcd.abcdefgh "), none},
		{"clés privées sans fin", ruleFill("-----BEGIN " + "PRIVATE KEY-----"), none},
		{"entropie", ruleFill("aB3dE5fG7hJ9kL1mN2pQ "), none},
		{"Docker auth", ruleFill("\"auth\":\"YTpi\","), none},
		{"lignes de clés sensibles en dotenv", ruleFill(key + "=x\n"), language{id: "dotenv", set: true}},
	}
}

func TestRuleWorstCases(t *testing.T) {
	rules := loadInitialRules(t)
	for _, c := range ruleWorstCases() {
		t.Run("pire cas des règles borné en temps — "+c.name, func(t *testing.T) {
			v := identityView(c.content)
			start := time.Now()
			if _, err := rules.scanFixedRules(v, &decodeBudget{}, true); err != nil {
				t.Fatalf("règles fixes : %v", err)
			}
			rules.scanCredentialURLs(v)
			if _, err := rules.scanContextualAssignments(v, &decodeBudget{}, c.lang, true); err != nil && !errors.Is(err, errDecodeBudgetExhausted) {
				t.Fatalf("affectations : %v", err)
			}
			rules.scanEntropy(v)
			if elapsed := time.Since(start); elapsed > worstCaseTimeLimit {
				t.Fatalf("%v pour %d octets", elapsed, len(c.content))
			}
		})
	}
}

// TestLoneSurrogateWorstCase : vue d'échappements JSON de 1 Mio dont la moitié est faite de substituts isolés
// (« \ud800 ») : l'entropie de chaque candidat cherche ses substituts sans reparcourir ceux qui le précèdent.
func TestLoneSurrogateWorstCase(t *testing.T) {
	rules := loadInitialRules(t)
	t.Run("substituts isolés et candidats d'entropie bornés en temps", func(t *testing.T) {
		half := worstCaseInputBytes / 2
		content := strings.Repeat(`\ud800`, half/6) + strings.Repeat("\npass"+"word="+entropyValue(20), half/31)
		v, err := jsonEscapedView(identityView([]byte(content)), newViewBudget())
		if err != nil || v == nil || len(v.lone) == 0 {
			t.Fatalf("vue JSON : %v", err)
		}
		start := time.Now()
		rules.scanEntropy(v)
		if _, err := rules.scanContextualAssignments(v, &decodeBudget{}, language{}, true); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(start); elapsed > worstCaseTimeLimit {
			t.Fatalf("%v pour %d octets", elapsed, len(content))
		}
	})
}

// TestRuleWorstCasesFullScan : pires cas par l'assemblage complet (toutes les vues, fenêtres jointes, candidats
// base64), substituts isolés compris.
func TestRuleWorstCasesFullScan(t *testing.T) {
	rules := loadInitialRules(t)
	key := "pass" + "word"
	cases := []struct {
		name    string
		content []byte
	}{
		{"substituts isolés et affectations", []byte(strings.Repeat(`\ud800`, ruleWorstCaseBytes/12) + strings.Repeat("\n"+key+"="+entropyValue(20)+" %41", ruleWorstCaseBytes/66))},
		{"échappements JSON d'affectations ouvertes", ruleFill(key + `=\u002f[a, `)},
		{"pourcentages d'URL à queue longue", ruleFill("http%3A%2F%2F" + strings.Repeat("a", 3000) + " ")},
	}
	for _, c := range cases {
		t.Run("pire cas de l'analyse complète borné en temps — "+c.name, func(t *testing.T) {
			start := time.Now()
			if result := Scan(c.content, rules, Options{LanguageID: "typescript"}); result.Failure == FailureScanLimit {
				t.Fatal("limite d'entrée")
			}
			if elapsed := time.Since(start); elapsed > worstCaseTimeLimit {
				t.Fatalf("%v pour %d octets", elapsed, len(c.content))
			}
		})
	}
}
