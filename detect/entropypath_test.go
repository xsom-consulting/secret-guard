// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"crypto/rand"
	"testing"
)

// entropyFindings rend le nombre de constats high_entropy de content.
func entropyFindings(t *testing.T, rules *Rules, content string) int {
	t.Helper()
	result := Scan([]byte(content), rules, Options{})
	if !result.Complete {
		t.Fatalf("analyse incomplète : %v", result.Failure)
	}
	n := 0
	for _, f := range result.Findings {
		if f.RuleID == ruleHighEntropy {
			n++
		}
	}
	return n
}

// randomToken tire un jeton de n caractères alphanumériques (forme des jetons opaques des API) ; l'alphabet est
// assemblé à l'exécution.
func randomToken(t *testing.T, n int) string {
	t.Helper()
	var alphabet []byte
	for c := byte('A'); c <= 'Z'; c++ {
		alphabet = append(alphabet, c, c+'a'-'A')
	}
	for c := byte('0'); c <= '9'; c++ {
		alphabet = append(alphabet, c)
	}
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = alphabet[int(raw[i])%len(alphabet)]
	}
	return string(raw)
}

func TestEntropyIgnoresPaths(t *testing.T) {
	rules := loadInitialRules(t)
	project := "-Users-jdupont-Documents-PRO-02-COMPANIES-Exemple-Conseil-DEV-exemple-fleet"
	for name, content := range map[string]string{
		"dossier de projet de Claude Code": "ls ~/.claude/projects/" + project + "/",
		"fichier d'une session":            "/Users/jdupont/.claude/projects/" + project + "/88ed6807-bc07-4e5b-b33b-494065655130/tool-results/bqc0i47ng.txt",
		"binaire d'une extension":          "/Users/jdupont/.vscode/extensions/anthropic.claude-code-2.1.318-darwin-arm64/resources/native-binary/claude",
		"nom en tirets seul":               project,
		"chemin relatif":                   "cd DEV/ai-website/frontend/public/signal-media && ls",
		"chemin relatif en majuscules":     "ls PRO/02-COMPANIES/Exemple-Conseil/DEV/site-web",
		// Mots de plus de 12 lettres (faux positifs relevés sur un Poste réel, novembre 2026).
		"mot de 13 lettres":                  "ls _bmad-output/brainstorming/brainstorm-gamme-cyber-exemple-2026-10-23",
		"mot de 14 lettres":                  "ls _bmad-output/brainstorming/brainstorm-autoprotection-fleet-guard-2026-11-06",
		"mot de 14 lettres sous docs":        "cat docs/implementation/spec-10-8-purge-journaux-chaines.md",
		"chemin absolu coupé par une espace": "cd /Users/jdupont/Documents/PRO/02-COMPANIES/Exemple Conseil/DEV/exemple-fleet-wt-capture-telechargements/agent/internal/domain/hook",
		"suite après un point":               "cat .agents/skills/bmad-retrospective/SKILL.md",
		"mot long en majuscules":             "ls DEV/DOCUMENTATIONS/ARCHITECTURES/exemple-fleet",
	} {
		t.Run(name, func(t *testing.T) {
			if n := entropyFindings(t, rules, content); n != 0 {
				t.Fatalf("%d constat(s) d'entropie sur un chemin", n)
			}
		})
	}
}

func TestEntropyKeepsTokens(t *testing.T) {
	rules := loadInitialRules(t)
	for i := 0; i < 20; i++ {
		token := randomToken(t, 40)
		for name, content := range map[string]string{
			"jeton seul":                                     token,
			"jeton dans le chemin d'URL":                     "curl https://api.exemple.fr/v1/" + token + "/status",
			"jeton après un point":                           "valeur." + token,
			"jeton dans un chemin relatif":                   "cp out/" + token + "/build .",
			"jeton de lettres en casse mêlée dans un chemin": "cp out/" + randomLetters(t, 32) + "/build .",
		} {
			if n := entropyFindings(t, rules, content); n == 0 {
				t.Fatalf("%s : jeton aléatoire non détecté", name)
			}
		}
	}
}

func TestIsWordSlug(t *testing.T) {
	for value, want := range map[string]bool{
		"-Users-jdupont-Documents-PRO-02-COMPANIES": true,
		"mon-projet-de-demo":                        true,
		"a-b-c-d":                                   false, // segments d'un caractère
		"ab-cd-ef":                                  false, // trois segments
		"x7Kq-9Zm2-Lp4W-8nR3":                       false, // moins de la moitié en lettres seules
		"abc_def-ghi-jkl-mno":                       false, // souligné
		"ab--cd-ef-gh":                              false, // tiret double
	} {
		if got := isWordSlug([]byte(value)); got != want {
			t.Errorf("isWordSlug(%q) = %v, attendu %v", value, got, want)
		}
	}
}

// randomLetters tire n lettres en casse mêlée au hasard.
func randomLetters(t *testing.T, n int) string {
	t.Helper()
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		c := byte('a' + int(raw[i])%26)
		if raw[i]&0x80 != 0 {
			c -= 'a' - 'A'
		}
		raw[i] = c
	}
	// Au moins une majuscule et une minuscule après la première lettre.
	raw[1], raw[2] = 'Q', 'q'
	return string(raw)
}

func TestIsLongNameWord(t *testing.T) {
	letters := "abcdefghijklmnopqrstuvwxyz"
	for value, want := range map[string]bool{
		"brainstorming":      true,
		"Autoprotection":     true,
		"TELECHARGEMENTS":    true,
		letters[:24]:         true,  // 24 lettres
		letters[:25]:         false, // 25 lettres
		"frontend":           false, // 12 lettres au plus : isNameWord
		"implementation2":    false, // chiffre
		"providerCredential": false, // casse mêlée
		"brainStorming":      false,
	} {
		if got := isLongNameWord([]byte(value)); got != want {
			t.Errorf("isLongNameWord(%q) = %v, attendu %v", value, got, want)
		}
	}
}
