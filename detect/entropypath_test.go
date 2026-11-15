// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"crypto/rand"
	"strings"
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
		// Identifiants publics dans le chemin d'une URL (15 novembre 2026).
		"référence d'un article de loi":         "Source : https://www.legifrance.gouv.fr/codes/article_lc/LEGIARTI000028345220 (version en vigueur)",
		"références d'un code et d'une section": "https://www.legifrance.gouv.fr/codes/section_lc/LEGITEXT000006070719/LEGISCTA000006149839/",
		"référence et date":                     "<a href=\"https://www.legifrance.gouv.fr/codes/id/LEGISCTA000006149839/2026-02-02\">",
		"numéro d'article d'un centre d'aide":   "https://aide.exemple.fr/hc/fr/articles/24373653275165-Configurer-les-restrictions-par-locataire-pour-les-applications-SaaS",
		"identifiant de page après un titre":    "https://notes.exemple.fr/p/Politique-restreindre-le-reseau-sortant-dans-les-reglages-" + publicPageID,
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
			"jeton après un titre dans le chemin d'URL":      "https://notes.exemple.fr/p/Politique-de-securite-" + token,
			"jeton après un numéro dans le chemin d'URL":     "https://support.exemple.fr/hc/fr/articles/24373653275165-" + token,
			"jeton à côté d'une référence":                   "https://www.exemple.fr/codes/LEGIARTI000028345220/" + token,
		} {
			if n := entropyFindings(t, rules, content); n == 0 {
				t.Fatalf("%s : jeton aléatoire non détecté", name)
			}
		}
	}
}

// publicPageID : identifiant de page synthétique, 32 chiffres hexadécimaux assemblés à l'exécution.
var publicPageID = strings.Repeat("0a1b2c3d", 4)

func TestIsPublicID(t *testing.T) {
	for word, want := range map[string]bool{
		"24373653275165":              true,  // numéro d'article
		"12345678901234567890":        true,  // 20 chiffres
		"123456789012345678901":       false, // 21 chiffres
		"LEGIARTI000028345220":        true,  // référence : 8 majuscules, 12 chiffres
		"JORFARTI000047915060":        true,
		"RFC000009110":                true,
		"A000028345220":               false, // une seule majuscule
		"ABCDEFGHIJKLM0000":           false, // 13 majuscules
		"LEGIARTIXXXXX123":            false, // 3 chiffres
		"legiarti000028345220":        false, // minuscules
		"LEGIARTI00002834522A":        false, // lettre après les chiffres
		publicPageID:                  true,  // 32 chiffres hexadécimaux
		strings.ToUpper(publicPageID): true,
		publicPageID[:31] + "A":       false, // casse mêlée
		publicPageID[:30]:             false, // 30 chiffres hexadécimaux
		strings.Repeat("abcdefab", 4): false, // aucun chiffre décimal
		"0a1b2c3d4e5f6071":            false, // 16 chiffres hexadécimaux : reste un candidat
		"prodview3ao52s7pq45py":       false,
		"Xk7Pq2Rm9Tz4Lw8Nb3Vc6H":      false,
	} {
		if got := isPublicID([]byte(word)); got != want {
			t.Errorf("isPublicID(%q) = %v, attendu %v", word, got, want)
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

func TestEntropyIgnoresClaudeResourceLinks(t *testing.T) {
	rules := loadInitialRules(t)
	for i := 0; i < 20; i++ {
		id := randomToken(t, 22)
		for name, content := range map[string]string{
			"Artifact":                "https://claude.ai/artifact/" + id,
			"Artifact de Claude Code": "Lien : https://claude.ai/code/artifact/" + id + " (privé)",
			"conversation":            "https://claude.ai/chat/" + id,
			"projet":                  "voir https://claude.ai/project/" + id + ".",
		} {
			if n := entropyFindings(t, rules, content); n != 0 {
				t.Fatalf("%s : %d constat(s) d'entropie sur un lien de ressource de claude.ai", name, n)
			}
		}
		// Suite plus longue que l'identifiant d'un Artifact : détectée sans dépendre du tirage.
		long := randomToken(t, 40)
		for name, content := range map[string]string{
			"lien de partage public":     "https://claude.ai/share/" + long,
			"autre hôte, même chemin":    "https://claude.ai.exemple.fr/artifact/" + long,
			"identifiant de connexion":   "https://user@claude.ai/artifact/" + long,
			"HTTP sans chiffrement":      "http://claude.ai/artifact/" + long,
			"jeton dans un chemin d'API": "https://api.exemple.fr/artifact/" + long,
		} {
			if n := entropyFindings(t, rules, content); n == 0 {
				t.Fatalf("%s : jeton aléatoire non détecté", name)
			}
		}
	}
}
