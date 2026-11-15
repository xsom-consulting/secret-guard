// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"strings"
	"testing"
)

// TestFencedBlockLanguage : dans un prompt analysé sans langage, un bloc clôturé par trois accents graves et un nom
// de langage connu est lu avec ce langage pour les affectations (v0.10.0). Un libellé de code n'y est plus un constat,
// une valeur à forme de secret le reste ; un bloc sans nom, de nom inconnu ou jamais refermé garde la lecture sans
// langage, et le langage déclaré par l'analyse l'emporte. Les valeurs sont assemblées par morceaux.
func TestFencedBlockLanguage(t *testing.T) {
	rules := loadInitialRules(t)
	fence := strings.Repeat("`", 3)
	name := "api" + "Key"
	label := "  " + name + ": '" + "test" + "-" + "key" + "',\n"
	shaped := "  " + name + ": '" + "q7Rk2" + "ZpX9v" + "Lm4Tn" + "8Wb3J" + "c6Hd1" + "',\n"
	prompt := func(opening, body, closing string) string {
		return "Voici ma configuration, que faut-il changer ?\n\n" + opening + "\nexport default {\n" + body + "}\n" + closing +
			"\nMerci.\n"
	}
	count := func(text, languageID string) int {
		t.Helper()
		result := Scan([]byte(text), rules, Options{LanguageID: languageID})
		if !result.Complete {
			t.Fatalf("analyse incomplète (%v)", result.Failure)
		}
		return len(result.Findings)
	}
	cases := []struct {
		name       string
		text       string
		languageID string
		want       int
	}{
		{"libellé dans un bloc ts", prompt(fence+"ts", label, fence), "", 0},
		{"libellé dans un bloc TypeScript à attributs", prompt(fence+" TypeScript title=config.ts", label, fence), "", 0},
		{"libellé dans un bloc à quatre accents graves", prompt(fence+"`tsx", label, fence+"`"), "", 0},
		{"valeur à forme de secret dans un bloc ts", prompt(fence+"ts", shaped, fence), "", 1},
		{"libellé dans un bloc sans langage", prompt(fence, label, fence), "", 1},
		{"libellé dans un bloc de langage inconnu", prompt(fence+"mermaid", label, fence), "", 1},
		{"libellé dans un bloc jamais refermé", prompt(fence+"ts", label, ""), "", 1},
		{"libellé après le bloc", prompt(fence+"ts", "", fence) + label, "", 1},
		{"langage déclaré par l'analyse", prompt(fence+"ts", label, fence), "plaintext", 1},
	}
	for _, c := range cases {
		if got := count(c.text, c.languageID); got != c.want {
			t.Errorf("%s : %d constats, %d attendus", c.name, got, c.want)
		}
	}
}
