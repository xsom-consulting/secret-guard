// SPDX-License-Identifier: PolyForm-Small-Business-1.0.0

package expurgation

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/detect"
)

// TestPasswordPhraseExpurgation : un mot de passe annoncé dans une phrase (v0.8.1) est remplacé par son Substitut, la
// phrase autour est gardée et le texte expurgé est relu sans constat. En échec avant v0.8.1 (aucun constat).
func TestPasswordPhraseExpurgation(t *testing.T) {
	rules := loadInitialRules(t)
	value := "Qv" + "7&" + "\"'" + "$*°" + "zé"
	for _, c := range []struct{ name, before, after string }{
		{"mon mdp", "check mon api avec mon m" + "dp ", " stp"},
		{"le mot de passe est", "Le mot de passe est ", "."},
		{"my password is", "my pass" + "word is ", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			input := c.before + value + c.after
			text, subs, sanitized := expurgateBoth(t, []byte(input), rules, nil, Options{}, func() func(detect.Finding) (int, bool) { return fixedOrdinal(1) })
			if sanitized.Failure != detect.SanitizeNone || bytes.Contains(text, []byte(value)) || len(subs) != 1 {
				t.Fatalf("expurgation : %s, %d Substituts", sanitized.Failure, len(subs))
			}
			if !strings.HasPrefix(string(text), c.before) || !strings.HasSuffix(string(text), c.after) ||
				!strings.Contains(string(text), "mot de passe, pas la vraie valeur]") {
				t.Fatalf("texte expurgé %q", text)
			}
		})
	}
}
