// SPDX-License-Identifier: BUSL-1.1

package expurgation

import (
	"errors"
	"testing"

	"github.com/xsom-consulting/secret-guard/detect"
)

// Numéros de Substitut de 1 à 999 999 999 (v0.13.0) : le millième secret d'une session reçoit un Substitut, relu sans
// constat ; au-delà de 999 999 999, l'expurgation échoue (ErrOrdinal), sans texte.
func TestExpurgateNineDigitOrdinals(t *testing.T) {
	rules := loadInitialRules(t)
	content := []byte("export TOKEN=" + syntheticGitHubToken() + "\n")
	t.Run("numéros 1000 et 999 999 999 : Substitut posé, texte relu sans constat", func(t *testing.T) {
		for _, n := range []int{1000, 65536, detect.MaxSubstituteOrdinal} {
			text, subs, result := ExpurgateAndRescan(content, rules, nil, Options{}, fixedOrdinal(n))
			want := "export TOKEN=" + subFR("ghp_", n, "jeton GitHub") + "\n"
			if result.Failure != detect.SanitizeNone || string(text) != want || len(subs) != 1 || subs[0].Ordinal != n ||
				len(result.Final.Findings) != 0 {
				t.Errorf("%d : %q %+v %+v", n, text, subs, result)
			}
		}
	})
	t.Run("numéro 1 000 000 000 : ErrOrdinal, aucun texte", func(t *testing.T) {
		ordinal := fixedOrdinal(detect.MaxSubstituteOrdinal + 1)
		initial := detect.Scan(content, rules, detect.Options{})
		if text, subs, err := Expurgate(content, initial, ordinal); text != nil || subs != nil || !errors.Is(err, ErrOrdinal) {
			t.Errorf("%q %v", text, err)
		}
		if text, subs, result := ExpurgateAndRescan(content, rules, nil, Options{}, ordinal); text != nil || subs != nil ||
			result.Failure != SanitizeOrdinal {
			t.Errorf("%+v", result)
		}
	})
}
