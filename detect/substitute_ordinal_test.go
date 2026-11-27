// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// Numéros de Substitut de 1 à 999 999 999 (v0.13.0) : jusqu'à 9 chiffres, sans zéro de tête. Une longue session
// d'agents dépasse 999 valeurs distinctes ; au-delà de 9 chiffres, le texte n'est plus un Substitut.

// largeOrdinals : numéros admis au-delà de l'ancienne borne de 999, jusqu'à la nouvelle.
var largeOrdinals = []int{1000, 4096, 65536, 1_000_000, 123_456_789, MaxSubstituteOrdinal}

func TestSubstituteNineDigitOrdinals(t *testing.T) {
	t.Run("borne : 999 999 999, neuf chiffres", func(t *testing.T) {
		if MinSubstituteOrdinal != 1 || MaxSubstituteOrdinal != 999_999_999 {
			t.Fatalf("bornes %d à %d, attendu 1 à 999999999", MinSubstituteOrdinal, MaxSubstituteOrdinal)
		}
	})
	t.Run("SubstituteText accepte 1000 et 999 999 999, refuse 0 et 1 000 000 000", func(t *testing.T) {
		for _, n := range largeOrdinals {
			got, err := SubstituteText([]byte("valeur"), "github_token", n, "")
			if err != nil || got != subFR("", n, "jeton GitHub") || !isSubstitute([]byte(got)) {
				t.Errorf("%d : %q %v", n, got, err)
			}
			got, err = SubstituteText([]byte("ghp_valeur"), "github_token", n, SubstituteEnglish)
			if err != nil || got != subEN("ghp_", n, "GitHub token") || !isSubstitute([]byte(got)) {
				t.Errorf("%d en anglais : %q %v", n, got, err)
			}
		}
		for _, n := range []int{0, -1, MaxSubstituteOrdinal + 1, 9_999_999_999, 1 << 40} {
			if got, err := SubstituteText([]byte("valeur"), "", n, ""); got != "" || !errors.Is(err, ErrSubstituteOrdinal) {
				t.Errorf("%d : %q %v", n, got, err)
			}
		}
	})
	t.Run("grammaire : 4 à 9 chiffres admis ; 10 chiffres, zéro de tête ou séparateur refusés", func(t *testing.T) {
		for _, n := range largeOrdinals {
			for _, value := range []string{subFR("", n, "secret"), subEN("AKIA", n, "AWS access key ID")} {
				if !isSubstitute([]byte(value)) {
					t.Errorf("%q non reconnu", value)
				}
			}
		}
		base := subFR("", 1000, "mot de passe")
		for _, value := range []string{
			subFR("", 1_000_000_000, "mot de passe"), subFR("", 9_999_999_999, "mot de passe"),
			subEN("", 1_000_000_000, "password"), strings.Replace(base, "n°1000", "n°01000", 1),
			strings.Replace(base, "n°1000", "n°000001000", 1), strings.Replace(base, "n°1000", "n°1 000", 1),
			strings.Replace(base, "n°1000", "n°1_000", 1), strings.Replace(base, "n°1000", "n°1.000", 1),
		} {
			if isSubstitute([]byte(value)) {
				t.Errorf("%q reconnu", value)
			}
		}
	})
	t.Run("FindSubstitutes rend les numéros 1000 et 999 999 999 ; pas un numéro à 10 chiffres", func(t *testing.T) {
		first, second := subFR("", 1000, "secret"), subEN("ghp_", MaxSubstituteOrdinal, "GitHub token")
		ten := subFR("", 1_000_000_000, "secret")
		text := first + " " + second + " " + ten
		want := []SubstituteSpan{
			{ByteStart: 0, ByteEnd: len(first), Ordinal: 1000},
			{ByteStart: len(first) + 1, ByteEnd: len(first) + 1 + len(second), Ordinal: MaxSubstituteOrdinal},
		}
		if got := FindSubstitutes([]byte(text)); !slices.Equal(got, want) {
			t.Errorf("%+v, attendu %+v", got, want)
		}
	})
	t.Run("un Substitut n°1000 ou n°999999999 ne déclenche aucun constat, dans chaque gabarit", func(t *testing.T) {
		rules := loadInitialRules(t)
		for _, n := range []int{1000, MaxSubstituteOrdinal} {
			for _, s := range []string{
				subFR("", n, "jeton d’accès"), subFR("ghp_", n, "jeton GitHub"), subEN("", n, "password"),
				subEN("sk-ant-", n, "Anthropic API key"),
			} {
				for _, template := range substituteTemplates {
					text := template.text(s)
					result := Scan([]byte(text), rules, Options{LanguageID: template.language})
					if !result.Complete || len(result.Findings) != 0 {
						t.Errorf("%d, %s : %+v", n, template.name, result.Findings)
					}
				}
			}
		}
	})
	t.Run("un faux Substitut à 10 chiffres reste analysé et détecté", func(t *testing.T) {
		rules := loadInitialRules(t)
		text := `export TOKEN="` + subFR("", 1_000_000_000, "jeton GitHub") + `"`
		if result := Scan([]byte(text), rules, Options{}); !result.Complete || len(result.Findings) == 0 {
			t.Errorf("non détecté : %+v", result)
		}
	})
}
