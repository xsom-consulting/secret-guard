// SPDX-License-Identifier: PolyForm-Small-Business-1.0.0

package expurgation

import (
	"errors"
	"testing"

	"github.com/xsom-consulting/secret-guard/detect"
)

// TestSubstituteTextErrors : chaque refus de detect.SubstituteText a son refus d'expurgation ; un refus inattendu
// n'est jamais pris pour une langue inconnue (ErrIncomplete), et aucun texte n'est rendu.
func TestSubstituteTextErrors(t *testing.T) {
	content := []byte("TOKEN=" + syntheticGitHubToken())
	rules := loadInitialRules(t)
	result := detect.Scan(content, rules, detect.Options{})
	if !result.Complete || len(result.Findings) != 1 {
		t.Fatalf("%+v", result)
	}
	defer func(saved func([]byte, string, int, detect.SubstituteLanguage) (string, error)) {
		substituteText = saved
	}(substituteText)
	for _, c := range []struct {
		err, want error
	}{
		{detect.ErrSubstituteOrdinal, ErrOrdinal},
		{detect.ErrSubstituteLanguage, ErrLanguage},
		{errors.New("autre refus"), ErrIncomplete},
	} {
		substituteText = func([]byte, string, int, detect.SubstituteLanguage) (string, error) { return "", c.err }
		text, subs, err := Expurgate(content, result, fixedOrdinal(1))
		if !errors.Is(err, c.want) || text != nil || subs != nil {
			t.Errorf("%v : %v, attendu %v", c.err, err, c.want)
		}
	}
}
