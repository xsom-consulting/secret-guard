// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"bytes"
	"errors"
	"testing"
	"unicode/utf16"
)

// utf16Bytes écrit text en UTF-16, petit-boutien ou gros-boutien, avec ou sans marque d'ordre.
func utf16Bytes(text string, big, mark bool) []byte {
	units := utf16.Encode([]rune(text))
	if mark {
		units = append([]uint16{0xFEFF}, units...)
	}
	out := make([]byte, 0, 2*len(units))
	for _, unit := range units {
		if big {
			out = append(out, byte(unit>>8), byte(unit))
		} else {
			out = append(out, byte(unit), byte(unit>>8))
		}
	}
	return out
}

// TestUTF16View : un jeton dans un fichier UTF-16 (deux ordres, avec ou sans marque) donne un constat de règle dont
// l'étendue est exactement celle des octets du jeton dans la source ; la vue garde les caractères accentués et la
// position de chacun ; une vue hors budget rend l'analyse incomplète.
func TestUTF16View(t *testing.T) {
	rules := loadInitialRules(t)
	token := syntheticGitHubToken()
	before := "clé d'accès à l'été : "
	for _, c := range []struct {
		name      string
		big, mark bool
	}{
		{"petit-boutien avec marque", false, true},
		{"petit-boutien sans marque", false, false},
		{"gros-boutien avec marque", true, true},
		{"gros-boutien sans marque", true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			content := utf16Bytes(before+token+" ; fin\r\n", c.big, c.mark)
			start := len(utf16Bytes(before, c.big, c.mark))
			want := Finding{
				RuleID: "github_token", SecretType: "provider_token", Encoding: EncodingNormalized, Score: 95, Level: LevelCritical,
				ByteStart: start, ByteEnd: start + 2*len(token),
			}
			result := Scan(content, rules, Options{})
			if !result.Complete || len(result.Findings) != 1 || result.Findings[0] != want {
				t.Fatalf("constats %+v, attendu %+v", result.Findings, want)
			}
			if !bytes.Equal(content[want.ByteStart:want.ByteEnd], utf16Bytes(token, c.big, false)) {
				t.Fatal("l'étendue du constat n'est pas celle des octets du jeton")
			}
			wide, err := utf16View(content, newViewBudget())
			if err != nil || wide == nil || string(wide.text) != before+token+" ; fin\r\n" {
				t.Fatal("la vue UTF-16 n'est pas le texte de la source, accents compris")
			}
			accent := bytes.Index(wide.text, []byte("é"))
			if s, e := wide.mapRange(accent, accent+len("é")); !bytes.Equal(content[s:e], utf16Bytes("é", c.big, false)) {
				t.Fatalf("« é » ramené à [%d, %d)", s, e)
			}
			if _, err := utf16View(content, &viewBudget{remaining: 8}); !errors.Is(err, errViewBudgetExhausted) {
				t.Fatalf("budget de vues dépassé : %v", err)
			}
		})
	}
}
