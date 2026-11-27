// SPDX-License-Identifier: BUSL-1.1

package request

import (
	"strconv"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/detect"
)

// Numéros de 1 à 999 999 999 (v0.13.0) : une demande au-delà de 999 est admise ; au-delà de 999 999 999, refusée, et
// la numérotation s'arrête (ordinal_refused).
func TestNineDigitOrdinals(t *testing.T) {
	fp := strings.Repeat("0a", 16)
	known := func(n int) string {
		return `{"known":[{"localFingerprint":"` + fp + `","ordinal":` + strconv.Itoa(n) + `}]}`
	}
	for _, accepted := range []string{`{"minOrdinal":1000}`, `{"minOrdinal":999999999}`, known(1000), known(999999999)} {
		if _, ok := ParseRequest([]byte(accepted)); !ok {
			t.Errorf("refusée : %q", accepted)
		}
	}
	for _, refused := range []string{`{"minOrdinal":1000000000}`, known(1000000000)} {
		if _, ok := ParseRequest([]byte(refused)); ok {
			t.Errorf("admise : %q", refused)
		}
	}
	n, ok := newNumbering(Request{Known: []Known{{LocalFingerprint: fp, Ordinal: detect.MaxSubstituteOrdinal - 1}}})
	if !ok {
		t.Fatal("numérotation refusée")
	}
	if got, ok := n.ordinal(detect.Finding{LocalFingerprint: strings.Repeat("b", 32)}); !ok || got != 999_999_999 {
		t.Errorf("dernier numéro : %d %v", got, ok)
	}
	if got, ok := n.ordinal(detect.Finding{LocalFingerprint: strings.Repeat("c", 32)}); ok {
		t.Errorf("numéro au-delà de 999 999 999 : %d", got)
	}
}
