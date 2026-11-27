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

// Une session de 10 000 Substituts connus à 9 chiffres tient dans une demande ; au-delà de 2 Mio, la demande est
// refusée.
func TestKnownListOfTenThousand(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"known":[`)
	for i := range 10_000 {
		if i > 0 {
			b.WriteByte(',')
		}
		fp := strconv.FormatInt(int64(i), 16)
		fp = strings.Repeat("0", 32-len(fp)) + fp
		b.WriteString(`{"localFingerprint":"` + fp + `","ordinal":` + strconv.Itoa(detect.MaxSubstituteOrdinal-i) + `}`)
	}
	b.WriteString(`]}`)
	t.Logf("demande de 10 000 numéros connus : %d octets", b.Len())
	request, ok := ParseRequest([]byte(b.String()))
	if !ok || len(request.Known) != 10_000 {
		t.Fatalf("demande de 10 000 numéros connus refusée (%d octets)", b.Len())
	}
	if MaxRequestBytes != 2<<20 {
		t.Errorf("MaxRequestBytes = %d, attendu 2 Mio", MaxRequestBytes)
	}
	over := []byte(`{"minOrdinal":1}` + strings.Repeat(" ", 2<<20))
	if _, ok := ParseRequest(over); ok {
		t.Error("demande de plus de 2 Mio admise")
	}
}
