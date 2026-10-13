package detect

import (
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Pires cas des vues et décodages (1 Mio, la limite d'entrée de l'analyse) : chaque construction finit dans une
// borne de temps et d'allocation, ou s'arrête sur un budget (analyse incomplète), jamais en temps quadratique.

const (
	worstCaseInputBytes = 1 << 20
	// worstCaseTimeLimit est large (machine de CI chargée) : une analyse quadratique sur 1 Mio prendrait des minutes.
	worstCaseTimeLimit = 3 * time.Second
	// worstCaseAllocLimit borne les octets alloués par une construction (vues, correspondance, fenêtres, décodages).
	worstCaseAllocLimit = 640 << 20
)

// fill répète unit jusqu'à worstCaseInputBytes octets au plus.
func fill(unit string) []byte {
	return []byte(strings.Repeat(unit, worstCaseInputBytes/len(unit)))
}

// worstCase est un pire cas : contenu et erreurs de budget admises (analyse incomplète) ; aucune autre.
type worstCase struct {
	name    string
	content []byte
	allowed []error
}

// worstCaseInputs rend les pires cas des vues et décodages, construits par fill.
func worstCaseInputs(fill func(string) []byte, size int) []worstCase {
	password := "PASS" + "WORD=" + "hunter" + "2"
	return []worstCase{
		{"pourcentages", fill("%41"), nil},
		{"échappements JSON", fill(`\u0041`), nil},
		{"pourcentage puis JSON imbriqués", fill(`%5Cu0041`), nil},
		{"JSON puis pourcentage imbriqués", fill(`\u0025\u0034\u0031`), nil},
		{"substituts isolés recombinés", fill(`\ud83d\u200b\ude00`), nil},
		{"CRLF", fill("\r\n"), nil},
		{"ignorables", fill("\xe2\x80\x8b"), nil},
		{"expansion NFKC maximale (U+FDFA, ×11)", fill("\xef\xb7\xba"), nil},
		{"expansion NFKC et pourcentages", fill("\xef\xb7\xba%41"), []error{errViewBudgetExhausted}},
		{"octets invalides", fill("\xff"), nil},
		{"NUL", fill("\x00"), nil},
		{"préfixes de jetons enchaînés", fill("sk-"), nil},
		{"préfixes de jetons coupés", fill("g\nhp_"), []error{errJoinedWindowBudgetExhausted}},
		{"jeton coupé sur des lignes d'un caractère", []byte("g\nhp_" + strings.Repeat("a\n    ", size/7)), nil},
		{"base64 coupé sur chaque ligne", fill("QUJDREVGR0hJ\n"), []error{errJoinedWindowBudgetExhausted, errDecodeBudgetExhausted}},
		{"une suite base64 de 1 Mio", fill("Ab3+"), []error{errDecodeBudgetExhausted}},
		{"candidats base64 décodés", fill(b64(password) + " "), []error{errDecodeBudgetExhausted}},
		{"base64 de pourcentages et d'échappements (décodages imbriqués)", fill(b64(strings.Repeat(`%5Cu0067hp\u005f`, 100)) + "\n"), []error{errDecodeBudgetExhausted}},
		{"mélange", fill("%5C\\u0041\r\n\xe2\x80\x8bg\nhp_\xff=QUJD"), []error{errJoinedWindowBudgetExhausted}},
	}
}

func TestWorstCases(t *testing.T) {
	for _, c := range worstCaseInputs(fill, worstCaseInputBytes) {
		t.Run("pire cas borné en temps et en mémoire — "+c.name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			start := time.Now()
			_, err := buildCorpusViews(c.content)
			elapsed := time.Since(start)
			runtime.ReadMemStats(&after)
			if err != nil {
				admitted := false
				for _, allowed := range c.allowed {
					admitted = admitted || errors.Is(err, allowed)
				}
				if !admitted {
					t.Fatalf("erreur %v", err)
				}
			}
			if elapsed > worstCaseTimeLimit {
				t.Fatalf("%v pour %d octets", elapsed, len(c.content))
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > worstCaseAllocLimit {
				t.Fatalf("%d Mio alloués", allocated>>20)
			}
		})
	}
}
