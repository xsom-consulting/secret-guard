package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Pont Unicode figé avec le Node qui a produit le corpus de parité (generator/unicode-parity.ts).
const unicodeParityPath = "../vectors/unicode-parity.json"

type unicodeParity struct {
	UnicodeVersion            string     `json:"unicodeVersion"`
	DefaultIgnorableCodePoint [][2]int32 `json:"defaultIgnorableCodePoint"`
	NFKCChangedCodePoints     int        `json:"nfkcChangedCodePoints"`
	NFKCSHA256                string     `json:"nfkcSha256"`
}

func loadUnicodeParity(t *testing.T) unicodeParity {
	t.Helper()
	data, err := os.ReadFile(unicodeParityPath)
	if err != nil {
		t.Fatalf("lecture du pont Unicode : %v", err)
	}
	var parity unicodeParity
	if err := json.Unmarshal(data, &parity); err != nil {
		t.Fatalf("pont Unicode illisible : %v", err)
	}
	return parity
}

// tableRanges rend les plages fermées d'une RangeTable de pas 1.
func tableRanges(t *testing.T, table *unicode.RangeTable) [][2]int32 {
	t.Helper()
	var ranges [][2]int32
	for _, r := range table.R16 {
		if r.Stride != 1 {
			t.Fatalf("pas %d", r.Stride)
		}
		ranges = append(ranges, [2]int32{int32(r.Lo), int32(r.Hi)})
	}
	for _, r := range table.R32 {
		if r.Stride != 1 {
			t.Fatalf("pas %d", r.Stride)
		}
		ranges = append(ranges, [2]int32{int32(r.Lo), int32(r.Hi)})
	}
	return ranges
}

// derivedDefaultIgnorable recalcule la propriété depuis les tables de la bibliothèque standard, par la dérivation
// écrite dans DerivedCoreProperties.txt.
func derivedDefaultIgnorable(r rune) bool {
	if unicode.Is(unicode.White_Space, r) || (r >= 0xFFF9 && r <= 0xFFFB) || (r >= 0x13430 && r <= 0x13440) ||
		unicode.Is(unicode.Prepended_Concatenation_Mark, r) {
		return false
	}
	return unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) || unicode.Is(unicode.Cf, r) ||
		unicode.Is(unicode.Variation_Selector, r)
}

func TestUnicodeParity(t *testing.T) {
	parity := loadUnicodeParity(t)

	t.Run("une seule version Unicode : table générée, golang.org/x/text, bibliothèque standard et Node du corpus", func(t *testing.T) {
		for name, version := range map[string]string{
			"unicode_tables.go":          unicodeTablesVersion,
			"golang.org/x/text/norm":     norm.Version,
			"unicode (Go)":               unicode.Version,
			"Node (unicode-parity.json)": parity.UnicodeVersion,
		} {
			if version != "17.0.0" {
				t.Errorf("%s : Unicode %s, attendu 17.0.0", name, version)
			}
		}
	})

	t.Run("la table Default_Ignorable_Code_Point est celle de Node (\\p{Default_Ignorable_Code_Point})", func(t *testing.T) {
		got := tableRanges(t, defaultIgnorableCodePoint)
		if fmt.Sprint(got) != fmt.Sprint(parity.DefaultIgnorableCodePoint) {
			t.Fatalf("plages %v, Node %v", got, parity.DefaultIgnorableCodePoint)
		}
	})

	t.Run("la table Default_Ignorable_Code_Point suit sa dérivation Unicode (bibliothèque standard)", func(t *testing.T) {
		for r := rune(0); r <= unicode.MaxRune; r++ {
			if got, want := unicode.Is(defaultIgnorableCodePoint, r), derivedDefaultIgnorable(r); got != want {
				t.Fatalf("%U : %v, dérivation %v", r, got, want)
			}
		}
	})

	t.Run("NFKC point de code par point de code identique à Node (empreinte de chaque point de code changé)", func(t *testing.T) {
		hash := sha256.New()
		changed := 0
		for r := rune(0); r <= unicode.MaxRune; r++ {
			if r >= 0xD800 && r <= 0xDFFF {
				continue
			}
			original := string(r)
			normalized := norm.NFKC.String(original)
			if normalized != original {
				changed++
				_, _ = fmt.Fprintf(hash, "%s:%s;", strconv.FormatInt(int64(r), 16), hex.EncodeToString([]byte(normalized)))
			}
		}
		if changed != parity.NFKCChangedCodePoints || hex.EncodeToString(hash.Sum(nil)) != parity.NFKCSHA256 {
			t.Fatalf("NFKC : %d points de code changés, empreinte différente de Node (%d)", changed, parity.NFKCChangedCodePoints)
		}
	})
}
