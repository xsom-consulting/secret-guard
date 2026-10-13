package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const committedTable = "../../detect/unicode_tables.go"

func TestFR13UnicodeTablesGenerator(t *testing.T) {
	t.Run("FR-13: lecture des plages d'une propriété, triées et fusionnées", func(t *testing.T) {
		data := strings.Join([]string{
			"# commentaire ; Default_Ignorable_Code_Point",
			"200B..200F    ; Default_Ignorable_Code_Point # Cf   [5] ...",
			"00AD          ; Default_Ignorable_Code_Point # Cf       SOFT HYPHEN",
			"2010          ; Default_Ignorable_Code_Point",
			"0041          ; Alphabetic",
			"E0000..E0FFF  ; Default_Ignorable_Code_Point",
		}, "\n")
		ranges, err := Parse(strings.NewReader(data), property)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(ranges) != "[{173 173} {8203 8208} {917504 921599}]" {
			t.Fatalf("plages %v", ranges)
		}
		for _, bad := range []string{"ZZZZ ; Default_Ignorable_Code_Point", "0042..0041 ; Default_Ignorable_Code_Point", "110000 ; Default_Ignorable_Code_Point", "0041 ; Alphabetic"} {
			if _, err := Parse(strings.NewReader(bad), property); err == nil {
				t.Fatalf("%q accepté", bad)
			}
		}
	})

	t.Run("FR-13: fichier Unicode d'une autre version ou modifié refusé avant toute écriture", func(t *testing.T) {
		if _, err := Generate([]byte("# DerivedCoreProperties-16.0.0.txt\n00AD ; Default_Ignorable_Code_Point\n")); err == nil {
			t.Fatal("SHA-256 non vérifié")
		}
	})

	t.Run("FR-13: unicode_tables.go a la mise en forme exacte du générateur (le contenu est vérifié par TestFR13UnicodeParity)", func(t *testing.T) {
		committed, err := os.ReadFile(committedTable)
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, match := range regexp.MustCompile(`\{Lo: 0x([0-9A-F]+), Hi: 0x([0-9A-F]+), Stride: 1\}`).FindAllStringSubmatch(string(committed), -1) {
			lo, _ := strconv.ParseUint(match[1], 16, 32)
			hi, _ := strconv.ParseUint(match[2], 16, 32)
			lines = append(lines, fmt.Sprintf("%04X..%04X ; %s", lo, hi, property))
		}
		ranges, err := Parse(strings.NewReader(strings.Join(lines, "\n")), property)
		if err != nil {
			t.Fatal(err)
		}
		if string(Render(ranges)) != string(committed) {
			t.Fatal("unicode_tables.go diffère de la sortie du générateur")
		}
	})
}
