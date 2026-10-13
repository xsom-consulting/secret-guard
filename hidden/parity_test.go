package hidden

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// vectorsPath : vecteurs de parité produits par hidden.ts d'origine (generator/hidden/main.ts).
const vectorsPath = "../vectors/hidden.json"

type vectorFinding struct {
	Kind      string `json:"kind"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	Count     int    `json:"count"`
	ByteStart int    `json:"byteStart"`
	ByteEnd   int    `json:"byteEnd"`
}

type vectorCase struct {
	ID            string `json:"id"`
	Input         string `json:"input"`
	InputEncoding string `json:"inputEncoding"`
	Expected      struct {
		Complete       bool            `json:"complete"`
		Hidden         int             `json:"hidden"`
		Findings       []vectorFinding `json:"findings"`
		Stripped       *string         `json:"stripped"`
		StrippedSha256 string          `json:"strippedSha256"`
	} `json:"expected"`
}

type vectorFile struct {
	FormatVersion               int          `json:"formatVersion"`
	UpstreamCommit              string       `json:"upstreamCommit"`
	MaxInputBytes               int          `json:"maxInputBytes"`
	MaxFindings                 int          `json:"maxFindings"`
	ScatteredInvisibleThreshold int          `json:"scatteredInvisibleThreshold"`
	Cases                       []vectorCase `json:"cases"`
}

func loadVectors(t testing.TB) vectorFile {
	t.Helper()
	data, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("lecture des vecteurs : %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var file vectorFile
	if err := decoder.Decode(&file); err != nil || file.FormatVersion != 1 || len(file.Cases) == 0 {
		t.Fatalf("vecteurs illisibles ou de format inconnu : %v", err)
	}
	return file
}

func caseInput(t testing.TB, c vectorCase) []byte {
	t.Helper()
	switch c.InputEncoding {
	case "utf8":
		return []byte(c.Input)
	case "base64":
		data, err := base64.StdEncoding.Strict().DecodeString(c.Input)
		if err != nil {
			t.Fatalf("%s : entrée base64 illisible", c.ID)
		}
		return data
	}
	t.Fatalf("%s : écriture d'entrée inconnue", c.ID)
	return nil
}

// difference compare Find et Strip au résultat d'origine ; rend la première différence, sans l'entrée.
func difference(t testing.TB, c vectorCase) string {
	input := caseInput(t, c)
	report := Find(input)
	want := c.Expected
	if report.Complete != want.Complete || report.Hidden != want.Hidden || len(report.Findings) != len(want.Findings) {
		return "issue, nombre ou suites différents"
	}
	for i, f := range report.Findings {
		w := want.Findings[i]
		if string(f.Kind) != w.Kind || f.Line != w.Line || f.Column != w.Column || f.Count != w.Count ||
			f.ByteStart != w.ByteStart || f.ByteEnd != w.ByteEnd {
			return "suite différente"
		}
	}
	stripped := Strip(input)
	if want.Stripped != nil {
		if !bytes.Equal(stripped, []byte(*want.Stripped)) {
			return "texte nettoyé différent"
		}
	} else {
		sum := sha256.Sum256(stripped)
		if hex.EncodeToString(sum[:]) != want.StrippedSha256 {
			return "texte nettoyé différent (SHA-256)"
		}
	}
	return ""
}

// TestHiddenParity : chaque cas de vectors/hidden.json, produit par hidden.ts d'origine, donne exactement le même
// rapport (issue, nombre, suites, positions) et le même texte nettoyé. Un échec n'affiche que l'identifiant du cas.
func TestHiddenParity(t *testing.T) {
	t.Run("parité à 100 % avec hidden.ts", func(t *testing.T) {
		file := loadVectors(t)
		if file.MaxInputBytes != MaxInputBytes || file.MaxFindings != MaxFindings ||
			file.ScatteredInvisibleThreshold != ScatteredInvisibleThreshold {
			t.Fatalf("constantes d'origine différentes : %d, %d, %d", file.MaxInputBytes, file.MaxFindings, file.ScatteredInvisibleThreshold)
		}
		ids := map[string]bool{}
		failed := 0
		for _, c := range file.Cases {
			if ids[c.ID] {
				t.Errorf("identifiant en double : %s", c.ID)
			}
			ids[c.ID] = true
			if diff := difference(t, c); diff != "" {
				failed++
				t.Errorf("%s : %s", c.ID, diff)
			}
		}
		t.Logf("%d cas, %d en écart", len(file.Cases), failed)
	})
}
