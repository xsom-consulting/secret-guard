package mentions

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// vectorsPath : vecteurs de parité produits par mentionedPaths d'origine (generator/hidden/main.ts).
const vectorsPath = "../vectors/mentions.json"

type vectorMention struct {
	Path      string `json:"path"`
	Lines     string `json:"lines"`
	ByteStart int    `json:"byteStart"`
	ByteEnd   int    `json:"byteEnd"`
}

type vectorCase struct {
	ID            string `json:"id"`
	Input         string `json:"input"`
	InputEncoding string `json:"inputEncoding"`
	Expected      struct {
		Mentions []vectorMention `json:"mentions"`
		Upstream []string        `json:"upstream"`
	} `json:"expected"`
}

type vectorFile struct {
	FormatVersion  int          `json:"formatVersion"`
	UpstreamCommit string       `json:"upstreamCommit"`
	Cwd            string       `json:"cwd"`
	Patterns       []string     `json:"patterns"`
	Cases          []vectorCase `json:"cases"`
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
	if err := decoder.Decode(&file); err != nil || file.FormatVersion != 1 || len(file.Cases) == 0 || file.Cwd != "/work" {
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

// asRead écrit des octets comme l'origine les lit après décodage : un octet invalide vaut U+FFFD, un par octet.
func asRead(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, w := utf8.DecodeRuneInString(s[i:])
		b.WriteRune(r)
		i += w
	}
	return b.String()
}

// resolve est path.resolve de Node en POSIX (répertoire de travail absolu).
func resolve(cwd, p string) string {
	if strings.HasPrefix(p, "/") {
		return path.Clean(p)
	}
	return path.Join(cwd, p)
}

// difference compare Parse au résultat d'origine : mentions détaillées (référence par les expressions d'origine) et,
// une fois résolues et fusionnées comme l'origine, la sortie même de mentionedPaths.
func difference(t testing.TB, cwd string, c vectorCase) string {
	got := Parse(caseInput(t, c))
	want := c.Expected.Mentions
	if len(got) != len(want) {
		return "nombre de mentions différent"
	}
	for i, m := range got {
		w := want[i]
		if asRead(m.Path) != w.Path || m.Lines != w.Lines || m.ByteStart != w.ByteStart || m.ByteEnd != w.ByteEnd {
			return "mention différente"
		}
	}
	var resolved []string
	for _, m := range got {
		if r := resolve(cwd, asRead(m.Path)); !slices.Contains(resolved, r) {
			resolved = append(resolved, r)
		}
	}
	if !slices.Equal(resolved, c.Expected.Upstream) {
		return "chemins résolus différents de mentionedPaths"
	}
	return ""
}

// TestMentionsParity : chaque cas de vectors/mentions.json, produit par mentionedPaths d'origine, donne les mêmes
// mentions ; résolues comme l'origine, elles donnent exactement sa sortie. Un échec n'affiche que l'identifiant.
func TestMentionsParity(t *testing.T) {
	t.Run("parité à 100 % avec mentionedPaths", func(t *testing.T) {
		file := loadVectors(t)
		want := []string{`/(?:^|\s)@(?:"([^"]+)"|(\S+))/gu`, `/#L\d+(?:-\d+)?$/u`, `/[,;:!?)]+$/u`}
		if !slices.Equal(file.Patterns, want) {
			t.Fatalf("expressions d'origine différentes : %q", file.Patterns)
		}
		ids := map[string]bool{}
		failed := 0
		for _, c := range file.Cases {
			if ids[c.ID] {
				t.Errorf("identifiant en double : %s", c.ID)
			}
			ids[c.ID] = true
			if diff := difference(t, file.Cwd, c); diff != "" {
				failed++
				t.Errorf("%s : %s", c.ID, diff)
			}
		}
		t.Logf("%d cas, %d en écart", len(file.Cases), failed)
	})
}
