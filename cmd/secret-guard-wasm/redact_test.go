package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/internal/limits"
	"github.com/xsom-consulting/secret-guard/internal/report"
)

// redactBuffer masque input par l'état du module et rend le document et le texte qui le suit.
func redactBuffer(t *testing.T, m *module, input []byte, language string) (report.Redaction, []byte) {
	t.Helper()
	ptr := put(t, m, input)
	defer m.free(ptr)
	var languagePtr uintptr
	if language != "" {
		languagePtr = put(t, m, []byte(language))
		defer m.free(languagePtr)
	}
	out, length, ok := m.redact(ptr, uint32(len(input)), languagePtr, uint32(len(language)))
	if !ok {
		t.Fatal("masquage refusé")
	}
	defer m.free(out)
	data, _ := m.slice(out, length)
	line, text, found := bytes.Cut(data, []byte("\n"))
	if !found {
		t.Fatal("document sans fin de ligne")
	}
	var document report.Redaction
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	return document, append([]byte(nil), text...)
}

func TestModuleRedact(t *testing.T) {
	token := "gh" + "p_" + strings.Repeat("aB3d", 9)
	m := newModule()
	t.Run("secret masqué : document none, texte masqué après la fin de ligne", func(t *testing.T) {
		document, text := redactBuffer(t, m, []byte("TOKEN="+token+"\n"), "")
		if document.Failure != "none" || len(document.Initial.Findings) != 1 || len(document.Final.Findings) != 0 ||
			string(text) != "TOKEN=<REDACTED_github_token>\n" {
			t.Fatalf("%+v %q", document, text)
		}
	})
	t.Run("rien à masquer : texte recopié ; identifiant de langage lu dans un tampon prêté", func(t *testing.T) {
		document, text := redactBuffer(t, m, []byte("password = hunter2secret\n"), "dotenv")
		if document.Failure != "none" || !document.Initial.Complete {
			t.Fatalf("%+v %q", document, text)
		}
		document, text = redactBuffer(t, m, []byte("rien\n"), "")
		if document.Failure != "none" || string(text) != "rien\n" {
			t.Fatalf("%+v %q", document, text)
		}
	})
	t.Run("échecs : aucun texte après la fin de ligne", func(t *testing.T) {
		document, text := redactBuffer(t, m, bytes.Repeat([]byte("a"), limits.MaxInputBytes+1), "")
		if document.Failure != "incomplete" || document.Initial.Failure != "scan_limit" || len(text) != 0 {
			t.Fatalf("%+v %d", document, len(text))
		}
		document, text = redactBuffer(t, m, []byte("API_KEY="+token+"\nNEXT=another"), "")
		if document.Failure != "residual" || len(text) != 0 {
			t.Fatalf("%+v %d", document, len(text))
		}
	})
	t.Run("tampons hors du module refusés", func(t *testing.T) {
		input := put(t, m, []byte("abc"))
		defer m.free(input)
		if _, _, ok := m.redact(input+1, 3, 0, 0); ok {
			t.Fatal("entrée hors d'un tampon admise")
		}
		if _, _, ok := m.redact(input, 3, input+1, 2); ok {
			t.Fatal("langage hors d'un tampon admis")
		}
	})
}
