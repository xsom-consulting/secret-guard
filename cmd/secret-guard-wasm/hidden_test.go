package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/internal/report"
)

func TestModuleFindHidden(t *testing.T) {
	t.Run("rapport des instructions cachées, sans le message ; tampon inconnu refusé", func(t *testing.T) {
		m := newModule()
		var b strings.Builder
		b.WriteString("ok")
		for _, r := range "evil" {
			b.WriteRune(0xE0000 + r)
		}
		ptr := put(t, m, []byte(b.String()))
		defer m.free(ptr)
		out, length, ok := m.findHidden(ptr, uint32(b.Len()))
		if !ok {
			t.Fatal("refus")
		}
		defer m.free(out)
		data, _ := m.slice(out, length)
		var document report.HiddenDocument
		if err := json.Unmarshal(data, &document); err != nil || !document.Complete || document.Hidden != 4 ||
			len(document.Findings) != 1 || strings.Contains(string(data), "evil") {
			t.Fatalf("%s", data)
		}
		if _, _, ok := m.findHidden(ptr+1, 1); ok {
			t.Fatal("adresse inconnue admise")
		}
	})
}
