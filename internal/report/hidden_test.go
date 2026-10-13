package report

import (
	"testing"

	"github.com/xsom-consulting/secret-guard/hidden"
)

func TestHiddenReport(t *testing.T) {
	t.Run("forme JSON : tableau vide, champs nommés, une ligne", func(t *testing.T) {
		if got := string(HiddenJSON(hidden.Find([]byte("plain")))); got != "{\"complete\":true,\"hidden\":0,\"findings\":[]}\n" {
			t.Fatal(got)
		}
		got := string(HiddenJSON(hidden.Find([]byte("a\U000E0041\U000E0042"))))
		want := "{\"complete\":true,\"hidden\":2,\"findings\":[{\"kind\":\"tag_characters\",\"line\":1,\"column\":2,\"count\":2,\"byteStart\":1,\"byteEnd\":9}]}\n"
		if got != want {
			t.Fatal(got)
		}
	})
	t.Run("codes de sortie : 0 rien, 1 trouvé, 2 incomplet", func(t *testing.T) {
		if HiddenExitCode(hidden.Report{Complete: true}) != ExitClean ||
			HiddenExitCode(hidden.Report{Complete: true, Hidden: 1}) != ExitFindings ||
			HiddenExitCode(hidden.Report{}) != ExitError {
			t.Fatal("code")
		}
	})
}
