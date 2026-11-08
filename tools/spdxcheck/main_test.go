// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func header(id string) string { return "// SPDX-License-" + "Identifier: " + id + "\n" }

func TestExpectedLicense(t *testing.T) {
	for rel, want := range map[string]string{
		"detect/scan.go": Apache, "wasm/node.mjs": Apache, "generator/corpus/main.ts": Apache, "expurgation.go": Apache,
		"expurgationx/a.go": Apache, "expurgation/expurgate.go": PolyForm, "expurgation/cmd/secret-guard-wasm/main_wasip1.go": PolyForm,
	} {
		if got := ExpectedLicense(rel); got != want {
			t.Errorf("%s : %s, attendu %s", rel, got, want)
		}
	}
}

func TestCheck(t *testing.T) {
	root := t.TempDir()
	write(t, root, "detect/ok.go", header(Apache)+"\npackage detect\n")
	write(t, root, "wasm/ok.mjs", header(Apache)+"export {};\n")
	write(t, root, "wasm/types.d.mts", header(Apache)+"export {};\n")
	write(t, root, "generator/script.ts", "#!/usr/bin/env node\n"+header(Apache)+"export {};\n")
	write(t, root, "expurgation/ok.go", header(PolyForm)+"\npackage expurgation\n")
	// Écarts : sans en-tête, mauvaise licence d'un côté et de l'autre, en-tête trop bas.
	write(t, root, "detect/missing.go", "package detect\n")
	write(t, root, "detect/polyform.go", header(PolyForm)+"\npackage detect\n")
	write(t, root, "expurgation/internal/request/apache.go", header(Apache)+"\npackage request\n")
	write(t, root, "wasm/late.mjs", "// a\n// b\n// c\n"+header(Apache))
	// Hors vérification : autre extension, dossiers ignorés.
	write(t, root, "README.md", "aucun en-tête\n")
	write(t, root, "generator/node_modules/x/index.ts", "export {};\n")
	write(t, root, "dist/npm/node.mjs", "export {};\n")
	write(t, root, "_bmad/x.ts", "export {};\n")
	problems, checked, err := Check(root)
	if err != nil {
		t.Fatal(err)
	}
	if checked != 9 {
		t.Errorf("%d fichiers vérifiés, 9 attendus", checked)
	}
	var got []string
	for _, p := range problems {
		got = append(got, p.String())
	}
	want := []string{
		"detect/missing.go : aucun identifiant SPDX, attendu Apache-2.0",
		"detect/polyform.go : identifiant SPDX PolyForm-Small-Business-1.0.0, attendu Apache-2.0",
		"expurgation/internal/request/apache.go : identifiant SPDX Apache-2.0, attendu PolyForm-Small-Business-1.0.0",
		"wasm/late.mjs : aucun identifiant SPDX, attendu Apache-2.0",
	}
	if !slices.Equal(got, want) {
		t.Errorf("écarts :\n%s\nattendu :\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestRepository : chaque fichier source de ce dépôt porte l'identifiant de son module (go test ./... échoue
// sinon, en nommant le fichier).
func TestRepository(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	problems, checked, err := Check(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
	if checked < 100 {
		t.Errorf("%d fichiers vérifiés : dépôt mal trouvé", checked)
	}
}

func TestRun(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(&stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "fichiers") {
		t.Fatalf("code %d : %s", code, stderr.String())
	}
}

func TestDeclaresRootModule(t *testing.T) {
	for goMod, want := range map[string]bool{
		"module github.com/xsom-consulting/secret-guard\n\ngo 1.27.2\n":           true,
		"module github.com/xsom-consulting/secret-guard\r\n":                      true,
		"module github.com/xsom-consulting/secret-guard/expurgation\n":            false,
		"// module github.com/xsom-consulting/secret-guard\nmodule example.com/x": false,
	} {
		if got := declaresRootModule(goMod); got != want {
			t.Errorf("%q : %t", goMod, got)
		}
	}
}
