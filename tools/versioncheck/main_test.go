// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// state décrit un dépôt d'essai : ce que chaque fichier annonce.
type state struct {
	rules                                  int
	wasm, required                         string
	readmeFrench, readmeEnglish, rulePackN int
	rulePackVersion                        string
	blockRequire                           bool
}

// released est un dépôt prêt pour la version donnée, à n règles.
func released(version string, n int) state {
	return state{rules: n, wasm: version, required: version, readmeFrench: n, readmeEnglish: n, rulePackN: n, rulePackVersion: version}
}

func (s state) write(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	rules := make([]string, s.rules)
	for i := range rules {
		rules[i] = fmt.Sprintf(`{"ruleId":"r%d"}`, i)
	}
	require := "require " + rootModule + " v" + s.required + "\n"
	if s.blockRequire {
		require = "require (\n\t" + rootModule + " v" + s.required + "\n\tgolang.org/x/text v0.43.0 // indirect\n)\n"
	}
	files := map[string]string{
		packFile: `{"schemaVersion":1,"rules":[` + strings.Join(rules, ",") + `]}`,
		wasmFile: `{"name":"@xsom/secret-guard-wasm","version":"` + s.wasm + `"}`,
		expurgationMod: "module " + rootModule + "/expurgation\n\ngo 1.27.2\n\n" + require +
			"\nreplace " + rootModule + " => ../\n",
		readmeFile: "# Secret Guard\n\n- " + fmt.Sprint(s.readmeFrench) + " règles (Pack initial, `pack/initial/pack.json`) : les 35…\n\n" +
			"**What it does**: " + fmt.Sprint(s.readmeEnglish) + " rules (initial Pack: the 35…\n",
		rulePackFile: "| `rules` | tableau de 1 à 1 000 règles (" + fmt.Sprint(s.rulePackN) + " dans le Pack initial de la v" +
			s.rulePackVersion + ") |\n",
	}
	for rel, content := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func problems(t *testing.T, s state, target string) []string {
	t.Helper()
	result, err := Check(s.write(t), target)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range result.Problems {
		out = append(out, p.String())
	}
	return out
}

func TestCheckReleasedState(t *testing.T) {
	for _, block := range []bool{false, true} {
		s := released("0.10.0", 436)
		s.blockRequire = block
		for _, target := range []string{"0.10.0", ""} {
			if got := problems(t, s, target); len(got) != 0 {
				t.Errorf("dépôt prêt (bloc require : %v, version %q) : %v", block, target, got)
			}
		}
	}
}

// TestCheckFailsOnV090State : l'état du commit étiqueté v0.9.0 (wasm/package.json et expurgation/go.mod restés en
// 0.8.1, décomptes restés à 334 pour 345 règles chargées) est refusé, avec la version visée comme sans elle.
func TestCheckFailsOnV090State(t *testing.T) {
	v090 := state{rules: 345, wasm: "0.8.1", required: "0.8.1", readmeFrench: 334, readmeEnglish: 334, rulePackN: 334, rulePackVersion: "0.8.1"}
	got := problems(t, v090, "0.9.0")
	want := []string{
		"wasm/package.json : version 0.8.1, attendu 0.9.0",
		"expurgation/go.mod : version exigée de " + rootModule + " v0.8.1, attendu v0.9.0",
		"README.md : nombre de règles (« - N règles (Pack initial ») 334, attendu 345",
		"README.md : nombre de règles (« **What it does**: N rules (initial Pack ») 334, attendu 345",
		"docs/rule-pack.md : nombre de règles (« (N dans le Pack initial de la vX.Y.Z) ») 334, attendu 345",
		"docs/rule-pack.md : version du décompte (« (N dans le Pack initial de la vX.Y.Z) ») v0.8.1, attendu v0.9.0",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("écarts :\n%s\nattendu :\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Sans version : les deux fichiers de version concordent entre eux (0.8.1), les trois décomptes restent faux.
	if got := problems(t, v090, ""); len(got) != 3 {
		t.Fatalf("sans version : %v", got)
	}
}

func TestCheckEachMismatch(t *testing.T) {
	for name, change := range map[string]func(*state){
		"wasm/package.json":       func(s *state) { s.wasm = "0.9.9" },
		"expurgation/go.mod":      func(s *state) { s.required = "0.9.9" },
		"README en français":      func(s *state) { s.readmeFrench-- },
		"README en anglais":       func(s *state) { s.readmeEnglish++ },
		"décompte de rule-pack":   func(s *state) { s.rulePackN = 1 },
		"version de rule-pack":    func(s *state) { s.rulePackVersion = "0.9.9" },
		"une règle de plus":       func(s *state) { s.rules++ },
		"bloc require, autre":     func(s *state) { s.blockRequire, s.required = true, "0.9.9" },
		"version à deux chiffres": func(s *state) { s.wasm = "0.1" },
	} {
		s := released("0.10.0", 436)
		change(&s)
		got := problems(t, s, "0.10.0")
		want := 1
		if name == "une règle de plus" {
			want = 3 // les trois décomptes de la documentation
		}
		if len(got) != want {
			t.Errorf("%s : %d écart(s) : %v", name, len(got), got)
		}
	}
}

// TestCheckMissingCount : un décompte reformulé, absent ou écrit deux fois est un écart, jamais un point sauté.
func TestCheckMissingCount(t *testing.T) {
	root := released("0.10.0", 436).write(t)
	readme := filepath.Join(root, readmeFile)
	if err := os.WriteFile(readme, []byte("# Secret Guard\n\nPlus de quatre cents règles.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Check(root, "0.10.0")
	if err != nil || len(result.Problems) != 2 || !strings.Contains(result.Problems[0].String(), "introuvable, attendu 436") {
		t.Fatalf("décompte absent : %v %v", result.Problems, err)
	}
	twice := "- 436 règles (Pack initial\n- 436 règles (Pack initial\n**What it does**: 436 rules (initial Pack\n"
	if err := os.WriteFile(readme, []byte(twice), 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := Check(root, "0.10.0"); err != nil || len(result.Problems) != 1 {
		t.Fatalf("décompte en double : %v %v", result.Problems, err)
	}
	// go.mod sans exigence du module racine.
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(expurgationMod)), []byte("module x\n\nreplace "+rootModule+" => ../\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := Check(root, "0.10.0"); err != nil || len(result.Problems) != 2 {
		t.Fatalf("exigence absente : %v %v", result.Problems, err)
	}
}

func TestCheckErrors(t *testing.T) {
	root := released("0.10.0", 436).write(t)
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(wasmFile))); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(root, "0.10.0"); err == nil {
		t.Error("fichier absent : accepté")
	}
	root = released("0.10.0", 436).write(t)
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(packFile)), []byte(`{"rules":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(root, "0.10.0"); err == nil {
		t.Error("Pack sans règles : accepté")
	}
	// Sans version visée, une version mal formée dans wasm/package.json est une erreur, pas une version.
	bad := released("0.10.0", 436)
	bad.wasm = "prochaine"
	if _, err := Check(bad.write(t), ""); err == nil {
		t.Error("version mal formée sans version visée : acceptée")
	}
}

func TestRun(t *testing.T) {
	ready := released("0.10.0", 436).write(t)
	invoke := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, _ := invoke("-root", ready, "v0.10.0"); code != exitOK || !strings.Contains(stdout, "6 points concordent") {
		t.Fatalf("dépôt prêt : %d %s", code, stdout)
	}
	if code, stdout, _ := invoke("-root", ready, "0.10.0"); code != exitOK || !strings.Contains(stdout, "v0.10.0 (donnée en argument)") {
		t.Fatalf("version sans « v » : %d %s", code, stdout)
	}
	if code, stdout, _ := invoke("-root", ready); code != exitOK || !strings.Contains(stdout, "lue dans wasm/package.json") {
		t.Fatalf("sans version : %d %s", code, stdout)
	}
	code, stdout, stderr := invoke("-root", ready, "v0.11.0")
	if code != exitMismatch || strings.Count(stdout, "ÉCART ") != 3 || !strings.Contains(stderr, "3 écart(s)") {
		t.Fatalf("version suivante : %d\n%s\n%s", code, stdout, stderr)
	}
	for _, args := range [][]string{{"-root", ready, "v1"}, {"-root", ready, "v0.10.0", "v0.11.0"}, {"-root", filepath.Join(ready, "absent")}, {"-inconnu"}} {
		if code, _, _ := invoke(args...); code != exitError {
			t.Errorf("%v : code %d", args, code)
		}
	}
}

// TestRepositoryAnchors : dans ce dépôt, chaque point de comparaison est trouvé (une seule fois). Les valeurs ne sont
// pas jugées ici (elles ne concordent qu'au commit de version) ; un texte reformulé qui ferait disparaître un
// décompte fait échouer cet essai.
func TestRepositoryAnchors(t *testing.T) {
	result, err := Check(filepath.Join("..", ".."), "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Checked != 6 || result.Rules == 0 {
		t.Fatalf("points comparés : %d, règles : %d", result.Checked, result.Rules)
	}
	for _, problem := range result.Problems {
		if problem.Found == "" {
			t.Errorf("point de comparaison introuvable : %s", problem)
		}
	}
}
