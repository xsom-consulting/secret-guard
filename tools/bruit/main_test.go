// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/detect"
	"github.com/xsom-consulting/secret-guard/pack"
)

// Valeurs d'essai assemblées par morceaux : aucune affectation à un nom sensible n'est écrite dans ce fichier.
var (
	sensitiveName = "pass" + "word"
	randomValue   = strings.Repeat("Xk7Pq2Rm9T", 2) + "Lw8Nb3Vc"
)

func TestAssignmentShape(t *testing.T) {
	for _, c := range []struct {
		before byte
		value  string
		want   string
	}{
		{' ', "${{ inputs.name }}", shapeCITemplate},
		{' ', "$(cat file)", shapeCommand},
		{' ', "$HOME/x", shapeShellReference},
		{' ', "{{ .Values.name }}", shapeTemplate},
		{' ', "[a, b]", shapeArray},
		{' ', "{ label: 'x' }", shapeObject},
		{' ', "await load()", shapeKeyword},
		{' ', "string;", shapeType},
		{' ', "Optional[str]", shapeType},
		{' ', "load(config)", shapeCall},
		{' ', "config.value,", shapeMember},
		{' ', "(a, b) => a", shapeExpression},
		{' ', "42,", shapeNumber},
		{' ', "expected", shapeIdentifier},
		{' ', "une phrase ordinaire", shapeOtherUnquoted},
		{'"', "prefix-${name}", shapeInterpolation},
		{'"', "$TOKEN other", shapeQuotedShell},
		{'\'', "test", shapeWeakLiteral},
		{'"', "short", shapeWeakLiteral},
		{'"', "Saisir le code reçu", shapeProse},
		{'"', "access_token_name", shapeCodeWord},
		{'"', "Placeholders", shapeSingleWord},
		{'"', randomValue, shapeSecretLike},
	} {
		if got := assignmentShape(c.before, []byte(c.value)); got != c.want {
			t.Errorf("assignmentShape(%q, %q) = %q, attendu %q", c.before, c.value, got, c.want)
		}
	}
}

func TestEntropyShape(t *testing.T) {
	for _, c := range []struct{ before, value, want string }{
		{"type ", "SubscriptionOverviewLinesElemVerificationsElem", shapeCamel},
		{"const ", "enumValues_SubscriptionFlowOfferId", shapeUnderscores},
		{"voir https://www.example.", "org/codes/article/ABCDEFGH000012345678", shapeURLPath},
		{"cd ", "internal/platform/windows/generation", shapePath},
		{"", "tmp-0123456789abcdef-suite", shapeDashes},
		{"", "0123456789abcdef0123456789", shapeHexadecimal},
		{"", randomValue + "+/" + randomValue + "=", shapeBase64Signs},
		{"", "9" + randomValue, shapeAlphanumeric},
		// Un blanc entre l'URL et la suite : la suite n'est plus dans l'URL.
		{"https://www.example.org puis ", "internal/platform/windows/generation", shapePath},
	} {
		if got := entropyShape([]byte(c.before), []byte(c.value)); got != c.want {
			t.Errorf("entropyShape(%q, %q) = %q, attendu %q", c.before, c.value, got, c.want)
		}
	}
}

func TestSelectBlobs(t *testing.T) {
	blobs := []blob{
		{path: "a/code.go", size: 10}, {path: "a/image.png", size: 10}, {path: "vectors/cases.json", size: 10},
		{path: "a/testdata/x.go", size: 10}, {path: "a/big.ts", size: maxFileBytes + 1}, {path: "pnpm-lock.yaml", size: 10},
		{path: "b/doc.md", size: maxFileBytes}, {path: "c/script.sh", size: 1}, {path: "d/app.tsx", size: 1},
	}
	kept := selectBlobs(blobs, 0)
	var paths []string
	for _, b := range kept {
		paths = append(paths, b.path)
	}
	if got := strings.Join(paths, " "); got != "a/code.go b/doc.md c/script.sh d/app.tsx" {
		t.Fatalf("fichiers gardés : %s", got)
	}
	first, second := selectBlobs(blobs, 2), selectBlobs(blobs, 2)
	if len(first) != 2 || first[0] != second[0] || first[1] != second[1] || first[0].path >= first[1].path {
		t.Fatalf("tirage non déterministe ou non trié : %v, %v", first, second)
	}
	if languageOf("x/app.tsx") != "typescriptreact" || languageOf("x/doc.md") != "" {
		t.Fatal("langage de l'extension")
	}
}

func TestCompare(t *testing.T) {
	previous := Repository{Name: "depot", Findings: 10, Incomplete: 1, ByRule: countsOf(map[string]int{"a": 6, "b": 4})}
	same := Repository{Name: "depot", Findings: 9, Incomplete: 1, ByRule: countsOf(map[string]int{"a": 6, "b": 3})}
	if problems := compare(previous, same); len(problems) != 0 {
		t.Fatalf("baisse refusée : %v", problems)
	}
	// Total égal, mais une règle monte et une règle neuve apparaît : deux hausses.
	moved := Repository{Name: "depot", Findings: 10, Incomplete: 1, ByRule: countsOf(map[string]int{"a": 7, "b": 2, "c": 1})}
	if problems := compare(previous, moved); len(problems) != 2 {
		t.Fatalf("hausses par règle : %v", problems)
	}
	worse := Repository{Name: "depot", Findings: 11, Incomplete: 2, ByRule: countsOf(map[string]int{"a": 7, "b": 4})}
	if problems := compare(previous, worse); len(problems) != 3 {
		t.Fatalf("hausses : %v", problems)
	}
}

func TestParseTargets(t *testing.T) {
	targets, err := parseTargets([]string{"un=/tmp/a b", "deux@abc123=rel"}, true)
	if err != nil || len(targets) != 2 || targets[0] != (target{name: "un", dir: "/tmp/a b"}) ||
		targets[1] != (target{name: "deux", commit: "abc123", dir: "rel"}) {
		t.Fatalf("%v %v", targets, err)
	}
	for _, args := range [][]string{{"sans-chemin"}, {"=x"}, {"a="}, {"a=x", "a=y"}, {"a/b=x"}, {"a@=x"}} {
		if _, err := parseTargets(args, true); err == nil {
			t.Errorf("%v : accepté", args)
		}
	}
	if _, err := parseTargets([]string{"a@abc=x"}, false); err == nil {
		t.Error("commit accepté sans -baseline")
	}
}

func mustRules(t *testing.T) *detect.Rules {
	t.Helper()
	initial, err := pack.Initial()
	if err != nil {
		t.Fatal(err)
	}
	rules, err := detect.LoadRules(initial)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

// repository crée un dépôt git d'essai et rend son chemin ; l'essai est sauté sans git.
func repository(t *testing.T, files map[string]string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git absent")
	}
	dir := t.TempDir()
	for rel, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	commit(t, dir, "init", "-q")
	commit(t, dir, "add", "-A")
	commit(t, dir, "-c", "user.name=essai", "-c", "user.email=essai@example.org", "-c", "commit.gpgsign=false",
		"commit", "-q", "-m", "essai")
	return dir
}

func commit(t *testing.T, dir string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", dir}, args...)...)
	command.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v : %v\n%s", args, err, out)
	}
}

func TestRun(t *testing.T) {
	today = func() string { return "2026-01-02" }
	noisy := "const " + sensitiveName + " = \"" + randomValue + "\"\n"
	dir := repository(t, map[string]string{
		"src/app.ts":         "// commentaire\n" + noisy + "export const x = 1\n",
		"src/clean.go":       "package clean\n",
		"vectors/cases.json": noisy,
		"image.png":          noisy,
	})
	reportPath := filepath.Join(t.TempDir(), "rapport.json")
	invoke := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := run(append([]string{"-report", reportPath}, args...), &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}

	if code, _, stderr := invoke("depot=" + dir); code != exitError || !strings.Contains(stderr, "absent du rapport") {
		t.Fatalf("dépôt absent du rapport : %d %s", code, stderr)
	}
	if code, _, _ := invoke(); code != exitError {
		t.Fatal("aucun dépôt : accepté")
	}
	if code, _, _ := invoke("-limit", "3", "depot="+dir); code != exitError {
		t.Fatal("-limit sans -baseline : accepté")
	}
	if code, _, stderr := invoke("-baseline", "depot@inconnu="+dir); code != exitError || !strings.Contains(stderr, "introuvable") {
		t.Fatalf("commit inconnu : %d %s", code, stderr)
	}

	code, stdout, stderr := invoke("-baseline", "-list", "depot="+dir)
	if code != exitOK {
		t.Fatalf("base : %d %s", code, stderr)
	}
	// La liste donne la position, jamais la valeur.
	if !strings.Contains(stdout, "depot\tsrc/app.ts\t2\t") || strings.Contains(stdout, randomValue) {
		t.Fatalf("liste : %s", stdout)
	}
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	// Le rapport ne porte ni chemin de fichier, ni chemin du dépôt, ni contenu, ni affectation d'un nombre à un nom
	// de règle (qui serait un constat pour qui analyse ce dépôt).
	if result := scanFile(raw, mustRules(t), ""); result.incomplete || len(result.findings) != 0 {
		t.Fatalf("le rapport est lui-même signalé par le moteur : %+v", result)
	}
	for _, forbidden := range []string{"app.ts", "src/", dir, randomValue, sensitiveName + " ="} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("le rapport porte %q", forbidden)
		}
	}
	var report Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Repositories) != 1 {
		t.Fatalf("%d dépôts", len(report.Repositories))
	}
	measured := report.Repositories[0]
	rule := "contextual_" + sensitiveName
	if measured.Name != "depot" || len(measured.Commit) != 41 || measured.Commit[0] != 'g' || measured.Date != "2026-01-02" || measured.Files != 2 ||
		measured.Findings == 0 || measured.ByRule.Of(rule) != 1 || measured.AssignmentShapes.Of(shapeSecretLike) != 1 ||
		measured.Rules == 0 {
		t.Fatalf("mesure : %+v", measured)
	}

	// Même mesure : aucune hausse, rapport inchangé sans -write.
	if code, _, stderr := invoke("depot=" + dir); code != exitOK {
		t.Fatalf("comparaison : %d %s", code, stderr)
	}
	// Le dépôt avance : la mesure reste celle du commit épinglé.
	if err := os.WriteFile(filepath.Join(dir, "src", "more.ts"), []byte(noisy), 0o600); err != nil {
		t.Fatal(err)
	}
	commit(t, dir, "add", "-A")
	commit(t, dir, "-c", "user.name=essai", "-c", "user.email=essai@example.org", "-c", "commit.gpgsign=false",
		"commit", "-q", "-m", "suite")
	if code, stdout, stderr := invoke("depot=" + dir); code != exitOK || !strings.Contains(stdout, "2 fichiers") {
		t.Fatalf("commit épinglé : %d %s %s", code, stdout, stderr)
	}

	// Un rapport qui annonçait moins : la hausse est refusée, par le total et par la règle, et rien n'est écrit.
	lower := report
	lower.Repositories = []Repository{measured}
	lower.Repositories[0].Findings--
	lower.Repositories[0].ByRule = withCount(measured.ByRule, rule, 0)
	if err := writeReport(reportPath, &lower); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(reportPath)
	code, stdout, stderr = invoke("-write", "depot="+dir)
	after, _ := os.ReadFile(reportPath)
	if code != exitRise || !strings.Contains(stdout, "HAUSSE") || !strings.Contains(stdout, rule) ||
		!strings.Contains(stderr, "refusé") || !bytes.Equal(before, after) {
		t.Fatalf("hausse : %d\n%s\n%s", code, stdout, stderr)
	}

	// Un rapport qui annonçait plus : la baisse passe, et -write l'enregistre.
	higher := lower
	higher.Repositories[0].Findings = measured.Findings + 5
	higher.Repositories[0].ByRule = withCount(measured.ByRule, rule, 6)
	if err := writeReport(reportPath, &higher); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := invoke("-write", "depot="+dir); code != exitOK || !strings.Contains(stdout, "baisse") {
		t.Fatalf("baisse : %d %s %s", code, stdout, stderr)
	}
	rewritten, err := readReport(reportPath)
	if err != nil || rewritten.Repositories[0].Findings != measured.Findings {
		t.Fatalf("rapport réécrit : %+v %v", rewritten, err)
	}

	// Nouvelle base sur le commit courant : trois fichiers, sans comparaison.
	if code, stdout, stderr := invoke("-baseline", "depot="+dir); code != exitOK || !strings.Contains(stdout, "3 fichiers") {
		t.Fatalf("nouvelle base : %d %s %s", code, stdout, stderr)
	}
}

// withCount rend une copie de counts où name vaut n.
func withCount(counts Counts, name string, n int) Counts {
	table := map[string]int{name: n}
	for _, c := range counts {
		if c.Name != name {
			table[c.Name] = c.Count
		}
	}
	return countsOf(table)
}

func TestReadReport(t *testing.T) {
	dir := t.TempDir()
	if report, err := readReport(filepath.Join(dir, "absent.json")); err != nil || len(report.Repositories) != 0 {
		t.Fatalf("rapport absent : %v %v", report, err)
	}
	for name, content := range map[string]string{
		"version.json": `{"formatVersion": 2, "about": "", "repositories": []}`,
		"champ.json":   `{"formatVersion": 1, "about": "", "repositories": [], "files": ["a"]}`,
		"forme.json":   `[`,
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readReport(path); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}

func TestPosition(t *testing.T) {
	content := []byte("un\ndéjà vu ici\n")
	for offset, want := range map[int][2]int{0: {1, 1}, 3: {2, 1}, 9: {2, 5}, len(content): {3, 1}, 99: {3, 1}} {
		if line, column := position(content, offset); line != want[0] || column != want[1] {
			t.Errorf("position(%d) = %d, %d ; attendu %v", offset, line, column, want)
		}
	}
}
