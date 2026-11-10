// SPDX-License-Identifier: Apache-2.0

// Commande depguardcheck : prouve que les règles depguard de .golangci.yml refusent chaque import interdit au
// moteur (detect), au Pack (pack), au Pack de règles du client (custom), aux instructions cachées (hidden), aux
// mentions (mentions), aux limites (internal/limits), à la sémantique des chaînes (internal/jstext) et au programme
// livré (cmd, internal) ; et que celles de expurgation/.golangci.yml (module expurgation) refusent chaque import
// interdit à l'expurgation et à son programme livré (cmd/secret-guard-wasm, internal/request).
//
// Usage (à la racine du dépôt) : go run ./tools/depguardcheck
//
// Elle copie le dépôt dans un dossier temporaire, vérifie que chaque module de la copie passe golangci-lint, puis, pour
// chaque import interdit, ajoute un fichier qui l'importe dans le paquet visé et exige que golangci-lint, lancé dans le
// module du paquet, échoue par depguard sur cet import. Le binaire golangci-lint est pris dans le PATH, ou dans la variable GOLANGCI_LINT.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const module = "github.com/xsom-consulting/secret-guard"

// nestedModule est le dossier du module expurgation, relatif au module racine.
const nestedModule = "expurgation"

type injection struct {
	module  string // dossier du module, relatif au module racine ("" : module racine)
	dir     string // dossier du paquet, relatif au module ("." : racine du module)
	pkg     string // nom du paquet Go de ce dossier
	imports string // chemin importé
}

// backtracking : moteurs d'expressions régulières à retour arrière, refusés partout.
var backtracking = []string{
	"github.com/dlclark/regexp2", "github.com/gijsbers/go-pcre", "github.com/GRbit/go-pcre",
	"github.com/glenn-brown/golang-pkg-pcre", "go.arsenm.dev/pcre",
}

// pureImports sont refusés aux paquets purs (moteur et expurgation).
var pureImports = []string{
	"os", "io/fs", "io/ioutil", "net", "net/http", "syscall", "golang.org/x/sys/cpu", "time", "math/rand",
	"crypto/rand", "log", "log/slog", "unsafe", "plugin", "os/exec",
	// Hors de la liste fermée. sync est admis seul (fils des familles sans budget, detect/detectors.go) :
	// ses sous-paquets restent refusés, et runtime aussi (le nombre de fils vient d'Options.Workers).
	"fmt", "path/filepath", "runtime", "runtime/debug", "sync/atomic", "mime", "hash/maphash",
	"golang.org/x/text/language",
	// Aucun condensat non salé dans le moteur.
	"crypto/md5", "crypto/sha1",
}

// shippedImports sont refusés au programme livré (ligne de commande, WebAssembly, rendu partagé).
var shippedImports = []string{"net", "net/http", "net/rpc", "net/smtp", "crypto/tls", "os/exec", "plugin"}

func injections() []injection {
	cases := []injection{}
	add := func(module, dir, pkg string, imports ...[]string) {
		for _, list := range imports {
			for _, imp := range list {
				cases = append(cases, injection{module: module, dir: dir, pkg: pkg, imports: imp})
			}
		}
	}
	// Moteur, Pack, Pack de règles du client, instructions cachées, mentions, limites et sémantique des chaînes :
	// purs, liste fermée d'imports.
	for _, target := range []struct{ dir, pkg string }{
		{"detect", "detect"}, {"pack", "pack"}, {"custom", "custom"}, {"hidden", "hidden"}, {"injection", "injection"}, {"mentions", "mentions"},
		{"internal/limits", "limits"}, {"internal/jstext", "jstext"},
	} {
		add("", target.dir, target.pkg, pureImports, backtracking)
	}
	// Programme livré du module racine (ligne de commande, rendu partagé) : ni réseau, ni autre programme, ni moteur à
	// retour arrière.
	for _, target := range []struct{ dir, pkg string }{{"cmd/secret-guard", "main"}, {"internal/report", "report"}} {
		add("", target.dir, target.pkg, shippedImports, backtracking)
	}
	// Expurgation : pure, liste fermée (detect et internal/jstext du module racine seulement : ni le Pack, ni le rendu
	// JSON, ni une autre partie du moteur).
	add(nestedModule, ".", "expurgation", pureImports, backtracking, []string{
		"bytes", "strings", "encoding/json", module + "/pack", module + "/internal/report",
	})
	// Programme livré du module expurgation (WebAssembly, demande d'expurgation).
	for _, target := range []struct{ dir, pkg string }{{"cmd/secret-guard-wasm", "main"}, {"internal/request", "request"}} {
		add(nestedModule, target.dir, target.pkg, shippedImports, backtracking)
	}
	return cases
}

func main() {
	if err := run(os.Stdout); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "depguardcheck : %v\n", err)
		os.Exit(1)
	}
}

func run(out io.Writer) error {
	src, err := moduleRoot()
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "depguardcheck-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	if err := copyTree(src, tmp); err != nil {
		return fmt.Errorf("copie du module : %w", err)
	}
	if err := prepare(tmp); err != nil {
		return err
	}

	for _, module := range []string{"", nestedModule} {
		if output, err := lint(filepath.Join(tmp, module)); err != nil {
			return fmt.Errorf("la copie intacte du module %q doit passer golangci-lint : %w\n%s", module, err, output)
		}
	}
	_, _ = fmt.Fprintln(out, "ok : copie intacte acceptée par golangci-lint (module racine et module expurgation)")

	failures := 0
	for _, c := range injections() {
		file := filepath.Join(tmp, c.module, filepath.FromSlash(c.dir), injectedFile)
		code := fmt.Sprintf("package %s\n\nimport _ %q\n", c.pkg, c.imports)
		if err := os.WriteFile(file, []byte(code), 0o600); err != nil {
			return err
		}
		output, lintErr := lint(filepath.Join(tmp, c.module))
		if err := os.Remove(file); err != nil {
			return err
		}
		refused := lintErr != nil && refusedByDepguard(output, c)
		if refused {
			_, _ = fmt.Fprintf(out, "ok : %s importe %s → refusé par depguard\n", c.path(), c.imports)
			continue
		}
		failures++
		_, _ = fmt.Fprintf(out, "ÉCHEC : %s importe %s → non refusé par depguard\n%s\n", c.path(), c.imports, output)
	}
	if failures > 0 {
		return fmt.Errorf("%d import(s) interdit(s) non refusé(s)", failures)
	}
	return nil
}

const injectedFile = "zz_depguardcheck.go"

// refusedByDepguard cherche, dans la sortie de golangci-lint, la ligne de depguard qui refuse
// exactement l'import injecté, dans le fichier injecté :
// <dir>/zz_depguardcheck.go:3:8: import '<import>' is not allowed from list '…': … (depguard)
func refusedByDepguard(output string, c injection) bool {
	location := injectedFile + ":"
	if c.dir != "." {
		location = c.dir + "/" + location
	}
	message := "import '" + c.imports + "' is not allowed"
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(filepath.ToSlash(line))
		if strings.HasPrefix(line, location) && strings.Contains(line, message) && strings.HasSuffix(line, "(depguard)") {
			return true
		}
	}
	return false
}

// path est le dossier du paquet, relatif au module racine.
func (c injection) path() string {
	return filepath.ToSlash(filepath.Join(c.module, c.dir))
}

// moduleRoot remonte depuis le dossier courant jusqu'au go.mod du module.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil && declaresModule(string(data)) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("module " + module + " introuvable : lancer depuis le dépôt")
		}
		dir = parent
	}
}

// declaresModule dit si go.mod déclare le module (fins de ligne CRLF et espaces tolérés).
func declaresModule(goMod string) bool {
	for _, line := range strings.Split(goMod, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "module" && fields[1] == module {
			return true
		}
	}
	return false
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
}

// prepare rend importables, dans la copie, les cibles qui n'existent pas dans le module : un faux module
// golang.org/x/sys local, et de faux modules regexp2 et PCRE.
func prepare(tmp string) error {
	files := map[string]string{}
	goMod, err := os.ReadFile(filepath.Join(tmp, "go.mod"))
	if err != nil {
		return err
	}
	if !strings.Contains(string(goMod), "golang.org/x/sys ") {
		files["_fakesys/go.mod"] = "module golang.org/x/sys\n\ngo 1.27.1\n"
		files["_fakesys/cpu/cpu.go"] = "// Package cpu est un faux paquet pour depguardcheck.\npackage cpu\n"
		goMod = append(goMod, []byte("\nrequire golang.org/x/sys v0.0.0-00010101000000-000000000000\n\nreplace golang.org/x/sys => ./_fakesys\n")...)
		if err := os.WriteFile(filepath.Join(tmp, "go.mod"), goMod, 0o600); err != nil {
			return err
		}
	}
	// Faux modules des moteurs à retour arrière refusés (importables dans la copie, sans réseau).
	for _, fake := range []struct{ dir, module, pkg string }{
		{"_fakeregexp2", "github.com/dlclark/regexp2", "regexp2"},
		{"_fakepcre", "github.com/gijsbers/go-pcre", "pcre"},
		{"_fakegrbitpcre", "github.com/GRbit/go-pcre", "pcre"},
		{"_fakeglennpcre", "github.com/glenn-brown/golang-pkg-pcre", "pcre"},
		{"_fakearsenmpcre", "go.arsenm.dev/pcre", "pcre"},
	} {
		files[fake.dir+"/go.mod"] = "module " + fake.module + "\n\ngo 1.27.1\n"
		files[fake.dir+"/"+fake.pkg+".go"] = "// Package " + fake.pkg + " est un faux paquet pour depguardcheck.\npackage " + fake.pkg + "\n"
		if !strings.Contains(string(goMod), fake.module+" ") {
			goMod = append(goMod, []byte("\nrequire "+fake.module+" v0.0.0-00010101000000-000000000000\n")...)
		}
		goMod = append(goMod, []byte("\nreplace "+fake.module+" => ./"+fake.dir+"\n")...)
	}
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), goMod, 0o600); err != nil {
		return err
	}
	if err := prepareNested(tmp, goMod); err != nil {
		return err
	}
	for name, content := range files {
		path := filepath.Join(tmp, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// prepareNested rend les mêmes faux modules importables dans la copie du module expurgation : chaque remplacement
// « replace <module> => ./_fake… » ajouté au go.mod racine (rootGoMod) y devient une exigence et un remplacement vers
// « ../_fake… ».
func prepareNested(tmp string, rootGoMod []byte) error {
	path := filepath.Join(tmp, nestedModule, "go.mod")
	goMod, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(rootGoMod), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 4 || fields[0] != "replace" || fields[2] != "=>" || !strings.HasPrefix(fields[3], "./_fake") {
			continue
		}
		fake := fields[1]
		if !strings.Contains(string(goMod), fake+" ") {
			goMod = append(goMod, []byte("\nrequire "+fake+" v0.0.0-00010101000000-000000000000\n")...)
		}
		goMod = append(goMod, []byte("\nreplace "+fake+" => ."+fields[3]+"\n")...)
	}
	return os.WriteFile(path, goMod, 0o600)
}

func lint(dir string) (string, error) {
	binary := os.Getenv("GOLANGCI_LINT")
	if binary == "" {
		binary = "golangci-lint"
	}
	cmd := exec.Command(binary, "run", "--config", filepath.Join(dir, ".golangci.yml"), "./...")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	return output.String(), err
}
