// SPDX-License-Identifier: Apache-2.0

// Commande spdxcheck : vérifie que chaque fichier source du dépôt (.go, .mjs, .mts, .ts) porte, dans ses premières
// lignes, l'identifiant SPDX de la licence de son module :
//
//   - Apache-2.0 partout (moteur, Pack, ligne de commande, chargeurs du module WebAssembly, générateur) ;
//   - PolyForm-Small-Business-1.0.0 sous expurgation/ (module github.com/xsom-consulting/secret-guard/expurgation :
//     expurgation, module WebAssembly qui l'embarque, outil de parité).
//
// Usage (à la racine du dépôt) : go run ./tools/spdxcheck
//
// Chaque fichier en écart est nommé, avec l'identifiant attendu ; sortie 1 s'il y en a un. Les dossiers de
// dépendances, de construction et d'outillage local (node_modules, dist, .git, _bmad, .claude, .agents) ne sont pas
// lus.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// Apache est l'identifiant du module racine.
	Apache = "Apache-2.0"
	// PolyForm est l'identifiant du module expurgation.
	PolyForm = "PolyForm-Small-Business-1.0.0"
	// headerLines : nombre de lignes lues en tête de fichier (une ligne #! comprise).
	headerLines = 3
	marker      = "SPDX-License-Identifier:"
)

// skippedDirs ne sont pas parcourus, à toute profondeur.
var skippedDirs = map[string]bool{
	".git": true, "node_modules": true, "dist": true, "_bmad": true, ".claude": true, ".agents": true,
}

// sourceExtensions sont les fichiers vérifiés.
var sourceExtensions = []string{".go", ".mjs", ".mts", ".ts"}

// Problem est un fichier en écart : chemin relatif à la racine (barres obliques), identifiant attendu et trouvé
// (vide : aucun).
type Problem struct {
	Path     string
	Expected string
	Found    string
}

func (p Problem) String() string {
	if p.Found == "" {
		return fmt.Sprintf("%s : aucun identifiant SPDX, attendu %s", p.Path, p.Expected)
	}
	return fmt.Sprintf("%s : identifiant SPDX %s, attendu %s", p.Path, p.Found, p.Expected)
}

// ExpectedLicense rend l'identifiant attendu d'un chemin relatif à la racine (barres obliques).
func ExpectedLicense(rel string) string {
	if rel == "expurgation" || strings.HasPrefix(rel, "expurgation/") {
		return PolyForm
	}
	return Apache
}

// Check parcourt root et rend les fichiers en écart, triés par chemin, et le nombre de fichiers vérifiés.
func Check(root string) ([]Problem, int, error) {
	var problems []Problem
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !isSource(d.Name()) {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		found, err := licenseOf(path)
		if err != nil {
			return fmt.Errorf("%s : %w", rel, err)
		}
		checked++
		if expected := ExpectedLicense(rel); found != expected {
			problems = append(problems, Problem{Path: rel, Expected: expected, Found: found})
		}
		return nil
	})
	sort.Slice(problems, func(i, j int) bool { return problems[i].Path < problems[j].Path })
	return problems, checked, err
}

func isSource(name string) bool {
	for _, ext := range sourceExtensions {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// licenseOf lit l'identifiant SPDX d'une ligne « // SPDX-License-Identifier: <id> » des premières lignes du fichier
// (après une ligne #! éventuelle) ; vide s'il n'y en a pas.
func licenseOf(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	for line := 0; line < headerLines && scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if rest, ok := strings.CutPrefix(text, "// "+marker); ok {
			return strings.TrimSpace(rest), nil
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, bufio.ErrTooLong) {
		return "", err
	}
	return "", nil
}

// moduleRoot remonte depuis le dossier courant jusqu'au go.mod du module racine.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil && declaresRootModule(string(data)) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("module github.com/xsom-consulting/secret-guard introuvable : lancer depuis le dépôt")
		}
		dir = parent
	}
}

// declaresRootModule dit si go.mod déclare le module racine (et non le module expurgation ; fins de ligne CRLF et
// espaces tolérés).
func declaresRootModule(goMod string) bool {
	for _, line := range strings.Split(goMod, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "module" && fields[1] == "github.com/xsom-consulting/secret-guard" {
			return true
		}
	}
	return false
}

func run(stdout, stderr io.Writer) int {
	root, err := moduleRoot()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "spdxcheck : %v\n", err)
		return 1
	}
	problems, checked, err := Check(root)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "spdxcheck : %v\n", err)
		return 1
	}
	for _, p := range problems {
		_, _ = fmt.Fprintln(stderr, p)
	}
	if len(problems) > 0 {
		_, _ = fmt.Fprintf(stderr, "spdxcheck : %d fichier(s) en écart sur %d\n", len(problems), checked)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "spdxcheck : %d fichiers, chacun avec l'identifiant SPDX de son module\n", checked)
	return 0
}

func main() {
	os.Exit(run(os.Stdout, os.Stderr))
}
