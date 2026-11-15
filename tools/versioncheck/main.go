// SPDX-License-Identifier: Apache-2.0

// Commande versioncheck : essai de cohérence d'une version, à lancer avant de poser l'étiquette. Elle compare à la
// version visée et au Pack initial (pack/initial/pack.json) ce que le commit de version doit avoir mis à jour :
//
//   - wasm/package.json : champ version (.github/workflows/release.yml refuse une étiquette qui en diffère) ;
//   - expurgation/go.mod : version exigée du module racine (même refus) ;
//   - README.md : nombre de règles du Pack initial, en français (« - N règles (Pack initial ») et en anglais
//     (« **What it does**: N rules (initial Pack ») ;
//   - docs/rule-pack.md : « (N dans le Pack initial de la vX.Y.Z) ».
//
// Usage (à la racine du dépôt) : go run ./tools/versioncheck [-root <dossier>] [vX.Y.Z]
//
// Sans version, la version visée est celle de wasm/package.json : l'essai ne dit alors que si les fichiers sont
// cohérents entre eux et avec le Pack. Avant une étiquette, donner la version.
//
// Chaque écart est nommé, avec la valeur attendue et la valeur trouvée. Un décompte introuvable est un écart : un
// texte reformulé ne désarme pas l'essai. Codes de sortie : 0 tout concorde ; 1 au moins un écart ; 2 erreur (usage,
// version mal formée, fichier illisible).
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

const (
	exitOK       = 0
	exitMismatch = 1
	exitError    = 2
	rootModule   = "github.com/xsom-consulting/secret-guard"
)

// Fichiers lus, relatifs à la racine du dépôt.
const (
	packFile       = "pack/initial/pack.json"
	wasmFile       = "wasm/package.json"
	expurgationMod = "expurgation/go.mod"
	readmeFile     = "README.md"
	rulePackFile   = "docs/rule-pack.md"
)

var (
	versionForm = regexp.MustCompile(`^v?(\d+\.\d+\.\d+)$`)
	// requireForm : exigence du module racine dans un go.mod, sur une ligne « require » ou dans un bloc.
	requireForm = regexp.MustCompile(`(?m)^(?:require\s+)?\s*` + regexp.QuoteMeta(rootModule) + `\s+v(\S+)`)
	// Décomptes écrits dans la documentation.
	readmeFrench  = regexp.MustCompile(`(?m)^- (\d+) règles \(Pack initial`)
	readmeEnglish = regexp.MustCompile(`\*\*What it does\*\*: (\d+) rules \(initial Pack`)
	rulePackCount = regexp.MustCompile(`\((\d+) dans le Pack initial de la v(\d+\.\d+\.\d+)\)`)
)

// Problem est un écart : fichier, ce qui est comparé, valeur attendue, valeur trouvée (vide : introuvable).
type Problem struct {
	File     string
	What     string
	Expected string
	Found    string
}

func (p Problem) String() string {
	if p.Found == "" {
		return fmt.Sprintf("%s : %s introuvable, attendu %s", p.File, p.What, p.Expected)
	}
	return fmt.Sprintf("%s : %s %s, attendu %s", p.File, p.What, p.Found, p.Expected)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("versioncheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "racine du dépôt")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	if flags.NArg() > 1 {
		_, _ = fmt.Fprintln(stderr, "versioncheck : une seule version (vX.Y.Z)")
		return exitError
	}
	target := ""
	if flags.NArg() == 1 {
		m := versionForm.FindStringSubmatch(flags.Arg(0))
		if m == nil {
			_, _ = fmt.Fprintf(stderr, "versioncheck : version %q mal formée, vX.Y.Z attendu\n", flags.Arg(0))
			return exitError
		}
		target = m[1]
	}
	result, err := Check(*root, target)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "versioncheck : %v\n", err)
		return exitError
	}
	origin := "donnée en argument"
	if target == "" {
		origin = "lue dans " + wasmFile + " : donner la version visée avant une étiquette"
	}
	_, _ = fmt.Fprintf(stdout, "version visée : v%s (%s) ; Pack initial : %d règles\n", result.Version, origin, result.Rules)
	for _, problem := range result.Problems {
		_, _ = fmt.Fprintf(stdout, "ÉCART %s\n", problem)
	}
	if len(result.Problems) > 0 {
		_, _ = fmt.Fprintf(stderr, "versioncheck : %d écart(s) : la version v%s n'est pas prête\n", len(result.Problems), result.Version)
		return exitMismatch
	}
	_, _ = fmt.Fprintf(stdout, "%d points concordent\n", result.Checked)
	return exitOK
}

// Result est l'issue d'un contrôle : version visée, nombre de règles du Pack initial, points comparés, écarts.
type Result struct {
	Version  string
	Rules    int
	Checked  int
	Problems []Problem
}

// Check compare les fichiers de root à la version visée target (« X.Y.Z » ; vide : celle de wasm/package.json) et au
// nombre de règles du Pack initial.
func Check(root, target string) (Result, error) {
	read := func(rel string) (string, error) {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return "", fmt.Errorf("%s : lecture impossible", rel)
		}
		return string(data), nil
	}
	packText, err := read(packFile)
	if err != nil {
		return Result{}, err
	}
	var initial struct {
		Rules []json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal([]byte(packText), &initial); err != nil || len(initial.Rules) == 0 {
		return Result{}, errors.New(packFile + " : document JSON sans règles")
	}
	wasmText, err := read(wasmFile)
	if err != nil {
		return Result{}, err
	}
	var manifest struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(wasmText), &manifest); err != nil {
		return Result{}, errors.New(wasmFile + " : document JSON illisible")
	}
	modText, err := read(expurgationMod)
	if err != nil {
		return Result{}, err
	}
	readme, err := read(readmeFile)
	if err != nil {
		return Result{}, err
	}
	rulePack, err := read(rulePackFile)
	if err != nil {
		return Result{}, err
	}

	result := Result{Version: target, Rules: len(initial.Rules)}
	if result.Version == "" {
		if !versionForm.MatchString(manifest.Version) {
			return Result{}, errors.New(wasmFile + " : champ version absent ou mal formé, donner la version visée")
		}
		result.Version = manifest.Version
	}
	rules := strconv.Itoa(result.Rules)
	compare := func(file, what, expected, found string) {
		result.Checked++
		if found != expected {
			result.Problems = append(result.Problems, Problem{File: file, What: what, Expected: expected, Found: found})
		}
	}
	// single rend le groupe n de l'unique correspondance de form ; vide si elle est absente ou multiple.
	single := func(form *regexp.Regexp, text string, n int) string {
		matches := form.FindAllStringSubmatch(text, -1)
		if len(matches) != 1 {
			return ""
		}
		return matches[0][n]
	}

	compare(wasmFile, "version", result.Version, manifest.Version)
	compare(expurgationMod, "version exigée de "+rootModule, "v"+result.Version, prefixed("v", single(requireForm, modText, 1)))
	compare(readmeFile, "nombre de règles (« - N règles (Pack initial »)", rules, single(readmeFrench, readme, 1))
	compare(readmeFile, "nombre de règles (« **What it does**: N rules (initial Pack »)", rules, single(readmeEnglish, readme, 1))
	compare(rulePackFile, "nombre de règles (« (N dans le Pack initial de la vX.Y.Z) »)", rules, single(rulePackCount, rulePack, 1))
	compare(rulePackFile, "version du décompte (« (N dans le Pack initial de la vX.Y.Z) »)", "v"+result.Version,
		prefixed("v", single(rulePackCount, rulePack, 2)))
	return result, nil
}

// prefixed rend prefix suivi de value ; une valeur vide (introuvable) reste vide.
func prefixed(prefix, value string) string {
	if value == "" {
		return ""
	}
	return prefix + value
}
