// Commande covercheck : lit un profil de couverture Go (go test -coverprofile) et échoue
// si le moteur de détection est couvert à moins du seuil.
//
// Usage : go run ./tools/covercheck [-min 80] coverage.out
//
// Les paquets mesurés sont detect, pack et internal, sous-paquets compris, chacun séparément.
// Un paquet sans aucune instruction est accepté (vacuité) ; dès qu'il en contient, elles
// figurent au profil, testées ou non, et comptent dans la mesure.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"strconv"
	"strings"
)

const module = "github.com/xsom-consulting/secret-guard"

// DefaultPackages sont les paquets du moteur soumis au seuil.
var DefaultPackages = []string{
	module + "/detect",
	module + "/pack",
	module + "/internal",
}

// DefaultMin est le seuil de couverture des instructions, en pourcentage.
const DefaultMin = 80.0

// Result est la mesure d'un paquet (et de ses sous-paquets).
type Result struct {
	Package string
	Covered int
	Total   int
}

// Percent renvoie le taux de couverture ; un paquet sans instruction vaut 100 %.
func (r Result) Percent() float64 {
	if r.Total == 0 {
		return 100
	}
	return 100 * float64(r.Covered) / float64(r.Total)
}

type block struct {
	statements int
	covered    bool
}

// Check lit le profil et mesure chaque paquet demandé.
func Check(profile io.Reader, packages []string) ([]Result, error) {
	scanner := bufio.NewScanner(profile)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("profil de couverture vide")
	}
	if !strings.HasPrefix(scanner.Text(), "mode: ") {
		return nil, errors.New("profil de couverture invalide : première ligne « mode: » absente")
	}

	// Un même bloc peut apparaître plusieurs fois (plusieurs binaires de test) : on le fusionne.
	blocks := map[string]block{}
	for line := 2; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 3 {
			return nil, fmt.Errorf("profil de couverture invalide, ligne %d", line)
		}
		statements, err1 := strconv.Atoi(fields[1])
		count, err2 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil || statements < 0 || count < 0 || !strings.Contains(fields[0], ".go:") {
			return nil, fmt.Errorf("profil de couverture invalide, ligne %d", line)
		}
		previous := blocks[fields[0]]
		blocks[fields[0]] = block{statements: statements, covered: previous.covered || count > 0}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	results := make([]Result, len(packages))
	for i, pkg := range packages {
		results[i].Package = pkg
	}
	for key, b := range blocks {
		file := key[:strings.LastIndex(key, ".go:")+len(".go")]
		dir := path.Dir(file)
		for i, pkg := range packages {
			if dir == pkg || strings.HasPrefix(dir, pkg+"/") {
				results[i].Total += b.statements
				if b.covered {
					results[i].Covered += b.statements
				}
			}
		}
	}
	return results, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("covercheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	minPercent := flags.Float64("min", DefaultMin, "seuil de couverture des instructions, en pourcentage")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 1 || math.IsNaN(*minPercent) || *minPercent < 0 || *minPercent > 100 {
		_, _ = fmt.Fprintln(stderr, "Usage : covercheck [-min 80] <profil de couverture> (seuil entre 0 et 100)")
		return 2
	}
	file, err := os.Open(flags.Arg(0))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "covercheck : %v\n", err)
		return 1
	}
	defer func() { _ = file.Close() }()

	results, err := Check(file, DefaultPackages)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "covercheck : %v\n", err)
		return 1
	}
	code := 0
	for _, r := range results {
		status := "ok"
		if r.Percent() < *minPercent {
			status = "ÉCHEC"
			code = 1
		}
		_, _ = fmt.Fprintf(stdout, "%s\t%.1f %% (%d/%d instructions, seuil %.0f %%)\t%s\n",
			r.Package, r.Percent(), r.Covered, r.Total, *minPercent, status)
	}
	return code
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
