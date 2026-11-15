// SPDX-License-Identifier: Apache-2.0

// Commande bruit : banc de bruit du moteur de détection. Elle analyse, sans langage (comme un hook qui ne connaît pas
// le fichier), les fichiers de code et de documentation de dépôts donnés en argument, lus dans git à un commit
// épinglé, compte les constats par règle et par forme de valeur, et refuse une hausse face au dernier rapport commité
// (tools/bruit/rapport.json).
//
// Usage (à la racine du dépôt) :
//
//	go run ./tools/bruit [-report <fichier>] [-write] [-list] [-workers <n>] <nom>=<chemin>…
//	go run ./tools/bruit -baseline [-limit <n>] [-language] [-report <fichier>] <nom>[@<commit>]=<chemin>…
//
// Sans -baseline, chaque dépôt nommé est relu au commit, avec la limite et l'option de langage que le rapport a
// retenus, puis comparé à sa mesure du rapport : une hausse du nombre de constats, des constats d'une règle ou des
// analyses incomplètes est refusée (sortie 1, rien n'est écrit). -write réécrit le rapport quand rien ne monte. Un
// dépôt du rapport que la ligne de commande ne donne pas n'est pas mesuré : il est nommé sur la sortie (« non
// mesuré »), pour qu'une passe partielle ne se lise pas comme « aucune hausse » sur tout le rapport.
// -baseline pose une nouvelle base sans comparer : nouveau dépôt, nouveau commit épinglé (HEAD, ou <commit>), ou
// hausse acceptée, à justifier dans le message du commit qui porte le rapport.
//
// Le rapport ne porte que des décomptes : nom donné au dépôt, commit, nombre de fichiers, constats par règle et par
// forme. Jamais un chemin de fichier, une ligne, une valeur ni un extrait de ces dépôts. -list écrit, sur la sortie
// standard seulement, la position de chaque constat (fichier, ligne, colonne, étendue en octets, règle, forme), pour
// qui cherche la cause d'un chiffre : toujours sans la valeur.
//
// Codes de sortie : 0 mesure faite, aucune hausse ; 1 hausse refusée ; 2 erreur (usage, git, rapport illisible, dépôt
// absent du rapport, mesure non comparable).
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xsom-consulting/secret-guard/detect"
	"github.com/xsom-consulting/secret-guard/pack"
)

const (
	exitOK      = 0
	exitRise    = 1
	exitError   = 2
	formatV1    = 1
	defaultPath = "tools/bruit/rapport.json"
	// commitPrefix précède l'identifiant d'un commit dans le rapport (Repository.Commit).
	commitPrefix = "g"
	// maxFileBytes : taille la plus grande d'un fichier analysé (limite d'entrée du moteur, 1 Mio).
	maxFileBytes = 1 << 20
	about        = "Banc de bruit du moteur de détection (tools/bruit) : constats du moteur sur des dépôts de code " +
		"ordinaires, lus à un commit épinglé, sans langage. Décomptes seulement : aucun chemin, aucune ligne, " +
		"aucune valeur de ces dépôts. Une hausse face à ce rapport est refusée."
)

// Report est le rapport commité : une mesure par dépôt, triée par nom.
type Report struct {
	FormatVersion int          `json:"formatVersion"`
	About         string       `json:"about"`
	Repositories  []Repository `json:"repositories"`
}

// Repository est la mesure d'un dépôt à un commit : décomptes seulement.
type Repository struct {
	// Name est le nom donné au dépôt sur la ligne de commande, jamais son chemin.
	Name string `json:"name"`
	// Commit est le commit épinglé, écrit « g » puis ses 40 chiffres hexadécimaux, comme le suffixe de « git
	// describe » : un identifiant nu de 40 chiffres hexadécimaux est pris pour un jeton par les détecteurs de secrets
	// (gitleaks, règle sourcegraph-access-token, dès que le fichier nomme ce fournisseur).
	Commit string `json:"commit"`
	// Date est le jour de la mesure (AAAA-MM-JJ, UTC).
	Date        string `json:"date"`
	PackVersion int64  `json:"packVersion"`
	Rules       int    `json:"rules"`
	// Language : vrai si chaque fichier a été analysé avec le langage de son extension.
	Language bool `json:"language"`
	// Limit : nombre de fichiers gardés par le tirage déterministe (0 : tous).
	Limit int `json:"limit"`
	// Files : fichiers analysés ; Incomplete : analyses incomplètes (un blocage pour l'appelant).
	Files      int `json:"files"`
	Incomplete int `json:"incomplete"`
	Findings   int `json:"findings"`
	// ByRule : constats par règle, triés par nom de règle.
	ByRule Counts `json:"byRule"`
	// AssignmentShapes et EntropyShapes : constats d'affectation (règles « contextual_… ») et d'entropie
	// (high_entropy) par forme de valeur, triés par forme.
	AssignmentShapes Counts `json:"assignmentShapes"`
	EntropyShapes    Counts `json:"entropyShapes"`
}

// Count est un décompte nommé. Le rapport écrit « {"name": …, "count": …} » plutôt qu'un objet « nom: nombre » : un
// nom de règle ou de forme porte souvent un mot sensible, et une affectation de ce nom à un nombre serait elle-même
// un constat pour qui analyse ce dépôt.
type Count struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Counts est une liste de décomptes triée par nom, sans doublon.
type Counts []Count

// Of rend le décompte de name (0 : absent).
func (c Counts) Of(name string) int {
	for _, count := range c {
		if count.Name == name {
			return count.Count
		}
	}
	return 0
}

// Total rend la somme des décomptes.
func (c Counts) Total() int {
	sum := 0
	for _, count := range c {
		sum += count.Count
	}
	return sum
}

// countsOf rend les décomptes d'une table, triés par nom ; jamais nil (tableau vide en JSON).
func countsOf(table map[string]int) Counts {
	counts := make(Counts, 0, len(table))
	for name, n := range table {
		counts = append(counts, Count{Name: name, Count: n})
	}
	sort.Slice(counts, func(i, j int) bool { return counts[i].Name < counts[j].Name })
	return counts
}

// today rend le jour de la mesure (couture de test).
var today = func() string { return time.Now().UTC().Format("2006-01-02") }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type target struct {
	name, commit, dir string
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("bruit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	reportPath := flags.String("report", defaultPath, "rapport commité")
	write := flags.Bool("write", false, "réécrit le rapport quand rien ne monte")
	baseline := flags.Bool("baseline", false, "pose une nouvelle base sans comparer")
	limit := flags.Int("limit", 0, "avec -baseline : nombre de fichiers gardés par dépôt (0 : tous)")
	language := flags.Bool("language", false, "avec -baseline : analyse chaque fichier avec le langage de son extension")
	list := flags.Bool("list", false, "écrit la position de chaque constat, sans la valeur")
	workers := flags.Int("workers", 3, "analyses en parallèle")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	fail := func(format string, a ...any) int {
		_, _ = fmt.Fprintf(stderr, "bruit : "+format+"\n", a...)
		return exitError
	}
	if flags.NArg() == 0 {
		return fail("aucun dépôt donné (<nom>=<chemin>)")
	}
	if !*baseline && (*limit != 0 || *language) {
		return fail("-limit et -language ne valent qu'avec -baseline : sans elle, le rapport les fixe")
	}
	if *limit < 0 || *workers < 1 {
		return fail("-limit et -workers : entiers positifs")
	}
	targets, err := parseTargets(flags.Args(), *baseline)
	if err != nil {
		return fail("%v", err)
	}
	report, err := readReport(*reportPath)
	if err != nil {
		return fail("rapport : %v", err)
	}
	initial, err := pack.Initial()
	if err != nil {
		return fail("%v", err)
	}
	rules, err := detect.LoadRules(initial)
	if err != nil {
		return fail("%v", err)
	}
	var listing io.Writer
	if *list {
		listing = stdout
	}
	rises := 0
	for _, t := range targets {
		previous, known := report.find(t.name)
		spec := measureSpec{name: t.name, dir: t.dir, rev: t.commit, limit: *limit, language: *language, workers: *workers}
		switch {
		case *baseline:
			if spec.rev == "" {
				spec.rev = "HEAD"
			}
		case !known:
			return fail("%s : absent du rapport ; première mesure avec -baseline", t.name)
		default:
			spec.rev, spec.limit, spec.language = strings.TrimPrefix(previous.Commit, commitPrefix), previous.Limit, previous.Language
		}
		measured, err := measure(spec, rules, listing)
		if err != nil {
			return fail("%s : %v", t.name, err)
		}
		measured.PackVersion, measured.Rules = initial.PackVersion, len(initial.Rules)
		printMeasure(stdout, measured)
		if !*baseline {
			if measured.Files != previous.Files {
				return fail("%s : %d fichiers analysés, %d au rapport : mesure non comparable (règles de sélection changées ?), nouvelle base avec -baseline",
					t.name, measured.Files, previous.Files)
			}
			problems := compare(previous, measured)
			for _, problem := range problems {
				_, _ = fmt.Fprintf(stdout, "  HAUSSE %s\n", problem)
			}
			rises += len(problems)
			printDrop(stdout, previous, measured)
		}
		report.set(measured)
	}
	if skipped := report.unmeasured(targets); len(skipped) > 0 {
		_, _ = fmt.Fprintf(stdout, "non mesuré : %s (au rapport, absent de la ligne de commande : aucune hausse n'y est cherchée)\n",
			strings.Join(skipped, ", "))
	}
	if rises > 0 {
		_, _ = fmt.Fprintf(stderr, "bruit : %d hausse(s) face au rapport %s : refusé, rapport inchangé\n", rises, *reportPath)
		return exitRise
	}
	if *write || *baseline {
		if err := writeReport(*reportPath, report); err != nil {
			return fail("rapport : %v", err)
		}
		_, _ = fmt.Fprintf(stdout, "rapport écrit : %s\n", *reportPath)
	}
	return exitOK
}

// parseTargets lit les arguments « nom=chemin » ; « nom@commit=chemin » n'est admis qu'avec une nouvelle base.
func parseTargets(args []string, baseline bool) ([]target, error) {
	var targets []target
	seen := map[string]bool{}
	for _, arg := range args {
		head, dir, ok := strings.Cut(arg, "=")
		if !ok || head == "" || dir == "" {
			return nil, fmt.Errorf("argument %q : <nom>=<chemin> attendu", arg)
		}
		name, commit, pinned := strings.Cut(head, "@")
		if pinned && !baseline {
			return nil, fmt.Errorf("%s : un commit ne se donne qu'avec -baseline (sans elle, le rapport l'épingle)", name)
		}
		if name == "" || strings.ContainsAny(name, "/\\ ") || (pinned && commit == "") {
			return nil, fmt.Errorf("argument %q : nom de dépôt sans barre ni espace, commit non vide", arg)
		}
		if seen[name] {
			return nil, fmt.Errorf("%s : dépôt donné deux fois", name)
		}
		seen[name] = true
		targets = append(targets, target{name: name, commit: commit, dir: dir})
	}
	return targets, nil
}

func (r *Report) find(name string) (Repository, bool) {
	for _, repository := range r.Repositories {
		if repository.Name == name {
			return repository, true
		}
	}
	return Repository{}, false
}

func (r *Report) set(measured Repository) {
	for i := range r.Repositories {
		if r.Repositories[i].Name == measured.Name {
			r.Repositories[i] = measured
			return
		}
	}
	r.Repositories = append(r.Repositories, measured)
	sort.Slice(r.Repositories, func(i, j int) bool { return r.Repositories[i].Name < r.Repositories[j].Name })
}

// unmeasured rend les noms des dépôts du rapport que targets ne donne pas, dans l'ordre du rapport.
func (r *Report) unmeasured(targets []target) []string {
	given := map[string]bool{}
	for _, t := range targets {
		given[t.name] = true
	}
	var names []string
	for _, repository := range r.Repositories {
		if !given[repository.Name] {
			names = append(names, repository.Name)
		}
	}
	return names
}

// readReport lit le rapport ; un fichier absent est un rapport vide (première base).
func readReport(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &Report{FormatVersion: formatV1, About: about}, nil
	}
	if err != nil {
		return nil, err
	}
	var report Report
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return nil, err
	}
	if report.FormatVersion != formatV1 {
		return nil, fmt.Errorf("version de format %d, attendu %d", report.FormatVersion, formatV1)
	}
	return &report, nil
}

func writeReport(path string, report *Report) error {
	report.FormatVersion, report.About = formatV1, about
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// compare rend les hausses de measured face à previous : constats, constats d'une règle, analyses incomplètes.
func compare(previous, measured Repository) []string {
	var problems []string
	if measured.Findings > previous.Findings {
		problems = append(problems, fmt.Sprintf("%s : %d constats, %d au rapport", measured.Name, measured.Findings, previous.Findings))
	}
	if measured.Incomplete > previous.Incomplete {
		problems = append(problems, fmt.Sprintf("%s : %d analyses incomplètes, %d au rapport", measured.Name, measured.Incomplete, previous.Incomplete))
	}
	for _, rule := range measured.ByRule {
		if before := previous.ByRule.Of(rule.Name); rule.Count > before {
			problems = append(problems, fmt.Sprintf("%s : règle %s, %d constats, %d au rapport", measured.Name, rule.Name, rule.Count, before))
		}
	}
	return problems
}

func printMeasure(w io.Writer, m Repository) {
	short := strings.TrimPrefix(m.Commit, commitPrefix)
	if len(short) > 12 {
		short = short[:12]
	}
	_, _ = fmt.Fprintf(w, "%s (%s) : %d fichiers, %d constats, %d analyses incomplètes ; affectations %d, entropie %d\n",
		m.Name, short, m.Files, m.Findings, m.Incomplete, m.AssignmentShapes.Total(), m.EntropyShapes.Total())
}

func printDrop(w io.Writer, previous, measured Repository) {
	if measured.Findings < previous.Findings || measured.Incomplete < previous.Incomplete {
		_, _ = fmt.Fprintf(w, "  baisse : %d constats (rapport : %d), %d analyses incomplètes (rapport : %d)\n",
			measured.Findings, previous.Findings, measured.Incomplete, previous.Incomplete)
	}
}

type measureSpec struct {
	name, dir, rev string
	limit          int
	language       bool
	workers        int
}

// located est un constat et sa position : jamais la valeur.
type located struct {
	rule, kind, shape  string
	line, column       int
	byteStart, byteEnd int
}

type fileResult struct {
	incomplete bool
	findings   []located
}

// measure analyse les fichiers retenus du dépôt au commit rev et rend ses décomptes. Avec listing, la position de
// chaque constat y est écrite, dans l'ordre des chemins.
func measure(spec measureSpec, rules *detect.Rules, listing io.Writer) (Repository, error) {
	commit, err := resolveCommit(spec.dir, spec.rev)
	if err != nil {
		return Repository{}, err
	}
	blobs, err := listBlobs(spec.dir, commit)
	if err != nil {
		return Repository{}, err
	}
	blobs = selectBlobs(blobs, spec.limit)
	results := make([]fileResult, len(blobs))
	type job struct {
		index   int
		content []byte
	}
	jobs := make(chan job, spec.workers)
	var wg sync.WaitGroup
	for range spec.workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				language := ""
				if spec.language {
					language = languageOf(blobs[j.index].path)
				}
				results[j.index] = scanFile(j.content, rules, language)
			}
		}()
	}
	readErr := readBlobs(spec.dir, blobs, func(index int, content []byte) {
		jobs <- job{index: index, content: content}
	})
	close(jobs)
	wg.Wait()
	if readErr != nil {
		return Repository{}, readErr
	}
	measured := Repository{
		Name: spec.name, Commit: commitPrefix + commit, Date: today(), Language: spec.language, Limit: spec.limit, Files: len(blobs),
	}
	byRule := map[string]int{}
	shapes := map[string]map[string]int{shapeKindAssignment: {}, shapeKindEntropy: {}}
	for i, result := range results {
		if result.incomplete {
			measured.Incomplete++
		}
		for _, f := range result.findings {
			measured.Findings++
			byRule[f.rule]++
			if f.kind != "" {
				shapes[f.kind][f.shape]++
			}
			if listing != nil {
				_, _ = fmt.Fprintf(listing, "%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\n", spec.name, blobs[i].path, f.line, f.column,
					f.byteStart, f.byteEnd, f.rule, f.shape)
			}
		}
		if listing != nil && result.incomplete {
			_, _ = fmt.Fprintf(listing, "%s\t%s\t0\t0\t0\t0\t(analyse incomplète)\t\n", spec.name, blobs[i].path)
		}
	}
	measured.ByRule = countsOf(byRule)
	measured.AssignmentShapes, measured.EntropyShapes = countsOf(shapes[shapeKindAssignment]), countsOf(shapes[shapeKindEntropy])
	return measured, nil
}

// scanFile analyse un fichier et classe chaque constat par forme ; le contenu ne sort pas de cette fonction.
func scanFile(content []byte, rules *detect.Rules, language string) fileResult {
	result := detect.Scan(content, rules, detect.Options{LanguageID: language, Workers: 1})
	if !result.Complete {
		return fileResult{incomplete: true}
	}
	out := fileResult{findings: make([]located, 0, len(result.Findings))}
	for _, f := range result.Findings {
		kind, shape := shapeOf(content, f)
		line, column := position(content, f.ByteStart)
		out.findings = append(out.findings, located{
			rule: f.RuleID, kind: kind, shape: shape, line: line, column: column, byteStart: f.ByteStart, byteEnd: f.ByteEnd,
		})
	}
	return out
}

// position rend la ligne et la colonne (en points de code, à partir de 1) de l'octet offset.
func position(content []byte, offset int) (int, int) {
	offset = min(max(offset, 0), len(content))
	line := 1 + bytes.Count(content[:offset], []byte("\n"))
	start := bytes.LastIndexByte(content[:offset], '\n') + 1
	return line, 1 + len(bytes.Runes(content[start:offset]))
}
