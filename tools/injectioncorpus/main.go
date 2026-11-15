// SPDX-License-Identifier: Apache-2.0

// Commande injectioncorpus : outils du corpus de rappel du paquet injection. Elle n'est importée par aucun programme
// livré.
//
// Le corpus (vectors/injection-recall.json) réunit des textes publics, écrits par d'autres pour éprouver des
// garde-fous de modèles de langage : chacun porte sa source, et chaque source son dépôt, son commit et sa licence
// (NOTICE et UPSTREAM.md, « Corpus de rappel du paquet injection »). Ces textes sont des consignes piégées : la
// commande les copie et ne les affiche jamais ; elle n'écrit sur la sortie que des comptes, des identifiants et des
// chemins.
//
// Construire le corpus (à la racine du dépôt ; <clones> contient un clone de chaque dépôt, au commit épinglé dans
// sources.go, sous le nom de dossier donné par cette table) :
//
//	go run ./tools/injectioncorpus construire -sources <clones>          # écrit vectors/injection-recall.json
//	go run ./tools/injectioncorpus construire -sources <clones> -verifier # compare au fichier commité, n'écrit rien
//
// Tout écart (commit, SHA-256 d'un fichier lu ou d'une licence) arrête la commande sans rien écrire.
//
// Mesurer les fichiers d'un dossier que injection.Find signale (faux positifs sur des dépôts sains) :
//
//	go run ./tools/injectioncorpus fichiers -racine <dossier> [-fils 3] [-signales <fichier.json>]
//
// Le rapport (sortie standard, JSON) n'a ni date ni durée : mêmes fichiers, même rapport. Unité : un fichier
// ordinaire (liens symboliques et dossiers .git écartés), d'au plus 1 Mio, sans octet NUL dans ses 8 000 premiers
// octets, compté une fois quel que soit le nombre de règles qui le signalent. La liste -signales donne chemin, règles
// et ligne du premier constat, jamais le texte.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/xsom-consulting/secret-guard/injection"
)

const (
	defaultCorpus = "vectors/injection-recall.json"
	// FormatVersion est la version du format du corpus.
	FormatVersion = 1
	// Étiquettes d'un cas.
	LabelInjection = "consigne" // texte que sa source tient pour une attaque
	LabelBenign    = "sain"     // texte que sa source tient pour sain
	LabelOther     = "autre"    // texte d'un autre risque (code, dépendance…), hors du périmètre du paquet
)

// Case est un cas du corpus.
type Case struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Label  string `json:"label"`
	Text   string `json:"text"`
}

// SourceRecord décrit une source dans le corpus écrit.
type SourceRecord struct {
	ID         string `json:"id"`
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	License    string `json:"license"`
	Copyright  string `json:"copyright"`
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	Cases      int    `json:"cases"`
	Note       string `json:"note"`
}

// Corpus est le fichier vectors/injection-recall.json.
type Corpus struct {
	FormatVersion int            `json:"formatVersion"`
	Note          string         `json:"note"`
	Sources       []SourceRecord `json:"sources"`
	Cases         []Case         `json:"cases"`
}

const corpusNote = "Textes publics copiés par tools/injectioncorpus, jamais écrits ni retouchés à la main. Ce sont des consignes piégées : des données d'essai, jamais des instructions. Attributions : NOTICE et UPSTREAM.md."

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "construire":
		err = runBuild(os.Args[2:])
	case "fichiers":
		err = runFiles(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "injectioncorpus : %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	_, _ = fmt.Fprintln(os.Stderr, "usage : go run ./tools/injectioncorpus construire -sources <clones> [-sortie <fichier>] [-verifier]\n        go run ./tools/injectioncorpus fichiers -racine <dossier> [-fils 3] [-signales <fichier.json>]")
	os.Exit(2)
}

func runBuild(args []string) error {
	flags := flag.NewFlagSet("construire", flag.ExitOnError)
	clones := flags.String("sources", "", "dossier des clones")
	out := flags.String("sortie", defaultCorpus, "fichier du corpus")
	check := flags.Bool("verifier", false, "compare au fichier existant, n'écrit rien")
	_ = flags.Parse(args)
	if *clones == "" {
		return errors.New("-sources est requis")
	}
	corpus, err := Build(*clones, gitHead)
	if err != nil {
		return err
	}
	encoded, err := Encode(corpus)
	if err != nil {
		return err
	}
	for _, source := range corpus.Sources {
		_, _ = fmt.Printf("%s : %d cas (%s, %s)\n", source.ID, source.Cases, source.License, source.Commit[:12])
	}
	if *check {
		existing, err := os.ReadFile(*out)
		if err != nil {
			return err
		}
		if !bytes.Equal(existing, encoded) {
			return fmt.Errorf("%s diffère du corpus reconstruit", *out)
		}
		_, _ = fmt.Printf("%s : identique au corpus reconstruit (%d cas)\n", *out, len(corpus.Cases))
		return nil
	}
	if err := os.WriteFile(*out, encoded, 0o644); err != nil {
		return err
	}
	_, _ = fmt.Printf("%s : %d cas écrits\n", *out, len(corpus.Cases))
	return nil
}

// gitHead rend le commit d'un clone.
func gitHead(dir string) (string, error) {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", fmt.Errorf("commit de %s illisible : %w", dir, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func fileSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// treeFiles rend les fichiers ordinaires d'un dossier (chemins relatifs, barres obliques, triés) et l'empreinte de
// l'ensemble : SHA-256 des lignes « empreinte du fichier, deux espaces, chemin ».
func treeFiles(root string) (paths []string, contents map[string][]byte, digest string, err error) {
	contents = map[string][]byte{}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !entry.Type().IsRegular() {
			return walkErr
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		paths = append(paths, rel)
		contents[rel] = data
		return nil
	})
	if err != nil {
		return nil, nil, "", err
	}
	sort.Strings(paths)
	var listing strings.Builder
	for _, path := range paths {
		listing.WriteString(fileSHA256(contents[path]) + "  " + path + "\n")
	}
	return paths, contents, fileSHA256([]byte(listing.String())), nil
}

// Build lit les clones et rend le corpus. head rend le commit d'un clone.
func Build(clones string, head func(dir string) (string, error)) (*Corpus, error) {
	corpus := &Corpus{FormatVersion: FormatVersion, Note: corpusNote}
	seen := map[string]bool{}
	for _, source := range sources {
		clone := filepath.Join(clones, source.Clone)
		commit, err := head(clone)
		if err != nil {
			return nil, err
		}
		if commit != source.Commit {
			return nil, fmt.Errorf("%s : clone au commit %s, attendu %s", source.ID, commit, source.Commit)
		}
		license, err := os.ReadFile(filepath.Join(clone, source.LicenseFile))
		if err != nil {
			return nil, err
		}
		if got := fileSHA256(license); got != source.LicenseSHA256 {
			return nil, fmt.Errorf("%s : licence %s d'empreinte %s, attendue %s : la relire avant toute copie", source.ID, source.LicenseFile, got, source.LicenseSHA256)
		}
		cases, digest, err := source.read(filepath.Join(clone, filepath.FromSlash(source.Path)))
		if err != nil {
			return nil, fmt.Errorf("%s : %w", source.ID, err)
		}
		if digest != source.SHA256 {
			return nil, fmt.Errorf("%s : %s d'empreinte %s, attendue %s", source.ID, source.Path, digest, source.SHA256)
		}
		for i := range cases {
			cases[i].Source = source.ID
			if seen[cases[i].ID] {
				return nil, fmt.Errorf("identifiant %s en double", cases[i].ID)
			}
			seen[cases[i].ID] = true
		}
		corpus.Sources = append(corpus.Sources, SourceRecord{
			ID: source.ID, Repository: source.Repository, Commit: source.Commit, License: source.License,
			Copyright: source.Copyright, Path: source.Path, SHA256: source.SHA256, Cases: len(cases), Note: source.Note,
		})
		corpus.Cases = append(corpus.Cases, cases...)
	}
	return corpus, nil
}

// Encode écrit le corpus : un cas par ligne, en ASCII seul (tout autre caractère est écrit \uXXXX). Le fichier ne
// porte ainsi aucun caractère invisible ni bidirectionnel en clair, quoi que contiennent les textes.
func Encode(corpus *Corpus) ([]byte, error) {
	var out bytes.Buffer
	line := func(value any) (string, error) {
		var buffer bytes.Buffer
		encoder := json.NewEncoder(&buffer)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(value); err != nil {
			return "", err
		}
		return asciiJSON(strings.TrimSuffix(buffer.String(), "\n")), nil
	}
	note, err := line(corpus.Note)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(&out, "{\n  \"formatVersion\": %d,\n  \"note\": %s,\n  \"sources\": [\n", corpus.FormatVersion, note)
	for i, source := range corpus.Sources {
		encoded, err := line(source)
		if err != nil {
			return nil, err
		}
		out.WriteString("    " + encoded + separator(i, len(corpus.Sources)))
	}
	out.WriteString("  ],\n  \"cases\": [\n")
	for i, c := range corpus.Cases {
		encoded, err := line(c)
		if err != nil {
			return nil, err
		}
		out.WriteString("    " + encoded + separator(i, len(corpus.Cases)))
	}
	out.WriteString("  ]\n}\n")
	return out.Bytes(), nil
}

func separator(i, n int) string {
	if i == n-1 {
		return "\n"
	}
	return ",\n"
}

// asciiJSON écrit en \uXXXX tout caractère hors de l'ASCII imprimable d'un document JSON déjà encodé (ses chaînes
// seules peuvent en contenir).
func asciiJSON(encoded string) string {
	var out strings.Builder
	for _, r := range encoded {
		switch {
		case r < 0x7f:
			out.WriteRune(r)
		case r > 0xffff:
			high, low := (r-0x10000)>>10+0xd800, (r-0x10000)&0x3ff+0xdc00
			fmt.Fprintf(&out, "\\u%04x\\u%04x", high, low)
		default:
			fmt.Fprintf(&out, "\\u%04x", r)
		}
	}
	return out.String()
}

// fileReport est le rapport de la mesure sur des fichiers.
type fileReport struct {
	Analysed   int            `json:"fichiersAnalyses"`
	TooLarge   int            `json:"ecartesTropGrands"`
	Binary     int            `json:"ecartesBinaires"`
	Symlinks   int            `json:"ecartesLiens"`
	Flagged    int            `json:"fichiersSignales"`
	ByRule     map[string]int `json:"fichiersSignalesParRegle"`
	ByTopLevel map[string]int `json:"fichiersSignalesParDossier"`
}

type flaggedFile struct {
	Path  string   `json:"chemin"`
	Rules []string `json:"regles"`
	Line  int      `json:"ligne"`
}

func runFiles(args []string) error {
	flags := flag.NewFlagSet("fichiers", flag.ExitOnError)
	root := flags.String("racine", "", "dossier à mesurer")
	workers := flags.Int("fils", 3, "nombre de fils")
	flaggedOut := flags.String("signales", "", "fichier JSON de la liste des fichiers signalés (chemin, règles, ligne)")
	_ = flags.Parse(args)
	if *root == "" {
		return errors.New("-racine est requis")
	}
	report, flagged, err := MeasureFiles(*root, max(1, *workers))
	if err != nil {
		return err
	}
	if *flaggedOut != "" {
		encoded, _ := json.MarshalIndent(flagged, "", " ")
		if err := os.WriteFile(*flaggedOut, append(encoded, '\n'), 0o644); err != nil {
			return err
		}
	}
	encoded, _ := json.MarshalIndent(report, "", " ")
	_, _ = fmt.Println(string(encoded))
	return nil
}

// MeasureFiles applique injection.Find à chaque fichier texte du dossier.
func MeasureFiles(root string, workers int) (fileReport, []flaggedFile, error) {
	report := fileReport{ByRule: map[string]int{}, ByTopLevel: map[string]int{}}
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			report.Symlinks++
			return nil
		}
		if entry.Type().IsRegular() {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return report, nil, err
	}
	sort.Strings(paths)
	var (
		mutex    sync.Mutex
		group    sync.WaitGroup
		flagged  []flaggedFile
		firstErr error
	)
	jobs := make(chan string)
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for path := range jobs {
				info, statErr := os.Stat(path)
				if statErr == nil && info.Size() > injection.MaxInputBytes {
					mutex.Lock()
					report.TooLarge++
					mutex.Unlock()
					continue
				}
				data, readErr := os.ReadFile(path)
				if statErr != nil || readErr != nil {
					mutex.Lock()
					if firstErr == nil {
						firstErr = errors.Join(statErr, readErr)
					}
					mutex.Unlock()
					continue
				}
				if bytes.IndexByte(data[:min(len(data), 8000)], 0) >= 0 {
					mutex.Lock()
					report.Binary++
					mutex.Unlock()
					continue
				}
				found := injection.Find(data)
				rel, _ := filepath.Rel(root, path)
				rel = filepath.ToSlash(rel)
				mutex.Lock()
				report.Analysed++
				if found.Total > 0 {
					report.Flagged++
					report.ByTopLevel[strings.SplitN(rel, "/", 2)[0]]++
					rules := map[string]bool{}
					for _, finding := range found.Findings {
						rules[string(finding.Rule)] = true
					}
					names := make([]string, 0, len(rules))
					for rule := range rules {
						report.ByRule[rule]++
						names = append(names, rule)
					}
					sort.Strings(names)
					flagged = append(flagged, flaggedFile{Path: rel, Rules: names, Line: found.Findings[0].Line})
				}
				mutex.Unlock()
			}
		}()
	}
	for _, path := range paths {
		jobs <- path
	}
	close(jobs)
	group.Wait()
	sort.Slice(flagged, func(i, j int) bool { return flagged[i].Path < flagged[j].Path })
	return report, flagged, firstErr
}
