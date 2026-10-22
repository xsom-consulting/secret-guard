// Commande wasmparity : exécute en Go natif, sur le corpus du module, les fonctions que rend le module WebAssembly
// (analyse, expurgation, instructions cachées), et écrit leurs documents JSON, cas par cas, en JSON Lines sur la sortie
// standard. L'essai sous Node (wasm/parity.test.mjs) exécute les mêmes cas dans le module WebAssembly et exige des
// documents identiques, octet pour octet : c'est la parité du module avec le moteur Go.
//
// Usage : go run ./tools/wasmparity [-root .]
//
// Chaque ligne est un objet {kind, id, languageId?, input, native, text?} : kind « scan », « expurgate » ou
// « hidden » ; input, les octets du cas en base64 (le module reçoit exactement les mêmes octets) ; native, le document
// JSON rendu par le code Go (internal/report, internal/expurgation), tel quel ; text, le texte expurgé en base64 (null
// sans texte). La première ligne est le décompte {kind: "summary", scan, expurgate, hidden}. Les cas « expurgate »
// sont ceux du corpus de détection (sans numéro minimal) et ceux de vectors/expurgate.json (numéro minimal du cas),
// avec la clé d'Empreinte locale de test FingerprintKey. Le corpus contient des valeurs synthétiques à la forme de
// jetons : la sortie est réservée à l'essai, jamais écrite dans le dépôt.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/xsom-consulting/secret-guard/detect"
	"github.com/xsom-consulting/secret-guard/hidden"
	"github.com/xsom-consulting/secret-guard/internal/expurgation"
	"github.com/xsom-consulting/secret-guard/internal/report"
	"github.com/xsom-consulting/secret-guard/pack"
)

// FingerprintKey est la clé d'Empreinte locale des cas « expurgate » : octets 1 à 32 (l'essai sous Node pose la même).
func FingerprintKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

// Line est une ligne de la sortie.
type Line struct {
	Kind       string  `json:"kind"`
	ID         string  `json:"id"`
	LanguageID *string `json:"languageId,omitempty"`
	MinOrdinal int     `json:"minOrdinal,omitempty"`
	Input      string  `json:"input"`
	Native     string  `json:"native"`
	Text       *string `json:"text,omitempty"`
}

// Summary est la première ligne : nombre de cas de chaque sorte.
type Summary struct {
	Kind      string `json:"kind"`
	Scan      int    `json:"scan"`
	Expurgate int    `json:"expurgate"`
	Hidden    int    `json:"hidden"`
}

type corpusCase struct {
	ID            string  `json:"id"`
	Input         string  `json:"input"`
	InputEncoding string  `json:"inputEncoding"`
	LanguageID    *string `json:"languageId"`
}

func (c corpusCase) bytes() ([]byte, error) {
	switch c.InputEncoding {
	case "utf8":
		return []byte(c.Input), nil
	case "base64":
		return base64.StdEncoding.DecodeString(c.Input)
	}
	return nil, fmt.Errorf("%s : inputEncoding inconnu", c.ID)
}

type expurgateCase struct {
	ID           string   `json:"id"`
	Input        []string `json:"input"`
	LanguageID   string   `json:"languageId"`
	FirstOrdinal int      `json:"firstOrdinal"`
}

func main() {
	root := flag.String("root", ".", "racine du dépôt secret-guard")
	flag.Parse()
	out := bufio.NewWriter(os.Stdout)
	if err := run(*root, out); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "wasmparity :", err)
		os.Exit(2)
	}
	if err := out.Flush(); err != nil {
		os.Exit(2)
	}
}

func readJSON(path string, into any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, into)
}

// detectionCases lit tous les cas du corpus de détection, dans l'ordre du manifeste ; le nombre lu doit être celui
// du manifeste.
func detectionCases(root string) ([]corpusCase, error) {
	dir := filepath.Join(root, "vectors", "detection")
	var manifest struct {
		FormatVersion int `json:"formatVersion"`
		Files         []struct {
			File  string `json:"file"`
			Cases int    `json:"cases"`
		} `json:"files"`
	}
	if err := readJSON(filepath.Join(dir, "manifest.json"), &manifest); err != nil {
		return nil, err
	}
	if manifest.FormatVersion != 1 || len(manifest.Files) == 0 {
		return nil, errors.New("manifeste du corpus de format inconnu")
	}
	var all []corpusCase
	for _, file := range manifest.Files {
		var cases []corpusCase
		if err := readJSON(filepath.Join(dir, file.File), &cases); err != nil {
			return nil, err
		}
		if len(cases) != file.Cases {
			return nil, fmt.Errorf("%s : %d cas, manifeste %d", file.File, len(cases), file.Cases)
		}
		all = append(all, cases...)
	}
	return all, nil
}

func options(languageID *string) (detect.Options, error) {
	if languageID == nil {
		return detect.Options{}, nil
	}
	if *languageID == "" {
		return detect.Options{}, errors.New("languageId vide, non représentable par Options")
	}
	return detect.Options{LanguageID: *languageID}, nil
}

func run(root string, w io.Writer) error {
	p, err := pack.Initial()
	if err != nil {
		return err
	}
	rules, err := detect.LoadRules(p)
	if err != nil {
		return err
	}
	key, err := detect.NewFingerprintKey(FingerprintKey())
	if err != nil {
		return err
	}
	cases, err := detectionCases(root)
	if err != nil {
		return err
	}
	var expurgateVectors struct {
		FormatVersion int             `json:"formatVersion"`
		Cases         []expurgateCase `json:"cases"`
	}
	if err := readJSON(filepath.Join(root, "vectors", "expurgate.json"), &expurgateVectors); err != nil {
		return err
	}
	var hiddenVectors struct {
		Cases []corpusCase `json:"cases"`
	}
	if err := readJSON(filepath.Join(root, "vectors", "hidden.json"), &hiddenVectors); err != nil {
		return err
	}
	if expurgateVectors.FormatVersion != 1 || len(expurgateVectors.Cases) == 0 || len(hiddenVectors.Cases) == 0 {
		return errors.New("vecteurs d'expurgation ou d'instructions cachées de format inconnu")
	}

	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	summary := Summary{Kind: "summary", Scan: len(cases), Expurgate: len(cases) + len(expurgateVectors.Cases), Hidden: len(hiddenVectors.Cases)}
	if err := encoder.Encode(summary); err != nil {
		return err
	}
	expurgateLine := func(id string, input []byte, languageID *string, minOrdinal int) error {
		opts, err := options(languageID)
		if err != nil {
			return fmt.Errorf("%s : %w", id, err)
		}
		document, text := expurgation.Run(input, rules, &key, opts, expurgation.Request{MinOrdinal: minOrdinal})
		line := Line{Kind: "expurgate", ID: id, LanguageID: languageID, MinOrdinal: minOrdinal,
			Input: base64.StdEncoding.EncodeToString(input), Native: string(document)}
		if text != nil {
			encoded := base64.StdEncoding.EncodeToString(text)
			line.Text = &encoded
		}
		return encoder.Encode(line)
	}
	for _, c := range cases {
		input, err := c.bytes()
		if err != nil {
			return err
		}
		opts, err := options(c.LanguageID)
		if err != nil {
			return fmt.Errorf("%s : %w", c.ID, err)
		}
		document := report.JSON(detect.Scan(input, rules, opts))
		if err := encoder.Encode(Line{Kind: "scan", ID: c.ID, LanguageID: c.LanguageID,
			Input: base64.StdEncoding.EncodeToString(input), Native: string(document)}); err != nil {
			return err
		}
		if err := expurgateLine(c.ID, input, c.LanguageID, 0); err != nil {
			return err
		}
	}
	for _, c := range expurgateVectors.Cases {
		input, err := base64.StdEncoding.DecodeString(strings.Join(c.Input, ""))
		if err != nil {
			return fmt.Errorf("%s : entrée base64 illisible", c.ID)
		}
		var languageID *string
		if c.LanguageID != "" {
			languageID = &c.LanguageID
		}
		if err := expurgateLine("expurgate/"+c.ID, input, languageID, c.FirstOrdinal); err != nil {
			return err
		}
	}
	for _, c := range hiddenVectors.Cases {
		input, err := c.bytes()
		if err != nil {
			return err
		}
		document := report.HiddenJSON(hidden.Find(input))
		if err := encoder.Encode(Line{Kind: "hidden", ID: c.ID,
			Input: base64.StdEncoding.EncodeToString(input), Native: string(document)}); err != nil {
			return err
		}
	}
	return nil
}
