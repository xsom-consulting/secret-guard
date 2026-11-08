// SPDX-License-Identifier: PolyForm-Small-Business-1.0.0

// Aides des essais de l’expurgation, reprises des essais du paquet detect (Pack initial, corpus de parité, vecteurs du
// masquage, valeurs fictives) et écrites sur l’API publique de detect.

package expurgation

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/detect"
	"github.com/xsom-consulting/secret-guard/pack"
)

// corpusFiles rend les fichiers du manifeste du corpus de parité.
func corpusFiles(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(corpusDir + "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Files []struct {
			File string `json:"file"`
		} `json:"files"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil || len(manifest.Files) == 0 {
		t.Fatalf("manifeste illisible : %v", err)
	}
	files := make([]string, 0, len(manifest.Files))
	for _, f := range manifest.Files {
		files = append(files, f.File)
	}
	return files
}

// options rend les options d'analyse du cas (languageId absent : Options vide) ; faux pour un languageId vide mais
// présent, que Options ne représente pas.
func (c corpusCase) options() (Options, bool) {
	if c.LanguageID == nil {
		return Options{}, true
	}
	return Options{LanguageID: *c.LanguageID}, *c.LanguageID != ""
}

// Corpus de parité (vectors/detection/), lu par chemin relatif comme les autres vecteurs.
const corpusDir = "../vectors/detection/"

type corpusFinding struct {
	RuleID     string          `json:"ruleId"`
	SecretType string          `json:"secretType"`
	Encoding   detect.Encoding `json:"encoding"`
	Score      int             `json:"score"`
	Level      string          `json:"level"`
	ByteStart  int             `json:"byteStart"`
	ByteEnd    int             `json:"byteEnd"`
}

type corpusCase struct {
	ID            string  `json:"id"`
	Input         string  `json:"input"`
	InputEncoding string  `json:"inputEncoding"`
	LanguageID    *string `json:"languageId"`
	Expected      struct {
		Complete bool            `json:"complete"`
		Failure  string          `json:"failure"`
		Findings []corpusFinding `json:"findings"`
	} `json:"expected"`
}

func loadCorpusFile(t *testing.T, name string) []corpusCase {
	t.Helper()
	data, err := os.ReadFile(corpusDir + name)
	if err != nil {
		t.Fatalf("lecture du corpus %s : %v", name, err)
	}
	var cases []corpusCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatalf("corpus %s illisible : %v", name, err)
	}
	var manifest struct {
		Files []struct {
			File  string `json:"file"`
			Cases int    `json:"cases"`
		} `json:"files"`
	}
	data, err = os.ReadFile(corpusDir + "manifest.json")
	if err != nil || json.Unmarshal(data, &manifest) != nil {
		t.Fatalf("manifeste du corpus illisible : %v", err)
	}
	listed := false
	for _, f := range manifest.Files {
		if f.File == name {
			listed = true
			if f.Cases != len(cases) {
				t.Fatalf("corpus %s : %d cas, manifeste %d", name, len(cases), f.Cases)
			}
		}
	}
	if !listed {
		t.Fatalf("corpus %s absent du manifeste", name)
	}
	return cases
}

func (c corpusCase) bytes(t *testing.T) []byte {
	t.Helper()
	switch c.InputEncoding {
	case "utf8":
		return []byte(c.Input)
	case "base64":
		data, err := base64.StdEncoding.DecodeString(c.Input)
		if err != nil {
			t.Fatalf("%s : entrée base64 illisible", c.ID)
		}
		return data
	default:
		t.Fatalf("%s : inputEncoding inconnu", c.ID)
		return nil
	}
}

// randomKey tire une clé d'Empreinte locale.
func randomKey(t testing.TB) detect.FingerprintKey {
	t.Helper()
	raw := make([]byte, detect.FingerprintKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	key, err := detect.NewFingerprintKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// loadInitialPack lit le Pack initial embarqué par le décodage strict du schéma RulePack (pack.Decode).
func loadInitialPack(t testing.TB) pack.Pack {
	t.Helper()
	initial, err := pack.Initial()
	if err != nil {
		t.Fatalf("Pack initial hors du schéma RulePack : %v", err)
	}
	if len(initial.Rules) == 0 {
		t.Fatal("Pack initial sans règle")
	}
	return *initial
}

func loadInitialRules(t testing.TB) *detect.Rules {
	t.Helper()
	p := loadInitialPack(t)
	rules, err := detect.LoadRules(&p)
	if err != nil {
		t.Fatalf("Pack initial refusé : %v", err)
	}
	return rules
}

// Vecteurs du masquage, produits par le moteur TypeScript de Secret Guard (generator/redact/,
// npm run vectors:redact -- --upstream <checkout>).
const redactVectorsFile = "../vectors/redact.json"

// redactedText est un texte masqué attendu : taille, SHA-256 et, s'il est court, le texte lui-même.
type redactedText struct {
	Bytes        int     `json:"bytes"`
	SHA256       string  `json:"sha256"`
	Text         *string `json:"text"`
	TextEncoding string  `json:"textEncoding"`
}

type scanExpectation struct {
	Complete bool            `json:"complete"`
	Failure  string          `json:"failure"`
	Findings []corpusFinding `json:"findings"`
}

type redactSpanCase struct {
	ID              string `json:"id"`
	Content         string `json:"content"`
	ContentEncoding string `json:"contentEncoding"`
	Findings        []struct {
		RuleID    string `json:"ruleId"`
		Score     int    `json:"score"`
		ByteStart int    `json:"byteStart"`
		ByteEnd   int    `json:"byteEnd"`
	} `json:"findings"`
	Redacted redactedText `json:"redacted"`
}

type redactCase struct {
	ID            string  `json:"id"`
	CorpusFile    string  `json:"corpusFile"`
	Input         *string `json:"input"`
	InputEncoding string  `json:"inputEncoding"`
	Repeat        *struct {
		Text  string `json:"text"`
		Count int    `json:"count"`
	} `json:"repeat"`
	LanguageID *string `json:"languageId"`
	Expected   struct {
		Failure  detect.SanitizeFailure `json:"failure"`
		Initial  *scanExpectation       `json:"initial"`
		Redacted *redactedText          `json:"redacted"`
		Final    *scanExpectation       `json:"final"`
	} `json:"expected"`
}

type redactVectors struct {
	FormatVersion  int              `json:"formatVersion"`
	UpstreamCommit string           `json:"upstreamCommit"`
	SpanCases      []redactSpanCase `json:"spanCases"`
	Cases          []redactCase     `json:"cases"`
}

func decodeVectorText(encoding, text string) []byte {
	if encoding == "base64" {
		data, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return nil
		}
		return data
	}
	return []byte(text)
}

// readStrict lit un fichier de vecteurs JSON ; un champ inconnu est refusé.
func readStrict(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("%s illisible : %v", path, err)
	}
}

func loadRedactVectors(t *testing.T) redactVectors {
	t.Helper()
	var vectors redactVectors
	readStrict(t, redactVectorsFile, &vectors)
	if vectors.FormatVersion != 1 || len(vectors.Cases) == 0 || len(vectors.SpanCases) == 0 {
		t.Fatalf("vecteurs du masquage de format inconnu ou vides")
	}
	var manifest struct {
		UpstreamCommit string `json:"upstreamCommit"`
	}
	data, err := os.ReadFile(corpusDir + "manifest.json")
	if err != nil || json.Unmarshal(data, &manifest) != nil || manifest.UpstreamCommit != vectors.UpstreamCommit {
		t.Fatalf("vecteurs du masquage d'un autre commit d'origine que le corpus de parité")
	}
	return vectors
}

// redactCorpus rend les cas du corpus de parité par fichier puis par identifiant.
func redactCorpus(t *testing.T) map[string]map[string]corpusCase {
	t.Helper()
	corpus := map[string]map[string]corpusCase{}
	for _, file := range corpusFiles(t) {
		corpus[file] = map[string]corpusCase{}
		for _, c := range loadCorpusFile(t, file) {
			corpus[file][c.ID] = c
		}
	}
	return corpus
}

// input rend l'entrée, les options et l'analyse initiale attendue d'un cas (renvoi au corpus ou entrée synthétique).
func (c redactCase) input(t *testing.T, corpus map[string]map[string]corpusCase) ([]byte, Options, scanExpectation) {
	t.Helper()
	if c.CorpusFile != "" {
		source, ok := corpus[c.CorpusFile][c.ID]
		if !ok || c.Input != nil || c.Expected.Initial != nil || c.Repeat != nil || c.LanguageID != nil {
			t.Fatalf("%s : renvoi au corpus de parité invalide", c.ID)
		}
		options, ok := source.options()
		if !ok {
			t.Fatalf("%s : languageId vide", c.ID)
		}
		return source.bytes(t), options, scanExpectation{Complete: source.Expected.Complete, Failure: source.Expected.Failure,
			Findings: source.Expected.Findings}
	}
	if c.Input == nil || c.Expected.Initial == nil || (c.InputEncoding != "utf8" && c.InputEncoding != "base64") {
		t.Fatalf("%s : entrée synthétique incomplète", c.ID)
	}
	content := decodeVectorText(c.InputEncoding, *c.Input)
	if c.Repeat != nil {
		content = append([]byte(strings.Repeat(c.Repeat.Text, c.Repeat.Count)), content...)
	}
	var options Options
	if c.LanguageID != nil {
		if *c.LanguageID == "" {
			t.Fatalf("%s : languageId vide", c.ID)
		}
		options.LanguageID = *c.LanguageID
	}
	return content, options, *c.Expected.Initial
}

// outsideSpans rend les morceaux de content hors de l'union des étendues des constats (calculée ici, indépendamment de
// Redact).
func outsideSpans(content []byte, findings []detect.Finding) [][]byte {
	covered := make([]bool, len(content))
	for _, f := range findings {
		for i := f.ByteStart; i < f.ByteEnd; i++ {
			covered[i] = true
		}
	}
	var pieces [][]byte
	start := -1
	for i := 0; i <= len(content); i++ {
		if i < len(content) && !covered[i] {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			pieces = append(pieces, content[start:i])
			start = -1
		}
	}
	return pieces
}

func containsIn(pieces [][]byte, window []byte) bool {
	for _, piece := range pieces {
		if bytes.Contains(piece, window) {
			return true
		}
	}
	return false
}

// syntheticPassword est une valeur synthétique de la règle contextual_password, construite à l'exécution.
func syntheticPassword() string { return "Xq7" + "Lm2Pz9" + "!Wr4Tn" }

// syntheticGitHubToken est une valeur synthétique de la règle github_token, construite à l'exécution (jamais écrite
// en clair dans le dépôt).
func syntheticGitHubToken() string { return "gh" + "p_" + strings.Repeat("aB3d", 9) }
