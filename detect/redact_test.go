package detect

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

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

// difference compare des octets au texte attendu ; vide s'ils sont égaux. Le message ne recopie jamais le texte.
func (r redactedText) difference(got []byte) string {
	sum := sha256.Sum256(got)
	if len(got) != r.Bytes || hex.EncodeToString(sum[:]) != r.SHA256 {
		return fmt.Sprintf("texte masqué de %d octets, attendu %d (SHA-256 différent)", len(got), r.Bytes)
	}
	if r.Text != nil && !bytes.Equal(decodeVectorText(r.TextEncoding, *r.Text), got) {
		return "texte masqué différent du texte écrit dans le vecteur"
	}
	return ""
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
		Failure  SanitizeFailure  `json:"failure"`
		Initial  *scanExpectation `json:"initial"`
		Redacted *redactedText    `json:"redacted"`
		Final    *scanExpectation `json:"final"`
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

// redactSelected dit si un cas du corpus est repris par les vecteurs du masquage : au moins un constat, ou analyse
// incomplète (selectedCorpusCase du générateur).
func redactSelected(c corpusCase) bool { return !c.Expected.Complete || len(c.Expected.Findings) > 0 }

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

// scanDifference compare un résultat à une analyse attendue ; vide s'ils sont égaux (issue, règles, positions).
func scanDifference(result Result, want scanExpectation) string {
	if result.Complete != want.Complete || string(result.Failure) != want.Failure {
		return fmt.Sprintf("issue %q (complete %v), attendu %q (complete %v)", result.Failure, result.Complete, want.Failure, want.Complete)
	}
	got := corpusForm(result.Findings)
	expected := append([]corpusFinding(nil), want.Findings...)
	sortCorpusFindings(expected)
	if len(got) != len(expected) {
		return fmt.Sprintf("%d constats, attendu %d", len(got), len(expected))
	}
	for i := range got {
		if got[i] != expected[i] {
			return fmt.Sprintf("constat %d : %+v, attendu %+v", i, got[i], expected[i])
		}
	}
	return ""
}

// redactCaseDifference rejoue un cas de RedactAndRescan ; vide s'il est égal au vecteur.
func redactCaseDifference(t *testing.T, rules *Rules, c redactCase, corpus map[string]map[string]corpusCase) string {
	content, options, initial := c.input(t, corpus)
	text, result := RedactAndRescan(content, rules, options, RedactOptions{})
	if result.Failure != c.Expected.Failure {
		return fmt.Sprintf("issue %q, attendu %q", result.Failure, c.Expected.Failure)
	}
	if diff := scanDifference(result.Initial, initial); diff != "" {
		return "analyse initiale : " + diff
	}
	redacted, err := Redact(content, result.Initial, RedactOptions{})
	switch {
	case c.Expected.Redacted == nil && !errors.Is(err, ErrRedactIncomplete):
		return "Redact accepte une analyse incomplète"
	case c.Expected.Redacted != nil && err != nil:
		return "Redact refuse : " + err.Error()
	case c.Expected.Redacted != nil:
		if diff := c.Expected.Redacted.difference(redacted); diff != "" {
			return "Redact : " + diff
		}
	}
	if c.Expected.Failure == SanitizeNone {
		if c.Expected.Redacted == nil {
			return "vecteur sans texte pour l'issue none"
		}
		if diff := c.Expected.Redacted.difference(text); diff != "" {
			return "RedactAndRescan : " + diff
		}
	} else if text != nil {
		return "texte rendu après un échec"
	}
	if c.Expected.Final == nil {
		if !reflect.DeepEqual(result.Final, result.Initial) {
			return "analyse finale différente de l'analyse initiale incomplète"
		}
	} else if diff := scanDifference(result.Final, *c.Expected.Final); diff != "" {
		return "analyse finale : " + diff
	}
	return ""
}

// TestRedactParity est le test de parité du masquage : chaque cas de vectors/redact.json, produit par redact et
// redactAndRescan du moteur TypeScript de Secret Guard, donne exactement la même issue, les mêmes analyses initiale
// et finale (règles, positions en octets) et les mêmes octets masqués. Les cas d'étendues éprouvent Redact seul sur
// des constats construits (fusion, ordre, nommage, contenu non ASCII ou hors UTF-8). Chaque cas du corpus de parité
// qui a un constat ou une analyse incomplète y figure. Un échec n'affiche que l'identifiant du cas.
func TestRedactParity(t *testing.T) {
	t.Run("parité à 100 % du masquage avec Secret Guard", func(t *testing.T) {
		rules := loadInitialRules(t)
		vectors := loadRedactVectors(t)
		corpus := redactCorpus(t)
		failed := 0
		for _, c := range vectors.SpanCases {
			findings := make([]Finding, 0, len(c.Findings))
			for _, f := range c.Findings {
				findings = append(findings, Finding{RuleID: f.RuleID, Score: f.Score, ByteStart: f.ByteStart, ByteEnd: f.ByteEnd})
			}
			got, err := Redact(decodeVectorText(c.ContentEncoding, c.Content), Result{Complete: true, Failure: FailureNone, Findings: findings}, RedactOptions{})
			diff := c.Redacted.difference(got)
			if err != nil {
				diff = err.Error()
			}
			if diff != "" {
				failed++
				t.Errorf("%s : %s", c.ID, diff)
			}
		}
		seen := map[string]bool{}
		referenced := 0
		for _, c := range vectors.Cases {
			key := c.CorpusFile + "\x00" + c.ID
			if seen[key] {
				t.Errorf("cas en double : %s", c.ID)
			}
			seen[key] = true
			if c.CorpusFile != "" {
				referenced++
			}
			if diff := redactCaseDifference(t, rules, c, corpus); diff != "" {
				failed++
				t.Errorf("%s : %s", c.ID, diff)
			}
		}
		selected := 0
		for file, cases := range corpus {
			for id, c := range cases {
				if redactSelected(c) {
					selected++
					if !seen[file+"\x00"+id] {
						t.Errorf("cas du corpus absent des vecteurs du masquage : %s", id)
					}
				}
			}
		}
		if referenced != selected || selected == 0 {
			t.Fatalf("%d renvois au corpus, %d cas du corpus à reprendre", referenced, selected)
		}
		t.Logf("%d cas de RedactAndRescan (%d du corpus), %d cas d'étendues, %d en écart", len(vectors.Cases), referenced,
			len(vectors.SpanCases), failed)
	})
}

// labelPattern est un libellé de masquage.
var labelPattern = regexp.MustCompile(`<REDACTED_[A-Za-z0-9_]*>`)

// outsideSpans rend les morceaux de content hors de l'union des étendues des constats (calculée ici, indépendamment de
// Redact).
func outsideSpans(content []byte, findings []Finding) [][]byte {
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

// TestRedactLeavesNoValue prouve, pour chaque cas du corpus de parité qui a un constat, que le texte masqué ne
// contient aucune fenêtre de 8 octets (la valeur entière si elle est plus courte) d'une valeur détectée, hors des
// libellés : la sortie est découpée aux libellés et chaque morceau est cherché. Seule exception : une fenêtre que
// l'entrée contient aussi hors de toute étendue détectée (« PASSWORD=process.env.PASSWORD » : la valeur contient le
// nom de la clé), texte que le moteur n'a pas reconnu comme secret ; ces fenêtres sont comptées. Un échec n'affiche
// que l'identifiant du cas.
func TestRedactLeavesNoValue(t *testing.T) {
	t.Run("aucune valeur détectée ne reste dans le texte masqué", func(t *testing.T) {
		rules := loadInitialRules(t)
		checked, excused := 0, 0
		for _, file := range corpusFiles(t) {
			for _, c := range loadCorpusFile(t, file) {
				if !c.Expected.Complete || len(c.Expected.Findings) == 0 {
					continue
				}
				options, _ := c.options()
				content := c.bytes(t)
				text, result := RedactAndRescan(content, rules, options, RedactOptions{})
				if result.Failure != SanitizeNone {
					if text != nil {
						t.Errorf("%s : texte rendu après un échec", c.ID)
					}
					continue
				}
				checked++
				var pieces [][]byte
				for _, piece := range labelPattern.Split(string(text), -1) {
					pieces = append(pieces, []byte(piece))
				}
				outside := outsideSpans(content, result.Initial.Findings)
				for _, f := range result.Initial.Findings {
					value := content[f.ByteStart:f.ByteEnd]
					width := min(8, len(value))
					for i := 0; i+width <= len(value) && width > 0; i++ {
						window := value[i : i+width]
						switch {
						case !containsIn(pieces, window):
						case containsIn(outside, window):
							excused++
						default:
							t.Errorf("%s : fenêtre de la valeur de %s dans le texte masqué", c.ID, f.RuleID)
						}
					}
				}
			}
		}
		if checked == 0 {
			t.Fatal("aucun cas masqué")
		}
		t.Logf("%d textes masqués vérifiés ; %d fenêtres présentes aussi hors des étendues dans l'entrée", checked, excused)
	})
}

// syntheticPassword est une valeur synthétique de la règle contextual_password, construite à l'exécution.
func syntheticPassword() string { return "Xq7" + "Lm2Pz9" + "!Wr4Tn" }

func TestRedact(t *testing.T) {
	rules := loadInitialRules(t)
	token := syntheticGitHubToken()
	t.Run("deux secrets masqués, octets hors des étendues gardés, texte sans finding après nouvelle analyse", func(t *testing.T) {
		content := []byte("A " + token + "\nDB_PASSWORD=" + syntheticPassword() + "\nfin é😀\n")
		text, result := RedactAndRescan(content, rules, Options{}, RedactOptions{})
		want := "A <REDACTED_github_token>\nDB_PASSWORD=<REDACTED_contextual_password>\nfin é😀\n"
		if result.Failure != SanitizeNone || string(text) != want || len(result.Initial.Findings) != 2 ||
			!result.Final.Complete || len(result.Final.Findings) != 0 {
			t.Fatalf("%q %+v", text, result)
		}
	})
	t.Run("sans constat : copie de l'entrée, sans seconde analyse", func(t *testing.T) {
		content := []byte("rien à masquer\n")
		calls := 0
		defer swapRedactScan(func(c []byte, r *Rules, o Options) Result { calls++; return Scan(c, r, o) })()
		text, result := RedactAndRescan(content, rules, Options{}, RedactOptions{})
		if result.Failure != SanitizeNone || string(text) != string(content) || calls != 1 || !reflect.DeepEqual(result.Final, result.Initial) {
			t.Fatalf("%q %+v %d", text, result, calls)
		}
		text[0] = 'X'
		if content[0] != 'r' {
			t.Fatal("le texte rendu partage la mémoire de l'entrée")
		}
		if text, result := RedactAndRescan(nil, rules, Options{}, RedactOptions{}); text == nil || len(text) != 0 || result.Failure != SanitizeNone {
			t.Fatalf("entrée vide : %v %+v", text, result)
		}
	})
	t.Run("analyse incomplète : aucun texte, Final égal à Initial ; règles absentes comprises", func(t *testing.T) {
		big := bytes.Repeat([]byte("a"), MaxInputBytes+1)
		for name, run := range map[string]func() ([]byte, SanitizeResult){
			"plus de 1 Mio": func() ([]byte, SanitizeResult) { return RedactAndRescan(big, rules, Options{}, RedactOptions{}) },
			"règles absentes": func() ([]byte, SanitizeResult) {
				return RedactAndRescan([]byte(token), nil, Options{}, RedactOptions{})
			},
		} {
			text, result := run()
			if text != nil || result.Failure != SanitizeIncomplete || result.Initial.Complete || !reflect.DeepEqual(result.Final, result.Initial) {
				t.Errorf("%s : %v %+v", name, text != nil, result)
			}
		}
	})
	t.Run("résidu : aucun texte, la copie masquée est effacée", func(t *testing.T) {
		content := []byte("API_KEY=" + token + "\nNEXT=another")
		var second []byte
		defer swapRedactScan(func(c []byte, r *Rules, o Options) Result {
			if !bytes.Equal(c, content) {
				second = c
			}
			return Scan(c, r, o)
		})()
		text, result := RedactAndRescan(content, rules, Options{}, RedactOptions{})
		if text != nil || result.Failure != SanitizeResidual || len(result.Final.Findings) == 0 {
			t.Fatalf("%v %+v", text != nil, result)
		}
		if len(second) == 0 || !bytes.Equal(second, make([]byte, len(second))) {
			t.Fatal("copie masquée non effacée")
		}
	})
	t.Run("texte masqué de plus de 1 Mio : analyse finale incomplète, aucun texte, copie effacée", func(t *testing.T) {
		tail := "\npassword = \"" + syntheticPassword() + "\"\n"
		content := append(bytes.Repeat([]byte("x "), (MaxInputBytes-len(tail))/2), tail...)
		var second []byte
		defer swapRedactScan(func(c []byte, r *Rules, o Options) Result {
			if len(c) > MaxInputBytes {
				second = c
			}
			return Scan(c, r, o)
		})()
		text, result := RedactAndRescan(content, rules, Options{}, RedactOptions{})
		if text != nil || result.Failure != SanitizeIncomplete || !result.Initial.Complete || result.Final.Failure != FailureScanLimit {
			t.Fatalf("%v %+v", text != nil, result)
		}
		if len(second) == 0 || !bytes.Equal(second, make([]byte, len(second))) {
			t.Fatal("copie masquée non effacée")
		}
	})
	t.Run("étendue hors du contenu dans l'analyse initiale : incomplète, sans texte (fail-closed)", func(t *testing.T) {
		defer swapRedactScan(func(c []byte, _ *Rules, _ Options) Result {
			return Result{Complete: true, Failure: FailureNone, Findings: []Finding{{RuleID: "r", ByteStart: 0, ByteEnd: len(c) + 1}}}
		})()
		text, result := RedactAndRescan([]byte("abc"), rules, Options{}, RedactOptions{})
		if text != nil || result.Failure != SanitizeIncomplete || result.Final.Failure != FailureScanError {
			t.Fatalf("%v %+v", text != nil, result)
		}
	})
	t.Run("Redact refuse une analyse incomplète et une étendue hors du contenu, sans texte", func(t *testing.T) {
		content := []byte("0123456789")
		for name, result := range map[string]Result{
			"scan_limit":               {Failure: FailureScanLimit},
			"scan_error":               {Failure: FailureScanError},
			"complet sans issue none":  {Complete: true, Failure: FailureScanError},
			"issue none sans complete": {Failure: FailureNone},
		} {
			if text, err := Redact(content, result, RedactOptions{}); text != nil || !errors.Is(err, ErrRedactIncomplete) {
				t.Errorf("%s : %v", name, err)
			}
		}
		for name, f := range map[string]Finding{
			"début négatif":     {ByteStart: -1, ByteEnd: 2},
			"fin avant début":   {ByteStart: 5, ByteEnd: 4},
			"fin après contenu": {ByteStart: 8, ByteEnd: 11},
		} {
			result := Result{Complete: true, Failure: FailureNone, Findings: []Finding{{RuleID: "ok", ByteStart: 0, ByteEnd: 2}, f}}
			if text, err := Redact(content, result, RedactOptions{}); text != nil || !errors.Is(err, ErrRedactSpan) {
				t.Errorf("%s : %v", name, err)
			}
		}
	})
	t.Run("libellé : identifiant de règle réduit à [A-Za-z0-9_], octet hors UTF-8 compris", func(t *testing.T) {
		for ruleID, want := range map[string]string{
			"github_token": "github_token", "a-b.c😀é z": "a_b_c____z", "": "", "x\xffy": "x_y", "Z9_": "Z9_",
		} {
			if got := placeholderName(ruleID); got != want {
				t.Errorf("%q : %q, attendu %q", ruleID, got, want)
			}
		}
	})
}

// swapRedactScan remplace l'analyse de RedactAndRescan et rend la fonction qui la rétablit.
func swapRedactScan(scan func([]byte, *Rules, Options) Result) func() {
	previous := redactScan
	redactScan = scan
	return func() { redactScan = previous }
}

// FuzzRedact : quelle que soit l'entrée, l'issue est dans la liste fermée ; un échec ne rend aucun texte ; un
// masquage réussi est le texte de Redact sur l'analyse de l'entrée, et une nouvelle analyse indépendante de ce texte
// est complète et sans constat.
//
//	go test ./detect -run '^$' -fuzz '^FuzzRedact$' -fuzztime=60s
func FuzzRedact(f *testing.F) {
	token := syntheticGitHubToken()
	for _, seed := range []string{
		"", "rien à signaler", "TOKEN=" + token, token + token, "DB_PASSWORD=" + syntheticPassword() + "\n" + token,
		"API_KEY=" + token + "\nNEXT=another", "payload " + base64.StdEncoding.EncodeToString([]byte("TOKEN="+token)),
		"token ghp%5F" + token[4:], "token " + token[:12] + "\n    " + token[12:], "é😀 " + token + " \xff",
		"<REDACTED_github_token>" + token, "app_secret: |\n  " + strings.Repeat("aZ3k", 6) + "\nnext: 1\n",
	} {
		f.Add([]byte(seed))
	}
	rules := loadInitialRules(f)
	f.Fuzz(func(t *testing.T, content []byte) {
		if len(content) > 64<<10 {
			return
		}
		text, result := RedactAndRescan(content, rules, Options{}, RedactOptions{})
		switch result.Failure {
		case SanitizeNone:
		case SanitizeIncomplete, SanitizeResidual:
			if text != nil {
				t.Fatalf("texte rendu après l'échec %s", result.Failure)
			}
			return
		default:
			t.Fatalf("issue hors liste : %q", result.Failure)
		}
		if !reflect.DeepEqual(result.Initial, Scan(content, rules, Options{})) {
			t.Fatal("analyse initiale différente de Scan")
		}
		redacted, err := Redact(content, result.Initial, RedactOptions{})
		if err != nil || !bytes.Equal(redacted, text) {
			t.Fatal("texte rendu différent de Redact")
		}
		if again := Scan(text, rules, Options{}); !again.Complete || len(again.Findings) != 0 {
			t.Fatal("constat après un masquage réussi")
		}
	})
}
