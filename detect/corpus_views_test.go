package detect

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"
)

// Corpus de parité (vectors/detection/), lu par chemin relatif comme les autres vecteurs.
const corpusDir = "../vectors/detection/"

// Fichiers du corpus des vues et décodages (vues, limites, cas limites) ; les règles et l'analyse complète ont leurs
// propres tests (TestRuleCorpus, TestParity).
var viewCorpusFiles = []string{"views.json", "edge-cases.json", "limits.json"}

type corpusFinding struct {
	RuleID     string   `json:"ruleId"`
	SecretType string   `json:"secretType"`
	Encoding   Encoding `json:"encoding"`
	Score      int      `json:"score"`
	Level      string   `json:"level"`
	ByteStart  int      `json:"byteStart"`
	ByteEnd    int      `json:"byteEnd"`
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

// corpusRule est une règle du Pack initial dont l'étendue d'un constat est celle d'une correspondance du motif (ou
// de son groupe) : jetons fixes et en-tête de clé privée.
type corpusRule struct {
	family  string
	pattern *regexp.Regexp
	// bounded : bornes de longueur hors du motif (minLength/maxLength, répétition RE2 ouverte) : la fin de la
	// correspondance est celle du code des règles, seul le début est comparé.
	bounded bool
}

func corpusRules(t *testing.T) map[string]corpusRule {
	t.Helper()
	rules := map[string]corpusRule{}
	for _, rule := range loadInitialPack(t).Rules {
		if rule.Family != "fixed_pattern" && rule.Family != "private_key" {
			continue
		}
		rules[rule.RuleID] = corpusRule{
			family:  string(rule.Family),
			pattern: regexp.MustCompile(rule.Pattern),
			bounded: rule.MinLength != 0 || rule.MaxLength != 0,
		}
	}
	return rules
}

// matchesSpan dit si une correspondance du motif dans la vue (ou d'un de ses groupes) se ramène à [start, end) de
// la source. Pour l'en-tête d'une clé privée, seul le début compte (la fin est la marque de fin ou la fin du
// texte). Secret Guard élargit l'étendue d'un constat à celle des constats qu'il chevauche (dedupeOverlaps) :
// une correspondance contenue dans l'étendue attendue et qui en partage une borne est admise.
func matchesSpan(v *view, rule corpusRule, start, end int) bool {
	for _, match := range rule.pattern.FindAllSubmatchIndex(v.text, -1) {
		for group := 0; group+1 < len(match); group += 2 {
			if match[group] < 0 {
				continue
			}
			s, e := v.mapRange(match[group], match[group+1])
			switch {
			case s == start && (e == end || rule.family == "private_key" || rule.bounded):
				return true
			case s >= start && e <= end && (s == start || e == end):
				return true
			}
		}
	}
	return false
}

// corpusViews rejoue la construction des vues de collectFindings sans les règles : vues de texte, fenêtres de
// lignes jointes et textes base64 décodés, avec les budgets partagés de l'analyse.
type corpusViews struct {
	text    *textViews
	joined  []*view
	decoded []decodedCandidate
}

type decodedCandidate struct {
	start, end int
	views      []*view
}

func buildCorpusViews(content []byte) (*corpusViews, error) {
	budget := newViewBudget()
	windows := &windowBudget{}
	decode := &decodeBudget{}
	seen := map[sourceRange]struct{}{}
	text, err := buildTextViews(content, budget)
	if err != nil {
		return nil, err
	}
	result := &corpusViews{text: text}
	visit := func(start, end int, decoded string) error {
		inner, err := buildTextViews([]byte(decoded), budget)
		if err != nil {
			return err
		}
		views := append([]*view{inner.identity}, inner.transformed...)
		if inner.normalized != nil {
			views = append(views, inner.normalized)
		}
		for _, v := range append([]*view{inner.canonical}, inner.transformed...) {
			fixed, err := lineWrappedFixedViews(v, windows, budget)
			if err != nil {
				return err
			}
			views = append(views, fixed...)
		}
		result.decoded = append(result.decoded, decodedCandidate{start: start, end: end, views: views})
		return nil
	}
	for _, v := range append([]*view{text.canonical}, text.transformed...) {
		fixed, err := lineWrappedFixedViews(v, windows, budget)
		if err != nil {
			return nil, err
		}
		result.joined = append(result.joined, fixed...)
		wrapped, err := lineWrappedBase64Views(v, windows, budget)
		if err != nil {
			return nil, err
		}
		for _, w := range wrapped {
			if err := forEachBase64Candidate(w, decode, seen, visit); err != nil {
				return nil, err
			}
		}
		if err := forEachBase64Candidate(v, decode, seen, visit); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// viewsFor rend les vues où Secret Guard trouve un constat de cet encodage.
func (cv *corpusViews) viewsFor(encoding Encoding) []*view {
	var views []*view
	switch encoding {
	case EncodingPlain:
		views = append(views, cv.text.identity)
	case EncodingNormalized:
		if cv.text.normalized != nil {
			views = append(views, cv.text.normalized)
		}
	case EncodingWhitespaceJoined:
		views = append(views, cv.joined...)
	default:
		for _, v := range cv.text.transformed {
			if v.encoding == encoding {
				views = append(views, v)
			}
		}
	}
	return views
}

func checkCorpusFinding(cv *corpusViews, rules map[string]corpusRule, f corpusFinding) error {
	rule, positional := rules[f.RuleID]
	if f.Encoding == EncodingBase64 {
		for _, candidate := range cv.decoded {
			if candidate.start != f.ByteStart || candidate.end != f.ByteEnd {
				continue
			}
			if !positional {
				return nil
			}
			for _, v := range candidate.views {
				if rule.pattern.Match(v.text) {
					return nil
				}
			}
			return fmt.Errorf("%s/base64 : aucun texte décodé à [%d, %d) ne porte le motif", f.RuleID, f.ByteStart, f.ByteEnd)
		}
		return fmt.Errorf("%s/base64 : aucun candidat décodé à [%d, %d)", f.RuleID, f.ByteStart, f.ByteEnd)
	}
	views := cv.viewsFor(f.Encoding)
	if len(views) == 0 {
		return fmt.Errorf("%s : aucune vue %s", f.RuleID, f.Encoding)
	}
	if !positional {
		return nil
	}
	for _, v := range views {
		if matchesSpan(v, rule, f.ByteStart, f.ByteEnd) {
			return nil
		}
	}
	return fmt.Errorf("%s : aucune correspondance de la vue %s ne se ramène à [%d, %d)", f.RuleID, f.Encoding, f.ByteStart, f.ByteEnd)
}

// TestViewCorpus rejoue les cas « views », « edge » et « limits » du corpus de parité : pour chaque constat
// attendu, la vue de son encodage existe, et pour un jeton fixe ou un en-tête de clé privée, une correspondance du
// motif du Pack dans cette vue se ramène à l'étendue d'octets attendue (correspondance vue → source), aux deux
// tolérances de matchesSpan près (étendue élargie par la fusion des constats ; règles bornées hors motif). Les
// étendues exactes sont vérifiées par les tests de views_test.go.
func TestViewCorpus(t *testing.T) {
	rules := corpusRules(t)
	for _, name := range viewCorpusFiles {
		cases := loadCorpusFile(t, name)
		t.Run(name+" : vues et correspondance vers les octets de la source", func(t *testing.T) {
			checked := 0
			for _, c := range cases {
				if !c.Expected.Complete {
					// Analyse incomplète attendue (au-delà de 1 Mio) : aucun constat à retrouver.
					continue
				}
				cv, err := buildCorpusViews(c.bytes(t))
				if err != nil {
					t.Errorf("%s : vues refusées (%v)", c.ID, err)
					continue
				}
				for _, f := range c.Expected.Findings {
					if err := checkCorpusFinding(cv, rules, f); err != nil {
						t.Errorf("%s : %v", c.ID, err)
					}
					checked++
				}
			}
			if checked == 0 {
				t.Fatal("aucun constat vérifié")
			}
		})
	}
}

// La complétude de l'analyse sur tout le corpus (aucun budget épuisé sur un cas que Secret Guard termine) est
// prouvée par TestParity (scan_test.go), qui compare l'issue de Scan à celle de chaque cas.
