// SPDX-License-Identifier: Apache-2.0

package injection

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Corpus de rappel : textes publics copiés par tools/injectioncorpus, chacun avec sa source (dépôt, commit, licence).
// Ce sont des consignes piégées écrites par d'autres : des données d'essai. Aucun diagnostic n'en affiche le texte.
const (
	recallPath = "../vectors/injection-recall.json"
	// recallRecordPath : relevé commité du rappel (comptes et identifiants, jamais de texte). Le test échoue dès que la
	// mesure s'en écarte ; après un changement voulu : go test ./injection -run '^TestRecallCorpus$' -update-recall
	recallRecordPath = "testdata/recall.json"
)

var updateRecall = flag.Bool("update-recall", false, "réécrit le relevé du rappel (testdata/recall.json)")

type recallSource struct {
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

type recallCase struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Label  string `json:"label"`
	Text   string `json:"text"`
}

type recallCorpus struct {
	FormatVersion int            `json:"formatVersion"`
	Note          string         `json:"note"`
	Sources       []recallSource `json:"sources"`
	Cases         []recallCase   `json:"cases"`
}

// recallGroup est la mesure d'une source pour une étiquette. Flagged compte les textes qui ont au moins un constat ;
// ByRule les textes signalés par chaque règle (un texte peut l'être par plusieurs). IDs liste les textes manqués
// (étiquette « consigne ») ou signalés (étiquettes « sain » et « autre »).
type recallGroup struct {
	Source  string         `json:"source"`
	Label   string         `json:"label"`
	Cases   int            `json:"cases"`
	Flagged int            `json:"flagged"`
	ByRule  map[string]int `json:"byRule"`
	IDs     []string       `json:"ids"`
}

type recallRecord struct {
	Note   string        `json:"note"`
	Groups []recallGroup `json:"groups"`
}

const recallRecordNote = "Relevé du rappel de injection.Find sur vectors/injection-recall.json, écrit par TestRecallCorpus (-update-recall). ids : textes manqués (consigne) ou signalés (sain, autre). Une mesure, pas une promesse."

var (
	hexDigest40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hexDigest64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func loadRecallCorpus(t testing.TB) recallCorpus {
	t.Helper()
	data, err := os.ReadFile(recallPath)
	if err != nil {
		t.Fatalf("lecture du corpus de rappel : %v", err)
	}
	for i, b := range data {
		if b > 0x7e || (b < 0x20 && b != '\n') {
			t.Fatalf("corpus de rappel : octet hors ASCII imprimable à la position %d (le fichier s'écrit en \\uXXXX)", i)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var corpus recallCorpus
	if err := decoder.Decode(&corpus); err != nil || corpus.FormatVersion != 1 {
		t.Fatalf("corpus de rappel illisible ou de format inconnu : %v", err)
	}
	return corpus
}

// TestRecallCorpusProvenance : chaque source porte dépôt, commit, licence (MIT ou Apache-2.0), détenteur des droits,
// chemin et empreinte ; chaque cas renvoie à une source, avec une étiquette connue et un identifiant unique.
func TestRecallCorpusProvenance(t *testing.T) {
	corpus := loadRecallCorpus(t)
	counts := map[string]int{}
	for _, c := range corpus.Cases {
		counts[c.Source]++
	}
	sources := map[string]bool{}
	for _, source := range corpus.Sources {
		sources[source.ID] = true
		if !strings.HasPrefix(source.Repository, "https://github.com/") || !hexDigest40.MatchString(source.Commit) || !hexDigest64.MatchString(source.SHA256) || source.Path == "" || source.Copyright == "" {
			t.Errorf("source %s : provenance incomplète", source.ID)
		}
		if source.License != "MIT" && source.License != "Apache-2.0" {
			t.Errorf("source %s : licence %q ni MIT ni Apache-2.0", source.ID, source.License)
		}
		if source.Cases == 0 || source.Cases != counts[source.ID] {
			t.Errorf("source %s : %d cas annoncés, %d présents", source.ID, source.Cases, counts[source.ID])
		}
	}
	for _, want := range []string{"llm-guard", "promptfoo", "akto", "skill-scanner"} {
		if !sources[want] {
			t.Errorf("source %s absente", want)
		}
	}
	seen := map[string]bool{}
	for _, c := range corpus.Cases {
		if seen[c.ID] || c.ID == "" || !strings.HasPrefix(c.ID, c.Source+"/") || !sources[c.Source] {
			t.Errorf("cas %s : identifiant en double, vide ou sans source", c.ID)
		}
		seen[c.ID] = true
		if c.Label != "consigne" && c.Label != "sain" && c.Label != "autre" {
			t.Errorf("cas %s : étiquette %q inconnue", c.ID, c.Label)
		}
		if c.Text == "" || len(c.Text) > MaxInputBytes {
			t.Errorf("cas %s : texte vide ou trop long", c.ID)
		}
	}
}

func measureRecall(t testing.TB, corpus recallCorpus) []recallGroup {
	t.Helper()
	index := map[string]*recallGroup{}
	var keys []string
	for _, c := range corpus.Cases {
		key := c.Source + "\x00" + c.Label
		group := index[key]
		if group == nil {
			group = &recallGroup{Source: c.Source, Label: c.Label, ByRule: map[string]int{}, IDs: []string{}}
			index[key] = group
			keys = append(keys, key)
		}
		group.Cases++
		report := Find([]byte(c.Text))
		if !report.Complete {
			t.Fatalf("%s : rapport incomplet", c.ID)
		}
		rules := map[Rule]bool{}
		for _, finding := range report.Findings {
			rules[finding.Rule] = true
		}
		for rule := range rules {
			group.ByRule[string(rule)]++
		}
		flagged := report.Total > 0
		if flagged {
			group.Flagged++
		}
		if flagged != (c.Label == "consigne") {
			group.IDs = append(group.IDs, c.ID)
		}
	}
	groups := make([]recallGroup, 0, len(keys))
	for _, key := range keys {
		sort.Strings(index[key].IDs)
		groups = append(groups, *index[key])
	}
	return groups
}

func rulesSummary(byRule map[string]int) string {
	var parts []string
	for _, rule := range Rules() {
		if n := byRule[string(rule)]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", strings.TrimPrefix(string(rule), "injection_"), n))
		}
	}
	return strings.Join(parts, ", ")
}

// TestRecallCorpus publie le taux de textes signalés par source, par étiquette et par règle, et refuse tout écart au
// relevé commité : une consigne signalée hier et manquée aujourd'hui, ou un texte sain signalé aujourd'hui, est un
// recul. Un progrès demande de réécrire le relevé (-update-recall), pour que les chiffres publiés restent ceux mesurés.
func TestRecallCorpus(t *testing.T) {
	groups := measureRecall(t, loadRecallCorpus(t))
	for _, group := range groups {
		t.Logf("%-14s %-9s %3d textes, %3d signalés (%3.0f %%) : %s", group.Source, group.Label, group.Cases, group.Flagged,
			100*float64(group.Flagged)/float64(group.Cases), rulesSummary(group.ByRule))
	}
	if *updateRecall {
		encoded, err := json.MarshalIndent(recallRecord{Note: recallRecordNote, Groups: groups}, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(recallRecordPath, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := os.ReadFile(recallRecordPath)
	if err != nil {
		t.Fatalf("relevé du rappel : %v", err)
	}
	var record recallRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("relevé du rappel illisible : %v", err)
	}
	recorded := map[string]recallGroup{}
	for _, group := range record.Groups {
		recorded[group.Source+"\x00"+group.Label] = group
	}
	if len(recorded) != len(groups) {
		t.Errorf("relevé : %d groupes, mesure : %d", len(recorded), len(groups))
	}
	for _, group := range groups {
		want, ok := recorded[group.Source+"\x00"+group.Label]
		if !ok {
			t.Errorf("%s/%s absent du relevé", group.Source, group.Label)
			continue
		}
		before := map[string]bool{}
		for _, id := range want.IDs {
			before[id] = true
		}
		now := map[string]bool{}
		for _, id := range group.IDs {
			now[id] = true
			if !before[id] {
				// Pour une consigne : manquée alors qu'elle était signalée. Pour un texte sain : signalé alors qu'il ne l'était pas.
				t.Errorf("recul : %s (%s)", id, group.Label)
			}
		}
		for _, id := range want.IDs {
			if !now[id] {
				t.Errorf("relevé périmé (-update-recall) : %s n'est plus dans la liste (%s)", id, group.Label)
			}
		}
		if want.Cases != group.Cases || want.Flagged != group.Flagged || fmt.Sprint(want.ByRule) != fmt.Sprint(group.ByRule) {
			t.Errorf("%s/%s : relevé %d/%d %v, mesure %d/%d %v (-update-recall après un changement voulu)", group.Source, group.Label,
				want.Flagged, want.Cases, want.ByRule, group.Flagged, group.Cases, group.ByRule)
		}
	}
}
