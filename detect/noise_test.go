// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"encoding/json"
	"os"
	"testing"
)

// noiseVectorsPath : corpus de bruit (vectors/noise.json) : textes ordinaires, relevés sur des Postes réels, qui ne
// doivent rien signaler. Rejoué à chaque version, à côté du corpus de parité, qui garde les cas positifs.
const noiseVectorsPath = "../vectors/noise.json"

type noiseCorpus struct {
	FormatVersion int    `json:"formatVersion"`
	About         string `json:"about"`
	Cases         []struct {
		ID       string `json:"id"`
		Input    string `json:"input"`
		Language string `json:"language"`
	} `json:"cases"`
}

// TestNoiseCorpus : chaque cas du corpus de bruit donne une analyse complète sans constat. Le diagnostic nomme le cas
// et la règle, jamais le texte.
func TestNoiseCorpus(t *testing.T) {
	raw, err := os.ReadFile(noiseVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var corpus noiseCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.FormatVersion != 1 || len(corpus.Cases) < 30 {
		t.Fatalf("corpus de bruit : version %d, %d cas", corpus.FormatVersion, len(corpus.Cases))
	}
	rules := loadInitialRules(t)
	seen := map[string]bool{}
	noisy := 0
	for _, c := range corpus.Cases {
		if seen[c.ID] {
			t.Fatalf("cas en double : %s", c.ID)
		}
		seen[c.ID] = true
		for _, workers := range []int{1, 0} {
			result := Scan([]byte(c.Input), rules, Options{LanguageID: c.Language, Workers: workers})
			if !result.Complete {
				t.Errorf("%s : analyse incomplète (%v)", c.ID, result.Failure)
				noisy++
				continue
			}
			for _, f := range result.Findings {
				t.Errorf("%s : constat %s", c.ID, f.RuleID)
				noisy++
			}
		}
	}
	t.Logf("%d cas de bruit, %d constats ou analyses incomplètes", len(corpus.Cases), noisy)
}
