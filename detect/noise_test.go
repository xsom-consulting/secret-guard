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

// noiseCorpusFiles : les fichiers de bruit du dépôt, tous de même format, et le nombre de cas au-dessous duquel un
// fichier a été vidé par erreur. TestNoiseCorpus les rejoue tous ; TestNoiseProviders et TestNoiseEntropyCorpus
// gardent ce qui est propre à leur fichier (motif de la règle qui reconnaît le texte, familles présentes).
var noiseCorpusFiles = []struct {
	path     string
	minCases int
}{
	{noiseVectorsPath, 30},
	{noiseProvidersPath, 280},
	{noiseEntropyVectorsPath, 15},
}

type noiseCorpus struct {
	FormatVersion int    `json:"formatVersion"`
	About         string `json:"about"`
	Cases         []struct {
		ID       string `json:"id"`
		Input    string `json:"input"`
		Language string `json:"language"`
	} `json:"cases"`
}

// TestNoiseCorpus : chaque cas de chaque fichier de bruit (noiseCorpusFiles) donne une analyse complète sans constat
// avec les règles que LoadRules exécute. Avec les règles « à activer » en plus (LoadRulesWithOptIn), seules celles-ci
// peuvent se déclencher, et chacune le fait au moins une fois : c'est le bruit qui la tient éteinte par défaut. Le
// diagnostic nomme le cas et la règle, jamais le texte.
func TestNoiseCorpus(t *testing.T) {
	p := loadInitialPack(t)
	defaults, err := LoadRules(&p)
	if err != nil {
		t.Fatal(err)
	}
	everything := loadInitialRules(t)
	optIn := map[string]bool{}
	for _, id := range OptInRuleIDs() {
		optIn[id] = false
	}
	seen := map[string]bool{}
	noisy := 0
	for _, file := range noiseCorpusFiles {
		raw, err := os.ReadFile(file.path)
		if err != nil {
			t.Fatal(err)
		}
		var corpus noiseCorpus
		if err := json.Unmarshal(raw, &corpus); err != nil {
			t.Fatalf("%s : %v", file.path, err)
		}
		if corpus.FormatVersion != 1 || len(corpus.Cases) < file.minCases {
			t.Fatalf("%s : version %d, %d cas", file.path, corpus.FormatVersion, len(corpus.Cases))
		}
		for _, c := range corpus.Cases {
			if seen[c.ID] {
				t.Fatalf("cas en double : %s", c.ID)
			}
			seen[c.ID] = true
			for _, workers := range []int{1, 0} {
				options := Options{LanguageID: c.Language, Workers: workers}
				result := Scan([]byte(c.Input), defaults, options)
				if !result.Complete {
					t.Errorf("%s : analyse incomplète (%v)", c.ID, result.Failure)
					noisy++
					continue
				}
				for _, f := range result.Findings {
					t.Errorf("%s : constat %s", c.ID, f.RuleID)
					noisy++
				}
				for _, f := range Scan([]byte(c.Input), everything, options).Findings {
					if _, known := optIn[f.RuleID]; !known {
						t.Errorf("%s : constat %s avec les règles à activer", c.ID, f.RuleID)
						continue
					}
					optIn[f.RuleID] = true
				}
			}
		}
	}
	for id, fired := range optIn {
		if !fired {
			t.Errorf("%s : règle à activer qu'aucun cas de bruit ne déclenche", id)
		}
	}
	t.Logf("%d cas de bruit dans %d fichiers, %d constats ou analyses incomplètes, %d règles à activer",
		len(seen), len(noiseCorpusFiles), noisy, len(optIn))
}
