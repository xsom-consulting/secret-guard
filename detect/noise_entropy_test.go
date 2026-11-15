// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// noiseEntropyVectorsPath : corpus de bruit de l'entropie (vectors/noise-entropy.json) : identifiants générés longs
// et chemins d'URL à identifiant public, relevés sur un Poste réel, qui ne doivent rien signaler. Rejoué à chaque
// version, à côté de vectors/noise.json (TestNoiseCorpus) et du corpus de parité, qui garde les cas positifs.
const noiseEntropyVectorsPath = "../vectors/noise-entropy.json"

// TestNoiseEntropyCorpus : chaque cas donne une analyse complète sans aucun constat, avec les règles que LoadRules
// exécute comme avec les règles « à activer » en plus, en un fil et en plusieurs. Le diagnostic nomme le cas et la
// règle, jamais le texte.
func TestNoiseEntropyCorpus(t *testing.T) {
	raw, err := os.ReadFile(noiseEntropyVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var corpus noiseCorpus
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.FormatVersion != 1 || len(corpus.Cases) < 15 {
		t.Fatalf("corpus de bruit de l'entropie : version %d, %d cas", corpus.FormatVersion, len(corpus.Cases))
	}
	p := loadInitialPack(t)
	defaults, err := LoadRules(&p)
	if err != nil {
		t.Fatal(err)
	}
	everything := loadInitialRules(t)
	seen := map[string]bool{}
	families := map[string]int{}
	for _, c := range corpus.Cases {
		if seen[c.ID] {
			t.Fatalf("cas en double : %s", c.ID)
		}
		seen[c.ID] = true
		family, _, ok := strings.Cut(c.ID, "/")
		if !ok || c.Input == "" {
			t.Fatalf("cas mal formé : %s", c.ID)
		}
		families[family]++
		for _, rules := range []*Rules{defaults, everything} {
			for _, workers := range []int{1, 0} {
				result := Scan([]byte(c.Input), rules, Options{LanguageID: c.Language, Workers: workers})
				if !result.Complete {
					t.Errorf("%s : analyse incomplète (%v)", c.ID, result.Failure)
					continue
				}
				for _, f := range result.Findings {
					t.Errorf("%s : constat %s", c.ID, f.RuleID)
				}
			}
		}
	}
	// Les deux familles de la Story 27.6 sont présentes : identifiants générés et chemins d'URL.
	if families["identifiant"] < 8 || families["url"] < 5 {
		t.Fatalf("familles du corpus : %v", families)
	}
	t.Logf("%d cas de bruit d'entropie, familles %v", len(corpus.Cases), families)
}
