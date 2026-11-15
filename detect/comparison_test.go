// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"testing"
)

// comparisonVectorsPath : banc de comparaison Betterleaks (vectors/comparison/betterleaks.json), écrit par
// generator/corpus/betterleaks.ts depuis les cas d'essai que chaque règle de Betterleaks porte dans son fichier source
// (lus, jamais exécutés ; MIT, origine dans UPSTREAM.md). C'est un banc, pas un corpus de parité : le fichier ne porte
// aucun résultat attendu de ce moteur.
const comparisonVectorsPath = "../vectors/comparison/betterleaks.json"

type comparisonCorpus struct {
	FormatVersion int `json:"formatVersion"`
	Source        struct {
		Repository  string `json:"repository"`
		Commit      string `json:"commit"`
		License     string `json:"license"`
		RulesDigest string `json:"rulesDigest"`
		UnreadCalls int    `json:"unreadCalls"`
	} `json:"source"`
	Cases []struct {
		ID     string `json:"id"`
		Rule   string `json:"rule"`
		File   string `json:"file"`
		Kind   string `json:"kind"`
		Name   string `json:"name"`
		Input  string `json:"input"`
		Secret string `json:"secret"`
	} `json:"cases"`
}

// comparisonFigures : les quatre chiffres du banc, en nombres de cas (les parts s'en déduisent).
type comparisonFigures struct {
	// Positives : cas positifs de Betterleaks (kind « match »), dénominateur des trois parts.
	Positives int
	// Found : positifs dont la valeur attendue est recouverte par un constat (rappel).
	Found int
	// Dedicated : positifs recouverts par le constat d'une règle dédiée (ni affectation, ni entropie).
	Dedicated int
	// Blocked : positifs recouverts par un constat que le préréglage bloque (DecisionForLevel : HIGH ou CRITICAL).
	Blocked int
	// LowDiversity : constats de règles de fournisseurs (motif seul, provider_token) sur les cas négatifs dont la valeur
	// est sans diversité (moins de 6 octets distincts, ou entropie de Shannon inférieure à 3,0).
	LowDiversity int
}

// comparisonBefore : chiffres mesurés avant la vraisemblance et les règles reprises (moteur v0.9.0, 345 règles),
// gardés pour la lecture du journal du test.
var comparisonBefore = comparisonFigures{Positives: 867, Found: 818, Dedicated: 397, Blocked: 725, LowDiversity: 62}

// comparisonFloor : chiffres de la version courante. Le test refuse une baisse du rappel, de la part par règle
// dédiée ou de la part bloquée, et une hausse des constats sans diversité. Une hausse d'un des trois premiers est
// permise : relever alors le plancher ici, avec la raison dans le message de commit.
var comparisonFloor = comparisonFigures{Positives: 867, Found: 826, Dedicated: 554, Blocked: 774, LowDiversity: 19}

// lowDiversity : seconde écriture, pour la mesure seulement, du contrôle de vraisemblance du moteur (validators.go).
func lowDiversity(value []byte) bool {
	var counts [256]int
	for _, b := range value {
		counts[b]++
	}
	distinct := 0
	entropy := 0.0
	for _, count := range counts {
		if count == 0 {
			continue
		}
		distinct++
		p := float64(count) / float64(len(value))
		entropy -= p * math.Log2(p)
	}
	return distinct < 6 || entropy < 3.0
}

// TestComparisonBetterleaks : banc rejoué à chaque version. Publie le rappel sur les positifs de Betterleaks, la part
// trouvée par une règle dédiée, la part bloquée par le préréglage et le nombre de constats sur des négatifs sans
// diversité, à côté des chiffres d'avant les règles reprises, et refuse une baisse. Le diagnostic nomme le cas et la
// règle, jamais la valeur.
func TestComparisonBetterleaks(t *testing.T) {
	raw, err := os.ReadFile(comparisonVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var corpus comparisonCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.FormatVersion != 1 || corpus.Source.License != "MIT" || len(corpus.Source.Commit) != 40 {
		t.Fatalf("banc : version %d, licence %q, commit %q", corpus.FormatVersion, corpus.Source.License, corpus.Source.Commit)
	}
	if len(corpus.Cases) != 1880 {
		t.Fatalf("banc : %d cas (1 880 attendus au commit épinglé)", len(corpus.Cases))
	}
	p := loadInitialPack(t)
	rules, err := LoadRules(&p)
	if err != nil {
		t.Fatal(err)
	}
	type kind struct{ family, secretType string }
	kinds := map[string]kind{}
	for _, spec := range p.Rules {
		kinds[spec.RuleID] = kind{string(spec.Family), string(spec.SecretType)}
	}
	generic := func(ruleID string) bool {
		family := kinds[ruleID].family
		return family == familyContextualAssignment || family == familyEntropy
	}
	var got comparisonFigures
	negatives := 0
	seen := map[string]bool{}
	var missed, undedicated []string
	for _, c := range corpus.Cases {
		if seen[c.ID] {
			t.Fatalf("cas en double : %s", c.ID)
		}
		seen[c.ID] = true
		input := []byte(c.Input)
		result := Scan(input, rules, Options{})
		if !result.Complete {
			t.Fatalf("%s : analyse incomplète (%v)", c.ID, result.Failure)
		}
		switch c.Kind {
		case "match":
			got.Positives++
			at := bytes.Index(input, []byte(c.Secret))
			if c.Secret == "" || at < 0 {
				t.Fatalf("%s : valeur attendue absente de l'entrée", c.ID)
			}
			found, dedicated, blocked := false, false, false
			for _, f := range result.Findings {
				if f.ByteStart >= at+len(c.Secret) || f.ByteEnd <= at {
					continue
				}
				found = true
				dedicated = dedicated || !generic(f.RuleID)
				blocked = blocked || DecisionForLevel(f.Level) == DecisionBlock
			}
			if found {
				got.Found++
			} else {
				missed = append(missed, c.ID)
			}
			if dedicated {
				got.Dedicated++
			} else if found {
				undedicated = append(undedicated, c.ID)
			}
			if blocked {
				got.Blocked++
			}
		case "no_match", "no_match_component":
			negatives++
			for _, f := range result.Findings {
				k := kinds[f.RuleID]
				if k.family == familyFixedPattern && k.secretType == "provider_token" && lowDiversity(input[f.ByteStart:f.ByteEnd]) {
					got.LowDiversity++
					t.Logf("%s : constat %s sur une valeur sans diversité", c.ID, f.RuleID)
				}
			}
		case "match_component":
			// Composant d'une règle composée (identifiant de client, nom d'utilisateur…) : pas un secret seul, hors mesure.
		default:
			t.Fatalf("%s : nature de cas inconnue %q", c.ID, c.Kind)
		}
	}
	if got.Positives != 867 || negatives != 931 {
		t.Fatalf("banc : %d positifs, %d négatifs (867 et 931 attendus)", got.Positives, negatives)
	}
	share := func(n int) float64 { return 100 * float64(n) / float64(got.Positives) }
	report := func(label string, f comparisonFigures) {
		t.Logf("%s : rappel %d/%d (%.1f %%), règle dédiée %d (%.1f %%), bloqué par le préréglage %d (%.1f %%), constats sur négatifs sans diversité %d",
			label, f.Found, f.Positives, share(f.Found), f.Dedicated, share(f.Dedicated), f.Blocked, share(f.Blocked), f.LowDiversity)
	}
	report("avant les règles reprises (v0.9.0)", comparisonBefore)
	report("cette version", got)
	t.Logf("positifs manqués : %d ; trouvés sans règle dédiée : %d", len(missed), len(undedicated))
	if os.Getenv("SECRET_GUARD_COMPARISON_DETAIL") != "" {
		t.Logf("manqués : %v", missed)
		t.Logf("sans règle dédiée : %v", undedicated)
	}
	if got.Found < comparisonFloor.Found {
		t.Errorf("rappel en baisse : %d positifs trouvés, plancher %d", got.Found, comparisonFloor.Found)
	}
	if got.Dedicated < comparisonFloor.Dedicated {
		t.Errorf("part par règle dédiée en baisse : %d, plancher %d", got.Dedicated, comparisonFloor.Dedicated)
	}
	if got.Blocked < comparisonFloor.Blocked {
		t.Errorf("part bloquée par le préréglage en baisse : %d, plancher %d", got.Blocked, comparisonFloor.Blocked)
	}
	if got.LowDiversity > comparisonFloor.LowDiversity {
		t.Errorf("constats sur négatifs sans diversité en hausse : %d, plafond %d", got.LowDiversity, comparisonFloor.LowDiversity)
	}
}
