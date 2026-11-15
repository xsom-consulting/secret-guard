// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"sort"
	"testing"
)

// corpusForm rend les constats de Scan dans la forme du corpus de parité, triés comme lui.
func corpusForm(findings []Finding) []corpusFinding {
	out := make([]corpusFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, corpusFinding{
			RuleID: f.RuleID, SecretType: f.SecretType, Encoding: f.Encoding, Score: f.Score, Level: string(f.Level),
			ByteStart: f.ByteStart, ByteEnd: f.ByteEnd,
		})
	}
	sortCorpusFindings(out)
	return out
}

func sortCorpusFindings(findings []corpusFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.ByteStart != b.ByteStart {
			return a.ByteStart < b.ByteStart
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.ByteEnd < b.ByteEnd
	})
}

func loadInitialRules(t testing.TB) *Rules {
	t.Helper()
	p := loadInitialPack(t)
	// Toutes les règles, règles « à activer » comprises : le corpus éprouve chacune (TestOptInRules pour LoadRules).
	rules, err := LoadRulesWithOptIn(&p, OptInRuleIDs())
	if err != nil {
		t.Fatalf("Pack initial refusé : %v", err)
	}
	return rules
}
