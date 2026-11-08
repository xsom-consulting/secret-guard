// SPDX-License-Identifier: Apache-2.0

package detect

import "testing"

// TestSecretRangeBounds : une étendue hors du contenu est rendue telle quelle, sans lecture ; FirstLineSecretEnd
// refuse des règles absentes, un constat du client et une étendue hors du contenu.
func TestSecretRangeBounds(t *testing.T) {
	content := []byte("TOKEN=" + syntheticGitHubToken())
	for _, f := range []Finding{
		{RuleID: ruleDatabaseURL, ByteStart: -1, ByteEnd: 3},
		{RuleID: ruleDatabaseURL, ByteStart: 4, ByteEnd: 2},
		{RuleID: rulePrivateKeyComplete, ByteStart: 0, ByteEnd: len(content) + 1},
	} {
		if start, end := SecretRange(content, f); start != f.ByteStart || end != f.ByteEnd {
			t.Errorf("%+v : %d..%d", f, start, end)
		}
	}
	rules := loadInitialRules(t)
	result := Scan(content, rules, Options{})
	if !result.Complete || len(result.Findings) != 1 {
		t.Fatalf("%+v", result)
	}
	f := result.Findings[0]
	if start, end := SecretRange(content, f); start != f.ByteStart || end != f.ByteEnd {
		t.Errorf("jeton : %d..%d, étendue entière attendue", start, end)
	}
	var none *Rules
	for _, c := range []struct {
		rules *Rules
		f     Finding
	}{
		{none, f}, {&Rules{}, f}, {rules, Finding{RuleID: f.RuleID, ByteStart: 0, ByteEnd: len(content) + 1}},
		{rules, Finding{RuleID: f.RuleID, ByteStart: -1, ByteEnd: 1}},
		{rules, Finding{RuleID: customRulePrefix + "interne", ByteStart: f.ByteStart, ByteEnd: f.ByteEnd}},
	} {
		if end, ok := c.rules.FirstLineSecretEnd(content, c.f); ok || end != 0 {
			t.Errorf("%+v : %d %t", c.f, end, ok)
		}
	}
}
