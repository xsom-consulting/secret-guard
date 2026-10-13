package detect

import (
	"reflect"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/pack"
)

func TestPackValidator(t *testing.T) {
	t.Run("une règle « motif seul » du Pack applique son validateur nommé, et seulement avec le décodage structuré", func(t *testing.T) {
		p := pack.Pack{SchemaVersion: 1, PackVersion: 3, Rules: []pack.Rule{{
			RuleID: "corpus_token", Family: familyFixedPattern, SecretType: "jwt", Score: 66, Validator: "jwt_structure",
			Pattern: `\btok=([A-Za-z0-9_.-]+)`,
		}}}
		rules, err := LoadRules(&p)
		if err != nil {
			t.Fatal(err)
		}
		valid := jwtValue()
		invalid := strings.Replace(valid, "eyJ", "eyX", 1)
		text := []byte("tok=" + invalid + " tok=" + valid)
		budget := &decodeBudget{}
		findings, err := rules.scanFixedRules(identityView(text), budget, true)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range findings {
			got = append(got, string(text[f.start:f.end]))
		}
		if !reflect.DeepEqual(got, []string{valid}) || budget.candidates == 0 {
			t.Fatalf("valeurs %v, décodages %d", got, budget.candidates)
		}
		if findings, _ := rules.scanFixedRules(identityView(text), &decodeBudget{}, false); len(findings) != 0 {
			t.Fatalf("règle à validateur exécutée sans décodage structuré : %d constats", len(findings))
		}
	})
}
