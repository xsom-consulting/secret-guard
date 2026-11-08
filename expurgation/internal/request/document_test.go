// SPDX-License-Identifier: PolyForm-Small-Business-1.0.0

package request

import (
	"testing"

	"github.com/xsom-consulting/secret-guard/detect"
	"github.com/xsom-consulting/secret-guard/expurgation"
)

func TestExpurgation(t *testing.T) {
	result := detect.SanitizeResult{
		Failure: detect.SanitizeNone,
		Initial: detect.Result{Complete: true, Failure: detect.FailureNone},
		Final:   detect.Result{Complete: true, Failure: detect.FailureNone},
	}
	substitutions := []expurgation.Substitution{{RuleID: "github_token", SecretType: "provider_token", ByteStart: 2, ByteEnd: 42,
		UTF16Start: 2, UTF16End: 42, LocalFingerprint: "0123456789abcdef0123456789abcdef", Ordinal: 3, Replacement: "ghp_XXX3"}}
	want := `{"failure":"none","initial":{"complete":true,"failure":"none","findings":[]},"final":{"complete":true,"failure":"none","findings":[]},` +
		`"substitutions":[{"ruleId":"github_token","secretType":"provider_token","byteStart":2,"byteEnd":42,"utf16Start":2,"utf16End":42,` +
		`"localFingerprint":"0123456789abcdef0123456789abcdef","ordinal":3,"replacement":"ghp_XXX3"}]}` + "\n"
	if got := string(ExpurgationJSON(result, substitutions)); got != want {
		t.Fatalf("%s", got)
	}
	if got := string(ExpurgationJSON(detect.SanitizeResult{Failure: detect.SanitizeResidual}, nil)); got !=
		`{"failure":"residual","initial":{"complete":false,"failure":"","findings":[]},"final":{"complete":false,"failure":"","findings":[]},"substitutions":[]}`+"\n" {
		t.Fatalf("%s", got)
	}
}
