package report

import (
	"testing"

	"github.com/xsom-consulting/secret-guard/detect"
)

func TestRedaction(t *testing.T) {
	t.Run("document du masquage : issue, analyses initiale et finale, aucun texte", func(t *testing.T) {
		result := detect.SanitizeResult{
			Failure: detect.SanitizeNone,
			Initial: detect.Result{Complete: true, Failure: detect.FailureNone, Findings: []detect.Finding{
				{RuleID: "github_token", SecretType: "provider_token", Encoding: detect.EncodingPlain, Score: 95,
					Level: detect.LevelCritical, ByteStart: 6, ByteEnd: 46},
			}},
			Final: detect.Result{Complete: true, Failure: detect.FailureNone},
		}
		want := `{"failure":"none","initial":{"complete":true,"failure":"none","findings":[` +
			`{"ruleId":"github_token","secretType":"provider_token","encoding":"plain","score":95,"level":"CRITICAL","byteStart":6,"byteEnd":46}]},` +
			`"final":{"complete":true,"failure":"none","findings":[]}}` + "\n"
		if got := string(RedactionJSON(result)); got != want {
			t.Fatalf("%s", got)
		}
		incomplete := detect.Result{Failure: detect.FailureScanLimit}
		got := string(RedactionJSON(detect.SanitizeResult{Failure: detect.SanitizeIncomplete, Initial: incomplete, Final: incomplete}))
		if got != `{"failure":"incomplete","initial":{"complete":false,"failure":"scan_limit","findings":[]},"final":{"complete":false,"failure":"scan_limit","findings":[]}}`+"\n" {
			t.Fatalf("%s", got)
		}
	})
}

func TestExpurgation(t *testing.T) {
	result := detect.SanitizeResult{
		Failure: detect.SanitizeNone,
		Initial: detect.Result{Complete: true, Failure: detect.FailureNone},
		Final:   detect.Result{Complete: true, Failure: detect.FailureNone},
	}
	substitutions := []detect.Substitution{{RuleID: "github_token", SecretType: "provider_token", ByteStart: 2, ByteEnd: 42,
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
