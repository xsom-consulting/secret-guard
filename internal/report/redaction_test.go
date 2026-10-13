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
