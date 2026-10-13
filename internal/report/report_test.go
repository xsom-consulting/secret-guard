package report

import (
	"reflect"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/detect"
)

func TestReport(t *testing.T) {
	t.Run("codes de sortie : 0 propre, 1 constat, 2 analyse incomplète", func(t *testing.T) {
		clean := detect.Result{Complete: true, Failure: detect.FailureNone}
		found := detect.Result{Complete: true, Failure: detect.FailureNone, Findings: []detect.Finding{{RuleID: "r"}}}
		for _, c := range []struct {
			result detect.Result
			code   int
		}{
			{clean, ExitClean}, {found, ExitFindings},
			{detect.Result{Failure: detect.FailureScanLimit}, ExitError},
			{detect.Result{Failure: detect.FailureScanError}, ExitError},
			{detect.Result{Complete: true, Failure: detect.FailureScanError}, ExitError},
		} {
			if got := ExitCode(c.result); got != c.code {
				t.Errorf("%+v : %d, attendu %d", c.result, got, c.code)
			}
		}
	})
	t.Run("document JSON : champs du constat, Empreinte locale seulement si calculée", func(t *testing.T) {
		result := detect.Result{Complete: true, Failure: detect.FailureNone, Findings: []detect.Finding{
			{RuleID: "github_token", SecretType: "provider_token", Encoding: detect.EncodingBase64, Score: 90,
				Level: detect.LevelCritical, ByteStart: 3, ByteEnd: 43},
			{RuleID: "jwt", SecretType: "jwt", Encoding: detect.EncodingPlain, Score: 60, Level: detect.LevelHigh,
				ByteStart: 50, ByteEnd: 90, LocalFingerprint: strings.Repeat("ab", 16)},
		}}
		want := `{"complete":true,"failure":"none","findings":[` +
			`{"ruleId":"github_token","secretType":"provider_token","encoding":"base64","score":90,"level":"CRITICAL","byteStart":3,"byteEnd":43},` +
			`{"ruleId":"jwt","secretType":"jwt","encoding":"plain","score":60,"level":"HIGH","byteStart":50,"byteEnd":90,"localFingerprint":"` +
			strings.Repeat("ab", 16) + `"}]}` + "\n"
		if got := string(JSON(result)); got != want {
			t.Fatalf("%s", got)
		}
		if got := string(JSON(detect.Result{Failure: detect.FailureScanError})); got != `{"complete":false,"failure":"scan_error","findings":[]}`+"\n" {
			t.Fatalf("%s", got)
		}
	})
	t.Run("le constat JSON a exactement les champs publics du constat du moteur", func(t *testing.T) {
		var engine, public []string
		for i := range reflect.TypeFor[detect.Finding]().NumField() {
			engine = append(engine, reflect.TypeFor[detect.Finding]().Field(i).Name)
		}
		for i := range reflect.TypeFor[Finding]().NumField() {
			public = append(public, reflect.TypeFor[Finding]().Field(i).Name)
		}
		if !reflect.DeepEqual(engine, public) {
			t.Fatalf("moteur %v, document %v", engine, public)
		}
	})
}
