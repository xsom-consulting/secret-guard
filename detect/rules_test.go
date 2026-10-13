// Apache-2.0 : les scores, raisons et pénalités attendus sont ceux de secret-guard/packages/core/src/rules.ts ; origine,
// avis et modifications dans UPSTREAM.md.

package detect

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/pack"
)

func clonePack(p pack.Pack) pack.Pack {
	clone := p
	clone.Rules = append([]pack.Rule(nil), p.Rules...)
	return clone
}

func removeRule(rules []pack.Rule, id string) []pack.Rule {
	kept := make([]pack.Rule, 0, len(rules))
	for _, r := range rules {
		if r.RuleID != id {
			kept = append(kept, r)
		}
	}
	return kept
}

func ruleIndex(t *testing.T, p pack.Pack, id string) int {
	t.Helper()
	for i, r := range p.Rules {
		if r.RuleID == id {
			return i
		}
	}
	t.Fatalf("règle %s absente du Pack initial", id)
	return -1
}

func TestPackUnusable(t *testing.T) {
	initial := loadInitialPack(t)
	if _, err := LoadRules(&initial); err != nil {
		t.Fatalf("le Pack initial doit se charger : %v", err)
	}
	cases := []struct {
		name   string
		mutate func(p *pack.Pack)
		reason PackRefusal
	}{
		{"famille inconnue du moteur", func(p *pack.Pack) { p.Rules[2].Family = "magic" }, RefusalUnknownFamily},
		{"type de secret inconnu", func(p *pack.Pack) { p.Rules[2].SecretType = "magic" }, RefusalUnknownSecretType},
		{"validateur inconnu", func(p *pack.Pack) { p.Rules[2].Validator = "luhn" }, RefusalUnknownValidator},
		{"motif qui ne compile pas en RE2 (regard arrière)", func(p *pack.Pack) { p.Rules[2].Pattern = `(?<=a)b` }, RefusalPatternNotRE2},
		{"motif qui ne compile pas en RE2 (rétro-référence)", func(p *pack.Pack) { p.Rules[2].Pattern = `(a)\1` }, RefusalPatternNotRE2},
		{"motif qui ne compile pas en RE2 (répétition > 1 000)", func(p *pack.Pack) { p.Rules[2].Pattern = `a{1,2048}` }, RefusalPatternNotRE2},
		{"motif vide hors affectation contextuelle", func(p *pack.Pack) { p.Rules[2].Pattern = "" }, RefusalPatternRequired},
		{"bornes inversées", func(p *pack.Pack) { p.Rules[2].MinLength, p.Rules[2].MaxLength = 10, 5 }, RefusalInvalidBounds},
		{"borne négative", func(p *pack.Pack) { p.Rules[2].MinLength = -1 }, RefusalInvalidBounds},
		{"borne sans motif", func(p *pack.Pack) {
			p.Rules[ruleIndex(t, *p, "contextual_password")].MaxLength = 5
		}, RefusalInvalidBounds},
		{"score hors de 0..100", func(p *pack.Pack) { p.Rules[2].Score = 101 }, RefusalInvalidScore},
		{"identifiant en double", func(p *pack.Pack) { p.Rules[3].RuleID = p.Rules[2].RuleID }, RefusalDuplicateRule},
		{"règle de famille du moteur inconnue de lui", func(p *pack.Pack) {
			p.Rules[ruleIndex(t, *p, "high_entropy")].RuleID = "entropy_v2"
		}, RefusalUnknownEngineRule},
		{"motif d'une règle du moteur modifié", func(p *pack.Pack) {
			p.Rules[ruleIndex(t, *p, "jwt")].Pattern = `\beyJ[A-Za-z0-9_-]{4,}`
		}, RefusalEngineMismatch},
		{"bornes d'une règle du moteur modifiées", func(p *pack.Pack) {
			p.Rules[ruleIndex(t, *p, "cli_basic_auth")].MaxLength = 2_000
		}, RefusalEngineMismatch},
		{"famille d'une règle du moteur modifiée", func(p *pack.Pack) {
			p.Rules[ruleIndex(t, *p, "jwt")].Family = familyEntropy
		}, RefusalEngineMismatch},
		{"type de secret d'une règle du moteur modifié", func(p *pack.Pack) {
			p.Rules[ruleIndex(t, *p, "contextual_password")].SecretType = "api_key"
		}, RefusalEngineMismatch},
		{"validateur retiré d'une règle du moteur", func(p *pack.Pack) {
			p.Rules[ruleIndex(t, *p, "jwt")].Validator = ""
		}, RefusalEngineMismatch},
		{"Pack sans règle", func(p *pack.Pack) { p.Rules = nil }, RefusalNoRule},
		{"motif qui reconnaît le texte vide", func(p *pack.Pack) { p.Rules[2].Pattern = `x*` }, RefusalPatternMatchesEmpty},
		{"motif qui ne reconnaît qu'une limite de mot", func(p *pack.Pack) { p.Rules[2].Pattern = `\b(?:a?)\b` }, RefusalPatternMatchesEmpty},
		{"clé privée complète sans la règle incomplète", func(p *pack.Pack) {
			p.Rules = removeRule(p.Rules, "private_key_pem_incomplete")
		}, RefusalIncompleteEngineFamily},
		{"clé privée incomplète sans la règle complète", func(p *pack.Pack) {
			p.Rules = removeRule(p.Rules, "private_key_pem")
		}, RefusalIncompleteEngineFamily},
		{"URL de base de données sans l'URL à identifiants", func(p *pack.Pack) {
			p.Rules = removeRule(p.Rules, "basic_auth_url")
		}, RefusalIncompleteEngineFamily},
		{"affectation contextuelle d'un seul type retirée", func(p *pack.Pack) {
			p.Rules = removeRule(p.Rules, "contextual_api_key")
		}, RefusalIncompleteEngineFamily},
	}
	for _, c := range cases {
		t.Run("un Pack de règles inexploitable est refusé en entier — "+c.name, func(t *testing.T) {
			p := clonePack(initial)
			c.mutate(&p)
			rules, err := LoadRules(&p)
			if rules != nil || !errors.Is(err, ErrPackUnusable) {
				t.Fatalf("Pack accepté (%v)", err)
			}
			var refusal *PackError
			if !errors.As(err, &refusal) || refusal.Reason != c.reason {
				t.Fatalf("raison %v, attendu %s", err, c.reason)
			}
			for _, r := range p.Rules {
				if r.Pattern != "" && strings.Contains(err.Error(), r.Pattern) {
					t.Fatal("le message cite un motif")
				}
			}
		})
	}
	t.Run("un identifiant de règle hors forme n'entre pas dans le message", func(t *testing.T) {
		p := clonePack(initial)
		p.Rules[2].RuleID = "Secret Value!"
		p.Rules[2].Family = "magic"
		_, err := LoadRules(&p)
		var refusal *PackError
		if !errors.As(err, &refusal) || refusal.RuleID != "" || strings.Contains(err.Error(), "Secret") {
			t.Fatalf("message %q", err)
		}
	})
	t.Run("Pack absent", func(t *testing.T) {
		if _, err := LoadRules(nil); !errors.Is(err, ErrPackUnusable) {
			t.Fatalf("erreur %v", err)
		}
	})
}

func TestEngineRulesMatchInitialPack(t *testing.T) {
	t.Run("chaque règle dont le moteur porte la logique est celle du Pack initial", func(t *testing.T) {
		p := loadInitialPack(t)
		byID := map[string]pack.Rule{}
		for _, r := range p.Rules {
			byID[r.RuleID] = r
		}
		engine := 0
		for _, e := range engineRules {
			r, ok := byID[e.ruleID]
			if !ok {
				t.Fatalf("%s absente du Pack initial", e.ruleID)
			}
			if string(r.Family) != e.family || string(r.SecretType) != e.secretType || r.Validator != e.validator ||
				r.Pattern != e.pattern || r.MinLength != e.minLength || r.MaxLength != e.maxLength {
				t.Errorf("%s : moteur et Pack diffèrent", e.ruleID)
			}
			engine++
		}
		for _, r := range p.Rules {
			isEngine := r.Family != familyFixedPattern || r.RuleID == ruleJWT
			found := false
			for _, e := range engineRules {
				found = found || e.ruleID == r.RuleID
			}
			if isEngine != found {
				t.Errorf("%s : règle du moteur %v, listée %v", r.RuleID, isEngine, found)
			}
		}
		if engine != 16 {
			t.Fatalf("%d règles du moteur, attendu 16", engine)
		}
	})
	t.Run("familles et types de secret du moteur sont ceux du schéma RulePack généré", func(t *testing.T) {
		data, err := os.ReadFile("../schema/RulePack.json")
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			Properties struct {
				Rules struct {
					Items struct {
						Properties struct {
							Family     struct{ Enum []string } `json:"family"`
							SecretType struct{ Enum []string } `json:"secretType"`
						} `json:"properties"`
					} `json:"items"`
				} `json:"rules"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(data, &schema); err != nil {
			t.Fatal(err)
		}
		item := schema.Properties.Rules.Items.Properties
		for _, c := range []struct {
			name   string
			schema []string
			engine map[string]bool
		}{{"familles", item.Family.Enum, knownFamilies}, {"types de secret", item.SecretType.Enum, knownSecretTypes}} {
			if len(c.schema) == 0 || len(c.schema) != len(c.engine) {
				t.Fatalf("%s : schéma %v, moteur %d", c.name, c.schema, len(c.engine))
			}
			for _, value := range c.schema {
				if !c.engine[value] {
					t.Errorf("%s : %q absent du moteur", c.name, value)
				}
			}
		}
	})
	t.Run("les validateurs du moteur sont la liste fermée RULE_VALIDATORS du générateur", func(t *testing.T) {
		ruleValidators := generatorValidators(t)
		if len(ruleValidators) != len(validators) {
			t.Fatalf("%d validateurs, liste fermée %d", len(validators), len(ruleValidators))
		}
		for _, name := range ruleValidators {
			if _, ok := validators[name]; !ok {
				t.Errorf("validateur %q absent du moteur", name)
			}
		}
	})
}

// generatorValidators lit la liste fermée RULE_VALIDATORS du schéma Zod du générateur (generator/src/rule-pack.ts),
// source de la règle « validator » de docs/rule-pack.md.
func generatorValidators(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("../generator/src/rule-pack.ts")
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`(?m)^export const RULE_VALIDATORS = \[([^\]]*)\] as const;$`).FindSubmatch(data)
	if match == nil {
		t.Fatal("RULE_VALIDATORS introuvable dans generator/src/rule-pack.ts")
	}
	var names []string
	for _, item := range regexp.MustCompile(`'([a-z0-9_]*)'`).FindAllSubmatch(match[1], -1) {
		names = append(names, string(item[1]))
	}
	if len(names) == 0 {
		t.Fatal("RULE_VALIDATORS vide")
	}
	return names
}

// entropyValue : valeur de forte entropie, construite à l'exécution (aucun secret écrit dans le dépôt).
func entropyValue(n int) string {
	const alphabet = "aB3dE5fG7hJ9kL1mN2pQrS4tU6vW8xY0z"
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(alphabet[(i*7)%len(alphabet)])
	}
	return b.String()
}

func jwtValue() string {
	enc := base64.RawURLEncoding.EncodeToString
	return strings.Join([]string{enc([]byte(`{"alg":"HS256","typ":"JWT"}`)), enc([]byte(`{"sub":"corpus"}`)), entropyValue(43)}, ".")
}

var allEncodings = []Encoding{
	EncodingPlain, EncodingNormalized, EncodingPercent, EncodingJSONEscaped, EncodingWhitespaceJoined, EncodingBase64,
}

// Raisons et pénalités de Secret Guard par vue, écrites telles qu'à l'origine.
var (
	expectedEncodingReasons = map[Encoding][]string{
		EncodingPlain:            {"fixed_format_match"},
		EncodingNormalized:       {"fixed_format_match", "unicode_normalization"},
		EncodingPercent:          {"fixed_format_match", "single_level_percent_decode"},
		EncodingJSONEscaped:      {"fixed_format_match", "single_level_json_unicode_decode"},
		EncodingWhitespaceJoined: {"fixed_format_match", "bounded_line_join"},
		EncodingBase64:           {"fixed_format_match", "single_level_base64_decode"},
	}
	expectedPenalty = map[Encoding]int{
		EncodingPlain: 0, EncodingNormalized: 0, EncodingPercent: 5, EncodingJSONEscaped: 5, EncodingWhitespaceJoined: 5,
		EncodingBase64: 5,
	}
)

// allFindings exécute toutes les familles sur une vue.
func allFindings(t *testing.T, rules *Rules, v *view) []finding {
	t.Helper()
	fixed, err := rules.scanFixedRules(v, &decodeBudget{}, true)
	if err != nil {
		t.Fatal(err)
	}
	contextual, err := rules.scanContextualAssignments(v, &decodeBudget{}, language{}, true)
	if err != nil {
		t.Fatal(err)
	}
	out := append(fixed, rules.scanCredentialURLs(v)...)
	out = append(out, contextual...)
	return append(out, rules.scanEntropy(v)...)
}

func TestRuleScoresAndReasons(t *testing.T) {
	rules := loadInitialRules(t)
	value := entropyValue(20)
	low := "hunter" + "two"
	pem := func(label string) string { return "-----" + "BEGIN " + label + "-----" }
	pemEnd := func(label string) string { return "-----" + "END " + label + "-----" }
	keyLabel := "RSA PRIVATE" + " KEY"
	// Client HTTP assemblé à l'exécution : la recherche de secrets du dépôt ne lit pas « curl -u » dans ce fichier.
	httpClient := "cu" + "rl"
	// fixedReasons, decodingOnly : raisons des règles fixes, puis celles des familles qui n'ajoutent que la vue.
	fixedReasons := func(e Encoding, extra ...string) []string {
		return append(append([]string(nil), expectedEncodingReasons[e]...), extra...)
	}
	decodingOnly := func(e Encoding, first ...string) []string {
		return append(append([]string(nil), first...), expectedEncodingReasons[e][1:]...)
	}
	type expectation struct {
		id, input string
		score     int
		reasons   func(Encoding) []string
		noPenalty func(Encoding) bool
	}
	fixed := func(id, input string, score int) expectation {
		return expectation{id: id, input: input, score: score, reasons: func(e Encoding) []string { return fixedReasons(e) }}
	}
	contextual := func(id, input string, score int, extra ...string) expectation {
		return expectation{id: id, input: input, score: score, reasons: func(e Encoding) []string {
			return append(append([]string{"sensitive_variable_name", "structured_assignment"}, extra...), expectedEncodingReasons[e][1:]...)
		}}
	}
	other := func(id, input, reason string) expectation {
		return expectation{id: id, input: input, score: 70, reasons: func(e Encoding) []string {
			return decodingOnly(e, reason, "structured_assignment")
		}}
	}
	cases := []expectation{
		{id: "private_key_pem", input: pem(keyLabel) + "\n" + value + "\n" + pemEnd(keyLabel), score: 100,
			reasons: func(e Encoding) []string { return fixedReasons(e, "complete_private_key_block") }},
		{id: "private_key_pem_incomplete", input: pem(keyLabel) + "\n" + value, score: 90,
			reasons: func(e Encoding) []string { return fixedReasons(e, "private_key_header_without_bounded_end") }},
		fixed("github_fine_grained_pat", "github_pat_"+strings.Repeat("aB3d_", 8), 95),
		fixed("github_token", "ghp_"+strings.Repeat("aB3d", 9), 95),
		fixed("gitlab_pat", "glpat-"+strings.Repeat("aB3d", 5), 95),
		fixed("openrouter_key", "sk-or-v1-"+strings.Repeat("aB3d", 8), 95),
		fixed("anthropic_key", "sk-ant-api03-"+strings.Repeat("aB3d", 6), 95),
		fixed("openai_key", "sk-proj-"+strings.Repeat("aB3d", 6), 92),
		fixed("stripe_secret_key", "sk_live_"+strings.Repeat("aB3d", 6), 95),
		fixed("slack_token", "xoxb-"+strings.Repeat("aB3d", 4), 95),
		fixed("slack_webhook", "https://hooks.slack.com/services/"+strings.Repeat("aB3d/", 5), 95),
		fixed("google_api_key", "AIza"+strings.Repeat("aB3d_", 7), 90),
		fixed("google_oauth_token", "ya29."+strings.Repeat("aB3d", 6), 95),
		fixed("sendgrid_key", "SG."+strings.Repeat("aB", 11)+"."+strings.Repeat("aB3", 14)+"a", 95),
		fixed("npm_token", "npm_"+strings.Repeat("aB3d", 9), 95),
		fixed("huggingface_token", "hf_"+strings.Repeat("aB", 17), 95),
		fixed("databricks_pat", "dapi"+strings.Repeat("a1b2", 8), 95),
		fixed("digitalocean_token", "dop_v1_"+strings.Repeat("a1b2", 16), 95),
		fixed("shopify_token", "shpat_"+strings.Repeat("a1b2", 8), 95),
		fixed("azure_storage_key", "AccountKey="+strings.Repeat("aB3d", 11)+"==", 95),
		fixed("aws_access_key_id", "AKIA"+strings.Repeat("B3D7", 4), 45),
		fixed("jwt", jwtValue(), 60),
		{id: "database_url_credentials", input: "postgres://app:" + value + "@db.example.test/app", score: 95,
			reasons: func(e Encoding) []string { return decodingOnly(e, "credential_bearing_url") }},
		{id: "basic_auth_url", input: "https://app:" + value + "@example.test/", score: 90,
			reasons: func(e Encoding) []string { return decodingOnly(e, "credential_bearing_url") }},
		contextual("contextual_password", "password = "+low, 70),
		contextual("contextual_private_key", "private_key = "+low, 70),
		contextual("contextual_cloud_credential", "aws_secret_access_key = "+low, 70),
		contextual("contextual_api_key", "api_key = "+value, 75, "value_shape_supports_secret"),
		contextual("contextual_access_token", "token = "+low, 70),
		contextual("contextual_generic_secret", "client_secret = "+low, 70),
		contextual("contextual_database_credentials", "DATABASE_URL = Password="+low, 70),
		other("cookie_session_credential", "Cookie: session="+value, "credential_cookie_header"),
		other("cli_basic_auth", httpClient+" -u alice:"+low+" https://example.test", "basic_auth_command_argument"),
		other("docker_auth", `{"auth":"`+base64.StdEncoding.EncodeToString([]byte("alice:"+low))+`"}`, "docker_auth_base64_credentials"),
		{id: "high_entropy", input: "note " + value + " fin", score: 35,
			reasons: func(e Encoding) []string {
				reasons := []string{"high_entropy_shape", "unanchored_entropy_is_warning_only"}
				if e == EncodingNormalized {
					reasons = append(reasons, "unicode_normalization")
				}
				return reasons
			},
			noPenalty: func(e Encoding) bool { return e == EncodingNormalized }},
	}
	p := loadInitialPack(t)
	if len(cases) != len(p.Rules) {
		t.Fatalf("%d règles testées, %d dans le Pack", len(cases), len(p.Rules))
	}
	for _, c := range cases {
		t.Run("règle "+c.id+" : score, raisons et pénalité d'encodage de Secret Guard", func(t *testing.T) {
			for _, e := range allEncodings {
				v := &view{text: []byte(c.input), encoding: e}
				var got *finding
				for _, f := range allFindings(t, rules, v) {
					if f.ruleID == c.id {
						f := f
						got = &f
						break
					}
				}
				if got == nil {
					t.Fatalf("%s : aucun constat", e)
				}
				want := c.score - expectedPenalty[e]
				if c.noPenalty != nil && c.noPenalty(e) {
					want = c.score
				}
				if got.score != want || got.encoding != e {
					t.Errorf("%s : score %d, attendu %d", e, got.score, want)
				}
				if !reflect.DeepEqual(got.reasons, c.reasons(e)) {
					t.Errorf("%s : raisons %v, attendu %v", e, got.reasons, c.reasons(e))
				}
			}
		})
	}
}

func TestRulesFromPack(t *testing.T) {
	initial := loadInitialPack(t)
	t.Run("une règle « motif seul » du Pack est exécutée telle qu'il la décrit (groupe 1, bornes, score)", func(t *testing.T) {
		p := pack.Pack{SchemaVersion: 1, PackVersion: 2, Rules: []pack.Rule{{
			RuleID: "corpus_code", Family: familyFixedPattern, SecretType: "api_key", Score: 81,
			Pattern: `\bzz_([a-z]+)\b`, MinLength: 5, MaxLength: 6,
		}}}
		rules, err := LoadRules(&p)
		if err != nil {
			t.Fatal(err)
		}
		text := []byte("zz_abcd zz_abcde zz_abcdef zz_abcdefg")
		findings, err := rules.scanFixedRules(identityView(text), &decodeBudget{}, true)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range findings {
			got = append(got, string(text[f.start:f.end]))
			if f.ruleID != "corpus_code" || f.secretType != "api_key" || f.score != 81 {
				t.Errorf("constat %+v", f)
			}
		}
		if !reflect.DeepEqual(got, []string{"abcde", "abcdef"}) {
			t.Fatalf("valeurs %v", got)
		}
	})
	t.Run("une règle absente du Pack (famille entière) n'est pas exécutée", func(t *testing.T) {
		p := clonePack(initial)
		kept := p.Rules[:0]
		for _, r := range p.Rules {
			if r.RuleID != "github_token" && !strings.HasPrefix(r.RuleID, "contextual_") && r.RuleID != "high_entropy" {
				kept = append(kept, r)
			}
		}
		p.Rules = kept
		rules, err := LoadRules(&p)
		if err != nil {
			t.Fatal(err)
		}
		text := "ghp_" + strings.Repeat("aB3d", 9) + " password = hunter2 " + entropyValue(24)
		for _, f := range allFindings(t, rules, identityView([]byte(text))) {
			if f.ruleID == "github_token" || strings.HasPrefix(f.ruleID, "contextual_") || f.ruleID == "high_entropy" {
				t.Fatalf("règle retirée exécutée : %s", f.ruleID)
			}
		}
	})
	t.Run("le score de base vient du Pack", func(t *testing.T) {
		p := clonePack(initial)
		p.Rules[ruleIndex(t, p, "contextual_password")].Score = 40
		rules, err := LoadRules(&p)
		if err != nil {
			t.Fatal(err)
		}
		findings := allFindings(t, rules, &view{text: []byte("password = hunter2"), encoding: EncodingPercent})
		if len(findings) != 1 || findings[0].score != 35 {
			t.Fatalf("constats %+v", findings)
		}
	})
}

func TestRulesHas(t *testing.T) {
	t.Run("Has reconnaît chaque règle du Pack chargé et rien d'autre", func(t *testing.T) {
		p := loadInitialPack(t)
		rules, err := LoadRules(&p)
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range p.Rules {
			if !rules.Has(rule.RuleID) {
				t.Fatalf("Has(%q) = faux pour une règle du Pack", rule.RuleID)
			}
		}
		for _, other := range []string{"", "check.internal_error", "unknown_rule", "JWT", "jwt "} {
			if rules.Has(other) {
				t.Fatalf("Has(%q) = vrai hors du Pack", other)
			}
		}
		var none *Rules
		if none.Has("jwt") || (&Rules{}).Has("jwt") {
			t.Fatal("Has doit être faux pour un Pack non chargé")
		}
	})
}
