// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/pack"
)

// contextRuleScores : règles de données à contexte du Pack initial (v0.9.0, puis identifiants européens et français
// et règle composée AWS de la v0.10.0), dans l'ordre du Pack, leur score et leur validateur nommé (vide : aucun).
var contextRuleScores = []struct {
	id        string
	score     int
	validator string
}{
	{"email_address", 30, ""}, {"phone_number", 30, ""}, {"passport_number", 60, ""},
	{"payment_card_security_code", 70, ""}, {"one_time_code", 45, ""}, {"azure_shared_access_key", 95, ""},
	{"internal_ip_address", 30, ""}, {"aws_arn", 30, ""}, {"aws_s3_bucket", 30, ""}, {"aws_rds_endpoint", 30, ""},
	{"aws_dynamodb_endpoint", 25, ""},
	// Identifiants européens à somme de contrôle, portés de Presidio (v0.10.0).
	{"es_nif", 60, "es_nif_mod23"}, {"es_nie", 60, "es_nie_mod23"}, {"it_fiscal_code", 60, "it_fiscal_code_check"},
	{"it_vat", 35, "it_vat_luhn"}, {"de_tax_id", 60, "de_tax_id_iso7064"}, {"de_vat", 35, "de_vat_iso7064"},
	{"pl_pesel", 60, "pl_pesel_check"}, {"uk_nhs", 60, "uk_nhs_mod11"}, {"se_personnummer", 60, "se_personnummer_luhn"},
	{"fi_personal_identity_code", 60, "fi_hetu_mod31"},
	// Identifiants français (v0.10.0), puis règle composée AWS.
	{"fr_vat", 35, "fr_vat_key"}, {"fr_rib", 45, "fr_rib_key"}, {"fr_license_plate", 30, ""},
	{"fr_postal_address", 30, ""}, {"aws_access_key_pair", 95, ""},
}

// mailbox assemble une adresse d'essai (domaine réservé) : jamais écrite d'un bloc dans le dépôt.
func mailbox(local, domain string) string { return local + "@" + domain }

// TestContextRules : règles de données à contexte du Pack initial (v0.9.0).
func TestContextRules(t *testing.T) {
	rules := loadInitialRules(t)
	p := loadInitialPack(t)
	byID := map[string]*rule{}
	for _, r := range rules.fixed {
		byID[r.id] = r
	}
	t.Run("chaque règle est une règle « motif seul », à porte, à un groupe capturant au plus, avec son score, son validateur et son libellé de Substitut", func(t *testing.T) {
		if len(contextSubstituteLabels) != len(contextRuleScores) {
			t.Fatalf("%d libellés, %d règles", len(contextSubstituteLabels), len(contextRuleScores))
		}
		// Les règles de données à contexte ferment le Pack, dans l'ordre de leur table.
		tail := p.Rules[len(p.Rules)-len(contextRuleScores):]
		for i, want := range contextRuleScores {
			spec, label := tail[i], contextSubstituteLabels[i]
			if spec.RuleID != want.id || label.RuleID != want.id {
				t.Fatalf("règle %d : %s dans le Pack, %s dans la table des libellés, %s attendue", i, spec.RuleID, label.RuleID, want.id)
			}
			r := byID[spec.RuleID]
			if r == nil || string(spec.Family) != familyFixedPattern || spec.Validator != want.validator || spec.MinLength != 0 || spec.MaxLength != 0 {
				t.Fatalf("%s : famille %s, validateur %q, bornes %d et %d", spec.RuleID, spec.Family, spec.Validator, spec.MinLength, spec.MaxLength)
			}
			if spec.Score != want.score {
				t.Errorf("%s : score %d, attendu %d", spec.RuleID, spec.Score, want.score)
			}
			if r.gate == nil {
				t.Errorf("%s : aucune porte littérale (la règle s'exécuterait sur tout texte)", spec.RuleID)
			}
			if r.pattern.NumSubexp() > 1 {
				t.Errorf("%s : %d groupes capturants (un seul : la valeur)", spec.RuleID, r.pattern.NumSubexp())
			}
			for _, text := range []string{label.French, label.English} {
				if text == "" || text == SubstituteDefaultLabel || strings.ContainsAny(text, "[]\n\r\t,:") || strings.TrimSpace(text) != text {
					t.Errorf("%s : libellé %q refusé", spec.RuleID, text)
				}
			}
			for _, language := range []SubstituteLanguage{SubstituteFrench, SubstituteEnglish} {
				substitute, err := SubstituteText([]byte("x"), spec.RuleID, 12, language)
				if err != nil {
					t.Fatal(err)
				}
				if found := FindSubstitutes([]byte("valeur : " + substitute + " fin")); len(found) != 1 {
					t.Errorf("%s (%s) : %d Substituts reconnus dans %q", spec.RuleID, language, len(found), substitute)
				}
				if got := Scan([]byte("note "+substitute+" fin"), rules, Options{}); !got.Complete || len(got.Findings) != 0 {
					t.Errorf("%s (%s) : Substitut détecté %+v", spec.RuleID, language, got.Findings)
				}
			}
		}
	})
	t.Run("le masquage retire la valeur, garde le mot-clé et la nouvelle analyse ne trouve plus rien", func(t *testing.T) {
		input := "Tél : 01 99 00 12 34, cvv 123, mon email est " + mailbox("camille", "societe.example") +
			", serveur interne 10.12.3.4, sauvegarde s3://demo-bucket-fictif/export fin"
		text, outcome := RedactAndRescan([]byte(input), rules, Options{}, RedactOptions{})
		if outcome.Failure != SanitizeNone {
			t.Fatalf("issue %q", outcome.Failure)
		}
		want := "Tél : <REDACTED_phone_number>, cvv <REDACTED_payment_card_security_code>, mon email est " +
			"<REDACTED_email_address>, serveur interne <REDACTED_internal_ip_address>, sauvegarde " +
			"<REDACTED_aws_s3_bucket>/export fin"
		if string(text) != want {
			t.Fatalf("texte masqué %q", text)
		}
		if len(outcome.Final.Findings) != 0 {
			t.Fatalf("constats après masquage : %+v", outcome.Final.Findings)
		}
	})
	t.Run("lecture en pourcentage et en échappements JSON : même règle, score diminué de 5 ; base64 : lue aussi (sans validateur)", func(t *testing.T) {
		for _, c := range []struct {
			name, input string
			encoding    Encoding
		}{
			{"pourcentage", "tel%3A%2B33%206%2039%2098%2012%2034", EncodingPercent},
			{"échappements JSON", `"tel: ` + "\\" + `u002b33 6 39 98 12 34"`, EncodingJSONEscaped},
			{"base64", "data=" + b64("message : tel +33 6 39 98 12 34, à bientôt"), EncodingBase64},
		} {
			result := Scan([]byte(c.input), rules, Options{})
			found := false
			for _, f := range result.Findings {
				if f.RuleID == "phone_number" {
					found = true
					if f.Encoding != c.encoding || f.Score != 25 {
						t.Errorf("%s : constat %+v", c.name, f)
					}
				}
			}
			if !result.Complete || !found {
				t.Errorf("%s : téléphone non trouvé (%+v)", c.name, result.Findings)
			}
		}
	})
	t.Run("une clé d'accès partagé Azure l'emporte sur l'entropie de la même valeur", func(t *testing.T) {
		key := strings.Repeat("aB3d", 10) + "eF7" + "="
		input := "Endpoint=sb://demo-ns.servicebus.windows.net/;" + "Shared" + "AccessKey=" + key
		result := Scan([]byte(input), rules, Options{})
		if !result.Complete || len(result.Findings) != 1 || result.Findings[0].RuleID != "azure_shared_access_key" ||
			result.Findings[0].Level != LevelCritical || result.Findings[0].ByteEnd != len(input) {
			t.Fatalf("constats %+v", result.Findings)
		}
	})
}

// TestOptInRules : règles « à activer » (optin.go).
func TestOptInRules(t *testing.T) {
	p := loadInitialPack(t)
	announced := []byte("mon email est " + mailbox("camille", "societe.example") + "\n")
	hasRule := func(result Result, id string) bool {
		return slices.ContainsFunc(result.Findings, func(f Finding) bool { return f.RuleID == id })
	}
	t.Run("la liste fermée est celle du générateur, faite de règles « motif seul » du Pack initial, et rendue en copie", func(t *testing.T) {
		ids := OptInRuleIDs()
		if !slices.Equal(ids, []string{"email_address", "fr_postal_address"}) {
			t.Fatalf("règles à activer %v", ids)
		}
		for _, id := range ids {
			if !slices.ContainsFunc(p.Rules, func(r pack.Rule) bool { return r.RuleID == id && string(r.Family) == familyFixedPattern }) {
				t.Errorf("%s : absente du Pack initial ou hors des règles « motif seul »", id)
			}
		}
		ids[0] = "x"
		if OptInRuleIDs()[0] != "email_address" {
			t.Fatal("la liste rendue n'est pas une copie")
		}
	})
	t.Run("LoadRules contrôle une règle à activer, la connaît (Has) et ne l'exécute pas", func(t *testing.T) {
		rules, err := LoadRules(&p)
		if err != nil {
			t.Fatal(err)
		}
		if !rules.Has("email_address") {
			t.Fatal("règle du Pack inconnue de Has")
		}
		if result := Scan(announced, rules, Options{}); !result.Complete || len(result.Findings) != 0 {
			t.Fatalf("constats %+v", result.Findings)
		}
		// Les autres règles de données à contexte s'exécutent d'office.
		if result := Scan([]byte("Tél : 01 99 00 12 34\n"), rules, Options{}); !hasRule(result, "phone_number") {
			t.Fatalf("téléphone non trouvé : %+v", result.Findings)
		}
	})
	t.Run("LoadRulesWithOptIn exécute la règle nommée ; sans nom, il charge comme LoadRules", func(t *testing.T) {
		rules, err := LoadRulesWithOptIn(&p, []string{"email_address"})
		if err != nil {
			t.Fatal(err)
		}
		if result := Scan(announced, rules, Options{}); !result.Complete || len(result.Findings) != 1 || !hasRule(result, "email_address") {
			t.Fatalf("constats %+v", result.Findings)
		}
		plain, err := LoadRulesWithOptIn(&p, nil)
		if err != nil {
			t.Fatal(err)
		}
		if result := Scan(announced, plain, Options{}); len(result.Findings) != 0 {
			t.Fatalf("constats %+v", result.Findings)
		}
	})
	t.Run("un identifiant hors de la liste fermée fait échouer le chargement", func(t *testing.T) {
		for _, id := range []string{"phone_number", "github_token", "inconnue", ""} {
			if rules, err := LoadRulesWithOptIn(&p, []string{"email_address", id}); rules != nil || !errors.Is(err, ErrUnknownOptInRule) {
				t.Errorf("%q : %v", id, err)
			}
		}
	})
	t.Run("une règle à activer inexploitable fait refuser le Pack, activée ou non ; absente du Pack, la nommer est sans effet", func(t *testing.T) {
		broken := p
		broken.Rules = slices.Clone(p.Rules)
		for i := range broken.Rules {
			if broken.Rules[i].RuleID == "email_address" {
				broken.Rules[i].Pattern = "("
			}
		}
		for _, optIn := range [][]string{nil, {"email_address"}} {
			var refusal *PackError
			if _, err := LoadRulesWithOptIn(&broken, optIn); !errors.As(err, &refusal) || refusal.Reason != RefusalPatternNotRE2 || refusal.RuleID != "email_address" {
				t.Errorf("%v : %v", optIn, err)
			}
		}
		without := p
		without.Rules = slices.DeleteFunc(slices.Clone(p.Rules), func(r pack.Rule) bool { return r.RuleID == "email_address" })
		rules, err := LoadRulesWithOptIn(&without, []string{"email_address"})
		if err != nil {
			t.Fatal(err)
		}
		if rules.Has("email_address") || len(Scan(announced, rules, Options{}).Findings) != 0 {
			t.Fatal("règle absente du Pack exécutée")
		}
	})
}
