// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/pack"
)

// noiseProvidersPath : cas de bruit des règles de fournisseurs (vectors/noise-providers.json, v0.10.0), écrits par
// generator/corpus/provider-noise.ts : pour chaque règle, la forme de sa valeur où chaque suite de caractères est un
// seul caractère répété. Même format que vectors/noise.json.
const noiseProvidersPath = "../vectors/noise-providers.json"

// TestNoiseProviders : chaque cas de bruit des règles de fournisseurs donne une analyse complète sans constat, alors
// que le motif de sa règle reconnaît le texte : c'est le contrôle de vraisemblance qui l'écarte. Avec les règles « à
// activer » en plus, seules celles-ci peuvent se déclencher. Le diagnostic nomme le cas et la règle, jamais le texte.
func TestNoiseProviders(t *testing.T) {
	raw, err := os.ReadFile(noiseProvidersPath)
	if err != nil {
		t.Fatal(err)
	}
	var corpus noiseCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.FormatVersion != 1 || len(corpus.Cases) < 280 {
		t.Fatalf("bruit des règles de fournisseurs : version %d, %d cas", corpus.FormatVersion, len(corpus.Cases))
	}
	p := loadInitialPack(t)
	defaults, err := LoadRules(&p)
	if err != nil {
		t.Fatal(err)
	}
	everything := loadInitialRules(t)
	byID := map[string]*rule{}
	for _, r := range defaults.fixed {
		byID[r.id] = r
	}
	optIn := map[string]bool{}
	for _, id := range OptInRuleIDs() {
		optIn[id] = true
	}
	seen := map[string]bool{}
	for _, c := range corpus.Cases {
		if seen[c.ID] {
			t.Fatalf("cas en double : %s", c.ID)
		}
		seen[c.ID] = true
		parts := strings.Split(c.ID, "/")
		if len(parts) != 3 || parts[0] != "fournisseur" || parts[2] != "caractere-repete" {
			t.Fatalf("identifiant de cas inattendu : %s", c.ID)
		}
		r := byID[parts[1]]
		if r == nil || r.secretType != providerRuleType || r.entropyFloor == 0 {
			t.Fatalf("%s : règle de fournisseur inconnue ou sans contrôle de vraisemblance", c.ID)
		}
		input := []byte(c.Input)
		if !r.pattern.Match(input) {
			t.Errorf("%s : le motif de la règle ne reconnaît pas le texte (le cas ne prouve rien)", c.ID)
		}
		for _, workers := range []int{1, 0} {
			options := Options{LanguageID: c.Language, Workers: workers}
			result := Scan(input, defaults, options)
			if !result.Complete {
				t.Errorf("%s : analyse incomplète (%v)", c.ID, result.Failure)
				continue
			}
			for _, f := range result.Findings {
				t.Errorf("%s : constat %s", c.ID, f.RuleID)
			}
			for _, f := range Scan(input, everything, options).Findings {
				if !optIn[f.RuleID] {
					t.Errorf("%s : constat %s avec les règles à activer", c.ID, f.RuleID)
				}
			}
		}
	}
	t.Logf("%d cas de bruit des règles de fournisseurs", len(corpus.Cases))
}

// TestPlausibility : contrôle de vraisemblance d'un jeton de fournisseur (validators.go, v0.10.0).
func TestPlausibility(t *testing.T) {
	t.Run("une valeur de moins de 6 octets distincts ou d'entropie inférieure au seuil n'est pas un jeton", func(t *testing.T) {
		eight := strings.Repeat("abcdefgh", 4)
		sixteen := strings.Repeat("0123456789abcdef", 2)
		cases := []struct {
			name  string
			value string
			floor int
			want  bool
		}{
			{"valeur vide", "", 30, false},
			{"une lettre répétée", strings.Repeat("a", 40), 30, false},
			{"des zéros", strings.Repeat("0", 32), 30, false},
			{"cinq caractères distincts", strings.Repeat("abcde", 8), 25, false},
			{"six caractères distincts à parts égales : entropie 2,58, sous 3,0", strings.Repeat("abcdef", 6), 30, false},
			{"six caractères distincts à parts égales : entropie 2,58, au-dessus de 2,5", strings.Repeat("abcdef", 6), 25, true},
			{"huit caractères distincts à parts égales : entropie 3,0 exactement", eight, 30, true},
			{"huit caractères distincts à parts égales, seuil 3,1", eight, 31, false},
			{"seize caractères distincts à parts égales : entropie 4,0 exactement", sixteen, 40, true},
			{"seize caractères distincts à parts égales, seuil 4,1", sixteen, 41, false},
			{"une lettre dominante et sept autres caractères", strings.Repeat("a", 33) + "bcdefgh", 30, false},
		}
		for _, c := range cases {
			if got := plausibleToken([]byte(c.value), c.floor); got != c.want {
				t.Errorf("%s : %v, attendu %v", c.name, got, c.want)
			}
		}
	})

	t.Run("le seuil vient du validateur nommé, sinon du type hors du catalogue d'origine", func(t *testing.T) {
		named := "token_entropy_35"
		cases := []struct {
			name                              string
			id, family, secretType, validator string
			want                              int
		}{
			{"règle de fournisseur sans validateur", "demo_rule", familyFixedPattern, providerRuleType, "", baseEntropyFloor},
			{"règle de fournisseur à validateur", "demo_rule", familyFixedPattern, providerRuleType, named, 35},
			{"règle du catalogue d'origine", "github_token", familyFixedPattern, providerRuleType, "", 0},
			{"règle du catalogue d'origine à validateur", "github_token", familyFixedPattern, providerRuleType, named, 35},
			{"autre type de secret", "demo_rule", familyFixedPattern, "api_key", "", 0},
			{"autre type de secret à validateur", "demo_rule", familyFixedPattern, "api_key", named, 35},
			{"autre famille", "demo_rule", familyContextualAssignment, providerRuleType, "", 0},
			{"autre validateur", "demo_rule", familyFixedPattern, "jwt", "jwt_structure", 0},
		}
		for _, c := range cases {
			if got := entropyFloorOf(c.id, c.family, c.secretType, c.validator); got != c.want {
				t.Errorf("%s : seuil %d, attendu %d", c.name, got, c.want)
			}
		}
	})

	t.Run("liste fermée : token_entropy_25 à token_entropy_45, tout autre nom fait refuser le Pack", func(t *testing.T) {
		if len(tokenEntropyFloors) != 21 {
			t.Fatalf("%d validateurs de vraisemblance", len(tokenEntropyFloors))
		}
		for name, floor := range tokenEntropyFloors {
			check, known := validators[name]
			if !known || check != nil || floor < 25 || floor > 45 || name != fmt.Sprintf("token_entropy_%d", floor) {
				t.Errorf("%s : seuil %d, connu %v", name, floor, known)
			}
		}
		initial := loadInitialPack(t)
		index := ruleIndex(t, initial, "adafruit_io_key")
		for _, name := range []string{"token_entropy_24", "token_entropy_46", "token_entropy_3", "token_entropy"} {
			p := clonePack(initial)
			p.Rules[index].Validator = name
			var refusal *PackError
			if _, err := LoadRules(&p); !errors.As(err, &refusal) || refusal.Reason != RefusalUnknownValidator {
				t.Errorf("%s : %v, refus unknown_validator attendu", name, err)
			}
		}
	})

	t.Run("les règles du catalogue d'origine exemptées sont celles du Pack initial", func(t *testing.T) {
		initial := loadInitialPack(t)
		found := map[string]bool{}
		// Les 35 premières règles du Pack sont le catalogue d'origine (TestProviderRules).
		for _, spec := range initial.Rules[:35] {
			if string(spec.Family) == familyFixedPattern && string(spec.SecretType) == providerRuleType {
				found[spec.RuleID] = true
			}
		}
		if len(found) != len(originCatalogRules) {
			t.Fatalf("%d règles du catalogue, %d exemptées", len(found), len(originCatalogRules))
		}
		for id := range found {
			if !originCatalogRules[id] {
				t.Errorf("%s : règle du catalogue d'origine non exemptée", id)
			}
		}
		for _, spec := range initial.Rules[35:] {
			if originCatalogRules[spec.RuleID] {
				t.Errorf("%s : règle exemptée hors du catalogue d'origine", spec.RuleID)
			}
		}
	})

	t.Run("Pack initial : une clé hexadécimale de 32 chiffres reste lue après le nom du fournisseur, un identifiant de code ne l'est pas", func(t *testing.T) {
		rules := loadInitialRules(t)
		// Huit chiffres distincts à parts égales : entropie 3,0, la plus basse d'une clé hexadécimale courante.
		hexEight := strings.Repeat("0a1b2c3d", 4)
		name := "dvc" + "_server_"
		cases := []struct {
			name, input, ruleID string
			want                bool
		}{
			{"clé Datadog hexadécimale d'entropie 3,0", "datadog api" + "key " + hexEight + " fin", "datadog_api_" + "key", true},
			{"clé Datadog faite de zéros", "datadog api" + "key " + strings.Repeat("0", 32) + " fin", "datadog_api_" + "key", false},
			{"clé Iterable hexadécimale d'entropie 3,0", "iterable api" + "key " + hexEight + " fin", "iterable_api_" + "key", true},
			{"clé DevCycle de 24 caractères", "id " + name + "5fbbd6p84oe7" + "ut4qrttebiwa" + " fin", "devcycle_server_sdk_" + "key", true},
			{"clé DevCycle de 8 caractères, chiffre en dernier", "id " + name + "abcdefg" + "7" + " fin", "devcycle_server_sdk_" + "key", true},
			{"identifiant de code à chiffre, moins de 8 caractères", "id " + name + "ipv4" + " fin", "devcycle_server_sdk_" + "key", false},
			{"identifiant de code sans chiffre", "id " + name + "hostname" + " fin", "devcycle_server_sdk_" + "key", false},
		}
		for _, c := range cases {
			result := Scan([]byte(c.input), rules, Options{})
			if !result.Complete {
				t.Fatalf("%s : analyse incomplète (%v)", c.name, result.Failure)
			}
			got := false
			for _, f := range result.Findings {
				got = got || f.RuleID == c.ruleID
			}
			if got != c.want {
				t.Errorf("%s : constat %s %v, attendu %v", c.name, c.ruleID, got, c.want)
			}
		}
	})

	t.Run("analyse : la valeur sans diversité n'est plus un constat, la valeur diverse le reste", func(t *testing.T) {
		p := clonePack(loadInitialPack(t))
		demo := func(id string, score int, validatorName, pattern string) pack.Rule {
			return pack.Rule{RuleID: id, Family: familyFixedPattern, SecretType: providerRuleType, Score: score, Validator: validatorName, Pattern: pattern}
		}
		p.Rules = append(p.Rules,
			demo("demo_prefix", 95, "", `\b(dmo_[0-9a-z]{32})\b`),
			demo("demo_named", 80, "token_entropy_35", `(?i:\bdemocorp.{0,16}?\b([0-9a-f]{32})\b)`),
			demo("demo_dash", 95, "", `\bdmt_[0-9a-z_-]{20}\b`),
		)
		rules, err := LoadRules(&p)
		if err != nil {
			t.Fatal(err)
		}
		diverse := strings.Repeat("a1b2c3d4e5f6g7h8", 2)
		hexSixteen := strings.Repeat("0123456789abcdef", 2)
		hexEight := strings.Repeat("01234567", 4)
		encoded := base64.StdEncoding.EncodeToString([]byte("note democorp " + hexSixteen + " (fin)\n"))
		cases := []struct {
			name, input, ruleID string
			want                bool
		}{
			{"préfixe fixe, une lettre répétée", "id dmo_" + strings.Repeat("a", 32) + " fin", "demo_prefix", false},
			{"préfixe fixe, valeur diverse", "id dmo_" + diverse + " fin", "demo_prefix", true},
			{"nom à proximité, zéros", "democorp " + strings.Repeat("0", 32) + " fin", "demo_named", false},
			{"nom à proximité, entropie 3,0 sous le seuil 3,5 de la règle", "democorp " + hexEight + " fin", "demo_named", false},
			{"nom à proximité, entropie 4,0", "democorp " + hexSixteen + " fin", "demo_named", true},
			{"nom à proximité, dans un texte décodé de base64", encoded, "demo_named", true},
			{"jeton fini par un tiret, une lettre répétée", "id dmt_" + strings.Repeat("a", 19) + "- fin", "demo_dash", false},
			{"jeton fini par un tiret, valeur diverse", "id dmt_" + "a1b2c3d4e5f6g7h8i9j" + "- fin", "demo_dash", true},
			{"règle du catalogue d'origine, une lettre répétée (parité gardée)", "id ghp_" + strings.Repeat("a", 36) + " fin", "github_token", true},
		}
		for _, c := range cases {
			for _, workers := range []int{1, 0} {
				result := Scan([]byte(c.input), rules, Options{Workers: workers})
				if !result.Complete {
					t.Fatalf("%s : analyse incomplète (%v)", c.name, result.Failure)
				}
				got := false
				for _, f := range result.Findings {
					got = got || f.RuleID == c.ruleID
				}
				if got != c.want {
					t.Errorf("%s : constat %s %v, attendu %v", c.name, c.ruleID, got, c.want)
				}
			}
		}
	})
}
