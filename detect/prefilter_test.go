// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"regexp/syntax"
	"runtime"
	"slices"
	"testing"

	"github.com/xsom-consulting/secret-guard/pack"
)

// ungated rend une copie des règles sans aucune porte littérale (référence des tests de parité de la porte).
func ungated(r *Rules) *Rules {
	copies := map[*rule]*rule{}
	strip := func(original *rule) *rule {
		if copied, ok := copies[original]; ok {
			return copied
		}
		copied := *original
		copied.gate = nil
		copies[original] = &copied
		return &copied
	}
	out := &Rules{engine: map[string]*rule{}, ids: r.ids, loaded: r.loaded}
	for _, fixed := range r.fixed {
		out.fixed = append(out.fixed, strip(fixed))
	}
	for id, engine := range r.engine {
		out.engine[id] = strip(engine)
	}
	return out
}

// parallelEverywhere fait analyser toute vue par le chemin parallèle (même la plus courte) le temps d'un test.
func parallelEverywhere(tb testing.TB) {
	tb.Helper()
	previous := parallelMinViewBytes
	parallelMinViewBytes = 0
	tb.Cleanup(func() { parallelMinViewBytes = previous })
}

// digitSuffixes : « -0 » à « -9 » devant suffix (fin d'une région AWS, « eu-west-3 », puis le domaine du service).
func digitSuffixes(suffix string) []string {
	out := make([]string, 0, 10)
	for digit := '0'; digit <= '9'; digit++ {
		out = append(out, "-"+string(digit)+suffix)
	}
	return out
}

// gateLiterals rend les littéraux d'une porte, triés (nil sans porte).
func gateLiterals(g *literalGate) []string {
	if g == nil {
		return nil
	}
	var out []string
	for _, literal := range g.literals {
		out = append(out, string(literal))
	}
	slices.Sort(out)
	return out
}

func gateOfPattern(t *testing.T, pattern string) []string {
	t.Helper()
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		t.Fatal(err)
	}
	return gateLiterals(gateFor(parsed))
}

func TestPrefilterInitialPack(t *testing.T) {
	t.Run("littéraux obligatoires de chaque règle du Pack initial", func(t *testing.T) {
		// En-têtes PEM assemblés à l'exécution (la recherche de secrets du dépôt prendrait l'en-tête écrit pour une clé).
		var privateKeyHeaders []string
		for _, kind := range []string{"DSA ", "EC ", "ENCRYPTED ", "OPENSSH ", "PGP ", "", "RSA "} {
			label := kind + "PRIVATE " + "KEY"
			if kind == "PGP " {
				label += " BLOCK"
			}
			privateKeyHeaders = append(privateKeyHeaders, "-----"+"BEGIN "+label+"-----")
		}
		// Table écrite à la main : une règle absente n'a pas de porte (motif sans littéral prouvé, ou sans motif).
		want := map[string][]string{
			"github_fine_grained_pat": {"github_pat_"},
			"github_token":            {"gho_", "ghp_", "ghr_", "ghs_", "ghu_"},
			"gitlab_pat":              {"glpat-"},
			"openrouter_key":          {"sk-or-v1-"},
			"anthropic_key":           {"sk-ant-"},
			// « sk-proj- » et « sk-svcacct- » contiennent « sk- » : seul « sk- » est gardé.
			"openai_key":                 {"sk-"},
			"stripe_secret_key":          {"rk_live_", "rk_test_", "sk_live_", "sk_test_"},
			"slack_token":                {"xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-"},
			"slack_webhook":              {"https://hooks.slack.com/services/"},
			"google_api_key":             {"AIza"},
			"google_oauth_token":         {"ya29."},
			"sendgrid_key":               {"SG."},
			"npm_token":                  {"npm_"},
			"huggingface_token":          {"hf_"},
			"databricks_pat":             {"dapi"},
			"digitalocean_token":         {"dop_v1_"},
			"shopify_token":              {"shpat_", "shpca_", "shppa_", "shpss_"},
			"azure_storage_key":          {"AccountKey="},
			"aws_access_key_id":          {"AGPA", "AIDA", "AIPA", "AKIA", "ANPA", "ANVA", "AROA", "ASIA"},
			"jwt":                        {".eyJ"},
			"private_key_pem":            privateKeyHeaders,
			"private_key_pem_incomplete": privateKeyHeaders,
			// Portes repliées (v0.8.1) : motifs dont la casse est repliée, littéraux en minuscules.
			"database_url_credentials": {"://"},
			"basic_auth_url":           {"://"},
			"docker_auth":              {"auth"},
			"fr_siren":                 {"siren"},
			// Données à contexte (v0.9.0) : mots-clés du contexte, ou littéral fixe du fournisseur.
			"email_address": {"courriel", "lectronique", "mail"},
			// Casses écrites une à une, sans repli : seize littéraux, le plus que porte une porte.
			"phone_number": {
				"Fax", "MOBILE", "Mobile", "PHONE", "Phone", "Portable", "TEL", "Tel", "TÉL", "Tél", "fax", "mobile", "phone",
				"portable", "tel", "tél",
			},
			"passport_number":            {"passeport", "passport"},
			"payment_card_security_code": {"code de s", "cryptogramme", "cvc", "cvv", "security code"},
			"one_time_code": {
				" usage unique", "2fa code", "authentication code", "authentification", "confirmation", "otp", "rification",
				"time code", "time passcode", "time " + "pass" + "word", "time pin", "validation",
			},
			"azure_shared_access_key": {"Shared" + "AccessKey="},
			"internal_ip_address":     {"bastion", "internal", "interne", "intranet", "priv", "vpn"},
			"aws_arn":                 {"arn:aws-cn:", "arn:aws-us-gov:", "arn:aws:"},
			"aws_s3_bucket":           {"amazonaws.com", "s3://"},
			"aws_rds_endpoint":        digitSuffixes(".rds.amazonaws.com"),
			"aws_dynamodb_endpoint":   digitSuffixes(".amazonaws.com"),
			// Identifiants européens et français (v0.10.0) : mots-clés du contexte, en français, en anglais et dans la
			// langue du pays ; un littéral qui en contient un autre n'est pas gardé.
			"es_nif":         {" espagnole", "dni", "documento nacional de identidad", "nif", "spanish id card", "spanish identity card"},
			"es_nie":         {"foreigner id number", "foreigner identification number", "identit", "mero de identidad de extranjero", "nie"},
			"it_fiscal_code": {"code fiscal italien", "codice fiscale", "italian fiscal code", "italian tax code"},
			"it_vat":         {"italian vat", "p iva", "p. iva", "p.iva", "partita iva", "piva", "tva italienne"},
			"de_tax_id": {
				"german tax id", "identifiant fiscal allemand", "idnr", "steuer-id", "steuerid", "steuerliche identifikationsnummer",
			},
			"de_vat":          {"german vat", "tva allemande", "umsatzsteuer-id", "umsatzsteuerid", "ust-id", "ustid"},
			"pl_pesel":        {"pesel"},
			"uk_nhs":          {"national health service", "nhs"},
			"se_personnummer": {"personal identity number", "personnummer", "ro personnel su", "samordningsnummer", "swedish personal id number"},
			"fi_personal_identity_code": {
				"finnish personal id code", "henkil", "hetu", "identifiant personnel finlandais", "personal identity code", "personbeteckning",
			},
			// TVA française : sans mot-clé, « FR » et le premier chiffre de la clé.
			"fr_vat": {"FR0", "FR1", "FR2", "FR3", "FR4", "FR5", "FR6", "FR7", "FR8", "FR9"},
			"fr_rib": {" bancaire", "bank account details", "rib"},
			"fr_license_plate": {
				"IMMATRICUL", "Immatricul", "PLAQUE", "PLATE", "Plaque", "Plate", "REGISTRATION", "Registration", "immatricul", "plaque",
				"plate", "registration",
			},
			"fr_postal_address": {
				"all", "avenue", "boulevard", "chemin", "cours", "faubourg", "impasse", "passage", "place", "quai", "route", "rue",
				"sentier", "square",
			},
			"aws_access_key_pair": {"AKIA", "ASIA"},
		}
		rules := loadInitialRules(t)
		p := loadInitialPack(t)
		providers := map[string]bool{}
		for _, l := range providerSubstituteLabels {
			providers[l.RuleID] = true
		}
		seen := 0
		for _, spec := range p.Rules {
			r := rules.engine[spec.RuleID]
			for _, fixed := range rules.fixed {
				if fixed.id == spec.RuleID {
					r = fixed
				}
			}
			if r == nil {
				t.Fatalf("%s : règle non chargée", spec.RuleID)
			}
			seen++
			if providers[spec.RuleID] {
				// Règle de fournisseur (v0.8.1) : une porte, toujours (TestProviderRules le redit avec ses littéraux).
				if r.gate == nil {
					t.Errorf("%s : règle de fournisseur sans porte", spec.RuleID)
				}
				continue
			}
			if got := gateLiterals(r.gate); !reflect.DeepEqual(got, want[spec.RuleID]) {
				t.Errorf("%s : littéraux %q, attendu %q", spec.RuleID, got, want[spec.RuleID])
			}
		}
		if seen != len(p.Rules) || seen != 40+len(providers)+len(contextSubstituteLabels) {
			t.Fatalf("%d règles relues", seen)
		}
	})
}

func TestPrefilterProof(t *testing.T) {
	t.Run("aucune porte sans littéral prouvé", func(t *testing.T) {
		for _, pattern := range []string{
			// Repliement de casse d'une lettre hors ASCII : il n'est pas développé.
			`(?i)\x{00e9}t\x{00e9}_[0-9]{4}`,
			// Alternance dont une branche n'a aucun littéral.
			`(?:abc_|[a-z]+)[0-9]{8}`,
			`\b(?:xyz_[0-9]{4}|[0-9]{12})\b`,
			// Littéral de moins de 3 octets.
			`\bxy[0-9]{5}\b`,
			// Répétitions qui admettent zéro, point, classe trop grande.
			`(?:abcd)*[0-9]{4}`, `(?:abcd)?[0-9]{4}`, `.{3,}`, `[a-z]{4}`,
			// U+FFFD : RE2 y lit aussi chaque octet hors UTF-8.
			`\x{FFFD}\x{FFFD}\x{FFFD}`, `\x{FFFD}ab[0-9]{4}`,
		} {
			if got := gateOfPattern(t, pattern); got != nil {
				t.Errorf("%s : porte %q, attendu aucune", pattern, got)
			}
		}
	})
	t.Run("littéraux prouvés : concaténation, classes, alternances, répétitions", func(t *testing.T) {
		for pattern, want := range map[string][]string{
			`\bkey_[0-9]{8}\b`:                    {"key_"},
			`[kK]ey_[0-9]{4}`:                     {"Key_", "key_"}, // [kK] n'est pas replié (orbite K, k, U+212A)
			`(?:abc|def)_[0-9]+`:                  {"abc_", "def_"},
			`[0-9]{4}(?:-live|-test)?[a-z]{2}xyz`: {"xyz"},
			`(?:zz_tok)+[0-9]{4}`:                 {"zz_tok"},
			`[0-9]{2,}(?:abcd){2,5}`:              {"abcd"},
			`(?:abc_[0-9]{3}|xyz_[a-z]{3})`:       {"abc_", "xyz_"},
			`\x{00e9}t\x{00e9}_[0-9]{4}`:          {"été_"},
			`.{3}needle.{3}`:                      {"needle"},
			// Porte repliée (« (?i) », ou classe [xX] que l'analyseur réécrit en littéral replié) : minuscules ASCII.
			`(?i)\bsecret_[a-z]{8}\b`:              {"secret_"},
			`(?i)ASK_[0-9]{8}`:                     {"ask_"},
			`\b[tT]ok_[0-9]{8}\b`:                  {"tok_"},
			`(?i)(?:datadog|dd).{0,8}[a-f0-9]{32}`: nil, // « dd » : moins de 3 octets, aucune porte
			// Produit de plus de 16 chaînes : il s'arrête et un nouveau commence au facteur qui déborde.
			`[a-d][a-d][a-d]xyz_[0-9]+`: {"axyz_", "bxyz_", "cxyz_", "dxyz_"},
		} {
			if got := gateOfPattern(t, pattern); !reflect.DeepEqual(got, want) {
				t.Errorf("%s : porte %q, attendu %q", pattern, got, want)
			}
		}
	})
}

// singleRulePack rend un Pack d'une seule règle « motif seul ».
func singleRulePack(t *testing.T, pattern string) *Rules {
	t.Helper()
	p := pack.Pack{SchemaVersion: 1, PackVersion: 2, Rules: []pack.Rule{{
		RuleID: "corpus_code", Family: familyFixedPattern, SecretType: "api_key", Score: 90, Pattern: pattern,
	}}}
	rules, err := LoadRules(&p)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func TestPrefilterFoldCase(t *testing.T) {
	t.Run("la porte ne saute jamais une règle (?i) que le repliement Unicode de RE2 fait correspondre", func(t *testing.T) {
		parallelEverywhere(t)
		for _, c := range []struct{ pattern, text, naive string }{
			// U+017F (ſ) se replie en s, U+212A (K) en k.
			{`(?i)ask_[0-9]{8}`, "x aſK_12345678 y", "ask_"},
			{`(?i)\btoken_[0-9]{6}\b`, "TOKEN_123456", "token_"},
			{`(?i)secret_[0-9]{6}`, "ſecret_123456 et SECRET_654321", ""},
		} {
			rules := singleRulePack(t, c.pattern)
			if gate := rules.fixed[0].gate; gate == nil || !gate.fold {
				t.Fatalf("%s : porte repliée attendue", c.pattern)
			}
			// Une porte naïve sur le littéral, sans la casse ASCII, aurait sauté la règle.
			if c.naive != "" && bytes.Contains(asciiLower([]byte(c.text)), []byte(c.naive)) {
				t.Fatalf("%s : cas sans caractère replié", c.pattern)
			}
			for _, workers := range []int{1, 8} {
				gated := Scan([]byte(c.text), rules, Options{Workers: workers})
				reference := Scan([]byte(c.text), ungated(rules), Options{Workers: 1})
				if !gated.Complete || len(gated.Findings) == 0 || !reflect.DeepEqual(gated, reference) {
					t.Fatalf("%s, %d fils : %+v, référence %+v", c.pattern, workers, gated, reference)
				}
			}
		}
	})
}

// asciiLower met en minuscules les seules lettres ASCII (bytes.ToLower replie aussi U+212A en k).
func asciiLower(text []byte) []byte {
	out := append([]byte(nil), text...)
	for i, c := range out {
		if 'A' <= c && c <= 'Z' {
			out[i] = c + 'a' - 'A'
		}
	}
	return out
}

// TestParityWorkers : le corpus de parité, analysé avec GOMAXPROCS à 1 puis à 8 et Options.Workers à 1 puis à 8
// (chemin parallèle forcé sur toute vue), donne l'issue et les constats attendus, et exactement le même résultat
// (ordre, étendues, scores) dans chaque configuration.
func TestParityWorkers(t *testing.T) {
	t.Run("parité à 100 % quel que soit le nombre de fils", func(t *testing.T) {
		parallelEverywhere(t)
		rules := loadInitialRules(t)
		previous := runtime.GOMAXPROCS(0)
		t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
		var cases []corpusCase
		for _, file := range corpusFiles(t) {
			cases = append(cases, loadCorpusFile(t, file)...)
		}
		reference := make([]Result, len(cases))
		first := true
		for _, procs := range []int{1, 8} {
			runtime.GOMAXPROCS(procs)
			for _, workers := range []int{1, 8} {
				failed := 0
				for i, c := range cases {
					options, ok := c.options()
					if !ok {
						continue
					}
					options.Workers = workers
					result := Scan(c.bytes(t), rules, options)
					if first {
						reference[i] = result
					} else if !reflect.DeepEqual(result, reference[i]) {
						failed++
						t.Errorf("%s : GOMAXPROCS %d, %d fils : résultat différent", c.ID, procs, workers)
					}
					if result.Failure != Failure(c.Expected.Failure) || result.Complete != c.Expected.Complete {
						failed++
						t.Errorf("%s : GOMAXPROCS %d, %d fils : issue %q", c.ID, procs, workers, result.Failure)
						continue
					}
					want := append([]corpusFinding(nil), c.Expected.Findings...)
					sortCorpusFindings(want)
					if got := corpusForm(result.Findings); !slices.Equal(got, want) {
						failed++
						t.Errorf("%s : GOMAXPROCS %d, %d fils : constats différents du corpus", c.ID, procs, workers)
					}
				}
				first = false
				t.Logf("GOMAXPROCS %d, %d fils : %d cas, %d en écart", procs, workers, len(cases), failed)
			}
		}
	})
	t.Run("textes de banc : même résultat et mêmes Empreintes locales quel que soit le nombre de fils", func(t *testing.T) {
		rules := loadInitialRules(t)
		key := testFingerprintKey(t)
		for _, size := range []int{2 << 10, 64 << 10} {
			for _, secrets := range []bool{false, true} {
				content := benchText(size, secrets)
				reference := scan(content, ungated(rules), Options{Workers: 1}, &key)
				for _, workers := range []int{0, 2, 8, 64} {
					if got := scan(content, rules, Options{Workers: workers}, &key); !reflect.DeepEqual(got, reference) {
						t.Fatalf("%d octets, %d fils : résultat différent", size, workers)
					}
				}
				if !reference.Complete || (len(reference.Findings) > 0) != secrets {
					t.Fatalf("%d octets : %+v", size, reference.Failure)
				}
			}
		}
	})
}

func testFingerprintKey(tb testing.TB) FingerprintKey {
	tb.Helper()
	raw := make([]byte, FingerprintKeyBytes)
	for i := range raw {
		raw[i] = byte(i*37 + 11)
	}
	key, err := NewFingerprintKey(raw)
	if err != nil {
		tb.Fatal(err)
	}
	return key
}

func TestParallelDetectorPanic(t *testing.T) {
	t.Run("une panique dans un fil rend scan_error, sans propager la panique ni attendre en vain", func(t *testing.T) {
		parallelEverywhere(t)
		rules := loadInitialRules(t)
		faulty := *rules
		faulty.fixed = append([]*rule{{
			id: "injected_fault", family: familyFixedPattern, secretType: "api_key", score: 90,
			pattern: nil, // scanFixedPattern déréférence le motif : panique dans un fil
		}}, rules.fixed...)
		// L'index du Pack ne décrit plus la liste : il est écarté (Rules.admittedFixed), chaque règle juge sa porte.
		content := benchText(8<<10, true)
		for _, workers := range []int{2, 8} {
			result := Scan(content, &faulty, Options{Workers: workers})
			if result.Complete || result.Failure != FailureScanError || result.Findings != nil {
				t.Fatalf("%d fils : %+v", workers, result)
			}
		}
		if _, err := collect(&faulty, content, language{}); err != errDetectorPanic {
			t.Fatalf("erreur %v", err)
		}
	})
}

// prefilterSeeds : graines du fuzz de la porte : graines des autres fuzz, entrées du corpus de parité, textes de banc,
// repliements de casse.
func prefilterSeeds(tb testing.TB) [][]byte {
	tb.Helper()
	var seeds [][]byte
	for _, s := range append(append([]string{}, fuzzSeeds...), ruleFuzzSeeds...) {
		seeds = append(seeds, []byte(s))
	}
	seeds = append(seeds, benchText(2<<10, true), benchText(16<<10, true),
		[]byte("x aſK_12345678 sk-Key ghſp_ AKIAK"))
	data, err := os.ReadFile(corpusDir + "manifest.json")
	if err != nil {
		tb.Fatal(err)
	}
	var manifest struct {
		Files []struct {
			File string `json:"file"`
		} `json:"files"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		tb.Fatal(err)
	}
	for _, file := range manifest.Files {
		data, err := os.ReadFile(corpusDir + file.File)
		if err != nil {
			tb.Fatal(err)
		}
		var cases []corpusCase
		if err := json.Unmarshal(data, &cases); err != nil {
			tb.Fatal(err)
		}
		for _, c := range cases {
			input := []byte(c.Input)
			if c.InputEncoding == "base64" {
				if input, err = base64.StdEncoding.DecodeString(c.Input); err != nil {
					tb.Fatal(err)
				}
			}
			// Entrées de plus de 64 Kio (limites) : jugées par TestParityWorkers, trop lentes pour le fuzz.
			if len(input) <= 64<<10 {
				seeds = append(seeds, input)
			}
		}
	}
	return seeds
}

// FuzzPrefilterParity : toute entrée, tout langage : l'analyse avec la porte littérale et 8 fils (chemin parallèle
// sur toute vue) rend exactement le résultat de l'analyse séquentielle sans porte (Workers à 1) : issue, constats,
// ordre, étendues, scores et Empreintes locales.
func FuzzPrefilterParity(f *testing.F) {
	for i, seed := range prefilterSeeds(f) {
		f.Add(seed, uint8(i))
	}
	parallelEverywhere(f)
	rules := loadInitialRules(f)
	reference := ungated(rules)
	key := testFingerprintKey(f)
	languages := []string{"", "typescript", "json", "dotenv", "yaml", "shellscript", "python"}
	f.Fuzz(func(t *testing.T, content []byte, choice uint8) {
		if len(content) > 64<<10 {
			return
		}
		lang := languages[int(choice)%len(languages)]
		want := scan(content, reference, Options{LanguageID: lang, Workers: 1}, &key)
		got := scan(content, rules, Options{LanguageID: lang, Workers: 8}, &key)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("porte et 8 fils : %+v ; référence : %+v", got.Failure, want.Failure)
		}
	})
}

func TestParallelDetectorNilPanic(t *testing.T) {
	t.Run("panic(nil) sous GODEBUG=panicnil=1 dans un fil rend scan_error, jamais une famille vide", func(t *testing.T) {
		parallelEverywhere(t)
		t.Setenv("GODEBUG", "panicnil=1")
		// Le réglage est actif : recover rend nil pour panic(nil).
		if recovered := func() (r any) {
			defer func() { r = recover() }()
			panic(nil) //nolint:govet // panic(nil) voulu : cas sous GODEBUG=panicnil=1
		}(); recovered != nil {
			t.Skipf("GODEBUG=panicnil=1 sans effet : %v", recovered)
		}
		previous := detectorTasksOf
		t.Cleanup(func() { detectorTasksOf = previous })
		detectorTasksOf = func(r *Rules, v *view, budget *decodeBudget, entropy bool, lang language, allowStructured bool) []detectorTask {
			tasks := previous(r, v, budget, entropy, lang, allowStructured)
			return append(tasks, detectorTask{run: func() ([]finding, error) { panic(nil) }, rank: rankAssignment})
		}
		rules := loadInitialRules(t)
		content := benchText(4<<10, true)
		for _, workers := range []int{2, 8} {
			result := Scan(content, rules, Options{Workers: workers})
			if result.Complete || result.Failure != FailureScanError || result.Findings != nil {
				t.Fatalf("%d fils : %+v", workers, result)
			}
		}
	})
}

func TestParallelDetectorBudgetStops(t *testing.T) {
	t.Run("budget de décodage épuisé par une famille à budget : les suivantes ne s'exécutent pas", func(t *testing.T) {
		parallelEverywhere(t)
		previous := detectorTasksOf
		t.Cleanup(func() { detectorTasksOf = previous })
		ran := false
		detectorTasksOf = func(r *Rules, v *view, budget *decodeBudget, entropy bool, lang language, allowStructured bool) []detectorTask {
			return []detectorTask{
				{run: func() ([]finding, error) { budget.exhausted = true; return nil, nil }, budgeted: true},
				{run: func() ([]finding, error) { ran = true; return nil, nil }, budgeted: true},
				{run: func() ([]finding, error) { return nil, nil }},
			}
		}
		s := newScanState(loadInitialRules(t))
		if _, err := s.detectors(identityView(benchText(2<<10, false)), true, language{}, true); err != errDecodeBudgetExhausted {
			t.Fatalf("erreur %v", err)
		}
		if ran {
			t.Fatal("famille à budget exécutée après l'épuisement du budget")
		}
	})
}
