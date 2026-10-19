package detect

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/xsom-consulting/secret-guard/pack"
)

// fixedOrdinal rend toujours le même numéro.
func fixedOrdinal(n int) func(Finding) (int, bool) {
	return func(Finding) (int, bool) { return n, true }
}

// startOrdinals numérote les étendues dans l'ordre où elles sont vues, à partir de first : même début, même numéro.
func startOrdinals(first int) func(Finding) (int, bool) {
	seen := map[int]int{}
	return func(f Finding) (int, bool) {
		if n, ok := seen[f.ByteStart]; ok {
			return n, true
		}
		seen[f.ByteStart] = first + len(seen)
		return seen[f.ByteStart], true
	}
}

// syntheticPEM est une clé privée PEM synthétique, construite à l'exécution.
func syntheticPEM(newline string) string {
	body := "MIIEow" + "IBAAKCAQEA" + strings.Repeat("q7Lm2Pz9Wr4Tn", 4) + newline + strings.Repeat("aZ3kQ9mW2xL7", 4)
	return pemHeader("RSA PRIVATE KEY") + newline + body + newline + "-----END RSA PRIVATE KEY-----"
}

// pemHeader et basicAuthCommand assemblent à l'exécution un en-tête PEM et le début d'une commande curl -u : écrits
// tels quels, la recherche de secrets du dépôt les prendrait pour une clé et des identifiants (règles private-key et
// curl-auth-user de gitleaks).
func pemHeader(label string) string { return "-----BEGIN" + " " + label + "-----" }

func basicAuthCommand() string { return curlUser("admin") }

func curlUser(user string) string { return "curl -u " + user + ":" }

// expurgateBoth exécute ExpurgateAndRescan avec Workers 1 et 8 et exige le même résultat.
func expurgateBoth(t *testing.T, content []byte, rules *Rules, key *FingerprintKey, options Options, ordinal func() func(Finding) (int, bool)) ([]byte, []Substitution, SanitizeResult) {
	t.Helper()
	options.Workers = 1
	text, subs, result := ExpurgateAndRescan(content, rules, key, options, ordinal())
	options.Workers = 8
	text8, subs8, result8 := ExpurgateAndRescan(content, rules, key, options, ordinal())
	if !bytes.Equal(text, text8) || !reflect.DeepEqual(subs, subs8) || !reflect.DeepEqual(result, result8) {
		t.Fatal("Workers 1 et 8 donnent des expurgations différentes")
	}
	return text, subs, result
}

func TestSubstituteGrammar(t *testing.T) {
	t.Run("grammaire ^(?:<préfixe>)?X{3,}[0-9]{1,3}$, X majuscules, préfixe de la table fermée", func(t *testing.T) {
		for value, want := range map[string]bool{
			"XXX1": true, "XXXX1": true, "XXXX999": true, "XXXX007": true, "ghp_XXX1": true, "sk-ant-XXXXXXX42": true,
			"AKIAXXXXXXXXXXXXXXX1": true, "https://hooks.slack.com/services/XXXX1": true,
			"": false, "XX1": false, "XXXX": false, "1": false, "XXXX1234": false, "xxxx1": false, "XXxX1": false,
			"ghp_XXXX1a": false, "ghp_XXXXAXXXX1": false, "ghq_XXXX1": false, "GHP_XXXX1": false, "aghp_XXXX1": false,
			"XXXX1 ": false, " XXXX1": false, "ghp_1": false, "XXXX٣": false, "XXXX１": false,
		} {
			if got := isSubstitute([]byte(value)); got != want {
				t.Errorf("%q : %v, attendu %v", value, got, want)
			}
		}
	})
	t.Run("SubstitutePrefixes rend une copie de la table fermée", func(t *testing.T) {
		first := SubstitutePrefixes()
		first[0] = "changé"
		if second := SubstitutePrefixes(); second[0] == "changé" || !slices.Equal(second, substitutePrefixes) {
			t.Fatal("table modifiable par l'appelant")
		}
		if !isSubstitute([]byte(SubstitutePrefixes()[0] + "XXXX1")) {
			t.Fatal("préfixe de la table non reconnu")
		}
	})
}

func TestSubstituteFor(t *testing.T) {
	t.Run("préfixe le plus long, X, numéro, à la longueur de la valeur en points de code", func(t *testing.T) {
		token := syntheticGitHubToken()
		for _, c := range []struct {
			value   string
			ruleID  string
			ordinal int
			want    string
		}{
			{token, "github_token", 1, "ghp_" + strings.Repeat("X", 35) + "1"},
			{"Xq7Lm2Pz9!Wr4Tn5", "contextual_password", 2, strings.Repeat("X", 15) + "2"},
			{"sk-ant-" + strings.Repeat("aB3d", 6), "anthropic_key", 42, "sk-ant-" + strings.Repeat("X", 22) + "42"},
			{"sk-" + strings.Repeat("aB3d", 6), "openai_key", 999, "sk-" + strings.Repeat("X", 21) + "999"},
			// Préfixe de la règle du constat seulement : un mot de passe ou une autre règle n'en a aucun.
			{"dapi" + strings.Repeat("q7Lm", 4), "contextual_password", 1, strings.Repeat("X", 19) + "1"},
			{"AKIA" + strings.Repeat("Q7LM", 4), "contextual_password", 1, strings.Repeat("X", 19) + "1"},
			{token, "high_entropy", 1, strings.Repeat("X", 39) + "1"},
			{token, "openai_key", 1, strings.Repeat("X", 39) + "1"},
			// Place insuffisante avec le préfixe : sans préfixe.
			{"ghp_abc", "github_token", 7, "XXXXXX7"},
			// Minimum « XXXX<n> », plus long que la valeur.
			{"ab", "", 3, "XXXX3"},
			{"", "", 12, "XXXX12"},
			// Longueur en points de code, pas en octets.
			{"éé😀😀ééé", "", 5, "XXXXXX5"},
			// Octet hors UTF-8 : un caractère.
			{"ab\xffcd", "", 1, "XXXX1"},
		} {
			got, err := substituteFor([]byte(c.value), c.ruleID, c.ordinal)
			if err != nil || got != c.want {
				t.Errorf("%q, %d : %q (%v), attendu %q", c.value, c.ordinal, got, err, c.want)
			}
			if !isSubstitute([]byte(got)) {
				t.Errorf("%q hors de la grammaire", got)
			}
		}
	})
	t.Run("numéro hors de 1 à 999 : ErrExpurgateOrdinal", func(t *testing.T) {
		for _, n := range []int{0, -1, 1000, 1 << 40} {
			if got, err := substituteFor([]byte("valeur"), "", n); got != "" || !errors.Is(err, ErrExpurgateOrdinal) {
				t.Errorf("%d : %q %v", n, got, err)
			}
		}
	})
}

// prefixSamples : longueur de la suite de « A » qui fait d'un préfixe une valeur de sa règle (40 par défaut), ou
// valeur complète pour les règles à plusieurs segments.
var prefixSamples = map[string]string{
	"AIza": "AIza" + strings.Repeat("A", 35), "npm_": "npm_" + strings.Repeat("A", 36), "dapi": "dapi" + strings.Repeat("A", 32),
	"dop_v1_": "dop_v1_" + strings.Repeat("A", 64), "shpat_": "shpat_" + strings.Repeat("A", 32),
	"shpss_": "shpss_" + strings.Repeat("A", 32), "shpca_": "shpca_" + strings.Repeat("A", 32),
	"shppa_": "shppa_" + strings.Repeat("A", 32), "SG.": "SG." + strings.Repeat("A", 22) + "." + strings.Repeat("A", 43),
	"eyJ": "eyJ" + "AAAA.eyJ" + "BBBB." + strings.Repeat("C", 8),
}

func TestSubstitutePrefixesFromInitialPack(t *testing.T) {
	t.Run("chaque préfixe vient du motif d'une règle « motif seul » du Pack initial", func(t *testing.T) {
		p := loadInitialPack(t)
		fixed := map[string]*regexp.Regexp{}
		for _, r := range p.Rules {
			if r.Family == pack.Family(familyFixedPattern) {
				fixed[r.RuleID] = regexp.MustCompile(r.Pattern)
			}
		}
		count := 0
		for _, r := range substituteRulePrefixes {
			re, ok := fixed[r.ruleID]
			if !ok {
				t.Errorf("%s : pas une règle « motif seul » du Pack initial", r.ruleID)
				continue
			}
			for _, prefix := range r.prefixes {
				count++
				sample, ok := prefixSamples[prefix]
				if !ok {
					sample = prefix + strings.Repeat("A", 40)
					if r.ruleID == "aws_access_key_id" {
						sample = prefix + strings.Repeat("A", 16)
					}
				}
				if loc := re.FindStringIndex(sample); loc == nil || loc[0] != 0 {
					t.Errorf("%q : le motif de %s ne le porte pas", prefix, r.ruleID)
				}
			}
		}
		if count != len(SubstitutePrefixes()) {
			t.Fatalf("%d préfixes, table de %d", count, len(SubstitutePrefixes()))
		}
	})
}

// substituteTemplates : gabarits où un Substitut ne doit jamais être détecté.
var substituteTemplates = []struct {
	name     string
	language string
	text     func(s string) string
}{
	{"seul", "", func(s string) string { return s }},
	{"shell", "", func(s string) string { return "export TOKEN=" + s }},
	{"shell entre guillemets", "shellscript", func(s string) string { return `export TOKEN="` + s + `"` }},
	{"JSON", "", func(s string) string { return `{"token": "` + s + `", "next": 1}` }},
	{"JSON typé", "json", func(s string) string { return `{"api_key": "` + s + `"}` }},
	{"YAML", "yaml", func(s string) string { return "auth:\n  token: " + s + "\n  user: app\n" }},
	{".env", "dotenv", func(s string) string { return "API_KEY=" + s + "\nDB_PASSWORD=" + s + "\n" }},
	{".env sans langage", "", func(s string) string { return "API_KEY=" + s + "\nDB_PASSWORD=" + s + "\n" }},
	{"URL", "", func(s string) string { return "postgres://app:" + s + "@db:5432/x" }},
	{"URL https", "", func(s string) string { return "git clone https://user:" + s + "@example.org/r.git" }},
	{"Authorization: Bearer", "", func(s string) string { return "Authorization: Bearer " + s }},
	{"curl -u", "", func(s string) string { return basicAuthCommand() + s + " https://x" }},
	{"en-tête curl", "", func(s string) string { return `curl -H "Authorization: Bearer ` + s + `" https://x` }},
	{"en-tête curl en JSON", "", func(s string) string { return `{"cmd": "curl -H \"Authorization: Bearer ` + s + `\" https://x"}` }},
	{"code", "typescript", func(s string) string { return `const apiKey = "` + s + `";` }},
}

func TestSubstituteNeverDetected(t *testing.T) {
	t.Run("un Substitut n'est jamais détecté, seul ni dans les gabarits shell, JSON, YAML, .env, URL et Bearer", func(t *testing.T) {
		rules := loadInitialRules(t)
		var substitutes []string
		for _, prefix := range append([]string{""}, SubstitutePrefixes()...) {
			for _, filler := range []int{4, 20, 36} {
				for _, n := range []string{"1", "42", "999"} {
					substitutes = append(substitutes, prefix+strings.Repeat("X", filler)+n)
				}
			}
		}
		checked := 0
		for _, s := range substitutes {
			for _, tpl := range substituteTemplates {
				if strings.Contains(s, "/") && strings.HasPrefix(tpl.name, "URL") {
					continue // un « / » dans l'information utilisateur termine l'autorité : ce n'est plus un mot de passe.
				}
				checked++
				result := Scan([]byte(tpl.text(s)), rules, Options{LanguageID: tpl.language})
				if !result.Complete || len(result.Findings) > 0 {
					t.Errorf("%q, gabarit %s : %+v", s, tpl.name, result)
				}
			}
		}
		t.Logf("%d textes analysés", checked)
	})
	t.Run("corps PEM fait d'un Substitut, lignes BEGIN et END intactes : jamais détecté", func(t *testing.T) {
		rules := loadInitialRules(t)
		for _, label := range []string{"RSA PRIVATE KEY", "PRIVATE KEY", "OPENSSH PRIVATE KEY", "PGP PRIVATE KEY BLOCK"} {
			begin, end := "-----BEGIN "+label+"-----", "-----END "+label+"-----"
			body := strings.Repeat("X", 120) + "7"
			for name, text := range map[string]string{
				"bloc":                 begin + "\n" + body + "\n" + end + "\n",
				"bloc CRLF":            begin + "\r\n" + body + "\r\n" + end,
				"incomplet":            "clé :\n" + begin + "\n" + body + "\n",
				"JSON échappé":         `{"key": "` + begin + `\n` + body + `\n` + end + `"}`,
				"affectation .env":     "PRIVATE_KEY=\"" + begin + "\n" + body + "\n" + end + "\"\n",
				"affectation YAML":     "private_key: |\n  " + begin + "\n  " + body + "\n  " + end + "\n",
				"bloc sans fin ligne":  begin + body + end,
				"bloc dans un message": "Voici la clé :\n" + begin + "\n" + body + "\n" + end + "\nmerci",
			} {
				for _, language := range []string{"", "yaml", "dotenv"} {
					result := Scan([]byte(text), rules, Options{LanguageID: language})
					if !result.Complete || len(result.Findings) > 0 {
						t.Errorf("%s, %s, %q : %+v", label, name, language, result.Findings)
					}
				}
			}
		}
	})
}

func TestFakeSubstituteDetected(t *testing.T) {
	t.Run("un corps qui porte autre chose que des X reste détecté", func(t *testing.T) {
		rules := loadInitialRules(t)
		for _, value := range []string{
			"ghp_" + strings.Repeat("X", 34) + "1a",
			"ghp_" + strings.Repeat("X", 15) + "A" + strings.Repeat("X", 19) + "1",
			"ghp_" + strings.Repeat("x", 35) + "1",
			"ghp_" + strings.Repeat("X", 32) + "1234",
		} {
			for _, tpl := range []func(string) string{
				func(s string) string { return s },
				func(s string) string { return "export TOKEN=" + s },
				func(s string) string { return "Authorization: Bearer " + s },
			} {
				result := Scan([]byte(tpl(value)), rules, Options{})
				if !result.Complete || len(result.Findings) == 0 {
					t.Errorf("%q non détecté", tpl(value))
				}
			}
		}
	})
}

// FuzzSubstituteGrammar : un caractère alphanumérique quelconque posé dans le corps d'un Substitut de jeton GitHub ;
// si le corps n'est plus dans la grammaire, la valeur est détectée.
//
//	go test ./detect -run '^$' -fuzz '^FuzzSubstituteGrammar$' -fuzztime=60s
func FuzzSubstituteGrammar(f *testing.F) {
	for _, seed := range []struct {
		pos  uint
		char byte
	}{{0, 'a'}, {34, 'A'}, {35, 'b'}, {35, '7'}, {12, 'X'}, {3, '0'}} {
		f.Add(seed.pos, seed.char)
	}
	rules := loadInitialRules(f)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	f.Fuzz(func(t *testing.T, pos uint, char byte) {
		body := []byte(strings.Repeat("X", 35) + "1")
		body[pos%uint(len(body))] = alphabet[int(char)%len(alphabet)]
		value := append([]byte("ghp_"), body...)
		if isSubstitute(value) {
			if result := Scan(value, rules, Options{}); !result.Complete || len(result.Findings) > 0 {
				t.Fatalf("Substitut détecté : %+v", result)
			}
			return
		}
		for _, text := range [][]byte{value, append([]byte("export TOKEN="), value...)} {
			if result := Scan(text, rules, Options{}); !result.Complete || len(result.Findings) == 0 {
				t.Fatalf("corps altéré non détecté (position %d)", pos%uint(len(body)))
			}
		}
	})
}

// expurgateCase est une ligne de la matrice de la fiche.
type expurgateCase struct {
	name    string
	input   string
	ordinal int
	want    string
	spans   [][2]int // étendues remplacées, en octets du texte d'origine
}

func TestExpurgateMatrix(t *testing.T) {
	rules := loadInitialRules(t)
	token := syntheticGitHubToken()
	password := syntheticPassword() + "5"
	opaque := "aZ3kQ9mW2xL7pR4tY8vB1nC6"
	pem := syntheticPEM("\n")
	for _, c := range []expurgateCase{
		{"jeton GitHub", "export TOKEN=" + token, 1, "export TOKEN=ghp_" + strings.Repeat("X", 35) + "1", [][2]int{{13, 53}}},
		{"URL", "postgres://app:" + password + "@db:5432/x", 2, "postgres://app:" + strings.Repeat("X", 15) + "2@db:5432/x", [][2]int{{15, 31}}},
		{"Bearer", "Authorization: Bearer " + opaque, 3, "Authorization: Bearer " + strings.Repeat("X", 23) + "3", [][2]int{{22, 46}}},
		{"Bearer et jeton GitHub", "Authorization: Bearer " + token, 4, "Authorization: Bearer ghp_" + strings.Repeat("X", 35) + "4", [][2]int{{22, 62}}},
		{"cli_basic_auth", basicAuthCommand() + password + " https://x", 5, basicAuthCommand() + strings.Repeat("X", 15) + "5 https://x", [][2]int{{14, 30}}},
		{"PEM", pem + "\n", 6, "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Repeat("X", 116) + "6\n-----END RSA PRIVATE KEY-----\n", [][2]int{{32, 149}}},
		{"PEM incomplet", pemHeader("PRIVATE KEY") + "\nMIIEow" + strings.Repeat("q7Lm2Pz9Wr4Tn", 4) + "\n", 7, pemHeader("PRIVATE KEY") + "\n" + strings.Repeat("X", 57) + "7\n", [][2]int{{28, 86}}},
		{"numéro à trois chiffres", "export TOKEN=" + token, 999, "export TOKEN=ghp_" + strings.Repeat("X", 33) + "999", [][2]int{{13, 53}}},
		{"en-tête curl", `curl -H "Authorization: Bearer ` + opaque + `" https://x`, 9, `curl -H "Authorization: Bearer ` + strings.Repeat("X", 23) + `9" https://x`, [][2]int{{31, 55}}},
		{"jeton comme nom d'utilisateur d'une URL", "git clone https://" + opaque + ":x-oauth-basic@github.com/o/r.git", 1, "git clone https://" + strings.Repeat("X", 37) + "1@github.com/o/r.git", [][2]int{{18, 56}}},
		// Jeton GitHub en nom d'utilisateur : étendue fusionnée de deux règles, URL entière.
		{"jeton GitHub comme nom d'utilisateur d'une URL", "git clone https://" + token + ":x-oauth-basic@github.com/o/r.git", 1, "git clone " + strings.Repeat("X", 80) + "1", [][2]int{{10, 91}}},
		{"nom d'utilisateur ordinaire d'une URL", "https://deploy-bot:" + password + "@example.org/x", 1, "https://deploy-bot:" + strings.Repeat("X", 15) + "1@example.org/x", [][2]int{{19, 35}}},
		{"clé d'API comme utilisateur de curl -u", curlUser(opaque) + "X https://x", 1, "curl -u " + strings.Repeat("X", 25) + "1 https://x", [][2]int{{8, 34}}},
		{"mot de passe qui commence comme un jeton Databricks", "PASSWORD=dapi" + strings.Repeat("q7Lm", 4), 1, "PASSWORD=" + strings.Repeat("X", 19) + "1", [][2]int{{9, 29}}},
		{"mot de passe qui commence comme une clé AWS", "DB_PASSWORD=AKIA" + strings.Repeat("q7Lm", 4), 1, "DB_PASSWORD=" + strings.Repeat("X", 19) + "1", [][2]int{{12, 32}}},
		{"schéma dans un mot de passe : remplacé avec la valeur", `DB_PASSWORD="Token ` + strings.Repeat("q7Lm", 4) + `"`, 1, `DB_PASSWORD="` + strings.Repeat("X", 21) + `1"`, [][2]int{{13, 35}}},
		{"faux Substitut détecté", "TOKEN=ghp_" + strings.Repeat("X", 34) + "1a", 8, "TOKEN=ghp_" + strings.Repeat("X", 35) + "8", [][2]int{{6, 46}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			text, subs, result := expurgateBoth(t, []byte(c.input), rules, nil, Options{}, func() func(Finding) (int, bool) { return fixedOrdinal(c.ordinal) })
			if result.Failure != SanitizeNone || string(text) != c.want {
				t.Fatalf("%s : %q, attendu %q", result.Failure, text, c.want)
			}
			if len(subs) != len(c.spans) {
				t.Fatalf("%d Substitutions, attendu %d", len(subs), len(c.spans))
			}
			for i, s := range subs {
				if s.ByteStart != c.spans[i][0] || s.ByteEnd != c.spans[i][1] || s.Ordinal != c.ordinal || !isSubstitute([]byte(s.Replacement)) {
					t.Errorf("Substitution %+v, étendue attendue %v", s, c.spans[i])
				}
			}
			if again := Scan(text, rules, Options{}); !again.Complete || len(again.Findings) > 0 {
				t.Fatalf("constat après expurgation : %+v", again.Findings)
			}
		})
	}
}

func TestExpurgate(t *testing.T) {
	rules := loadInitialRules(t)
	token := syntheticGitHubToken()
	t.Run("étendues UTF-16 sur un texte non ASCII, octets hors des étendues gardés", func(t *testing.T) {
		content := "é😀 clé « " + token + " »\nDB_PASSWORD=" + syntheticPassword() + "\nfin 😀"
		text, subs, result := expurgateBoth(t, []byte(content), rules, nil, Options{}, func() func(Finding) (int, bool) { return startOrdinals(10) })
		if result.Failure != SanitizeNone || len(subs) != 2 {
			t.Fatalf("%s %+v", result.Failure, subs)
		}
		want := "é😀 clé « ghp_" + strings.Repeat("X", 34) + "10 »\nDB_PASSWORD=" + strings.Repeat("X", 13) + "11\nfin 😀"
		if string(text) != want {
			t.Fatalf("%q", text)
		}
		for _, s := range subs {
			prefix := utf16.Encode([]rune(content[:s.ByteStart]))
			inner := utf16.Encode([]rune(content[s.ByteStart:s.ByteEnd]))
			if s.UTF16Start != len(prefix) || s.UTF16End != len(prefix)+len(inner) {
				t.Errorf("%+v : UTF-16 attendu %d-%d", s, len(prefix), len(prefix)+len(inner))
			}
		}
		if subs[0].RuleID != "github_token" || subs[0].SecretType != "provider_token" || subs[1].Ordinal != 11 {
			t.Errorf("%+v", subs)
		}
	})
	t.Run("Empreinte locale du constat avec une clé, vide sans clé", func(t *testing.T) {
		raw := make([]byte, FingerprintKeyBytes)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		key, err := NewFingerprintKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		defer key.Wipe()
		content := []byte("A " + token + " et B " + token)
		_, subs, result := expurgateBoth(t, content, rules, &key, Options{}, func() func(Finding) (int, bool) { return startOrdinals(1) })
		if result.Failure != SanitizeNone || len(subs) != 2 || len(subs[0].LocalFingerprint) != 32 ||
			subs[0].LocalFingerprint != subs[1].LocalFingerprint || subs[0].LocalFingerprint != result.Initial.Findings[0].LocalFingerprint {
			t.Fatalf("%+v", subs)
		}
		_, subs, _ = ExpurgateAndRescan(content, rules, nil, Options{}, fixedOrdinal(1))
		if subs[0].LocalFingerprint != "" {
			t.Fatal("Empreinte locale sans clé")
		}
	})
	t.Run("le numéro reçoit le constat ramené à la partie remplacée", func(t *testing.T) {
		content := []byte("postgres://app:" + syntheticPassword() + "@db/x")
		var got []Finding
		_, _, result := ExpurgateAndRescan(content, rules, nil, Options{}, func(f Finding) (int, bool) {
			got = append(got, f)
			return 1, true
		})
		if result.Failure != SanitizeNone || len(got) != 1 || got[0].ByteStart != 15 || got[0].ByteEnd != 15+len(syntheticPassword()) ||
			got[0].RuleID != "database_url_credentials" {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("sans constat : copie de l'entrée, aucune Substitution ni numéro demandé", func(t *testing.T) {
		content := []byte("rien à signaler")
		text, subs, result := ExpurgateAndRescan(content, rules, nil, Options{}, nil)
		if result.Failure != SanitizeNone || !bytes.Equal(text, content) || &text[0] == &content[0] || subs == nil || len(subs) != 0 {
			t.Fatalf("%q %+v %+v", text, subs, result)
		}
	})
	t.Run("étendues fusionnées : un Substitut, représentée par le premier constat", func(t *testing.T) {
		content := []byte("0123456789abcdef")
		result := Result{Complete: true, Failure: FailureNone, Findings: []Finding{
			{RuleID: "b", Score: 10, ByteStart: 4, ByteEnd: 8}, {RuleID: "a", Score: 90, ByteStart: 2, ByteEnd: 6},
			{RuleID: "c", Score: 50, ByteStart: 8, ByteEnd: 10}, {RuleID: "vide", ByteStart: 12, ByteEnd: 12},
			{RuleID: "d", Score: 50, ByteStart: 12, ByteEnd: 16},
		}}
		text, subs, err := Expurgate(content, result, startOrdinals(1))
		if err != nil || string(text) != "01XXXXXXX1abXXXX2" || len(subs) != 2 || subs[0].RuleID != "a" ||
			subs[0].ByteStart != 2 || subs[0].ByteEnd != 10 || subs[1].RuleID != "d" {
			t.Fatalf("%q %+v %v", text, subs, err)
		}
	})
	t.Run("étendue fusionnée qui n'a pas la forme de sa règle : remplacée en entier", func(t *testing.T) {
		content := []byte("x postgres://app:pw@db/x y")
		for _, f := range []Finding{
			{RuleID: ruleDatabaseURL, ByteStart: 0, ByteEnd: 24}, // déborde avant l'URL
			{RuleID: ruleDatabaseURL, ByteStart: 2, ByteEnd: 26}, // déborde après l'URL (espace)
			{RuleID: rulePrivateKeyComplete, ByteStart: 2, ByteEnd: 24},
			{RuleID: ruleCLIBasicAuth, ByteStart: 0, ByteEnd: 24}, // espace dans l'étendue
		} {
			start, end := secretPart(content, f)
			if start != f.ByteStart || end != f.ByteEnd {
				t.Errorf("%+v : %d-%d", f, start, end)
			}
		}
	})
}

func TestExpurgateRefusals(t *testing.T) {
	rules := loadInitialRules(t)
	token := syntheticGitHubToken()
	content := []byte("TOKEN=" + token)
	t.Run("analyse incomplète : erreur, aucun texte", func(t *testing.T) {
		for name, result := range map[string]Result{
			"scan_limit": {Failure: FailureScanLimit}, "scan_error": {Failure: FailureScanError},
			"complet sans issue none": {Complete: true, Failure: FailureScanError}, "issue none sans complete": {Failure: FailureNone},
		} {
			if text, subs, err := Expurgate(content, result, fixedOrdinal(1)); text != nil || subs != nil || !errors.Is(err, ErrExpurgateIncomplete) {
				t.Errorf("%s : %v", name, err)
			}
		}
		huge := bytes.Repeat([]byte("a"), MaxInputBytes+1)
		if text, subs, result := ExpurgateAndRescan(huge, rules, nil, Options{}, fixedOrdinal(1)); text != nil || subs != nil ||
			result.Failure != SanitizeIncomplete || result.Initial.Failure != FailureScanLimit {
			t.Fatalf("%+v", result)
		}
	})
	t.Run("étendue hors du contenu : erreur, aucun texte", func(t *testing.T) {
		for name, f := range map[string]Finding{
			"début négatif": {ByteStart: -1, ByteEnd: 2}, "fin avant début": {ByteStart: 5, ByteEnd: 4},
			"fin après contenu": {ByteStart: 8, ByteEnd: len(content) + 1},
		} {
			result := Result{Complete: true, Failure: FailureNone, Findings: []Finding{{RuleID: "ok", ByteStart: 0, ByteEnd: 2}, f}}
			if text, subs, err := Expurgate(content, result, fixedOrdinal(1)); text != nil || subs != nil || !errors.Is(err, ErrExpurgateSpan) {
				t.Errorf("%s : %v", name, err)
			}
		}
	})
	t.Run("contenu hors UTF-8 : refusé, aucun texte", func(t *testing.T) {
		invalid := append([]byte("é \xff "), content...)
		initial := Scan(invalid, rules, Options{})
		if text, subs, err := Expurgate(invalid, initial, fixedOrdinal(1)); text != nil || subs != nil || !errors.Is(err, ErrExpurgateEncoding) {
			t.Errorf("Expurgate : %v", err)
		}
		if text, subs, result := ExpurgateAndRescan(invalid, rules, nil, Options{}, fixedOrdinal(1)); text != nil || subs != nil ||
			result.Failure != SanitizeIncomplete || !result.Initial.Complete {
			t.Errorf("ExpurgateAndRescan : %+v", result)
		}
		if text, _, result := ExpurgateAndRescan([]byte("rien \xff"), rules, nil, Options{}, fixedOrdinal(1)); text != nil || result.Failure != SanitizeIncomplete {
			t.Errorf("sans constat : %+v", result)
		}
	})
	t.Run("étendue qui coupe un caractère : ErrExpurgateSpan", func(t *testing.T) {
		text := []byte("aé😀b")
		for _, f := range []Finding{{ByteStart: 2, ByteEnd: 3}, {ByteStart: 1, ByteEnd: 4}, {ByteStart: 3, ByteEnd: 5}} {
			result := Result{Complete: true, Failure: FailureNone, Findings: []Finding{f}}
			if out, subs, err := Expurgate(text, result, fixedOrdinal(1)); out != nil || subs != nil || !errors.Is(err, ErrExpurgateSpan) {
				t.Errorf("%+v : %v", f, err)
			}
		}
		result := Result{Complete: true, Failure: FailureNone, Findings: []Finding{{ByteStart: 1, ByteEnd: 7}}}
		if out, _, err := Expurgate(text, result, fixedOrdinal(1)); err != nil || string(out) != "aXXXX1b" {
			t.Errorf("%q %v", out, err)
		}
	})
	t.Run("numéro nil refusé même sans étendue à remplacer", func(t *testing.T) {
		empty := Result{Complete: true, Failure: FailureNone}
		if out, subs, err := Expurgate([]byte("rien"), empty, nil); out != nil || subs != nil || !errors.Is(err, ErrExpurgateOrdinal) {
			t.Errorf("%v", err)
		}
	})
	t.Run("numéro absent, refusé ou hors de 1 à 999 : ErrExpurgateOrdinal, aucun texte", func(t *testing.T) {
		initial := Scan(content, rules, Options{})
		for name, ordinal := range map[string]func(Finding) (int, bool){
			"nil": nil, "faux": func(Finding) (int, bool) { return 1, false }, "0": fixedOrdinal(0), "1000": fixedOrdinal(1000),
		} {
			if text, subs, err := Expurgate(content, initial, ordinal); text != nil || subs != nil || !errors.Is(err, ErrExpurgateOrdinal) {
				t.Errorf("%s : %v", name, err)
			}
			if text, subs, result := ExpurgateAndRescan(content, rules, nil, Options{}, ordinal); text != nil || subs != nil ||
				result.Failure != SanitizeOrdinal || result.Final.Failure != FailureScanError {
				t.Errorf("%s : %+v", name, result)
			}
		}
	})
	t.Run("clé absente ou effacée : analyse incomplète", func(t *testing.T) {
		var zero FingerprintKey
		if text, _, result := ExpurgateAndRescan(content, rules, &zero, Options{}, fixedOrdinal(1)); text != nil || result.Failure != SanitizeIncomplete {
			t.Fatalf("%+v", result)
		}
		raw := make([]byte, FingerprintKeyBytes)
		raw[0] = 1
		key, err := NewFingerprintKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		key.Wipe()
		if text, _, result := ExpurgateAndRescan(bytes.Repeat([]byte("a"), MaxInputBytes+1), rules, &key, Options{}, fixedOrdinal(1)); text != nil ||
			result.Initial.Failure != FailureScanLimit {
			t.Fatalf("%+v", result)
		}
	})
}

// swapExpurgateScan remplace l'analyse d'ExpurgateAndRescan et rend la fonction qui la rétablit.
func swapExpurgateScan(scan func([]byte, *Rules, Options, *FingerprintKey) Result) func() {
	previous := expurgateScan
	expurgateScan = scan
	return func() { expurgateScan = previous }
}

func TestExpurgateResidualLadder(t *testing.T) {
	rules := loadInitialRules(t)
	content := []byte("a b\nkey " + syntheticGitHubToken() + " suite\nfin")
	t.Run("résidu : élargi au jeton, puis à la ligne, puis échec ; chaque copie expurgée effacée", func(t *testing.T) {
		var seen [][]byte
		calls := 0
		defer swapExpurgateScan(func(c []byte, r *Rules, o Options, k *FingerprintKey) Result {
			calls++
			if calls == 1 {
				return scan(c, r, o, k)
			}
			seen = append(seen, c)
			// Résidu permanent sur « key » (octets 4 à 7 du texte expurgé, les mêmes dans le texte d'origine).
			return Result{Complete: true, Failure: FailureNone, Findings: []Finding{{RuleID: "r", SecretType: "s", ByteStart: 4, ByteEnd: 7}}}
		})()
		text, subs, result := ExpurgateAndRescan(content, rules, nil, Options{}, fixedOrdinal(1))
		if text != nil || subs != nil || result.Failure != SanitizeResidual || len(seen) != 3 {
			t.Fatalf("%v %+v, %d analyses", text != nil, result, len(seen))
		}
		for i, c := range seen {
			if !bytes.Equal(c, make([]byte, len(c))) {
				t.Errorf("copie expurgée %d non effacée", i)
			}
		}
	})
	t.Run("résidu levé par l'élargissement au jeton ; puis par la ligne", func(t *testing.T) {
		for _, c := range []struct {
			cleanAfter int
			subs       int
			want       string
		}{
			{2, 2, "a b\nXXXX1 ghp_" + strings.Repeat("X", 35) + "1 suite\nfin"},
			{3, 1, "a b\n" + strings.Repeat("X", 49) + "1\nfin"},
		} {
			calls := 0
			restore := swapExpurgateScan(func(text []byte, r *Rules, o Options, k *FingerprintKey) Result {
				calls++
				if calls == 1 || calls > c.cleanAfter {
					return scan(text, r, o, k)
				}
				return Result{Complete: true, Failure: FailureNone, Findings: []Finding{{RuleID: "r", ByteStart: 4, ByteEnd: 7}}}
			})
			text, subs, result := ExpurgateAndRescan(content, rules, nil, Options{}, fixedOrdinal(1))
			restore()
			if result.Failure != SanitizeNone || string(text) != c.want || len(subs) != c.subs {
				t.Errorf("%d : %s %q %+v", c.cleanAfter, result.Failure, text, subs)
			}
		}
	})
	t.Run("seconde analyse incomplète : aucun texte, copie effacée", func(t *testing.T) {
		var second []byte
		calls := 0
		defer swapExpurgateScan(func(c []byte, r *Rules, o Options, k *FingerprintKey) Result {
			calls++
			if calls == 1 {
				return scan(c, r, o, k)
			}
			second = c
			return incomplete(FailureScanError)
		})()
		text, _, result := ExpurgateAndRescan(content, rules, nil, Options{}, fixedOrdinal(1))
		if text != nil || result.Failure != SanitizeIncomplete || !bytes.Equal(second, make([]byte, len(second))) {
			t.Fatalf("%+v", result)
		}
	})
	t.Run("positions d'un résidu ramenées au texte d'origine", func(t *testing.T) {
		spans := []expurgatedSpan{{origStart: 2, origEnd: 6, outStart: 2, outEnd: 8}, {origStart: 10, origEnd: 20, outStart: 12, outEnd: 17}}
		for _, c := range [][4]int{{0, 1, 0, 1}, {3, 5, 2, 6}, {8, 9, 6, 7}, {9, 14, 7, 20}, {17, 19, 20, 22}, {2, 8, 2, 6}} {
			if start, end := originalRange(spans, c[0], c[1]); start != c[2] || end != c[3] {
				t.Errorf("%v : %d-%d", c, start, end)
			}
		}
		if s, e := widenToLine([]byte("ab\r\ncd ef\r\ngh"), 5, 6); s != 4 || e != 9 {
			t.Errorf("ligne : %d-%d", s, e)
		}
		if s, e := widenToToken([]byte("ab cd😀ef gh"), 5, 6); s != 4 || e != 12 {
			t.Errorf("jeton : %d-%d", s, e)
		}
	})
}

// TestExpurgateRedactResiduals rejoue par ExpurgateAndRescan chaque cas des vecteurs du masquage, dont les cinq que le
// masquage laisse en résidu : le nombre de résidus restants est consigné, l'objectif est 0. Un échec ne rend aucun
// texte ; un texte rendu est sans constat à une nouvelle analyse indépendante.
func TestExpurgateRedactResiduals(t *testing.T) {
	t.Run("les résidus du masquage sont levés par l'expurgation", func(t *testing.T) {
		rules := loadInitialRules(t)
		vectors := loadRedactVectors(t)
		corpus := redactCorpus(t)
		counts := map[SanitizeFailure]int{}
		residualCases, remaining := 0, 0
		for _, c := range vectors.Cases {
			content, options, _ := c.input(t, corpus)
			text, subs, result := ExpurgateAndRescan(content, rules, nil, options, startOrdinals(1))
			counts[result.Failure]++
			if c.Expected.Failure == SanitizeResidual {
				residualCases++
				if result.Failure != SanitizeNone {
					remaining++
				}
			}
			switch {
			case result.Failure != SanitizeNone && (text != nil || subs != nil):
				t.Errorf("%s : texte rendu après un échec", c.ID)
			case result.Failure == SanitizeNone:
				if again := Scan(text, rules, options); !again.Complete || len(again.Findings) > 0 {
					t.Errorf("%s : constat après expurgation", c.ID)
				}
			case c.Expected.Failure == SanitizeNone && utf8.Valid(content):
				t.Errorf("%s : masqué par Redact, refusé par l'expurgation (%s)", c.ID, result.Failure)
			}
		}
		t.Logf("%d cas : %v ; résidus du masquage : %d, restants après expurgation : %d", len(vectors.Cases), counts, residualCases, remaining)
		if residualCases != 5 || remaining != 0 {
			t.Fatalf("%d résidus du masquage, %d restants", residualCases, remaining)
		}
	})
}

// TestExpurgateCorpus : pour chaque cas du corpus de parité qui a un constat, l'expurgation réussie remplace chaque
// étendue par son Substitut, garde tels quels les octets hors des étendues, son texte est sans constat à une nouvelle
// analyse indépendante (Workers 1 et 8), et il ne contient aucune fenêtre de 8 octets (la partie entière si elle est
// plus courte) d'une partie remplacée, hors préfixe public gardé, sauf une fenêtre que l'entrée contient aussi hors des
// parties remplacées (comptée). Un échec n'affiche que l'identifiant du cas.
func TestExpurgateCorpus(t *testing.T) {
	t.Run("expurgation du corpus de parité", func(t *testing.T) {
		rules := loadInitialRules(t)
		counts := map[SanitizeFailure]int{}
		excused := 0
		for _, file := range corpusFiles(t) {
			for _, c := range loadCorpusFile(t, file) {
				if !c.Expected.Complete || len(c.Expected.Findings) == 0 {
					continue
				}
				options, _ := c.options()
				content := c.bytes(t)
				text, subs, result := expurgateBoth(t, content, rules, nil, options, func() func(Finding) (int, bool) { return startOrdinals(1) })
				counts[result.Failure]++
				if result.Failure != SanitizeNone {
					if text != nil || subs != nil {
						t.Errorf("%s : texte rendu après un échec", c.ID)
					}
					continue
				}
				if diff := substitutionDifference(content, text, subs); diff != "" {
					t.Errorf("%s : %s", c.ID, diff)
				}
				if again := Scan(text, rules, options); !again.Complete || len(again.Findings) > 0 {
					t.Errorf("%s : constat après expurgation", c.ID)
				}
				excused += replacedWindowsLeft(t, c.ID, content, text, subs)
			}
		}
		t.Logf("issues : %v ; %d fenêtres présentes aussi hors des étendues remplacées dans l'entrée", counts, excused)
		if counts[SanitizeNone] == 0 || counts[SanitizeResidual] != 0 {
			t.Fatalf("issues %v", counts)
		}
	})
}

// substitutionDifference reconstruit le texte expurgé à partir du texte d'origine et des Substitutions ; vide s'il est
// égal au texte rendu. Le message ne recopie jamais le texte.
func substitutionDifference(content, text []byte, subs []Substitution) string {
	var rebuilt []byte
	cursor := 0
	for i, s := range subs {
		if s.ByteStart < cursor || s.ByteEnd <= s.ByteStart || s.ByteEnd > len(content) {
			return fmt.Sprintf("Substitution %d hors d'ordre ou du contenu", i)
		}
		if !isSubstitute([]byte(s.Replacement)) || s.Ordinal < 1 || s.Ordinal > 999 {
			return fmt.Sprintf("Substitution %d hors de la grammaire", i)
		}
		rebuilt = append(append(rebuilt, content[cursor:s.ByteStart]...), s.Replacement...)
		cursor = s.ByteEnd
	}
	if !bytes.Equal(append(rebuilt, content[cursor:]...), text) {
		return "texte expurgé différent du texte d'origine et des Substitutions"
	}
	return ""
}

// replacedWindowsLeft vérifie qu'aucune fenêtre de 8 octets d'une partie remplacée ne reste dans le texte expurgé, hors
// fenêtre que l'entrée contient aussi hors des parties remplacées ; rend le nombre de ces fenêtres excusées.
func replacedWindowsLeft(t *testing.T, id string, content, text []byte, subs []Substitution) int {
	t.Helper()
	covered := make([]Finding, 0, len(subs))
	for _, s := range subs {
		covered = append(covered, Finding{ByteStart: s.ByteStart, ByteEnd: s.ByteEnd})
	}
	outside := outsideSpans(content, covered)
	excused := 0
	for _, s := range subs {
		value := content[s.ByteStart:s.ByteEnd]
		// Préfixe public gardé par le Substitut (table fermée) : une fenêtre qui n'en sort pas n'est pas secrète.
		public := 0
		if prefix := substitutePrefixOf(value, s.RuleID); strings.HasPrefix(s.Replacement, prefix) {
			public = len(prefix)
		}
		width := min(8, len(value))
		for i := 0; i+width <= len(value) && width > 0; i++ {
			window := value[i : i+width]
			switch {
			case i+width <= public:
			case !bytes.Contains(text, window):
			case containsIn(outside, window):
				excused++
			default:
				t.Errorf("%s : fenêtre d'une partie remplacée (%s) dans le texte expurgé", id, s.RuleID)
			}
		}
	}
	return excused
}

// FuzzExpurgate : quelle que soit l'entrée, l'issue est dans la liste fermée ; un échec ne rend ni texte ni
// Substitution ; une expurgation réussie est le texte d'origine où chaque étendue rendue est remplacée par son
// Substitut, et une nouvelle analyse indépendante de ce texte est complète et sans constat.
//
//	go test ./detect -run '^$' -fuzz '^FuzzExpurgate$' -fuzztime=60s
func FuzzExpurgate(f *testing.F) {
	token := syntheticGitHubToken()
	for _, seed := range []string{
		"", "rien à signaler", "TOKEN=" + token, token + token, "DB_PASSWORD=" + syntheticPassword() + "\n" + token,
		"API_KEY=" + token + "\nNEXT=another", "Authorization: Bearer " + token, "postgres://app:" + syntheticPassword() + "@db/x",
		syntheticPEM("\n"), basicAuthCommand() + syntheticPassword() + " https://x", "é😀 " + token + " \xff",
		"ghp_" + strings.Repeat("X", 35) + "1", "app_secret: |\n  " + strings.Repeat("aZ3k", 6) + "\nnext: 1\n",
	} {
		f.Add([]byte(seed))
	}
	rules := loadInitialRules(f)
	f.Fuzz(func(t *testing.T, content []byte) {
		if len(content) > 64<<10 {
			return
		}
		text, subs, result := ExpurgateAndRescan(content, rules, nil, Options{}, startOrdinals(1))
		switch result.Failure {
		case SanitizeNone:
		case SanitizeIncomplete, SanitizeResidual, SanitizeOrdinal:
			if text != nil || subs != nil {
				t.Fatalf("texte rendu après l'échec %s", result.Failure)
			}
			return
		default:
			t.Fatalf("issue hors liste : %q", result.Failure)
		}
		if !reflect.DeepEqual(result.Initial, Scan(content, rules, Options{})) {
			t.Fatal("analyse initiale différente de Scan")
		}
		if diff := substitutionDifference(content, text, subs); diff != "" {
			t.Fatal(diff)
		}
		if again := Scan(text, rules, Options{}); !again.Complete || len(again.Findings) != 0 {
			t.Fatal("constat après une expurgation réussie")
		}
	})
}
