// SPDX-License-Identifier: PolyForm-Small-Business-1.0.0

package expurgation

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/xsom-consulting/secret-guard/detect"
)

// fixedOrdinal rend toujours le même numéro.
func fixedOrdinal(n int) func(detect.Finding) (int, bool) {
	return func(detect.Finding) (int, bool) { return n, true }
}

// startOrdinals numérote les étendues dans l'ordre où elles sont vues, à partir de first : même début, même numéro.
func startOrdinals(first int) func(detect.Finding) (int, bool) {
	seen := map[int]int{}
	return func(f detect.Finding) (int, bool) {
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
func expurgateBoth(t *testing.T, content []byte, rules *detect.Rules, key *detect.FingerprintKey, options Options, ordinal func() func(detect.Finding) (int, bool)) ([]byte, []Substitution, detect.SanitizeResult) {
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

// subFR et subEN écrivent à l'exécution le Substitut attendu : préfixe, numéro, type.
func subFR(prefix string, n int, label string) string {
	return prefix + "[secret masqué par xSOM n°" + strconv.Itoa(n) + " : " + label + ", pas la vraie valeur]"
}

func subEN(prefix string, n int, label string) string {
	return prefix + "[secret masked by xSOM #" + strconv.Itoa(n) + ": " + label + ", not the real value]"
}

// oldSubstitute écrit à l'exécution un Substitut de l'ancienne forme (préfixe, X, numéro).
func oldSubstitute(prefix string, filler int, n string) string {
	return prefix + strings.Repeat("X", filler) + n
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
		{"jeton GitHub", "export TOKEN=" + token, 1, "export TOKEN=" + subFR("ghp_", 1, "jeton GitHub"), [][2]int{{13, 53}}},
		{"URL", "postgres://app:" + password + "@db:5432/x", 2, "postgres://app:" + subFR("", 2, "mot de passe de base de données") + "@db:5432/x", [][2]int{{15, 31}}},
		{"Bearer", "Authorization: Bearer " + opaque, 3, "Authorization: Bearer " + subFR("", 3, "jeton d’accès"), [][2]int{{22, 46}}},
		{"Bearer et jeton GitHub", "Authorization: Bearer " + token, 4, "Authorization: Bearer " + subFR("ghp_", 4, "jeton GitHub"), [][2]int{{22, 62}}},
		{"cli_basic_auth", basicAuthCommand() + password + " https://x", 5, basicAuthCommand() + subFR("", 5, "mot de passe") + " https://x", [][2]int{{14, 30}}},
		{"PEM", pem + "\n", 6, pemHeader("RSA PRIVATE KEY") + "\n" + subFR("", 6, "clé privée") + "\n-----END RSA PRIVATE KEY-----\n", [][2]int{{32, 149}}},
		{"PEM incomplet", pemHeader("PRIVATE KEY") + "\nMIIEow" + strings.Repeat("q7Lm2Pz9Wr4Tn", 4) + "\n", 7, pemHeader("PRIVATE KEY") + "\n" + subFR("", 7, "clé privée") + "\n", [][2]int{{28, 86}}},
		{"numéro à trois chiffres", "export TOKEN=" + token, 999, "export TOKEN=" + subFR("ghp_", 999, "jeton GitHub"), [][2]int{{13, 53}}},
		{"en-tête curl", `curl -H "Authorization: Bearer ` + opaque + `" https://x`, 9, `curl -H "Authorization: Bearer ` + subFR("", 9, "jeton d’accès") + `" https://x`, [][2]int{{31, 55}}},
		{"jeton comme nom d'utilisateur d'une URL", "git clone https://" + opaque + ":x-oauth-basic@github.com/o/r.git", 1, "git clone https://" + subFR("", 1, "mot de passe") + "@github.com/o/r.git", [][2]int{{18, 56}}},
		// Jeton GitHub en nom d'utilisateur : étendue fusionnée de deux règles, URL entière.
		{"jeton GitHub comme nom d'utilisateur d'une URL", "git clone https://" + token + ":x-oauth-basic@github.com/o/r.git", 1, "git clone " + subFR("", 1, "jeton GitHub"), [][2]int{{10, 91}}},
		{"nom d'utilisateur ordinaire d'une URL", "https://deploy-bot:" + password + "@example.org/x", 1, "https://deploy-bot:" + subFR("", 1, "mot de passe") + "@example.org/x", [][2]int{{19, 35}}},
		{"clé d'API comme utilisateur de curl -u", curlUser(opaque) + "X https://x", 1, "curl -u " + subFR("", 1, "mot de passe") + " https://x", [][2]int{{8, 34}}},
		{"mot de passe qui commence comme un jeton Databricks", "PASSWORD=dapi" + strings.Repeat("q7Lm", 4), 1, "PASSWORD=" + subFR("", 1, "mot de passe"), [][2]int{{9, 29}}},
		{"mot de passe qui commence comme une clé AWS", "DB_PASSWORD=AKIA" + strings.Repeat("q7Lm", 4), 1, "DB_PASSWORD=" + subFR("", 1, "mot de passe"), [][2]int{{12, 32}}},
		{"schéma dans un mot de passe : remplacé avec la valeur", `DB_PASSWORD="Token ` + strings.Repeat("q7Lm", 4) + `"`, 1, `DB_PASSWORD="` + subFR("", 1, "mot de passe") + `"`, [][2]int{{13, 35}}},
		{"faux Substitut détecté", "TOKEN=ghp_" + strings.Repeat("X", 34) + "1a", 8, "TOKEN=" + subFR("ghp_", 8, "jeton GitHub"), [][2]int{{6, 46}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			text, subs, result := expurgateBoth(t, []byte(c.input), rules, nil, Options{}, func() func(detect.Finding) (int, bool) { return fixedOrdinal(c.ordinal) })
			if result.Failure != detect.SanitizeNone || string(text) != c.want {
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
			if again := detect.Scan(text, rules, detect.Options{}); !again.Complete || len(again.Findings) > 0 {
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
		text, subs, result := expurgateBoth(t, []byte(content), rules, nil, Options{}, func() func(detect.Finding) (int, bool) { return startOrdinals(10) })
		if result.Failure != detect.SanitizeNone || len(subs) != 2 {
			t.Fatalf("%s %+v", result.Failure, subs)
		}
		want := "é😀 clé « " + subFR("ghp_", 10, "jeton GitHub") + " »\nDB_PASSWORD=" + subFR("", 11, "mot de passe") + "\nfin 😀"
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
		raw := make([]byte, detect.FingerprintKeyBytes)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		key, err := detect.NewFingerprintKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		defer key.Wipe()
		content := []byte("A " + token + " et B " + token)
		_, subs, result := expurgateBoth(t, content, rules, &key, Options{}, func() func(detect.Finding) (int, bool) { return startOrdinals(1) })
		if result.Failure != detect.SanitizeNone || len(subs) != 2 || len(subs[0].LocalFingerprint) != 32 ||
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
		var got []detect.Finding
		_, _, result := ExpurgateAndRescan(content, rules, nil, Options{}, func(f detect.Finding) (int, bool) {
			got = append(got, f)
			return 1, true
		})
		if result.Failure != detect.SanitizeNone || len(got) != 1 || got[0].ByteStart != 15 || got[0].ByteEnd != 15+len(syntheticPassword()) ||
			got[0].RuleID != "database_url_credentials" {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("sans constat : copie de l'entrée, aucune Substitution ni numéro demandé", func(t *testing.T) {
		content := []byte("rien à signaler")
		text, subs, result := ExpurgateAndRescan(content, rules, nil, Options{}, nil)
		if result.Failure != detect.SanitizeNone || !bytes.Equal(text, content) || &text[0] == &content[0] || subs == nil || len(subs) != 0 {
			t.Fatalf("%q %+v %+v", text, subs, result)
		}
	})
	t.Run("étendues fusionnées : un Substitut, représentée par le premier constat", func(t *testing.T) {
		content := []byte("0123456789abcdef")
		result := detect.Result{Complete: true, Failure: detect.FailureNone, Findings: []detect.Finding{
			{RuleID: "b", Score: 10, ByteStart: 4, ByteEnd: 8}, {RuleID: "a", Score: 90, ByteStart: 2, ByteEnd: 6},
			{RuleID: "c", Score: 50, ByteStart: 8, ByteEnd: 10}, {RuleID: "vide", ByteStart: 12, ByteEnd: 12},
			{RuleID: "d", Score: 50, ByteStart: 12, ByteEnd: 16},
		}}
		text, subs, err := Expurgate(content, result, startOrdinals(1))
		if err != nil || string(text) != "01"+subFR("", 1, "secret")+"ab"+subFR("", 2, "secret") || len(subs) != 2 || subs[0].RuleID != "a" ||
			subs[0].ByteStart != 2 || subs[0].ByteEnd != 10 || subs[1].RuleID != "d" {
			t.Fatalf("%q %+v %v", text, subs, err)
		}
	})
	t.Run("étendue fusionnée qui n'a pas la forme de sa règle : remplacée en entier", func(t *testing.T) {
		content := []byte("x postgres://app:pw@db/x y")
		for _, f := range []detect.Finding{
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
		for name, result := range map[string]detect.Result{
			"scan_limit": {Failure: detect.FailureScanLimit}, "scan_error": {Failure: detect.FailureScanError},
			"complet sans issue none": {Complete: true, Failure: detect.FailureScanError}, "issue none sans complete": {Failure: detect.FailureNone},
		} {
			if text, subs, err := Expurgate(content, result, fixedOrdinal(1)); text != nil || subs != nil || !errors.Is(err, ErrIncomplete) {
				t.Errorf("%s : %v", name, err)
			}
		}
		huge := bytes.Repeat([]byte("a"), detect.MaxInputBytes+1)
		if text, subs, result := ExpurgateAndRescan(huge, rules, nil, Options{}, fixedOrdinal(1)); text != nil || subs != nil ||
			result.Failure != detect.SanitizeIncomplete || result.Initial.Failure != detect.FailureScanLimit {
			t.Fatalf("%+v", result)
		}
	})
	t.Run("étendue hors du contenu : erreur, aucun texte", func(t *testing.T) {
		for name, f := range map[string]detect.Finding{
			"début négatif": {ByteStart: -1, ByteEnd: 2}, "fin avant début": {ByteStart: 5, ByteEnd: 4},
			"fin après contenu": {ByteStart: 8, ByteEnd: len(content) + 1},
		} {
			result := detect.Result{Complete: true, Failure: detect.FailureNone, Findings: []detect.Finding{{RuleID: "ok", ByteStart: 0, ByteEnd: 2}, f}}
			if text, subs, err := Expurgate(content, result, fixedOrdinal(1)); text != nil || subs != nil || !errors.Is(err, ErrSpan) {
				t.Errorf("%s : %v", name, err)
			}
		}
	})
	t.Run("contenu hors UTF-8 : refusé, aucun texte", func(t *testing.T) {
		invalid := append([]byte("é \xff "), content...)
		initial := detect.Scan(invalid, rules, detect.Options{})
		if text, subs, err := Expurgate(invalid, initial, fixedOrdinal(1)); text != nil || subs != nil || !errors.Is(err, ErrEncoding) {
			t.Errorf("Expurgate : %v", err)
		}
		if text, subs, result := ExpurgateAndRescan(invalid, rules, nil, Options{}, fixedOrdinal(1)); text != nil || subs != nil ||
			result.Failure != detect.SanitizeIncomplete || !result.Initial.Complete {
			t.Errorf("ExpurgateAndRescan : %+v", result)
		}
		if text, _, result := ExpurgateAndRescan([]byte("rien \xff"), rules, nil, Options{}, fixedOrdinal(1)); text != nil || result.Failure != detect.SanitizeIncomplete {
			t.Errorf("sans constat : %+v", result)
		}
	})
	t.Run("étendue qui coupe un caractère : ErrSpan", func(t *testing.T) {
		text := []byte("aé😀b")
		for _, f := range []detect.Finding{{ByteStart: 2, ByteEnd: 3}, {ByteStart: 1, ByteEnd: 4}, {ByteStart: 3, ByteEnd: 5}} {
			result := detect.Result{Complete: true, Failure: detect.FailureNone, Findings: []detect.Finding{f}}
			if out, subs, err := Expurgate(text, result, fixedOrdinal(1)); out != nil || subs != nil || !errors.Is(err, ErrSpan) {
				t.Errorf("%+v : %v", f, err)
			}
		}
		result := detect.Result{Complete: true, Failure: detect.FailureNone, Findings: []detect.Finding{{ByteStart: 1, ByteEnd: 7}}}
		if out, _, err := Expurgate(text, result, fixedOrdinal(1)); err != nil || string(out) != "a"+subFR("", 1, "secret")+"b" {
			t.Errorf("%q %v", out, err)
		}
	})
	t.Run("numéro nil refusé même sans étendue à remplacer", func(t *testing.T) {
		empty := detect.Result{Complete: true, Failure: detect.FailureNone}
		if out, subs, err := Expurgate([]byte("rien"), empty, nil); out != nil || subs != nil || !errors.Is(err, ErrOrdinal) {
			t.Errorf("%v", err)
		}
	})
	t.Run("numéro absent, refusé ou hors de 1 à 999 : ErrOrdinal, aucun texte", func(t *testing.T) {
		initial := detect.Scan(content, rules, detect.Options{})
		for name, ordinal := range map[string]func(detect.Finding) (int, bool){
			"nil": nil, "faux": func(detect.Finding) (int, bool) { return 1, false }, "0": fixedOrdinal(0), "1000": fixedOrdinal(1000),
		} {
			if text, subs, err := Expurgate(content, initial, ordinal); text != nil || subs != nil || !errors.Is(err, ErrOrdinal) {
				t.Errorf("%s : %v", name, err)
			}
			if text, subs, result := ExpurgateAndRescan(content, rules, nil, Options{}, ordinal); text != nil || subs != nil ||
				result.Failure != SanitizeOrdinal || result.Final.Failure != detect.FailureScanError {
				t.Errorf("%s : %+v", name, result)
			}
		}
	})
	t.Run("clé absente ou effacée : analyse incomplète", func(t *testing.T) {
		var zero detect.FingerprintKey
		if text, _, result := ExpurgateAndRescan(content, rules, &zero, Options{}, fixedOrdinal(1)); text != nil || result.Failure != detect.SanitizeIncomplete {
			t.Fatalf("%+v", result)
		}
		raw := make([]byte, detect.FingerprintKeyBytes)
		raw[0] = 1
		key, err := detect.NewFingerprintKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		key.Wipe()
		if text, _, result := ExpurgateAndRescan(bytes.Repeat([]byte("a"), detect.MaxInputBytes+1), rules, &key, Options{}, fixedOrdinal(1)); text != nil ||
			result.Initial.Failure != detect.FailureScanLimit {
			t.Fatalf("%+v", result)
		}
	})
}

// swapExpurgateScan remplace l'analyse d'ExpurgateAndRescan et rend la fonction qui la rétablit.
func swapExpurgateScan(scan func([]byte, *detect.Rules, detect.Options, *detect.FingerprintKey) detect.Result) func() {
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
		defer swapExpurgateScan(func(c []byte, r *detect.Rules, o detect.Options, k *detect.FingerprintKey) detect.Result {
			calls++
			if calls == 1 {
				return scan(c, r, o, k)
			}
			seen = append(seen, c)
			// Résidu permanent sur « key » (octets 4 à 7 du texte expurgé, les mêmes dans le texte d'origine).
			return detect.Result{Complete: true, Failure: detect.FailureNone, Findings: []detect.Finding{{RuleID: "r", SecretType: "s", ByteStart: 4, ByteEnd: 7}}}
		})()
		text, subs, result := ExpurgateAndRescan(content, rules, nil, Options{}, fixedOrdinal(1))
		if text != nil || subs != nil || result.Failure != detect.SanitizeResidual || len(seen) != 3 {
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
			{2, 2, "a b\n" + subFR("", 1, "secret") + " " + subFR("ghp_", 1, "jeton GitHub") + " suite\nfin"},
			{3, 1, "a b\n" + subFR("", 1, "secret") + "\nfin"},
		} {
			calls := 0
			restore := swapExpurgateScan(func(text []byte, r *detect.Rules, o detect.Options, k *detect.FingerprintKey) detect.Result {
				calls++
				if calls == 1 || calls > c.cleanAfter {
					return scan(text, r, o, k)
				}
				return detect.Result{Complete: true, Failure: detect.FailureNone, Findings: []detect.Finding{{RuleID: "r", ByteStart: 4, ByteEnd: 7}}}
			})
			text, subs, result := ExpurgateAndRescan(content, rules, nil, Options{}, fixedOrdinal(1))
			restore()
			if result.Failure != detect.SanitizeNone || string(text) != c.want || len(subs) != c.subs {
				t.Errorf("%d : %s %q %+v", c.cleanAfter, result.Failure, text, subs)
			}
		}
	})
	t.Run("seconde analyse incomplète : aucun texte, copie effacée", func(t *testing.T) {
		var second []byte
		calls := 0
		defer swapExpurgateScan(func(c []byte, r *detect.Rules, o detect.Options, k *detect.FingerprintKey) detect.Result {
			calls++
			if calls == 1 {
				return scan(c, r, o, k)
			}
			second = c
			return incomplete(detect.FailureScanError)
		})()
		text, _, result := ExpurgateAndRescan(content, rules, nil, Options{}, fixedOrdinal(1))
		if text != nil || result.Failure != detect.SanitizeIncomplete || !bytes.Equal(second, make([]byte, len(second))) {
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

// fingerprintOrdinals numérote par Empreinte locale, à partir de 1 : même Empreinte locale, même numéro (ce que fait
// l'appelant qui veut le même Substitut pour la même valeur).
func fingerprintOrdinals() func(detect.Finding) (int, bool) {
	seen := map[string]int{}
	return func(f detect.Finding) (int, bool) {
		if n, ok := seen[f.LocalFingerprint]; ok {
			return n, true
		}
		seen[f.LocalFingerprint] = 1 + len(seen)
		return seen[f.LocalFingerprint], true
	}
}

// TestExpurgateSubstitutionFingerprint : avec la clé, l'Empreinte locale d'un Substitut (et du constat que reçoit
// ordinal) est celle des octets d'origine qu'il remplace exactement, que l'étendue soit fusionnée, rétrécie ou élargie ;
// sans la clé (Expurgate), l'Empreinte locale d'un constat n'est gardée que pour son étendue exacte.
func TestExpurgateSubstitutionFingerprint(t *testing.T) {
	rules := loadInitialRules(t)
	key := randomKey(t)
	defer key.Wipe()
	token := syntheticGitHubToken()
	// checkFingerprints exige, pour chaque Substitution, l'Empreinte locale de content[ByteStart:ByteEnd], et la même
	// Empreinte locale pour le constat reçu par ordinal à cette étendue.
	checkFingerprints := func(t *testing.T, content []byte, subs []Substitution, seen map[[2]int]string) {
		t.Helper()
		for _, s := range subs {
			want := localFingerprint(key, content[s.ByteStart:s.ByteEnd])
			if s.LocalFingerprint != want || seen[[2]int{s.ByteStart, s.ByteEnd}] != want {
				t.Errorf("Substitution %d-%d : Empreinte locale qui n'est pas celle des octets remplacés", s.ByteStart, s.ByteEnd)
			}
		}
	}
	recording := func(seen map[[2]int]string) func(detect.Finding) (int, bool) {
		return func(f detect.Finding) (int, bool) {
			seen[[2]int{f.ByteStart, f.ByteEnd}] = f.LocalFingerprint
			return 1, true
		}
	}
	t.Run("étendue fusionnée de deux constats qui se touchent : Empreinte locale des octets fusionnés", func(t *testing.T) {
		content := []byte("A " + token + "!" + token + " B")
		end := 2 + len(token)
		calls := 0
		defer swapExpurgateScan(func(c []byte, r *detect.Rules, o detect.Options, k *detect.FingerprintKey) detect.Result {
			calls++
			if calls > 1 {
				return scan(c, r, o, k)
			}
			// Deux constats qui se touchent, chacun avec l'Empreinte locale de sa seule valeur.
			return detect.Result{Complete: true, Failure: detect.FailureNone, Findings: []detect.Finding{
				{RuleID: "github_token", SecretType: "provider_token", Score: 95, ByteStart: 2, ByteEnd: end + 1,
					LocalFingerprint: localFingerprint(key, content[2:end+1])},
				{RuleID: "github_token", SecretType: "provider_token", Score: 95, ByteStart: end + 1, ByteEnd: end + 1 + len(token),
					LocalFingerprint: localFingerprint(key, content[end+1:end+1+len(token)])},
			}}
		})()
		seen := map[[2]int]string{}
		_, subs, result := ExpurgateAndRescan(content, rules, &key, Options{}, recording(seen))
		if result.Failure != detect.SanitizeNone || len(subs) != 1 || subs[0].ByteStart != 2 || subs[0].ByteEnd != end+1+len(token) ||
			subs[0].LocalFingerprint == result.Initial.Findings[0].LocalFingerprint {
			t.Fatalf("%s %+v", result.Failure, subs)
		}
		checkFingerprints(t, content, subs, seen)
	})
	t.Run("même jeton sur deux lignes : même Empreinte locale, celle du jeton", func(t *testing.T) {
		content := []byte("GITHUB_TOKEN=" + token + "\nOTHER=1\nAGAIN=" + token + "\nZ=2")
		seen := map[[2]int]string{}
		_, subs, result := expurgateBoth(t, content, rules, &key, Options{}, func() func(detect.Finding) (int, bool) { return recording(seen) })
		if result.Failure != detect.SanitizeNone || len(subs) != 2 || subs[0].LocalFingerprint != subs[1].LocalFingerprint ||
			subs[0].LocalFingerprint != localFingerprint(key, []byte(token)) {
			t.Fatalf("%s %+v", result.Failure, subs)
		}
		checkFingerprints(t, content, subs, seen)
	})
	t.Run("partie secrète d'une URL : Empreinte locale du seul mot de passe", func(t *testing.T) {
		content := []byte("postgres://app:" + syntheticPassword() + "@db/x")
		seen := map[[2]int]string{}
		_, subs, result := ExpurgateAndRescan(content, rules, &key, Options{}, recording(seen))
		if result.Failure != detect.SanitizeNone || len(subs) != 1 || subs[0].LocalFingerprint != localFingerprint(key, []byte(syntheticPassword())) {
			t.Fatalf("%s %+v", result.Failure, subs)
		}
		checkFingerprints(t, content, subs, seen)
	})
	t.Run("résidu élargi au jeton puis à la ligne : Empreinte locale des octets élargis", func(t *testing.T) {
		content := []byte("a b\nkey " + token + " suite\nfin")
		for _, cleanAfter := range []int{2, 3} {
			calls := 0
			restore := swapExpurgateScan(func(text []byte, r *detect.Rules, o detect.Options, k *detect.FingerprintKey) detect.Result {
				calls++
				if calls == 1 || calls > cleanAfter {
					return scan(text, r, o, k)
				}
				return detect.Result{Complete: true, Failure: detect.FailureNone, Findings: []detect.Finding{{RuleID: "r", ByteStart: 4, ByteEnd: 7}}}
			})
			seen := map[[2]int]string{}
			_, subs, result := ExpurgateAndRescan(content, rules, &key, Options{}, recording(seen))
			restore()
			if result.Failure != detect.SanitizeNone || len(subs) == 0 || subs[0].ByteStart != 4 {
				t.Fatalf("%d : %s %+v", cleanAfter, result.Failure, subs)
			}
			checkFingerprints(t, content, subs, seen)
		}
	})
	t.Run("Expurgate sans clé : Empreinte locale gardée pour l'étendue exacte du constat seulement", func(t *testing.T) {
		password := syntheticPassword()
		content := []byte("A " + token + " postgres://app:" + password + "@db/x")
		result := detect.ScanWithFingerprint(content, rules, key)
		if !result.Complete || len(result.Findings) != 2 {
			t.Fatalf("%+v", result.Findings)
		}
		// Étendue exacte : Empreinte locale du constat gardée.
		exact := detect.Result{Complete: true, Failure: detect.FailureNone, Findings: result.Findings[:1]}
		_, subs, err := Expurgate(content, exact, fixedOrdinal(1))
		if err != nil || len(subs) != 1 || subs[0].LocalFingerprint != result.Findings[0].LocalFingerprint {
			t.Fatalf("%+v %v", subs, err)
		}
		// Étendue rétrécie au mot de passe : refus, aucun texte.
		text, subs, err := Expurgate(content, result, fixedOrdinal(1))
		if !errors.Is(err, ErrSpan) || text != nil || subs != nil {
			t.Fatalf("%q %+v %v", text, subs, err)
		}
		// Étendue fusionnée par l'expurgation, dont le représentant porte une Empreinte locale : refus.
		touching := detect.Result{Complete: true, Failure: detect.FailureNone, Findings: []detect.Finding{
			{RuleID: "a", Score: 90, ByteStart: 0, ByteEnd: 4, LocalFingerprint: localFingerprint(key, content[0:4])},
			{RuleID: "b", Score: 10, ByteStart: 4, ByteEnd: 8, LocalFingerprint: localFingerprint(key, content[4:8])},
		}}
		if _, _, err := Expurgate(content, touching, fixedOrdinal(1)); !errors.Is(err, ErrSpan) {
			t.Fatalf("fusion acceptée : %v", err)
		}
		// Sans Empreinte locale : étendue rétrécie admise, Substitution sans Empreinte locale.
		_, subs, err = Expurgate(content, detect.Scan(content, rules, detect.Options{}), fixedOrdinal(1))
		if err != nil || len(subs) != 2 || subs[0].LocalFingerprint != "" || subs[1].LocalFingerprint != "" {
			t.Fatalf("%+v %v", subs, err)
		}
	})
	t.Run("clé effacée entre les analyses : aucun texte", func(t *testing.T) {
		wiped := randomKey(t)
		content := []byte("A " + token)
		calls := 0
		defer swapExpurgateScan(func(c []byte, r *detect.Rules, o detect.Options, k *detect.FingerprintKey) detect.Result {
			calls++
			result := scan(c, r, o, k)
			if calls == 1 {
				wiped.Wipe()
			}
			return result
		})()
		text, _, result := ExpurgateAndRescan(content, rules, &wiped, Options{}, fixedOrdinal(1))
		if text != nil || result.Failure != detect.SanitizeIncomplete {
			t.Fatalf("%+v", result)
		}
	})
}

// TestExpurgateLineBreak : un jeton complet en fin de ligne, suivi d'une ligne qui commence par un mot, donne un
// constat dont l'étendue (fusion avec la vue jointe des jetons coupés) prend ce mot. Seule la première ligne est
// remplacée ; la fin de ligne et la ligne suivante restent, et le Substitut a l'Empreinte locale du seul jeton. Un
// secret réellement coupé par un retour à la ligne est remplacé en entier. Les étendues de détection ne changent pas.
func TestExpurgateLineBreak(t *testing.T) {
	rules := loadInitialRules(t)
	token := syntheticGitHubToken()
	substitute := func(n string) string { number, _ := strconv.Atoi(n); return subFR("ghp_", number, "jeton GitHub") }
	raw := make([]byte, detect.FingerprintKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	key, err := detect.NewFingerprintKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Wipe()
	alone := detect.ScanWithFingerprint([]byte(token), rules, key)
	if len(alone.Findings) != 1 {
		t.Fatalf("%+v", alone)
	}
	tokenFingerprint := alone.Findings[0].LocalFingerprint
	t.Run("première ligne seule remplacée, fin de ligne et ligne suivante gardées (LF, CRLF, .env)", func(t *testing.T) {
		for _, c := range []struct {
			name, input, want string
			spans             [][2]int
		}{
			{"shell", "export A=" + token + "\nexport B=x", "export A=" + substitute("1") + "\nexport B=x", [][2]int{{9, 49}}},
			{"shell CRLF", "export A=" + token + "\r\nexport B=x", "export A=" + substitute("1") + "\r\nexport B=x", [][2]int{{9, 49}}},
			{
				".env, même jeton deux fois", "GITHUB_TOKEN=" + token + "\nOTHER=1\nAGAIN=" + token + "\nZ=2",
				"GITHUB_TOKEN=" + substitute("1") + "\nOTHER=1\nAGAIN=" + substitute("1") + "\nZ=2", [][2]int{{13, 53}, {68, 108}},
			},
			{
				".env CRLF, même jeton deux fois", "GITHUB_TOKEN=" + token + "\r\nOTHER=1\r\nAGAIN=" + token + "\r\nZ=2",
				"GITHUB_TOKEN=" + substitute("1") + "\r\nOTHER=1\r\nAGAIN=" + substitute("1") + "\r\nZ=2", [][2]int{{13, 53}, {70, 110}},
			},
			{"YAML", "token: " + token + "\nnext: 1", "token: " + substitute("1") + "\nnext: 1", [][2]int{{7, 47}}},
		} {
			t.Run(c.name, func(t *testing.T) {
				initial := detect.ScanWithFingerprint([]byte(c.input), rules, key)
				if !initial.Complete || len(initial.Findings) != len(c.spans) || !bytes.ContainsAny([]byte(c.input[initial.Findings[0].ByteStart:initial.Findings[0].ByteEnd]), "\r\n") {
					t.Fatalf("cas sans étendue qui passe la fin de ligne : %+v", initial.Findings)
				}
				text, subs, result := expurgateBoth(t, []byte(c.input), rules, &key, Options{}, fingerprintOrdinals)
				if result.Failure != detect.SanitizeNone || string(text) != c.want || len(subs) != len(c.spans) {
					t.Fatalf("%s : %q %+v", result.Failure, text, subs)
				}
				for i, s := range subs {
					if s.ByteStart != c.spans[i][0] || s.ByteEnd != c.spans[i][1] || s.UTF16Start != s.ByteStart || s.UTF16End != s.ByteEnd ||
						s.RuleID != "github_token" || s.LocalFingerprint != tokenFingerprint || s.Ordinal != 1 {
						t.Errorf("Substitution %+v, étendue attendue %v", s, c.spans[i])
					}
				}
				if again := detect.Scan(text, rules, detect.Options{}); !again.Complete || len(again.Findings) > 0 {
					t.Fatalf("constat après expurgation : %+v", again.Findings)
				}
			})
		}
	})
	t.Run("le numéro reçoit le constat ramené à la première ligne, avec son Empreinte locale", func(t *testing.T) {
		var got []detect.Finding
		_, _, result := ExpurgateAndRescan([]byte("export A="+token+"\nexport B=x"), rules, &key, Options{}, func(f detect.Finding) (int, bool) {
			got = append(got, f)
			return 1, true
		})
		if result.Failure != detect.SanitizeNone || len(got) != 1 || got[0].ByteStart != 9 || got[0].ByteEnd != 49 || got[0].LocalFingerprint != tokenFingerprint {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("secret réellement coupé, ou suite ambiguë : étendue entière remplacée", func(t *testing.T) {
		head, tail := "ghp_"+strings.Repeat("aB3d", 5), strings.Repeat("aB3d", 4)
		for _, c := range []struct{ name, input string }{
			// Première ligne trop courte pour la règle : jeton coupé.
			{"jeton coupé", "TOKEN=" + head + "\n" + tail + " suite"},
			{"jeton coupé CRLF", "TOKEN=" + head + "\r\n" + tail + " suite"},
			// Première ligne complète, mais la suite finit le texte (ou sa ligne) : rien ne dit que ce n'est pas la fin
			// du jeton.
			{"suite en fin de texte", "TOKEN=" + token + "\n" + tail},
			{"suite en fin de ligne", "TOKEN=" + token + "\n" + tail + "\nfin"},
		} {
			t.Run(c.name, func(t *testing.T) {
				initial := detect.Scan([]byte(c.input), rules, detect.Options{})
				if !initial.Complete || len(initial.Findings) != 1 {
					t.Fatalf("%+v", initial.Findings)
				}
				f := initial.Findings[0]
				if !bytes.ContainsAny([]byte(c.input[f.ByteStart:f.ByteEnd]), "\r\n") {
					t.Fatalf("constat qui ne passe pas la fin de ligne : %+v", f)
				}
				if _, ok := firstLineSecretEnd([]byte(c.input), rules, f); ok {
					t.Fatal("rétréci à la première ligne")
				}
				// Étendue entière remplacée (l'échelle des résidus peut l'élargir encore).
				text, subs, result := expurgateBoth(t, []byte(c.input), rules, nil, Options{}, func() func(detect.Finding) (int, bool) { return fixedOrdinal(1) })
				if result.Failure != detect.SanitizeNone || len(subs) != 1 || subs[0].ByteStart > f.ByteStart || subs[0].ByteEnd < f.ByteEnd ||
					bytes.Contains(text, []byte("aB3d")) {
					t.Fatalf("%s : %q %+v, constat %+v", result.Failure, text, subs, f)
				}
			})
		}
	})
	t.Run("sans règles (Expurgate) : étendue entière remplacée", func(t *testing.T) {
		content := []byte("export A=" + token + "\nexport B=x")
		text, subs, err := Expurgate(content, detect.Scan(content, rules, detect.Options{}), fixedOrdinal(1))
		if err != nil || len(subs) != 1 || subs[0].ByteEnd != 56 || string(text) != "export A="+subFR("ghp_", 1, "jeton GitHub")+" B=x" {
			t.Fatalf("%q %+v %v", text, subs, err)
		}
	})
	t.Run("rétrécissement réservé aux règles « motif seul » dont la première ligne est une valeur exacte", func(t *testing.T) {
		content := []byte("export A=" + token + "\nexport B=x")
		for _, c := range []struct {
			f    detect.Finding
			want bool
		}{
			{detect.Finding{RuleID: "github_token", ByteStart: 9, ByteEnd: 56}, true},
			{detect.Finding{RuleID: "github_token", ByteStart: 8, ByteEnd: 56}, false},           // « = » en tête : pas une valeur exacte
			{detect.Finding{RuleID: "github_token", ByteStart: 9, ByteEnd: 49}, false},           // aucune fin de ligne
			{detect.Finding{RuleID: "github_token", ByteStart: 9, ByteEnd: len(content)}, false}, // fin du texte
			{detect.Finding{RuleID: "openai_key", ByteStart: 9, ByteEnd: 56}, false},             // autre règle
			{detect.Finding{RuleID: "high_entropy", ByteStart: 9, ByteEnd: 56}, false},           // règle sans motif du Pack
			{detect.Finding{RuleID: "contextual_generic_secret", ByteStart: 9, ByteEnd: 56}, false},
			{detect.Finding{RuleID: customRulePrefix + "x", SecretType: customSecretType, ByteStart: 9, ByteEnd: 56}, false},
		} {
			_, ok := firstLineSecretEnd(content, rules, c.f)
			if ok != c.want {
				t.Errorf("%+v : %v", c.f, ok)
			}
		}
		if _, ok := firstLineSecretEnd(content, nil, detect.Finding{RuleID: "github_token", ByteStart: 9, ByteEnd: 56}); ok {
			t.Error("rétréci sans règles")
		}
		if _, ok := firstLineSecretEnd(content, &detect.Rules{}, detect.Finding{RuleID: "github_token", ByteStart: 9, ByteEnd: 56}); ok {
			t.Error("rétréci avec des règles non chargées")
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
		counts := map[detect.SanitizeFailure]int{}
		residualCases, remaining, overLimit := 0, 0, 0
		for _, c := range vectors.Cases {
			content, options, _ := c.input(t, corpus)
			text, subs, result := ExpurgateAndRescan(content, rules, nil, options, startOrdinals(1))
			counts[result.Failure]++
			if c.Expected.Failure == detect.SanitizeResidual {
				residualCases++
				if result.Failure != detect.SanitizeNone {
					remaining++
				}
			}
			switch {
			case result.Failure != detect.SanitizeNone && (text != nil || subs != nil):
				t.Errorf("%s : texte rendu après un échec", c.ID)
			case result.Failure == detect.SanitizeNone:
				if again := detect.Scan(text, rules, options.Options); !again.Complete || len(again.Findings) > 0 {
					t.Errorf("%s : constat après expurgation", c.ID)
				}
			case result.Failure == detect.SanitizeIncomplete && result.Initial.Complete && result.Final.Failure == detect.FailureScanLimit:
				// Texte proche de 1 Mio : le Substitut, plus long que la valeur, fait passer le texte expurgé au-delà de
				// MaxInputBytes ; refus, jamais un texte non analysé.
				overLimit++
			case c.Expected.Failure == detect.SanitizeNone && utf8.Valid(content):
				t.Errorf("%s : masqué par Redact, refusé par l'expurgation (%s)", c.ID, result.Failure)
			}
		}
		t.Logf("%d cas : %v ; résidus du masquage : %d, restants après expurgation : %d ; texte expurgé au-delà de 1 Mio : %d",
			len(vectors.Cases), counts, residualCases, remaining, overLimit)
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
		counts := map[detect.SanitizeFailure]int{}
		refused := map[string]int{}
		excused := 0
		for _, file := range corpusFiles(t) {
			for _, c := range loadCorpusFile(t, file) {
				if !c.Expected.Complete || len(c.Expected.Findings) == 0 {
					continue
				}
				options, _ := c.options()
				content := c.bytes(t)
				text, subs, result := expurgateBoth(t, content, rules, nil, options, func() func(detect.Finding) (int, bool) { return startOrdinals(1) })
				counts[result.Failure]++
				if result.Failure != detect.SanitizeNone {
					if text != nil || subs != nil {
						t.Errorf("%s : texte rendu après un échec", c.ID)
					}
					switch {
					case !utf8.Valid(content):
						refused["hors UTF-8"]++
					case result.Initial.Complete && result.Final.Failure == detect.FailureScanLimit:
						// Substituts plus longs que les valeurs : texte expurgé au-delà de 1 Mio, refusé.
						refused["au-delà de 1 Mio"]++
					default:
						t.Errorf("%s : expurgation refusée (%s)", c.ID, result.Failure)
					}
					continue
				}
				if diff := substitutionDifference(content, text, subs); diff != "" {
					t.Errorf("%s : %s", c.ID, diff)
				}
				if again := detect.Scan(text, rules, options.Options); !again.Complete || len(again.Findings) > 0 {
					t.Errorf("%s : constat après expurgation", c.ID)
				}
				excused += replacedWindowsLeft(t, c.ID, content, text, subs)
			}
		}
		t.Logf("issues : %v (refus : %v) ; %d fenêtres présentes aussi hors des étendues remplacées dans l'entrée", counts, refused, excused)
		if counts[detect.SanitizeNone] == 0 || counts[detect.SanitizeResidual] != 0 {
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
	covered := make([]detect.Finding, 0, len(subs))
	for _, s := range subs {
		covered = append(covered, detect.Finding{ByteStart: s.ByteStart, ByteEnd: s.ByteEnd})
	}
	outside := outsideSpans(content, covered)
	// Texte expurgé sans ses Substituts : leur texte est fixe (grammaire), il ne vient pas de la valeur ; il est vérifié
	// à part, égal à celui que la grammaire écrit pour la règle et le numéro.
	var kept []byte
	cursor, shift := 0, 0
	for _, s := range subs {
		start := s.ByteStart + shift
		kept = append(append(kept, text[cursor:start]...), 0)
		cursor = start + len(s.Replacement)
		shift += len(s.Replacement) - (s.ByteEnd - s.ByteStart)
		want, err := substituteFor(content[s.ByteStart:s.ByteEnd], s.RuleID, s.Ordinal, "")
		if err != nil || s.Replacement != want {
			t.Errorf("%s : Substitut hors de la forme écrite pour sa règle et son numéro", id)
		}
	}
	kept = append(kept, text[cursor:]...)
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
			case !bytes.Contains(kept, window):
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
//	cd expurgation && go test . -run '^$' -fuzz '^FuzzExpurgate$' -fuzztime=60s
func FuzzExpurgate(f *testing.F) {
	token := syntheticGitHubToken()
	for _, seed := range []string{
		"", "rien à signaler", "TOKEN=" + token, token + token, "DB_PASSWORD=" + syntheticPassword() + "\n" + token,
		"API_KEY=" + token + "\nNEXT=another", "Authorization: Bearer " + token, "postgres://app:" + syntheticPassword() + "@db/x",
		syntheticPEM("\n"), basicAuthCommand() + syntheticPassword() + " https://x", "é😀 " + token + " \xff",
		oldSubstitute("ghp_", 35, "1"), subFR("ghp_", 1, "jeton GitHub"), "TOKEN=" + subEN("", 2, "access token"), "app_secret: |\n  " + strings.Repeat("aZ3k", 6) + "\nnext: 1\n",
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
		case detect.SanitizeNone:
		case detect.SanitizeIncomplete, detect.SanitizeResidual, SanitizeOrdinal:
			if text != nil || subs != nil {
				t.Fatalf("texte rendu après l'échec %s", result.Failure)
			}
			return
		default:
			t.Fatalf("issue hors liste : %q", result.Failure)
		}
		if !reflect.DeepEqual(result.Initial, detect.Scan(content, rules, detect.Options{})) {
			t.Fatal("analyse initiale différente de Scan")
		}
		if diff := substitutionDifference(content, text, subs); diff != "" {
			t.Fatal(diff)
		}
		if again := detect.Scan(text, rules, detect.Options{}); !again.Complete || len(again.Findings) != 0 {
			t.Fatal("constat après une expurgation réussie")
		}
	})
}

// TestExpurgateLanguage : Substituts en français par défaut, en anglais avec Options.SubstituteLanguage ; une autre
// langue fait échouer l'expurgation sans texte ; le texte expurgé ne porte ni la valeur, ni sa longueur.
func TestExpurgateLanguage(t *testing.T) {
	rules := loadInitialRules(t)
	token := syntheticGitHubToken()
	password := syntheticPassword() + "5"
	content := []byte("postgres://admin:" + password + "@db.exemple.fr:5432/prod\nexport GH=" + token)
	for _, c := range []struct {
		language detect.SubstituteLanguage
		want     string
	}{
		{"", "postgres://admin:" + subFR("", 1, "mot de passe de base de données") + "@db.exemple.fr:5432/prod\nexport GH=" + subFR("ghp_", 2, "jeton GitHub")},
		{detect.SubstituteFrench, "postgres://admin:" + subFR("", 1, "mot de passe de base de données") + "@db.exemple.fr:5432/prod\nexport GH=" + subFR("ghp_", 2, "jeton GitHub")},
		{detect.SubstituteEnglish, "postgres://admin:" + subEN("", 1, "database password") + "@db.exemple.fr:5432/prod\nexport GH=" + subEN("ghp_", 2, "GitHub token")},
	} {
		text, subs, result := expurgateBoth(t, content, rules, nil, Options{SubstituteLanguage: c.language}, func() func(detect.Finding) (int, bool) { return startOrdinals(1) })
		if result.Failure != detect.SanitizeNone || string(text) != c.want || len(subs) != 2 {
			t.Fatalf("%q : %s %q", c.language, result.Failure, text)
		}
		if bytes.Contains(text, []byte(password)) || bytes.Contains(text, []byte(token[4:12])) {
			t.Fatal("valeur dans le texte expurgé")
		}
	}
	// Même Substitut quelle que soit la longueur de la valeur.
	short, _, _ := ExpurgateAndRescan([]byte("postgres://admin:"+password[:8]+"@db/x"), rules, nil, Options{}, fixedOrdinal(1))
	long, _, _ := ExpurgateAndRescan([]byte("postgres://admin:"+password+password+"@db/x"), rules, nil, Options{}, fixedOrdinal(1))
	if short == nil || !bytes.Equal(short, long) {
		t.Fatalf("%q %q", short, long)
	}
	for _, language := range []detect.SubstituteLanguage{"de", "FR", "fr-FR"} {
		text, subs, result := ExpurgateAndRescan(content, rules, nil, Options{SubstituteLanguage: language}, fixedOrdinal(1))
		if text != nil || subs != nil || result.Failure != detect.SanitizeIncomplete {
			t.Errorf("%q : %s", language, result.Failure)
		}
	}
	// Une langue inconnue est refusée même sans constat.
	if text, _, result := ExpurgateAndRescan([]byte("rien"), rules, nil, Options{SubstituteLanguage: "de"}, fixedOrdinal(1)); text != nil || result.Failure != detect.SanitizeIncomplete {
		t.Fatalf("%s", result.Failure)
	}
}
