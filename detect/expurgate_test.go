package detect

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"
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

func TestSubstituteGrammar(t *testing.T) {
	t.Run("grammaire exacte et fermée : préfixe de la table ou aucun, forme française ou anglaise, numéro, type", func(t *testing.T) {
		valid := []string{
			subFR("", 1, "mot de passe de base de données"), subFR("ghp_", 2, "jeton GitHub"), subFR("", 999, "secret"),
			subFR("sk-ant-", 42, "clé d’API Anthropic"), subFR("https://hooks.slack.com/services/", 7, "webhook Slack"),
			subEN("", 1, "database password"), subEN("ghp_", 2, "GitHub token"), subEN("AKIA", 999, "AWS access key ID"),
			subEN("", 3, "secret"),
		}
		for _, value := range valid {
			if !isSubstitute([]byte(value)) {
				t.Errorf("%q non reconnu", value)
			}
		}
		base := subFR("", 1, "mot de passe")
		for _, value := range []string{
			// Ancienne forme : texte ordinaire depuis la v0.5.0.
			"", "[]", oldSubstitute("", 4, "1"), oldSubstitute("ghp_", 4, "1"), oldSubstitute("ghp_", 35, "1"),
			subFR("", 0, "mot de passe"), subFR("", 1000, "mot de passe"), strings.Replace(base, "n°1", "n°01", 1),
			strings.Replace(base, "n°1", "n°١", 1), strings.Replace(base, "n°1", "n°１", 1), strings.Replace(base, "n°1", "n° 1", 1),
			subFR("", 1, "password"), subEN("", 1, "mot de passe"), subFR("", 1, "Mot de passe"), subFR("", 1, "mot de passe "),
			subFR("", 1, "jeton inconnu"), subFR("", 1, ""), subFR("ghq_", 1, "jeton GitHub"), subFR("GHP_", 1, "jeton GitHub"),
			subFR("aghp_", 1, "jeton GitHub"), subFR("x", 1, "secret"), " " + base, base + " ", base + "1", base[:len(base)-1],
			strings.Replace(base, "masqué", "masque", 1), strings.Replace(base, "xSOM", "XSOM", 1), strings.Replace(base, " : ", ": ", 1),
			strings.Replace(base, "[", "(", 1), strings.Replace(base, "]", ")", 1), strings.Replace(base, "pas la vraie valeur", "la vraie valeur", 1),
			strings.Replace(subEN("", 1, "password"), "#1: ", "#1 : ", 1), base + "]",
		} {
			if isSubstitute([]byte(value)) {
				t.Errorf("%q reconnu", value)
			}
		}
	})
	t.Run("substituteAt et isSubstituteFragment : Substitut complet au début, morceau coupé à une espace", func(t *testing.T) {
		s := subFR("ghp_", 3, "jeton GitHub")
		text := []byte(basicAuthCommand() + s + " https://x")
		start := len(basicAuthCommand())
		end, ok := substituteAt(text, start)
		if !ok || end != start+len(s) {
			t.Fatalf("%d %v", end, ok)
		}
		cut := start + strings.IndexByte(s, ' ')
		if !isSubstituteFragment(text, start, cut) || !isSubstituteFragment(text, start, end) || isSubstituteFragment(text, start, end+1) {
			t.Fatal("morceau d'un Substitut complet")
		}
		for _, glued := range []string{s + "abc https://x", s + "@", s} {
			text := []byte(basicAuthCommand() + glued)
			if got := isSubstituteFragment(text, start, cut); got != (glued == s) {
				t.Errorf("%q : %v", glued, got)
			}
		}
		if _, ok := substituteAt([]byte("x"+s), 0); ok {
			t.Fatal("préfixe hors de la table")
		}
		if _, ok := substituteAt([]byte(s[:len(s)-1]), 0); ok {
			t.Fatal("Substitut tronqué")
		}
	})
	t.Run("SubstitutePrefixes et SubstituteLabels rendent des copies des tables fermées", func(t *testing.T) {
		first := SubstitutePrefixes()
		first[0] = "changé"
		if second := SubstitutePrefixes(); second[0] == "changé" || !slices.Equal(second, substitutePrefixes) {
			t.Fatal("table modifiable par l'appelant")
		}
		labels := SubstituteLabels()
		labels[0].French = "changé"
		if again := SubstituteLabels(); again[0].French == "changé" || !slices.Equal(again, substituteLabels) {
			t.Fatal("table des types modifiable par l'appelant")
		}
		longest := 0
		for _, prefix := range substitutePrefixes {
			longest = max(longest, len(prefix))
			if strings.ContainsAny(prefix, "[]") {
				t.Fatalf("préfixe %q avec un crochet", prefix)
			}
		}
		if longest != substituteMaxPrefix {
			t.Fatalf("préfixe le plus long : %d, borne %d", longest, substituteMaxPrefix)
		}
		seen := map[string]bool{}
		for _, l := range substituteLabels {
			if seen[l.RuleID] || l.French == "" || l.English == "" {
				t.Fatalf("type de %s en double ou vide", l.RuleID)
			}
			seen[l.RuleID] = true
			for _, label := range []string{l.French, l.English} {
				// Un type ne porte ni crochet, ni guillemet, ni barre oblique inverse, ni séparateur de la grammaire.
				if strings.ContainsAny(label, "[]\"'`\\,:#\n") || strings.TrimSpace(label) != label {
					t.Fatalf("type %q", label)
				}
			}
		}
	})
}

func TestSubstituteFor(t *testing.T) {
	t.Run("préfixe le plus long de la règle, numéro et type, rien d'autre de la valeur", func(t *testing.T) {
		token := syntheticGitHubToken()
		for _, c := range []struct {
			value    string
			ruleID   string
			ordinal  int
			language SubstituteLanguage
			want     string
		}{
			{token, "github_token", 1, "", subFR("ghp_", 1, "jeton GitHub")},
			{token, "github_token", 1, SubstituteFrench, subFR("ghp_", 1, "jeton GitHub")},
			{token, "github_token", 1, SubstituteEnglish, subEN("ghp_", 1, "GitHub token")},
			{"Xq7Lm2Pz9!Wr4Tn5", "contextual_password", 2, "", subFR("", 2, "mot de passe")},
			{"Xq7Lm2Pz9!Wr4Tn5", "database_url_credentials", 2, SubstituteEnglish, subEN("", 2, "database password")},
			{"sk-ant-" + strings.Repeat("aB3d", 6), "anthropic_key", 42, "", subFR("sk-ant-", 42, "clé d’API Anthropic")},
			{"sk-" + strings.Repeat("aB3d", 6), "openai_key", 999, "", subFR("sk-", 999, "clé d’API OpenAI")},
			// Préfixe de la règle du constat seulement : un mot de passe ou une autre règle n'en a aucun.
			{"dapi" + strings.Repeat("q7Lm", 4), "contextual_password", 1, "", subFR("", 1, "mot de passe")},
			{"AKIA" + strings.Repeat("Q7LM", 4), "contextual_password", 1, "", subFR("", 1, "mot de passe")},
			{token, "high_entropy", 1, "", subFR("", 1, "secret")},
			{token, "openai_key", 1, SubstituteEnglish, subEN("", 1, "OpenAI API key")},
			// Règle hors de la table (Pack du client, règle inconnue) : type « secret ».
			{"valeur", "custom_interne", 5, "", subFR("", 5, "secret")},
			{"valeur", "", 5, SubstituteEnglish, subEN("", 5, "secret")},
			// Valeur courte, vide, hors ASCII ou hors UTF-8 : même forme, aucune longueur.
			{"ghp_abc", "github_token", 7, "", subFR("ghp_", 7, "jeton GitHub")},
			{"", "", 12, "", subFR("", 12, "secret")},
			{"éé😀😀ééé", "", 5, "", subFR("", 5, "secret")},
			{"ab\xffcd", "", 1, "", subFR("", 1, "secret")},
		} {
			got, err := substituteFor([]byte(c.value), c.ruleID, c.ordinal, c.language)
			if err != nil || got != c.want {
				t.Errorf("%q, %d, %q : %q (%v), attendu %q", c.ruleID, c.ordinal, c.language, got, err, c.want)
			}
			if !isSubstitute([]byte(got)) {
				t.Errorf("%q hors de la grammaire", got)
			}
		}
	})
	t.Run("chaque type de la table, dans chaque langue, est dans la grammaire", func(t *testing.T) {
		for _, l := range substituteLabels {
			for _, language := range []SubstituteLanguage{SubstituteFrench, SubstituteEnglish} {
				for _, n := range []int{1, 42, 999} {
					got, err := substituteFor([]byte("valeur"), l.RuleID, n, language)
					if err != nil || !isSubstitute([]byte(got)) {
						t.Errorf("%s %s %d : %q %v", l.RuleID, language, n, got, err)
					}
				}
			}
		}
	})
	t.Run("numéro hors de 1 à 999 : ErrExpurgateOrdinal ; langue inconnue : ErrExpurgateLanguage", func(t *testing.T) {
		for _, n := range []int{0, -1, 1000, 1 << 40} {
			if got, err := substituteFor([]byte("valeur"), "", n, ""); got != "" || !errors.Is(err, ErrExpurgateOrdinal) {
				t.Errorf("%d : %q %v", n, got, err)
			}
		}
		for _, language := range []SubstituteLanguage{"de", "FR", "fr-FR", " en"} {
			if got, err := substituteFor([]byte("valeur"), "", 1, language); got != "" || !errors.Is(err, ErrExpurgateLanguage) {
				t.Errorf("%q : %q %v", language, got, err)
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
	{"cookie", "", func(s string) string { return "Cookie: session=" + s + "; theme=dark" }},
	{"Python", "python", func(s string) string { return `client = Client(password="` + s + `")` }},
	{"phrase", "", func(s string) string { return "Le mot de passe est " + s + ", merci." }},
}

// neverDetectedSubstitutes : sans préfixe, chaque type de chaque langue aux numéros 1, 42 et 999 ; avec chaque préfixe de
// la table, le type de sa règle et le repli, aux numéros 1 et 999, dans les deux langues.
func neverDetectedSubstitutes() []string {
	var substitutes []string
	for _, n := range []int{1, 42, 999} {
		for _, label := range substituteLabelSets[SubstituteFrench] {
			substitutes = append(substitutes, subFR("", n, label))
		}
		for _, label := range substituteLabelSets[SubstituteEnglish] {
			substitutes = append(substitutes, subEN("", n, label))
		}
	}
	for _, r := range substituteRulePrefixes {
		for _, prefix := range r.prefixes {
			for _, n := range []int{1, 999} {
				substitutes = append(substitutes,
					subFR(prefix, n, substituteLabelOf(r.ruleID, SubstituteFrench)), subFR(prefix, n, SubstituteDefaultLabel),
					subEN(prefix, n, substituteLabelOf(r.ruleID, SubstituteEnglish)), subEN(prefix, n, SubstituteDefaultLabel))
			}
		}
	}
	return substitutes
}

func TestSubstituteNeverDetected(t *testing.T) {
	t.Run("un Substitut n'est jamais détecté, seul ni dans les gabarits shell, JSON, YAML, .env, URL et Bearer", func(t *testing.T) {
		rules := loadInitialRules(t)
		checked := 0
		for _, s := range neverDetectedSubstitutes() {
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
			begin, end := pemHeader(label), "-----END "+label+"-----"
			for _, body := range []string{subFR("", 7, "clé privée"), subEN("", 7, "private key")} {
				for name, text := range map[string]string{
					"bloc":                 begin + "\n" + body + "\n" + end + "\n",
					"bloc CRLF":            begin + "\r\n" + body + "\r\n" + end,
					"incomplet":            "clé :\n" + begin + "\n" + body + "\n",
					"JSON échappé":         `{"key": "` + begin + `\n` + body + `\n` + end + `"}`,
					"affectation .env":     "PRIVATE_KEY=\"" + begin + "\n" + body + "\n" + end + "\"\n",
					"affectation YAML":     "private" + "_key: |\n  " + begin + "\n  " + body + "\n  " + end + "\n",
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
		}
	})
}

func TestFakeSubstituteDetected(t *testing.T) {
	t.Run("un texte qui ressemble à un Substitut sans en être un reste analysé et détecté", func(t *testing.T) {
		rules := loadInitialRules(t)
		token := syntheticGitHubToken()
		password := syntheticPassword() + "5"
		base := subFR("", 1, "jeton GitHub")
		for name, text := range map[string]string{
			"jeton à la place du type":          "[secret masqué par xSOM n°1 : " + token + ", pas la vraie valeur]",
			"jeton collé après le Substitut":    `export TOKEN="` + base + token[4:] + `"`,
			"mot de passe collé":                `DB_PASSWORD="` + base + password + `"`,
			"mot de passe devant":               `DB_PASSWORD="` + password + base + `"`,
			"numéro 0":                          `export TOKEN="` + subFR("", 0, "jeton GitHub") + `"`,
			"numéro 1000":                       `export TOKEN="` + subFR("", 1000, "jeton GitHub") + `"`,
			"type d'une autre langue":           `export TOKEN="` + subFR("", 1, "GitHub token") + `"`,
			"type hors de la table":             `export TOKEN="` + subFR("", 1, "jeton maison") + `"`,
			"crochet fermant absent":            `export TOKEN="` + base[:len(base)-1] + `"`,
			"curl -u, Substitut suivi de texte": basicAuthCommand() + base + "abc https://x",
			"ancienne forme, jeton GitHub":      "export TOKEN=" + oldSubstitute("ghp_", 35, "1"),
			"ancienne forme, corps altéré":      "export TOKEN=" + oldSubstitute("ghp_", 34, "1a"),
		} {
			result := Scan([]byte(text), rules, Options{})
			if !result.Complete || len(result.Findings) == 0 {
				t.Errorf("%s : non détecté", name)
			}
		}
	})
}

// FuzzSubstituteGrammar : un octet quelconque posé dans un Substitut ; la grammaire n'admet le texte obtenu que s'il
// est exactement un Substitut que le moteur écrirait (autre préfixe de la règle, autre numéro), et un Substitut admis
// n'est jamais détecté.
//
//	go test ./detect -run '^$' -fuzz '^FuzzSubstituteGrammar$' -fuzztime=60s
func FuzzSubstituteGrammar(f *testing.F) {
	for _, seed := range []struct {
		pos  uint
		char byte
	}{{0, 'a'}, {4, '('}, {32, '2'}, {33, '0'}, {40, 'X'}, {60, ' '}, {5, 's'}} {
		f.Add(seed.pos, seed.char, false)
		f.Add(seed.pos, seed.char, true)
	}
	rules := loadInitialRules(f)
	// Ce qu'un seul octet changé peut encore donner : un autre préfixe de la règle (ghs_, gho_…) ou un autre numéro.
	written := map[string]bool{}
	for _, prefix := range substitutePrefixesByRule["github_token"] {
		for n := 1; n <= 9; n++ {
			written[subFR(prefix, n, "jeton GitHub")] = true
			written[subEN(prefix, n, "GitHub token")] = true
		}
	}
	f.Fuzz(func(t *testing.T, pos uint, char byte, english bool) {
		original := subFR("ghp_", 1, "jeton GitHub")
		if english {
			original = subEN("ghp_", 1, "GitHub token")
		}
		value := []byte(original)
		value[pos%uint(len(value))] = char
		if !isSubstitute(value) {
			return
		}
		if !written[string(value)] {
			t.Fatalf("%q admis par la grammaire", value)
		}
		if result := Scan(value, rules, Options{}); !result.Complete || len(result.Findings) > 0 {
			t.Fatalf("Substitut détecté : %+v", result)
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
		if err != nil || string(text) != "01"+subFR("", 1, "secret")+"ab"+subFR("", 2, "secret") || len(subs) != 2 || subs[0].RuleID != "a" ||
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
		if out, _, err := Expurgate(text, result, fixedOrdinal(1)); err != nil || string(out) != "a"+subFR("", 1, "secret")+"b" {
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
			{2, 2, "a b\n" + subFR("", 1, "secret") + " " + subFR("ghp_", 1, "jeton GitHub") + " suite\nfin"},
			{3, 1, "a b\n" + subFR("", 1, "secret") + "\nfin"},
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

// fingerprintOrdinals numérote par Empreinte locale, à partir de 1 : même Empreinte locale, même numéro (ce que fait
// l'appelant qui veut le même Substitut pour la même valeur).
func fingerprintOrdinals() func(Finding) (int, bool) {
	seen := map[string]int{}
	return func(f Finding) (int, bool) {
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
	recording := func(seen map[[2]int]string) func(Finding) (int, bool) {
		return func(f Finding) (int, bool) {
			seen[[2]int{f.ByteStart, f.ByteEnd}] = f.LocalFingerprint
			return 1, true
		}
	}
	t.Run("étendue fusionnée de deux constats qui se touchent : Empreinte locale des octets fusionnés", func(t *testing.T) {
		content := []byte("A " + token + "!" + token + " B")
		end := 2 + len(token)
		calls := 0
		defer swapExpurgateScan(func(c []byte, r *Rules, o Options, k *FingerprintKey) Result {
			calls++
			if calls > 1 {
				return scan(c, r, o, k)
			}
			// Deux constats qui se touchent, chacun avec l'Empreinte locale de sa seule valeur.
			return Result{Complete: true, Failure: FailureNone, Findings: []Finding{
				{RuleID: "github_token", SecretType: "provider_token", Score: 95, ByteStart: 2, ByteEnd: end + 1,
					LocalFingerprint: localFingerprint(key, content[2:end+1])},
				{RuleID: "github_token", SecretType: "provider_token", Score: 95, ByteStart: end + 1, ByteEnd: end + 1 + len(token),
					LocalFingerprint: localFingerprint(key, content[end+1:end+1+len(token)])},
			}}
		})()
		seen := map[[2]int]string{}
		_, subs, result := ExpurgateAndRescan(content, rules, &key, Options{}, recording(seen))
		if result.Failure != SanitizeNone || len(subs) != 1 || subs[0].ByteStart != 2 || subs[0].ByteEnd != end+1+len(token) ||
			subs[0].LocalFingerprint == result.Initial.Findings[0].LocalFingerprint {
			t.Fatalf("%s %+v", result.Failure, subs)
		}
		checkFingerprints(t, content, subs, seen)
	})
	t.Run("même jeton sur deux lignes : même Empreinte locale, celle du jeton", func(t *testing.T) {
		content := []byte("GITHUB_TOKEN=" + token + "\nOTHER=1\nAGAIN=" + token + "\nZ=2")
		seen := map[[2]int]string{}
		_, subs, result := expurgateBoth(t, content, rules, &key, Options{}, func() func(Finding) (int, bool) { return recording(seen) })
		if result.Failure != SanitizeNone || len(subs) != 2 || subs[0].LocalFingerprint != subs[1].LocalFingerprint ||
			subs[0].LocalFingerprint != localFingerprint(key, []byte(token)) {
			t.Fatalf("%s %+v", result.Failure, subs)
		}
		checkFingerprints(t, content, subs, seen)
	})
	t.Run("partie secrète d'une URL : Empreinte locale du seul mot de passe", func(t *testing.T) {
		content := []byte("postgres://app:" + syntheticPassword() + "@db/x")
		seen := map[[2]int]string{}
		_, subs, result := ExpurgateAndRescan(content, rules, &key, Options{}, recording(seen))
		if result.Failure != SanitizeNone || len(subs) != 1 || subs[0].LocalFingerprint != localFingerprint(key, []byte(syntheticPassword())) {
			t.Fatalf("%s %+v", result.Failure, subs)
		}
		checkFingerprints(t, content, subs, seen)
	})
	t.Run("résidu élargi au jeton puis à la ligne : Empreinte locale des octets élargis", func(t *testing.T) {
		content := []byte("a b\nkey " + token + " suite\nfin")
		for _, cleanAfter := range []int{2, 3} {
			calls := 0
			restore := swapExpurgateScan(func(text []byte, r *Rules, o Options, k *FingerprintKey) Result {
				calls++
				if calls == 1 || calls > cleanAfter {
					return scan(text, r, o, k)
				}
				return Result{Complete: true, Failure: FailureNone, Findings: []Finding{{RuleID: "r", ByteStart: 4, ByteEnd: 7}}}
			})
			seen := map[[2]int]string{}
			_, subs, result := ExpurgateAndRescan(content, rules, &key, Options{}, recording(seen))
			restore()
			if result.Failure != SanitizeNone || len(subs) == 0 || subs[0].ByteStart != 4 {
				t.Fatalf("%d : %s %+v", cleanAfter, result.Failure, subs)
			}
			checkFingerprints(t, content, subs, seen)
		}
	})
	t.Run("Expurgate sans clé : Empreinte locale gardée pour l'étendue exacte du constat seulement", func(t *testing.T) {
		password := syntheticPassword()
		content := []byte("A " + token + " postgres://app:" + password + "@db/x")
		result := ScanWithFingerprint(content, rules, key)
		if !result.Complete || len(result.Findings) != 2 {
			t.Fatalf("%+v", result.Findings)
		}
		// Étendue exacte : Empreinte locale du constat gardée.
		exact := Result{Complete: true, Failure: FailureNone, Findings: result.Findings[:1]}
		_, subs, err := Expurgate(content, exact, fixedOrdinal(1))
		if err != nil || len(subs) != 1 || subs[0].LocalFingerprint != result.Findings[0].LocalFingerprint {
			t.Fatalf("%+v %v", subs, err)
		}
		// Étendue rétrécie au mot de passe : refus, aucun texte.
		text, subs, err := Expurgate(content, result, fixedOrdinal(1))
		if !errors.Is(err, ErrExpurgateSpan) || text != nil || subs != nil {
			t.Fatalf("%q %+v %v", text, subs, err)
		}
		// Étendue fusionnée par l'expurgation, dont le représentant porte une Empreinte locale : refus.
		touching := Result{Complete: true, Failure: FailureNone, Findings: []Finding{
			{RuleID: "a", Score: 90, ByteStart: 0, ByteEnd: 4, LocalFingerprint: localFingerprint(key, content[0:4])},
			{RuleID: "b", Score: 10, ByteStart: 4, ByteEnd: 8, LocalFingerprint: localFingerprint(key, content[4:8])},
		}}
		if _, _, err := Expurgate(content, touching, fixedOrdinal(1)); !errors.Is(err, ErrExpurgateSpan) {
			t.Fatalf("fusion acceptée : %v", err)
		}
		// Sans Empreinte locale : étendue rétrécie admise, Substitution sans Empreinte locale.
		_, subs, err = Expurgate(content, Scan(content, rules, Options{}), fixedOrdinal(1))
		if err != nil || len(subs) != 2 || subs[0].LocalFingerprint != "" || subs[1].LocalFingerprint != "" {
			t.Fatalf("%+v %v", subs, err)
		}
	})
	t.Run("clé effacée entre les analyses : aucun texte", func(t *testing.T) {
		wiped := randomKey(t)
		content := []byte("A " + token)
		calls := 0
		defer swapExpurgateScan(func(c []byte, r *Rules, o Options, k *FingerprintKey) Result {
			calls++
			result := scan(c, r, o, k)
			if calls == 1 {
				wiped.Wipe()
			}
			return result
		})()
		text, _, result := ExpurgateAndRescan(content, rules, &wiped, Options{}, fixedOrdinal(1))
		if text != nil || result.Failure != SanitizeIncomplete {
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
	raw := make([]byte, FingerprintKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	key, err := NewFingerprintKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Wipe()
	alone := ScanWithFingerprint([]byte(token), rules, key)
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
				initial := ScanWithFingerprint([]byte(c.input), rules, key)
				if !initial.Complete || len(initial.Findings) != len(c.spans) || !bytes.ContainsAny([]byte(c.input[initial.Findings[0].ByteStart:initial.Findings[0].ByteEnd]), "\r\n") {
					t.Fatalf("cas sans étendue qui passe la fin de ligne : %+v", initial.Findings)
				}
				text, subs, result := expurgateBoth(t, []byte(c.input), rules, &key, Options{}, fingerprintOrdinals)
				if result.Failure != SanitizeNone || string(text) != c.want || len(subs) != len(c.spans) {
					t.Fatalf("%s : %q %+v", result.Failure, text, subs)
				}
				for i, s := range subs {
					if s.ByteStart != c.spans[i][0] || s.ByteEnd != c.spans[i][1] || s.UTF16Start != s.ByteStart || s.UTF16End != s.ByteEnd ||
						s.RuleID != "github_token" || s.LocalFingerprint != tokenFingerprint || s.Ordinal != 1 {
						t.Errorf("Substitution %+v, étendue attendue %v", s, c.spans[i])
					}
				}
				if again := Scan(text, rules, Options{}); !again.Complete || len(again.Findings) > 0 {
					t.Fatalf("constat après expurgation : %+v", again.Findings)
				}
			})
		}
	})
	t.Run("le numéro reçoit le constat ramené à la première ligne, avec son Empreinte locale", func(t *testing.T) {
		var got []Finding
		_, _, result := ExpurgateAndRescan([]byte("export A="+token+"\nexport B=x"), rules, &key, Options{}, func(f Finding) (int, bool) {
			got = append(got, f)
			return 1, true
		})
		if result.Failure != SanitizeNone || len(got) != 1 || got[0].ByteStart != 9 || got[0].ByteEnd != 49 || got[0].LocalFingerprint != tokenFingerprint {
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
				initial := Scan([]byte(c.input), rules, Options{})
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
				text, subs, result := expurgateBoth(t, []byte(c.input), rules, nil, Options{}, func() func(Finding) (int, bool) { return fixedOrdinal(1) })
				if result.Failure != SanitizeNone || len(subs) != 1 || subs[0].ByteStart > f.ByteStart || subs[0].ByteEnd < f.ByteEnd ||
					bytes.Contains(text, []byte("aB3d")) {
					t.Fatalf("%s : %q %+v, constat %+v", result.Failure, text, subs, f)
				}
			})
		}
	})
	t.Run("sans règles (Expurgate) : étendue entière remplacée", func(t *testing.T) {
		content := []byte("export A=" + token + "\nexport B=x")
		text, subs, err := Expurgate(content, Scan(content, rules, Options{}), fixedOrdinal(1))
		if err != nil || len(subs) != 1 || subs[0].ByteEnd != 56 || string(text) != "export A="+subFR("ghp_", 1, "jeton GitHub")+" B=x" {
			t.Fatalf("%q %+v %v", text, subs, err)
		}
	})
	t.Run("rétrécissement réservé aux règles « motif seul » dont la première ligne est une valeur exacte", func(t *testing.T) {
		content := []byte("export A=" + token + "\nexport B=x")
		for _, c := range []struct {
			f    Finding
			want bool
		}{
			{Finding{RuleID: "github_token", ByteStart: 9, ByteEnd: 56}, true},
			{Finding{RuleID: "github_token", ByteStart: 8, ByteEnd: 56}, false},           // « = » en tête : pas une valeur exacte
			{Finding{RuleID: "github_token", ByteStart: 9, ByteEnd: 49}, false},           // aucune fin de ligne
			{Finding{RuleID: "github_token", ByteStart: 9, ByteEnd: len(content)}, false}, // fin du texte
			{Finding{RuleID: "openai_key", ByteStart: 9, ByteEnd: 56}, false},             // autre règle
			{Finding{RuleID: "high_entropy", ByteStart: 9, ByteEnd: 56}, false},           // règle sans motif du Pack
			{Finding{RuleID: "contextual_generic_secret", ByteStart: 9, ByteEnd: 56}, false},
			{Finding{RuleID: customRulePrefix + "x", SecretType: customSecretType, ByteStart: 9, ByteEnd: 56}, false},
		} {
			_, ok := firstLineSecretEnd(content, rules, c.f)
			if ok != c.want {
				t.Errorf("%+v : %v", c.f, ok)
			}
		}
		if _, ok := firstLineSecretEnd(content, nil, Finding{RuleID: "github_token", ByteStart: 9, ByteEnd: 56}); ok {
			t.Error("rétréci sans règles")
		}
		if _, ok := firstLineSecretEnd(content, &Rules{}, Finding{RuleID: "github_token", ByteStart: 9, ByteEnd: 56}); ok {
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
		counts := map[SanitizeFailure]int{}
		residualCases, remaining, overLimit := 0, 0, 0
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
			case result.Failure == SanitizeIncomplete && result.Initial.Complete && result.Final.Failure == FailureScanLimit:
				// Texte proche de 1 Mio : le Substitut, plus long que la valeur, fait passer le texte expurgé au-delà de
				// MaxInputBytes ; refus, jamais un texte non analysé.
				overLimit++
			case c.Expected.Failure == SanitizeNone && utf8.Valid(content):
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
		counts := map[SanitizeFailure]int{}
		refused := map[string]int{}
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
					switch {
					case !utf8.Valid(content):
						refused["hors UTF-8"]++
					case result.Initial.Complete && result.Final.Failure == FailureScanLimit:
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
				if again := Scan(text, rules, options); !again.Complete || len(again.Findings) > 0 {
					t.Errorf("%s : constat après expurgation", c.ID)
				}
				excused += replacedWindowsLeft(t, c.ID, content, text, subs)
			}
		}
		t.Logf("issues : %v (refus : %v) ; %d fenêtres présentes aussi hors des étendues remplacées dans l'entrée", counts, refused, excused)
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
//	go test ./detect -run '^$' -fuzz '^FuzzExpurgate$' -fuzztime=60s
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

// TestExpurgateLanguage : Substituts en français par défaut, en anglais avec Options.SubstituteLanguage ; une autre
// langue fait échouer l'expurgation sans texte ; le texte expurgé ne porte ni la valeur, ni sa longueur.
func TestExpurgateLanguage(t *testing.T) {
	rules := loadInitialRules(t)
	token := syntheticGitHubToken()
	password := syntheticPassword() + "5"
	content := []byte("postgres://admin:" + password + "@db.exemple.fr:5432/prod\nexport GH=" + token)
	for _, c := range []struct {
		language SubstituteLanguage
		want     string
	}{
		{"", "postgres://admin:" + subFR("", 1, "mot de passe de base de données") + "@db.exemple.fr:5432/prod\nexport GH=" + subFR("ghp_", 2, "jeton GitHub")},
		{SubstituteFrench, "postgres://admin:" + subFR("", 1, "mot de passe de base de données") + "@db.exemple.fr:5432/prod\nexport GH=" + subFR("ghp_", 2, "jeton GitHub")},
		{SubstituteEnglish, "postgres://admin:" + subEN("", 1, "database password") + "@db.exemple.fr:5432/prod\nexport GH=" + subEN("ghp_", 2, "GitHub token")},
	} {
		text, subs, result := expurgateBoth(t, content, rules, nil, Options{SubstituteLanguage: c.language}, func() func(Finding) (int, bool) { return startOrdinals(1) })
		if result.Failure != SanitizeNone || string(text) != c.want || len(subs) != 2 {
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
	for _, language := range []SubstituteLanguage{"de", "FR", "fr-FR"} {
		text, subs, result := ExpurgateAndRescan(content, rules, nil, Options{SubstituteLanguage: language}, fixedOrdinal(1))
		if text != nil || subs != nil || result.Failure != SanitizeIncomplete {
			t.Errorf("%q : %s", language, result.Failure)
		}
	}
	// Une langue inconnue est refusée même sans constat.
	if text, _, result := ExpurgateAndRescan([]byte("rien"), rules, nil, Options{SubstituteLanguage: "de"}, fixedOrdinal(1)); text != nil || result.Failure != SanitizeIncomplete {
		t.Fatalf("%s", result.Failure)
	}
}

func TestFindSubstitutes(t *testing.T) {
	a, b := subFR("", 1, "mot de passe de base de données"), subEN("gh"+"p_", 12, "GitHub token")
	text := "psql postgres://admin:" + a + "@db.exemple.fr:5432/prod && " + curlUser("x") + b + " https://x " +
		"[secret masqué par xSOM n°3 : inconnu, pas la vraie valeur] " + strings.Repeat("X", 4) + "4 x" + subFR("sk-", 999, "secret")
	got := FindSubstitutes([]byte(text))
	first := strings.Index(text, a)
	second := strings.Index(text, b)
	third := strings.Index(text, "x"+subFR("sk-", 999, "secret")) + 1
	want := []SubstituteSpan{
		{ByteStart: first, ByteEnd: first + len(a), Ordinal: 1},
		{ByteStart: second, ByteEnd: second + len(b), Ordinal: 12},
		{ByteStart: third, ByteEnd: len(text), Ordinal: 999},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%+v, attendu %+v", got, want)
	}
	for _, none := range []string{"", "[", "[]", "[secret", subFR("", 1, "mot de passe")[1:], strings.Replace(a, "n°1", "n°0", 1)} {
		if spans := FindSubstitutes([]byte(none)); len(spans) != 0 {
			t.Errorf("%q : %+v", none, spans)
		}
	}
}

// FuzzFindSubstitutes : quelle que soit l'entrée, les étendues rendues sont dans l'ordre, sans chevauchement, et chacune
// est exactement un Substitut de la grammaire, de numéro 1 à 999.
//
//	go test ./detect -run '^$' -fuzz '^FuzzFindSubstitutes$' -fuzztime=60s
func FuzzFindSubstitutes(f *testing.F) {
	for _, seed := range []string{"", "[", subFR("ghp_", 1, "jeton GitHub") + "x" + subEN("", 2, "password"), "a[" + subFR("", 3, "secret")} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, text []byte) {
		cursor := 0
		for _, s := range FindSubstitutes(text) {
			if s.ByteStart < cursor || s.ByteEnd <= s.ByteStart || s.ByteEnd > len(text) || !isSubstitute(text[s.ByteStart:s.ByteEnd]) ||
				s.Ordinal < MinSubstituteOrdinal || s.Ordinal > MaxSubstituteOrdinal {
				t.Fatalf("%+v", s)
			}
			cursor = s.ByteEnd
		}
	})
}
