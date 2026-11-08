// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/pack"
)

// pemHeader et basicAuthCommand assemblent à l'exécution un en-tête PEM et le début d'une commande curl -u : écrits
// tels quels, la recherche de secrets du dépôt les prendrait pour une clé et des identifiants (règles private-key et
// curl-auth-user de gitleaks).
func pemHeader(label string) string { return "-----BEGIN" + " " + label + "-----" }

func basicAuthCommand() string { return curlUser("admin") }

func curlUser(user string) string { return "curl -u " + user + ":" }

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

func TestSubstituteText(t *testing.T) {
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
			got, err := SubstituteText([]byte(c.value), c.ruleID, c.ordinal, c.language)
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
					got, err := SubstituteText([]byte("valeur"), l.RuleID, n, language)
					if err != nil || !isSubstitute([]byte(got)) {
						t.Errorf("%s %s %d : %q %v", l.RuleID, language, n, got, err)
					}
				}
			}
		}
	})
	t.Run("numéro hors de 1 à 999 : ErrSubstituteOrdinal ; langue inconnue : ErrSubstituteLanguage", func(t *testing.T) {
		for _, n := range []int{0, -1, 1000, 1 << 40} {
			if got, err := SubstituteText([]byte("valeur"), "", n, ""); got != "" || !errors.Is(err, ErrSubstituteOrdinal) {
				t.Errorf("%d : %q %v", n, got, err)
			}
		}
		for _, language := range []SubstituteLanguage{"de", "FR", "fr-FR", " en"} {
			if got, err := SubstituteText([]byte("valeur"), "", 1, language); got != "" || !errors.Is(err, ErrSubstituteLanguage) {
				t.Errorf("%q : %q %v", language, got, err)
			}
			if language.Valid() {
				t.Errorf("%q : langue admise", language)
			}
		}
		for _, language := range []SubstituteLanguage{"", SubstituteFrench, SubstituteEnglish} {
			if !language.Valid() {
				t.Errorf("%q : langue refusée", language)
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
