package detect

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

// Vecteurs de l'expurgation, propres à ce module (aucune origine TypeScript, avis dans UPSTREAM.md). Écrits par ce
// test : go test ./detect -run '^TestExpurgateVectors$' -update.
const expurgateVectorsFile = "../vectors/expurgate.json"

var updateExpurgateVectors = flag.Bool("update", false, "réécrit vectors/expurgate.json")

// expurgateVectorInput est un cas des vecteurs : entrée construite à l'exécution (valeurs synthétiques), identifiant
// de langage, premier numéro (les étendues sont numérotées dans l'ordre où elles sont vues, à partir de lui).
type expurgateVectorInput struct {
	id           string
	input        string
	languageID   string
	firstOrdinal int
}

func expurgateVectorInputs() []expurgateVectorInput {
	token := syntheticGitHubToken()
	password := syntheticPassword() + "5"
	opaque := "aZ3kQ9mW2xL7pR4tY8vB1nC6"
	return []expurgateVectorInput{
		{"matrice/jeton-github", "export TOKEN=" + token, "", 1},
		{"matrice/url", "postgres://app:" + password + "@db:5432/x", "", 2},
		{"matrice/bearer", "Authorization: Bearer " + opaque, "", 1},
		{"matrice/bearer-jeton-github", "Authorization: Bearer " + token, "", 1},
		{"matrice/pem", syntheticPEM("\n") + "\n", "", 1},
		{"matrice/pem-crlf", "clé :\r\n" + syntheticPEM("\r\n") + "\r\n", "", 1},
		{"matrice/pem-json", `{"key": "` + syntheticPEM(`\n`) + `"}`, "", 1},
		{"matrice/pem-incomplet", pemHeader("PRIVATE KEY") + "\nMIIEow" + strings.Repeat("q7Lm2Pz9Wr4Tn", 4) + "\n", "", 1},
		{"matrice/cli-basic-auth", basicAuthCommand() + password + " https://x", "", 1},
		{"matrice/faux-substitut-fin", "TOKEN=ghp_" + strings.Repeat("X", 34) + "1a", "", 1},
		{"matrice/faux-substitut-corps", "TOKEN=ghp_" + strings.Repeat("X", 15) + "A" + strings.Repeat("X", 19) + "1", "", 1},
		{"matrice/numero-999", "export TOKEN=" + token, "", 999},
		{"matrice/numero-trop-grand", "A=" + token + "\nB_PASSWORD=" + password, "", 999},
		{"longueur/minimum", "postgres://u:p4ss@db/x", "", 1},
		{"longueur/points-de-code", "PASSWORD=é" + password + "😀", "", 1},
		{"utf16/non-ascii", "é😀 clé « " + token + " »\nDB_PASSWORD=" + syntheticPassword() + "\nfin 😀", "", 10},
		{"utf8/refuse", "TOKEN=" + token + "\n\xff", "", 1},
		{"matrice/en-tete-curl", `curl -H "Authorization: Bearer ` + opaque + `" https://x`, "", 1},
		{"matrice/url-jeton-utilisateur", "git clone https://" + token + ":x-oauth-basic@github.com/o/r.git", "", 1},
		{"matrice/url-cle-utilisateur", "git clone https://" + opaque + ":x-oauth-basic@github.com/o/r.git", "", 1},
		{"matrice/curl-u-cle-api", curlUser(opaque) + "X https://x", "", 1},
		{"matrice/prefixe-hors-regle", "PASSWORD=dapi" + strings.Repeat("q7Lm", 4) + "\nDB_PASSWORD=AKIA" + strings.Repeat("q7Lm", 4), "", 1},
		{"matrice/schema-dans-mot-de-passe", `DB_PASSWORD="Token ` + strings.Repeat("q7Lm", 4) + `"`, "", 1},
		{"gabarit/json", `{"token": "` + token + `", "password": "` + password + `"}`, "json", 1},
		{"gabarit/yaml", "auth:\n  token: " + token + "\n  password: " + password + "\n", "yaml", 1},
		{"gabarit/dotenv", "API_KEY=" + token + "\nDB_PASSWORD=" + password + "\n", "dotenv", 1},
		{"gabarit/shell", `export TOKEN="` + token + `" && ` + basicAuthCommand() + password + " https://x", "shellscript", 1},
		{"gabarit/meme-valeur", "A " + token + " B " + token, "", 1},
		{"residu/affectation-ligne-suivante", "API_KEY=" + token + "\nNEXT=another", "", 1},
		{"residu/bloc-yaml", "app_secret: |\n  " + strings.Repeat("aZ3k", 6) + "\n  " + strings.Repeat("Lm2P", 6) + "\nnext: 1\n", "yaml", 1},
		{"ligne/shell-ligne-suivante", "export A=" + token + "\nexport B=x", "shellscript", 1},
		{"ligne/shell-crlf", "export A=" + token + "\r\nexport B=x", "shellscript", 1},
		{"ligne/dotenv-meme-jeton", "GITHUB_TOKEN=" + token + "\nOTHER=1\nAGAIN=" + token + "\nZ=2", "dotenv", 1},
		{"ligne/dotenv-crlf", "GITHUB_TOKEN=" + token + "\r\nOTHER=1\r\n", "dotenv", 1},
		{"ligne/jeton-coupe", "clé " + token[:24] + "\n" + token[24:] + " suite", "", 1},
		{"ligne/suite-en-fin-de-texte", "clé " + token + "\n" + strings.Repeat("aB3d", 4), "", 1},
		{"sans-constat", "rien à signaler", "", 1},
	}
}

type expurgateVectorSubstitution struct {
	RuleID      string `json:"ruleId"`
	SecretType  string `json:"secretType"`
	ByteStart   int    `json:"byteStart"`
	ByteEnd     int    `json:"byteEnd"`
	UTF16Start  int    `json:"utf16Start"`
	UTF16End    int    `json:"utf16End"`
	Ordinal     int    `json:"ordinal"`
	Replacement string `json:"replacement"`
}

type expurgateVectorCase struct {
	ID string `json:"id"`
	// Entrée en base64, coupée en morceaux de 8 caractères : ni les valeurs synthétiques ni leur base64 ne sont écrites
	// d'un seul tenant (recherche de secrets du dépôt, qui décode le base64).
	Input        []string `json:"input"`
	LanguageID   string   `json:"languageId,omitempty"`
	FirstOrdinal int      `json:"firstOrdinal"`
	Expected     struct {
		Failure SanitizeFailure `json:"failure"`
		// Texte expurgé, coupé en morceaux d'au plus 16 octets aux limites de caractères (une clé PEM au corps fait
		// d'un Substitut a la forme d'une clé privée pour la recherche de secrets) ; en base64 coupé comme l'entrée si
		// textEncoding vaut « base64 » (texte hors UTF-8). Absent après un échec.
		Text          []string                      `json:"text"`
		TextEncoding  string                        `json:"textEncoding,omitempty"`
		Substitutions []expurgateVectorSubstitution `json:"substitutions"`
	} `json:"expected"`
}

// chunks coupe text en morceaux d'au plus size octets, aux limites de caractères UTF-8.
func chunks(text string, size int) []string {
	var out []string
	for len(text) > 0 {
		end := min(size, len(text))
		for end < len(text) && end > 0 && !utf8.RuneStart(text[end]) {
			end--
		}
		if end == 0 {
			end = min(size, len(text))
		}
		out = append(out, text[:end])
		text = text[end:]
	}
	return out
}

type expurgateVectors struct {
	FormatVersion int                   `json:"formatVersion"`
	Description   string                `json:"description"`
	Cases         []expurgateVectorCase `json:"cases"`
}

// buildExpurgateVectors exécute ExpurgateAndRescan (sans clé : aucune Empreinte locale) sur chaque entrée.
func buildExpurgateVectors(t *testing.T) []byte {
	t.Helper()
	rules := loadInitialRules(t)
	vectors := expurgateVectors{
		FormatVersion: 1,
		Description: "Expurgation (detect.ExpurgateAndRescan, sans clé d'Empreinte locale) : entrée en base64 et texte " +
			"expurgé, coupés en morceaux à joindre (recherche de secrets du dépôt) ; numéros " +
			"donnés dans l'ordre où les étendues sont vues à partir de firstOrdinal (même début, même numéro). Extension de " +
			"ce module, sans origine TypeScript ; écrit par go test ./detect -run '^TestExpurgateVectors$' -update.",
	}
	for _, in := range expurgateVectorInputs() {
		text, subs, result := ExpurgateAndRescan([]byte(in.input), rules, nil, Options{LanguageID: in.languageID}, startOrdinals(in.firstOrdinal))
		c := expurgateVectorCase{
			ID: in.id, Input: chunks(base64.StdEncoding.EncodeToString([]byte(in.input)), 8), LanguageID: in.languageID,
			FirstOrdinal: in.firstOrdinal,
		}
		c.Expected.Failure = result.Failure
		c.Expected.Substitutions = []expurgateVectorSubstitution{}
		if text != nil {
			c.Expected.Text = chunks(string(text), 16)
			if !utf8.Valid(text) {
				c.Expected.Text, c.Expected.TextEncoding = chunks(base64.StdEncoding.EncodeToString(text), 8), "base64"
			}
		}
		for _, s := range subs {
			c.Expected.Substitutions = append(c.Expected.Substitutions, expurgateVectorSubstitution{
				RuleID: s.RuleID, SecretType: s.SecretType, ByteStart: s.ByteStart, ByteEnd: s.ByteEnd,
				UTF16Start: s.UTF16Start, UTF16End: s.UTF16End, Ordinal: s.Ordinal, Replacement: s.Replacement,
			})
		}
		vectors.Cases = append(vectors.Cases, c)
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(vectors); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// TestExpurgateVectors : vectors/expurgate.json est exactement l'expurgation de ses entrées par le moteur (même
// texte, mêmes Substitutions, mêmes issues). Chaque cas réussi est relu : texte reconstruit à partir de l'entrée et des
// Substitutions, sans constat à une nouvelle analyse.
func TestExpurgateVectors(t *testing.T) {
	t.Run("vecteurs de l'expurgation égaux au moteur", func(t *testing.T) {
		built := buildExpurgateVectors(t)
		if *updateExpurgateVectors {
			if err := os.WriteFile(expurgateVectorsFile, built, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		committed, err := os.ReadFile(expurgateVectorsFile)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(committed, built) {
			t.Fatal("vectors/expurgate.json diffère de l'expurgation du moteur (go test ./detect -run '^TestExpurgateVectors$' -update)")
		}
		var vectors expurgateVectors
		readStrict(t, expurgateVectorsFile, &vectors)
		rules := loadInitialRules(t)
		failures := map[SanitizeFailure]int{}
		for _, c := range vectors.Cases {
			failures[c.Expected.Failure]++
			if c.Expected.Text == nil {
				continue
			}
			content, err := base64.StdEncoding.DecodeString(strings.Join(c.Input, ""))
			if err != nil {
				t.Fatalf("%s : entrée illisible", c.ID)
			}
			text := decodeVectorText(c.Expected.TextEncoding, strings.Join(c.Expected.Text, ""))
			subs := make([]Substitution, 0, len(c.Expected.Substitutions))
			for _, s := range c.Expected.Substitutions {
				subs = append(subs, Substitution{ByteStart: s.ByteStart, ByteEnd: s.ByteEnd, Ordinal: s.Ordinal, Replacement: s.Replacement})
			}
			if diff := substitutionDifference(content, text, subs); diff != "" {
				t.Errorf("%s : %s", c.ID, diff)
			}
			if again := Scan(text, rules, Options{LanguageID: c.LanguageID}); !again.Complete || len(again.Findings) > 0 {
				t.Errorf("%s : constat après expurgation", c.ID)
			}
		}
		if failures[SanitizeNone] == 0 || failures[SanitizeOrdinal] == 0 || failures[SanitizeIncomplete] == 0 {
			t.Fatalf("issues %v", failures)
		}
		t.Logf("%d cas : %v", len(vectors.Cases), failures)
	})
}
