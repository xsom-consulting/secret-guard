// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"strings"
	"testing"
	"time"
)

// Noms sensibles et valeurs d'essai, assemblés par morceaux : la recherche de secrets du dépôt et celle des Postes ne
// lisent pas ces essais comme des affectations.
var (
	namePassword = "pass" + "word"
	nameToken    = "tok" + "en"
	nameAPIKey   = "api" + "Key"
	nameSecret   = "sec" + "ret"
	nameAuth     = "Authori" + "zation"
	// literalStrong : littéral de forme stricte (chiffre, trois classes de caractères).
	literalStrong = "Xy7#" + "kLm9" + "Qr2v"
	// literalWords : mot de passe fait de mots, sans chiffre.
	literalWords = "not-a-real-" + namePassword
)

// assignmentFindings rend les constats des règles d'affectation (contextual_*) de l'analyse de text.
func assignmentFindings(t *testing.T, text, languageID string) []Finding {
	t.Helper()
	result := Scan([]byte(text), loadInitialRules(t), Options{LanguageID: languageID})
	if !result.Complete {
		t.Fatalf("analyse incomplète : %v", result.Failure)
	}
	var out []Finding
	for _, f := range result.Findings {
		if strings.HasPrefix(f.RuleID, contextualRulePrefix) {
			out = append(out, f)
		}
	}
	return out
}

type noiseCase struct {
	name, text, language string
}

// TestAssignmentValueIsNotALiteral : palier 1. Une référence, un gabarit, une chaîne à interpolation, une structure
// de code ou un texte sans guillemets lu à la ligne suivante n'est pas un constat d'affectation, avec ou sans langage.
func TestAssignmentValueIsNotALiteral(t *testing.T) {
	option := "--" + nameToken
	cases := []noiseCase{
		{"variable entre guillemets puis option", `./config.sh --url "$REPO_URL" ` + option + ` "$RUNNER_VALUE" --unattended --replace`, "shellscript"},
		{"variable sans guillemets puis option", `./config.sh ` + option + ` $RUNNER_VALUE --unattended`, "shellscript"},
		{"variable entre accolades puis option", `./config.sh ` + option + ` "${RUNNER_VALUE}" --unattended`, "shellscript"},
		{"variable après le signe égal", `./config.sh ` + option + `="$RUNNER_VALUE" --unattended`, "shellscript"},
		{"paramètre positionnel", `register ` + option + ` "$1" --name "$2"`, "shellscript"},
		{"paramètre positionnel affecté", `  local ` + nameToken + `="$1"`, "shellscript"},
		{"expansion à message d'erreur", `RUNNER_` + strings.ToUpper(nameToken) + `="${RUNNER_VALUE:?variable requise}"`, "shellscript"},
		{"expansion à défaut vide", strings.ToUpper(nameToken) + `="${RUNNER_VALUE:-}"`, "shellscript"},
		{"expansion dont le défaut est une variable", strings.ToUpper(nameToken) + `="${RUNNER_VALUE:-$OTHER_VALUE}"`, "shellscript"},
		{"substitution de commande puis option", `./config.sh ` + option + ` "$(gh api -X POST repos/o/r/runners --jq .value)" --unattended`, "shellscript"},
		{"substitution de commande à guillemets imbriqués", `export GH_` + strings.ToUpper(nameToken) + `="$(cat "$HOME/.config/value")"`, "shellscript"},
		{"accents graves", strings.ToUpper(nameToken) + "=`cat /run/value`", "shellscript"},
		{"schéma puis variable dans un en-tête", `curl -sS -H "` + nameAuth + `: Bearer $RUNNER_VALUE" https://api.example.test/v1/runners`, "shellscript"},
		{"variable dans une option de mot de passe", `psql --host "$HOST" --` + namePassword + ` "$PGPASS" --dbname app`, "shellscript"},
		{"expression de CI github", `          GITHUB_` + strings.ToUpper(nameToken) + `: ${{ github.` + nameToken + ` }}`, "yaml"},
		{"expression de CI sortie d'étape", `          ` + nameToken + `: ${{ steps.app.outputs.value }}`, "yaml"},
		{"expression de CI entrée", `          ` + nameToken + `: ${{ inputs.value }}`, "yaml"},
		{"gabarit Helm", `  ` + namePassword + `: {{ .Values.database.value }}`, "yaml"},
		{"gabarit Helm à filtre", `  ` + nameToken + `: {{ .Values.auth.value | quote }}`, "yaml"},
		{"gabarit Jinja à appel", `  ` + namePassword + `: "{{ lookup('env', 'DB_VALUE') }}"`, "yaml"},
		{"interpolation Ruby", `  ` + namePassword + `: "#{ENV.fetch('DB_VALUE')}",`, "ruby"},
		{"gabarit JavaScript", "  " + nameAPIKey + ": `${prefix}-${suffix}`,", "typescript"},
		{"chaîne à champs Python", `    headers = {"` + nameAuth + `": f"Bearer {access_value}"}`, "python"},
		{"champ de format", `    ` + strings.ToLower(nameAuth) + ` = "Bearer %s" % value`, "python"},
		{"tableau sur une ligne", `  ` + nameAPIKey + `: ["cle-a", "cle-b"],`, "typescript"},
		{"tableau sur plusieurs lignes", "const config = {\n  " + nameAPIKey + ": [\n    primary,\n    fallback,\n  ],\n};", "typescript"},
		{"étalement", `  ` + nameAPIKey + `: [...defaults.keys, ...extra],`, "typescript"},
		{"objet", `  ` + nameSecret + `: { ref: "vault://kv/app", version: 2 },`, "typescript"},
		{"table de libellés", `  ` + namePassword + `: { label: "Mot de passe", hint: "8 caractères au moins" },`, "typescript"},
		{"objet sur plusieurs lignes", "const fields = {\n  " + namePassword + ": {\n    label: \"Mot de passe\",\n    required: true,\n  },\n};", "typescript"},
		{"schéma JSON", `  "` + namePassword + `": { "type": "string", "minLength": 8 },`, "json"},
		{"appel à argument chaîne", `  ` + nameAPIKey + `: readSetting("provider.key"),`, "typescript"},
		{"appel attendu", `  ` + nameAPIKey + `: await vault.read(name),`, "typescript"},
		{"appel imbriqué", `  ` + namePassword + `: hashValue(input.value, salt),`, "typescript"},
		{"appel Go", "\t" + nameToken + ` := r.Header.Get("X-Request-Id")`, "go"},
		{"appel Python", `    ` + namePassword + ` = getpass.getpass("Mot de passe : ")`, "python"},
		{"type générique", `  ` + nameToken + `: Map<string, Session>;`, "typescript"},
		{"fonction fléchée", `  ` + nameToken + `: (request) => request.headers.get("x-request-id"),`, "typescript"},
		{"clé de section YAML", "    secrets:\n      NPM_" + strings.ToUpper(nameToken) + ":\n        required: true", "yaml"},
		{"case puis instruction", "\tcase n == \"" + strings.ToLower(nameAuth) + "\":\n\t\treturn kind, true", "go"},
		{"comparaison puis continue", "    if name == \"access_" + nameToken + "\":\n        continue", "python"},
	}
	for _, c := range cases {
		for _, language := range []string{"", c.language} {
			if got := assignmentFindings(t, c.text+"\n", language); len(got) != 0 {
				t.Errorf("%s (langage %q) : %d constat(s) d'affectation, règle %s", c.name, language, len(got), got[0].RuleID)
			}
		}
	}
}

// TestStructureIsWalked : une structure n'est pas écartée en bloc. Sur sa première ligne, un littéral crédible garde
// le constat d'origine ; sur les lignes suivantes, chaque littéral crédible a son constat, sur son étendue exacte ; un
// champ au nom sensible est lu pour lui-même.
func TestStructureIsWalked(t *testing.T) {
	spanOf := func(text, value string) [2]int {
		at := strings.Index(text, value)
		return [2]int{at, at + len(value)}
	}
	t.Run("première ligne : le constat d'origine est gardé", func(t *testing.T) {
		for name, text := range map[string]string{
			"objet JSON qui porte un mot de passe fait de mots": `{"` + namePassword + `":{"value":"` + literalWords + `"}}`,
			"tableau qui porte un littéral":                     `  ` + nameAPIKey + `: ["` + literalStrong + `"],`,
			"objet qui porte un littéral":                       `  ` + nameSecret + `: { value: "` + literalStrong + `", version: 2 },`,
			"appel dont un argument est un littéral":            `  ` + nameToken + `: sign(payload, "` + literalStrong + `"),`,
			"tableau qui porte un mot nu de forme stricte":      `  ` + nameAPIKey + `: [` + literalStrong + `],`,
			"gabarit à défaut littéral":                         `  ` + nameToken + `: {{ .Values.value | default "` + literalStrong + `" }}`,
			"chaîne à interpolation et littéral":                "  " + nameAPIKey + ": `" + literalStrong + "${suffix}`,",
			"substitution de commande qui porte un littéral":    strings.ToUpper(nameToken) + `="$(fetch --key '` + literalStrong + `')"`,
		} {
			got := assignmentFindings(t, text+"\n", "")
			if len(got) != 1 {
				t.Errorf("%s : %d constat(s) %+v", name, len(got), got)
				continue
			}
			value := literalStrong
			if strings.Contains(text, literalWords) {
				value = literalWords
			}
			if span := spanOf(text, value); got[0].ByteStart > span[0] || got[0].ByteEnd < span[1] {
				t.Errorf("%s : le constat [%d,%d) ne couvre pas le littéral [%d,%d)", name, got[0].ByteStart, got[0].ByteEnd, span[0], span[1])
			}
		}
	})
	t.Run("lignes suivantes : un constat sur le littéral", func(t *testing.T) {
		for name, c := range map[string]struct{ text, rule string }{
			"tableau":                {"const config = {\n  " + nameAPIKey + ": [\n    \"" + literalStrong + "\",\n    fallback,\n  ],\n};\n", "contextual_api_key"},
			"objet, champ ordinaire": {nameSecret + " = {\n  value = \"" + literalStrong + "\"\n  version = 2\n}\n", "contextual_generic_secret"},
			"appel":                  {"  const " + nameToken + " = issue(\n    subject,\n    \"" + literalStrong + "\",\n  );\n", "contextual_access_token"},
			"mot de passe fait de mots dans un tableau": {namePassword + ": [\n  \"" + literalWords + "\"\n]\n", "contextual_password"},
		} {
			value := literalStrong
			if strings.Contains(c.text, literalWords) {
				value = literalWords
			}
			got := assignmentFindings(t, c.text, "")
			want := spanOf(c.text, value)
			if len(got) != 1 || got[0].RuleID != c.rule || got[0].ByteStart != want[0] || got[0].ByteEnd != want[1] {
				t.Errorf("%s : constats %+v, attendu %s sur [%d,%d)", name, got, c.rule, want[0], want[1])
			}
		}
	})
	t.Run("champ au nom sensible : lu pour lui-même", func(t *testing.T) {
		text := "const settings = {\n  " + nameSecret + ": {\n    " + namePassword + ": \"" + literalStrong + "\",\n    label: \"Base\",\n  },\n};\n"
		got := assignmentFindings(t, text, "typescript")
		want := spanOf(text, literalStrong)
		if len(got) != 1 || got[0].RuleID != "contextual_"+namePassword || got[0].ByteStart != want[0] || got[0].ByteEnd != want[1] {
			t.Errorf("constats %+v, attendu un mot de passe sur [%d,%d)", got, want[0], want[1])
		}
	})
	t.Run("argument d'un appel : un nom n'est pas un littéral", func(t *testing.T) {
		text := "  " + namePassword + ": t(\"login.field.label\"),\n"
		if got := assignmentFindings(t, text, ""); len(got) != 0 {
			t.Errorf("constats %+v", got)
		}
	})
}

// TestAssignmentNoiseGuards : garde-fous du palier 1. Chaque cas garde son constat.
func TestAssignmentNoiseGuards(t *testing.T) {
	upperToken := strings.ToUpper(nameToken)
	cases := []noiseCase{
		{"défaut littéral d'une expansion de shell", "POSTGRES_" + strings.ToUpper(namePassword) + `: ${POSTGRES_VALUE:-` + literalStrong + `}`, "yaml"},
		{"défaut littéral banal d'une expansion", upperToken + `="${RUNNER_VALUE:-changeme}"`, "shellscript"},
		{"valeur de remplacement littérale", upperToken + `="${RUNNER_VALUE:+` + literalStrong + `}"`, "shellscript"},
		{"tableau dans un fichier dotenv", upperToken + `=[` + literalWords + `]`, "dotenv"},
		{"objet dans une affectation nue d'environnement", `export ` + upperToken + `={"a":"b"}`, ""},
		{"appel dans une affectation nue d'environnement", upperToken + `=compute(1)`, ""},
		{"mot de passe qui porte un dollar", namePassword + `: "Pa$sw0rd!x"`, "yaml"},
		{"mot de passe qui porte un champ de format collé", namePassword + `: "100%sure"`, "yaml"},
		{"mot de passe fait de lettres et d'une variable", namePassword + `: "prefix-${suffix}"`, "yaml"},
		{"variable prolongée par une concaténation", `const ` + nameToken + ` = "$PREFIX" + stored;`, "typescript"},
		{"variable suivie d'un texte collé", upperToken + `=$PREFIX` + `.` + literalStrong, "shellscript"},
		{"gabarit à défaut littéral", nameToken + `: {{ .Values.value | default "` + literalStrong + `" }}`, "yaml"},
		{"mot suivi de parenthèses et d'un signe collé", `le ` + namePassword + `: Sesame(2024)!`, ""},
		{"valeur sans guillemets à la ligne suivante, à forme de secret", upperToken + ":\n  " + literalStrong, "yaml"},
		{"accents graves hors d'un script shell", nameAPIKey + ": `" + literalStrong + "`,", "typescript"},
		{"accents graves d'un mot, sans commande", strings.ToUpper(nameToken) + "=`sesame`", ""},
		{"valeur entre guillemets à la ligne suivante", nameToken + " =\n  \"" + literalStrong + "\"", "typescript"},
		{"mot court sans langage", nameAPIKey + `: "test",`, ""},
		{"accolades suivies d'un texte collé", namePassword + `={label}` + literalStrong, "properties"},
		{"crochets suivis d'un texte collé", namePassword + `: [a]` + literalWords, "yaml"},
	}
	for _, c := range cases {
		for _, language := range []string{"", c.language} {
			if got := assignmentFindings(t, c.text+"\n", language); len(got) == 0 {
				t.Errorf("%s (langage %q) : aucun constat d'affectation", c.name, language)
			}
		}
	}
}

// TestReferenceAt : grammaire des références.
func TestReferenceAt(t *testing.T) {
	for text, want := range map[string]int{
		"$NAME rest":                   5,
		"$1":                           2,
		"$@":                           2,
		"${NAME}":                      7,
		"${#NAME}":                     8,
		"${NAME:?required value}":      23,
		"${NAME:-}":                    9,
		"${NAME:-$OTHER}":              15,
		"${NAME:-${OTHER}}":            17,
		"${NAME[0]}":                   10,
		"$(cat \"$HOME/file\") rest":   19,
		"`cat file`":                   10,
		"${{ steps.x.outputs.value }}": 28,
		"{{ .Values.x | quote }}":      23,
		"#{ENV['X']}":                  11,
		"%{name}":                      7,
		"%s":                           2,
		// Refusées.
		"${NAME:-literal}": 0,
		"${NAME:+literal}": 0,
		"${}":              0,
		"$":                0,
		"$ NAME":           0,
		"%sure":            0,
		"{{ }}":            0,
		"{{ x | default(\"" + literalStrong + "\") }}": 0,
		"$(echo '" + literalStrong + "')":              0,
		"plain":                                        0,
	} {
		v := identityView([]byte(text))
		ref, ok := referenceAt(v, 0, len(text), "access_token")
		if (want == 0) == ok || ref.end != want {
			t.Errorf("%q : fin %d (%v), attendu %d", text, ref.end, ok, want)
		}
	}
}

// TestSecretShapes : formes de valeur des deux paliers.
func TestSecretShapes(t *testing.T) {
	for value, want := range map[string][2]bool{
		// {secretShaped, strictShaped}
		literalStrong:                      {true, true},
		"test-key":                         {false, false},
		"bearer":                           {false, false},
		"provider.key":                     {false, false},
		"X-Request-Id":                     {true, false},
		"defaults.keys":                    {false, false},
		"2026-01-01":                       {false, false},
		"abcdefghij12":                     {true, false},
		"E2E_PUBLISH_NAME":                 {true, false},
		"2026-10-12T10:00:00.000Z":         {true, false},
		"2026-10-12Txy7":                   {true, true},
		"correct horse battery staple 1":   {false, false},
		"https://vault.example.test/v1":    {true, false},
		"0f1e2d3c4b5a69788796a5b4c3d2e1f0": {true, true},
	} {
		v := identityView([]byte(value))
		if got := secretShaped(v, 0, len(value)); got != want[0] {
			t.Errorf("secretShaped(%q) = %v", value, got)
		}
		if got := strictShaped(v, 0, len(value)); got != want[1] {
			t.Errorf("strictShaped(%q) = %v", value, got)
		}
	}
}

// TestCodeNoiseWorstCases : les filtres relisent un nombre borné d'octets par vue (spend) : structures imbriquées,
// références ouvertes et lignes longues finissent dans la borne de temps des pires cas.
func TestCodeNoiseWorstCases(t *testing.T) {
	rules := loadInitialRules(t)
	for name, content := range map[string][]byte{
		"tableaux imbriqués sur une ligne":   ruleFill("a_" + nameToken + ": ["),
		"objets imbriqués sur une ligne":     ruleFill(nameSecret + ": {"),
		"appels imbriqués sur une ligne":     ruleFill(nameToken + ": f("),
		"tableaux ouverts ligne après ligne": ruleFill(nameToken + ": [\n"),
		"substitutions ouvertes":             ruleFill(nameToken + "=$("),
		"gabarits ouverts":                   ruleFill(nameToken + ": {{ "),
		"expansions ouvertes":                ruleFill(nameToken + "=${A:-"),
		"chaînes à références":               ruleFill(nameToken + "=\"$A$B\" "),
		"affectations enchaînées sans fin":   ruleFill(nameToken + " = "),
		"clés de section":                    ruleFill(nameToken + ":\n"),
	} {
		t.Run(name, func(t *testing.T) {
			v := identityView(content)
			for _, lang := range []language{{}, {id: "typescript", set: true}} {
				start := time.Now()
				for i := range assignmentPatterns {
					rules.scanAssignmentPattern(v, newContextualText(v.text), &assignmentPatterns[i], lang, nil)
				}
				if elapsed := time.Since(start); elapsed > worstCaseTimeLimit {
					t.Fatalf("%v pour %d octets (langage %q)", elapsed, len(content), lang.id)
				}
			}
		})
	}
}

// TestCodeValueWithoutSecretShape : palier 2. Dans du code (langage de code déclaré, ou ligne à mot-clé de
// déclaration), une valeur dont aucun mot n'a la forme d'un secret n'est ni une clé d'API, ni un jeton, ni un secret
// générique.
func TestCodeValueWithoutSecretShape(t *testing.T) {
	cases := []noiseCase{
		{"valeur d'essai courte", `  ` + nameAPIKey + `: "test",`, "typescript"},
		{"valeur d'essai en mots", `    ` + strings.ToLower(nameAPIKey) + ` = 'test-key'`, "python"},
		{"littéral de type", `  ` + nameToken + `: "bearer" as const,`, "typescript"},
		{"union de littéraux", `type Kind = { ` + nameToken + `: "access" | "refresh" };`, ""},
		{"constante", `    intake = await start({ port: 0, ` + nameSecret + `: SHARED, sink: queue });`, "typescript"},
		{"autre variable", `    ` + nameToken + ` = next_page_cursor`, "python"},
		{"type nu", `  client` + strings.ToUpper(nameSecret[:1]) + nameSecret[1:] + `: Buffer,`, "typescript"},
		{"libellé", `const ` + nameToken + ` = "jeton d'enrôlement absent";`, ""},
		{"déclaration à valeur d'essai", `const ` + nameAPIKey + ` = "test-key";`, ""},
		{"retour d'une valeur d'essai", `  return { ` + nameToken + `: "fixture" };`, ""},
	}
	for _, c := range cases {
		if got := assignmentFindings(t, c.text+"\n", c.language); len(got) != 0 {
			t.Errorf("%s (langage %q) : %d constat(s), règle %s", c.name, c.language, len(got), got[0].RuleID)
		}
	}
}

// TestCodeValueGuards : garde-fous du palier 2. Chaque cas garde son constat.
func TestCodeValueGuards(t *testing.T) {
	upperKey := "API_" + "KEY"
	cases := []noiseCase{
		{"sans langage ni mot-clé", `  ` + nameAPIKey + `: "test",`, ""},
		{"YAML", nameToken + `: fixture`, "yaml"},
		{"JSON", `{"` + nameToken + `": "fixture"}`, "json"},
		{"script shell", nameToken + `=fixture`, "shellscript"},
		{"fichier dotenv", upperKey + `=fixture`, "dotenv"},
		{"affectation nue d'environnement dans du code", upperKey + ` = "test-key"`, "python"},
		{"affectation nue d'environnement sans langage", `export ` + upperKey + `=fixture`, ""},
		{"mot de passe", `  ` + namePassword + `: "test",`, "typescript"},
		{"mot de passe déclaré", `const ` + namePassword + ` = "fixture";`, ""},
		{"valeur à forme de secret", `  ` + nameAPIKey + `: "` + literalStrong + `",`, "typescript"},
		{"valeur à forme de secret déclarée", `const ` + nameToken + ` = "` + literalStrong + `";`, ""},
		{"lettres et deux chiffres sur dix caractères", `  ` + nameAPIKey + `: "fixturekey42",`, "typescript"},
		{"chaîne prolongée par une concaténation", `const ` + nameToken + ` = "gh" + stored;`, "typescript"},
	}
	for _, c := range cases {
		if got := assignmentFindings(t, c.text+"\n", c.language); len(got) == 0 {
			t.Errorf("%s (langage %q) : aucun constat d'affectation", c.name, c.language)
		}
	}
}

// splitmix est un générateur déterministe (SplitMix64) : les chiffres de TestSecretShapeThreshold, repris dans
// docs/bench.md, se rejouent à l'identique.
type splitmix uint64

func (s *splitmix) next() uint64 {
	*s += 0x9E3779B97F4A7C15
	z := uint64(*s)
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

func (s *splitmix) token(alphabet string, length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = alphabet[s.next()%uint64(len(alphabet))]
	}
	return out
}

// TestSecretShapeThreshold : seuil du palier 2 (secretShaped). Part des suites aléatoires qui gardent la forme d'un
// secret, par alphabet et par longueur, sur 20 000 tirages déterministes ; le journal de l'essai (-v) est la table de
// docs/bench.md. À 16 caractères et plus, au moins 990 suites sur 1 000 la gardent, quel que soit l'alphabet. Perte
// acceptée, dans du code seulement : les suites plus courtes sans chiffre, et les lettres d'une seule casse sous
// 16 caractères, qu'on ne distingue pas d'un mot.
func TestSecretShapeThreshold(t *testing.T) {
	const samples = 20_000
	const lower, upper, digits = "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789"
	alphabets := []struct {
		name, letters string
		// floor : part minimale, en pour mille, à 16 caractères et plus.
		floor int
	}{
		{"hexadécimal", "0123456789abcdef", 990},
		{"base32", upper + "234567", 990},
		{"minuscules et chiffres", lower + digits, 990},
		{"base62", lower + upper + digits, 990},
		{"base64url", lower + upper + digits + "-_", 990},
		{"minuscules seules", lower, 990},
	}
	generator := splitmix(46)
	for _, alphabet := range alphabets {
		for _, length := range []int{8, 12, 16, 20, 24, 32, 40} {
			shaped := 0
			for i := 0; i < samples; i++ {
				value := generator.token(alphabet.letters, length)
				if secretShaped(identityView(value), 0, len(value)) {
					shaped++
				}
			}
			perMille := shaped * 1000 / samples
			t.Logf("%-24s %2d caractères : %5d sur %d (%d ‰)", alphabet.name, length, shaped, samples, perMille)
			if length >= 16 && perMille < alphabet.floor {
				t.Errorf("%s, %d caractères : %d ‰ des suites aléatoires ont la forme d'un secret, moins de %d ‰", alphabet.name, length, perMille, alphabet.floor)
			}
		}
	}
}

// TestSecretShapeCoversProviderTokens : chaque étendue détectée par une règle de fournisseur du corpus (jeton à
// préfixe, forme fixe) porte un mot à forme de secret au sens du palier 2 : écrite dans du code sous un nom sensible,
// elle garde aussi son constat d'affectation.
func TestSecretShapeCoversProviderTokens(t *testing.T) {
	values, shaped := 0, 0
	for _, c := range loadCorpusFile(t, providerRulesCorpusFile) {
		input := c.bytes(t)
		for _, f := range c.Expected.Findings {
			if f.ByteEnd > len(input) || f.Encoding != EncodingPlain {
				continue
			}
			values++
			if hasSecretWord(identityView(input), f.ByteStart, f.ByteEnd) {
				shaped++
			}
		}
	}
	t.Logf("%d valeurs de fournisseurs du corpus, %d à forme de secret", values, shaped)
	if values < 250 || shaped != values {
		t.Fatalf("%d valeurs sur %d ont la forme d'un secret", shaped, values)
	}
}

// basicAuthFindings rend les constats de la règle cli_basic_auth de l'analyse de text.
func basicAuthFindings(t *testing.T, text string) []Finding {
	t.Helper()
	result := Scan([]byte(text), loadInitialRules(t), Options{})
	if !result.Complete {
		t.Fatalf("analyse incomplète : %v", result.Failure)
	}
	var out []Finding
	for _, f := range result.Findings {
		if f.RuleID == ruleCLIBasicAuth {
			out = append(out, f)
		}
	}
	return out
}

// Options d'utilisateur et arguments, assemblés par morceaux (voir namePassword).
var (
	optionUser     = " -" + "u "
	optionLongUser = " --" + "user"
	pair           = func(user, secret string) string { return user + ":" + secret }
)

// TestBasicAuthIgnoresDatesAndNumericIDs : l'option d'utilisateur suivie d'un format de date ou de deux nombres n'est
// pas un couple utilisateur et mot de passe (commandes date et docker run bloquées sur un Poste réel).
func TestBasicAuthIgnoresDatesAndNumericIDs(t *testing.T) {
	clock := "+%H" + ":%M" + ":%S"
	iso := "+%Y-%m-%dT%H" + ":%M" + ":%SZ"
	for name, text := range map[string]string{
		"date en temps universel, format d'heure":      "date" + optionUser + clock,
		"date en temps universel, format ISO":          "date" + optionUser + iso,
		"date entre guillemets":                        `stamp="$(date` + optionUser + `"` + iso + `")"`,
		"docker run, utilisateur et groupe numériques": "docker run --rm" + optionUser + pair("1000", "1000") + " alpine id",
		"docker run, option longue":                    "docker run --rm" + optionLongUser + " " + pair("501", "20") + " alpine id",
		"docker run, option longue avec signe égal":    "docker run" + optionLongUser + "=" + pair("0", "0") + " alpine id",
	} {
		if got := basicAuthFindings(t, text+"\n"); len(got) != 0 {
			t.Errorf("%s : %d constat(s) %s", name, len(got), ruleCLIBasicAuth)
		}
	}
}

// TestBasicAuthKeepsCredentials : un couple utilisateur et mot de passe reste signalé, y compris quand l'un des deux
// est un nombre ou porte un signe de pourcentage.
func TestBasicAuthKeepsCredentials(t *testing.T) {
	user := "admin"
	url := " https://api.example.test/"
	for name, text := range map[string]string{
		"curl":                                 "curl" + optionUser + pair(user, literalStrong) + url,
		"curl entre guillemets":                "curl" + optionUser + `"` + pair(user, literalStrong) + `"` + url,
		"option longue":                        "curl" + optionLongUser + " " + pair(user, literalStrong) + url,
		"utilisateur numérique":                "curl" + optionUser + pair("1000", literalStrong) + url,
		"mot de passe numérique":               "curl" + optionUser + pair(user, "2026"+"1115") + url,
		"utilisateur à signe plus sans format": "curl" + optionUser + pair("+"+user, literalStrong) + url,
		"mot de passe à pourcentage":           "curl" + optionUser + pair(user, "+%"+literalStrong) + url,
		"sans commande":                        strings.TrimPrefix(optionUser, " ") + pair(user, literalStrong),
	} {
		if got := basicAuthFindings(t, text+"\n"); len(got) != 1 {
			t.Errorf("%s : %d constat(s) %s, attendu 1", name, len(got), ruleCLIBasicAuth)
		}
	}
}
