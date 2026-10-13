package pack

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/internal/limits"
)

// validRule et validPack écrivent un Pack minimal conforme ; chaque cas de refus en modifie un seul élément.
const validRule = `{"ruleId":"demo_rule","family":"fixed_pattern","secretType":"api_key","score":80,"validator":"","pattern":"\\bdemo_[a-z]{8}\\b","minLength":0,"maxLength":0}`

func validPack(rule string) string {
	return `{"schemaVersion":1,"minAgentVersion":"0.1.0","packVersion":7,"issuedAt":"2026-10-07T00:00:00Z","rules":[` + rule + `]}`
}

func TestInitialPack(t *testing.T) {
	t.Run("le Pack initial embarqué se décode strictement : 35 règles, version 1", func(t *testing.T) {
		p, err := Initial()
		if err != nil {
			t.Fatal(err)
		}
		if p.SchemaVersion != 1 || p.PackVersion != 1 || len(p.Rules) != 35 {
			t.Fatalf("schéma %d, version %d, %d règles", p.SchemaVersion, p.PackVersion, len(p.Rules))
		}
	})
	t.Run("InitialJSON rend une copie : la modifier ne change pas le Pack embarqué", func(t *testing.T) {
		data := InitialJSON()
		data[0] = 'x'
		if _, err := Initial(); err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(data, InitialJSON()) {
			t.Fatal("copie partagée")
		}
	})
	t.Run("le fichier embarqué est initial/pack.json, octet pour octet", func(t *testing.T) {
		data, err := os.ReadFile("initial/pack.json")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, InitialJSON()) {
			t.Fatal("Pack embarqué différent du fichier")
		}
	})
	t.Run("le même Pack écrit dans l'ordre canonique des clés (ordre de signature) se décode à l'identique", func(t *testing.T) {
		var value any
		if err := json.Unmarshal(InitialJSON(), &value); err != nil {
			t.Fatal(err)
		}
		canonical, err := json.Marshal(value) // encoding/json trie les clés des objets.
		if err != nil {
			t.Fatal(err)
		}
		p, err := Decode(canonical)
		if err != nil {
			t.Fatal(err)
		}
		initial, _ := Initial()
		if !reflect.DeepEqual(p, initial) {
			t.Fatal("décodages différents")
		}
	})
	t.Run("un Pack réécrit par encoding/json se relit à l'identique", func(t *testing.T) {
		initial, _ := Initial()
		data, err := json.Marshal(initial)
		if err != nil {
			t.Fatal(err)
		}
		again, err := Decode(data)
		if err != nil || !reflect.DeepEqual(again, initial) {
			t.Fatalf("relecture : %v", err)
		}
	})
}

func TestDecodeStrict(t *testing.T) {
	if _, err := Decode([]byte(validPack(validRule))); err != nil {
		t.Fatalf("Pack minimal refusé : %v", err)
	}
	rule := func(old, replacement string) string {
		if !strings.Contains(validRule, old) {
			t.Fatalf("%q absent de la règle", old)
		}
		return validPack(strings.Replace(validRule, old, replacement, 1))
	}
	top := func(old, replacement string) string {
		document := validPack(validRule)
		if !strings.Contains(document, old) {
			t.Fatalf("%q absent du Pack", old)
		}
		return strings.Replace(document, old, replacement, 1)
	}
	cases := []struct {
		name, document, path string
	}{
		{"membre inconnu à la racine", top(`"schemaVersion":1,`, `"schemaVersion":1,"extra":1,`), ""},
		{"membre inconnu dans une règle", rule(`"score":80,`, `"score":80,"capture":1,`), "/rules/0"},
		{"nom de membre d'une autre casse", rule(`"ruleId"`, `"RuleId"`), "/rules/0"},
		{"membre inconnu dont le nom contient « / »", rule(`"score":80,`, `"score":80,"a/b":1,`), "/rules/0"},
		{"membre en double", rule(`"score":80,`, `"score":80,"score":81,`), "/rules/0"},
		{"champ absent", rule(`"validator":"",`, ``), "/rules/0/validator"},
		{"champ null", rule(`"pattern":"\\bdemo_[a-z]{8}\\b"`, `"pattern":null`), "/rules/0/pattern"},
		{"racine null", "null", "/schemaVersion"},
		{"règle null", validPack("null"), "/rules/0"},
		{"rules null", top(`"rules":[`+validRule+`]`, `"rules":null`), "/rules"},
		{"type différent", rule(`"score":80`, `"score":"80"`), "/rules/0/score"},
		{"nombre non entier", rule(`"score":80`, `"score":80.0`), "/rules/0/score"},
		{"nombre en notation exponentielle", rule(`"score":80`, `"score":8e1`), "/rules/0/score"},
		{"score au-delà de 100", rule(`"score":80`, `"score":101`), "/rules/0/score"},
		{"score négatif", rule(`"score":80`, `"score":-1`), "/rules/0/score"},
		{"famille inconnue", rule(`"fixed_pattern"`, `"magic"`), "/rules/0/family"},
		{"type de secret inconnu", rule(`"api_key"`, `"magic"`), "/rules/0/secretType"},
		{"identifiant hors forme", rule(`"demo_rule"`, `"Demo-Rule"`), "/rules/0/ruleId"},
		{"identifiant de 65 caractères", rule(`"demo_rule"`, `"`+strings.Repeat("a", 65)+`"`), "/rules/0/ruleId"},
		{"validateur hors forme", rule(`"validator":""`, `"validator":"JWT"`), "/rules/0/validator"},
		{"motif de 4 097 unités UTF-16", rule(`"\\bdemo_[a-z]{8}\\b"`, `"`+strings.Repeat("a", 4097)+`"`), "/rules/0/pattern"},
		{"motif de 2 049 points de code hors du plan de base (4 098 unités)", rule(`"\\bdemo_[a-z]{8}\\b"`, `"`+strings.Repeat("😀", 2049)+`"`), "/rules/0/pattern"},
		{"borne négative", rule(`"minLength":0`, `"minLength":-1`), "/rules/0/minLength"},
		{"borne au-delà de 1 Mio", rule(`"maxLength":0`, `"maxLength":1048577`), "/rules/0/maxLength"},
		{"schemaVersion 0", top(`"schemaVersion":1`, `"schemaVersion":0`), "/schemaVersion"},
		{"schemaVersion au-delà de 1 000 000", top(`"schemaVersion":1`, `"schemaVersion":1000001`), "/schemaVersion"},
		{"packVersion 0", top(`"packVersion":7`, `"packVersion":0`), "/packVersion"},
		{"packVersion au-delà de 2^53 − 1", top(`"packVersion":7`, `"packVersion":9007199254740992`), "/packVersion"},
		{"minAgentVersion avec pré-version", top(`"0.1.0"`, `"0.1.0-rc.1"`), "/minAgentVersion"},
		{"minAgentVersion à zéro de tête", top(`"0.1.0"`, `"0.01.0"`), "/minAgentVersion"},
		{"issuedAt hors forme", top(`"2026-10-07T00:00:00Z"`, `"2026-10-07 00:00:00Z"`), "/issuedAt"},
		{"issuedAt du 30 février", top(`"2026-10-07T00:00:00Z"`, `"2026-02-30T00:00:00Z"`), "/issuedAt"},
		{"issuedAt du 29 février d'une année non bissextile", top(`"2026-10-07T00:00:00Z"`, `"2100-02-29T00:00:00Z"`), "/issuedAt"},
		{"issuedAt à 24 h", top(`"2026-10-07T00:00:00Z"`, `"2026-10-07T24:00:00Z"`), "/issuedAt"},
		{"aucune règle", top(`[`+validRule+`]`, `[]`), "/rules"},
		{"contenu après le document", validPack(validRule) + ` {}`, ""},
		{"UTF-8 invalide", rule(`"demo_rule"`, "\"demo_\xff\""), "/rules/0/ruleId"},
		{"substitut isolé", rule(`"\\bdemo_[a-z]{8}\\b"`, `"\ud800"`), "/rules/0/pattern"},
		{"tableau à la racine", "[]", ""},
		{"document vide", "", ""},
	}
	for _, c := range cases {
		t.Run("refusé : "+c.name, func(t *testing.T) {
			p, err := Decode([]byte(c.document))
			if p != nil || !errors.Is(err, ErrInvalidPack) {
				t.Fatalf("accepté : %v", err)
			}
			var refusal *DecodeError
			if !errors.As(err, &refusal) {
				t.Fatalf("erreur non typée : %v", err)
			}
			if c.path != "" && refusal.Path != c.path {
				t.Fatalf("chemin %q, attendu %q (%v)", refusal.Path, c.path, err)
			}
			for _, quoted := range []string{"demo_", "magic", "Demo-Rule", "JWT", "0.1.0-rc.1", "2026-02-30", "aaaa"} {
				if strings.Contains(c.document, quoted) && strings.Contains(err.Error(), quoted) {
					t.Fatalf("le message cite le document : %q", err)
				}
			}
		})
	}
	t.Run("refusé : document au-delà de MaxPackBytes, avant toute lecture", func(t *testing.T) {
		big := append([]byte(validPack(validRule)), bytes.Repeat([]byte(" "), limits.MaxPackBytes)...)
		if _, err := Decode(big); !errors.Is(err, ErrInvalidPack) {
			t.Fatalf("accepté : %v", err)
		}
	})
	t.Run("admis : 29 février d'une année bissextile, millisecondes, bornes extrêmes", func(t *testing.T) {
		document := strings.NewReplacer(
			`"2026-10-07T00:00:00Z"`, `"2024-02-29T23:59:59.999Z"`,
			`"packVersion":7`, `"packVersion":9007199254740991`,
			`"schemaVersion":1`, `"schemaVersion":1000000`,
		).Replace(validPack(strings.NewReplacer(`"maxLength":0`, `"maxLength":1048576`, `"score":80`, `"score":100`).Replace(validRule)))
		p, err := Decode([]byte(document))
		if err != nil {
			t.Fatal(err)
		}
		if p.PackVersion != limits.MaxPackVersion || p.Rules[0].MaxLength != limits.MaxLengthBound || p.Rules[0].Score != 100 {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("admis : motif vide, validateur nommé, membres dans un autre ordre, espaces", func(t *testing.T) {
		document := "{\n \"rules\" : [ {\"maxLength\":0,\"minLength\":0,\"pattern\":\"\",\"validator\":\"jwt_structure\",\"score\":0,\"secretType\":\"jwt\",\"family\":\"contextual_assignment\",\"ruleId\":\"r\"} ],\n \"issuedAt\":\"2026-10-07T00:00:00.000Z\", \"packVersion\":1, \"minAgentVersion\":\"10.20.30\", \"schemaVersion\":1 }\n"
		p, err := Decode([]byte(document))
		if err != nil {
			t.Fatal(err)
		}
		want := Rule{RuleID: "r", Family: FamilyContextualAssignment, SecretType: SecretTypeJWT, Validator: "jwt_structure"}
		if !reflect.DeepEqual(p.Rules, []Rule{want}) {
			t.Fatalf("%+v", p.Rules)
		}
	})
}

// schemaFile est la copie du schéma RulePack du contrat signé (schema/RulePack.json).
const schemaFile = "../schema/RulePack.json"

type schemaProperty struct {
	Type      string        `json:"type"`
	Enum      []string      `json:"enum"`
	Pattern   string        `json:"pattern"`
	MaxLength *int64        `json:"maxLength"`
	Minimum   *int64        `json:"minimum"`
	Maximum   *int64        `json:"maximum"`
	MinItems  *int64        `json:"minItems"`
	MaxItems  *int64        `json:"maxItems"`
	Items     *schemaObject `json:"items"`
}

type schemaObject struct {
	AdditionalProperties *bool                     `json:"additionalProperties"`
	Properties           map[string]schemaProperty `json:"properties"`
	Required             []string                  `json:"required"`
	Type                 string                    `json:"type"`
}

func jsonNames(typ reflect.Type) []string {
	var names []string
	for i := range typ.NumField() {
		names = append(names, typ.Field(i).Tag.Get("json"))
	}
	slices.Sort(names)
	return names
}

func keys(m map[string]schemaProperty) []string {
	var names []string
	for name := range m {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func TestSchemaCopy(t *testing.T) {
	data, err := os.ReadFile(schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	var root schemaObject
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&root); err != nil {
		t.Fatal(err)
	}
	if root.Items() == nil {
		t.Fatal("schéma sans règles")
	}
	t.Run("le type Pack a exactement les champs du schéma RulePack, tous obligatoires, objet fermé", func(t *testing.T) {
		checkObject(t, "Pack", reflect.TypeFor[Pack](), root.Type, root.AdditionalProperties, root.Properties, root.Required)
		items := root.Items()
		checkObject(t, "Rule", reflect.TypeFor[Rule](), items.Type, items.AdditionalProperties, items.Properties, items.Required)
	})
	t.Run("énumérations, motifs et bornes du schéma sont ceux du décodage", func(t *testing.T) {
		rules := root.Properties["rules"]
		item := root.Items().Properties
		checkEnum(t, "family", item["family"].Enum, Families())
		checkEnum(t, "secretType", item["secretType"].Enum, SecretTypes())
		for _, c := range []struct {
			name string
			got  string
			want string
		}{
			{"ruleId", item["ruleId"].Pattern, identifierPattern},
			{"validator", item["validator"].Pattern, validatorPattern},
			{"minAgentVersion", root.Properties["minAgentVersion"].Pattern, semVerPattern},
			{"issuedAt", root.Properties["issuedAt"].Pattern, timestampPattern},
		} {
			if c.got != c.want {
				t.Errorf("%s : motif du schéma %q, décodage %q", c.name, c.got, c.want)
			}
		}
		for _, c := range []struct {
			name string
			got  *int64
			want int64
		}{
			{"ruleId.maxLength", item["ruleId"].MaxLength, limits.MaxIdentifierLength},
			{"validator.maxLength", item["validator"].MaxLength, limits.MaxIdentifierLength},
			{"pattern.maxLength", item["pattern"].MaxLength, limits.MaxPatternUnits},
			{"score.minimum", item["score"].Minimum, 0},
			{"score.maximum", item["score"].Maximum, limits.MaxScore},
			{"minLength.minimum", item["minLength"].Minimum, 0},
			{"minLength.maximum", item["minLength"].Maximum, limits.MaxLengthBound},
			{"maxLength.minimum", item["maxLength"].Minimum, 0},
			{"maxLength.maximum", item["maxLength"].Maximum, limits.MaxLengthBound},
			{"rules.minItems", rules.MinItems, 1},
			{"rules.maxItems", rules.MaxItems, limits.MaxRules},
			{"schemaVersion.minimum", root.Properties["schemaVersion"].Minimum, 1},
			{"schemaVersion.maximum", root.Properties["schemaVersion"].Maximum, limits.MaxSchemaVersion},
			{"packVersion.minimum", root.Properties["packVersion"].Minimum, 1},
			{"packVersion.maximum", root.Properties["packVersion"].Maximum, limits.MaxPackVersion},
		} {
			if c.got == nil || *c.got != c.want {
				t.Errorf("%s : schéma %v, décodage %d", c.name, c.got, c.want)
			}
		}
		for name, property := range item {
			kind := map[string]string{"score": "integer", "minLength": "integer", "maxLength": "integer"}[name]
			if kind == "" {
				kind = "string"
			}
			if property.Type != kind {
				t.Errorf("rules.%s : type %q", name, property.Type)
			}
		}
	})
}

// Items rend le schéma d'une règle.
func (o schemaObject) Items() *schemaObject { return o.Properties["rules"].Items }

func checkObject(t *testing.T, name string, typ reflect.Type, kind string, additional *bool, properties map[string]schemaProperty, required []string) {
	t.Helper()
	if kind != "object" || additional == nil || *additional {
		t.Errorf("%s : objet non fermé dans le schéma", name)
	}
	if got, want := jsonNames(typ), keys(properties); !slices.Equal(got, want) {
		t.Errorf("%s : champs %v, schéma %v", name, got, want)
	}
	sortedRequired := slices.Clone(required)
	slices.Sort(sortedRequired)
	if !slices.Equal(sortedRequired, keys(properties)) {
		t.Errorf("%s : obligatoires %v, propriétés %v", name, sortedRequired, keys(properties))
	}
}

func checkEnum[T ~string](t *testing.T, name string, schema []string, values []T) {
	t.Helper()
	var got []string
	for _, v := range values {
		got = append(got, string(v))
	}
	if !slices.Equal(schema, got) {
		t.Errorf("%s : schéma %v, paquet %v", name, schema, got)
	}
}

// FuzzDecode : Decode ne panique jamais ; un Pack admis se réécrit et se relit à l'identique, et ses valeurs
// respectent les bornes du schéma.
// go test ./pack -run '^$' -fuzz '^FuzzDecode$' -fuzztime=30s
func FuzzDecode(f *testing.F) {
	f.Add(InitialJSON())
	f.Add([]byte(validPack(validRule)))
	f.Add([]byte(`{"schemaVersion":1,"rules":[null]}`))
	f.Add([]byte("{\"a\":\"\xff\"}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Decode(data)
		if err != nil {
			if p != nil || !errors.Is(err, ErrInvalidPack) {
				t.Fatalf("refus mal formé : %v", err)
			}
			return
		}
		if len(p.Rules) < 1 || len(p.Rules) > limits.MaxRules || p.PackVersion < 1 || p.PackVersion > limits.MaxPackVersion {
			t.Fatalf("bornes : %+v", p)
		}
		again, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		reread, err := Decode(again)
		if err != nil || !reflect.DeepEqual(reread, p) {
			t.Fatalf("relecture : %v", err)
		}
	})
}
