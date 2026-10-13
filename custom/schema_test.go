package custom

// La copie du schéma (schema/CustomPack.json) et le décodage strict de ce paquet disent la même chose : mêmes
// formes, mêmes listes fermées, mêmes bornes. Le contenu de la copie est celui de l'origine (seuls le titre et la
// description changent : test du générateur custom-vectors).

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestCustomSchemaCopy(t *testing.T) {
	data, err := os.ReadFile("../schema/CustomPack.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	at := func(path ...string) any {
		var node any = schema
		for _, key := range path {
			object, ok := node.(map[string]any)
			if !ok {
				t.Fatalf("chemin %v absent", path)
			}
			node = object[key]
		}
		return node
	}
	props := func(path ...string) []string { return append(path, "properties") }
	checks := []struct {
		path []string
		want any
	}{
		{append(props(), "schemaVersion", "const"), 1.0},
		{append(props(), "kind", "const"), payloadKind},
		{append(props(), "packId", "pattern"), identifierForm.String()},
		{append(props(), "tenantId", "maxLength"), 128.0},
		{append(props(), "version", "maximum"), float64(maxVersion)},
		{append(props(), "issuedAt", "pattern"), `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`},
		{append(props(), "issuer", "maxLength"), 80.0},
		{append(props(), "detectors", "maxItems"), 200.0},
		{append(props("properties", "tests"), "positives", "maxItems"), 200.0},
		{append(props("properties", "tests"), "negatives", "maxItems"), 200.0},
		{append(props("properties", "tests"), "negatives", "items", "maxLength"), 2000.0},
		{[]string{"$defs", "detectorId", "pattern"}, identifierForm.String()},
		{append(props("$defs", "detector"), "label", "maxLength"), 80.0},
		{append(props("$defs", "detector"), "action", "enum"), []any{ActionWarn, ActionBlock}},
		{append(props("$defs", "detector", "properties", "context"), "keywords", "maxItems"), 20.0},
		{append(props("$defs", "detector", "properties", "context"), "keywords", "items", "pattern"), keywordForm.String()},
		{append(props("$defs", "detector", "properties", "context"), "window", "maximum"), 256.0},
		{append(props("$defs", "patternMatch"), "pattern", "maxLength"), float64(maxPatternLength)},
		{append(props("$defs", "patternMatch"), "minEntropyTenths", "maximum"), 80.0},
		{append(props("$defs", "termsMatch"), "salt", "pattern"), saltForm.String()},
		{append(props("$defs", "termsMatch"), "digests", "maxItems"), 5000.0},
		{append(props("$defs", "termsMatch"), "digests", "items", "pattern"), digestForm.String()},
		{append(props("$defs", "termsMatch"), "maxWords", "maximum"), 4.0},
	}
	for _, c := range checks {
		if got := at(c.path...); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%v : %v, attendu %v", c.path, got, c.want)
		}
	}
	// Horodatage : \d du schéma (ASCII en JSON Schema sans drapeau u) est [0-9] dans le décodage.
	if timestampForm.String() != `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$` {
		t.Error("forme d'horodatage")
	}
	categories := at(append(props("$defs", "detector"), "category", "enum")...).([]any)
	if len(categories) != len(Categories()) {
		t.Fatal("catégories")
	}
	for i, c := range Categories() {
		if categories[i] != c {
			t.Errorf("catégorie %d : %v", i, categories[i])
		}
	}
}
