package custom

// API publique du paquet en liste fermée : aucun type, champ ni fonction exportés ne rend un texte détecté, un terme
// ou un condensat non salé. Relevé par l'arbre syntaxique (fichiers hors tests) et par réflexion.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

var allowedCustomTypes = map[string][]string{
	"PatternErrorCode": nil,
	"PatternError":     {"Code"},
	"PackErrorCode":    nil,
	"PackError":        {"Code"},
	"Detector":         {"ID", "Label", "Category", "Action"},
	"Pack":             {},
	"Meter":            {},
	"Match":            {"Detector", "ByteStart", "ByteEnd"},
}

// textResults : fonctions exportées qui rendent du texte, toutes sans texte analysé : messages d'erreur, identité du
// Pack, forme normalisée et condensat salé d'un terme donné par l'appelant (outil de l'émetteur et du client).
var textResults = map[string]bool{
	"Error": true, "PackID": true, "TenantID": true, "IssuedAt": true, "ExpiresAt": true, "Issuer": true,
	"NormalizeTerm": true, "TermDigest": true, "DigestTerm": true,
}

func TestCustomPublicAPI(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]bool{}
	var funcs, vars []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.TypeSpec:
						if sp.Name.IsExported() {
							types[sp.Name.Name] = true
						}
					case *ast.ValueSpec:
						for _, n := range sp.Names {
							if n.IsExported() && d.Tok == token.VAR {
								vars = append(vars, n.Name)
							}
						}
					}
				}
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				funcs = append(funcs, d.Name.Name)
				if d.Type.Results == nil {
					continue
				}
				for _, result := range d.Type.Results.List {
					switch r := result.Type.(type) {
					case *ast.ArrayType:
						elem, _ := r.Elt.(*ast.Ident)
						allowed := elem != nil && (elem.Name == "Match" || elem.Name == "Detector" || elem.Name == "PatternErrorCode" ||
							elem.Name == "PackErrorCode" || (elem.Name == "string" && d.Name.Name == "Categories") ||
							(elem.Name == "byte" && d.Name.Name == "DecodeSalt"))
						if !allowed {
							t.Errorf("%s : rend une tranche non contrôlée", d.Name.Name)
						}
					case *ast.Ident:
						if r.Name == "string" && !textResults[d.Name.Name] {
							t.Errorf("%s : rend du texte", d.Name.Name)
						}
						if r.Name == "any" || r.Name == "byte" {
							t.Errorf("%s : rend %s", d.Name.Name, r.Name)
						}
					case *ast.InterfaceType, *ast.FuncType, *ast.ChanType, *ast.MapType:
						t.Errorf("%s : rend un type non contrôlé", d.Name.Name)
					}
				}
			}
		}
	}
	for name := range types {
		if _, ok := allowedCustomTypes[name]; !ok {
			t.Errorf("type exporté hors de la liste fermée : %s", name)
		}
	}
	if len(types) != len(allowedCustomTypes) {
		t.Errorf("%d types exportés, %d attendus", len(types), len(allowedCustomTypes))
	}
	slices.Sort(vars)
	if want := []string{"ErrInvalidPack", "ErrInvalidPattern", "ErrInvalidSalt", "ErrTooManyMatches", "ErrWorkBudget"}; !slices.Equal(vars, want) {
		t.Errorf("variables exportées %v, attendu %v", vars, want)
	}
	slices.Sort(funcs)
	if want := []string{
		"Analyze", "Categories", "Compile", "DecodeSalt", "Detectors", "DigestTerm", "Error", "Error", "ExpiresAt",
		"IssuedAt", "Issuer", "NewMeter", "NormalizeTerm", "PackErrorCodes", "PackID", "PatternErrorCodes", "TenantID",
		"TermDigest", "Unwrap", "Unwrap", "Used", "ValidatePattern", "Version",
	}; !slices.Equal(funcs, want) {
		t.Errorf("fonctions exportées %v, attendu %v", funcs, want)
	}
	for _, typ := range []reflect.Type{
		reflect.TypeFor[PatternError](), reflect.TypeFor[PackError](), reflect.TypeFor[Detector](), reflect.TypeFor[Pack](),
		reflect.TypeFor[Meter](), reflect.TypeFor[Match](),
	} {
		var exported []string
		for i := range typ.NumField() {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			exported = append(exported, field.Name)
			if kind := field.Type.Kind(); kind != reflect.String && kind != reflect.Int {
				t.Errorf("%s.%s : genre %s", typ.Name(), field.Name, kind)
			}
		}
		if want := allowedCustomTypes[typ.Name()]; !slices.Equal(exported, want) {
			t.Errorf("%s : champs %v, attendu %v", typ.Name(), exported, want)
		}
	}
}
