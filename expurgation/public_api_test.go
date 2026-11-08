// SPDX-License-Identifier: PolyForm-Small-Business-1.0.0

package expurgation

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

// TestPublicAPI : types, fonctions et variables exportés du paquet en liste fermée (repris des essais de detect avant la
// v0.6.0). Une Substitution porte des positions, la règle, une Empreinte locale (HMAC sous la clé de l'appelant), le
// numéro et le Substitut écrit, jamais la valeur ; seules Expurgate et ExpurgateAndRescan rendent des octets : le
// texte de l'appelant, chaque partie secrète remplacée par un Substitut (TestExpurgateCorpus).
func TestPublicAPI(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var types, funcs, values []string
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
							types = append(types, sp.Name.Name)
						}
					case *ast.ValueSpec:
						for _, n := range sp.Names {
							if n.IsExported() {
								values = append(values, n.Name)
							}
						}
					}
				}
			case *ast.FuncDecl:
				if d.Name.IsExported() {
					funcs = append(funcs, d.Name.Name)
				}
				if d.Name.IsExported() && d.Type.Results != nil {
					for _, result := range d.Type.Results.List {
						if array, ok := result.Type.(*ast.ArrayType); ok {
							elem, _ := array.Elt.(*ast.Ident)
							if elem == nil || (elem.Name != "byte" && elem.Name != "Substitution") {
								t.Errorf("%s : rend une tranche non contrôlée", d.Name.Name)
							}
						}
						if ident, ok := result.Type.(*ast.Ident); ok && (ident.Name == "string" || ident.Name == "any") {
							t.Errorf("%s : rend %s", d.Name.Name, ident.Name)
						}
					}
				}
			}
		}
	}
	for _, c := range []struct {
		name      string
		got, want []string
	}{
		{"types", types, []string{"Options", "Substitution"}},
		{"fonctions", funcs, []string{"Expurgate", "ExpurgateAndRescan"}},
		{"variables et constantes", values, []string{"ErrEncoding", "ErrIncomplete", "ErrLanguage", "ErrOrdinal", "ErrSpan", "SanitizeOrdinal"}},
	} {
		slices.Sort(c.got)
		if !slices.Equal(c.got, c.want) {
			t.Errorf("%s exportés %v, attendu %v", c.name, c.got, c.want)
		}
	}
	for typ, want := range map[reflect.Type][]string{
		reflect.TypeFor[Substitution](): {"RuleID", "SecretType", "ByteStart", "ByteEnd", "UTF16Start", "UTF16End", "LocalFingerprint", "Ordinal", "Replacement"},
		reflect.TypeFor[Options]():      {"Options", "SubstituteLanguage"},
	} {
		var got []string
		for i := range typ.NumField() {
			field := typ.Field(i)
			switch field.Type.Kind() {
			case reflect.String, reflect.Int, reflect.Struct:
			default:
				t.Errorf("%s.%s : genre %s", typ.Name(), field.Name, field.Type.Kind())
			}
			got = append(got, field.Name)
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s : champs %v, attendu %v", typ.Name(), got, want)
		}
	}
}
