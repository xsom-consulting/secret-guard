// Validateurs nommés et filtres de valeurs du moteur de détection.
//
// Portage en Go de isPlaceholder, isExactPublicExample et safeLiteral de secret-guard/packages/core/src/rules.ts
// (Apache-2.0, origine, avis et modifications dans UPSTREAM.md). Les motifs viennent de engine_patterns.go (traduits
// de rules.ts par la traduction du Pack).

package detect

import (
	"regexp"
	"strings"
)

// validator valide la valeur détectée par une règle « motif seul » (validator d'une règle de FIXED_RULES). Le budget
// de décodage de l'analyse est débité ; budget épuisé : errDecodeBudgetExhausted.
type validator func(value string, budget *decodeBudget) (bool, error)

// validators est la liste fermée RULE_VALIDATORS (generator/src/rule-pack.ts, docs/rule-pack.md) : nom du Pack → validateur. Le nom
// vide est « sans validateur » (nil). Un nom absent fait refuser le Pack.
var validators = map[string]validator{
	"":              nil,
	"jwt_structure": isStructurallyValidJWT,
}

// publicExamples : valeurs d'exemple publiques de la documentation des Fournisseurs (PUBLIC_EXAMPLES de Secret
// Guard), assemblées à l'exécution (comme la troisième à l'origine) pour que la recherche de secrets du dépôt ne les
// prenne pas pour des secrets.
var publicExamples = map[string]bool{
	strings.Join([]string{"AKIA", "IOSFODNN7", "EXAMPLE"}, ""):                    true,
	strings.Join([]string{"wJalrXUtnFEMI", "K7MDENG", "bPxRfiCYEXAMPLEKEY"}, "/"): true,
	strings.Join([]string{"sk", "test", "4eC39HqLyjWDarjtT1zdp7dc"}, "_"):         true,
}

var (
	placeholderPattern     = regexp.MustCompile(rePlaceholder)
	placeholderWordPattern = regexp.MustCompile(rePlaceholderWord)
)

// isPlaceholder suit isPlaceholder de Secret Guard : valeur fictive (gabarit, variable, x répétés…), espaces de
// JavaScript retirés aux deux bouts.
func isPlaceholder(value []byte) bool {
	trimmed := jsTrim(value)
	return placeholderPattern.Match(trimmed) || placeholderWordPattern.Match(trimmed)
}

// isExactPublicExample suit isExactPublicExample de Secret Guard.
func isExactPublicExample(value []byte) bool { return publicExamples[string(value)] }

// safeLiteral suit safeLiteral de Secret Guard.
func safeLiteral(value []byte) bool { return isPlaceholder(value) || isExactPublicExample(value) }
