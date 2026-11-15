// SPDX-License-Identifier: Apache-2.0

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
	// Données personnelles (v0.7.0, personaldata.go).
	validatorIBAN:  plainValidator(isValidIBAN),
	validatorNIR:   plainValidator(isValidNIR),
	validatorSiret: plainValidator(isValidSiret),
	validatorSiren: plainValidator(isValidSiren),
	validatorCard:  plainValidator(isValidPaymentCard),
	// Identifiants européens et français à somme de contrôle (v0.10.0, personaldata.go).
	validatorSpanishNIF:        plainValidator(isValidSpanishNIF),
	validatorSpanishNIE:        plainValidator(isValidSpanishNIE),
	validatorItalianFiscalCode: plainValidator(isValidItalianFiscalCode),
	validatorItalianVAT:        plainValidator(isValidItalianVAT),
	validatorGermanTaxID:       plainValidator(isValidGermanTaxID),
	validatorGermanVAT:         plainValidator(isValidGermanVAT),
	validatorPESEL:             plainValidator(isValidPESEL),
	validatorNHS:               plainValidator(isValidNHSNumber),
	validatorPersonnummer:      plainValidator(isValidPersonnummer),
	validatorFinnishIdentity:   plainValidator(isValidFinnishIdentityCode),
	validatorFrenchVAT:         plainValidator(isValidFrenchVAT),
	validatorRIB:               plainValidator(isValidRIB),
	// Vraisemblance d'un jeton de fournisseur (v0.10.0) : noms connus, sans fonction ici. Le contrôle est appliqué par
	// scanFixedPattern depuis rule.entropyFloor (tokenEntropyFloors) : il ne décode rien, ne débite aucun budget et
	// s'exécute aussi dans un texte décodé de base64, où les validateurs à budget ne s'exécutent pas.
	"token_entropy_25": nil, "token_entropy_26": nil, "token_entropy_27": nil, "token_entropy_28": nil,
	"token_entropy_29": nil, "token_entropy_30": nil, "token_entropy_31": nil, "token_entropy_32": nil,
	"token_entropy_33": nil, "token_entropy_34": nil, "token_entropy_35": nil, "token_entropy_36": nil,
	"token_entropy_37": nil, "token_entropy_38": nil, "token_entropy_39": nil, "token_entropy_40": nil,
	"token_entropy_41": nil, "token_entropy_42": nil, "token_entropy_43": nil, "token_entropy_44": nil,
	"token_entropy_45": nil,
}

// Vraisemblance d'un jeton de fournisseur (v0.10.0, écart d'analyse ajouté, absent de Secret Guard).
//
// Une règle de fournisseur reconnaît une forme : un préfixe et une suite de caractères, ou le nom du fournisseur puis
// une suite de caractères. Une valeur sans diversité (une lettre répétée, des zéros, des « X ») a la forme et n'est
// pas un jeton. Le moteur écarte donc, pour toute règle « motif seul » du type des jetons de fournisseur hors du
// catalogue d'origine (originCatalogRules), une valeur de moins de minDistinctBytes octets distincts ou d'entropie de
// Shannon inférieure à baseEntropyFloor/10 bits par octet. Une règle peut porter un autre seuil par un validateur
// nommé « token_entropy_NN » (NN de 25 à 45 : seuil en dixièmes de bit, au-dessus ou au-dessous du seuil d'office),
// qui s'applique aussi à une règle d'un autre type. Les seuils par règle du Pack initial sont repris de Titus
// (Apache-2.0) et de Betterleaks (MIT), puis plafonnés (UPSTREAM.md, « Vraisemblance des règles de fournisseurs »).
const (
	// providerRuleType : type de secret des règles de fournisseurs.
	providerRuleType = "provider_" + "token"
	// minDistinctBytes : nombre minimal d'octets distincts d'un jeton de fournisseur.
	minDistinctBytes = 6
	// baseEntropyFloor : entropie minimale d'un jeton de fournisseur, en dixièmes de bit par octet.
	baseEntropyFloor = 30
)

// tokenEntropyFloors : validateur de vraisemblance → entropie minimale, en dixièmes de bit par octet.
var tokenEntropyFloors = map[string]int{
	"token_entropy_25": 25, "token_entropy_26": 26, "token_entropy_27": 27, "token_entropy_28": 28,
	"token_entropy_29": 29, "token_entropy_30": 30, "token_entropy_31": 31, "token_entropy_32": 32,
	"token_entropy_33": 33, "token_entropy_34": 34, "token_entropy_35": 35, "token_entropy_36": 36,
	"token_entropy_37": 37, "token_entropy_38": 38, "token_entropy_39": 39, "token_entropy_40": 40,
	"token_entropy_41": 41, "token_entropy_42": 42, "token_entropy_43": 43, "token_entropy_44": 44,
	"token_entropy_45": 45,
}

// originCatalogRules : règles « motif seul » du type des jetons de fournisseur qui viennent du catalogue d'origine de
// Secret Guard (rules.ts). Leur comportement est fixé par la parité avec le moteur d'origine, dont les essais
// attendent un constat sur des valeurs sans diversité : le contrôle de vraisemblance ne s'y applique pas d'office
// (TestPlausibility compare cette liste au Pack initial).
var originCatalogRules = map[string]bool{
	"github_fine_grained_pat": true, "github_token": true, "gitlab_pat": true, "openrouter_key": true,
	"anthropic_key": true, "openai_key": true, "stripe_secret_key": true, "slack_token": true, "slack_webhook": true,
	"sendgrid_key": true, "npm_token": true, "huggingface_token": true, "databricks_pat": true,
	"digitalocean_token": true, "shopify_token": true,
}

// entropyFloorOf rend l'entropie minimale (dixièmes de bit par octet) qu'une règle exige de la valeur détectée : celle
// de son validateur de vraisemblance, sinon baseEntropyFloor pour une règle « motif seul » du type des jetons de
// fournisseur hors du catalogue d'origine (règles de fournisseurs du Pack initial, règles ajoutées par un Pack),
// sinon 0 (aucun contrôle).
func entropyFloorOf(ruleID, family, secretType, validatorName string) int {
	if floor, named := tokenEntropyFloors[validatorName]; named {
		return floor
	}
	if family == familyFixedPattern && secretType == providerRuleType && !originCatalogRules[ruleID] {
		return baseEntropyFloor
	}
	return 0
}

// plausibleToken dit si value a la diversité d'un jeton : au moins minDistinctBytes octets distincts et une entropie
// de Shannon d'au moins floor/10 bits par octet. Fréquences sommées dans l'ordre des octets, logarithme de JavaScript
// (jsLog2) : la lecture de référence du générateur (generator/rule-pack/provider-rules.ts) rend le même résultat au
// bit près.
func plausibleToken(value []byte, floor int) bool {
	var counts [256]int
	for _, b := range value {
		counts[b]++
	}
	distinct := 0
	entropy := 0.0
	length := float64(len(value))
	for _, count := range counts {
		if count == 0 {
			continue
		}
		distinct++
		probability := float64(count) / length
		entropy -= float64(probability * jsLog2(probability))
	}
	return distinct >= minDistinctBytes && entropy >= float64(floor)/10
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

// safeLiteral suit safeLiteral de Secret Guard, et reconnaît en plus un Substitut (substitute.go), espaces de
// JavaScript retirés aux deux bouts : extension de ce module, sans effet sur une valeur hors de sa grammaire.
func safeLiteral(value []byte) bool {
	return isPlaceholder(value) || isExactPublicExample(value) || isSubstitute(jsTrim(value))
}
