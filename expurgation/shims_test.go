// SPDX-License-Identifier: PolyForm-Small-Business-1.0.0

// Équivalents, sur l'API publique de detect, des fonctions internes du moteur qu'appelaient les essais de l'expurgation
// quand ils étaient dans le paquet detect (avant la v0.6.0). Les noms sont gardés : les essais déplacés n'ont pas
// changé.

package expurgation

import (
	"bytes"
	"slices"

	"github.com/xsom-consulting/secret-guard/detect"
)

// Identifiants de règles du Pack initial et préfixes des règles du client et des affectations contextuelles (constantes
// non exportées de detect).
const (
	rulePrivateKeyComplete = "private_key_pem"
	ruleDatabaseURL        = "database_url_credentials"
	ruleBasicAuthURL       = "basic_auth_url"
	ruleCLIBasicAuth       = "cli_basic_auth"
	contextualRulePrefix   = "contextual_"
	customRulePrefix       = "xsom_"
	customSecretType       = "custom_rule"
)

// scan est detect.ScanWith (analyse avec options et, si key n'est pas nil, Empreinte locale).
func scan(content []byte, rules *detect.Rules, options detect.Options, key *detect.FingerprintKey) detect.Result {
	return detect.ScanWith(content, rules, options, key)
}

// localFingerprint est detect.Fingerprint, pour une clé utilisable (sinon : panique, l'essai est faux).
func localFingerprint(key detect.FingerprintKey, value []byte) string {
	fingerprint, ok := detect.Fingerprint(key, value)
	if !ok {
		panic("clé d'Empreinte locale inutilisable")
	}
	return fingerprint
}

// secretPart est detect.SecretRange.
func secretPart(content []byte, f detect.Finding) (int, int) { return detect.SecretRange(content, f) }

// firstLineSecretEnd est Rules.FirstLineSecretEnd.
func firstLineSecretEnd(content []byte, rules *detect.Rules, f detect.Finding) (int, bool) {
	return rules.FirstLineSecretEnd(content, f)
}

// substituteFor est detect.SubstituteText.
func substituteFor(value []byte, ruleID string, ordinal int, language detect.SubstituteLanguage) (string, error) {
	return detect.SubstituteText(value, ruleID, ordinal, language)
}

// isSubstitute dit si value est exactement un Substitut de la grammaire (detect.FindSubstitutes : un seul, qui la
// couvre entière).
func isSubstitute(value []byte) bool {
	spans := detect.FindSubstitutes(value)
	return len(spans) == 1 && spans[0].ByteStart == 0 && spans[0].ByteEnd == len(value)
}

// substitutePrefixOf rend le préfixe public le plus long de la table (detect.SubstitutePrefixes) par lequel commence
// value et que garde le Substitut de la règle ruleID (detect.SubstituteText, dont le texte commence par ce préfixe), ou
// "".
func substitutePrefixOf(value []byte, ruleID string) string {
	text, err := detect.SubstituteText(value, ruleID, detect.MinSubstituteOrdinal, detect.SubstituteFrench)
	if err != nil {
		return ""
	}
	prefixes := detect.SubstitutePrefixes()
	slices.SortStableFunc(prefixes, func(a, b string) int { return len(b) - len(a) })
	for _, p := range prefixes {
		if bytes.HasPrefix(value, []byte(p)) && len(text) >= len(p) && text[:len(p)] == p {
			return p
		}
	}
	return ""
}
