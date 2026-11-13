// SPDX-License-Identifier: Apache-2.0

// Substituts : textes typés qui remplacent la partie secrète d'un constat (SecretRange, secretrange.go).
//
// Extension propre à ce module, sans origine dans Secret Guard (avis dans UPSTREAM.md). Un Substitut dit lui-même au
// lecteur (un modèle de langage) ce qu'il remplace : préfixe public facultatif, puis, entre crochets, le numéro et le
// type de secret, en français ou en anglais :
//
//	[secret masqué par xSOM n°1 : mot de passe de base de données, pas la vraie valeur]
//	ghp_[secret masqué par xSOM n°2 : jeton GitHub, pas la vraie valeur]
//	[secret masked by xSOM #1: database password, not the real value]
//
// Grammaire exacte et fermée : préfixe de la table fermée substituteRulePrefixes (ou aucun), puis l'une des deux formes
// ci-dessus, octet pour octet, avec un numéro de 1 à 999 sans zéro de tête et un type de la table fermée
// substituteLabels de la même langue (ou SubstituteDefaultLabel). Rien d'autre : ni espace de plus, ni autre casse, ni
// type d'une autre langue. Le Substitut ne porte rien de la valeur, sauf le préfixe public de sa règle : ni sa longueur,
// ni un de ses caractères. Le moteur reconnaît un Substitut comme une valeur fictive (safeLiteral, scanPrivateKeys,
// safeContextualValue, argument de curl -u) : un texte expurgé, analysé de nouveau, ne bloque pas sur ses Substituts.
// Un texte qui ne suit pas exactement la grammaire reste analysé comme tout autre texte.
//
// Ce fichier tient la grammaire (le moteur doit reconnaître un Substitut) et son écrivain (SubstituteText) ; il reste
// sous Apache-2.0. L'expurgation qui pose les Substituts dans un texte est le module
// github.com/xsom-consulting/secret-guard/expurgation (README, « Licences »).
//
// Depuis la v0.5.0, l'ancienne forme (« préfixe, X majuscules, numéro ») n'est plus reconnue : c'est un texte ordinaire,
// détecté s'il a la forme d'un secret.

package detect

import (
	"bytes"
	"errors"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// MaxSubstituteOrdinal est le plus grand numéro d'un Substitut ; MinSubstituteOrdinal, le plus petit.
	MinSubstituteOrdinal = 1
	MaxSubstituteOrdinal = 999
	// substituteMaxDigits : nombre de chiffres le plus grand du numéro.
	substituteMaxDigits = 3
	// substituteMaxPrefix : longueur du plus long préfixe de la table (vérifiée par un test).
	substituteMaxPrefix = len("https://hooks.slack.com/services/")
)

// SubstituteLanguage est la langue du texte d'un Substitut.
type SubstituteLanguage string

const (
	// SubstituteFrench : « [secret masqué par xSOM n°<numéro> : <type>, pas la vraie valeur] ». Langue par défaut
	// (valeur vide).
	SubstituteFrench SubstituteLanguage = "fr"
	// SubstituteEnglish : « [secret masked by xSOM #<numéro>: <type>, not the real value] ».
	SubstituteEnglish SubstituteLanguage = "en"
)

// substituteForm est la forme d'un Substitut dans une langue : début jusqu'au numéro, séparateur entre le numéro et le
// type, fin après le type.
type substituteForm struct {
	language       SubstituteLanguage
	open, mid, end string
}

// substituteForms : les deux formes, dans l'ordre où la grammaire les essaie.
var substituteForms = []substituteForm{
	{SubstituteFrench, "[secret masqué par xSOM n°", " : ", ", pas la vraie valeur]"},
	{SubstituteEnglish, "[secret masked by xSOM #", ": ", ", not the real value]"},
}

// SubstituteDefaultLabel est le type écrit pour une règle absente de la table substituteLabels (Pack du client,
// entropie…), dans les deux langues.
const SubstituteDefaultLabel = "secret"

// SubstituteLabel est le type de secret écrit dans un Substitut pour une règle, en français et en anglais.
type SubstituteLabel struct {
	RuleID  string
	French  string
	English string
}

// substituteLabels est la table fermée des types de secret, par règle (repli : SubstituteDefaultLabel) : les règles
// du catalogue et de données personnelles (baseSubstituteLabels), puis les règles de fournisseurs du Pack initial
// (providerSubstituteLabels, substitute_providers.go, v0.8.1). Un type est public : il dit la nature du secret, jamais
// la valeur. Même table que le Mod de l'organisation de xSOM Fleet.
var substituteLabels = append(append([]SubstituteLabel(nil), baseSubstituteLabels...), providerSubstituteLabels...)

// baseSubstituteLabels : types de secret des règles du catalogue d'origine et des règles de données personnelles.
var baseSubstituteLabels = []SubstituteLabel{
	{"private_key_pem", "clé privée", "private key"},
	{"private_key_pem_incomplete", "clé privée", "private key"},
	{"contextual_private_key", "clé privée", "private key"},
	{"github_fine_grained_pat", "jeton GitHub", "GitHub token"},
	{"github_token", "jeton GitHub", "GitHub token"},
	{"gitlab_pat", "jeton GitLab", "GitLab token"},
	{"openrouter_key", "clé d’API OpenRouter", "OpenRouter API key"},
	{"anthropic_key", "clé d’API Anthropic", "Anthropic API key"},
	{"openai_key", "clé d’API OpenAI", "OpenAI API key"},
	{"stripe_secret_key", "clé secrète Stripe", "Stripe secret key"},
	{"slack_token", "jeton Slack", "Slack token"},
	{"slack_webhook", "webhook Slack", "Slack webhook"},
	{"google_api_key", "clé d’API Google", "Google API key"},
	{"google_oauth_token", "jeton OAuth Google", "Google OAuth token"},
	{"sendgrid_key", "clé d’API SendGrid", "SendGrid API key"},
	{"npm_token", "jeton npm", "npm token"},
	{"huggingface_token", "jeton Hugging Face", "Hugging Face token"},
	{"databricks_pat", "jeton Databricks", "Databricks token"},
	{"digitalocean_token", "jeton DigitalOcean", "DigitalOcean token"},
	{"shopify_token", "jeton Shopify", "Shopify token"},
	{"azure_storage_key", "clé de stockage Azure", "Azure storage key"},
	{"aws_access_key_id", "identifiant de clé d’accès AWS", "AWS access key ID"},
	{"contextual_cloud_credential", "identifiant cloud", "cloud credential"},
	{"jwt", "jeton JWT", "JWT"},
	{"database_url_credentials", "mot de passe de base de données", "database password"},
	{"contextual_database_credentials", "identifiants de base de données", "database credentials"},
	{"basic_auth_url", "mot de passe", "password"},
	{"contextual_password", "mot de passe", "password"},
	{"cli_basic_auth", "mot de passe", "password"},
	{"docker_auth", "mot de passe", "password"},
	{"contextual_api_key", "clé d’API", "API key"},
	{"contextual_access_token", "jeton d’accès", "access token"},
	{"cookie_session_credential", "cookie de session", "session cookie"},
	// Données personnelles (v0.7.0).
	{"iban", "IBAN", "IBAN"},
	{"fr_nir", "numéro de sécurité sociale", "social security number"},
	{"fr_siret", "numéro SIRET", "SIRET number"},
	{"fr_siren", "numéro SIREN", "SIREN number"},
	{"payment_card", "numéro de carte bancaire", "payment card number"},
}

// substituteLabelByRule : la table, par règle.
var substituteLabelByRule = func() map[string]SubstituteLabel {
	byRule := make(map[string]SubstituteLabel, len(substituteLabels))
	for _, l := range substituteLabels {
		byRule[l.RuleID] = l
	}
	return byRule
}()

// substituteLabelSets : types admis par la grammaire, par langue (table et repli), sans doublon, du plus long au plus
// court.
var substituteLabelSets = func() map[SubstituteLanguage][]string {
	sets := map[SubstituteLanguage][]string{}
	add := func(language SubstituteLanguage, label string) {
		for _, known := range sets[language] {
			if known == label {
				return
			}
		}
		sets[language] = append(sets[language], label)
	}
	for _, l := range substituteLabels {
		add(SubstituteFrench, l.French)
		add(SubstituteEnglish, l.English)
	}
	add(SubstituteFrench, SubstituteDefaultLabel)
	add(SubstituteEnglish, SubstituteDefaultLabel)
	for _, labels := range sets {
		sort.SliceStable(labels, func(i, j int) bool { return len(labels[i]) > len(labels[j]) })
	}
	return sets
}()

// SubstituteLabels rend une copie de la table fermée des types de secret des Substituts, dans son ordre.
func SubstituteLabels() []SubstituteLabel { return append([]SubstituteLabel(nil), substituteLabels...) }

// substituteLabelOf rend le type de la règle ruleID dans la langue (repli : SubstituteDefaultLabel).
func substituteLabelOf(ruleID string, language SubstituteLanguage) string {
	l, ok := substituteLabelByRule[ruleID]
	switch {
	case !ok:
		return SubstituteDefaultLabel
	case language == SubstituteEnglish:
		return l.English
	default:
		return l.French
	}
}

// Valid dit si la langue est SubstituteFrench, SubstituteEnglish ou vide (français).
func (l SubstituteLanguage) Valid() bool {
	_, ok := substituteFormOf(l)
	return ok
}

// substituteFormOf rend la forme de la langue (vide : français) ; faux pour une autre langue.
func substituteFormOf(language SubstituteLanguage) (substituteForm, bool) {
	if language == "" {
		language = SubstituteFrench
	}
	for _, form := range substituteForms {
		if form.language == language {
			return form, true
		}
	}
	return substituteForm{}, false
}

// substituteRulePrefixes est la table fermée des préfixes publics, par règle « motif seul » du Pack initial dont le
// motif les porte (test TestSubstitutePrefixesFromInitialPack). Un préfixe est public : il dit le type de secret,
// jamais la valeur. Un Substitut ne reprend que le préfixe de la règle de son constat : une valeur d'une autre règle
// (mot de passe, entropie, URL, cookie, Pack du client…) n'en a aucun, même si elle commence par les mêmes caractères.
var substituteRulePrefixes = []struct {
	ruleID   string
	prefixes []string
}{
	{"github_fine_grained_pat", []string{"github_pat_"}},
	{"github_token", []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}},
	{"gitlab_pat", []string{"glpat-"}},
	{"openrouter_key", []string{"sk-or-v1-"}},
	{"anthropic_key", []string{"sk-ant-"}},
	{"openai_key", []string{"sk-proj-", "sk-svcacct-", "sk-"}},
	{"stripe_secret_key", []string{"sk_live_", "sk_test_", "rk_live_", "rk_test_"}},
	{"slack_token", []string{"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"}},
	{"slack_webhook", []string{"https://hooks.slack.com/services/"}},
	{"google_api_key", []string{"AIza"}},
	{"google_oauth_token", []string{"ya29."}},
	{"sendgrid_key", []string{"SG."}},
	{"npm_token", []string{"npm_"}},
	{"huggingface_token", []string{"hf_"}},
	{"databricks_pat", []string{"dapi"}},
	{"digitalocean_token", []string{"dop_v1_"}},
	{"shopify_token", []string{"shpat_", "shpss_", "shpca_", "shppa_"}},
	{"aws_access_key_id", []string{"AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA"}},
	{"jwt", []string{"eyJ"}},
}

// substitutePrefixes : tous les préfixes de la table, dans son ordre.
var substitutePrefixes = func() []string {
	var all []string
	for _, r := range substituteRulePrefixes {
		all = append(all, r.prefixes...)
	}
	return all
}()

// substitutePrefixesByRule : préfixes de chaque règle, du plus long au plus court, pour prendre le préfixe le plus long
// par lequel commence une valeur.
var substitutePrefixesByRule = func() map[string][]string {
	byRule := make(map[string][]string, len(substituteRulePrefixes))
	for _, r := range substituteRulePrefixes {
		sorted := append([]string(nil), r.prefixes...)
		sort.SliceStable(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
		byRule[r.ruleID] = sorted
	}
	return byRule
}()

// substitutePrefixSet : la table, pour reconnaître un préfixe exact.
var substitutePrefixSet = func() map[string]bool {
	set := make(map[string]bool, len(substitutePrefixes))
	for _, p := range substitutePrefixes {
		set[p] = true
	}
	return set
}()

// SubstitutePrefixes rend une copie de la table fermée des préfixes publics des Substituts. Chaque préfixe vient du
// motif d'une règle « motif seul » du Pack initial ; aucun ne dépend d'une valeur détectée.
func SubstitutePrefixes() []string { return append([]string(nil), substitutePrefixes...) }

// ErrSubstituteOrdinal refuse un numéro de Substitut hors de [MinSubstituteOrdinal, MaxSubstituteOrdinal].
var ErrSubstituteOrdinal = errors.New("substitut refusé : numéro hors de 1 à 999")

// ErrSubstituteLanguage refuse une langue de Substitut autre que SubstituteFrench, SubstituteEnglish ou vide.
var ErrSubstituteLanguage = errors.New("substitut refusé : langue inconnue")

// substituteBodyLength rend la longueur du corps de Substitut (crochets compris, sans préfixe) qui commence text, ou 0
// si text ne commence pas par un corps exact de la grammaire.
func substituteBodyLength(text []byte) int {
	length, _ := parseSubstituteBody(text)
	return length
}

// parseSubstituteBody rend la longueur et le numéro du corps de Substitut qui commence text, ou 0, 0.
func parseSubstituteBody(text []byte) (int, int) {
	for _, form := range substituteForms {
		if !bytes.HasPrefix(text, []byte(form.open)) {
			continue
		}
		rest := text[len(form.open):]
		digits := 0
		for digits < len(rest) && digits <= substituteMaxDigits && isASCIIDigit(rest[digits]) {
			digits++
		}
		if digits == 0 || digits > substituteMaxDigits || rest[0] == '0' {
			return 0, 0
		}
		ordinal, err := strconv.Atoi(string(rest[:digits]))
		if err != nil {
			return 0, 0
		}
		rest = rest[digits:]
		if !bytes.HasPrefix(rest, []byte(form.mid)) {
			return 0, 0
		}
		rest = rest[len(form.mid):]
		for _, label := range substituteLabelSets[form.language] {
			if bytes.HasPrefix(rest, []byte(label)) && bytes.HasPrefix(rest[len(label):], []byte(form.end)) {
				return len(form.open) + digits + len(form.mid) + len(label) + len(form.end), ordinal
			}
		}
		return 0, 0
	}
	return 0, 0
}

// SubstituteSpan est l'étendue [ByteStart, ByteEnd) d'un Substitut exact dans un texte (préfixe public compris) et son
// numéro. Elle ne porte aucune valeur : un Substitut n'en contient pas.
type SubstituteSpan struct {
	ByteStart int
	ByteEnd   int
	Ordinal   int
}

// substitutePrefixesLongestFirst : la table des préfixes, du plus long au plus court.
var substitutePrefixesLongestFirst = func() []string {
	sorted := append([]string(nil), substitutePrefixes...)
	sort.SliceStable(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	return sorted
}()

// FindSubstitutes rend, dans l'ordre et sans chevauchement, les Substituts exacts de la grammaire présents dans text :
// chaque corps entre crochets (« [secret masqué par xSOM n°…] », « [secret masked by xSOM #…] ») avec, s'il le
// précède immédiatement, le plus long préfixe de la table. Un texte qui ne suit pas exactement la grammaire n'en est
// pas un. Sert à l'appelant qui doit juger un texte comme si chaque Substitut était un mot opaque : une commande, par
// exemple, dont un Substitut (espaces, crochets, dièse) changerait sinon le découpage en mots.
func FindSubstitutes(text []byte) []SubstituteSpan {
	var spans []SubstituteSpan
	for cursor := 0; cursor < len(text); {
		open := bytes.IndexByte(text[cursor:], '[')
		if open < 0 {
			break
		}
		at := cursor + open
		length, ordinal := parseSubstituteBody(text[at:])
		if length == 0 {
			cursor = at + 1
			continue
		}
		start := at
		for _, prefix := range substitutePrefixesLongestFirst {
			if at-len(prefix) >= cursor && bytes.Equal(text[at-len(prefix):at], []byte(prefix)) {
				start = at - len(prefix)
				break
			}
		}
		spans = append(spans, SubstituteSpan{ByteStart: start, ByteEnd: at + length, Ordinal: ordinal})
		cursor = at + length
	}
	return spans
}

// substituteAt rend la fin du Substitut (préfixe de la table ou aucun, puis corps exact) qui commence text[start:], et
// faux s'il n'y en a pas. Un préfixe n'est lu que s'il est suivi d'un corps.
func substituteAt(text []byte, start int) (int, bool) {
	if start < 0 || start >= len(text) {
		return 0, false
	}
	rest := text[start:]
	open := bytes.IndexByte(rest[:min(len(rest), substituteMaxPrefix+1)], '[')
	if open < 0 || (open > 0 && !substitutePrefixSet[string(rest[:open])]) {
		return 0, false
	}
	length := substituteBodyLength(rest[open:])
	if length == 0 {
		return 0, false
	}
	return start + open + length, true
}

// isSubstitute dit si value est exactement un Substitut de la grammaire, sans retrait d'espaces : un Substitut est
// exact.
func isSubstitute(value []byte) bool {
	end, ok := substituteAt(value, 0)
	return ok && end == len(value)
}

// isSubstituteFragment dit si text[start:end], valeur lue par une règle qui s'arrête à une espace, une virgule ou un
// dièse (argument de curl -u sans guillemets, valeur d'affectation sans guillemets, cookie), est le début d'un Substitut
// complet qui commence en start et finit proprement (substituteEndsCleanly) : la valeur coupée est un morceau du
// Substitut, pas un secret. Un Substitut suivi d'autres caractères (« …valeur]abc ») ne l'est pas.
func isSubstituteFragment(text []byte, start, end int) bool {
	stop, ok := substituteAt(text, start)
	return ok && end <= stop && substituteEndsCleanly(text, stop)
}

// substituteEndsCleanly dit si le Substitut qui finit en stop est suivi de la fin du texte, d'une espace, d'une fin de
// ligne, d'un guillemet (au plus précédé d'une barre oblique inverse, chaîne échappée) ou d'une fin de valeur
// (« , ; # } ) ] »), et non d'autres caractères qui lui seraient collés.
func substituteEndsCleanly(text []byte, stop int) bool {
	if stop >= len(text) {
		return true
	}
	c := text[stop]
	if c == '\\' && stop+1 < len(text) {
		c = text[stop+1]
		return c == '"' || c == '\'' || c == '`'
	}
	return bytes.IndexByte([]byte(" \t\r\n\"'`,;#})]"), c) >= 0
}

// substitutePrefixOf rend le préfixe le plus long de la règle ruleID par lequel commence value, ou "" (règle sans
// préfixe dans la table).
func substitutePrefixOf(value []byte, ruleID string) string {
	for _, p := range substitutePrefixesByRule[ruleID] {
		if bytes.HasPrefix(value, []byte(p)) {
			return p
		}
	}
	return ""
}

// SubstituteText écrit le Substitut de value, trouvée par la règle ruleID, au numéro ordinal, dans la langue language
// (vide : français) : préfixe le plus long de cette règle par lequel commence value (ou aucun, table fermée), puis le
// corps avec le numéro et le type de la règle. Rien d'autre de la valeur : ni sa longueur, ni un de ses caractères.
// Numéro hors de 1 à 999 : ErrSubstituteOrdinal ; langue inconnue : ErrSubstituteLanguage ; aucun texte dans les deux
// cas. Le texte rendu suit exactement la grammaire : le moteur le reconnaît comme une valeur fictive.
func SubstituteText(value []byte, ruleID string, ordinal int, language SubstituteLanguage) (string, error) {
	if ordinal < MinSubstituteOrdinal || ordinal > MaxSubstituteOrdinal {
		return "", ErrSubstituteOrdinal
	}
	form, ok := substituteFormOf(language)
	if !ok {
		return "", ErrSubstituteLanguage
	}
	return substitutePrefixOf(value, ruleID) + form.open + strconv.Itoa(ordinal) + form.mid +
		substituteLabelOf(ruleID, form.language) + form.end, nil
}

// Schémas d'authentification dont le mot n'est pas secret : la valeur qui suit l'est (« Bearer <jeton> »).
var authSchemes = []string{"bearer", "basic", "token"}

// authSchemeEnd rend la fin du schéma d'authentification qui commence value (mot sans tenir compte de la casse, puis
// au moins une espace ou tabulation), et faux s'il n'y en a pas ou si rien ne le suit.
func authSchemeEnd(value []byte) (int, bool) {
	for _, scheme := range authSchemes {
		if len(value) <= len(scheme) || !strings.EqualFold(string(value[:len(scheme)]), scheme) {
			continue
		}
		end := len(scheme)
		for end < len(value) && (value[end] == ' ' || value[end] == '\t') {
			end++
		}
		if end > len(scheme) && end < len(value) {
			return end, true
		}
	}
	return 0, false
}

// authValueLength rend la longueur de la valeur qui suit un schéma d'authentification : jusqu'au premier guillemet
// (« " », « ' », « ` ») ou à la première barre oblique inverse (fin d'une chaîne qui contient l'en-tête), sinon jusqu'à
// la fin. Une espace ne l'arrête pas.
func authValueLength(value []byte) int {
	if i := bytes.IndexAny(value, "\"'`\\"); i >= 0 {
		return i
	}
	return len(value)
}

// isAuthSchemeSubstitute dit si value est un schéma d'authentification suivi d'un Substitut, puis de la fin, ou d'un
// guillemet (précédé au plus d'une barre oblique inverse) suivi de la fin ou d'une espace : « Bearer XXXX1 »,
// « Bearer XXXX1" https://x » (en-tête dans une commande curl).
func isAuthSchemeSubstitute(value []byte) bool {
	trimmed := jsTrim(value)
	end, ok := authSchemeEnd(trimmed)
	if !ok {
		return false
	}
	rest := trimmed[end:]
	length := authValueLength(rest)
	if !isSubstitute(rest[:length]) {
		return false
	}
	tail := rest[length:]
	if len(tail) == 0 {
		return true
	}
	if tail[0] == '\\' {
		tail = tail[1:]
	}
	if len(tail) == 0 || (tail[0] != '"' && tail[0] != '\'' && tail[0] != '`') {
		return false
	}
	tail = tail[1:]
	if len(tail) == 0 {
		return true
	}
	r, _ := utf8.DecodeRune(tail)
	return isJSWhitespace(r)
}

// pemLabelOf lit l'en-tête « -----BEGIN <étiquette>----- » au début de text : rend l'étiquette et la fin de l'en-tête.
func pemLabelOf(text []byte) ([]byte, int, bool) {
	const begin = "-----BEGIN "
	if !bytes.HasPrefix(text, []byte(begin)) {
		return nil, 0, false
	}
	closing := bytes.Index(text[len(begin):], []byte("-----"))
	if closing <= 0 {
		return nil, 0, false
	}
	label := text[len(begin) : len(begin)+closing]
	if bytes.ContainsAny(label, "\r\n") {
		return nil, 0, false
	}
	return label, len(begin) + closing + len("-----"), true
}

// pemEndMarker écrit « -----END <étiquette>----- ».
func pemEndMarker(label []byte) []byte {
	marker := make([]byte, 0, len(label)+14)
	marker = append(marker, "-----END "...)
	marker = append(marker, label...)
	return append(marker, "-----"...)
}

// pemBodyRange retire aux deux bouts de text[start:end] les espaces de JavaScript et les fins de ligne échappées
// (« \n », « \r » d'une chaîne JSON ou d'un littéral) ; rend l'étendue du corps qui reste.
func pemBodyRange(text []byte, start, end int) (int, int) {
	for start < end {
		if r, width := utf8.DecodeRune(text[start:end]); isJSWhitespace(r) {
			start += width
		} else if text[start] == '\\' && start+1 < end && (text[start+1] == 'n' || text[start+1] == 'r') {
			start += 2
		} else {
			break
		}
	}
	for end > start {
		if r, width := utf8.DecodeLastRune(text[start:end]); isJSWhitespace(r) {
			end -= width
		} else if end-start >= 2 && text[end-2] == '\\' && (text[end-1] == 'n' || text[end-1] == 'r') {
			end -= 2
		} else {
			break
		}
	}
	return start, end
}

// isSubstitutePEMBody dit si text[start:end], corps d'un bloc PEM, est un Substitut entouré de fins de ligne.
func isSubstitutePEMBody(text []byte, start, end int) bool {
	start, end = pemBodyRange(text, start, end)
	return start < end && isSubstitute(text[start:end])
}

// isSubstitutePEM dit si value est un bloc PEM complet (en-tête, corps, marque de fin de même étiquette) dont le corps
// est un Substitut, précédé au plus de l'indicateur d'un bloc YAML (« | », « > », suivis de « + », « - » ou d'un
// chiffre).
func isSubstitutePEM(value []byte) bool {
	trimmed := jsTrim(value)
	if len(trimmed) > 0 && (trimmed[0] == '|' || trimmed[0] == '>') {
		header := 1
		for header < len(trimmed) && (trimmed[header] == '+' || trimmed[header] == '-' || isASCIIDigit(trimmed[header])) {
			header++
		}
		trimmed = jsTrim(trimmed[header:])
	}
	label, headerEnd, ok := pemLabelOf(trimmed)
	if !ok {
		return false
	}
	marker := pemEndMarker(label)
	if !bytes.HasSuffix(trimmed, marker) || len(trimmed)-len(marker) < headerEnd {
		return false
	}
	return isSubstitutePEMBody(trimmed, headerEnd, len(trimmed)-len(marker))
}

// isSubstituteBeforeJoin dit si, dans une vue jointe (lignes d'un jeton coupé recollées, EncodingWhitespaceJoined), la
// valeur [start, end) commence par un Substitut qui finit exactement à la première jointure : un Substitut en fin de
// ligne, suivi d'une ligne qui commence par des caractères de jeton, n'est pas un jeton coupé. La ligne suivante reste
// analysée dans les autres vues.
func isSubstituteBeforeJoin(v *view, start, end int) bool {
	if v.encoding != EncodingWhitespaceJoined || v.starts == nil {
		return false
	}
	for j := max(start, 0) + 1; j < end && j < len(v.starts); j++ {
		if v.starts[j] > v.ends[j-1] {
			return isSubstitute(v.text[start:j])
		}
	}
	return false
}
