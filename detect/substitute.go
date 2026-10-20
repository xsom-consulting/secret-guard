// Substituts : valeurs fictives typées qui remplacent la partie secrète d'un constat (Expurgate, expurgate.go).
//
// Extension propre à ce module, sans origine dans Secret Guard (avis dans UPSTREAM.md). Un Substitut s'écrit
// « préfixe public, puis des X majuscules, puis un numéro de 1 à 3 chiffres » : grammaire ^(?:<préfixe>)?X{3,}[0-9]{1,3}$,
// où le préfixe vient d'une table fermée. Le moteur reconnaît un Substitut comme une valeur fictive (safeLiteral,
// scanPrivateKeys, safeContextualValue) : un texte expurgé, analysé de nouveau, ne bloque pas sur ses Substituts. Un
// corps qui porte autre chose que des X reste détecté : la grammaire n'admet aucune autre lettre.

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
	// substituteFiller est le caractère de remplissage d'un Substitut.
	substituteFiller = 'X'
	// substituteMinFiller : nombre de X le plus petit qu'écrit substituteFor (minimum « XXXX<n> »).
	substituteMinFiller = 4
	// substituteGrammarMinFiller : nombre de X le plus petit qu'admet la grammaire (X{3,}).
	substituteGrammarMinFiller = 3
	// substituteMaxDigits : nombre de chiffres le plus grand du numéro ([0-9]{1,3}).
	substituteMaxDigits = 3
	// MaxSubstituteOrdinal est le plus grand numéro d'un Substitut ; MinSubstituteOrdinal, le plus petit.
	MinSubstituteOrdinal = 1
	MaxSubstituteOrdinal = 999
)

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

// ErrExpurgateOrdinal refuse un numéro de Substitut hors de [MinSubstituteOrdinal, MaxSubstituteOrdinal], ou que
// l'appelant ne donne pas.
var ErrExpurgateOrdinal = errors.New("expurgation refusée : numéro de Substitut absent ou hors de 1 à 999")

// isSubstitute dit si value suit la grammaire des Substituts : ^(?:<préfixe>)?X{3,}[0-9]{1,3}$, X majuscules
// seulement, préfixe de la table fermée (ou aucun). Sans retrait d'espaces : un Substitut est exact.
func isSubstitute(value []byte) bool {
	digits := 0
	for digits < len(value) && isASCIIDigit(value[len(value)-1-digits]) {
		digits++
	}
	if digits == 0 || digits > substituteMaxDigits {
		return false
	}
	rest := value[:len(value)-digits]
	filler := 0
	for filler < len(rest) && rest[len(rest)-1-filler] == substituteFiller {
		filler++
	}
	if filler < substituteGrammarMinFiller {
		return false
	}
	head := rest[:len(rest)-filler]
	return len(head) == 0 || substitutePrefixSet[string(head)]
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

// substituteFor construit le Substitut de value, trouvée par la règle ruleID, au numéro ordinal : préfixe le plus long
// de cette règle par lequel commence value, puis des X, puis le numéro, à la longueur de value en points de code. La
// place manque : sans préfixe ; elle manque encore : « XXXX<n> », plus long que value. Numéro hors de 1 à 999 :
// ErrExpurgateOrdinal.
func substituteFor(value []byte, ruleID string, ordinal int) (string, error) {
	if ordinal < MinSubstituteOrdinal || ordinal > MaxSubstituteOrdinal {
		return "", ErrExpurgateOrdinal
	}
	number := strconv.Itoa(ordinal)
	length := utf8.RuneCount(value)
	prefix := substitutePrefixOf(value, ruleID)
	filler := length - len(prefix) - len(number)
	if prefix == "" || filler < substituteMinFiller {
		prefix = ""
		filler = max(length-len(number), substituteMinFiller)
	}
	return prefix + strings.Repeat(string(substituteFiller), filler) + number, nil
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
