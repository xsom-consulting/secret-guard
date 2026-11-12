// SPDX-License-Identifier: Apache-2.0

// Mot de passe annoncé dans une phrase (écart d'analyse ajouté en v0.8.1, absent de Secret Guard) : un indice de mot de
// passe, en français ou en anglais, suivi, sur la même ligne, d'une liaison facultative puis d'un seul mot qui a la
// forme d'un mot de passe. « check mon api avec mon mdp <valeur> », « le mot de passe est <valeur> », « my password is
// <valeur> », « mot de passe : <valeur> ». Constat de la règle contextual_password, étendue réduite à la valeur.
//
// Relevé sur un Poste réel le 2026-11-12 : un prompt « … avec mon mdp <valeur> » passait sans constat. L'affectation
// ordinaire (scanAssignmentPattern) ne connaît que des noms de variables anglais reliés par « = » ou « : », et
// l'entropie demande 20 caractères de la classe base64 : un mot de passe court qui mêle symboles et accents échappait
// aux deux.
//
//   - Indices (sans la casse) : « mdp », « mot de passe », « mot-de-passe », « code d'accès » (apostrophe droite ou
//     typographique), « pass », et les noms anglais que typeForSensitiveKey classe « password » tels quels
//     (« password », « passwd », « pwd », « passphrase » ; test TestPasswordPhraseHintsFollowSensitiveKeys). L'indice
//     est un mot entier : ni lettre, chiffre, « _ », « - », « . », « / », « \ », « $ », « @ » juste avant (nom de
//     variable, option, propriété), et une espace (ou, pour un indice français et « pass », « : » ou « = ») juste
//     après.
//   - Liaison, facultative, sur la même ligne (espaces et tabulations seulement) : « est », « is », « c'est », puis,
//     pour un indice que l'affectation ordinaire ne connaît pas (français, « pass »), « : » ou « = ». Un indice anglais
//     suivi de « : » ou « = » est laissé à l'affectation ordinaire et à ses filtres (expressions, références de code) ;
//     « pass » exige une liaison (« we pass Config-V2 to » n'est pas une annonce).
//   - Valeur : un mot sans espace, guillemets d'ouverture (« " ' ` « “ ‘ ») et de fermeture assortis retirés, ponctuation
//     finale « . , ; : ? » et « ) » sans « ( » retirées ; de 8 à 256 points de code ; au moins trois classes parmi
//     minuscules, majuscules (lettres de toute écriture, par leur casse : « Réinitialisé » n'en a que deux), chiffres et
//     autres caractères (symboles, ponctuation, lettres sans casse) ; ni valeur fictive, ni Substitut, ni référence de
//     code ou d'environnement, ni substitution de commande, ni « ${ », « $( », « {{ », « % … % », ni adresse « :// ».
//   - Un constat qui chevauche un constat de l'affectation ordinaire, des cookies ou de « -u » dans la même vue n'est pas
//     ajouté : les résultats de l'origine restent ceux de l'origine (corpus de parité inchangé).
//
// Linéaire : une seule recherche RE2 des indices ; chaque indice lit au plus une liaison et 256 points de code.

package detect

import (
	"bytes"
	"regexp"
	"unicode"
	"unicode/utf8"
)

// rePasswordHint : indices, du plus long au plus court à préfixe commun (RE2 prend la première alternative qui
// correspond). Les noms anglais sont ceux que typeForSensitiveKey classe « password ».
const rePasswordHint = `(?i)(?:mot[ \t-]+de[ \t-]+passe|code[ \t]+d['’]acc[eè]s|mdp|passphrase|password|passwd|pwd|pass)`

var passwordHint = regexp.MustCompile(rePasswordHint)

// englishPasswordHints : indices que l'affectation ordinaire reconnaît déjà comme noms de variables (« : », « = »
// lui sont laissés).
var englishPasswordHints = map[string]bool{"password": true, "passwd": true, "pwd": true, "passphrase": true}

// Bornes de la valeur, en points de code.
const (
	passwordPhraseMinRunes = 8
	passwordPhraseMaxRunes = 256
)

// scanPasswordPhrases ajoute à findings les mots de passe annoncés dans une phrase de la vue v, sauf ceux qui
// chevauchent un constat déjà présent (assignment : constats de l'affectation ordinaire de cette vue).
func (r *Rules) scanPasswordPhrases(v *view, assignment []finding, findings []finding) []finding {
	password := r.contextualRuleFor("password")
	if password == nil {
		return findings
	}
	text := v.text
	for _, m := range passwordHint.FindAllIndex(text, -1) {
		start, end, ok := passwordPhraseValue(text, m[0], m[1])
		if !ok {
			continue
		}
		f := contextualFinding(v, password, start, end, "password_in_sentence")
		if overlapsAny(f, assignment) {
			continue
		}
		findings = append(findings, f)
	}
	return findings
}

// overlapsAny dit si f chevauche l'un des constats (étendues de la source).
func overlapsAny(f finding, others []finding) bool {
	for _, o := range others {
		if o.start < f.end && f.start < o.end {
			return true
		}
	}
	return false
}

// withoutOverlaps rend les constats de phrases qui ne chevauchent aucun de others (chemin parallèle de detectors.go).
func withoutOverlaps(phrases, others []finding) []finding {
	kept := phrases[:0]
	for _, f := range phrases {
		if !overlapsAny(f, others) {
			kept = append(kept, f)
		}
	}
	return kept
}

// passwordPhraseValue rend l'étendue [start, end) de la valeur annoncée par l'indice text[hintStart:hintEnd], dans
// text, si l'annonce et la valeur ont la forme attendue.
func passwordPhraseValue(text []byte, hintStart, hintEnd int) (int, int, bool) {
	if hintStart > 0 {
		previous, _ := utf8.DecodeLastRune(text[:hintStart])
		if !hintMayFollow(previous) {
			return 0, 0, false
		}
	}
	hint := bytes.ToLower(text[hintStart:hintEnd])
	english := englishPasswordHints[string(hint)]
	bare := string(hint) == "pass"
	i := hintEnd
	if i >= len(text) {
		return 0, 0, false
	}
	next, _ := utf8.DecodeRune(text[i:])
	if !isPhraseSpace(next) && (english || (next != ':' && next != '=')) {
		return 0, 0, false
	}
	i = skipPhraseSpaces(text, i)
	linked := false
	if j, ok := phraseWordLink(text, i); ok {
		i, linked = skipPhraseSpaces(text, j), true
	}
	if i < len(text) && (text[i] == ':' || text[i] == '=') {
		if english {
			return 0, 0, false
		}
		i, linked = skipPhraseSpaces(text, i+1), true
	}
	if bare && !linked {
		return 0, 0, false
	}
	return phraseValueSpan(text, i)
}

// hintMayFollow dit si un indice peut suivre le caractère r (début de mot hors nom de variable, option, propriété).
func hintMayFollow(r rune) bool {
	if unicode.IsLetter(r) || unicode.IsDigit(r) {
		return false
	}
	switch r {
	case '_', '-', '.', '/', '\\', '$', '@':
		return false
	}
	return true
}

// isPhraseSpace : espace d'une même ligne (pas de fin de ligne entre l'indice et la valeur).
func isPhraseSpace(r rune) bool { return isJSWhitespace(r) && !isJSLineTerminator(r) }

func skipPhraseSpaces(text []byte, i int) int {
	for i < len(text) {
		r, width := utf8.DecodeRune(text[i:])
		if !isPhraseSpace(r) {
			break
		}
		i += width
	}
	return i
}

// phraseWordLinks : liaisons en mots, sans la casse, suivies d'une espace.
var phraseWordLinks = [][]byte{[]byte("est"), []byte("is"), []byte("c'est"), []byte("c’est")}

// phraseWordLink rend la fin d'une liaison en mot qui commence en i et qu'une espace suit.
func phraseWordLink(text []byte, i int) (int, bool) {
	for _, link := range phraseWordLinks {
		end := i + len(link)
		if end < len(text) && bytes.EqualFold(text[i:end], link) {
			if r, _ := utf8.DecodeRune(text[end:]); isPhraseSpace(r) {
				return end, true
			}
		}
	}
	return 0, false
}

// phraseQuotes : guillemet d'ouverture → guillemet de fermeture.
var phraseQuotes = map[rune]rune{'"': '"', '\'': '\'', '`': '`', '«': '»', '“': '”', '‘': '’'}

// phraseValueSpan lit, à partir de i, un mot sans espace et rend l'étendue de la valeur s'il a la forme d'un mot de
// passe.
func phraseValueSpan(text []byte, i int) (int, int, bool) {
	start := i
	closing := rune(-1)
	if i < len(text) {
		if r, width := utf8.DecodeRune(text[i:]); phraseQuotes[r] != 0 {
			closing = phraseQuotes[r]
			start = i + width
			if r == '«' {
				start = skipPhraseSpaces(text, start)
			}
		}
	}
	end, runes := start, 0
	for end < len(text) {
		r, width := utf8.DecodeRune(text[end:])
		if isJSWhitespace(r) {
			break
		}
		if runes++; runes > passwordPhraseMaxRunes+2 {
			return 0, 0, false
		}
		end += width
	}
	for end > start {
		r, width := utf8.DecodeLastRune(text[start:end])
		// « ) » fermante d'un appel (« getPassword(…) ») gardée : la référence de code est alors reconnue.
		if r != '.' && r != ',' && r != ';' && r != ':' && r != '?' && (r != ')' || bytes.IndexByte(text[start:end], '(') >= 0) {
			break
		}
		end -= width
	}
	if closing >= 0 && end > start {
		if r, width := utf8.DecodeLastRune(text[start:end]); r == closing {
			end -= width
		}
	}
	if closing == '»' {
		// « valeur » : espace avant le guillemet fermant, mot suivant hors de la valeur.
		end = trimRightPhraseSpaces(text, start, end)
	}
	if !passwordPhraseShape(text[start:end]) || isSubstituteFragment(text, start, end) {
		return 0, 0, false
	}
	return start, end, true
}

func trimRightPhraseSpaces(text []byte, start, end int) int {
	for end > start {
		r, width := utf8.DecodeLastRune(text[start:end])
		if !isPhraseSpace(r) {
			break
		}
		end -= width
	}
	return end
}

// passwordPhraseShape dit si value a la forme d'un mot de passe annoncé : longueur, trois classes, et rien qui en fasse
// une valeur fictive, un Substitut, une référence ou une adresse.
func passwordPhraseShape(value []byte) bool {
	if !utf8.Valid(value) {
		return false
	}
	runes := utf8.RuneCount(value)
	if runes < passwordPhraseMinRunes || runes > passwordPhraseMaxRunes {
		return false
	}
	var lower, upper, digit, other bool
	for _, r := range string(value) {
		switch {
		case isJSWhitespace(r) || unicode.IsControl(r):
			return false
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r) || unicode.IsTitle(r):
			upper = true
		case '0' <= r && r <= '9':
			digit = true
		default:
			other = true
		}
	}
	classes := 0
	for _, present := range []bool{lower, upper, digit, other} {
		if present {
			classes++
		}
	}
	if classes < 3 {
		return false
	}
	if bytes.HasPrefix(value, []byte("${")) || bytes.HasPrefix(value, []byte("$(")) ||
		bytes.HasPrefix(value, []byte("{{")) || bytes.Contains(value, []byte("://")) ||
		(len(value) > 2 && value[0] == '%' && value[len(value)-1] == '%') {
		return false
	}
	return !safeLiteral(value) && !isSafeReference(value) && !isShellCommandSubstitution(value)
}
