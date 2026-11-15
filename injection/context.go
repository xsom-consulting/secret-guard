// SPDX-License-Identifier: Apache-2.0

// Contexte d'une correspondance : ce qui la précède et l'entoure, lu à la main.
//
// RE2 n'a pas d'assertion arrière. Deux contrôles bornés la remplacent, après chaque correspondance :
//
//   - un motif de contexte, propre à un motif de règle, cherché dans les contextBytes octets qui précèdent sur la même
//     ligne : une négation devant « révèle ton prompt système » (« ne révèle jamais… » est une défense, pas une
//     attaque), ou au contraire une négation exigée devant « bound by the content policy » ;
//   - la citation : une formule courte entre guillemets au milieu d'une phrase (« Les attaquants écrivent “ignore all
//     previous instructions” dans une page ») est une mention, pas une consigne. Elle n'est pas signalée. Une valeur
//     (guillemet après « : », « = » ou en début de ligne), une citation qui se poursuit au-delà d'une phrase et un
//     texte sans guillemets le restent.
//
// La citation est un compromis mesuré (docs/bench.md) : elle retire du bruit des documentations, et laisse passer
// une consigne qu'un attaquant prendrait soin d'écrire entre guillemets au milieu d'une phrase. Elle ne vaut donc que
// pour les règles dont la mesure montre ce bruit (mentionRules) : un ordre d'envoyer des secrets ou de cacher une
// action reste signalé entre guillemets, comme avant la v0.10.0.

package injection

import "bytes"

const (
	// contextBytes : octets lus avant une correspondance pour le motif de contexte.
	contextBytes = 48
	// quoteLead : espaces et marques d'emphase admis entre le guillemet ouvrant et la correspondance.
	quoteLead = 4
	// quoteTail : octets admis entre la fin de la correspondance et le guillemet fermant.
	quoteTail = 40
	// contextMargin : octets lus au-delà de quoteTail (guillemet fermant et caractère qui le suit).
	contextMargin = 8
)

// mentionRules sont les règles pour lesquelles une formule citée est une mention : la formule d'annulation, la plus
// citée des documentations, et les jetons de modèles (balises de tours de parole, étiquettes de rôle). Ce sont celles
// dont la mesure montre le bruit (docs/bench.md, « Citations »).
var mentionRules = map[Rule]bool{InstructionOverride: true, MessageMarkers: true, RoleLabels: true}

// accept dit si la correspondance [start, end) du motif dans text est gardée.
func (p *pattern) accept(text []byte, start, end int) bool {
	if p.before != nil {
		from := max(0, start-contextBytes)
		if lineStart := bytes.LastIndexByte(text[from:start], '\n'); lineStart >= 0 {
			from += lineStart + 1
		}
		if p.before.Match(text[from:start]) != p.beforeRequired {
			return false
		}
	}
	return !mentionRules[p.rule] || !quotedMention(text, start, end)
}

// blankBefore rend la longueur de l'espace qui finit à l'octet i (exclu) : espace, tabulation, espace insécable
// (U+00A0) ou espace fine insécable (U+202F) ; 0 s'il n'y en a pas.
func blankBefore(text []byte, i int) int {
	switch {
	case i >= 1 && (text[i-1] == ' ' || text[i-1] == '\t'):
		return 1
	case i >= 2 && text[i-2] == 0xC2 && text[i-1] == 0xA0:
		return 2
	case i >= 3 && text[i-3] == 0xE2 && text[i-2] == 0x80 && text[i-1] == 0xAF:
		return 3
	default:
		return 0
	}
}

// openingQuotes et closingQuotes sont les guillemets reconnus, en UTF-8.
var (
	openingQuotes = [][]byte{[]byte(`"`), []byte(`'`), []byte("`"), []byte("“"), []byte("‘"), []byte("«")}
	closingQuotes = [][]byte{[]byte(`"`), []byte(`'`), []byte("`"), []byte("”"), []byte("’"), []byte("»")}
)

// isProseByte dit si c appartient à un mot : lettre ou chiffre ASCII, ou octet d'un caractère hors ASCII.
func isProseByte(c byte) bool {
	return c >= 0x80 || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// quotedMention dit si la correspondance [start, end) est une citation courte au milieu d'une phrase : un guillemet
// ouvrant juste avant elle, lui-même précédé d'une espace puis d'un mot (ni « : », ni « = », ni début de ligne, ni
// apostrophe d'élision), et un guillemet fermant dans les quoteTail octets qui la suivent, sans fin de phrase ni fin
// de ligne entre les deux, et sans lettre après lui.
func quotedMention(text []byte, start, end int) bool {
	i := start
	for lead := 0; lead < quoteLead && i > 0; lead++ {
		if n := blankBefore(text, i); n > 0 {
			i -= n
		} else if text[i-1] == '*' || text[i-1] == '_' {
			i--
		} else {
			break
		}
	}
	opened := false
	for _, quote := range openingQuotes {
		if bytes.HasSuffix(text[:i], quote) {
			i -= len(quote)
			opened = true
			break
		}
	}
	if !opened {
		return false
	}
	// Espaces devant le guillemet, sans jamais lire plus de contextBytes octets avant la correspondance.
	blanks := 0
	for n := blankBefore(text, i); n > 0 && start-i < contextBytes-8; n = blankBefore(text, i) {
		i -= n
		blanks++
	}
	if blanks == 0 || i == 0 || !isProseByte(text[i-1]) {
		return false
	}
	for k := end; k < len(text) && k-end <= quoteTail; k++ {
		switch text[k] {
		case '\n', '.', '!', '?', ';':
			return false
		}
		for _, quote := range closingQuotes {
			if bytes.HasPrefix(text[k:], quote) {
				after := k + len(quote)
				return after == len(text) || !isProseByte(text[after])
			}
		}
	}
	return false
}
