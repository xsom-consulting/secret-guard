// SPDX-License-Identifier: Apache-2.0

// Chemins et noms en tirets écartés de l'entropie : faux positifs relevés sur un Poste réel (xSOM Fleet, novembre
// 2026), qui bloquaient des commandes de développeur ordinaires.
//
// Écart avec Secret Guard (UPSTREAM.md) : la suite de caractères base64 de scanEntropy (« [A-Za-z0-9+/_-] ») ne
// contient pas le point ; dans « ~/.claude/projects/… » ou « …/claude-code-2.1.318-darwin-arm64/resources/… », elle
// commence après un point et n'a donc plus la forme d'un chemin (rePathLike exige « / » en tête). De même, un dossier
// de projet de Claude Code (« -Users-nom-Documents-… ») est un nom en tirets de forte entropie. Le moteur les écarte :
// moins de constats d'entropie, jamais moins de constats d'une règle ancrée.

package detect

import "bytes"

// isPathContinuation dit si la suite [start, start+len(value)) de la vue est un chemin : elle contient une barre
// oblique et n'a que des caractères de chemin, et
//   - précédée d'un point ou d'une barre oblique (suite d'un chemin coupé par un point), chacun de ses segments de 16
//     unités ou plus est fait de mots courts (isShortWords) ou écarté de l'entropie ;
//   - sinon (chemin relatif, « DEV/site/frontend/public »), chacun de ses mots est un mot de nom de dossier
//     (isNameWord).
//
// Un jeton dans le chemin d'une URL reste détecté.
func isPathContinuation(v *view, start int, value []byte) bool {
	text := v.text
	if !bytes.Contains(value, []byte("/")) {
		return false
	}
	for _, c := range value {
		if !isASCIIAlphanumeric(c) && c != '/' && c != '-' && c != '_' {
			return false
		}
	}
	if start == 0 || (text[start-1] != '.' && text[start-1] != '/') {
		for _, word := range bytes.FieldsFunc(value, func(r rune) bool { return r == '/' || r == '-' || r == '_' }) {
			if !isNameWord(word) {
				return false
			}
		}
		return true
	}
	for _, segment := range bytes.Split(value, []byte("/")) {
		if utf16Units(segment) >= 16 && !entropyExcluded(segment) && !isShortWords(segment) {
			return false
		}
	}
	return true
}

// isNameWord dit si word est un mot de nom de dossier : 12 caractères au plus, en minuscules (« frontend »), avec une
// majuscule initiale (« Documents »), ou en majuscules (« DEV ») ; chiffres admis. Une suite aléatoire de jeton mêle
// majuscules et minuscules au hasard et n'a presque jamais cette forme. Un mot plus long n'est admis que fait de
// lettres seules (isLongNameWord).
func isNameWord(word []byte) bool {
	if len(word) > shortWordMax {
		return isLongNameWord(word)
	}
	if len(word) == 0 {
		return false
	}
	var upperAfterFirst, lower bool
	for i, c := range word {
		switch {
		case c >= 'A' && c <= 'Z':
			if i > 0 {
				upperAfterFirst = true
			}
		case c >= 'a' && c <= 'z':
			lower = true
		}
	}
	// Majuscules après la première lettre : seulement un mot tout en majuscules.
	return !upperAfterFirst || !lower
}

// shortWordMax : longueur la plus grande d'un mot d'un segment de chemin (« native-binary », « darwin-arm64 »).
const shortWordMax = 12

// longWordMax : longueur la plus grande d'un mot long de nom de dossier (« brainstorming », « autoprotection »,
// « telechargements »).
const longWordMax = 24

// isLongNameWord dit si word, de 13 à 24 caractères, est un mot de nom de dossier fait de lettres seules : en
// minuscules, avec une majuscule initiale, ou en majuscules. Faux positifs relevés sur un Poste réel (xSOM Fleet,
// novembre 2026) : un seul mot de plus de 12 lettres (« brainstorming », « implementation ») faisait de tout le chemin
// un candidat d'entropie. Une suite aléatoire en base64 n'a cette forme qu'avec une probabilité de l'ordre de 10⁻⁵ par
// mot (chaque caractère une lettre de la même casse), et chaque mot du chemin doit l'avoir.
func isLongNameWord(word []byte) bool {
	if len(word) <= shortWordMax || len(word) > longWordMax {
		return false
	}
	var upper, lower int
	for i, c := range word {
		switch {
		case c >= 'A' && c <= 'Z':
			if i > 0 {
				upper++
			}
		case c >= 'a' && c <= 'z':
			lower++
		default:
			return false
		}
	}
	return upper == 0 || lower == 0
}

// isShortWords dit si segment n'est fait que de mots courts séparés par « - » ou « _ » : un nom de dossier
// (« 318-darwin-arm64 », « -Users-nom-Documents-… »), jamais un jeton, dont les suites aléatoires sont plus longues.
func isShortWords(segment []byte) bool {
	for _, word := range bytes.FieldsFunc(segment, func(r rune) bool { return r == '-' || r == '_' }) {
		if len(word) > shortWordMax {
			if !isLongNameWord(word) {
				return false
			}
			continue
		}
		if isMixedToken(word) {
			return false
		}
	}
	return true
}

// isMixedToken dit si word, de 5 caractères au moins, mêle majuscules, minuscules et chiffres : forme d'un morceau de
// jeton (« aB3xK9Lm »), jamais d'un mot de nom de dossier (« Documents », « arm64 »).
func isMixedToken(word []byte) bool {
	if len(word) < 5 {
		return false
	}
	var upper, lower, digit bool
	for _, c := range word {
		switch {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	return upper && lower && digit
}

// slugMinSegments : nombre de tirets au moins d'un nom en tirets écarté (4 segments).
const slugMinSegments = 4

// isWordSlug dit si value est un nom en tirets fait de mots : au moins quatre segments séparés par un seul tiret (un
// tiret en tête admis), chaque segment de 2 à 24 caractères alphanumériques, et au moins la moitié des segments faits
// de lettres seules. Une valeur aléatoire en base64url n'a presque jamais cette forme.
func isWordSlug(value []byte) bool {
	body := bytes.TrimPrefix(value, []byte("-"))
	segments := bytes.Split(body, []byte("-"))
	if len(segments) < slugMinSegments {
		return false
	}
	letters := 0
	for _, segment := range segments {
		if len(segment) < 2 || len(segment) > 24 {
			return false
		}
		alpha := true
		for _, c := range segment {
			if !isASCIIAlphanumeric(c) {
				return false
			}
			if c >= '0' && c <= '9' {
				alpha = false
			}
		}
		if alpha {
			letters++
		}
	}
	return 2*letters >= len(segments)
}
