// SPDX-License-Identifier: Apache-2.0

// Package jstext porte la sémantique des chaînes de JavaScript que partagent le moteur (detect) et l'expurgation
// (module expurgation) : espaces de \s et de trim(), longueur en unités UTF-16. Apache-2.0 : portage de
// secret-guard/packages/core/src/rules.ts, origine et avis dans UPSTREAM.md. Paquet pur (règle depguard de
// .golangci.yml) : seule source de ces deux définitions, pour que l'expurgation compte et découpe exactement comme le
// moteur.
package jstext

import "unicode/utf8"

// IsWhitespace dit si r est un espace de \s et de trim() en JavaScript (WhiteSpace et LineTerminator).
func IsWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x00A0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return 0x2000 <= r && r <= 0x200A
}

// UTF16Units est la longueur de text en unités UTF-16 (String.prototype.length) : un octet hors UTF-8 vaut U+FFFD, une
// unité ; un point de code hors du plan multilingue de base, deux.
func UTF16Units(text []byte) int {
	units := 0
	for i := 0; i < len(text); {
		r, width := utf8.DecodeRune(text[i:])
		if r > 0xFFFF {
			units += 2
		} else {
			units++
		}
		i += width
	}
	return units
}
