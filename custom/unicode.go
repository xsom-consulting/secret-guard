// Sémantique Unicode de JavaScript utilisée par les termes confidentiels : classes de mots \p{L}\p{N}\p{M},
// String.prototype.toLowerCase (règle Final_Sigma comprise) et propriété Default_Ignorable_Code_Point du texte
// visible. Les tables de la bibliothèque standard de Go 1.27 et de golang.org/x/text sont en Unicode 17.0.0, comme
// Node 26 (ICU 78) ; vectors/custom-unicode.json et vectors/unicode-parity.json figent ce que calcule Node.

package custom

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// isWordRune dit si r appartient à \p{L}, \p{N} ou \p{M} (WORD_PATTERN de l'origine).
func isWordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsMark(r) }

// wordBreakIgnorable : valeurs MidLetter, MidNumLet et Single_Quote de Word_Break (Unicode 17.0.0), qui entrent dans
// Case_Ignorable.
var wordBreakIgnorable = map[rune]bool{
	0x0027: true,                                                                                     // Single_Quote
	0x002E: true, 0x2018: true, 0x2019: true, 0x2024: true, 0xFE52: true, 0xFF07: true, 0xFF0E: true, // MidNumLet
	0x003A: true, 0x00B7: true, 0x0387: true, 0x055F: true, 0x05F4: true, 0x2027: true, 0xFE13: true, 0xFE55: true,
	0xFF1A: true, // MidLetter
}

// isCaseIgnorable est la propriété Case_Ignorable : Mn, Me, Cf, Lm, Sk, et Word_Break MidLetter, MidNumLet ou
// Single_Quote.
func isCaseIgnorable(r rune) bool {
	return unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf, unicode.Lm, unicode.Sk) || wordBreakIgnorable[r]
}

// isCased est la propriété Cased : Lu, Ll, Lt, Other_Lowercase, Other_Uppercase.
func isCased(r rune) bool {
	return unicode.In(r, unicode.Lu, unicode.Ll, unicode.Lt, unicode.Other_Lowercase, unicode.Other_Uppercase)
}

// casedNeighbour lit, depuis runes[at] dans le sens step, les caractères ignorables de la casse, comme ICU
// (isFollowedByCasedLetter) : un caractère ignorable est sauté même s'il a une casse ; le premier autre décide.
func casedNeighbour(runes []rune, at, step int) bool {
	for i := at; i >= 0 && i < len(runes); i += step {
		r := runes[i]
		if isCaseIgnorable(r) {
			continue
		}
		return isCased(r)
	}
	return false
}

// jsToLower suit String.prototype.toLowerCase de V8 (u_strToLower d'ICU, locale racine) : correspondances simples
// de Unicode, U+0130 → « i » et U+0307 (seule correspondance inconditionnelle à plusieurs points de code), et sigma
// final (U+03A3 → U+03C2 après une lettre à casse, sans lettre à casse après, caractères ignorables sautés).
func jsToLower(value string) string {
	runes := []rune(value)
	var b strings.Builder
	b.Grow(len(value))
	for i, r := range runes {
		switch r {
		case 0x0130:
			b.WriteString("i\u0307")
		case 0x03A3:
			if casedNeighbour(runes, i-1, -1) && !casedNeighbour(runes, i+1, 1) {
				b.WriteRune(0x03C2)
			} else {
				b.WriteRune(0x03C3)
			}
		default:
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// defaultIgnorable est la propriété Default_Ignorable_Code_Point, Unicode 17.0.0 : mêmes plages que la table de
// detect (tools/unicodetables) et que Node (vectors/unicode-parity.json, test TestCustomUnicodeTables).
var defaultIgnorable = &unicode.RangeTable{
	R16: []unicode.Range16{
		{Lo: 0x00AD, Hi: 0x00AD, Stride: 1},
		{Lo: 0x034F, Hi: 0x034F, Stride: 1},
		{Lo: 0x061C, Hi: 0x061C, Stride: 1},
		{Lo: 0x115F, Hi: 0x1160, Stride: 1},
		{Lo: 0x17B4, Hi: 0x17B5, Stride: 1},
		{Lo: 0x180B, Hi: 0x180F, Stride: 1},
		{Lo: 0x200B, Hi: 0x200F, Stride: 1},
		{Lo: 0x202A, Hi: 0x202E, Stride: 1},
		{Lo: 0x2060, Hi: 0x206F, Stride: 1},
		{Lo: 0x3164, Hi: 0x3164, Stride: 1},
		{Lo: 0xFE00, Hi: 0xFE0F, Stride: 1},
		{Lo: 0xFEFF, Hi: 0xFEFF, Stride: 1},
		{Lo: 0xFFA0, Hi: 0xFFA0, Stride: 1},
		{Lo: 0xFFF0, Hi: 0xFFF8, Stride: 1},
	},
	R32: []unicode.Range32{
		{Lo: 0x1BCA0, Hi: 0x1BCA3, Stride: 1},
		{Lo: 0x1D173, Hi: 0x1D17A, Stride: 1},
		{Lo: 0xE0000, Hi: 0xE0FFF, Stride: 1},
	},
	LatinOffset: 1,
}

// utf16Units est la longueur de text en unités UTF-16 (String.prototype.length) : un octet hors séquence UTF-8
// valide vaut U+FFFD (une unité), un point de code hors du plan multilingue de base, deux.
func utf16Units(text []byte) int {
	units := 0
	for i := 0; i < len(text); {
		r, width := utf8.DecodeRune(text[i:])
		units++
		if r > 0xFFFF {
			units++
		}
		i += width
	}
	return units
}

// ceilDiv rend ⌈n / d⌉ pour n ≥ 0 (Math.ceil(n / d) de l'origine).
func ceilDiv(n, d int) int64 { return int64((n + d - 1) / d) }
