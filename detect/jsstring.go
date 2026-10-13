// Sémantique des chaînes et des expressions régulières de JavaScript utilisée par les règles. Apache-2.0 : portage de secret-guard/packages/core/src/rules.ts, origine et avis dans UPSTREAM.md.
//
// Secret Guard manipule des chaînes JavaScript (unités UTF-16) ; les règles portées lisent les octets d'une vue. Ces
// fonctions rendent les opérations de JavaScript dont le résultat dépend de cette différence : espaces de \s et de
// trim(), fins de ligne du drapeau m, toLowerCase(), longueurs en unités UTF-16 (un octet invalide vaut U+FFFD, une
// unité ; un point de code hors du plan multilingue de base, deux).

package detect

import (
	"math"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// isJSWhitespace dit si r est un espace de \s et de trim() en JavaScript (WhiteSpace et LineTerminator).
func isJSWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x00A0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return 0x2000 <= r && r <= 0x200A
}

// isJSLineTerminator dit si r termine une ligne pour ^ et $ du drapeau m de JavaScript.
func isJSLineTerminator(r rune) bool { return r == '\n' || r == '\r' || r == 0x2028 || r == 0x2029 }

// jsTrim retire les espaces de JavaScript aux deux bouts (String.prototype.trim).
func jsTrim(value []byte) []byte {
	start := 0
	for start < len(value) {
		r, width := utf8.DecodeRune(value[start:])
		if !isJSWhitespace(r) {
			break
		}
		start += width
	}
	end := len(value)
	for end > start {
		r, width := utf8.DecodeLastRune(value[start:end])
		if !isJSWhitespace(r) {
			break
		}
		end -= width
	}
	return value[start:end]
}

// isJSBlank dit si value ne contient que des espaces de JavaScript (trim() vide), sans parcourir au-delà du premier
// caractère qui n'en est pas un.
func isJSBlank(value []byte) bool {
	for i := 0; i < len(value); {
		r, width := utf8.DecodeRune(value[i:])
		if !isJSWhitespace(r) {
			return false
		}
		i += width
	}
	return true
}

// utf16Units est la longueur de text en unités UTF-16 (String.prototype.length).
func utf16Units(text []byte) int {
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

// prefixOfUnits rend le nombre d'octets du plus long préfixe de text qui tient en limit unités UTF-16 sans couper
// un point de code (JavaScript couperait une paire de substitution : écart hors du plan multilingue de base).
func prefixOfUnits(text []byte, limit int) int {
	units := 0
	for i := 0; i < len(text); {
		r, width := utf8.DecodeRune(text[i:])
		u := 1
		if r > 0xFFFF {
			u = 2
		}
		if units+u > limit {
			return i
		}
		units += u
		i += width
	}
	return len(text)
}

// jsToLower suit String.prototype.toLowerCase pour la comparaison à un texte ASCII : correspondances simples de
// Unicode, plus la seule correspondance inconditionnelle à plusieurs points de code (U+0130 → « i » et U+0307).
func jsToLower(value []byte) string {
	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); {
		r, width := utf8.DecodeRune(value[i:])
		if r == 0x0130 {
			b.WriteString("i\u0307")
		} else {
			b.WriteRune(unicode.ToLower(r))
		}
		i += width
	}
	return b.String()
}

// jsLineStart dit si ^ du drapeau m de JavaScript reconnaît la position at de text.
func jsLineStart(text []byte, at int) bool {
	if at == 0 {
		return true
	}
	r, _ := utf8.DecodeLastRune(text[:at])
	return isJSLineTerminator(r)
}

// wordBoundaryBefore dit si \b de JavaScript reconnaît la position at de text, sachant que le caractère en at est un
// caractère de mot ASCII.
func wordBoundaryBefore(text []byte, at int) bool { return at == 0 || !isWordByte(text[at-1]) }

// nextRune rend la position du caractère qui suit celui en at.
func nextRune(text []byte, at int) int {
	_, width := utf8.DecodeRune(text[at:])
	return at + width
}

// startCondition décrit l'assertion de début d'un motif pour execFrom. RE2, lancé sur text[at:], lit le début de la
// sous-tranche comme le début du texte (^ et \b sans contexte) ; JavaScript, reprenant sa recherche exactement en at
// (lastIndex), lit le caractère qui précède.
type startCondition interface {
	// admits dit si une correspondance de RE2 qui commence exactement en at (> 0) est aussi une correspondance de
	// JavaScript.
	admits(text []byte, at int) bool
	// next rend la première position après at où JavaScript peut commencer une correspondance et où RE2, lancé sur la
	// sous-tranche, lit l'assertion comme JavaScript ; len(text) s'il n'y en a pas.
	next(text []byte, at int) int
}

// lineStartOr : motif (?m)(?:^|[classe])… dont la suite ne commence par aucun caractère de la classe (ou le consomme
// au même effet) : RE2 a pris ^ (admis seulement si at est un début de ligne de JavaScript) ou la classe (toujours
// admise). Toute fin de ligne de JavaScript est dans la classe : la prochaine position possible est le prochain
// caractère de la classe.
type lineStartOr func(rune) bool

func (inClass lineStartOr) admits(text []byte, at int) bool {
	if jsLineStart(text, at) {
		return true
	}
	r, _ := utf8.DecodeRune(text[at:])
	return inClass(r)
}

func (inClass lineStartOr) next(text []byte, at int) int {
	for i := nextRune(text, at); i < len(text); {
		r, width := utf8.DecodeRune(text[i:])
		if inClass(r) {
			return i
		}
		i += width
	}
	return len(text)
}

// wordStart : motif \b suivi d'un caractère de mot ASCII.
type wordStart struct{}

func (wordStart) admits(text []byte, at int) bool { return wordBoundaryBefore(text, at) }

func (wordStart) next(text []byte, at int) int {
	for i := at + 1; i < len(text); i++ {
		if isWordByte(text[i]) && !isWordByte(text[i-1]) {
			return i
		}
	}
	return len(text)
}

// execFrom rend la première correspondance de re à partir de l'octet from, comme RegExp.prototype.exec de
// JavaScript avec lastIndex = from (les positions des groupes sont des octets de text). start décrit l'assertion de
// début du motif ; nil : motif sans assertion de début. Une correspondance que JavaScript n'admettrait pas en from
// relance la recherche à la prochaine position possible (au plus une fois : la recherche relancée lit l'assertion
// comme JavaScript).
func execFrom(re *regexp.Regexp, text []byte, from int, start startCondition) []int {
	for from <= len(text) {
		m := re.FindSubmatchIndex(text[from:])
		if m == nil {
			return nil
		}
		if m[0] == 0 && from > 0 && start != nil && !start.admits(text, from) {
			if from >= len(text) {
				return nil
			}
			from = start.next(text, from)
			continue
		}
		for i := range m {
			if m[i] >= 0 {
				m[i] += from
			}
		}
		return m
	}
	return nil
}

// Constantes de __ieee754_log2 (FreeBSD e_log2.c, k_log.h), l'implémentation de Math.log2 du moteur V8.
const (
	log2Two54  = 1.80143985094819840000e+16
	log2IvLn2H = 1.44269504072144627571e+00
	log2IvLn2L = 1.67517131648865118353e-10
	log2Lg1    = 6.666666666666735130e-01
	log2Lg2    = 3.999999999940941908e-01
	log2Lg3    = 2.857142874366239149e-01
	log2Lg4    = 2.222219843214978396e-01
	log2Lg5    = 1.818357216161805012e-01
	log2Lg6    = 1.531383769920937332e-01
	log2Lg7    = 1.479819860511658591e-01
)

// jsLog2 est Math.log2 de JavaScript (V8 : portage de FreeBSD e_log2.c), au bit près pour 0 < x ≤ 1, seul usage
// (probabilités de shannonEntropy) : un écart d'un bit avec math.Log2 changerait la comparaison au seuil d'entropie.
// Chaque produit est converti explicitement en float64, ce qui interdit au compilateur de le fusionner avec une
// addition (FMA sur arm64), comme V8 qui n'en fusionne aucun.
func jsLog2(x float64) float64 {
	bits := math.Float64bits(x)
	hx := int32(bits >> 32)
	lx := uint32(bits)
	k := int32(0)
	if hx < 0x00100000 {
		if (hx&0x7fffffff)|int32(lx) == 0 {
			return math.Inf(-1)
		}
		if hx < 0 {
			return math.NaN()
		}
		k -= 54
		x = float64(x * log2Two54)
		hx = int32(math.Float64bits(x) >> 32)
	}
	if hx >= 0x7ff00000 {
		return x + x
	}
	if hx == 0x3ff00000 && lx == 0 {
		return 0
	}
	k += (hx >> 20) - 1023
	hx &= 0x000fffff
	i := (hx + 0x95f64) & 0x100000
	x = math.Float64frombits(uint64(uint32(hx|(i^0x3ff00000)))<<32 | math.Float64bits(x)&0xffffffff)
	k += i >> 20
	y := float64(k)
	f := x - 1.0
	hfsq := float64(float64(0.5*f) * f)
	r := kLog1p(f)
	hi := f - hfsq
	hi = math.Float64frombits(math.Float64bits(hi) &^ 0xffffffff)
	lo := (f - hi) - hfsq + r
	valHi := float64(hi * log2IvLn2H)
	valLo := float64((lo+hi)*log2IvLn2L) + float64(lo*log2IvLn2H)
	w := y + valHi
	valLo += (y - w) + valHi
	valHi = w
	return valLo + valHi
}

// kLog1p est k_log1p de FreeBSD k_log.h.
func kLog1p(f float64) float64 {
	s := f / (2.0 + f)
	z := float64(s * s)
	w := float64(z * z)
	t1 := float64(w * (log2Lg2 + float64(w*(log2Lg4+float64(w*log2Lg6)))))
	t2 := float64(z * (log2Lg1 + float64(w*(log2Lg3+float64(w*(log2Lg5+float64(w*log2Lg7)))))))
	r := t2 + t1
	hfsq := float64(float64(0.5*f) * f)
	return float64(s * (hfsq + r))
}
