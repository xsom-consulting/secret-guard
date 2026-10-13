// Motifs sûrs du Pack de règles du client (docs/custom-pack.md, §3).
//
// Portage en Go de secret-guard/packages/core/src/custom/pattern.ts (Apache-2.0, origine, avis et modifications dans
// UPSTREAM.md). Le motif est lu en arbre et validé avec les codes du contrat, dans l'ordre de l'origine ; il est
// ensuite traduit en RE2 (regexp de Go, temps linéaire) au lieu d'être exécuté par un automate à retour arrière
// compté. La traduction rend exactement les correspondances d'ECMAScript (matchAll sans drapeau u), seule sémantique
// de référence du contrat :
//
//   - \d, \w, \s et chaque classe deviennent des classes explicites d'octets ASCII ; le drapeau caseInsensitive replie
//     les seules lettres ASCII (jamais (?i) de RE2, qui replie aussi K, ſ et le signe kelvin) ;
//   - ECMAScript refuse l'itération vide d'un quantificateur de minimum 0 (RepeatMatcher) : (?:a?|b)? reconnaît « b »
//     en ECMAScript, rien en RE2. Un groupe optionnel dont le contenu peut être vide est donc réécrit en l'alternative
//     ordonnée de ses seuls chemins non vides (nonEmptyPieces), ce qui garde l'ordre de préférence d'ECMAScript.
//
// Les autres constructions admises (classes, groupes non capturants, alternatives, quantificateurs bornés gloutons)
// ont la même sémantique « la plus à gauche, premier choix d'abord » en RE2 et en ECMAScript.

package custom

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ErrInvalidPattern : le motif n'appartient pas au sous-ensemble sûr du §3. Toute erreur de ValidatePattern
// l'enveloppe (errors.Is).
var ErrInvalidPattern = errors.New("motif refusé")

// PatternErrorCode est le code, en liste fermée, d'un motif refusé (PatternError du contrat).
type PatternErrorCode string

// Codes d'un motif refusé, dans l'ordre du contrat.
const (
	PatternLength              PatternErrorCode = "length"
	PatternInvalidCharacter    PatternErrorCode = "invalid_character"
	PatternEmptyAlternative    PatternErrorCode = "empty_alternative"
	PatternTooDeep             PatternErrorCode = "too_deep"
	PatternEmptyClass          PatternErrorCode = "empty_class"
	PatternNegatedClass        PatternErrorCode = "negated_class"
	PatternBadClassChar        PatternErrorCode = "bad_class_char"
	PatternBadRange            PatternErrorCode = "bad_range"
	PatternBadEscape           PatternErrorCode = "bad_escape"
	PatternDotNotAllowed       PatternErrorCode = "dot_not_allowed"
	PatternAnchorNotAllowed    PatternErrorCode = "anchor_not_allowed"
	PatternGroupNotAllowed     PatternErrorCode = "group_not_allowed"
	PatternUnboundedQuantifier PatternErrorCode = "unbounded_quantifier"
	PatternDanglingQuantifier  PatternErrorCode = "dangling_quantifier"
	PatternStackedQuantifier   PatternErrorCode = "stacked_quantifier"
	PatternBadQuantifier       PatternErrorCode = "bad_quantifier"
	PatternUnbalancedClass     PatternErrorCode = "unbalanced_class"
	PatternUnbalancedGroup     PatternErrorCode = "unbalanced_group"
	PatternBadLiteral          PatternErrorCode = "bad_literal"
	PatternNestedRepetition    PatternErrorCode = "nested_repetition"
	PatternTooShort            PatternErrorCode = "too_short"
	PatternTooLong             PatternErrorCode = "too_long"
	PatternNoAnchor            PatternErrorCode = "no_anchor"
)

// PatternErrorCodes rend la liste fermée des codes d'un motif refusé, dans l'ordre du contrat.
func PatternErrorCodes() []PatternErrorCode {
	return []PatternErrorCode{
		PatternLength, PatternInvalidCharacter, PatternEmptyAlternative, PatternTooDeep, PatternEmptyClass,
		PatternNegatedClass, PatternBadClassChar, PatternBadRange, PatternBadEscape, PatternDotNotAllowed,
		PatternAnchorNotAllowed, PatternGroupNotAllowed, PatternUnboundedQuantifier, PatternDanglingQuantifier,
		PatternStackedQuantifier, PatternBadQuantifier, PatternUnbalancedClass, PatternUnbalancedGroup,
		PatternBadLiteral, PatternNestedRepetition, PatternTooShort, PatternTooLong, PatternNoAnchor,
	}
}

// PatternError est le refus typé d'un motif : son code seulement, jamais le motif.
type PatternError struct {
	Code PatternErrorCode
}

func (e *PatternError) Error() string { return ErrInvalidPattern.Error() + " (" + string(e.Code) + ")" }

// Unwrap rattache le refus à ErrInvalidPattern.
func (e *PatternError) Unwrap() error { return ErrInvalidPattern }

const (
	maxPatternLength = 256
	maxGroupDepth    = 4
	maxBound         = 64
	minMatchLength   = 3
	maxMatchLength   = 256
	minAnchorLength  = 3
)

// escapable : caractères que « \ » rend littéraux, dans une classe comme hors d'une classe.
const escapable = `\^$.|?*+()[]{}-/`

var (
	digitCodes = codeRange('0', '9')
	wordCodes  = append(append(append(codeRange('A', 'Z'), codeRange('a', 'z')...), digitCodes...), '_')
	// Espaces ASCII seulement : \s de JavaScript admet aussi l'espace insécable et les espaces Unicode.
	spaceCodes = []byte{' ', '\t', '\n', '\r', '\f', '\v'}
)

func codeRange(from, to byte) []byte {
	out := make([]byte, 0, int(to-from)+1)
	for c := int(from); c <= int(to); c++ {
		out = append(out, byte(c))
	}
	return out
}

// atom est un atome du motif : un caractère (codes ASCII admis, sans repliement) ou un groupe non capturant.
type atom struct {
	// group : alternatives d'un groupe ; nil pour un caractère.
	group [][]term
	// codes : codes ASCII admis par un caractère (non repliés).
	codes []byte
	// literal : caractère littéral, simple ou échappé (candidat à l'ancre).
	literal bool
}

func (a atom) isGroup() bool { return a.group != nil }

type term struct {
	atom       atom
	min, max   int
	quantified bool
}

// patternFailure est levée par le lecteur et rattrapée par parsePattern (throw de l'origine).
type patternFailure struct{ code PatternErrorCode }

func failPattern(code PatternErrorCode) { panic(patternFailure{code}) }

type patternParser struct {
	source   string
	position int
	depth    int
}

// peek rend le caractère à position + offset, ou -1 au-delà de la fin.
func (p *patternParser) peek(offset int) int {
	at := p.position + offset
	if at >= len(p.source) {
		return -1
	}
	return int(p.source[at])
}

func (p *patternParser) parse() [][]term {
	alternatives := p.alternatives()
	// La suite de premier niveau ne s'arrête tôt que sur une « ) » sans pendant.
	if p.position < len(p.source) {
		failPattern(PatternUnbalancedGroup)
	}
	return alternatives
}

func (p *patternParser) alternatives() [][]term {
	alternatives := [][]term{p.sequence()}
	for p.peek(0) == '|' {
		p.position++
		alternatives = append(alternatives, p.sequence())
	}
	return alternatives
}

func (p *patternParser) sequence() []term {
	var terms []term
	for {
		next := p.peek(0)
		if next == -1 || next == '|' {
			break
		}
		if next == ')' {
			if p.depth == 0 {
				failPattern(PatternUnbalancedGroup)
			}
			break
		}
		terms = append(terms, p.term())
	}
	if len(terms) == 0 {
		failPattern(PatternEmptyAlternative)
	}
	return terms
}

func (p *patternParser) term() term {
	a := p.atom()
	t := term{atom: a, min: 1, max: 1}
	switch p.peek(0) {
	case '?':
		p.position++
		t.min, t.quantified = 0, true
	case '*', '+':
		failPattern(PatternUnboundedQuantifier)
	case '{':
		t.min, t.max = p.braces()
		t.quantified = true
	}
	if t.quantified {
		if a.isGroup() && t.max > 1 && repeatsOrBranches(a.group) {
			failPattern(PatternNestedRepetition)
		}
		switch p.peek(0) {
		case '?', '*', '+', '{':
			failPattern(PatternStackedQuantifier)
		}
	}
	return t
}

func (p *patternParser) atom() atom {
	character := p.peek(0)
	switch character {
	case '(':
		return p.groupAtom()
	case '[':
		return p.characterClass()
	case '\\':
		return p.escape()
	case '.':
		failPattern(PatternDotNotAllowed)
	case '^', '$':
		failPattern(PatternAnchorNotAllowed)
	case '*', '+':
		failPattern(PatternUnboundedQuantifier)
	case '?', '{':
		failPattern(PatternDanglingQuantifier)
	case ']', '}':
		failPattern(PatternBadLiteral)
	}
	p.position++
	return atom{codes: []byte{byte(character)}, literal: true}
}

func (p *patternParser) groupAtom() atom {
	if !strings.HasPrefix(p.source[p.position:], "(?:") {
		failPattern(PatternGroupNotAllowed)
	}
	if p.depth+1 > maxGroupDepth {
		failPattern(PatternTooDeep)
	}
	p.position += 3
	p.depth++
	alternatives := p.alternatives()
	if p.peek(0) != ')' {
		failPattern(PatternUnbalancedGroup)
	}
	p.position++
	p.depth--
	return atom{group: alternatives}
}

func (p *patternParser) escape() atom {
	escaped := p.peek(1)
	if escaped == -1 {
		failPattern(PatternBadEscape)
	}
	p.position += 2
	switch escaped {
	case 'd':
		return atom{codes: digitCodes}
	case 'w':
		return atom{codes: wordCodes}
	case 's':
		return atom{codes: spaceCodes}
	}
	if !strings.ContainsRune(escapable, rune(escaped)) {
		failPattern(PatternBadEscape)
	}
	return atom{codes: []byte{byte(escaped)}, literal: true}
}

func (p *patternParser) characterClass() atom {
	p.position++
	if p.peek(0) == '^' {
		failPattern(PatternNegatedClass)
	}
	if p.peek(0) == ']' {
		failPattern(PatternEmptyClass)
	}
	var codes []byte
	for {
		next := p.peek(0)
		if next == -1 {
			failPattern(PatternUnbalancedClass)
		}
		if next == ']' {
			p.position++
			break
		}
		lower := p.classMember()
		if len(lower) == 1 && p.peek(0) == '-' && p.peek(1) != -1 && p.peek(1) != ']' {
			p.position++
			upper := p.classMember()
			if len(upper) != 1 {
				failPattern(PatternBadClassChar)
			}
			if upper[0] < lower[0] {
				failPattern(PatternBadRange)
			}
			codes = append(codes, codeRange(lower[0], upper[0])...)
		} else {
			codes = append(codes, lower...)
		}
	}
	return atom{codes: codes}
}

// classMember lit un membre de classe : un caractère (longueur 1) ou une classe ASCII.
func (p *patternParser) classMember() []byte {
	character := p.peek(0)
	if character == -1 {
		failPattern(PatternUnbalancedClass)
	}
	if character == '\\' {
		escaped := p.peek(1)
		if escaped == -1 {
			failPattern(PatternBadEscape)
		}
		p.position += 2
		switch escaped {
		case 'd':
			return digitCodes
		case 'w':
			return wordCodes
		case 's':
			return spaceCodes
		}
		if !strings.ContainsRune(escapable, rune(escaped)) {
			failPattern(PatternBadEscape)
		}
		return []byte{byte(escaped)}
	}
	if character == '[' || character == '^' || character == '-' {
		failPattern(PatternBadClassChar)
	}
	p.position++
	return []byte{byte(character)}
}

func (p *patternParser) braces() (int, int) {
	p.position++
	minimum, ok := p.number()
	if !ok {
		failPattern(PatternBadQuantifier)
	}
	if p.peek(0) == '}' {
		p.position++
		if minimum < 1 || minimum > maxBound {
			failPattern(PatternBadQuantifier)
		}
		return minimum, minimum
	}
	if p.peek(0) != ',' {
		failPattern(PatternBadQuantifier)
	}
	p.position++
	if p.peek(0) == '}' {
		failPattern(PatternUnboundedQuantifier)
	}
	maximum, ok := p.number()
	if !ok || p.peek(0) != '}' {
		failPattern(PatternBadQuantifier)
	}
	p.position++
	if maximum < 1 || maximum > maxBound || minimum > maximum {
		failPattern(PatternBadQuantifier)
	}
	return minimum, maximum
}

// number lit « 0 | [1-9][0-9]{0,2} » ; tout autre texte n'est pas une borne.
func (p *patternParser) number() (int, bool) {
	first := p.peek(0)
	if first == '0' {
		p.position++
		return 0, true
	}
	if first < '1' || first > '9' {
		return 0, false
	}
	value, digits := 0, 0
	for {
		digit := p.peek(0)
		if digit < '0' || digit > '9' || digits == 3 {
			break
		}
		value = value*10 + digit - '0'
		digits++
		p.position++
	}
	return value, true
}

func repeatsOrBranches(alternatives [][]term) bool {
	if len(alternatives) > 1 {
		return true
	}
	for _, terms := range alternatives {
		for _, t := range terms {
			if t.quantified || (t.atom.isGroup() && repeatsOrBranches(t.atom.group)) {
				return true
			}
		}
	}
	return false
}

func minimumLength(alternatives [][]term) int {
	best := -1
	for _, terms := range alternatives {
		total := 0
		for _, t := range terms {
			unit := 1
			if t.atom.isGroup() {
				unit = minimumLength(t.atom.group)
			}
			total += t.min * unit
		}
		if best < 0 || total < best {
			best = total
		}
	}
	return best
}

func maximumLength(alternatives [][]term) int {
	best := 0
	for _, terms := range alternatives {
		total := 0
		for _, t := range terms {
			unit := 1
			if t.atom.isGroup() {
				unit = maximumLength(t.atom.group)
			}
			total += t.max * unit
		}
		best = max(best, total)
	}
	return best
}

// patternAnchor est un texte littéral que toute correspondance contient (minuscules ASCII si le motif ignore la
// casse), à une distance du début de la correspondance comprise dans [offsetMin, offsetMax].
type patternAnchor struct {
	text                 []byte
	offsetMin, offsetMax int
}

// findAnchor rend la plus longue suite de premier niveau de littéraux non quantifiés, de 3 caractères au moins.
func findAnchor(alternatives [][]term, caseInsensitive bool) *patternAnchor {
	if len(alternatives) != 1 {
		return nil
	}
	terms := alternatives[0]
	bestStart, bestLength := -1, 0
	for index := 0; index < len(terms); {
		length := 0
		for index+length < len(terms) {
			t := terms[index+length]
			if t.quantified || t.atom.isGroup() || !t.atom.literal {
				break
			}
			length++
		}
		if length >= minAnchorLength && bestLength < length {
			bestStart, bestLength = index, length
		}
		index += max(1, length)
	}
	if bestStart < 0 {
		return nil
	}
	prefix := [][]term{terms[:bestStart]}
	text := make([]byte, 0, bestLength)
	for _, t := range terms[bestStart : bestStart+bestLength] {
		text = append(text, t.atom.codes[0])
	}
	if caseInsensitive {
		text = asciiLower(text)
	}
	return &patternAnchor{text: text, offsetMin: minimumLength(prefix), offsetMax: maximumLength(prefix)}
}

// asciiLower rend une copie de value aux seules lettres ASCII mises en minuscules (même longueur).
func asciiLower(value []byte) []byte {
	out := make([]byte, len(value))
	for i, c := range value {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// safePattern est un motif validé, traduit en RE2.
type safePattern struct {
	// re reconnaît exactement les correspondances d'ECMAScript (voir l'en-tête du fichier).
	re *regexp.Regexp
	// key identifie la traduction : deux détecteurs de même motif et même casse partagent leurs correspondances.
	key             string
	caseInsensitive bool
	anchor          *patternAnchor
	// first : octets qui peuvent commencer une correspondance.
	first     [256]bool
	maxLength int
	// states est le nombre de caractères du motif traduit, répétitions développées : borne du nombre d'états de
	// l'automate de RE2, base du coût de travail d'une recherche (cost.go).
	states int
}

// ValidatePattern valide un motif du §3 ; hasContext dit si le détecteur porte un contexte (qui dispense de
// l'ancre), caseInsensitive s'il ignore la casse des lettres ASCII. Rend nil pour un motif valide, sinon un
// *PatternError (errors.Is(err, ErrInvalidPattern)) dont le code suit l'ordre des contrôles du contrat.
func ValidatePattern(pattern string, hasContext, caseInsensitive bool) error {
	if _, failure := compilePattern(pattern, hasContext, caseInsensitive); failure != "" {
		return &PatternError{Code: failure}
	}
	return nil
}

// compilePattern valide et traduit un motif ; rend le code du refus, vide pour un motif valide.
func compilePattern(source string, hasContext, caseInsensitive bool) (*safePattern, PatternErrorCode) {
	if count := utf8.RuneCountInString(source); count < 1 || count > maxPatternLength {
		return nil, PatternLength
	}
	for i := 0; i < len(source); i++ {
		if source[i] < 0x20 || source[i] > 0x7e {
			return nil, PatternInvalidCharacter
		}
	}
	alternatives, failure := parsePattern(source)
	if failure != "" {
		return nil, failure
	}
	minimum, maximum := minimumLength(alternatives), maximumLength(alternatives)
	if minimum < minMatchLength {
		return nil, PatternTooShort
	}
	if maximum > maxMatchLength {
		return nil, PatternTooLong
	}
	anchor := findAnchor(alternatives, caseInsensitive)
	if anchor == nil && !hasContext {
		return nil, PatternNoAnchor
	}
	translation := translator{caseInsensitive: caseInsensitive}.alternatives(alternatives)
	key := translation.src
	re, err := regexp.Compile(key)
	if err != nil {
		// Toute traduction d'un motif valide est une expression RE2 : une erreur ici est un défaut du traducteur.
		panic("custom : traduction RE2 refusée")
	}
	p := &safePattern{
		re: re, key: key, caseInsensitive: caseInsensitive, anchor: anchor, maxLength: maximum,
		states: max(1, translation.states),
	}
	firstSet(alternatives, caseInsensitive, &p.first)
	return p, ""
}

func parsePattern(source string) (alternatives [][]term, failure PatternErrorCode) {
	defer func() {
		if recovered := recover(); recovered != nil {
			refusal, ok := recovered.(patternFailure)
			if !ok {
				panic(recovered)
			}
			alternatives, failure = nil, refusal.code
		}
	}()
	parser := &patternParser{source: source}
	return parser.parse(), ""
}

// foldedCodes rend l'ensemble des octets admis par un caractère : ses codes et, si le motif ignore la casse, la
// lettre ASCII de l'autre casse (repliement d'ECMAScript sans drapeau u, réduit à ASCII).
func foldedCodes(codes []byte, caseInsensitive bool) [128]bool {
	var set [128]bool
	for _, c := range codes {
		set[c] = true
		if !caseInsensitive {
			continue
		}
		if 'A' <= c && c <= 'Z' {
			set[c+'a'-'A'] = true
		}
		if 'a' <= c && c <= 'z' {
			set[c-('a'-'A')] = true
		}
	}
	return set
}

// firstSet ajoute à into chaque octet qui peut commencer une correspondance ; rend vrai si les alternatives peuvent
// aussi reconnaître le texte vide.
func firstSet(alternatives [][]term, caseInsensitive bool, into *[256]bool) bool {
	nullable := false
	for _, terms := range alternatives {
		sequenceNullable := true
		for _, t := range terms {
			atomNullable := false
			if t.atom.isGroup() {
				atomNullable = firstSet(t.atom.group, caseInsensitive, into)
			} else {
				set := foldedCodes(t.atom.codes, caseInsensitive)
				for c, ok := range set {
					if ok {
						into[c] = true
					}
				}
			}
			if !atomNullable && t.min != 0 {
				sequenceNullable = false
				break
			}
		}
		if sequenceNullable {
			nullable = true
		}
	}
	return nullable
}

// translator écrit un arbre de motif en syntaxe RE2.
type translator struct {
	caseInsensitive bool
}

// rx est une expression RE2 écrite par translator et son nombre d'états : caractères de l'expression, répétitions
// développées (chaque classe ou octet compte pour la borne haute de ses répétitions).
type rx struct {
	src    string
	states int
}

// charClass écrit l'ensemble d'octets d'un caractère : \xHH pour un seul octet, sinon une classe d'intervalles
// \xHH-\xHH (aucun caractère du motif n'est recopié tel quel : aucune interprétation propre à RE2).
func (tr translator) charClass(codes []byte) string {
	set := foldedCodes(codes, tr.caseInsensitive)
	var parts []string
	count := 0
	for c := 0; c < 128; {
		if !set[c] {
			c++
			continue
		}
		start := c
		for c < 128 && set[c] {
			c++
		}
		count += c - start
		if c-1 == start {
			parts = append(parts, hexByte(start))
		} else {
			parts = append(parts, hexByte(start)+"-"+hexByte(c-1))
		}
	}
	if count == 1 {
		return parts[0]
	}
	return "[" + strings.Join(parts, "") + "]"
}

func hexByte(c int) string {
	const digits = "0123456789ABCDEF"
	return `\x` + string(digits[c>>4]) + string(digits[c&0xf])
}

func quantifier(minimum, maximum int) string {
	switch {
	case minimum == 1 && maximum == 1:
		return ""
	case minimum == 0 && maximum == 1:
		return "?"
	case minimum == maximum:
		return "{" + strconv.Itoa(minimum) + "}"
	}
	return "{" + strconv.Itoa(minimum) + "," + strconv.Itoa(maximum) + "}"
}

func join(parts []rx) rx {
	out := rx{}
	sources := make([]string, len(parts))
	for i, part := range parts {
		sources[i] = part.src
		out.states += part.states
	}
	out.src = strings.Join(sources, "|")
	return out
}

func (tr translator) alternatives(alternatives [][]term) rx {
	parts := make([]rx, len(alternatives))
	for i, terms := range alternatives {
		parts[i] = tr.sequence(terms)
	}
	return join(parts)
}

func (tr translator) sequence(terms []term) rx {
	var b strings.Builder
	states := 0
	for _, t := range terms {
		written := tr.term(t)
		b.WriteString(written.src)
		states += written.states
	}
	return rx{src: b.String(), states: states}
}

// term écrit un terme. Seul cas réécrit : le groupe optionnel ((?:…)? ou (?:…){0,1}) dont le contenu peut être vide,
// remplacé par l'alternative ordonnée de ses chemins non vides (ECMAScript refuse l'itération vide).
func (tr translator) term(t term) rx {
	if !t.atom.isGroup() {
		return rx{src: tr.charClass(t.atom.codes) + quantifier(t.min, t.max), states: t.max}
	}
	if t.min == 0 && t.max == 1 && nullableAlternatives(t.atom.group) {
		inner := join(tr.nonEmptyPieces(t.atom.group))
		return rx{src: "(?:" + inner.src + ")?", states: inner.states}
	}
	inner := tr.alternatives(t.atom.group)
	return rx{src: "(?:" + inner.src + ")" + quantifier(t.min, t.max), states: inner.states * t.max}
}

func nullableTerm(t term) bool {
	return t.min == 0 || (t.atom.isGroup() && nullableAlternatives(t.atom.group))
}

func nullableSequence(terms []term) bool {
	for _, t := range terms {
		if !nullableTerm(t) {
			return false
		}
	}
	return true
}

func nullableAlternatives(alternatives [][]term) bool {
	for _, terms := range alternatives {
		if nullableSequence(terms) {
			return true
		}
	}
	return false
}

// piece est un morceau de l'ordre des chemins d'ECMAScript : une expression RE2 qui ne reconnaît que des textes non
// vides, ou le chemin vide (empty).
type piece struct {
	rx
	empty bool
}

// nonEmptyPieces rend les chemins non vides des alternatives, dans l'ordre de préférence d'ECMAScript.
func (tr translator) nonEmptyPieces(alternatives [][]term) []rx {
	var out []rx
	for _, p := range tr.alternativePieces(alternatives) {
		if !p.empty {
			out = append(out, p.rx)
		}
	}
	return out
}

// alternativePieces découpe l'ordre des chemins des alternatives : les morceaux de chaque alternative, dans l'ordre.
func (tr translator) alternativePieces(alternatives [][]term) []piece {
	var out []piece
	for _, terms := range alternatives {
		out = append(out, tr.sequencePieces(terms)...)
	}
	return out
}

// sequencePieces découpe l'ordre des chemins d'une suite : pour chaque morceau de son premier terme, ce morceau suivi
// du reste (morceau non vide), ou les morceaux du reste (morceau vide).
func (tr translator) sequencePieces(terms []term) []piece {
	if len(terms) == 0 {
		return []piece{{empty: true}}
	}
	if !nullableSequence(terms) {
		return []piece{{rx: tr.sequence(terms)}}
	}
	rest := tr.sequence(terms[1:])
	var out []piece
	for _, p := range tr.termPieces(terms[0]) {
		if p.empty {
			out = append(out, tr.sequencePieces(terms[1:])...)
			continue
		}
		out = append(out, piece{rx: rx{src: "(?:" + p.src + ")" + rest.src, states: p.states + rest.states}})
	}
	return out
}

// termPieces découpe l'ordre des chemins d'un terme qui peut être vide.
func (tr translator) termPieces(t term) []piece {
	if !nullableTerm(t) {
		return []piece{{rx: tr.term(t)}}
	}
	if !t.atom.isGroup() {
		// Caractère de minimum 0, glouton : de max à 1 répétitions, puis aucune.
		return []piece{{rx: rx{src: tr.charClass(t.atom.codes) + quantifier(1, t.max), states: t.max}}, {empty: true}}
	}
	if t.max > 1 {
		// Groupe répété : contenu de longueur fixe non nulle (ni quantificateur ni alternative dedans).
		inner := tr.alternatives(t.atom.group)
		return []piece{{rx: rx{src: "(?:" + inner.src + ")" + quantifier(1, t.max), states: inner.states * t.max}}, {empty: true}}
	}
	inner := tr.alternativePieces(t.atom.group)
	if t.min == 1 {
		// Groupe non quantifié (ou {1}) : ses chemins tels quels, chemin vide compris.
		return inner
	}
	// Groupe optionnel : ses chemins non vides (ECMAScript refuse l'itération vide), puis l'omission.
	var nonEmpty []rx
	for _, p := range inner {
		if !p.empty {
			nonEmpty = append(nonEmpty, p.rx)
		}
	}
	merged := join(nonEmpty)
	return []piece{{rx: rx{src: "(?:" + merged.src + ")", states: merged.states}}, {empty: true}}
}
