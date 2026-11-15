// SPDX-License-Identifier: Apache-2.0

// Lectures du texte.
//
// Une consigne se cache sans peine dans un texte lu tel quel : écrite en pleine chasse, avec des espaces insécables,
// repliée sur plusieurs lignes, en pourcentages, en échappements ou en base64. Find lit donc aussi :
//
//   - le texte normalisé (NFKC : pleine chasse, espaces insécables et typographiques, ligatures) où une fin de ligne
//     simple vaut une espace (texte replié ; une ligne vide, une puce, un titre, une ligne de tableau restent des
//     coupures) ;
//   - le texte décodé une fois : suites %XX et échappements de chaîne (\uXXXX, \xXX, \n, \t, \", \\…) d'une part,
//     blocs base64 (alphabet standard ou URL, d'un bloc ou à lignes rejointes) dont le contenu est du texte d'autre
//     part ; chaque texte décodé est lu à son tour normalisé et déplié. Rien n'est décodé deux fois.
//
// Chaque vue garde la correspondance de ses octets avec ceux de la source (suites recopiées, morceaux remplacés) : un
// constat est toujours rendu en octets, ligne et colonne de la source. Un bloc base64 est un tout : un constat dans son texte décodé désigne le
// bloc entier.
//
// Le paquet ne dépend pas de detect : ces lectures sont écrites ici, plus simples que celles du moteur de détection
// (pas de fenêtres de lignes jointes, pas de budget de décodage : chaque lecture est un parcours linéaire du texte, et
// la somme des blocs base64 d'un texte ne dépasse pas ce texte). Seule borne : une vue de plus de maxViewBytes octets
// (expansion NFKC d'un texte choisi pour cela) n'est pas construite, et le rapport est incomplet.

package injection

import (
	"bytes"
	"sort"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	// maxViewBytes borne le texte d'une vue.
	maxViewBytes = 4 * MaxInputBytes
	// minBase64Length est la longueur la plus courte d'un bloc base64 lu (15 octets décodés).
	minBase64Length = 20
	// maxLineIndent : espaces ou tabulations admis devant une ligne de base64 rejointe.
	maxLineIndent = 8
)

// segment est une suite d'octets d'une vue qui vient d'une même étendue de la source.
type segment struct {
	// at est le premier octet de la suite dans la vue ; elle va jusqu'au segment suivant.
	at int32
	// start est l'octet de la source dont vient le premier octet de la suite.
	start int32
	// end est la fin, dans la source, d'un morceau remplacé : chaque octet de la suite vient de [start, end). -1 : la
	// suite est recopiée de la source, l'octet i venant de l'octet start + i − at.
	end int32
	// decoded : le morceau vient d'un décodage (pourcentage, échappement, base64), ou d'une normalisation ou d'un
	// dépliage d'octets décodés. Faux pour un morceau seulement normalisé ou déplié.
	decoded bool
}

// view est un texte et sa correspondance avec la source.
type view struct {
	text []byte
	// segs découpe text en suites, dans l'ordre. nil : la source elle-même.
	segs []segment
	// sourceLen est la longueur de la source.
	sourceLen int
	// afterDecoding : la vue est la forme normalisée et dépliée d'un texte décodé (seen).
	afterDecoding bool
}

// segmentAt rend le rang du segment qui contient l'octet i.
func (v *view) segmentAt(i int) int {
	return sort.Search(len(v.segs), func(k int) bool { return int(v.segs[k].at) > i }) - 1
}

// span rend l'étendue de la source dont vient l'octet i.
func (v *view) span(i int) (int, int) {
	if v.segs == nil {
		return i, i + 1
	}
	seg := v.segs[v.segmentAt(i)]
	if seg.end < 0 {
		start := int(seg.start) + i - int(seg.at)
		return start, start + 1
	}
	return int(seg.start), int(seg.end)
}

// source ramène l'étendue [start, end) de la vue, non vide, à des octets de la source.
func (v *view) source(start, end int) (int, int) {
	sourceStart, _ := v.span(start)
	_, sourceEnd := v.span(end - 1)
	return sourceStart, sourceEnd
}

// unchanged dit si les octets [lo, hi) d'une vue dérivée, l'octet qui les précède et celui qui les suit sont recopiés
// tels quels de la source : un motif y trouve exactement ce qu'il trouve dans la source, déjà lue.
func (v *view) unchanged(lo, hi int) bool {
	if v.segs == nil {
		return false
	}
	k := v.segmentAt(lo)
	seg := v.segs[k]
	if seg.end >= 0 || (lo == int(seg.at) && (lo != 0 || seg.start != 0)) {
		return false
	}
	segEnd := len(v.text)
	if k+1 < len(v.segs) {
		segEnd = int(v.segs[k+1].at)
	}
	if hi < segEnd {
		return true
	}
	// La fenêtre va jusqu'au bout de la vue : il faut que ce soit aussi le bout de la source.
	return hi == segEnd && segEnd == len(v.text) && int(seg.start)+segEnd-int(seg.at) == v.sourceLen
}

// seen dit si les octets [lo, hi) de la vue, voisins compris, ont déjà été lus dans une vue lue avant elle, où un
// motif trouve donc la même chose :
//   - dans la source, pour une vue qui en dérive directement, quand ces octets en sont recopiés tels quels ;
//   - dans la forme normalisée et dépliée de la source, pour celle d'un texte décodé, quand aucun de ces octets ne
//     vient d'un décodage : normaliser et déplier ne dépendent que des octets voisins, et un décodage ne change ni un
//     début de bloc ni une fin de ligne de la source.
func (v *view) seen(lo, hi int) bool {
	if !v.afterDecoding {
		return v.unchanged(lo, hi)
	}
	for k := v.segmentAt(max(lo-1, 0)); k < len(v.segs) && int(v.segs[k].at) <= hi; k++ {
		if v.segs[k].decoded {
			return false
		}
	}
	return true
}

// builder écrit une vue dérivée d'une autre. keep et replace sont appelés dans l'ordre du texte du parent.
type builder struct {
	parent *view
	text   []byte
	segs   []segment
	// cursor est le rang, dans le parent, du segment du dernier octet recopié.
	cursor int
	// changed : au moins un octet diffère du parent ; overflow : la vue dépasserait maxViewBytes.
	changed, overflow bool
}

func newBuilder(parent *view, capacity int) *builder {
	return &builder{parent: parent, text: make([]byte, 0, capacity)}
}

func (b *builder) identity(at, source int) {
	if n := len(b.segs); n > 0 && b.segs[n-1].end < 0 && int(b.segs[n-1].start)+at-int(b.segs[n-1].at) == source {
		return
	}
	b.segs = append(b.segs, segment{at: int32(at), start: int32(source), end: -1})
}

func (b *builder) replaced(at, start, end int, decoded bool) {
	if n := len(b.segs); n > 0 && b.segs[n-1].end == int32(end) && b.segs[n-1].start == int32(start) && b.segs[n-1].decoded == decoded {
		return
	}
	b.segs = append(b.segs, segment{at: int32(at), start: int32(start), end: int32(end), decoded: decoded})
}

// keep recopie les octets [i, j) du parent, avec leur correspondance.
func (b *builder) keep(i, j int) {
	if i >= j {
		return
	}
	if b.overflow || len(b.text)+j-i > maxViewBytes {
		b.overflow = true
		return
	}
	at := len(b.text)
	b.text = append(b.text, b.parent.text[i:j]...)
	segs := b.parent.segs
	if segs == nil {
		b.identity(at, i)
		return
	}
	k := b.cursor
	for k+1 < len(segs) && int(segs[k+1].at) <= i {
		k++
	}
	for position := i; position < j; {
		seg, segEnd := segs[k], len(b.parent.text)
		if k+1 < len(segs) {
			segEnd = int(segs[k+1].at)
		}
		if seg.end < 0 {
			b.identity(at+position-i, int(seg.start)+position-int(seg.at))
		} else {
			b.replaced(at+position-i, int(seg.start), int(seg.end), seg.decoded)
		}
		position = min(j, segEnd)
		if position < j {
			k++
		}
	}
	b.cursor = k
}

// replace écrit piece, non vide, à la place des octets [i, j) du parent, non vides : chaque octet écrit vient de
// toute l'étendue remplacée. decoding : le remplacement est un décodage.
func (b *builder) replace(piece []byte, i, j int, decoding bool) {
	b.changed = true
	if b.overflow || len(b.text)+len(piece) > maxViewBytes {
		b.overflow = true
		return
	}
	start, _ := b.parent.span(i)
	_, end := b.parent.span(j - 1)
	if segs := b.parent.segs; segs != nil && !decoding {
		for k := b.parent.segmentAt(i); k < len(segs) && int(segs[k].at) < j; k++ {
			decoding = decoding || segs[k].decoded
		}
	}
	b.replaced(len(b.text), start, end, decoding)
	b.text = append(b.text, piece...)
}

// done rend la vue, nil si elle est identique au parent ; ok est faux si elle n'a pas pu être construite.
func (b *builder) done() (v *view, ok bool) {
	if b.overflow {
		return nil, false
	}
	if !b.changed {
		return nil, true
	}
	sourceLen := b.parent.sourceLen
	if b.parent.segs == nil {
		sourceLen = len(b.parent.text)
	}
	return &view{text: b.text, segs: b.segs, sourceLen: sourceLen}, true
}

// normalized rend le texte en forme NFKC, segment de normalisation par segment : un segment déjà normalisé est
// recopié, un autre est remplacé en entier.
func normalized(v *view) (*view, bool) {
	text := v.text
	if norm.NFKC.IsNormal(text) {
		return nil, true
	}
	b := newBuilder(v, len(text))
	var buffer []byte
	for i := 0; i < len(text) && !b.overflow; {
		if n := norm.NFKC.QuickSpan(text[i:]); n > 0 {
			b.keep(i, i+n)
			i += n
			continue
		}
		n := norm.NFKC.NextBoundary(text[i:], true)
		if n <= 0 {
			n = 1
		}
		buffer = norm.NFKC.Append(buffer[:0], text[i:i+n]...)
		if bytes.Equal(buffer, text[i:i+n]) {
			b.keep(i, i+n)
		} else {
			b.replace(buffer, i, i+n, false)
		}
		i += n
	}
	return b.done()
}

func isBlank(c byte) bool { return c == ' ' || c == '\t' }

// lineBreak rend la longueur de la fin de ligne à l'octet i (« \n » ou « \r\n »), 0 s'il n'y en a pas.
func lineBreak(text []byte, i int) int {
	if i < len(text) && text[i] == '\n' {
		return 1
	}
	if i+1 < len(text) && text[i] == '\r' && text[i+1] == '\n' {
		return 2
	}
	return 0
}

// startsBlock dit si la ligne qui commence à l'octet i ouvre un bloc (puce, liste numérotée, titre, citation, ligne
// de tableau, filet, clôture de code) : la fin de ligne qui la précède reste alors une coupure.
func startsBlock(text []byte, i int) bool {
	if i >= len(text) {
		return true
	}
	next := func(offset int) byte {
		if i+offset < len(text) {
			return text[i+offset]
		}
		return '\n'
	}
	switch c := text[i]; {
	case c == '#' || c == '>' || c == '|' || c == '}' || c == ')' || c == ']':
		return true
	case c == '-' || c == '*' || c == '+' || c == '_' || c == '=' || c == '`' || c == '~':
		return isBlank(next(1)) || (next(1) == c && next(2) == c) || lineBreak(text, i+1) > 0
	case c >= '0' && c <= '9':
		j := 1
		for j < 9 && next(j) >= '0' && next(j) <= '9' {
			j++
		}
		return (next(j) == '.' || next(j) == ')') && isBlank(next(j+1))
	default:
		return false
	}
}

// endsStatement dit si c, dernier caractère d'une ligne, est celui d'une ligne de code (accolade, parenthèse ou
// crochet ouvrants, point-virgule, signe égal, barre oblique inverse) : la ligne suivante n'est pas la suite d'une
// phrase repliée.
func endsStatement(c byte) bool {
	switch c {
	case '{', '}', '(', '[', ';', '=', '\\':
		return true
	}
	return false
}

// unwrapped rend le texte où une fin de ligne simple, avec les espaces qui la bordent, vaut une espace. Deux fins de
// ligne ou plus (ligne vide) et une fin de ligne devant un début de bloc sont gardées.
func unwrapped(v *view) (*view, bool) {
	text := v.text
	if bytes.IndexByte(text, '\n') < 0 {
		return nil, true
	}
	b := newBuilder(v, len(text))
	from := 0
	for i := 0; i < len(text) && !b.overflow; {
		if !isBlank(text[i]) && lineBreak(text, i) == 0 {
			i++
			continue
		}
		// Suite d'espaces et de fins de ligne à partir de i.
		end, breaks := i, 0
		for end < len(text) {
			if n := lineBreak(text, end); n > 0 {
				breaks++
				end += n
			} else if isBlank(text[end]) {
				end++
			} else {
				break
			}
		}
		if breaks == 1 && i > 0 && !endsStatement(text[i-1]) && !startsBlock(text, end) {
			b.keep(from, i)
			b.replace([]byte{' '}, i, end, false)
			from = end
		}
		i = end
	}
	b.keep(from, len(text))
	return b.done()
}

// folded rend la lecture normalisée puis dépliée de v ; nil si elle est identique à v.
func folded(v *view) (*view, bool) {
	n, ok := normalized(v)
	if !ok {
		return nil, false
	}
	base := v
	if n != nil {
		base = n
	}
	u, ok := unwrapped(base)
	if !ok {
		return nil, false
	}
	if u != nil {
		return u, true
	}
	return n, true
}

func hexValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}

// hexRun lit n chiffres hexadécimaux à l'octet i ; -1 s'il n'y en a pas n.
func hexRun(text []byte, i, n int) int {
	if i+n > len(text) {
		return -1
	}
	value := 0
	for _, c := range text[i : i+n] {
		digit := hexValue(c)
		if digit < 0 {
			return -1
		}
		value = value<<4 | digit
	}
	return value
}

// simpleEscapes sont les échappements d'un caractère des chaînes JSON et JavaScript.
var simpleEscapes = [256]byte{'n': '\n', 't': '\t', 'r': '\r', 'b': '\b', 'f': '\f', '"': '"', '\'': '\'', '\\': '\\', '/': '/'}

// escapeAt décode l'échappement de chaîne qui commence par la barre oblique inverse de l'octet i : \uXXXX (deux
// substituts qui se suivent font un caractère, un substitut isolé vaut U+FFFD), \xXX, ou un échappement d'un
// caractère. Il rend le texte décodé (dans buffer) et la fin de l'échappement ; end vaut i devant autre chose.
func escapeAt(text []byte, i int, buffer *[utf8.UTFMax]byte) (piece []byte, end int) {
	if i+1 >= len(text) {
		return nil, i
	}
	switch c := text[i+1]; {
	case simpleEscapes[c] != 0:
		buffer[0] = simpleEscapes[c]
		return buffer[:1], i + 2
	case c == 'x':
		value := hexRun(text, i+2, 2)
		if value < 0 {
			return nil, i
		}
		return buffer[:utf8.EncodeRune(buffer[:], rune(value))], i + 4
	case c == 'u':
		value := hexRun(text, i+2, 4)
		if value < 0 {
			return nil, i
		}
		end = i + 6
		r := rune(value)
		if utf16.IsSurrogate(r) {
			low := -1
			if end+1 < len(text) && text[end] == '\\' && text[end+1] == 'u' {
				low = hexRun(text, end+2, 4)
			}
			if pair := utf16.DecodeRune(r, rune(low)); low >= 0 && pair != utf8.RuneError {
				r = pair
				end += 6
			} else {
				r = utf8.RuneError
			}
		}
		return buffer[:utf8.EncodeRune(buffer[:], r)], end
	default:
		return nil, i
	}
}

// decodedOnce rend le texte dont chaque suite %XX est remplacée par son octet et chaque échappement de chaîne par
// son caractère, en un seul parcours : ce qu'un décodage produit n'est pas décodé à son tour. Une suite « % » ou
// « \ » qui n'est ni l'une ni l'autre est gardée.
func decodedOnce(v *view) (*view, bool) {
	text := v.text
	if bytes.IndexByte(text, '%') < 0 && bytes.IndexByte(text, '\\') < 0 {
		return nil, true
	}
	b := newBuilder(v, len(text))
	from := 0
	var buffer [utf8.UTFMax]byte
	for i := 0; i < len(text) && !b.overflow; i++ {
		var piece []byte
		end := i
		switch text[i] {
		case '%':
			if value := hexRun(text, i+1, 2); value >= 0 {
				buffer[0] = byte(value)
				piece, end = buffer[:1], i+3
			}
		case '\\':
			piece, end = escapeAt(text, i, &buffer)
		}
		if end == i {
			continue
		}
		b.keep(from, i)
		b.replace(piece, i, end, true)
		from = end
		i = end - 1
	}
	b.keep(from, len(text))
	return b.done()
}

// base64Values donne la valeur d'un caractère de l'alphabet base64 standard ou URL, -1 sinon.
var base64Values = func() [256]int8 {
	var table [256]int8
	for i := range table {
		table[i] = -1
	}
	for i, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" {
		table[c] = int8(i)
	}
	table['+'], table['/'], table['-'], table['_'] = 62, 63, 62, 63
	return table
}()

// decodeBase64 décode les morceaux, mis bout à bout, en base64 standard ou URL (jamais les deux), suivis de padding
// signes « = ». Le résultat n'est rendu que s'il est du texte : UTF-8 valide, sans NUL, imprimable à 90 % au moins.
func decodeBase64(text []byte, pieces [][2]int, padding int) []byte {
	length := 0
	standard, urlSafe := false, false
	for _, piece := range pieces {
		length += piece[1] - piece[0]
		for _, c := range text[piece[0]:piece[1]] {
			standard = standard || c == '+' || c == '/'
			urlSafe = urlSafe || c == '-' || c == '_'
		}
	}
	if length < minBase64Length || length%4 == 1 || (standard && urlSafe) || (padding > 0 && (length+padding)%4 != 0) {
		return nil
	}
	decoded := make([]byte, 0, length/4*3+3)
	accumulator, bits := uint32(0), 0
	for _, piece := range pieces {
		for _, c := range text[piece[0]:piece[1]] {
			accumulator = accumulator<<6 | uint32(base64Values[c])
			bits += 6
			if bits >= 8 {
				bits -= 8
				decoded = append(decoded, byte(accumulator>>bits))
			}
		}
	}
	if !utf8.Valid(decoded) || bytes.IndexByte(decoded, 0) >= 0 {
		return nil
	}
	total, printable := 0, 0
	for _, r := range string(decoded) {
		total++
		if r >= ' ' || r == '\n' || r == '\r' || r == '\t' {
			printable++
		}
	}
	if total == 0 || printable*10 < total*9 {
		return nil
	}
	return decoded
}

// base64Run rend la fin de la suite de caractères base64 qui commence à l'octet i.
func base64Run(text []byte, i int) int {
	for i < len(text) && base64Values[text[i]] >= 0 {
		i++
	}
	return i
}

// paddingAt compte les signes « = » (deux au plus) à l'octet i.
func paddingAt(text []byte, i int) int {
	n := 0
	for n < 2 && i+n < len(text) && text[i+n] == '=' {
		n++
	}
	return n
}

// atLineStart dit si l'octet i n'est précédé, sur sa ligne, que d'espaces (maxLineIndent au plus).
func atLineStart(text []byte, i int) bool {
	for back := 0; back <= maxLineIndent; back++ {
		if i-back == 0 || text[i-back-1] == '\n' {
			return true
		}
		if !isBlank(text[i-back-1]) {
			return false
		}
	}
	return false
}

// base64Decoded rend, bout à bout et séparés par une ligne vide, les textes décodés des blocs base64 de la vue. Un
// bloc est une suite de caractères base64 d'au moins minBase64Length caractères, ou plusieurs lignes entières de
// base64 qui se suivent (base64 replié, lignes rejointes) ; si les lignes rejointes ne se décodent pas, chacune est
// essayée seule. Chaque octet décodé vient du bloc entier.
func base64Decoded(v *view) (*view, bool) {
	text := v.text
	b := newBuilder(v, 0)
	separator := []byte("\n\n")
	emit := func(pieces [][2]int, padding int) bool {
		decoded := decodeBase64(text, pieces, padding)
		if decoded == nil {
			return false
		}
		start, end := pieces[0][0], pieces[len(pieces)-1][1]+padding
		b.replace(decoded, start, end, true)
		b.replace(separator, start, end, true)
		return true
	}
	var pieces [][2]int
	for i := 0; i < len(text) && !b.overflow; {
		if base64Values[text[i]] < 0 {
			i++
			continue
		}
		end := base64Run(text, i)
		padding := paddingAt(text, end)
		pieces = append(pieces[:0], [2]int{i, end})
		next := end + padding
		// Lignes entières de base64 qui se suivent : la première commence sa ligne et va jusqu'à la fin de ligne.
		if padding == 0 && atLineStart(text, i) {
			for {
				n := lineBreak(text, next)
				if n == 0 {
					break
				}
				start := next + n
				for start < len(text) && start-next-n < maxLineIndent && isBlank(text[start]) {
					start++
				}
				lineEnd := base64Run(text, start)
				linePadding := paddingAt(text, lineEnd)
				after := lineEnd + linePadding
				if lineEnd == start || (after < len(text) && lineBreak(text, after) == 0) {
					break
				}
				pieces = append(pieces, [2]int{start, lineEnd})
				next, padding = after, linePadding
				if linePadding > 0 {
					break
				}
			}
		}
		if !emit(pieces, padding) && len(pieces) > 1 {
			for k, piece := range pieces {
				piecePadding := 0
				if k == len(pieces)-1 {
					piecePadding = padding
				}
				emit([][2]int{piece}, piecePadding)
			}
		}
		i = max(next, end)
	}
	return b.done()
}
