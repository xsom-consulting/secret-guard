// Vues de texte du moteur de détection.
//
// Portage en Go de secret-guard/packages/core/src/mapping.ts et des parties de scanner.ts qui construisent des vues
// (transformedTextViews, lineWrappedFixedViews, lineWrappedBase64Views) ; Apache-2.0, origine, avis et modifications
// dans UPSTREAM.md.
//
// Secret Guard parcourt une chaîne JavaScript (unités UTF-16) ; ce portage parcourt des octets, comme le corpus de
// parité les définit : un octet hors séquence UTF-8 valide vaut U+FFFD (un par octet) et NUL est un
// caractère ordinaire. Chaque vue garde, pour chaque octet de son texte, l'étendue d'octets de la source dont il vient
// (starts/ends) ; une correspondance d'expression régulière sur une vue se ramène ainsi à des octets de la source.
//
// Écarts de représentation, sans effet sur ce que voient les règles :
//   - la vue d'identité est la source telle quelle (octets invalides compris) ; les vues dérivées écrivent U+FFFD
//     (3 octets) pour chaque octet invalide, pour que deux octets invalides rendus adjacents par un retrait ne forment
//     jamais une séquence valide que Secret Guard n'aurait pas vue ;
//   - un substitut UTF-16 isolé (échappement JSON \uD800…\uDFFF sans son pendant) est écrit U+FFFD et retenu dans
//     view.lone ; si une vue dérivée rend adjacents un substitut haut et un substitut bas isolés (retrait d'un
//     ignorable, jonction de lignes), ils forment un seul point de code, comme dans une chaîne JavaScript.
//
// Bornes : chaque vue est construite en un parcours linéaire ; l'ensemble des vues d'une analyse est borné par
// maxViewBytes (viewBudget), les fenêtres de lignes jointes par maxJoinedWindows et maxJoinedCandidateCharacters
// (windowBudget, comme Secret Guard). Un budget épuisé est une erreur : l'analyse est incomplète.

package detect

import (
	"bytes"
	"errors"
	"math"
	"sort"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Encoding est la vue dans laquelle un constat a été trouvé (FindingEncoding de Secret Guard, champ encoding du
// corpus de parité).
type Encoding string

// Vues de Secret Guard.
const (
	EncodingPlain            Encoding = "plain"
	EncodingNormalized       Encoding = "normalized"
	EncodingPercent          Encoding = "percent"
	EncodingJSONEscaped      Encoding = "json-escaped"
	EncodingBase64           Encoding = "base64"
	EncodingWhitespaceJoined Encoding = "whitespace-joined"
)

const (
	// maxViewBytes borne la somme des textes des vues gardées pendant une analyse (identité exclue : c'est
	// l'entrée). Chaque octet de vue gardée coûte 9 octets de mémoire (texte et deux int32 de correspondance, taille
	// exacte) : 16 Mio de vues ≈ 144 Mio ; s'y ajoutent, le temps de la construire, la vue en cours (capacité doublée
	// à chaque croissance, au plus deux fois sa taille avant la copie finale) et les fins de suites de jeton d'une vue
	// (4 octets par octet). Une entrée de 1 Mio sans expansion produit au plus une quinzaine de Mio de vues (neuf vues
	// de texte, fenêtres, textes décodés) ; seule l'expansion NFKC (jusqu'à 11 fois, U+FDFA) dépasse.
	maxViewBytes = 16 << 20
	// maxJoinedWindows et maxJoinedCandidateCharacters sont les bornes des fenêtres de lignes jointes de Secret Guard
	// (MAX_JOINED_WINDOWS, MAX_JOINED_CANDIDATE_CHARACTERS).
	maxJoinedWindows             = 128
	maxJoinedCandidateCharacters = 16_384
	// maxJoinedIndentation est le nombre d'espaces ou de tabulations retirés après un saut de ligne.
	maxJoinedIndentation = 4
)

var (
	// errViewBudgetExhausted : les vues dépasseraient maxViewBytes ; l'analyse est incomplète (blocage).
	errViewBudgetExhausted = errors.New("détection : budget des vues de texte épuisé")
	// errJoinedWindowBudgetExhausted : plus de maxJoinedWindows fenêtres de lignes jointes ; l'analyse est incomplète.
	errJoinedWindowBudgetExhausted = errors.New("détection : budget des fenêtres de lignes jointes épuisé")
)

// replacement est U+FFFD en UTF-8.
var replacement = []byte("\uFFFD")

// viewBudget est le budget d'octets de vues d'une analyse (propre au portage : Secret Guard n'en a pas). Il relève
// aussi les tampons de texte que l'analyse alloue (vues dérivées, textes décodés), qui portent des valeurs : wipe les
// efface à la fin de l'analyse.
type viewBudget struct {
	remaining int
	builders  []*builder
	owned     [][]byte
}

// own relève un tampon alloué par l'analyse, effacé par wipe.
func (b *viewBudget) own(buffer []byte) { b.owned = append(b.owned, buffer) }

// wipe efface tous les tampons de texte relevés, sur toute leur capacité. Les vues de l'analyse ne doivent plus
// être lues ensuite.
func (b *viewBudget) wipe() {
	for _, builder := range b.builders {
		clear(builder.text[:cap(builder.text)])
	}
	for _, buffer := range b.owned {
		clear(buffer[:cap(buffer)])
	}
}

func newViewBudget() *viewBudget { return &viewBudget{remaining: maxViewBytes} }

// windowBudget compte les fenêtres de lignes jointes d'une analyse (JoinedWindowBudget de Secret Guard).
type windowBudget struct{ windows int }

// loneSurrogate est un substitut UTF-16 isolé : U+FFFD à l'octet pos du texte de la vue.
type loneSurrogate struct {
	pos  int32
	unit uint16
}

// view est une vue de texte (MappedView de Secret Guard).
type view struct {
	text []byte
	// starts et ends donnent, pour chaque octet de text, l'étendue [start, end) d'octets de la source. nil : vue
	// d'identité (l'octet i vient de [i, i+1)).
	starts, ends []int32
	// lone liste, par position croissante, les substituts isolés de text.
	lone     []loneSurrogate
	encoding Encoding
}

// identityView est la source telle quelle.
func identityView(content []byte) *view { return &view{text: content, encoding: EncodingPlain} }

// mapRange ramène l'étendue [start, end) de la vue à des octets de la source (mapRange de Secret Guard).
func (v *view) mapRange(start, end int) (int, int) { return v.originalBounds(start, end) }

// slice rend les octets [start, end) du texte de la vue, sans copie et sans capacité au-delà, bornes ramenées au
// texte (une étendue hors de la vue, que mapRange admet, ne fait jamais paniquer l'analyse).
func (v *view) slice(start, end int) []byte {
	start = max(0, min(start, len(v.text)))
	end = max(start, min(end, len(v.text)))
	return v.text[start:end:end]
}

// originalBounds suit originalBounds de Secret Guard, valeurs de repli comprises (index hors vue).
func (v *view) originalBounds(start, end int) (int, int) {
	if v.starts == nil {
		return start, end
	}
	n := len(v.starts)
	if start >= end {
		switch {
		case start >= 0 && start < n:
			return int(v.starts[start]), int(v.starts[start])
		case start-1 >= 0 && start-1 < n:
			return int(v.ends[start-1]), int(v.ends[start-1])
		default:
			return 0, 0
		}
	}
	s, e := 0, len(v.text)
	if start >= 0 && start < n {
		s = int(v.starts[start])
	}
	if end-1 >= 0 && end-1 < n {
		e = int(v.ends[end-1])
	}
	return s, e
}

// builder écrit une vue dérivée en respectant le budget de vues.
type builder struct {
	text         []byte
	starts, ends []int32
	lone         []loneSurrogate
	limit        int
}

func newBuilder(capacity int, budget *viewBudget) *builder {
	capacity = min(capacity, budget.remaining)
	b := &builder{
		text:   make([]byte, 0, capacity),
		starts: make([]int32, 0, capacity),
		ends:   make([]int32, 0, capacity),
		limit:  budget.remaining,
	}
	budget.builders = append(budget.builders, b)
	return b
}

// reserve garantit la place de n octets de plus, dans le budget. La capacité double (au plus jusqu'à la limite) :
// la croissance par défaut d'append (×1,25 au-delà de 256 éléments) allouerait au total cinq fois la vue finale.
func (b *builder) reserve(n int) error {
	need := len(b.text) + n
	if need > b.limit {
		return errViewBudgetExhausted
	}
	if need <= cap(b.text) {
		return nil
	}
	capacity := min(max(2*cap(b.text), need, 64), b.limit)
	text := make([]byte, len(b.text), capacity)
	copy(text, b.text)
	clear(b.text[:cap(b.text)])
	starts := make([]int32, len(b.starts), capacity)
	copy(starts, b.starts)
	ends := make([]int32, len(b.ends), capacity)
	copy(ends, b.ends)
	b.text, b.starts, b.ends = text, starts, ends
	return nil
}

// push ajoute value, dont chaque octet vient de [start, end) de la source (appendMapped de Secret Guard).
func (b *builder) push(value []byte, start, end int) error {
	if err := b.reserve(len(value)); err != nil {
		return err
	}
	n := len(b.text)
	b.text = append(b.text, value...)
	b.starts = b.starts[:len(b.text)]
	b.ends = b.ends[:len(b.text)]
	for i := n; i < len(b.text); i++ {
		b.starts[i] = int32(start)
		b.ends[i] = int32(end)
	}
	return nil
}

func (b *builder) pushByte(c byte, start, end int) error {
	if err := b.reserve(1); err != nil {
		return err
	}
	b.text = append(b.text, c)
	b.starts = append(b.starts, int32(start))
	b.ends = append(b.ends, int32(end))
	return nil
}

// pushUnit ajoute une unité UTF-16 (String.fromCharCode de Secret Guard). Un substitut isolé est écrit U+FFFD et
// retenu ; un substitut bas qui suit immédiatement un substitut haut isolé forme avec lui un seul point de code.
func (b *builder) pushUnit(unit uint16, start, end int) error {
	r := rune(unit)
	if !utf16.IsSurrogate(r) {
		return b.push(utf8.AppendRune(nil, r), start, end)
	}
	if r >= 0xDC00 && len(b.lone) > 0 {
		last := b.lone[len(b.lone)-1]
		if int(last.pos) == len(b.text)-len(replacement) && last.unit < 0xDC00 {
			highStart := int(b.starts[last.pos])
			b.text = b.text[:last.pos]
			b.starts = b.starts[:last.pos]
			b.ends = b.ends[:last.pos]
			b.lone = b.lone[:len(b.lone)-1]
			return b.push(utf8.AppendRune(nil, utf16.DecodeRune(rune(last.unit), r)), highStart, end)
		}
	}
	pos := len(b.text)
	if err := b.push(replacement, start, end); err != nil {
		return err
	}
	b.lone = append(b.lone, loneSurrogate{pos: int32(pos), unit: unit})
	return nil
}

// finish rend la vue construite, à sa taille exacte (la capacité de croissance n'est pas gardée), et la débite du
// budget.
func (b *builder) finish(budget *viewBudget, encoding Encoding) *view {
	text, starts, ends, lone := b.text, b.starts, b.ends, b.lone
	if cap(text) > len(text) {
		text = make([]byte, len(b.text))
		copy(text, b.text)
		clear(b.text[:cap(b.text)])
		b.text = text
		starts = make([]int32, len(b.starts))
		copy(starts, b.starts)
		ends = make([]int32, len(b.ends))
		copy(ends, b.ends)
	}
	// Le constructeur ne garde que le texte de la vue (effacé par wipe) : ses tables de correspondance, devenues
	// des copies, sont rendues au ramasse-miettes.
	b.starts, b.ends, b.lone = nil, nil, nil
	budget.remaining -= len(text)
	return &view{text: text, starts: starts, ends: ends, lone: lone, encoding: encoding}
}

// cursor parcourt une vue comme Secret Guard parcourt sa chaîne : substitut isolé, octet invalide (U+FFFD), point
// de code valide.
type cursor struct {
	v    *view
	lone int // premier substitut isolé à une position ≥ à la position courante
}

// cursorAt place un curseur à l'octet start.
func cursorAt(v *view, start int) cursor {
	return cursor{v: v, lone: sort.Search(len(v.lone), func(k int) bool { return int(v.lone[k].pos) >= start })}
}

// loneAt dit si un substitut isolé commence à l'octet i (positions demandées croissantes).
func (c *cursor) loneAt(i int) (uint16, bool) {
	for c.lone < len(c.v.lone) && int(c.v.lone[c.lone].pos) < i {
		c.lone++
	}
	if c.lone < len(c.v.lone) && int(c.v.lone[c.lone].pos) == i {
		return c.v.lone[c.lone].unit, true
	}
	return 0, false
}

// copyElement recopie l'élément qui commence à l'octet i et rend la position suivante.
func (c *cursor) copyElement(b *builder, i int) (int, error) {
	text := c.v.text
	if unit, ok := c.loneAt(i); ok {
		s, e := c.v.originalBounds(i, i+len(replacement))
		return i + len(replacement), b.pushUnit(unit, s, e)
	}
	if text[i] < utf8.RuneSelf {
		s, e := c.v.originalBounds(i, i+1)
		return i + 1, b.pushByte(text[i], s, e)
	}
	r, width := utf8.DecodeRune(text[i:])
	if r == utf8.RuneError && width == 1 {
		s, e := c.v.originalBounds(i, i+1)
		return i + 1, b.push(replacement, s, e)
	}
	s, e := c.v.originalBounds(i, i+width)
	return i + width, b.push(text[i:i+width], s, e)
}

// normalizedView normalise en NFKC point de code par point de code, retire les points de code
// Default_Ignorable_Code_Point et remplace CRLF par LF, en gardant la correspondance (normalizedView de Secret
// Guard). nil : texte ASCII sans CRLF, ou texte inchangé.
func normalizedView(v *view, budget *viewBudget) (*view, error) {
	content := v.text
	if !normalizationChanges(v) {
		// Rien ne change : aucune vue, et rien n'est alloué ni débité (Secret Guard la construit puis rend null).
		return nil, nil
	}
	b := newBuilder(len(content), budget)
	c := cursor{v: v}
	var scratch []byte
	for i := 0; i < len(content); {
		if content[i] == '\r' && i+1 < len(content) && content[i+1] == '\n' {
			start, _ := v.originalBounds(i, i+1)
			_, end := v.originalBounds(i+1, i+2)
			if err := b.pushByte('\n', start, end); err != nil {
				return nil, err
			}
			i += 2
			continue
		}
		if _, ok := c.loneAt(i); ok || content[i] < utf8.RuneSelf {
			// Substitut isolé (laissé tel quel par normalize) ou ASCII (stable en NFKC, jamais ignorable).
			next, err := c.copyElement(b, i)
			if err != nil {
				return nil, err
			}
			i = next
			continue
		}
		r, width := utf8.DecodeRune(content[i:])
		if r == utf8.RuneError && width == 1 {
			next, err := c.copyElement(b, i)
			if err != nil {
				return nil, err
			}
			i = next
			continue
		}
		if !unicode.Is(defaultIgnorableCodePoint, r) {
			start, end := v.originalBounds(i, i+width)
			// Un point de code à la fois, comme original.normalize("NFKC") : jamais de composition avec le précédent.
			scratch = norm.NFKC.Append(scratch[:0], content[i:i+width]...)
			if err := b.push(scratch, start, end); err != nil {
				return nil, err
			}
		}
		i += width
	}
	if sameText(v, b.text, b.lone) {
		return nil, nil
	}
	encoding := v.encoding
	if encoding == EncodingPlain {
		encoding = EncodingNormalized
	}
	return b.finish(budget, encoding), nil
}

// canonicalizedView est la vue normalisée, ou la vue elle-même quand la normalisation ne change rien.
func canonicalizedView(v *view, budget *viewBudget) (*view, error) {
	normalized, err := normalizedView(v, budget)
	if err != nil || normalized == nil {
		return v, err
	}
	return normalized, nil
}

// normalizationChanges dit si normalizedView change le texte : CRLF, point de code ignorable par défaut, ou point de
// code que NFKC change. Les substituts isolés et les octets invalides ne changent pas ; une recombinaison de
// substituts suppose un retrait, donc un ignorable.
func normalizationChanges(v *view) bool {
	content := v.text
	if bytes.Contains(content, []byte("\r\n")) {
		return true
	}
	c := cursor{v: v}
	for i := 0; i < len(content); {
		if content[i] < utf8.RuneSelf {
			i++
			continue
		}
		if _, ok := c.loneAt(i); ok {
			i += len(replacement)
			continue
		}
		r, width := utf8.DecodeRune(content[i:])
		if r == utf8.RuneError && width == 1 {
			i++
			continue
		}
		if unicode.Is(defaultIgnorableCodePoint, r) || !norm.NFKC.IsNormal(content[i:i+width]) {
			return true
		}
		i += width
	}
	return false
}

// sameText compare le texte de v à text comme JavaScript compare deux chaînes (text === content) : octet invalide
// = U+FFFD, substitut isolé = son unité.
func sameText(v *view, text []byte, lone []loneSurrogate) bool {
	left := elements{text: v.text, lone: v.lone}
	right := elements{text: text, lone: lone}
	for {
		a, aok := left.next()
		b, bok := right.next()
		if aok != bok || a != b {
			return false
		}
		if !aok {
			return true
		}
	}
}

// elements énumère les éléments d'un texte de vue : point de code, U+FFFD d'un octet invalide, ou substitut isolé
// (valeur de l'unité, distincte de tout point de code scalaire).
type elements struct {
	text []byte
	lone []loneSurrogate
	i, l int
}

func (e *elements) next() (rune, bool) {
	if e.i >= len(e.text) {
		return 0, false
	}
	if e.l < len(e.lone) && int(e.lone[e.l].pos) == e.i {
		unit := e.lone[e.l].unit
		e.l++
		e.i += len(replacement)
		return rune(unit), true
	}
	r, width := utf8.DecodeRune(e.text[e.i:])
	e.i += width
	return r, true
}

// isHex dit si c est un chiffre hexadécimal ASCII.
func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func hexValue(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c >= 'a':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// percentByteAt lit « %XX » à l'octet i (percentByteAt de Secret Guard).
func percentByteAt(text []byte, i int) (byte, bool) {
	if i < 0 || i+2 >= len(text) || text[i] != '%' || !isHex(text[i+1]) || !isHex(text[i+2]) {
		return 0, false
	}
	return hexValue(text[i+1])<<4 | hexValue(text[i+2]), true
}

// utf8Width suit utf8Width de Secret Guard (0 : premier octet impossible).
func utf8Width(first byte) int {
	switch {
	case first <= 0x7F:
		return 1
	case first >= 0xC2 && first <= 0xDF:
		return 2
	case first >= 0xE0 && first <= 0xEF:
		return 3
	case first >= 0xF0 && first <= 0xF4:
		return 4
	default:
		return 0
	}
}

// decodePercentCodePoint décode un point de code UTF-8 écrit en « %XX » à partir de l'octet start : ses octets et
// la position qui suit (decodePercentCodePoint de Secret Guard, TextDecoder strict : ni forme trop longue, ni
// substitut, ni au-delà de U+10FFFF).
func decodePercentCodePoint(text []byte, start int, scratch *[utf8.UTFMax]byte) ([]byte, int, bool) {
	first, ok := percentByteAt(text, start)
	if !ok {
		return nil, 0, false
	}
	width := utf8Width(first)
	if width == 0 {
		return nil, 0, false
	}
	scratch[0] = first
	for offset := 1; offset < width; offset++ {
		next, ok := percentByteAt(text, start+offset*3)
		if !ok || next < 0x80 || next > 0xBF {
			return nil, 0, false
		}
		scratch[offset] = next
	}
	encoded := scratch[:width]
	if r, size := utf8.DecodeRune(encoded); size != width || (r == utf8.RuneError && size == 1) {
		return nil, 0, false
	}
	return encoded, start + width*3, true
}

// percentDecodedView décode exactement une couche d'échappements « %XX » UTF-8 (percentDecodedView de Secret
// Guard). nil : aucun « %XX », ou aucune séquence valide.
func percentDecodedView(v *view, budget *viewBudget) (*view, error) {
	text := v.text
	var scratch [utf8.UTFMax]byte
	if !containsDecodablePercentEscape(text, &scratch) {
		// Aucune séquence décodée : aucune vue, et rien n'est alloué ni débité.
		return nil, nil
	}
	b := newBuilder(len(text), budget)
	c := cursor{v: v}
	changed := false
	for i := 0; i < len(text); {
		if text[i] == '%' {
			if encoded, end, ok := decodePercentCodePoint(text, i, &scratch); ok {
				start, _ := v.originalBounds(i, i+1)
				_, last := v.originalBounds(end-1, end)
				// TextDecoder (ignoreBOM faux) retire une marque d'ordre d'octets en tête de chaque décodage : chez
				// Secret Guard, « %EF%BB%BF » ne laisse rien dans la vue.
				if bytes.Equal(encoded, byteOrderMark) {
					encoded = nil
				}
				if err := b.push(encoded, start, last); err != nil {
					return nil, err
				}
				i = end
				changed = true
				continue
			}
		}
		next, err := c.copyElement(b, i)
		if err != nil {
			return nil, err
		}
		i = next
	}
	if !changed {
		return nil, nil
	}
	return b.finish(budget, EncodingPercent), nil
}

// byteOrderMark est U+FEFF en UTF-8.
var byteOrderMark = []byte{0xEF, 0xBB, 0xBF}

// containsDecodablePercentEscape dit si percentDecodedView décode au moins une séquence.
func containsDecodablePercentEscape(text []byte, scratch *[utf8.UTFMax]byte) bool {
	for i := bytes.IndexByte(text, '%'); i >= 0; {
		if _, _, ok := decodePercentCodePoint(text, i, scratch); ok {
			return true
		}
		next := bytes.IndexByte(text[i+1:], '%')
		if next < 0 {
			return false
		}
		i += 1 + next
	}
	return false
}

// jsonUnicodeEscapeAt lit « \uXXXX » à l'octet i.
func jsonUnicodeEscapeAt(text []byte, i int) (uint16, bool) {
	if i+6 > len(text) || text[i] != '\\' || text[i+1] != 'u' {
		return 0, false
	}
	var unit uint16
	for _, c := range text[i+2 : i+6] {
		if !isHex(c) {
			return 0, false
		}
		unit = unit<<4 | uint16(hexValue(c))
	}
	return unit, true
}

// jsonEscapedView décode une couche d'échappements JSON « \uXXXX » et « \/ » (jsonEscapedView de Secret Guard).
// nil : aucun échappement.
func jsonEscapedView(v *view, budget *viewBudget) (*view, error) {
	text := v.text
	if !containsJSONEscape(text) {
		return nil, nil
	}
	b := newBuilder(len(text), budget)
	c := cursor{v: v}
	changed := false
	for i := 0; i < len(text); {
		if unit, ok := jsonUnicodeEscapeAt(text, i); ok {
			start, _ := v.originalBounds(i, i+1)
			_, end := v.originalBounds(i+5, i+6)
			if err := b.pushUnit(unit, start, end); err != nil {
				return nil, err
			}
			i += 6
			changed = true
			continue
		}
		if text[i] == '\\' && i+1 < len(text) && text[i+1] == '/' {
			start, _ := v.originalBounds(i, i+1)
			_, end := v.originalBounds(i+1, i+2)
			if err := b.pushByte('/', start, end); err != nil {
				return nil, err
			}
			i += 2
			changed = true
			continue
		}
		next, err := c.copyElement(b, i)
		if err != nil {
			return nil, err
		}
		i = next
	}
	if !changed {
		return nil, nil
	}
	return b.finish(budget, EncodingJSONEscaped), nil
}

func containsJSONEscape(text []byte) bool {
	for i := bytes.IndexByte(text, '\\'); i >= 0; {
		if _, ok := jsonUnicodeEscapeAt(text, i); ok || (i+1 < len(text) && text[i+1] == '/') {
			return true
		}
		next := bytes.IndexByte(text[i+1:], '\\')
		if next < 0 {
			return false
		}
		i += 1 + next
	}
	return false
}

// joinedLineView retire chaque saut de ligne (CR, LF ou CRLF) et jusqu'à quatre espaces ou tabulations qui le
// suivent (joinedLineView de Secret Guard). nil : aucun CR ni LF.
func joinedLineView(v *view, budget *viewBudget) (*view, error) {
	return joinedWindow(v, 0, len(v.text), budget)
}

// joinedWindow est joinedLineView(sliceMappedView(v, start, end)) de Secret Guard, sans copie intermédiaire.
func joinedWindow(v *view, start, end int, budget *viewBudget) (*view, error) {
	start = max(0, min(len(v.text), start))
	end = max(start, min(len(v.text), end))
	text := v.text[:end]
	if bytes.IndexByte(text[start:], '\r') < 0 && bytes.IndexByte(text[start:], '\n') < 0 {
		return nil, nil
	}
	b := newBuilder(end-start, budget)
	c := cursorAt(v, start)
	for i := start; i < end; {
		if text[i] == '\r' || text[i] == '\n' {
			if text[i] == '\r' && i+1 < end && text[i+1] == '\n' {
				i++
			}
			i++
			for indentation := 0; indentation < maxJoinedIndentation && i < end && (text[i] == ' ' || text[i] == '\t'); indentation++ {
				i++
			}
			continue
		}
		next, err := c.copyElement(b, i)
		if err != nil {
			return nil, err
		}
		i = next
	}
	return b.finish(budget, EncodingWhitespaceJoined), nil
}

// textViews sont les vues d'une entrée (collectFindings et scanDecodedText de Secret Guard) : identité, normalisée
// (absente si la normalisation ne change rien), canonique (normalisée, sinon identité) et transformées.
type textViews struct {
	identity, normalized, canonical *view
	transformed                     []*view
}

// buildTextViews construit les vues d'une entrée lue en octets. La limite d'entrée de 1 Mio est celle de l'analyse,
// appliquée avant cet appel ; au-delà de maxViewBytes, l'entrée est refusée ici aussi.
func buildTextViews(content []byte, budget *viewBudget) (*textViews, error) {
	if len(content) > maxViewBytes || len(content) > math.MaxInt32 {
		return nil, errViewBudgetExhausted
	}
	identity := identityView(content)
	normalized, err := normalizedView(identity, budget)
	if err != nil {
		return nil, err
	}
	canonical := identity
	if normalized != nil {
		canonical = normalized
	}
	transformed, err := transformedTextViews(canonical, budget)
	if err != nil {
		return nil, err
	}
	return &textViews{identity: identity, normalized: normalized, canonical: canonical, transformed: transformed}, nil
}

// transformedTextViews applique au plus une couche de pourcentage et une couche JSON, dans les deux ordres, chaque
// vue étant ensuite canonicalisée (transformedTextViews de Secret Guard).
func transformedTextViews(canonical *view, budget *viewBudget) ([]*view, error) {
	var transformed []*view
	percent, err := percentDecodedView(canonical, budget)
	if err != nil {
		return nil, err
	}
	json, err := jsonEscapedView(canonical, budget)
	if err != nil {
		return nil, err
	}
	if percent != nil {
		canonicalPercent, err := canonicalizedView(percent, budget)
		if err != nil {
			return nil, err
		}
		transformed = append(transformed, canonicalPercent)
		jsonAfterPercent, err := jsonEscapedView(canonicalPercent, budget)
		if err != nil {
			return nil, err
		}
		if jsonAfterPercent != nil {
			canonicalJSONAfterPercent, err := canonicalizedView(jsonAfterPercent, budget)
			if err != nil {
				return nil, err
			}
			transformed = append(transformed, canonicalJSONAfterPercent)
		}
	}
	if json != nil {
		canonicalJSON, err := canonicalizedView(json, budget)
		if err != nil {
			return nil, err
		}
		transformed = append(transformed, canonicalJSON)
		percentAfterJSON, err := percentDecodedView(canonicalJSON, budget)
		if err != nil {
			return nil, err
		}
		if percentAfterJSON != nil {
			canonicalPercentAfterJSON, err := canonicalizedView(percentAfterJSON, budget)
			if err != nil {
				return nil, err
			}
			transformed = append(transformed, canonicalPercentAfterJSON)
		}
	}
	return transformed, nil
}

// isBase64Character suit isBase64Character de Secret Guard (alphabets standard et URL).
func isBase64Character(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '+' || c == '/' || c == '_' || c == '-'
}

// isFixedTokenCharacter suit isFixedTokenCharacter de Secret Guard.
func isFixedTokenCharacter(c byte) bool { return isBase64Character(c) || c == '.' || c == '=' }

func byteAt(text []byte, i int) (byte, bool) {
	if i < 0 || i >= len(text) {
		return 0, false
	}
	return text[i], true
}

func isAt(text []byte, i int, want byte) bool {
	c, ok := byteAt(text, i)
	return ok && c == want
}

func isSpaceOrTab(text []byte, i int) bool { return isAt(text, i, ' ') || isAt(text, i, '\t') }

func isBase64At(text []byte, i int) bool {
	c, ok := byteAt(text, i)
	return ok && isBase64Character(c)
}

func isFixedTokenAt(text []byte, i int) bool {
	c, ok := byteAt(text, i)
	return ok && isFixedTokenCharacter(c)
}

// tokenPrefixes sont les préfixes de jetons fixes cherchés à travers un retour à la ligne (TOKEN_PREFIXES de Secret
// Guard, même ordre : à une même position, le premier préfixe qui correspond l'emporte).
var tokenPrefixes = []string{
	"github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "glpat-", "sk-", "sk_live_", "sk_test_", "rk_live_",
	"rk_test_", "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "https://hooks.slack.com/services/", "AIza", "ya29.",
	"SG.", "npm_", "hf_", "dapi", "dop_v1_", "shpat_", "shpss_", "shpca_", "shppa_", "AccountKey=", "AKIA", "ASIA",
	"AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "eyJ",
}

// prefixesByFirstByte indexe tokenPrefixes par premier octet, dans l'ordre de la liste.
var prefixesByFirstByte = func() *[256][]string {
	var index [256][]string
	for _, prefix := range tokenPrefixes {
		index[prefix[0]] = append(index[prefix[0]], prefix)
	}
	return &index
}()

// skipLineWrap passe un retour à la ligne facultatif « \r?\n[ \t]{0,4} » (OPTIONAL_LINE_WRAP de Secret Guard).
func skipLineWrap(text []byte, i int) int {
	switch {
	case isAt(text, i, '\r') && isAt(text, i+1, '\n'):
		i += 2
	case isAt(text, i, '\n'):
		i++
	default:
		return i
	}
	for indentation := 0; indentation < maxJoinedIndentation && isSpaceOrTab(text, i); indentation++ {
		i++
	}
	return i
}

// matchPrefixAt rend la fin de la correspondance de SPLIT_TOKEN_PREFIX qui commence à l'octet i. L'expression
// d'origine est une alternative de littéraux séparés par OPTIONAL_LINE_WRAP ; aucun littéral n'étant un espace, une
// tabulation, CR ou LF, la lecture gloutonne sans retour arrière donne la même correspondance.
func matchPrefixAt(text []byte, i int) (int, bool) {
	for _, prefix := range prefixesByFirstByte[text[i]] {
		position := i + 1
		matched := true
		for k := 1; k < len(prefix); k++ {
			position = skipLineWrap(text, position)
			if !isAt(text, position, prefix[k]) {
				matched = false
				break
			}
			position++
		}
		if matched {
			return position, true
		}
	}
	return 0, false
}

// fixedRunEnds donne, pour chaque position, la fin de la suite de caractères de jeton fixe qui y commence.
func fixedRunEnds(text []byte) []int32 {
	ends := make([]int32, len(text)+1)
	ends[len(text)] = int32(len(text))
	for i := len(text) - 1; i >= 0; i-- {
		if isFixedTokenCharacter(text[i]) {
			ends[i] = ends[i+1]
		} else {
			ends[i] = int32(i)
		}
	}
	return ends
}

func isWordByte(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '_'
}

// lineWrappedFixedViews rend les fenêtres jointes des jetons fixes coupés par un retour à la ligne
// (lineWrappedFixedViews de Secret Guard). Linéaire : la fin de chaque suite de caractères de jeton est calculée une
// fois, et seules les fenêtres qui contiennent un saut de ligne (au plus maxJoinedWindows) en parcourent plusieurs.
func lineWrappedFixedViews(v *view, windows *windowBudget, budget *viewBudget) ([]*view, error) {
	text := v.text
	if bytes.IndexByte(text, '\n') < 0 {
		return nil, nil
	}
	var runEnds []int32
	var joined []*view
	for i := 0; i < len(text); {
		matchEnd, ok := matchPrefixAt(text, i)
		if !ok {
			i++
			continue
		}
		start := i
		i = matchEnd
		if previous, ok := byteAt(text, start-1); ok && isWordByte(previous) {
			continue
		}
		if runEnds == nil {
			runEnds = fixedRunEnds(text)
		}
		end := matchEnd
		characters := 0
		hasNewline := false
		for _, c := range text[start:matchEnd] {
			switch c {
			case '\n':
				hasNewline = true
			case '\r', ' ', '\t':
			default:
				characters++
			}
		}
		take := min(int(runEnds[end])-end, max(0, maxJoinedCandidateCharacters-characters))
		end += take
		characters += take
		for characters < maxJoinedCandidateCharacters {
			cursor := end
			switch {
			case isAt(text, cursor, '\r') && isAt(text, cursor+1, '\n'):
				cursor += 2
			case isAt(text, cursor, '\n'):
				cursor++
			default:
				cursor = -1
			}
			if cursor < 0 {
				break
			}
			for indentation := 0; indentation < maxJoinedIndentation && isSpaceOrTab(text, cursor); indentation++ {
				cursor++
			}
			if !isFixedTokenAt(text, cursor) {
				break
			}
			take := min(int(runEnds[cursor])-cursor, maxJoinedCandidateCharacters-characters)
			cursor += take
			characters += take
			end = cursor
			hasNewline = true
		}
		if !hasNewline {
			continue
		}
		window, err := joinedWindow(v, start, end, budget)
		if err != nil {
			return nil, err
		}
		if window != nil {
			joined = append(joined, window)
			windows.windows++
		}
		if windows.windows > maxJoinedWindows {
			return nil, errJoinedWindowBudgetExhausted
		}
	}
	return joined, nil
}

// consumeWrappedTail suit consumeWrappedTail de Secret Guard : prolonge une fenêtre base64 sur les lignes
// suivantes jusqu'au remplissage « = » ou à maxJoinedCandidateCharacters.
func consumeWrappedTail(text []byte, initialEnd, initialCharacters int) int {
	end := initialEnd
	characters := initialCharacters
	padding := 0
	for padding < 2 && isAt(text, end, '=') {
		end++
		padding++
	}
	if padding > 0 {
		return end
	}
	for characters < maxJoinedCandidateCharacters {
		cursor := end
		switch {
		case isAt(text, cursor, '\r') && isAt(text, cursor+1, '\n'):
			cursor += 2
		case isAt(text, cursor, '\n'):
			cursor++
		default:
			return end
		}
		for indentation := 0; indentation < maxJoinedIndentation && isSpaceOrTab(text, cursor); indentation++ {
			cursor++
		}
		if !isBase64At(text, cursor) {
			return end
		}
		for characters < maxJoinedCandidateCharacters && isBase64At(text, cursor) {
			cursor++
			characters++
		}
		padding = 0
		for padding < 2 && isAt(text, cursor, '=') {
			cursor++
			padding++
		}
		end = cursor
		if padding > 0 {
			return end
		}
	}
	return end
}

// lineWrappedBase64Views rend les fenêtres jointes des charges base64 coupées par un retour à la ligne
// (lineWrappedBase64Views de Secret Guard). Linéaire : la suite avant et la suite après chaque saut de ligne sont
// lues une fois chacune, et un saut de ligne déjà couvert par une fenêtre est passé.
func lineWrappedBase64Views(v *view, windows *windowBudget, budget *viewBudget) ([]*view, error) {
	text := v.text
	newline := bytes.IndexByte(text, '\n')
	if newline < 0 {
		return nil, nil
	}
	var joined []*view
	coveredUntil := -1
	for newline >= 0 {
		if newline >= coveredUntil {
			left := newline - 1
			if isAt(text, left, '\r') {
				left--
			}
			leftLength := 0
			for left >= 0 && leftLength < maxJoinedCandidateCharacters && isBase64Character(text[left]) {
				left--
				leftLength++
			}
			right := newline + 1
			for indentation := 0; indentation < maxJoinedIndentation && isSpaceOrTab(text, right); indentation++ {
				right++
			}
			rightStart := right
			rightBudget := max(0, maxJoinedCandidateCharacters-leftLength)
			for right-rightStart < rightBudget && isBase64At(text, right) {
				right++
			}
			rightLength := right - rightStart
			if leftLength >= 8 && rightLength >= 8 {
				extendedEnd := consumeWrappedTail(text, right, leftLength+rightLength)
				window, err := joinedWindow(v, left+1, extendedEnd, budget)
				if err != nil {
					return nil, err
				}
				if window != nil {
					joined = append(joined, window)
					windows.windows++
				}
				coveredUntil = extendedEnd
				if windows.windows > maxJoinedWindows {
					return nil, errJoinedWindowBudgetExhausted
				}
			}
		}
		next := bytes.IndexByte(text[newline+1:], '\n')
		if next < 0 {
			break
		}
		newline += 1 + next
	}
	return joined, nil
}
