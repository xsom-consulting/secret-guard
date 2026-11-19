// SPDX-License-Identifier: Apache-2.0

// Porte littérale des motifs.
//
// Chaque motif commence par des mots obligatoires (« ignore », « you are now », « <|im_start|> »…). À la
// compilation, l'arbre regexp/syntax du motif donne ces débuts littéraux (anchors). Une lecture du texte, replié en
// minuscules, relève leurs occurrences ; le motif n'est exécuté qu'à ces endroits, ancré, sur une fenêtre de la
// longueur de sa plus longue correspondance. Un texte sans aucun de ces mots ne coûte qu'une lecture.
//
// Le résultat est celui du motif cherché à chaque position du texte (test TestGateFindsEveryMatch), à deux écarts
// près, bornés et sans effet sur un texte ordinaire : une répétition sans borne (« \s+ ») est lue sur
// unboundedRepeat caractères au plus, et le repli des mots obligatoires ne connaît que l'ASCII et les lettres
// accentuées du Latin-1 (U+212A et U+017F, que RE2 replie sur « k » et « s », sont lus par la vue normalisée).

package injection

import (
	"bytes"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// unboundedRepeat est le nombre de répétitions compté pour « * », « + » et « {n,} » dans la fenêtre d'un motif.
	unboundedRepeat = 64
	// windowMargin : octets lus après la plus longue correspondance, pour que la limite de mot finale voie le texte.
	windowMargin = 8
	// maxAnchors borne les débuts littéraux d'un motif.
	maxAnchors = 96
	// minAnchorBytes : un début littéral plus court ne trie rien.
	minAnchorBytes = 2
	// minRequiredBytes : un mot obligatoire plus court n'est pas cherché.
	minRequiredBytes = 3
)

// pattern est un motif compilé et sa porte.
type pattern struct {
	rule Rule
	// re est le motif ancré au début de la fenêtre.
	re *regexp.Regexp
	// anchors sont les débuts littéraux, en minuscules : toute correspondance commence par l'un d'eux.
	anchors []string
	// wordStart : le motif commence par une limite de mot ; lineStart : par un début de ligne.
	wordStart, lineStart bool
	// window est la longueur de fenêtre, en octets.
	window int
	// singleLine : aucune correspondance ne contient de fin de ligne ; la fenêtre s'arrête alors à la fin de la ligne.
	singleLine bool
	// required : listes de mots en minuscules ; toute correspondance contient au moins un mot de chaque liste.
	required [][]string
	// requiredSets sont les rangs de ces listes dans l'index de la porte.
	requiredSets []int
	// requiredShort : listes de même sens dont un mot a moins de minRequiredBytes octets (« @ »), cherchées dans la
	// fenêtre.
	requiredShort [][]string
	// before est un motif de contexte, cherché dans les octets qui précèdent la correspondance sur sa ligne
	// (context.go). beforeRequired : la correspondance n'est gardée que s'il s'y trouve ; sinon elle est écartée s'il
	// s'y trouve.
	before         *regexp.Regexp
	beforeRequired bool
}

// compilePattern compile un motif RE2 et calcule sa porte. Un motif sans début littéral utilisable est une erreur de
// programmation : la panique arrête les tests du paquet.
func compilePattern(rule Rule, source string) pattern {
	tree, err := syntax.Parse(source, syntax.Perl)
	if err != nil {
		panic("injection : motif illisible : " + source)
	}
	p := pattern{rule: rule}
	// Les assertions de tête (limite de mot, début de ligne) sont vérifiées à la main, sur le texte entier : la
	// fenêtre commence au mot obligatoire, et le motif ancré est compilé sans elles.
	subs := []*syntax.Regexp{tree}
	if tree.Op == syntax.OpConcat {
		subs = tree.Sub
	}
	flags, rest := splitFlags(source)
	for len(subs) > 0 && (subs[0].Op == syntax.OpWordBoundary || subs[0].Op == syntax.OpBeginLine) {
		assertion := `\b`
		if subs[0].Op == syntax.OpWordBoundary {
			p.wordStart = true
		} else {
			p.lineStart = true
			assertion = "^"
		}
		if !strings.HasPrefix(rest, assertion) {
			panic("injection : assertion de tête illisible : " + source)
		}
		rest = rest[len(assertion):]
		subs = subs[1:]
	}
	body := &syntax.Regexp{Op: syntax.OpConcat, Sub: subs, Flags: tree.Flags}
	p.re = regexp.MustCompile(anchoredSource(flags, rest))
	set, _ := leadingLiterals(body)
	p.anchors = pruneAnchors(set)
	for _, anchor := range p.anchors {
		if len(anchor) < minAnchorBytes {
			panic("injection : motif sans début littéral : " + source)
		}
	}
	if len(p.anchors) == 0 {
		panic("injection : motif sans début littéral : " + source)
	}
	p.window = maxMatchBytes(body) + windowMargin
	p.singleLine = !matchesNewline(body)
	// Mots obligatoires de la suite du motif : chaque élément de la concaténation dont toute correspondance contient
	// l'un de quelques mots connus en impose un. Le premier élément est le début littéral, déjà trouvé. Une liste dont
	// un mot est trop court pour l'index est cherchée dans la fenêtre elle-même.
	for _, sub := range subs[min(1, len(subs)):] {
		words, ok := containedLiterals(sub)
		if !ok || len(words) == 0 || len(words) > maxAnchors {
			continue
		}
		words = pruneContained(words)
		if len(words[0]) >= minRequiredBytes {
			p.required = append(p.required, words)
		} else {
			p.requiredShort = append(p.requiredShort, words)
		}
	}
	return p
}

// splitFlags sépare la source d'un motif de ses drapeaux de tête (« (?i) », « (?im) »), qui valent pour tout le motif.
func splitFlags(source string) (flags, rest string) {
	if !strings.HasPrefix(source, "(?") {
		return "", source
	}
	end := strings.IndexByte(source, ')')
	if end < 0 || strings.Trim(source[2:end], "imsU-") != "" {
		return "", source
	}
	return source[:end+1], source[end+1:]
}

// anchoredSource rend le motif ancré au début de la fenêtre : ses drapeaux de tête, \A, puis le reste du motif tel
// qu'il est écrit, assertions de tête retirées. Le motif n'est pas réécrit depuis son arbre ((*syntax.Regexp).String) :
// pour chaque classe niée ([^.\n]) répétée, cette réécriture replie la casse de chaque point de code d'Unicode, et
// coûtait plus de 150 ms pour l'ensemble des motifs, à chaque processus qui cherchait une consigne. Le programme
// compilé est le même (TestAnchoredSourceSameProgram).
func anchoredSource(flags, rest string) string {
	return flags + `\A(?:` + rest + `)`
}

// leadingLiterals rend des chaînes en minuscules dont l'une commence toute correspondance du nœud. exact : le nœud
// ne correspond qu'à ces chaînes entières (la suite d'une concaténation peut alors les prolonger).
func leadingLiterals(re *syntax.Regexp) (set []string, exact bool) {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{strings.ToLower(string(re.Rune))}, true
	case syntax.OpCharClass:
		// Petite classe ([eé], [rz]) : une chaîne par caractère. Les variantes de casse se rejoignent en minuscules.
		seen := map[string]bool{}
		for i := 0; i+1 < len(re.Rune); i += 2 {
			if re.Rune[i+1]-re.Rune[i] > 8 {
				return []string{""}, false
			}
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				seen[string(unicode.ToLower(r))] = true
			}
		}
		if len(seen) == 0 || len(seen) > 4 {
			return []string{""}, false
		}
		for s := range seen {
			set = append(set, s)
		}
		sort.Strings(set)
		return set, true
	case syntax.OpCapture:
		return leadingLiterals(re.Sub[0])
	case syntax.OpEmptyMatch:
		return []string{""}, true
	case syntax.OpConcat:
		set = []string{""}
		for _, sub := range re.Sub {
			next, nextExact := leadingLiterals(sub)
			if len(set)*len(next) > maxAnchors {
				return set, false
			}
			product := make([]string, 0, len(set)*len(next))
			for _, head := range set {
				for _, tail := range next {
					product = append(product, head+tail)
				}
			}
			set = product
			if !nextExact {
				return set, false
			}
		}
		return set, true
	case syntax.OpAlternate:
		exact = true
		for _, sub := range re.Sub {
			next, nextExact := leadingLiterals(sub)
			set = append(set, next...)
			exact = exact && nextExact
		}
		if len(set) > maxAnchors {
			return []string{""}, false
		}
		return set, exact
	case syntax.OpQuest:
		next, nextExact := leadingLiterals(re.Sub[0])
		return append([]string{""}, next...), nextExact
	case syntax.OpPlus:
		next, _ := leadingLiterals(re.Sub[0])
		return next, false
	case syntax.OpRepeat:
		if re.Min >= 1 {
			next, _ := leadingLiterals(re.Sub[0])
			return next, false
		}
		return []string{""}, false
	default:
		// Étoile, classe large, point, assertion : rien de sûr à partir d'ici.
		return []string{""}, false
	}
}

// containedLiterals rend des chaînes en minuscules dont l'une au moins figure dans toute correspondance du nœud ;
// ok est faux quand on ne sait pas en donner.
func containedLiterals(re *syntax.Regexp) (words []string, ok bool) {
	switch re.Op {
	case syntax.OpLiteral, syntax.OpCharClass:
		words, exact := leadingLiterals(re)
		return words, exact
	case syntax.OpCapture, syntax.OpPlus:
		return containedLiterals(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return containedLiterals(re.Sub[0])
		}
		return nil, false
	case syntax.OpConcat:
		// Une correspondance contient celle de chaque élément : on garde la liste dont le mot le plus court est le
		// plus long. Deux littéraux qui se suivent ne sont pas réunis.
		best := -1
		for _, sub := range re.Sub {
			candidate, candidateOK := containedLiterals(sub)
			if !candidateOK || len(candidate) == 0 {
				continue
			}
			shortest := len(candidate[0])
			for _, word := range candidate {
				shortest = min(shortest, len(word))
			}
			if shortest > best {
				best, words = shortest, candidate
			}
		}
		return words, best > 0
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			branch, branchOK := containedLiterals(sub)
			if !branchOK {
				return nil, false
			}
			words = append(words, branch...)
		}
		return words, true
	default:
		return nil, false
	}
}

// pruneContained retire les doublons et tout mot qui en contient un autre de la liste.
func pruneContained(words []string) []string {
	sort.Slice(words, func(i, j int) bool {
		if len(words[i]) != len(words[j]) {
			return len(words[i]) < len(words[j])
		}
		return words[i] < words[j]
	})
	var kept []string
	for _, word := range words {
		contained := false
		for _, shorter := range kept {
			if strings.Contains(word, shorter) {
				contained = true
				break
			}
		}
		if !contained {
			kept = append(kept, word)
		}
	}
	return kept
}

// matchesNewline dit si une correspondance du nœud peut contenir une fin de ligne.
func matchesNewline(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if r == '\n' {
				return true
			}
		}
		return false
	case syntax.OpCharClass:
		for i := 0; i+1 < len(re.Rune); i += 2 {
			if re.Rune[i] <= '\n' && '\n' <= re.Rune[i+1] {
				return true
			}
		}
		return false
	case syntax.OpAnyChar:
		return true
	default:
		for _, sub := range re.Sub {
			if matchesNewline(sub) {
				return true
			}
		}
		return false
	}
}

// pruneAnchors retire les doublons et toute chaîne qu'une autre, plus courte, commence déjà. Une chaîne vide rend
// l'ensemble inutilisable (rendue telle quelle : compilePattern la refuse).
func pruneAnchors(set []string) []string {
	sort.Strings(set)
	var kept []string
	for _, anchor := range set {
		covered := false
		for _, shorter := range kept {
			if strings.HasPrefix(anchor, shorter) {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, anchor)
		}
	}
	return kept
}

// maxMatchBytes majore la longueur en octets d'une correspondance : un littéral compte la plus longue de ses
// écritures (repli de casse compris), une classe son caractère le plus long, une répétition sans borne
// unboundedRepeat fois.
func maxMatchBytes(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpLiteral:
		total := 0
		for _, r := range re.Rune {
			longest := utf8.RuneLen(r)
			if re.Flags&syntax.FoldCase != 0 {
				for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
					longest = max(longest, utf8.RuneLen(folded))
				}
			}
			total += longest
		}
		return total
	case syntax.OpCharClass:
		if len(re.Rune) == 0 {
			return 0
		}
		return utf8.RuneLen(re.Rune[len(re.Rune)-1])
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return utf8.UTFMax
	case syntax.OpCapture, syntax.OpQuest:
		return maxMatchBytes(re.Sub[0])
	case syntax.OpStar, syntax.OpPlus:
		return unboundedRepeat * maxMatchBytes(re.Sub[0])
	case syntax.OpRepeat:
		count := re.Max
		if count < 0 {
			count = max(re.Min, unboundedRepeat)
		}
		return count * maxMatchBytes(re.Sub[0])
	case syntax.OpConcat:
		total := 0
		for _, sub := range re.Sub {
			total += maxMatchBytes(sub)
		}
		return total
	case syntax.OpAlternate:
		longest := 0
		for _, sub := range re.Sub {
			longest = max(longest, maxMatchBytes(sub))
		}
		return longest
	default:
		return 0
	}
}

// entry est un mot de l'index : début littéral d'un motif (pattern ≥ 0) ou mot d'une liste obligatoire (pattern < 0,
// liste de rang set).
type entry struct {
	text         string
	pattern, set int
}

// gate est l'index des débuts littéraux et des mots obligatoires de tous les motifs : buckets[k] liste ceux qui
// commencent par les deux octets de clé k (premier octet × 256 + second).
type gate struct {
	index   [1 << 16]uint16 // numéro de liste + 1 ; 0 : aucun mot ne commence par ces deux octets
	buckets [][]entry
	// sets est le nombre de listes de mots obligatoires.
	sets int
}

func (g *gate) add(e entry) {
	key := int(e.text[0])<<8 | int(e.text[1])
	if g.index[key] == 0 {
		g.buckets = append(g.buckets, nil)
		g.index[key] = uint16(len(g.buckets))
	}
	bucket := g.index[key] - 1
	g.buckets[bucket] = append(g.buckets[bucket], e)
}

// newGate indexe les motifs et note, dans chacun, le rang de ses listes de mots obligatoires.
func newGate(patterns []pattern) *gate {
	g := &gate{}
	for i := range patterns {
		for _, anchor := range patterns[i].anchors {
			g.add(entry{text: anchor, pattern: i})
		}
		for _, words := range patterns[i].required {
			for _, word := range words {
				g.add(entry{text: word, pattern: -1, set: g.sets})
			}
			patterns[i].requiredSets = append(patterns[i].requiredSets, g.sets)
			g.sets++
		}
	}
	return g
}

// foldLower rend le texte en minuscules, octet pour octet : lettres ASCII, et lettres majuscules accentuées du
// Latin-1 (U+00C0 à U+00DE, écrites 0xC3 puis 0x80 à 0x9E en UTF-8), dont la minuscule a la même longueur.
func foldLower(text []byte) []byte {
	folded := make([]byte, len(text))
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
		case c == 0xC3 && i+1 < len(text) && text[i+1] >= 0x80 && text[i+1] <= 0x9E && text[i+1] != 0x97:
			folded[i] = c
			i++
			c = text[i] + 0x20
		}
		folded[i] = c
	}
	return folded
}

func isWordByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// containsAny dit si la fenêtre contient l'un des mots.
func containsAny(window []byte, words []string) bool {
	for _, word := range words {
		if bytes.Contains(window, []byte(word)) {
			return true
		}
	}
	return false
}

// occurs dit si l'une des positions, croissantes, est dans [lo, hi).
func occurs(positions []int32, lo, hi int) bool {
	k := sort.Search(len(positions), func(k int) bool { return int(positions[k]) >= lo })
	return k < len(positions) && int(positions[k]) < hi
}

// hit est l'occurrence d'un début littéral.
type hit struct {
	at, pattern int32
}

// scan appelle yield pour chaque correspondance d'un motif dans la vue : rang du motif et étendue, en octets de la
// vue. Une lecture du texte relève les débuts littéraux et la position des mots obligatoires ; un motif n'est exécuté
// qu'à un début dont la fenêtre porte un mot de chacune de ses listes. Dans une vue dérivée, une fenêtre déjà lue
// dans une vue précédente (view.seen) n'est pas relue.
func (g *gate) scan(patterns []pattern, v *view, yield func(pattern, start, end int)) {
	text := v.text
	if len(text) < minAnchorBytes {
		return
	}
	folded := foldLower(text)
	var hits []hit
	words := make([][]int32, g.sets)
	for i := 0; i+1 < len(folded); i++ {
		bucket := g.index[int(folded[i])<<8|int(folded[i+1])]
		if bucket == 0 {
			continue
		}
		for _, e := range g.buckets[bucket-1] {
			if len(folded)-i < len(e.text) || string(folded[i:i+len(e.text)]) != e.text {
				continue
			}
			if e.pattern < 0 {
				words[e.set] = append(words[e.set], int32(i))
			} else {
				hits = append(hits, hit{int32(i), int32(e.pattern)})
			}
		}
	}
candidates:
	for _, h := range hits {
		i, p := int(h.at), &patterns[h.pattern]
		if p.wordStart && (i > 0 && isWordByte(text[i-1])) == isWordByte(text[i]) {
			continue
		}
		if p.lineStart && i > 0 && text[i-1] != '\n' {
			continue
		}
		end := min(len(text), i+p.window)
		if p.singleLine {
			if lineEnd := bytes.IndexByte(text[i:end], '\n'); lineEnd >= 0 {
				end = i + lineEnd
			}
		}
		for _, set := range p.requiredSets {
			if !occurs(words[set], i, end) {
				continue candidates
			}
		}
		for _, short := range p.requiredShort {
			if !containsAny(folded[i:end], short) {
				continue candidates
			}
		}
		// Le contexte d'une correspondance (context.go) déborde de la fenêtre : il fait partie de ce qui doit avoir
		// été lu à l'identique.
		if v.seen(i-contextBytes, end+quoteTail+contextMargin) {
			continue
		}
		if loc := p.re.FindIndex(text[i:end]); loc != nil && p.accept(text, i, i+loc[1]) {
			yield(int(h.pattern), i, i+loc[1])
		}
	}
}
