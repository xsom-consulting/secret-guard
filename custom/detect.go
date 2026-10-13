// Sémantique de détection du Pack de règles du client (docs/custom-pack.md, §4), avec le préfiltre littéral et le
// budget de travail du §5.
//
// Portage en Go de secret-guard/packages/core/src/custom/detect.ts et de collectCustomFindings de
// secret-guard/packages/core/src/scanner.ts (Apache-2.0, origine, avis et modifications dans UPSTREAM.md). Positions
// en octets du texte ; longueurs comptées en unités UTF-16 là où l'origine compte le travail, en points de code pour
// la fenêtre de contexte, comme l'origine.

package custom

import (
	"bytes"
	"crypto/sha256"
	"unicode"
	"unicode/utf8"
)

// compiledContext : mots-clés en minuscules ASCII et fenêtre en points de code de chaque côté d'une correspondance.
type compiledContext struct {
	keywords [][]byte
	window   int
}

// detector est un détecteur compilé : motif (pattern) ou termes (terms non nil).
type detector struct {
	spec    Detector
	pattern *safePattern
	// minEntropyTenths : seuil d'entropie en dixièmes de bit par caractère ; -1 sans seuil.
	minEntropyTenths int
	terms            *termsDetector
	context          *compiledContext
}

type termsDetector struct {
	salt     string
	digests  map[[sha256.Size]byte]bool
	maxWords int
}

// termGroup : détecteurs de termes de même sel, hachés en une passe.
type termGroup struct {
	salt      []byte
	maxWords  int
	digests   map[[sha256.Size]byte]bool
	detectors []int
}

func termGroups(detectors []*detector) []termGroup {
	var groups []termGroup
	bySalt := map[string]int{}
	for index, d := range detectors {
		if d.terms == nil {
			continue
		}
		at, ok := bySalt[d.terms.salt]
		if !ok {
			at = len(groups)
			bySalt[d.terms.salt] = at
			groups = append(groups, termGroup{salt: decodeSalt(d.terms.salt), digests: map[[sha256.Size]byte]bool{}})
		}
		group := &groups[at]
		group.detectors = append(group.detectors, index)
		group.maxWords = max(group.maxWords, d.terms.maxWords)
		for digest := range d.terms.digests {
			group.digests[digest] = true
		}
	}
	return groups
}

// span est une détection : étendue [start, end) en octets du texte, jamais son contenu.
type span struct{ start, end int }

// textView porte l'état partagé par tous les détecteurs d'une analyse d'un texte (TextView de l'origine).
type textView struct {
	text       []byte
	meter      *Meter
	maxMatches int // < 0 : sans limite
	matches    int
	units      int
	lowered    []byte
	words      []word
	wordsReady bool
	// found : correspondances de chaque motif traduit sur tout le texte, partagées par les détecteurs de même motif.
	found map[string][]span
}

func newTextView(text []byte, meter *Meter, maxMatches int) *textView {
	return &textView{text: text, meter: meter, maxMatches: maxMatches, units: utf16Units(text), found: map[string][]span{}}
}

// keep compte les détections gardées ; au-delà de la limite, l'analyse s'arrête (fail-closed).
func (v *textView) keep(count int) {
	v.matches += count
	if v.maxMatches >= 0 && v.matches > v.maxMatches {
		panic(tooManyMatches{})
	}
}

// lower rend la copie du texte aux lettres ASCII en minuscules (même longueur), calculée une fois.
func (v *textView) lower() []byte {
	if v.lowered == nil {
		v.meter.spend(ceilDiv(v.units, 64))
		v.lowered = asciiLower(v.text)
	}
	return v.lowered
}

func (v *textView) textWords() []word {
	if !v.wordsReady {
		v.words = textWords(v.text, v.meter)
		v.wordsReady = true
	}
	return v.words
}

// backwards recule de count points de code depuis index, dans les bornes du texte.
func backwards(text []byte, index, count int) int {
	for step := 0; step < count && index > 0; step++ {
		_, width := utf8.DecodeLastRune(text[:index])
		index -= width
	}
	return index
}

// forwards avance de count points de code depuis index, dans les bornes du texte.
func forwards(text []byte, index, count int) int {
	for step := 0; step < count && index < len(text); step++ {
		_, width := utf8.DecodeRune(text[index:])
		index += width
	}
	return index
}

// contextHolds dit si un mot-clé est entièrement dans [début − fenêtre, fin + fenêtre), en points de code.
func (v *textView) contextHolds(match span, context *compiledContext) bool {
	from := backwards(v.text, match.start, context.window)
	to := forwards(v.text, match.end, context.window)
	around := v.lower()[from:to]
	v.meter.spend(int64(utf16Units(around) + context.window))
	for _, keyword := range context.keywords {
		if bytes.Contains(around, keyword) {
			return true
		}
	}
	return false
}

// anyKeyword dit si un mot-clé du contexte apparaît dans le texte (préfiltre d'un motif sans ancre).
func (v *textView) anyKeyword(context *compiledContext) bool {
	for _, keyword := range context.keywords {
		v.meter.spend(ceilDiv(v.units, 64))
		if bytes.Contains(v.lower(), keyword) {
			return true
		}
	}
	return false
}

// interval : positions de début [start, end] où une correspondance peut commencer.
type interval struct{ start, end int }

// anchorIntervals rend les débuts possibles d'une correspondance autour de chaque occurrence de l'ancre, fusionnés.
func (v *textView) anchorIntervals(p *safePattern) []interval {
	haystack := v.text
	if p.caseInsensitive {
		haystack = v.lower()
	}
	v.meter.spend(ceilDiv(v.units, 64))
	var intervals []interval
	for from := 0; ; {
		at := bytes.Index(haystack[from:], p.anchor.text)
		if at < 0 {
			break
		}
		found := from + at
		from = found + 1
		v.meter.spend(1)
		start, end := max(0, found-p.anchor.offsetMax), found-p.anchor.offsetMin
		if end < 0 {
			continue
		}
		if last := len(intervals) - 1; last >= 0 && start <= intervals[last].end+1 {
			intervals[last].end = max(intervals[last].end, end)
			continue
		}
		intervals = append(intervals, interval{start: start, end: end})
	}
	return intervals
}

// patternMatches rend les correspondances « les plus à gauche, premier choix d'abord », sans chevauchement, sur tout
// le texte (matchAll d'ECMAScript), cherchées seulement là où une correspondance peut commencer : autour de l'ancre,
// ou dans tout le texte pour un motif sans ancre si un mot-clé de son contexte y apparaît.
func (v *textView) patternMatches(d *detector) []span {
	p := d.pattern
	var intervals []interval
	switch {
	case p.anchor != nil:
		intervals = v.anchorIntervals(p)
	case d.context != nil && v.anyKeyword(d.context):
		intervals = []interval{{start: 0, end: len(v.text) - 1}}
	default:
		return nil
	}
	if found, ok := v.found[p.key]; ok {
		return found
	}
	found := v.search(p, intervals)
	v.found[p.key] = found
	return found
}

// keepPatternMatch applique le seuil d'entropie puis le contexte.
func (v *textView) keepPatternMatch(d *detector, match span) bool {
	if d.minEntropyTenths >= 0 {
		v.meter.spend(int64(match.end - match.start))
		if shannonEntropy(v.text[match.start:match.end]) < float64(d.minEntropyTenths)/10 {
			return false
		}
	}
	return d.context == nil || v.contextHolds(match, d.context)
}

// shannonEntropy est l'entropie de Shannon de value en bits par caractère (correspondance ASCII : un octet par
// caractère), comptée dans l'ordre des premières occurrences et sommée naïvement, comme l'origine.
func shannonEntropy(value []byte) float64 {
	var counts [256]int
	var order []byte
	for _, c := range value {
		if counts[c] == 0 {
			order = append(order, c)
		}
		counts[c]++
	}
	length := float64(len(value))
	entropy := 0.0
	for _, c := range order {
		probability := float64(counts[c]) / length
		entropy -= float64(probability * jsLog2(probability))
	}
	return entropy
}

// resolveTermCandidates trie les candidats par début croissant puis longueur décroissante, et garde chaque candidat
// qui ne chevauche pas le précédent gardé.
func resolveTermCandidates(candidates []termHit) []span {
	ordered := make([]span, len(candidates))
	for i, c := range candidates {
		ordered[i] = span{start: c.start, end: c.end}
	}
	// Tri par insertion stable (candidats déjà presque triés : par premier mot, puis nombre de mots croissant).
	for i := 1; i < len(ordered); i++ {
		for j := i; j > 0 && termBefore(ordered[j], ordered[j-1]); j-- {
			ordered[j], ordered[j-1] = ordered[j-1], ordered[j]
		}
	}
	var kept []span
	for _, candidate := range ordered {
		if last := len(kept) - 1; last >= 0 && candidate.start < kept[last].end {
			continue
		}
		kept = append(kept, candidate)
	}
	return kept
}

func termBefore(left, right span) bool {
	if left.start != right.start {
		return left.start < right.start
	}
	return left.end-left.start > right.end-right.start
}

// detectAll rend les détections de chaque détecteur, dans l'ordre des détecteurs ; only (non nil) restreint aux
// détecteurs listés (essais du Pack).
func (p *Pack) detectAll(v *textView, only map[int]bool) [][]span {
	results := make([][]span, len(p.detectors))
	for index, d := range p.detectors {
		if d.pattern == nil || (only != nil && !only[index]) {
			continue
		}
		var kept []span
		for _, match := range v.patternMatches(d) {
			if v.keepPatternMatch(d, match) {
				kept = append(kept, match)
			}
		}
		v.keep(len(kept))
		results[index] = kept
	}
	for _, group := range p.groups {
		if only != nil && !wantedGroup(group, only) {
			continue
		}
		hits := findTermHits(v.textWords(), group.salt, group.maxWords, group.digests, v.meter)
		for _, index := range group.detectors {
			if only != nil && !only[index] {
				continue
			}
			d := p.detectors[index]
			var candidates []termHit
			for _, hit := range hits {
				if hit.words <= d.terms.maxWords && d.terms.digests[hit.digest] &&
					(d.context == nil || v.contextHolds(span{start: hit.start, end: hit.end}, d.context)) {
					candidates = append(candidates, hit)
				}
			}
			kept := resolveTermCandidates(candidates)
			v.keep(len(kept))
			results[index] = kept
		}
	}
	return results
}

func wantedGroup(group termGroup, only map[int]bool) bool {
	for _, index := range group.detectors {
		if only[index] {
			return true
		}
	}
	return false
}

// detect lance detectAll sur text et rattrape l'arrêt d'une analyse : budget épuisé (ErrWorkBudget) ou trop de
// détections (ErrTooManyMatches). Toute autre panique est propagée.
func (p *Pack) detect(text []byte, meter *Meter, maxMatches int, only map[int]bool) (results [][]span, err error) {
	defer func() {
		switch recovered := recover(); recovered.(type) {
		case nil:
		case budgetExceeded:
			results, err = nil, ErrWorkBudget
		case tooManyMatches:
			results, err = nil, ErrTooManyMatches
		default:
			panic(recovered)
		}
	}()
	return p.detectAll(newTextView(text, meter, maxMatches), only), nil
}

// Match est une détection d'un Pack de règles du client : index du détecteur dans Pack.Detectors et étendue
// [ByteStart, ByteEnd) en octets du contenu analysé. Jamais le contenu détecté.
type Match struct {
	Detector  int
	ByteStart int
	ByteEnd   int
}

// containsDefaultIgnorable dit si text contient un point de code ignorable par défaut.
func containsDefaultIgnorable(text []byte) bool {
	for i := 0; i < len(text); {
		r, width := utf8.DecodeRune(text[i:])
		if unicode.Is(defaultIgnorable, r) {
			return true
		}
		i += width
	}
	return false
}

// visibleText rend text sans ses caractères ignorables par défaut (trait d'union conditionnel, espace sans chasse…),
// et la position dans text de chaque octet gardé. Un octet hors séquence UTF-8 valide y est écrit U+FFFD (trois
// octets, tous rattachés à lui) : retirer un caractère ne peut pas former une séquence valide avec ses voisins.
func visibleText(text []byte) ([]byte, []int) {
	visible := make([]byte, 0, len(text))
	origin := make([]int, 0, len(text))
	for i := 0; i < len(text); {
		r, width := utf8.DecodeRune(text[i:])
		switch {
		case r == utf8.RuneError && width == 1:
			visible = append(visible, "\uFFFD"...)
			origin = append(origin, i, i, i)
		case !unicode.Is(defaultIgnorable, r):
			visible = append(visible, text[i:i+width]...)
			for k := range width {
				origin = append(origin, i+k)
			}
		}
		i += width
	}
	return visible, origin
}

// Analyze rend les détections du Pack dans content, comme collectCustomFindings de l'origine : sur le texte tel
// quel puis, s'il contient des caractères ignorables par défaut, sur son texte visible (positions ramenées au
// contenu, doublons d'un même détecteur sur une même étendue retirés). Ordre : détections du texte tel quel, puis
// du texte visible, chacune par détecteur puis dans l'ordre du texte.
//
// meter compte le travail (nil : un compteur de ScanWorkBudget unités) ; maxMatches borne les détections (< 0 :
// sans limite). Erreurs, sans aucune détection : ErrWorkBudget (budget épuisé) et ErrTooManyMatches (plus de
// maxMatches détections) ; l'appelant traite l'une et l'autre comme une analyse incomplète, jamais comme « rien
// trouvé ».
func (p *Pack) Analyze(content []byte, meter *Meter, maxMatches int) ([]Match, error) {
	if meter == nil {
		meter = NewMeter(ScanWorkBudget, nil)
	}
	type pass struct {
		results [][]span
		origin  []int
	}
	results, err := p.detect(content, meter, maxMatches, nil)
	if err != nil {
		return nil, err
	}
	passes := []pass{{results: results}}
	if containsDefaultIgnorable(content) {
		visible, origin := visibleText(content)
		if err := spendSafely(meter, ceilDiv(utf16Units(content), 16)); err != nil {
			return nil, err
		}
		results, err := p.detect(visible, meter, maxMatches, nil)
		if err != nil {
			return nil, err
		}
		passes = append(passes, pass{results: results, origin: origin})
	}
	var matches []Match
	seen := map[Match]bool{}
	for _, pass := range passes {
		for index, spans := range pass.results {
			for _, s := range spans {
				m := Match{Detector: index, ByteStart: s.start, ByteEnd: s.end}
				if pass.origin != nil {
					m.ByteStart, m.ByteEnd = pass.origin[s.start], pass.origin[s.end-1]+1
				}
				if seen[m] {
					continue
				}
				seen[m] = true
				matches = append(matches, m)
			}
		}
	}
	if maxMatches >= 0 && len(matches) > maxMatches {
		return nil, ErrTooManyMatches
	}
	return matches, nil
}

// spendSafely compte units hors d'une analyse : ErrWorkBudget au-delà du budget.
func spendSafely(meter *Meter, units int64) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if _, ok := recovered.(budgetExceeded); !ok {
				panic(recovered)
			}
			err = ErrWorkBudget
		}
	}()
	meter.spend(units)
	return nil
}
