// Recherche d'un motif traduit en RE2 et coût compté de cette recherche.
//
// L'origine essaie son automate à retour arrière à chaque début possible et compte chaque pas. Ici, les débuts
// possibles (intervalles de l'ancre, ou tout le texte) sont réduits aux octets qui peuvent commencer une
// correspondance (first) ; chaque début possible ouvre une fenêtre [début, début + longueur maximale), les fenêtres
// qui se chevauchent sont fusionnées, et RE2 cherche les correspondances successives de chaque fenêtre. Une
// correspondance qui commence au plus tard au dernier début de sa fenêtre tient entière dans la fenêtre (motif
// ASCII : un octet par caractère, longueur maximale bornée) : elle est celle que trouverait une recherche sur tout le
// texte. Une correspondance qui commencerait après ce dernier début n'est pas gardée (aucune ne commence hors des
// débuts possibles).
//
// Coût compté (budget du §5) : une unité par position examinée (l'origine en compte une par début essayé), puis,
// pour chaque fenêtre, sa longueur en octets fois le nombre d'états du motif traduit, borne du travail de RE2 (au
// plus un fil par état et par octet), comptée avant la recherche.

package custom

// window : fenêtre de recherche [start, end) et dernier début possible qu'elle contient.
type window struct {
	start, end, last int
}

// search rend les correspondances de p sur tout le texte, cherchées dans les débuts possibles des intervalles.
func (v *textView) search(p *safePattern, intervals []interval) []span {
	var windows []window
	examined := 0
	for _, in := range intervals {
		for s := in.start; s <= in.end && s < len(v.text); s++ {
			examined++
			if !p.first[v.text[s]] {
				continue
			}
			end := min(len(v.text), s+p.maxLength)
			if last := len(windows) - 1; last >= 0 && s < windows[last].end {
				windows[last].end, windows[last].last = end, s
				continue
			}
			windows = append(windows, window{start: s, end: end, last: s})
		}
	}
	v.meter.spend(int64(examined))
	var matches []span
	for _, w := range windows {
		v.meter.spend(int64(w.end-w.start) * int64(p.states))
		for _, loc := range p.re.FindAllIndex(v.text[w.start:w.end], -1) {
			start := w.start + loc[0]
			if start > w.last {
				break
			}
			matches = append(matches, span{start: start, end: w.start + loc[1]})
		}
	}
	return matches
}
