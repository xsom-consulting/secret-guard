// SPDX-License-Identifier: Apache-2.0

// Index des portes littérales des règles « motif seul » d'un Pack (v0.8.1).
//
// Avec des centaines de règles, chercher les littéraux de chaque porte l'un après l'autre coûte une lecture du texte
// par littéral. L'index réunit les littéraux de toutes les portes dans un automate d'Aho-Corasick : une seule lecture
// du texte rend l'ensemble des règles dont un littéral y figure. La recherche ne tient pas compte de la casse ASCII :
// elle admet donc au moins les règles que leur porte admet (literalGate.admits, que scanFixedPattern rejoue pour les
// règles admises), jamais moins. Une règle sans porte est toujours admise ; une règle à porte repliée l'est aussi dès
// que le texte porte U+212A ou U+017F (hasFoldEscape). L'index ne change donc jamais un résultat : il évite seulement
// de préparer et d'exécuter les règles qui ne peuvent rien trouver.

package detect

// literalIndex est l'automate des littéraux des portes d'une liste de règles. Immuable après newLiteralIndex.
type literalIndex struct {
	// class : classe d'un octet (majuscule et minuscule ASCII dans la même classe ; 0 : octet absent des littéraux).
	class [256]uint8
	// width : nombre de classes ; next[état*width+classe] : état suivant (automate complet, 0 : racine).
	width int
	next  []int32
	// rules[état] : règles dont un littéral finit dans cet état (suffixes compris).
	rules [][]int32
	// always : règles sans porte ; folded : règles à porte repliée.
	always, folded []int32
	// count : nombre de règles indexées.
	count int
}

// admittedRules est l'ensemble des règles admises pour un texte, par indice dans la liste indexée.
type admittedRules []uint64

func (a admittedRules) set(i int32)    { a[i>>6] |= 1 << (uint(i) & 63) }
func (a admittedRules) has(i int) bool { return a[i>>6]&(1<<(uint(i)&63)) != 0 }

// newLiteralIndex construit l'index des portes de rules (dans l'ordre de la liste).
func newLiteralIndex(rules []*rule) *literalIndex {
	x := &literalIndex{count: len(rules), width: 1}
	type literal struct {
		bytes []byte
		rule  int32
	}
	var literals []literal
	for i, r := range rules {
		switch {
		case r.gate == nil:
			x.always = append(x.always, int32(i))
			continue
		case r.gate.fold:
			x.folded = append(x.folded, int32(i))
		}
		for _, l := range r.gate.literals {
			folded := make([]byte, len(l))
			for k, c := range l {
				folded[k] = lowerASCII(c)
			}
			literals = append(literals, literal{folded, int32(i)})
		}
	}
	for _, l := range literals {
		for _, c := range l.bytes {
			if x.class[c] == 0 {
				x.class[c] = uint8(x.width)
				x.width++
			}
		}
	}
	for c := byte('A'); c <= 'Z'; c++ {
		x.class[c] = x.class[c+'a'-'A']
	}
	// Arbre des littéraux (transitions absentes : -1), puis liens d'échec en largeur et automate complet.
	newState := func() int32 {
		for i := 0; i < x.width; i++ {
			x.next = append(x.next, -1)
		}
		x.rules = append(x.rules, nil)
		return int32(len(x.rules) - 1)
	}
	newState()
	for _, l := range literals {
		state := int32(0)
		for _, c := range l.bytes {
			at := int(state)*x.width + int(x.class[c])
			if x.next[at] < 0 {
				// newState peut déplacer x.next : l'indice est recalculé après l'ajout.
				created := newState()
				x.next[at] = created
			}
			state = x.next[at]
		}
		x.rules[state] = appendRule(x.rules[state], l.rule)
	}
	fail := make([]int32, len(x.rules))
	queue := make([]int32, 0, len(x.rules))
	for c := 0; c < x.width; c++ {
		if target := x.next[c]; target > 0 {
			queue = append(queue, target)
		} else {
			x.next[c] = 0
		}
	}
	for head := 0; head < len(queue); head++ {
		state := queue[head]
		for _, r := range x.rules[fail[state]] {
			x.rules[state] = appendRule(x.rules[state], r)
		}
		for c := 0; c < x.width; c++ {
			at := int(state)*x.width + c
			fallback := x.next[int(fail[state])*x.width+c]
			if target := x.next[at]; target > 0 {
				fail[target] = fallback
				queue = append(queue, target)
			} else {
				x.next[at] = fallback
			}
		}
	}
	return x
}

// appendRule ajoute une règle à une liste sans doublon.
func appendRule(list []int32, rule int32) []int32 {
	for _, known := range list {
		if known == rule {
			return list
		}
	}
	return append(list, rule)
}

// admitted rend les règles à exécuter sur text : règles sans porte, règles dont un littéral figure dans text sans
// tenir compte de la casse ASCII, et règles à porte repliée si text porte U+212A ou U+017F.
func (x *literalIndex) admitted(text []byte) admittedRules {
	out := make(admittedRules, (x.count+63)>>6)
	for _, r := range x.always {
		out.set(r)
	}
	if len(x.folded) > 0 && hasFoldEscape(text) {
		for _, r := range x.folded {
			out.set(r)
		}
	}
	state := int32(0)
	width := int32(x.width)
	for _, c := range text {
		state = x.next[state*width+int32(x.class[c])]
		if hits := x.rules[state]; hits != nil {
			for _, r := range hits {
				out.set(r)
			}
		}
	}
	return out
}
