// Porte littérale exacte des règles à motif.
//
// À la compilation d'une règle (LoadRules), l'arbre regexp/syntax de son motif donne, quand on sait le prouver, un
// ensemble de littéraux dont l'un au moins figure dans toute correspondance du motif. Une vue dont le texte ne
// contient aucun de ces littéraux n'a aucune correspondance : la règle n'y est pas exécutée, son résultat serait vide
// par construction. Sinon, le motif s'exécute sur tout le texte de la vue, comme sans porte : la porte ne change
// jamais un résultat, elle évite seulement une exécution inutile. Une règle dont les littéraux ne sont pas prouvés
// n'a pas de porte et s'exécute toujours.

package detect

import (
	"bytes"
	"regexp/syntax"
	"strings"
	"unicode/utf8"
)

const (
	// gateMaxVariants borne le nombre de littéraux d'un ensemble (développement d'une classe de caractères, produit
	// d'une concaténation, union d'une alternance) : au-delà, l'ensemble n'est pas gardé.
	gateMaxVariants = 16
	// gateMinLiteralBytes : longueur, en octets, du plus court littéral d'une porte. Un littéral plus court se
	// trouverait dans presque tout texte : aucune porte.
	gateMinLiteralBytes = 3
)

// literalGate est la porte d'une règle : l'un de ces littéraux figure dans toute correspondance de son motif. nil :
// aucune porte, la règle s'exécute toujours.
type literalGate struct {
	literals [][]byte
}

// admits dit si la règle doit s'exécuter sur text : vrai sans porte, ou si l'un des littéraux y figure.
func (g *literalGate) admits(text []byte) bool {
	if g == nil {
		return true
	}
	for _, literal := range g.literals {
		if bytes.Contains(text, literal) {
			return true
		}
	}
	return false
}

// literalInfo décrit les correspondances d'un nœud de l'arbre :
//   - exact : vrai si exactSet est l'ensemble de toutes les correspondances possibles du nœud (fini, au plus
//     gateMaxVariants chaînes, la chaîne vide comprise) ;
//   - required : ensemble de littéraux dont l'un figure dans toute correspondance du nœud ; nil si aucun n'est prouvé.
type literalInfo struct {
	exact    bool
	exactSet []string
	required []string
}

// unknownLiterals : rien n'est prouvé sur les correspondances du nœud.
var unknownLiterals = literalInfo{}

// gateFor calcule la porte d'un motif analysé par syntax.Parse (mêmes drapeaux que regexp.Compile). Tout nœud qui
// replie la casse (drapeau FoldCase, « (?i) » ou classe [xX] que l'analyseur a réécrite en littéral replié) retire
// toute porte : le repliement Unicode de RE2 (K et U+212A, s et U+017F…) n'est pas développé.
func gateFor(re *syntax.Regexp) *literalGate {
	if foldsCase(re) {
		return nil
	}
	info := literalsOf(re)
	set := info.required
	if info.exact {
		set = info.exactSet
	}
	if !usableGate(set) {
		return nil
	}
	gate := &literalGate{}
	for _, literal := range set {
		if !containsAnother(set, literal) {
			gate.literals = append(gate.literals, []byte(literal))
		}
	}
	return gate
}

// containsAnother dit si literal contient un autre littéral de l'ensemble (sans doublon) : il est alors superflu, un
// texte qui le contient contient aussi l'autre.
func containsAnother(set []string, literal string) bool {
	for _, other := range set {
		if other != literal && strings.Contains(literal, other) {
			return true
		}
	}
	return false
}

// foldsCase dit si un nœud de l'arbre porte le drapeau FoldCase.
func foldsCase(re *syntax.Regexp) bool {
	if re.Flags&syntax.FoldCase != 0 {
		return true
	}
	for _, sub := range re.Sub {
		if foldsCase(sub) {
			return true
		}
	}
	return false
}

// usableGate : ensemble non vide, d'au plus gateMaxVariants littéraux d'au moins gateMinLiteralBytes octets chacun.
func usableGate(set []string) bool {
	if len(set) == 0 || len(set) > gateMaxVariants {
		return false
	}
	for _, literal := range set {
		if len(literal) < gateMinLiteralBytes {
			return false
		}
	}
	return true
}

// shortest rend la longueur du plus court littéral d'un ensemble utilisable, -1 sinon.
func shortest(set []string) int {
	if !usableGate(set) {
		return -1
	}
	least := -1
	for _, literal := range set {
		if least < 0 || len(literal) < least {
			least = len(literal)
		}
	}
	return least
}

// better rend celui des deux ensembles requis dont le plus court littéral est le plus long (à égalité, le moins
// nombreux, puis le premier) ; nil si aucun n'est utilisable.
func better(a, b []string) []string {
	la, lb := shortest(a), shortest(b)
	switch {
	case la < 0 && lb < 0:
		return nil
	case lb > la || (lb == la && len(b) < len(a)):
		return b
	}
	return a
}

// literalsOf analyse un nœud de l'arbre.
func literalsOf(re *syntax.Regexp) literalInfo {
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if !exactRune(r) {
				return unknownLiterals
			}
		}
		return exactLiterals([]string{string(re.Rune)})
	case syntax.OpCharClass:
		return classLiterals(re.Rune)
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		// Assertions : aucun caractère consommé.
		return exactLiterals([]string{""})
	case syntax.OpCapture:
		return literalsOf(re.Sub[0])
	case syntax.OpConcat:
		return concatLiterals(re.Sub)
	case syntax.OpAlternate:
		return alternateLiterals(re.Sub)
	case syntax.OpQuest:
		// Correspondance vide ou une du sous-nœud : exacte si le sous-nœud l'est, rien de requis sinon.
		sub := literalsOf(re.Sub[0])
		if sub.exact {
			if set, ok := union(sub.exactSet, []string{""}); ok {
				return exactLiterals(set)
			}
		}
		return unknownLiterals
	case syntax.OpPlus:
		return requiredOnly(literalsOf(re.Sub[0]))
	case syntax.OpRepeat:
		if re.Min == 1 && re.Max == 1 {
			return literalsOf(re.Sub[0])
		}
		if re.Min >= 1 {
			// Toute correspondance contient au moins une correspondance du sous-nœud.
			return requiredOnly(literalsOf(re.Sub[0]))
		}
	}
	// Étoile, répétition qui admet zéro, point, aucune correspondance : rien n'est prouvé.
	return unknownLiterals
}

// exactRune : un point de code que RE2 ne reconnaît que par son encodage UTF-8 exact. U+FFFD est exclu : RE2 lit
// chaque octet hors UTF-8 valide comme U+FFFD, que bytes.Contains ne trouverait pas.
func exactRune(r rune) bool {
	return r != utf8.RuneError && utf8.ValidRune(r)
}

func exactLiterals(set []string) literalInfo {
	return literalInfo{exact: true, exactSet: set, required: set}
}

// requiredOnly garde ce qui est requis d'un nœud, sans l'ensemble exact (répétition).
func requiredOnly(info literalInfo) literalInfo {
	if info.exact {
		return literalInfo{required: info.exactSet}
	}
	return literalInfo{required: info.required}
}

// classLiterals développe une classe de caractères (paires [lo, hi]) en au plus gateMaxVariants caractères.
func classLiterals(ranges []rune) literalInfo {
	var set []string
	for i := 0; i+1 < len(ranges); i += 2 {
		if ranges[i+1]-ranges[i]+1 > gateMaxVariants {
			return unknownLiterals
		}
		for r := ranges[i]; r <= ranges[i+1]; r++ {
			if !exactRune(r) {
				return unknownLiterals
			}
			set = append(set, string(r))
			if len(set) > gateMaxVariants {
				return unknownLiterals
			}
		}
	}
	if len(set) == 0 {
		return unknownLiterals
	}
	return exactLiterals(set)
}

// concatLiterals : produit des facteurs exacts consécutifs tant qu'il reste dans gateMaxVariants chaînes ; chaque
// produit et l'ensemble requis de chaque facteur non exact sont des candidats (la correspondance d'un facteur, ou de
// facteurs consécutifs, est une sous-chaîne de la correspondance entière) ; le meilleur est gardé.
func concatLiterals(subs []*syntax.Regexp) literalInfo {
	product := []string{""}
	allExact := true
	var best []string
	for _, sub := range subs {
		info := literalsOf(sub)
		if !info.exact {
			allExact = false
			best = better(best, product)
			best = better(best, info.required)
			product = []string{""}
			continue
		}
		next, ok := cross(product, info.exactSet)
		if !ok {
			// Produit trop grand : il s'arrête ici, un nouveau commence par ce facteur.
			allExact = false
			best = better(best, product)
			product = info.exactSet
			continue
		}
		product = next
	}
	if allExact {
		return exactLiterals(product)
	}
	return literalInfo{required: better(best, product)}
}

// alternateLiterals : union des ensembles exacts si chaque branche est exacte, sinon union des ensembles requis ;
// une branche sans littéral prouvé retire tout (aucune porte).
func alternateLiterals(subs []*syntax.Regexp) literalInfo {
	infos := make([]literalInfo, len(subs))
	allExact := true
	for i, sub := range subs {
		infos[i] = literalsOf(sub)
		allExact = allExact && infos[i].exact
	}
	if allExact {
		var set []string
		for _, info := range infos {
			var ok bool
			if set, ok = union(set, info.exactSet); !ok {
				allExact = false
				break
			}
		}
		if allExact {
			return exactLiterals(set)
		}
	}
	var required []string
	for _, info := range infos {
		branch := info.required
		if info.exact {
			branch = info.exactSet
		}
		if shortest(branch) < 0 {
			return unknownLiterals
		}
		var ok bool
		if required, ok = union(required, branch); !ok {
			return unknownLiterals
		}
	}
	return literalInfo{required: required}
}

// cross rend le produit de deux ensembles (concaténation de chaque paire), faux au-delà de gateMaxVariants chaînes.
func cross(left, right []string) ([]string, bool) {
	if len(left)*len(right) > gateMaxVariants {
		return nil, false
	}
	out := make([]string, 0, len(left)*len(right))
	seen := map[string]bool{}
	for _, l := range left {
		for _, r := range right {
			if s := l + r; !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out, true
}

// union rend la réunion de deux ensembles, sans doublon, dans l'ordre de première apparition ; faux au-delà de
// gateMaxVariants chaînes.
func union(left, right []string) ([]string, bool) {
	out := make([]string, 0, len(left)+len(right))
	seen := map[string]bool{}
	for _, list := range [][]string{left, right} {
		for _, s := range list {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out, len(out) <= gateMaxVariants
}
