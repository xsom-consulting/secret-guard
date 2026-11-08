// SPDX-License-Identifier: Apache-2.0

// Affectations indirectes (écart d'analyse ajouté en v0.5.2, absent de Secret Guard) : le nom sensible et sa valeur
// ne sont pas reliés par « = » ou « : » derrière une espace, mais par une paire d'arguments ou une ligne de diff.
//
//   - paire entre guillemets : os.Setenv("…", "…"), props.setProperty("…", "…"), std::env::set_var("…", "…"),
//     os.environ.setdefault("…", "…"), INSERT … VALUES ('…', '…'), tuple ou tableau (« ("…", "…") ») ;
//   - nom entre accents graves, Markdown : « - `NOM` : `valeur` », « | `NOM` | `valeur` | » ;
//   - ligne de diff : « +NOM=valeur », « -NOM=valeur », « +export NOM=valeur » ;
//   - déclaration typée : « const NOM: &str = "…" » (Rust), « let nom: String = "…" » (Swift, Kotlin), « nom: str =
//     "…" » (Python), « const nom: string = '…' » (TypeScript), « var nom string = "…" » (Go).
//
// Relevé sur le banc de lecture d'images du 2026-11-08 : ces sept gabarits ratés à chaque fois pour un mot de passe
// fort ou une valeur hexadécimale de 40 caractères (les autres formes passaient par l'entropie). Les deux premières
// formes, plus ouvertes que « NOM = valeur » (libellés, valeurs par défaut, documentation de types), exigent une valeur
// entre guillemets qui a la forme d'un secret (indirectValueShape) ; la ligne de diff suit les règles de l'affectation
// ordinaire.

package detect

import (
	"bytes"
	"regexp"
	"sort"
)

// jsSpaceClass est \s de JavaScript, écrit comme dans engine_patterns.go.
const jsSpaceClass = `[\t\n\x0B\f\r \x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}]`

const indirectKey = `([A-Za-z_][A-Za-z0-9_.-]{0,80})`

// reQuotedPairAssignment : nom entre guillemets, premier élément d'une liste d'arguments, d'un tuple, d'un tableau ou
// d'un objet (juste après « ( », « [ » ou « { », espaces admises), suivi d'une virgule. Un nom qui n'est pas le
// premier élément (« Errorf("…", "Token", `…`) ») n'est pas lu.
const reQuotedPairAssignment = `[(\[{]` + jsSpaceClass + `*["']` + indirectKey + `["']` + jsSpaceClass + `*,` + jsSpaceClass + `*`

// reBacktickKeyAssignment : nom entre accents graves suivi de « : », « = », « := », « -> », « => », « | », d'un
// tiret long ou demi-long.
const reBacktickKeyAssignment = `(?m)(?:^|[\t\n\x0B\f\r \x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}(|*])` +
	"`" + indirectKey + "`" + jsSpaceClass + `*(?::=|->|=>|[:=|]|\x{2014}|\x{2013})` + jsSpaceClass + `*`

// reDiffLineAssignment : affectation qui suit le signe « + » ou « - » d'une ligne de diff unifié.
const reDiffLineAssignment = `(?m)(?:^|[\r\x{2028}\x{2029}])[+-](?:(?:[eE][xX][pP][oO][rR][tT]|[sS][eE][tT])` + jsSpaceClass + `+)?` +
	`["']?` + indirectKey + `["']?[\t\x0B\f \x{00A0}\x{1680}\x{2000}-\x{200A}\x{202F}\x{205F}\x{3000}\x{FEFF}]*(?::=|[:=])` +
	`[\t\x0B\f \x{00A0}\x{1680}\x{2000}-\x{200A}\x{202F}\x{205F}\x{3000}\x{FEFF}]*`

// typeAnnotation est le type d'une déclaration : « &str », « &'static str », « String », « Option<String> »,
// « []byte », « *string », « str | None » n'est pas lu (une espace avant « | »).
const typeAnnotation = `[&*]?(?:'[A-Za-z_]{1,20}` + jsSpaceClass + `+)?[A-Za-z_\[][A-Za-z0-9_<>\[\]?.:,]{0,60}`

// reTypedDeclaration : nom, « : », type, « = » (Rust, Swift, Kotlin, Python, TypeScript).
const reTypedDeclaration = `(?m)(?:^|[\t\n\x0B\f\r \x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF},{;(])` +
	indirectKey + jsSpaceClass + `*:` + jsSpaceClass + `*` + typeAnnotation + jsSpaceClass + `*=` + jsSpaceClass + `*`

// reGoTypedDeclaration : « var » ou « const », nom, type, « = » (Go).
const reGoTypedDeclaration = `(?m)(?:^|[\t\n\x0B\f\r \x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}(;])` +
	`(?:var|const)` + jsSpaceClass + `+` + indirectKey + jsSpaceClass + `+[*\[\]]*[A-Za-z_][A-Za-z0-9_.]{0,60}` + jsSpaceClass + `*=` + jsSpaceClass + `*`

func isBacktickBoundary(r rune) bool { return isJSWhitespace(r) || r == '(' || r == '|' || r == '*' }

var indirectAssignmentPatterns = []assignmentPattern{
	{re: regexp.MustCompile(reQuotedPairAssignment), valueShape: true, windowed: true},
	{re: regexp.MustCompile(reBacktickKeyAssignment), start: lineStartOr(isBacktickBoundary), valueShape: true, windowed: true},
	{re: regexp.MustCompile(reDiffLineAssignment), start: lineStartOr(isLineBreak), plain: true, windowed: true},
	{re: regexp.MustCompile(reTypedDeclaration), start: lineStartOr(isTypedBoundary), valueShape: true, windowed: true},
	{re: regexp.MustCompile(reGoTypedDeclaration), start: lineStartOr(isGoBoundary), valueShape: true, windowed: true},
}

func isTypedBoundary(r rune) bool {
	return isJSWhitespace(r) || r == ',' || r == '{' || r == ';' || r == '('
}

func isGoBoundary(r rune) bool { return isJSWhitespace(r) || r == '(' || r == ';' }

func init() { assignmentPatterns = append(assignmentPatterns, indirectAssignmentPatterns...) }

// indirectValueShape dit si la valeur d'une affectation indirecte a la forme d'un secret : entre guillemets ou accents
// graves, sans espace, d'au moins 8 unités UTF-16, qui n'est pas une expression régulière ancrée, et de forte entropie (hasStrongEntropy) ou mêlant au moins trois
// classes de caractères parmi minuscules, majuscules, chiffres et autres. « Mot de passe », « required », « string »,
// « default-value » n'ont pas cette forme.
func indirectValueShape(v *view, p *parsedValue) bool {
	if p.kind != kindQuoted {
		return false
	}
	value := v.text[p.start:p.valueEnd]
	if utf16Units(value) < 8 || value[0] == '^' && value[len(value)-1] == '$' {
		// Trop court, ou expression régulière ancrée (« ^[A-Za-z0-9_-]{43}$ »).
		return false
	}
	var lower, upper, digit, other bool
	for _, r := range string(value) {
		switch {
		case isJSWhitespace(r):
			return false
		case 'a' <= r && r <= 'z':
			lower = true
		case 'A' <= r && r <= 'Z':
			upper = true
		case '0' <= r && r <= '9':
			digit = true
		default:
			other = true
		}
	}
	classes := 0
	for _, present := range []bool{lower, upper, digit, other} {
		if present {
			classes++
		}
	}
	return classes >= 3 || hasStrongEntropy(v, p.start, p.valueEnd)
}

// sensitiveKeyFragments : morceaux dont au moins un figure, sans tenir compte de la casse, dans tout nom que reconnaît
// typeForSensitiveKey (« password », « passwd », « passphrase », « dbpass » ; « pwd » ; « privatekey », « apikey »,
// « signingkey », « encryptionkey », « azurestoragekey » ; « token » ; « authorization » ; « secret » ;
// « databaseurl » ; « connectionstring »), le nom étant lu avec ses séparateurs (« API_KEY », « db.password »).
var sensitiveKeyFragments = []string{"pass", "pwd", "key", "token", "auth", "secret", "url", "connection"}

// indirectWindows rend les fenêtres de text où chercher une affectation indirecte : chaque ligne qui contient un morceau
// de nom sensible, avec la ligne qui la précède et celle qui la suit, fenêtres jointes quand elles se touchent. Un nom
// sensible ne s'écrit pas sans l'un de ces morceaux : chercher ailleurs ne trouverait rien, et le coût de ces motifs
// reste borné aux lignes qui en ont un (un texte sans aucun ne coûte qu'une lecture).
func indirectWindows(text []byte) [][2]int {
	var hits []int
	for _, fragment := range sensitiveKeyFragments {
		for from := 0; from < len(text); {
			i := indexFold(text[from:], fragment)
			if i < 0 {
				break
			}
			hits = append(hits, from+i)
			from += i + len(fragment)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	sort.Ints(hits)
	// Débuts de ligne, relevés une fois : chaque fenêtre se lit par recherche dichotomique (linéaire même sur une
	// seule ligne très longue).
	starts := []int{0}
	for from := 0; ; {
		i := bytes.IndexByte(text[from:], '\n')
		if i < 0 {
			break
		}
		from += i + 1
		starts = append(starts, from)
	}
	line := func(at int) int { return sort.SearchInts(starts, at+1) - 1 }
	var windows [][2]int
	for _, at := range hits {
		l := line(at)
		start := starts[max(0, l-1)]
		end := len(text)
		if l+2 < len(starts) {
			end = starts[l+2]
		}
		if n := len(windows); n > 0 && start <= windows[n-1][1] {
			windows[n-1][1] = max(windows[n-1][1], end)
			continue
		}
		windows = append(windows, [2]int{start, end})
	}
	return windows
}

// indexFold est bytes.Index sans tenir compte de la casse ASCII (fragment en minuscules), sans copie du texte.
func indexFold(text []byte, fragment string) int {
	first, upper := fragment[0], fragment[0]-'a'+'A'
	for i := 0; i+len(fragment) <= len(text); i++ {
		if c := text[i]; c != first && c != upper {
			continue
		}
		matched := true
		for k := 1; k < len(fragment); k++ {
			if c := text[i+k] | 0x20; c != fragment[k] {
				matched = false
				break
			}
		}
		if matched {
			return i
		}
	}
	return -1
}

// findIndirect rend la prochaine correspondance du motif p à partir de lastIndex, cherchée dans les seules fenêtres de
// indirectWindows (execFrom sur le texte coupé à la fin de la fenêtre : l'assertion de début se lit sur le vrai texte).
func (ctx *contextualText) findIndirect(p *assignmentPattern, lastIndex int) []int {
	if !ctx.indirectReady {
		ctx.indirect, ctx.indirectReady = indirectWindows(ctx.text), true
	}
	for _, w := range ctx.indirect {
		if w[1] <= lastIndex {
			continue
		}
		if m := execFrom(p.re, ctx.text[:w[1]], max(w[0], lastIndex), p.start); m != nil {
			return m
		}
	}
	return nil
}
