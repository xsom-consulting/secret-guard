// Package hidden trouve les instructions cachées d'un texte : des caractères qu'une personne ne voit pas mais qu'un
// modèle de langage lit. Portage en Go de hidden.ts de Secret Guard (origine, avis et modifications dans UPSTREAM.md).
//
// Quatre porteurs, chacun une attaque documentée contre les assistants de code :
//
//   - les caractères d'étiquette Unicode (U+E0000 à U+E007F), « ASCII smuggling » : chaque étiquette double un
//     caractère ASCII, invisible à l'écran, lu comme du texte par un modèle ;
//   - les plongements, forçages et isolats bidirectionnels, « Trojan Source » (CVE-2021-42574) : ce que lit un
//     relecteur n'est pas ce que lit le modèle ;
//   - les suites de caractères invisibles de largeur nulle (et autres caractères ignorables par défaut) : des bits
//     écrits entre des lettres visibles ;
//   - les suites de sélecteurs de variante après un caractère, « emoji smuggling » : un sélecteur par octet d'un
//     message caché.
//
// Leurs usages légitimes restent silencieux : la suite d'étiquettes d'un drapeau de subdivision, le liant sans
// chasse (ZWJ) dans un emoji, les liants des écritures qui joignent leurs lettres, un sélecteur de variante après sa
// base, les sélecteurs de forme du mongol, la césure conditionnelle entre deux lettres, une marque d'ordre des octets
// en tête du texte, les marques de direction (U+200E, U+200F, U+061C). Quelques caractères invisibles isolés (moins de
// ScatteredInvisibleThreshold dans le texte) sont tenus pour du bruit.
//
// Find rend la sorte, l'étendue en octets, la ligne, la colonne et le nombre de caractères de chaque suite ; jamais ce
// que les caractères cachés écrivent (l'origine ne l'expose pas non plus). Strip retire exactement ce que Find
// signale.
//
// Octets : le texte est lu en UTF-8 ; un octet hors d'une séquence UTF-8 valide vaut U+FFFD, un par octet
// (utf8.DecodeRune), comme dans le corpus de parité. Il n'est jamais signalé, mais il compte comme un caractère
// (colonne, voisin d'un caractère examiné). Au-delà de MaxInputBytes octets, rien n'est lu : le rapport est
// incomplet, et ne vaut jamais « rien trouvé ».
//
// Le paquet est pur (règle depguard de .golangci.yml) : ni E/S, ni réseau, ni horloge, ni hasard, ni journal. Les
// deux fonctions sont en temps linéaire et sûres pour des appels concurrents.
package hidden

import (
	"unicode"
	"unicode/utf8"

	"github.com/xsom-consulting/secret-guard/internal/limits"
)

// Kind est la sorte d'un porteur d'instructions cachées (HiddenKind de l'origine).
type Kind string

const (
	// TagCharacters : caractères d'étiquette Unicode (U+E0000 à U+E007F) hors d'un drapeau de subdivision.
	TagCharacters Kind = "tag_characters"
	// BidiControls : plongements, forçages et isolats bidirectionnels (U+202A à U+202E, U+2066 à U+2069).
	BidiControls Kind = "bidi_controls"
	// InvisibleCharacters : caractères ignorables par défaut, en suite ou trop nombreux pour être du bruit.
	InvisibleCharacters Kind = "invisible_characters"
	// VariationSelectors : sélecteurs de variante en tête du texte ou après un autre sélecteur.
	VariationSelectors Kind = "variation_selectors"
)

const (
	// MaxInputBytes est la taille de texte la plus grande lue, en octets reçus (MAX_INPUT_BYTES de Secret Guard,
	// 1 Mio, la limite du moteur de détection). Au-delà, rien n'est lu : Report.Complete est faux.
	MaxInputBytes = limits.MaxInputBytes
	// MaxFindings est le nombre de suites gardées dans un rapport (MAX_HIDDEN_FINDINGS) ; Report.Hidden reste exact
	// au-delà.
	MaxFindings = 50
	// ScatteredInvisibleThreshold : en dessous de ce nombre dans tout le texte, des caractères invisibles isolés
	// (aucun voisin invisible) sont tenus pour du bruit (SCATTERED_INVISIBLE_THRESHOLD).
	ScatteredInvisibleThreshold = 4
)

// Finding est une suite de caractères cachés d'une même sorte (HiddenFinding de l'origine, plus l'étendue en
// octets). Son contenu n'est jamais rendu.
type Finding struct {
	Kind Kind
	// Line est la ligne (à partir de 1, fins de ligne « \n ») du premier caractère de la suite.
	Line int
	// Column est la colonne (à partir de 1), en points de code, du premier caractère de la suite ; un octet invalide
	// compte pour un.
	Column int
	// Count est le nombre de caractères (points de code) de la suite.
	Count int
	// ByteStart et ByteEnd bornent la suite dans le texte, en octets (fin exclue).
	ByteStart int
	ByteEnd   int
}

// Report est le résultat de Find (HiddenReport de l'origine).
type Report struct {
	// Complete est faux au-delà de MaxInputBytes : le texte n'est pas lu et ne doit pas être tenu pour propre.
	Complete bool
	// Hidden est le nombre exact de caractères signalés, même au-delà des suites gardées.
	Hidden int
	// Findings sont les suites, dans l'ordre du texte, au plus MaxFindings.
	Findings []Finding
}

const (
	blackFlag  = 0x1F3F4
	cancelTag  = 0xE007F
	zwnj       = 0x200C
	zwj        = 0x200D
	bom        = 0xFEFF
	softHyphen = 0x00AD
	// maxFlagTags : un drapeau de subdivision porte au plus 7 étiquettes avant l'étiquette d'annulation.
	maxFlagTags = 7
	// noRune marque l'absence de voisin (début ou fin du texte).
	noRune rune = -1
)

// verdict est le premier jugement d'un caractère, avant la règle des caractères invisibles isolés.
type verdict uint8

const (
	verdictNone verdict = iota
	verdictTag
	verdictBidi
	verdictVariation
	verdictSuspect
	verdictInvisible
)

var kinds = [...]Kind{
	verdictTag:       TagCharacters,
	verdictBidi:      BidiControls,
	verdictVariation: VariationSelectors,
	verdictInvisible: InvisibleCharacters,
}

func isTag(cp rune) bool { return cp >= 0xE0000 && cp <= 0xE007F }

func isBidiControl(cp rune) bool {
	return (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069)
}

func isVariationSelector(cp rune) bool {
	return (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF)
}

// isDirectionalMark : les marques de direction ne portent rien et le texte de droite à gauche en a besoin.
func isDirectionalMark(cp rune) bool { return cp == 0x200E || cp == 0x200F || cp == 0x061C }

func in(table *unicode.RangeTable, cp rune) bool { return cp >= 0 && unicode.Is(table, cp) }

func isEmojiContext(cp rune) bool { return in(emoji, cp) || cp == 0xFE0F || cp == 0x20E3 }

// benignInvisible : un liant ou une césure employés comme leur écriture les emploie (benignInvisible de l'origine).
func benignInvisible(cp rune, index int, before, after rune) bool {
	switch {
	case cp == bom:
		return index == 0
	case cp == zwj && isEmojiContext(before) && isEmojiContext(after):
		return true
	case (cp == zwj || cp == zwnj) && in(joiningScript, before) && (in(joiningScript, after) || in(letterOrMark, after)):
		return true
	case cp >= 0x180B && cp <= 0x180F && cp != 0x180E && in(mongolian, before):
		// Les sélecteurs de variante libres du mongol choisissent une forme de lettre.
		return true
	}
	return cp == softHyphen && in(letterOrMark, before) && in(letterOrMark, after)
}

// judge rend le premier jugement du caractère cp, d'indice index (en points de code), entre before et after
// (noRune aux bords) ; flagTag dit si une étiquette appartient à un drapeau de subdivision.
func judge(cp rune, index int, before, after rune, flagTag bool) verdict {
	switch {
	case isTag(cp):
		if flagTag {
			return verdictNone
		}
		return verdictTag
	case isBidiControl(cp):
		return verdictBidi
	case isVariationSelector(cp):
		// Le premier sélecteur après une base visible choisit un glyphe (emoji, idéogramme) ; chaque suivant est un
		// octet d'autre chose.
		if before == noRune || isVariationSelector(before) {
			return verdictVariation
		}
		return verdictNone
	case isDirectionalMark(cp), !in(defaultIgnorable, cp), benignInvisible(cp, index, before, after):
		return verdictNone
	}
	return verdictSuspect
}

// decodeAt lit le point de code à l'octet off : un octet invalide vaut U+FFFD, sur un octet.
func decodeAt(text []byte, off int) (rune, int) {
	if off >= len(text) {
		return noRune, 0
	}
	if c := text[off]; c < utf8.RuneSelf {
		return rune(c), 1
	}
	return utf8.DecodeRune(text[off:])
}

// flagTags rend le nombre d'étiquettes d'un drapeau de subdivision qui suit le drapeau noir finissant à l'octet off
// (étiquettes de U+E0020 à U+E007E, 7 au plus, puis l'étiquette d'annulation, comptée), ou 0 (flagTags de l'origine).
func flagTags(text []byte, off int) int {
	count := 0
	for {
		cp, width := decodeAt(text, off)
		if count < maxFlagTags && cp >= 0xE0020 && cp <= 0xE007E {
			count++
			off += width
			continue
		}
		if count > 0 && cp == cancelTag {
			return count + 1
		}
		return 0
	}
}

// isASCII : un texte ASCII ne peut porter aucun des quatre porteurs.
func isASCII(text []byte) bool {
	for _, c := range text {
		if c >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// classify juge chaque caractère du texte (une entrée par point de code), puis applique la règle des caractères
// invisibles isolés (resolveInvisible de l'origine). Rend nil si aucun caractère n'est signalé.
func classify(text []byte) []verdict {
	if isASCII(text) {
		return nil
	}
	verdicts := make([]verdict, 0, len(text))
	suspects, flagged := 0, false
	before, flagUntil := noRune, -1
	cp, width := decodeAt(text, 0)
	for off, index := 0, 0; off < len(text); index++ {
		next := off + width
		after, afterWidth := decodeAt(text, next)
		if cp == blackFlag {
			if tags := flagTags(text, next); tags > 0 {
				flagUntil = index + tags
			}
		}
		v := judge(cp, index, before, after, index <= flagUntil)
		switch v {
		case verdictSuspect:
			suspects++
		case verdictNone:
		default:
			flagged = true
		}
		verdicts = append(verdicts, v)
		before, cp, width, off = cp, after, afterWidth, next
	}
	if suspects == 0 {
		if !flagged {
			return nil
		}
		return verdicts
	}
	for i, v := range verdicts {
		if v != verdictSuspect {
			continue
		}
		// Le voisin de gauche est déjà jugé : un suspect qui précède un suspect est toujours dans une suite.
		inRun := (i > 0 && verdicts[i-1] == verdictInvisible) || (i+1 < len(verdicts) && verdicts[i+1] == verdictSuspect)
		if inRun || suspects >= ScatteredInvisibleThreshold {
			verdicts[i] = verdictInvisible
			flagged = true
		} else {
			verdicts[i] = verdictNone
		}
	}
	if !flagged {
		return nil
	}
	return verdicts
}

// Find rend les suites de caractères cachés du texte (findHidden de l'origine). Au-delà de MaxInputBytes octets,
// rien n'est lu : Complete est faux, Hidden vaut 0 et Findings est vide.
func Find(text []byte) Report {
	if len(text) > MaxInputBytes {
		return Report{}
	}
	verdicts := classify(text)
	report := Report{Complete: true}
	if verdicts == nil {
		return report
	}
	line, column := 1, 1
	run := Finding{}
	open := false
	off := 0
	for _, v := range verdicts {
		cp, width := decodeAt(text, off)
		kind := Kind("")
		if v != verdictNone {
			kind = kinds[v]
		}
		if open && kind != run.Kind {
			report.keep(run)
			open = false
		}
		if kind != "" {
			report.Hidden++
			if !open {
				run = Finding{Kind: kind, Line: line, Column: column, ByteStart: off}
				open = true
			}
			run.Count++
			run.ByteEnd = off + width
		}
		if cp == '\n' {
			line++
			column = 1
		} else {
			column++
		}
		off += width
	}
	if open {
		report.keep(run)
	}
	return report
}

// keep ajoute une suite au rapport s'il en garde moins de MaxFindings.
func (r *Report) keep(run Finding) {
	if len(r.Findings) < MaxFindings {
		r.Findings = append(r.Findings, run)
	}
}

// replacement est U+FFFD en UTF-8.
const replacement = "\uFFFD"

// Strip rend une copie du texte sans les caractères que Find signale (stripHidden de l'origine) ; les usages
// légitimes restent.
//
// Le résultat est toujours de l'UTF-8 valide : chaque octet invalide y devient U+FFFD, comme Find le lit. Garder un
// octet invalide pourrait, une fois retiré un caractère voisin, former avec d'autres octets un caractère qui n'était
// pas dans le texte (par exemple U+202E). Au-delà de MaxInputBytes octets, rien n'est lu et la copie est rendue
// inchangée : vérifier Find(text).Complete avant d'employer le résultat comme un texte nettoyé. Comme à l'origine,
// une seule passe : des caractères que le retrait rapproche peuvent être signalés par un nouvel appel de Find.
func Strip(text []byte) []byte {
	if len(text) > MaxInputBytes || isASCII(text) {
		return append([]byte{}, text...)
	}
	verdicts := classify(text)
	out := make([]byte, 0, len(text))
	for off, index := 0, 0; off < len(text); index++ {
		cp, width := decodeAt(text, off)
		switch {
		case verdicts != nil && verdicts[index] != verdictNone:
		case cp == utf8.RuneError && width == 1:
			out = append(out, replacement...)
		default:
			out = append(out, text[off:off+width]...)
		}
		off += width
	}
	return out
}
