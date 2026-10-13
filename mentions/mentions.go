// Package mentions relève les fichiers cités par « @ » dans un prompt d'assistant de code : « @chemin »,
// « @"chemin avec espaces" » et « @chemin#L10-20 ». Portage en Go de mentionedPaths de Secret Guard (file-guard.ts ;
// origine, avis et modifications dans UPSTREAM.md), sans lecture de fichier ni résolution de chemin : l'appelant
// résout chaque chemin (répertoire de travail de l'assistant) et lit le fichier lui-même, sous l'identité de la
// personne, puis l'analyse (par exemple avec detect et hidden).
//
// Un assistant peut ajouter à son contexte le contenu d'un fichier cité par « @ » sans appel d'outil, donc sans hook
// avant outil : un hook à la soumission du prompt retrouve ces fichiers par Parse pour les analyser avant l'envoi.
//
// Règles de l'origine, reprises telles quelles :
//
//   - une mention commence le prompt ou suit un caractère d'espacement (\s de JavaScript) : une adresse électronique
//     (nom@domaine) n'est pas une mention ;
//   - le chemin est soit entre guillemets droits (au moins un caractère, retours à la ligne compris), soit la suite de
//     caractères qui ne sont pas des espacements ; « @"" » ou un guillemet non refermé se lisent sans guillemets
//     particuliers (le chemin garde alors son guillemet) ;
//   - un suffixe final « #L<chiffres> » ou « #L<chiffres>-<chiffres> » est retiré du chemin (Lines le garde), puis toute
//     ponctuation finale parmi « , ; : ! ? ) » ; un chemin vide ensuite n'est pas une mention. L'ordre compte, comme à
//     l'origine : dans « @a.ts#L1-2, » la virgule est retirée après le suffixe, qui reste alors dans le chemin ;
//   - les doublons sont fusionnés : une mention par chemin, la première, dans l'ordre du prompt.
//
// L'origine fusionne les chemins une fois résolus ; ici, sans résolution, la fusion porte sur le chemin tel qu'écrit :
// « @a.ts » et « @./a.ts » restent deux mentions, que l'appelant fusionne après résolution. Fusionner des mentions
// dont les suffixes de lignes diffèrent vide Lines : la fusion ne restreint jamais la lecture.
//
// Le paquet est pur (règle depguard de .golangci.yml) : ni E/S, ni réseau, ni horloge, ni journal ; Parse est en temps
// linéaire (expressions RE2) et sûre pour des appels concurrents.
package mentions

import (
	"math"
	"regexp"
)

// jsSpace est la classe \s de JavaScript (espacements et fins de ligne d'ECMAScript : tabulation, VT, FF, espace,
// U+00A0, U+FEFF, séparateurs d'espace Zs d'Unicode 17, LF, CR, U+2028, U+2029). Le \s de RE2 n'a que l'ASCII.
const jsSpace = `\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}`

var (
	// mention : /(?:^|\s)@(?:"([^"]+)"|(\S+))/gu de l'origine, \s et \S écrits par jsSpace.
	mention = regexp.MustCompile(`(?:^|[` + jsSpace + `])@(?:"([^"]+)"|([^` + jsSpace + `]+))`)
	// linesSuffix : /#L\d+(?:-\d+)?$/u (\d de JavaScript : chiffres ASCII ; $ : fin du texte).
	linesSuffix = regexp.MustCompile(`#L[0-9]+(?:-[0-9]+)?$`)
	// trailingPunctuation : /[,;:!?)]+$/u.
	trailingPunctuation = regexp.MustCompile(`[,;:!?)]+$`)
)

// Mention est un fichier cité par « @ ».
type Mention struct {
	// Path est le chemin tel qu'écrit, sans guillemets, sans suffixe de lignes ni ponctuation finale ; jamais vide. Ses
	// octets sont ceux du prompt (un octet invalide y reste tel quel).
	Path string
	// Lines sont les chiffres du suffixe « #L » tels qu'écrits (« 10-20 », « 7 ») ; vide sans suffixe, ou quand des
	// mentions fusionnées ont des suffixes différents (lire alors tout le fichier).
	Lines string
	// ByteStart est la position de « @ » dans le prompt ; ByteEnd la fin (exclue) de la mention telle qu'écrite
	// (guillemet fermant, suffixe et ponctuation compris). Ceux de la première occurrence en cas de doublon.
	ByteStart int
	ByteEnd   int
}

// LineRange rend les lignes de Lines (« 10-20 » : 10 et 20 ; « 7 » : 7 et 7), telles qu'écrites, sans contrôle
// d'ordre ni de zéro. Faux si Lines est vide ou si un nombre dépasse math.MaxInt : lire alors tout le fichier.
func (m Mention) LineRange() (first, last int, ok bool) {
	if m.Lines == "" {
		return 0, 0, false
	}
	first, i, ok := number(m.Lines, 0)
	if !ok {
		return 0, 0, false
	}
	if i == len(m.Lines) {
		return first, first, true
	}
	if m.Lines[i] != '-' {
		return 0, 0, false
	}
	last, j, ok := number(m.Lines, i+1)
	if !ok || j != len(m.Lines) {
		return 0, 0, false
	}
	return first, last, true
}

// number lit les chiffres ASCII de s à partir de i ; faux sans chiffre ou au-delà de math.MaxInt.
func number(s string, i int) (int, int, bool) {
	value, start := 0, i
	for ; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		digit := int(s[i] - '0')
		if value > (math.MaxInt-digit)/10 {
			return 0, 0, false
		}
		value = value*10 + digit
	}
	return value, i, i > start
}

// Parse rend les fichiers cités par « @ » dans le prompt, dans l'ordre, sans doublon (mentionedPaths de l'origine,
// sans résolution). Un octet hors UTF-8 se lit comme U+FFFD, qui n'est pas un espacement.
func Parse(prompt []byte) []Mention {
	var out []Mention
	seen := map[string]int{}
	for _, loc := range mention.FindAllSubmatchIndex(prompt, -1) {
		start, end, at := loc[4], loc[5], loc[4]-1 // chemin sans guillemets
		if loc[2] >= 0 {
			start, end, at = loc[2], loc[3], loc[2]-2 // chemin entre guillemets
		}
		token := prompt[start:end]
		lines := ""
		if suffix := linesSuffix.FindIndex(token); suffix != nil {
			lines = string(token[suffix[0]+len("#L") : suffix[1]])
			token = token[:suffix[0]]
		}
		if punctuation := trailingPunctuation.FindIndex(token); punctuation != nil {
			token = token[:punctuation[0]]
		}
		if len(token) == 0 {
			continue
		}
		path := string(token)
		if index, ok := seen[path]; ok {
			if out[index].Lines != lines {
				out[index].Lines = ""
			}
			continue
		}
		seen[path] = len(out)
		out = append(out, Mention{Path: path, Lines: lines, ByteStart: at, ByteEnd: loc[1]})
	}
	return out
}
