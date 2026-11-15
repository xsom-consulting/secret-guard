// SPDX-License-Identifier: Apache-2.0

// Langage par bloc de code (v0.10.0). Écart avec Secret Guard (UPSTREAM.md) : dans un texte analysé sans langage
// (un prompt), un bloc clôturé par trois accents graves ou plus, ouvert avec un nom de langage connu du moteur
// (codeLanguages, structuredLanguages, dotenvLanguages, shellLanguages de contextual.go), est lu avec ce langage pour
// les affectations, comme si l'analyse l'avait déclaré (Options.LanguageID). Un bloc sans nom, de nom inconnu, ou
// jamais refermé garde la lecture sans langage. Un langage déclaré par l'analyse l'emporte toujours.
//
// Lecture en un passage sur les lignes de la vue, faite au plus une fois par contextualText et seulement si le texte
// porte trois accents graves ; la recherche du bloc d'une position est logarithmique.

package detect

import (
	"bytes"
	"sort"
)

// fencedBlock est le contenu [start, end) d'un bloc clôturé (de la ligne qui suit l'ouverture au début de la ligne de
// fermeture) et le langage nommé à son ouverture.
type fencedBlock struct {
	start, end int
	lang       language
}

var fenceMark = []byte("```")

// maxFenceLanguageBytes borne le nom lu après l'ouverture (le plus long nom connu a 15 octets).
const maxFenceLanguageBytes = 16

// languageAt rend le langage de l'affectation dont le nom commence en at : le langage déclaré par l'analyse s'il
// existe, sinon celui du bloc clôturé qui contient at, sinon aucun.
func (ctx *contextualText) languageAt(declared language, at int) language {
	if declared.set {
		return declared
	}
	if !ctx.fencesReady {
		ctx.fences = fencedBlocksOf(ctx.text)
		ctx.fencesReady = true
	}
	blocks := ctx.fences
	if len(blocks) == 0 {
		return declared
	}
	i := sort.Search(len(blocks), func(i int) bool { return blocks[i].end > at })
	if i < len(blocks) && blocks[i].start <= at {
		return blocks[i].lang
	}
	return declared
}

// fencedBlocksOf rend, dans l'ordre du texte, les blocs clôturés et refermés dont l'ouverture nomme un langage connu.
func fencedBlocksOf(text []byte) []fencedBlock {
	if !bytes.Contains(text, fenceMark) {
		return nil
	}
	var blocks []fencedBlock
	open := false
	ticks, contentStart := 0, 0
	var lang language
	for lineStart := 0; lineStart < len(text); {
		lineEnd := len(text)
		if found := bytes.IndexByte(text[lineStart:], '\n'); found >= 0 {
			lineEnd = lineStart + found
		}
		next := min(lineEnd+1, len(text))
		if run, rest, ok := fenceLine(text[lineStart:lineEnd]); ok {
			switch {
			case !open && bytes.IndexByte(rest, '`') < 0:
				open, ticks, contentStart, lang = true, run, next, fenceLanguage(rest)
			case open && run >= ticks && len(bytes.TrimRight(rest, " \t\r")) == 0:
				if lang.set && contentStart < lineStart {
					blocks = append(blocks, fencedBlock{start: contentStart, end: lineStart, lang: lang})
				}
				open = false
			}
		}
		lineStart = next
	}
	return blocks
}

// fenceLine dit si la ligne est une clôture : au plus trois espaces, puis trois accents graves ou plus. Elle rend le
// nombre d'accents graves et le reste de la ligne.
func fenceLine(line []byte) (int, []byte, bool) {
	indent := 0
	for indent < len(line) && indent < 3 && line[indent] == ' ' {
		indent++
	}
	run := 0
	for indent+run < len(line) && line[indent+run] == '`' {
		run++
	}
	if run < len(fenceMark) {
		return 0, nil, false
	}
	return run, line[indent+run:], true
}

// fenceLanguage rend le langage nommé par le premier mot qui suit l'ouverture, s'il est connu du moteur ; le nom est
// gardé tel qu'il est écrit, comme un LanguageID.
func fenceLanguage(info []byte) language {
	info = bytes.TrimLeft(info, " \t")
	end := 0
	for end < len(info) && end <= maxFenceLanguageBytes && isFenceLanguageByte(info[end]) {
		end++
	}
	if end == 0 || end > maxFenceLanguageBytes {
		return language{}
	}
	if end < len(info) {
		switch info[end] {
		case ' ', '\t', '\r', '{', ':', ',':
		default:
			return language{}
		}
	}
	named := language{id: string(info[:end]), set: true}
	lowered := named.lowered()
	if codeLanguages[lowered] || structuredLanguages[lowered] || dotenvLanguages[lowered] || shellLanguages[lowered] {
		return named
	}
	return language{}
}

func isFenceLanguageByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}
