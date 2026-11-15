// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// pyToken est un lexème de Python : chaîne ('s', texte décodé), nom ('n'), nombre ('d') ou ponctuation ('p').
type pyToken struct {
	kind byte
	text string
}

// pyTokens découpe un source Python en lexèmes, commentaires et espaces retirés. Seuls les littéraux de chaîne
// ordinaires sont décodés : une chaîne formatée (préfixe f), d'octets (préfixe b) ou un échappement \N{…} arrête la
// lecture (le fichier lu n'en contient pas ; mieux vaut une erreur qu'un texte mal copié).
func pyTokens(src string) ([]pyToken, error) {
	var tokens []pyToken
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '"' || c == '\'':
			text, next, err := pyString(src, i, false)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, pyToken{'s', text})
			i = next
		case isNameStart(c):
			end := i
			for end < len(src) && (isNameStart(src[end]) || isDigit(src[end])) {
				end++
			}
			if end < len(src) && (src[end] == '"' || src[end] == '\'') && end-i <= 2 {
				prefix := strings.ToLower(src[i:end])
				if strings.ContainsAny(prefix, "fb") || strings.Trim(prefix, "ru") != "" {
					return nil, fmt.Errorf("préfixe de chaîne %q non lu (octet %d)", prefix, i)
				}
				text, next, err := pyString(src, end, strings.Contains(prefix, "r"))
				if err != nil {
					return nil, err
				}
				tokens = append(tokens, pyToken{'s', text})
				i = next
				continue
			}
			tokens = append(tokens, pyToken{'n', src[i:end]})
			i = end
		case isDigit(c):
			end := i
			for end < len(src) && (isDigit(src[end]) || src[end] == '.' || src[end] == '_' || isNameStart(src[end])) {
				end++
			}
			tokens = append(tokens, pyToken{'d', src[i:end]})
			i = end
		default:
			tokens = append(tokens, pyToken{'p', src[i : i+1]})
			i++
		}
	}
	return tokens, nil
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// pyString décode le littéral de chaîne qui commence par un guillemet à src[at] et rend le texte et l'octet suivant.
func pyString(src string, at int, raw bool) (string, int, error) {
	quote := src[at : at+1]
	if strings.HasPrefix(src[at:], strings.Repeat(quote, 3)) {
		quote = strings.Repeat(quote, 3)
	}
	var out strings.Builder
	for i := at + len(quote); i < len(src); {
		if strings.HasPrefix(src[i:], quote) {
			return out.String(), i + len(quote), nil
		}
		c := src[i]
		if c == '\n' && len(quote) == 1 {
			break
		}
		if c != '\\' || i+1 >= len(src) {
			out.WriteByte(c)
			i++
			continue
		}
		next := src[i+1]
		if raw {
			out.WriteByte(c)
			out.WriteByte(next)
			i += 2
			continue
		}
		i += 2
		switch next {
		case '\n':
		case '\\', '\'', '"':
			out.WriteByte(next)
		case 'a':
			out.WriteByte(7)
		case 'b':
			out.WriteByte(8)
		case 'f':
			out.WriteByte(12)
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 't':
			out.WriteByte('\t')
		case 'v':
			out.WriteByte(11)
		case 'x', 'u', 'U':
			width := map[byte]int{'x': 2, 'u': 4, 'U': 8}[next]
			if i+width > len(src) {
				return "", 0, fmt.Errorf("échappement \\%c tronqué (octet %d)", next, i)
			}
			value, err := strconv.ParseUint(src[i:i+width], 16, 32)
			if err != nil || value > utf8.MaxRune {
				return "", 0, fmt.Errorf("échappement \\%c invalide (octet %d)", next, i)
			}
			out.WriteRune(rune(value))
			i += width
		case 'N':
			return "", 0, fmt.Errorf("échappement \\N{…} non lu (octet %d)", i)
		default:
			if next >= '0' && next <= '7' {
				end := i
				for end < len(src) && end < i+2 && src[end] >= '0' && src[end] <= '7' {
					end++
				}
				value, _ := strconv.ParseUint(src[i-1:end], 8, 32)
				out.WriteRune(rune(value))
				i = end
				continue
			}
			// Échappement inconnu : Python garde la barre oblique inverse.
			out.WriteByte('\\')
			out.WriteByte(next)
		}
	}
	return "", 0, fmt.Errorf("chaîne non fermée (octet %d)", at)
}

// labelledText est un texte étiqueté d'un jeu d'essai : valid dit si le jeu le tient pour sain.
type labelledText struct {
	text  string
	valid bool
}

// llmGuardCases relève, dans le fichier d'essai de LLM Guard, chaque cas « (MatchType.X, "texte", True|False, score) » :
// le texte est une suite de littéraux de chaîne juxtaposés. Un cas dont le texte n'est pas un littéral est écarté et
// compté.
func llmGuardCases(src string) (cases []labelledText, skipped int, err error) {
	tokens, err := pyTokens(src)
	if err != nil {
		return nil, 0, err
	}
	is := func(i int, kind byte, text string) bool {
		return i < len(tokens) && tokens[i].kind == kind && tokens[i].text == text
	}
	for i := 0; i < len(tokens); i++ {
		if !is(i, 'p', "(") || !is(i+1, 'n', "MatchType") || !is(i+2, 'p', ".") || i+4 >= len(tokens) || tokens[i+3].kind != 'n' || !is(i+4, 'p', ",") {
			continue
		}
		at := i + 5
		var text strings.Builder
		parts := 0
		for at < len(tokens) && tokens[at].kind == 's' {
			text.WriteString(tokens[at].text)
			parts++
			at++
		}
		if parts == 0 || !is(at, 'p', ",") || at+1 >= len(tokens) || tokens[at+1].kind != 'n' || (tokens[at+1].text != "True" && tokens[at+1].text != "False") {
			skipped++
			continue
		}
		cases = append(cases, labelledText{text.String(), tokens[at+1].text == "True"})
		i = at + 1
	}
	if len(cases) == 0 {
		return nil, skipped, errors.New("aucun cas lu")
	}
	return cases, skipped, nil
}

// jsLiteralLines relève les lignes « '…', » ou « "…", » d'un tableau TypeScript (un littéral par ligne, deux espaces
// de retrait) et décode chaque littéral sans l'exécuter.
func jsLiteralLines(src string) ([]string, error) {
	var texts []string
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\r"), ",")
		if len(line) < 4 || !strings.HasPrefix(line, "  ") || (line[2] != '\'' && line[2] != '"') || line[len(line)-1] != line[2] {
			continue
		}
		text, err := jsUnescape(line[3 : len(line)-1])
		if err != nil {
			return nil, err
		}
		texts = append(texts, text)
	}
	if len(texts) == 0 {
		return nil, errors.New("aucun littéral lu")
	}
	return texts, nil
}

// jsUnescape décode les échappements d'un littéral de chaîne JavaScript. Le résultat est celui d'une chaîne
// JavaScript écrite en UTF-8 : deux substituts qui se suivent font un point de code, un substitut isolé vaut U+FFFD.
func jsUnescape(body string) (string, error) {
	var units []uint16
	for i := 0; i < len(body); {
		c := body[i]
		if c != '\\' {
			r, width := utf8.DecodeRuneInString(body[i:])
			units = utf16.AppendRune(units, r)
			i += width
			continue
		}
		if i+1 >= len(body) {
			return "", errors.New("littéral JavaScript terminé par une barre oblique inverse")
		}
		next := body[i+1]
		i += 2
		hex := func(width int) (rune, error) {
			if i+width > len(body) {
				return 0, errors.New("échappement JavaScript tronqué")
			}
			value, err := strconv.ParseUint(body[i:i+width], 16, 32)
			i += width
			return rune(value), err
		}
		switch next {
		case 'n':
			units = append(units, '\n')
		case 't':
			units = append(units, '\t')
		case 'r':
			units = append(units, '\r')
		case 'x':
			value, err := hex(2)
			if err != nil {
				return "", err
			}
			units = append(units, uint16(value))
		case 'u':
			if i < len(body) && body[i] == '{' {
				end := strings.IndexByte(body[i:], '}')
				if end < 0 {
					return "", errors.New("échappement \\u{…} non fermé")
				}
				value, err := strconv.ParseUint(body[i+1:i+end], 16, 32)
				if err != nil || value > utf8.MaxRune {
					return "", errors.New("échappement \\u{…} invalide")
				}
				units = utf16.AppendRune(units, rune(value))
				i += end + 1
				continue
			}
			value, err := hex(4)
			if err != nil {
				return "", err
			}
			units = append(units, uint16(value))
		default:
			r, width := utf8.DecodeRuneInString(body[i-1:])
			units = utf16.AppendRune(units, r)
			i += width - 1
		}
	}
	return string(utf16.Decode(units)), nil
}

// percentDecode décode les suites %XX d'une ligne, comme urllib.parse.unquote : une suite qui n'est pas de
// l'hexadécimal reste telle quelle, et chaque octet décodé qui ne fait pas de l'UTF-8 valide vaut U+FFFD.
func percentDecode(line string) string {
	out := make([]byte, 0, len(line))
	for i := 0; i < len(line); i++ {
		if line[i] == '%' && i+2 < len(line) && isHex(line[i+1]) && isHex(line[i+2]) {
			if value, err := strconv.ParseUint(line[i+1:i+3], 16, 8); err == nil {
				out = append(out, byte(value))
				i += 2
				continue
			}
		}
		out = append(out, line[i])
	}
	var text strings.Builder
	for len(out) > 0 {
		r, width := utf8.DecodeRune(out)
		text.WriteRune(r)
		out = out[width:]
	}
	return text.String()
}

func isHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
