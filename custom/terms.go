// Termes confidentiels du Pack de règles du client (docs/custom-pack.md, §4).
//
// Portage en Go de secret-guard/packages/core/src/custom/terms.ts (Apache-2.0, origine, avis et modifications dans
// UPSTREAM.md). Le Pack ne porte que des condensats SHA-256 salés de n-grammes normalisés, jamais un terme : le
// moteur normalise les mots du texte, hache leurs n-grammes avec le sel et compare. Aucun terme, n-gramme ni
// condensat ne sort d'une analyse : une détection est une étendue d'octets.

package custom

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	// memoWords et memoEntries bornent la mémoire des verdicts des mots et paires de mots (MEMO_WORDS,
	// MEMO_ENTRIES) : même mémoire, donc même travail compté, que l'origine.
	memoWords   = 1 << 21
	memoEntries = 500_000
)

// isASCIIText suit ASCII_ONLY de l'origine (/^[ -~\t\n\r]*$/).
func isASCIIText(word string) bool {
	for i := 0; i < len(word); i++ {
		c := word[i]
		if (c < 0x20 || c > 0x7e) && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
	}
	return true
}

// normalizeWord suit normalizeWord de l'origine : NFKD, marques (\p{M}) retirées, minuscules de toLowerCase.
func normalizeWord(word string) string {
	if isASCIIText(word) {
		return strings.ToLower(word)
	}
	decomposed := norm.NFKD.String(word)
	var b strings.Builder
	b.Grow(len(decomposed))
	for _, r := range decomposed {
		if !unicode.IsMark(r) {
			b.WriteRune(r)
		}
	}
	return jsToLower(b.String())
}

// forEachWord appelle fn pour chaque mot de text (suite maximale de points de code \p{L}, \p{N} ou \p{M}) avec ses
// bornes en octets ; un octet hors séquence UTF-8 valide vaut U+FFFD, qui sépare les mots.
func forEachWord(text []byte, fn func(start, end int)) {
	start := -1
	for i := 0; i < len(text); {
		r, width := utf8.DecodeRune(text[i:])
		word := isWordRune(r)
		switch {
		case word && start < 0:
			start = i
		case !word && start >= 0:
			fn(start, i)
			start = -1
		}
		i += width
	}
	if start >= 0 {
		fn(start, len(text))
	}
}

// NormalizeTerm rend la forme normalisée d'un terme saisi : ses mots normalisés, joints par une espace (les mots
// devenus vides sont omis). C'est sur cette forme que se calcule le condensat d'un terme (TermDigest).
func NormalizeTerm(term string) string {
	normalized, _ := normalizeTerm(term)
	return normalized
}

// normalizeTerm rend la forme normalisée d'un terme et son nombre de mots (longueur du n-gramme qu'il forme).
func normalizeTerm(term string) (string, int) {
	var words []string
	forEachWord([]byte(term), func(start, end int) {
		if normalized := normalizeWord(term[start:end]); normalized != "" {
			words = append(words, normalized)
		}
	})
	return strings.Join(words, " "), len(words)
}

// TermDigest rend l'hexadécimal minuscule de SHA-256(salt ‖ UTF-8(normalized)), condensat d'un terme dans un Pack.
// normalized doit être la forme rendue par NormalizeTerm.
func TermDigest(salt []byte, normalized string) string {
	message := make([]byte, 0, len(salt)+len(normalized))
	message = append(append(message, salt...), normalized...)
	sum := sha256.Sum256(message)
	return hex.EncodeToString(sum[:])
}

// ErrInvalidSalt : le sel n'a pas la forme du schéma (base64 de 16 octets : 22 caractères et « == » ; de 32 octets :
// 43 caractères et « = »).
var ErrInvalidSalt = errors.New("sel refusé : base64 de 16 ou 32 octets attendu")

// DecodeSalt lit le sel d'un détecteur de termes comme le moteur, après avoir vérifié sa forme.
func DecodeSalt(salt string) ([]byte, error) {
	if !saltForm.MatchString(salt) {
		return nil, ErrInvalidSalt
	}
	return decodeSalt(salt), nil
}

// DigestTerm normalise un terme saisi et rend le condensat de sa forme normalisée sous salt, et son nombre de mots :
// 0 pour un terme sans mot (jamais détecté) ; un détecteur ne le trouve que si son maxWords l'atteint (au plus 4).
func DigestTerm(salt []byte, term string) (string, int) {
	normalized, words := normalizeTerm(term)
	return TermDigest(salt, normalized), words
}

// decodeSalt suit decodeBase64 de l'origine : « = » finaux retirés, groupes de 6 bits lus, bits restants ignorés.
// Le sel a déjà la forme du schéma (22 caractères et « == », ou 43 et « = »).
func decodeSalt(value string) []byte {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	clean := strings.TrimRight(value, "=")
	out := make([]byte, 0, len(clean)*6/8)
	buffer, bits := 0, 0
	for i := 0; i < len(clean); i++ {
		buffer = (buffer<<6 | strings.IndexByte(alphabet, clean[i])) & 0xffffff
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buffer>>bits))
		}
	}
	return out
}

// word est un mot du texte : bornes en octets, octets UTF-8 du mot normalisé, et numéro du mot normalisé (même
// numéro pour un même mot normalisé dans un texte).
type word struct {
	start, end int
	bytes      []byte
	id         int
}

type normalizedWord struct {
	bytes []byte
	id    int
}

// textWords suit textWords de l'origine : un mot compte une unité ; un mot devenu vide est ignoré.
func textWords(text []byte, meter *Meter) []word {
	var words []word
	byRaw := map[string]*normalizedWord{}
	byNormalized := map[string]*normalizedWord{}
	forEachWord(text, func(start, end int) {
		raw := string(text[start:end])
		meter.spend(1)
		entry, seen := byRaw[raw]
		if !seen {
			normalized := normalizeWord(raw)
			if normalized != "" {
				entry = byNormalized[normalized]
				if entry == nil {
					entry = &normalizedWord{bytes: []byte(normalized), id: len(byNormalized)}
					byNormalized[normalized] = entry
				}
			}
			byRaw[raw] = entry
		}
		if entry != nil {
			words = append(words, word{start: start, end: end, bytes: entry.bytes, id: entry.id})
		}
	})
	return words
}

// termHit est un n-gramme de mots [premier, dernier] dont le condensat est dans le Pack : bornes en octets,
// condensat et nombre de mots.
type termHit struct {
	start, end int
	digest     [sha256.Size]byte
	words      int
}

// sha256Blocks est le nombre de compressions SHA-256 d'un message de length octets (Sha256.blocks de l'origine).
func sha256Blocks(length int) int64 { return int64((length+8)/64 + 1) }

// memoVerdict est le verdict mémorisé d'un mot ou d'une paire de mots : condensat présent dans le Pack, ou absent.
type memoVerdict struct {
	digest [sha256.Size]byte
	found  bool
}

// findTermHits suit findTermHits de l'origine : chaque n-gramme de 1 à maxWords mots consécutifs est haché avec le
// sel ; ceux dont le condensat est dans digests sont rendus. Les verdicts des mots et des paires de mots sont
// mémorisés (une unité), les autres n-grammes hachés (hashBlockCost unités par compression).
func findTermHits(words []word, salt []byte, maxWords int, digests map[[sha256.Size]byte]bool, meter *Meter) []termHit {
	var hits []termHit
	buffer := make([]byte, 0, len(salt)+256)
	buffer = append(buffer, salt...)
	seen := map[int64]memoVerdict{}
	for first := range words {
		buffer = buffer[:len(salt)]
		key := int64(-1)
		for count := 1; count <= maxWords && first+count-1 < len(words); count++ {
			w := words[first+count-1]
			memoizable := w.id < memoWords
			switch {
			case count == 1 && memoizable:
				key = int64(w.id)
			case count == 2 && key >= 0 && memoizable:
				key = memoWords*(key+1) + int64(w.id)
			default:
				key = -1
			}
			if count > 1 {
				buffer = append(buffer, ' ')
			}
			buffer = append(buffer, w.bytes...)
			verdict, remembered := memoVerdict{}, false
			if key >= 0 {
				verdict, remembered = seen[key]
			}
			if remembered {
				meter.spend(1)
			} else {
				meter.spend(sha256Blocks(len(buffer)) * hashBlockCost)
				verdict.digest = sha256.Sum256(buffer)
				verdict.found = digests[verdict.digest]
				if key >= 0 && len(seen) < memoEntries {
					seen[key] = verdict
				}
			}
			if !verdict.found {
				continue
			}
			hits = append(hits, termHit{start: words[first].start, end: w.end, digest: verdict.digest, words: count})
		}
	}
	return hits
}
