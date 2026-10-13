// Décodages bornés du moteur de détection.
//
// Portage en Go de secret-guard/packages/core/src/encoding.ts et des candidats base64 de scanner.ts
// (BASE64_CANDIDATE, isKnownSriCandidate, isPlausibleBase64Payload, boucle de scanBase64Candidates sans l'analyse du
// texte décodé, qui relève de scan.go) ; Apache-2.0, origine, avis et modifications dans UPSTREAM.md.
//
// Budget (comme Secret Guard) : au plus maxDecodeAttempts candidats et maxDecodedBytes octets décodés par analyse,
// candidats refusés compris. Un budget épuisé rend errDecodeBudgetExhausted : l'analyse est incomplète, jamais un
// candidat ignoré. Aucune valeur, ni son encodage, n'entre dans une erreur.

package detect

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	// maxDecodeAttempts et maxDecodedBytes sont MAX_DECODE_ATTEMPTS et MAX_DECODED_BYTES de Secret Guard.
	maxDecodeAttempts = 128
	maxDecodedBytes   = 262_144
	// maxCandidateDecodedBytes borne le décodage d'un candidat base64 (16 384 dans scanBase64Candidates et par
	// défaut dans decodeBase64).
	maxCandidateDecodedBytes = 16_384
	// maxJWTHeaderBytes et maxJWTPayloadBytes bornent le décodage d'un en-tête et d'une charge de JWT.
	maxJWTHeaderBytes  = 4_096
	maxJWTPayloadBytes = 16_384
	// minBase64CandidateLength et maxBase64CandidateLength sont les bornes de BASE64_CANDIDATE
	// (/[A-Za-z0-9+/_-]{20,16384}={0,2}/g).
	minBase64CandidateLength = 20
	maxBase64CandidateLength = 16_384
	// minJWTSignatureLength est la longueur minimale de la signature d'un JWT (en unités UTF-16).
	minJWTSignatureLength = 8
)

// errDecodeBudgetExhausted : le budget de décodage base64 de l'analyse est épuisé ; l'analyse est incomplète.
var errDecodeBudgetExhausted = errors.New("détection : budget de décodage base64 épuisé")

// decodeBudget est le budget de décodage d'une analyse (DecodeBudget de Secret Guard).
type decodeBudget struct {
	candidates int
	bytes      int
	exhausted  bool
}

// base64Sextets donne la valeur d'un caractère de l'alphabet base64 standard, -1 sinon.
var base64Sextets = func() [256]int8 {
	var table [256]int8
	for i := range table {
		table[i] = -1
	}
	for i, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" {
		table[c] = int8(i)
	}
	return table
}()

// utf16Length est la longueur d'un texte en unités UTF-16 (value.length de JavaScript ; un octet invalide compte
// pour U+FFFD).
func utf16Length(value string) int {
	length := 0
	for _, r := range value {
		if r > 0xFFFF {
			length += 2
		} else {
			length++
		}
	}
	return length
}

// decodeBase64 décode strictement value en base64 standard ou URL, remplissage facultatif, et ne rend le texte que
// s'il est de l'UTF-8 valide sans NUL, non vide et imprimable à 90 % au moins (decodeBase64 de Secret Guard). Une
// marque d'ordre d'octets initiale est retirée, comme le fait TextDecoder.
func decodeBase64(value string, maxDecoded int) (string, bool) {
	length := len(value)
	padding := 0
	for padding < length && value[length-1-padding] == '=' {
		padding++
	}
	if padding > 2 || length%4 == 1 {
		return "", false
	}
	for i := 0; i < length-padding; i++ {
		if c := value[i]; base64Sextets[c] < 0 && c != '-' && c != '_' {
			return "", false
		}
	}
	padded := length + (4-length%4)%4
	quads := padded / 4
	// Octets décodés : trois par quadruplet, moins un par « = » du dernier (remplissage reçu ou ajouté). Secret
	// Guard refuse dès que le compte dépasse la borne ; le compte croît avec chaque quadruplet, la borne finale suffit.
	decodedLength := quads*3 - (padded - (length - padding))
	if decodedLength > maxDecoded {
		return "", false
	}
	sextet := func(i int) int8 {
		if i >= length-padding {
			return -2 // « = », reçu ou ajouté
		}
		c := value[i]
		switch c {
		case '-':
			c = '+'
		case '_':
			c = '/'
		}
		return base64Sextets[c]
	}
	decoded := make([]byte, 0, max(decodedLength, 0))
	// Octets décodés effacés au retour ; la chaîne rendue, immuable, ne peut pas l'être.
	defer func() { clear(decoded[:cap(decoded)]) }()
	for q := 0; q < quads; q++ {
		a, b, c, d := sextet(4*q), sextet(4*q+1), sextet(4*q+2), sextet(4*q+3)
		if a < 0 || b < 0 {
			return "", false
		}
		// Comme Secret Guard : un « = » vaut 0 et retire l'octet qu'il terminerait.
		cValue := max(c, 0)
		decoded = append(decoded, byte(a)<<2|byte(b)>>4)
		if c >= 0 {
			decoded = append(decoded, byte(b&15)<<4|byte(cValue)>>2)
		}
		if d >= 0 {
			decoded = append(decoded, byte(cValue&3)<<6|byte(d))
		}
	}
	if !utf8.Valid(decoded) {
		return "", false
	}
	text := strings.TrimPrefix(string(decoded), "\xef\xbb\xbf")
	if text == "" || strings.IndexByte(text, 0) >= 0 {
		return "", false
	}
	total, printable := 0, 0
	for _, r := range text {
		total++
		if r == '\n' || r == '\r' || r == '\t' || r >= ' ' {
			printable++
		}
	}
	if float64(printable)/float64(total) < 0.9 {
		return "", false
	}
	return text, true
}

// decodeBase64 débite le budget avant tout décodage (decodeBase64Budgeted de Secret Guard). Budget épuisé, déjà ou
// par ce candidat : errDecodeBudgetExhausted.
func (b *decodeBudget) decodeBase64(value string, maxDecoded int) (string, bool, error) {
	if b.exhausted {
		return "", false, errDecodeBudgetExhausted
	}
	b.candidates++
	b.bytes += min((utf16Length(value)*3+3)/4, maxDecoded+1)
	if b.candidates > maxDecodeAttempts || b.bytes > maxDecodedBytes {
		b.exhausted = true
		return "", false, errDecodeBudgetExhausted
	}
	text, ok := decodeBase64(value, maxDecoded)
	return text, ok, nil
}

// isJSONObject dit si text est un document JSON dont la valeur est un objet (JSON.parse puis typeof "object", ni
// null ni tableau).
func isJSONObject(text string) bool {
	trimmed := strings.TrimLeft(text, " \t\n\r")
	return strings.HasPrefix(trimmed, "{") && json.Valid([]byte(text))
}

// isStructurallyValidJWT suit isStructurallyValidJwt de Secret Guard : trois segments, signature de huit
// caractères au moins, en-tête et charge décodés en objets JSON. budget nil : décodage hors budget. Le budget
// épuisé pendant ou avant l'appel rend errDecodeBudgetExhausted (le jeton n'est alors pas reconnu).
func isStructurallyValidJWT(value string, budget *decodeBudget) (bool, error) {
	exhausted := func() error {
		if budget != nil && budget.exhausted {
			return errDecodeBudgetExhausted
		}
		return nil
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 || utf16Length(parts[2]) < minJWTSignatureLength {
		return false, exhausted()
	}
	decode := func(part string, maxDecoded int) (string, bool) {
		if budget == nil {
			return decodeBase64(part, maxDecoded)
		}
		text, ok, _ := budget.decodeBase64(part, maxDecoded)
		return text, ok
	}
	// Ordre de Secret Guard : un en-tête décodé qui n'est pas du JSON arrête avant le décodage de la charge.
	header, headerOK := decode(parts[0], maxJWTHeaderBytes)
	if headerOK && !json.Valid([]byte(header)) {
		return false, exhausted()
	}
	payload, payloadOK := decode(parts[1], maxJWTPayloadBytes)
	if payloadOK && !json.Valid([]byte(payload)) {
		return false, exhausted()
	}
	return headerOK && payloadOK && isJSONObject(header) && isJSONObject(payload), exhausted()
}

// knownSRIDigest est l'empreinte d'intégrité de sous-ressource de isKnownSriCandidate.
var knownSRIDigest = regexp.MustCompile(`(?i)^sha(256|384|512)-([A-Za-z0-9+/]+={0,2})$`)

// isKnownSRICandidate suit isKnownSriCandidate de Secret Guard : une empreinte SRI exacte n'est pas une charge.
func isKnownSRICandidate(value string) bool {
	match := knownSRIDigest.FindStringSubmatch(value)
	if match == nil {
		return false
	}
	switch body := len(match[2]); match[1] {
	case "256":
		return body == 43 || body == 44
	case "384":
		return body == 64
	default:
		return body == 86 || body == 88
	}
}

// isPlausibleBase64Payload suit isPlausibleBase64Payload de Secret Guard : quatre caractères distincts au moins,
// longueur possible, un seul alphabet (standard ou URL).
func isPlausibleBase64Payload(value string) bool {
	if isKnownSRICandidate(value) {
		return false
	}
	var seen [256]bool
	symbols := 0
	for i := 0; i < len(value) && symbols < 4; i++ {
		if !seen[value[i]] {
			seen[value[i]] = true
			symbols++
		}
	}
	if symbols < 4 || utf16Length(value)%4 == 1 {
		return false
	}
	standard := strings.ContainsAny(value, "+/")
	urlSafe := strings.ContainsAny(value, "-_")
	return !standard || !urlSafe
}

// base64Candidates rend les étendues [start, end) des correspondances de BASE64_CANDIDATE dans text, dans l'ordre
// de matchAll : suites maximales de l'alphabet base64 découpées en morceaux de 16 384 caractères, chaque morceau
// d'au moins 20 caractères étant suivi de jusqu'à deux « = » s'il termine la suite. RE2 ne borne pas une répétition
// au-delà de 1 000 : la lecture est écrite à la main, linéaire.
func base64Candidates(text []byte, yield func(start, end int) error) error {
	for i := 0; i < len(text); {
		if !isBase64Character(text[i]) {
			i++
			continue
		}
		runEnd := i
		for runEnd < len(text) && isBase64Character(text[runEnd]) {
			runEnd++
		}
		for position := i; runEnd-position >= minBase64CandidateLength; {
			end := position + min(maxBase64CandidateLength, runEnd-position)
			next := end
			if end == runEnd {
				for padding := 0; padding < 2 && isAt(text, next, '='); padding++ {
					next++
				}
			}
			if err := yield(position, next); err != nil {
				return err
			}
			position = end
		}
		i = runEnd
	}
	return nil
}

// sourceRange est une étendue d'octets de la source.
type sourceRange struct{ start, end int }

// forEachBase64Candidate décode, dans le budget de l'analyse, chaque candidat base64 plausible de la vue qui n'a pas
// déjà été vu à la même étendue de la source, et passe le texte décodé à visit (boucle de scanBase64Candidates de
// Secret Guard ; l'analyse du texte décodé relève de scan.go). Un candidat refusé par le décodage est débité.
func forEachBase64Candidate(v *view, budget *decodeBudget, seen map[sourceRange]struct{}, visit func(start, end int, decoded string) error) error {
	return base64Candidates(v.text, func(viewStart, viewEnd int) error {
		value := string(v.text[viewStart:viewEnd])
		if !isPlausibleBase64Payload(value) {
			return nil
		}
		start, end := v.mapRange(viewStart, viewEnd)
		key := sourceRange{start, end}
		if _, ok := seen[key]; ok {
			return nil
		}
		seen[key] = struct{}{}
		decoded, ok, err := budget.decodeBase64(value, maxCandidateDecodedBytes)
		if err != nil || !ok {
			return err
		}
		return visit(start, end, decoded)
	})
}
