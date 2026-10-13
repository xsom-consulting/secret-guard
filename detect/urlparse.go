// Analyse d'URL du moteur de détection : ce que scanCredentialUrls de Secret Guard lit
// du constructeur URL de JavaScript (norme URL du WHATWG) — l'analyse échoue-t-elle, et quel est le mot de passe —,
// puis decodeURIComponent.
//
// Portage partiel de l'algorithme d'analyse de la norme URL (https://url.spec.whatwg.org/, états « scheme »,
// « authority », « host », « port »), limité aux candidats de URL_WITH_CREDENTIALS : un schéma de la liste
// (http, https, ftp : spéciaux ; postgres, mysql, mariadb, mongodb, redis, amqp… : non spéciaux) suivi de « :// » et
// de caractères qui ne sont ni des espaces de JavaScript ni « " ' < > ». Les chemins, requêtes et fragments ne font
// jamais échouer l'analyse et ne sont pas lus. Écart : un hôte spécial non ASCII, ou dont une étiquette commence par
// « xn-- », passe par UTS 46 (IDNA) dans la norme ; le moteur, sans ces tables, le tient pour valide (constat
// possible là où JavaScript échouerait : jamais un secret manqué).

package detect

import (
	"strings"
	"unicode/utf8"
)

// specialSchemes : schémas spéciaux de la norme parmi ceux de URL_WITH_CREDENTIALS.
var specialSchemes = map[string]bool{"http": true, "https": true, "ftp": true}

// urlPassword rend le mot de passe (forme encodée de la norme) de l'URL candidate, et faux si le constructeur URL de
// JavaScript lèverait une erreur.
func urlPassword(candidate []byte) (string, bool) {
	input := candidate
	// Espaces et caractères de commande C0 retirés aux deux bouts : le candidat commence par un schéma, seule la fin
	// en a.
	for len(input) > 0 && input[len(input)-1] <= ' ' {
		input = input[:len(input)-1]
	}
	colon := strings.IndexByte(string(input), ':')
	if colon <= 0 || len(input) < colon+3 || input[colon+1] != '/' || input[colon+2] != '/' {
		return "", false
	}
	special := specialSchemes[strings.ToLower(string(input[:colon]))]
	rest := input[colon+3:]
	if special {
		// État « special authority ignore slashes » : toute barre supplémentaire, oblique ou inverse, est ignorée.
		for len(rest) > 0 && (rest[0] == '/' || rest[0] == '\\') {
			rest = rest[1:]
		}
	}
	isAuthorityEnd := func(c byte) bool { return c == '/' || c == '?' || c == '#' || (special && c == '\\') }
	authorityEnd := len(rest)
	for i := 0; i < len(rest); i++ {
		if isAuthorityEnd(rest[i]) {
			authorityEnd = i
			break
		}
	}
	authority := rest[:authorityEnd]
	at := strings.LastIndexByte(string(authority), '@')
	if at < 0 {
		// Sans « @ », pas d'identifiants : mot de passe vide, que l'analyse réussisse ou non.
		return "", false
	}
	if at == len(authority)-1 {
		// « @ » suivi de rien avant la fin de l'autorité : échec de la norme (host-missing).
		return "", false
	}
	password, hasPassword := userinfoPassword(authority[:at])
	if !validHostAndPort(authority[at+1:], special) {
		return "", false
	}
	if !hasPassword {
		return "", true
	}
	return password, true
}

// userinfoPassword suit l'état « authority » : chaque « @ » sauf le dernier devient « %40 » ; le mot de passe suit le
// premier « : » ; chaque point de code est encodé avec l'ensemble userinfo.
func userinfoPassword(userinfo []byte) (string, bool) {
	colon := strings.IndexByte(string(userinfo), ':')
	if colon < 0 {
		return "", false
	}
	var b strings.Builder
	for i := colon + 1; i < len(userinfo); {
		r, width := utf8.DecodeRune(userinfo[i:])
		if r == '@' {
			b.WriteString("%40")
		} else {
			percentEncodeUserinfo(&b, r)
		}
		i += width
	}
	return b.String(), true
}

// percentEncodeUserinfo écrit r encodé avec l'ensemble « userinfo percent-encode set » de la norme.
func percentEncodeUserinfo(b *strings.Builder, r rune) {
	if r < 0x80 && !inUserinfoSet(byte(r)) {
		b.WriteByte(byte(r))
		return
	}
	var buffer [utf8.UTFMax]byte
	n := utf8.EncodeRune(buffer[:], r)
	const hex = "0123456789ABCDEF"
	for _, c := range buffer[:n] {
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
}

func inUserinfoSet(c byte) bool {
	if c <= 0x1F || c > 0x7E {
		return true
	}
	return strings.IndexByte(" \"#<>?`{}/:;=@[\\]^|", c) >= 0
}

// validHostAndPort suit les états « host » et « port » sur la partie de l'autorité qui suit le dernier « @ ».
func validHostAndPort(hostPort []byte, special bool) bool {
	insideBrackets := false
	end := len(hostPort)
	for i, c := range hostPort {
		if c == ':' && !insideBrackets {
			end = i
			break
		}
		switch c {
		case '[':
			insideBrackets = true
		case ']':
			insideBrackets = false
		}
	}
	host := hostPort[:end]
	if end < len(hostPort) {
		if len(host) == 0 {
			return false
		}
		if !validPort(hostPort[end+1:]) {
			return false
		}
	} else if special && len(host) == 0 {
		return false
	}
	return validHost(host, special)
}

// validPort : chiffres ASCII seulement (vide admis), valeur ≤ 65 535.
func validPort(port []byte) bool {
	value := 0
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
		value = value*10 + int(c-'0')
		if value > 65_535 {
			return false
		}
	}
	return true
}

// isForbiddenHostCodePoint : « forbidden host code point » de la norme.
func isForbiddenHostCodePoint(r rune) bool {
	switch r {
	case 0, '\t', '\n', '\r', ' ', '#', '/', ':', '<', '>', '?', '@', '[', '\\', ']', '^', '|':
		return true
	}
	return false
}

// validHost suit « host parser » : IPv6 entre crochets ; hôte opaque (non spécial) ; domaine (spécial) décodé en
// pourcentage, mis en ASCII, sans « forbidden domain code point », et IPv4 s'il finit par un nombre.
func validHost(host []byte, special bool) bool {
	if len(host) > 0 && host[0] == '[' {
		if host[len(host)-1] != ']' || len(host) < 2 {
			return false
		}
		return validIPv6(host[1 : len(host)-1])
	}
	if !special {
		for i := 0; i < len(host); {
			r, width := utf8.DecodeRune(host[i:])
			if isForbiddenHostCodePoint(r) {
				return false
			}
			i += width
		}
		return true
	}
	domain := percentDecodeBytes(host)
	ascii, status := domainToASCII(domain)
	switch status {
	case domainFailure:
		return false
	case domainUnknown:
		// UTS 46 non porté : tenu pour valide (fail-closed : constat possible).
		return true
	}
	if ascii == "" {
		return false
	}
	for i := 0; i < len(ascii); i++ {
		c := ascii[i]
		if isForbiddenHostCodePoint(rune(c)) || c <= 0x1F || c == '%' || c == 0x7F {
			return false
		}
	}
	if endsInANumber(ascii) {
		return validIPv4(ascii)
	}
	return true
}

// percentDecodeBytes suit « percent-decode » de la norme : « %HH » devient l'octet, tout autre octet est gardé.
func percentDecodeBytes(input []byte) []byte {
	out := make([]byte, 0, len(input))
	for i := 0; i < len(input); i++ {
		if input[i] == '%' && i+2 < len(input) && isHex(input[i+1]) && isHex(input[i+2]) {
			out = append(out, hexValue(input[i+1])<<4|hexValue(input[i+2]))
			i += 2
			continue
		}
		out = append(out, input[i])
	}
	return out
}

// domainStatus : issue de domainToASCII.
type domainStatus int

const (
	domainASCII domainStatus = iota
	domainFailure
	domainUnknown
)

// domainToASCII suit « domain to ASCII » (beStrict faux) : un domaine ASCII sans étiquette « xn-- » est mis en
// minuscules ASCII. Un domaine qui contient U+FFFD (après « UTF-8 decode without BOM », un octet invalide vaut
// U+FFFD) échoue : U+FFFD est interdit par UTS 46. Tout autre domaine : issue inconnue (domainUnknown).
func domainToASCII(domain []byte) (string, domainStatus) {
	ascii := true
	for i := 0; i < len(domain); {
		r, width := utf8.DecodeRune(domain[i:])
		if r == utf8.RuneError {
			return "", domainFailure
		}
		if r >= 0x80 {
			ascii = false
		}
		i += width
	}
	if !ascii {
		return "", domainUnknown
	}
	lower := strings.ToLower(string(domain))
	for _, label := range strings.Split(lower, ".") {
		if strings.HasPrefix(label, "xn--") {
			return "", domainUnknown
		}
	}
	return lower, domainASCII
}

// endsInANumber suit « ends in a number checker ».
func endsInANumber(domain string) bool {
	parts := strings.Split(domain, ".")
	if parts[len(parts)-1] == "" {
		if len(parts) == 1 {
			return false
		}
		parts = parts[:len(parts)-1]
	}
	last := parts[len(parts)-1]
	if last != "" && strings.Trim(last, "0123456789") == "" {
		return true
	}
	_, ok := ipv4Number(last)
	return ok
}

// ipv4Number suit « IPv4 number parser » ; la valeur est saturée au-delà de 2^32 (seules les comparaisons à 255 et à
// 256^n comptent).
func ipv4Number(input string) (uint64, bool) {
	if input == "" {
		return 0, false
	}
	radix := uint64(10)
	switch {
	case len(input) >= 2 && (input[:2] == "0x" || input[:2] == "0X"):
		input, radix = input[2:], 16
	case len(input) >= 2 && input[0] == '0':
		input, radix = input[1:], 8
	}
	value := uint64(0)
	for i := 0; i < len(input); i++ {
		c := input[i]
		var digit uint64
		switch {
		case '0' <= c && c <= '9':
			digit = uint64(c - '0')
		case radix == 16 && 'a' <= c && c <= 'f':
			digit = uint64(c-'a') + 10
		case radix == 16 && 'A' <= c && c <= 'F':
			digit = uint64(c-'A') + 10
		default:
			return 0, false
		}
		if digit >= radix {
			return 0, false
		}
		value = min(value*radix+digit, 1<<40)
	}
	return value, true
}

// validIPv4 suit « IPv4 parser » (échec seulement : au plus quatre nombres, chacun valide, aucun sauf le dernier au-delà
// de 255, le dernier sous 256^(5 − n)).
func validIPv4(domain string) bool {
	parts := strings.Split(domain, ".")
	if parts[len(parts)-1] == "" && len(parts) > 1 {
		parts = parts[:len(parts)-1]
	}
	if len(parts) > 4 {
		return false
	}
	numbers := make([]uint64, 0, len(parts))
	for _, part := range parts {
		n, ok := ipv4Number(part)
		if !ok {
			return false
		}
		numbers = append(numbers, n)
	}
	for _, n := range numbers[:len(numbers)-1] {
		if n > 255 {
			return false
		}
	}
	limit := uint64(1) << (8 * (5 - len(numbers)))
	return numbers[len(numbers)-1] < limit
}

// validIPv6 suit « IPv6 parser » (échec seulement).
func validIPv6(input []byte) bool {
	pieceIndex, compress := 0, -1
	i := 0
	at := func(k int) int {
		if k < len(input) {
			return int(input[k])
		}
		return -1
	}
	if at(i) == ':' {
		if at(i+1) != ':' {
			return false
		}
		i += 2
		pieceIndex++
		compress = pieceIndex
	}
	for at(i) != -1 {
		if pieceIndex == 8 {
			return false
		}
		if at(i) == ':' {
			if compress != -1 {
				return false
			}
			i++
			pieceIndex++
			compress = pieceIndex
			continue
		}
		length := 0
		for length < 4 && at(i) != -1 && isHex(byte(at(i))) {
			i++
			length++
		}
		if at(i) == '.' {
			if length == 0 {
				return false
			}
			i -= length
			if pieceIndex > 6 {
				return false
			}
			numbersSeen := 0
			for at(i) != -1 {
				value := -1
				if numbersSeen > 0 {
					if at(i) == '.' && numbersSeen < 4 {
						i++
					} else {
						return false
					}
				}
				if at(i) == -1 || at(i) < '0' || at(i) > '9' {
					return false
				}
				for at(i) >= '0' && at(i) <= '9' {
					digit := at(i) - '0'
					switch value {
					case -1:
						value = digit
					case 0:
						return false
					default:
						value = value*10 + digit
					}
					if value > 255 {
						return false
					}
					i++
				}
				numbersSeen++
				if numbersSeen == 2 || numbersSeen == 4 {
					pieceIndex++
				}
			}
			if numbersSeen != 4 {
				return false
			}
			break
		} else if at(i) == ':' {
			i++
			if at(i) == -1 {
				return false
			}
		} else if at(i) != -1 {
			return false
		}
		pieceIndex++
	}
	if compress != -1 {
		return true
	}
	return pieceIndex == 8
}

// decodeURIComponent suit decodeURIComponent de JavaScript : chaque « %HH » est un octet, une séquence UTF-8
// incomplète, invalide ou de substitut fait échouer (URIError : faux).
func decodeURIComponent(value string) (string, bool) {
	if strings.IndexByte(value, '%') < 0 {
		return value, true
	}
	var b strings.Builder
	for i := 0; i < len(value); {
		if value[i] != '%' {
			b.WriteByte(value[i])
			i++
			continue
		}
		first, ok := hexByteAt(value, i)
		if !ok {
			return "", false
		}
		i += 3
		if first < 0x80 {
			b.WriteByte(first)
			continue
		}
		n := 0
		switch {
		case first&0xE0 == 0xC0:
			n = 2
		case first&0xF0 == 0xE0:
			n = 3
		case first&0xF8 == 0xF0:
			n = 4
		default:
			return "", false
		}
		sequence := []byte{first}
		for k := 1; k < n; k++ {
			next, ok := hexByteAt(value, i)
			if !ok || next&0xC0 != 0x80 {
				return "", false
			}
			sequence = append(sequence, next)
			i += 3
		}
		// Forme trop longue, substitut ou au-delà de U+10FFFF : DecodeRune rend une largeur de 1 (URIError).
		if _, width := utf8.DecodeRune(sequence); width != n {
			return "", false
		}
		b.Write(sequence)
	}
	return b.String(), true
}

func hexByteAt(value string, i int) (byte, bool) {
	if i+2 >= len(value) || value[i] != '%' || !isHex(value[i+1]) || !isHex(value[i+2]) {
		return 0, false
	}
	return hexValue(value[i+1])<<4 | hexValue(value[i+2]), true
}
