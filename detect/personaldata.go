// SPDX-License-Identifier: Apache-2.0

// Validateurs des données personnelles (v0.7.0) : IBAN, numéro de sécurité sociale français (NIR), SIRET, SIREN,
// numéro de carte bancaire.
//
// Extension propre à ce module, sans origine dans Secret Guard (avis dans UPSTREAM.md). Les règles correspondantes du
// Pack initial sont des règles « motif seul » : le motif RE2 délimite un candidat, le validateur nommé (liste fermée
// RULE_VALIDATORS) le juge par la clé de contrôle de son format (modulo 97 de l'ISO 13616, clé du NIR, Luhn…). Sans
// clé valide, le candidat n'est pas un constat : c'est ce qui écarte les numéros de téléphone, de commande ou de
// suivi de même longueur.
//
// Chaque validateur lit la valeur détectée (motif et séparateurs compris) et rend vrai ou faux ; aucun ne garde ni ne
// renvoie rien de la valeur, et aucun n'a d'effet de bord. Les tampons de la valeur appartiennent à l'analyse.

package detect

// Validateurs nommés des données personnelles (RULE_VALIDATORS du Pack).
const (
	validatorIBAN  = "iban_mod97"
	validatorNIR   = "fr_nir_key"
	validatorSiret = "fr_siret_luhn"
	validatorSiren = "fr_siren_luhn"
	validatorCard  = "payment_card_luhn"
)

// plainValidator adapte un contrôle sans décodage (donc sans budget) au type validator.
func plainValidator(check func(string) bool) validator {
	return func(value string, _ *decodeBudget) (bool, error) { return check(value), nil }
}

// compactDigits rend les chiffres de value et dit si value n'est faite que de chiffres et du séparateur admis (une
// espace, ou le tiret si dash est vrai) ; à séparateurs mêlés (espaces et tirets) : faux.
func compactDigits(value string, dash bool) (digits []byte, ok bool) {
	digits = make([]byte, 0, len(value))
	var separator byte
	for i := 0; i < len(value); i++ {
		switch c := value[i]; {
		case c >= '0' && c <= '9':
			digits = append(digits, c)
		case c == ' ' || (dash && c == '-'):
			if separator != 0 && separator != c {
				return nil, false
			}
			separator = c
		default:
			return nil, false
		}
	}
	return digits, true
}

// luhn dit si la suite de chiffres ASCII passe le contrôle de Luhn (ISO/IEC 7812-1).
func luhn(digits []byte) bool {
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return len(digits) > 0 && sum%10 == 0
}

// allSameDigit dit si tous les chiffres sont égaux (« 0000… », « 1111… ») : valeurs de remplissage qui passent parfois
// le contrôle sans désigner personne.
func allSameDigit(digits []byte) bool {
	for _, d := range digits {
		if d != digits[0] {
			return false
		}
	}
	return len(digits) > 0
}

// ibanLengths : longueur de l'IBAN par pays pour les pays d'Europe et du pourtour (registre ISO 13616) ; un pays hors de
// cette table n'a pas de longueur imposée (15 à 34 caractères, contrôle modulo 97).
var ibanLengths = map[string]int{
	"AD": 24, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BY": 28, "CH": 21, "CY": 28, "CZ": 24,
	"DE": 22, "DK": 18, "EE": 20, "ES": 24, "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18,
	"GR": 27, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IS": 26, "IT": 27, "LI": 21, "LT": 20, "LU": 20, "LV": 21,
	"MC": 27, "MD": 24, "ME": 22, "MK": 19, "MT": 31, "NL": 18, "NO": 15, "PL": 28, "PT": 25, "RO": 24, "RS": 22,
	"SE": 24, "SI": 19, "SK": 24, "SM": 27, "TR": 26, "UA": 29, "VA": 22, "XK": 20,
}

// isValidIBAN : IBAN (ISO 13616) écrit avec ou sans espaces, en majuscules ou en minuscules : deux lettres de pays,
// deux chiffres de contrôle (02 à 98), longueur du pays quand elle est connue (15 à 34 sinon), reste modulo 97 égal à
// 1 une fois les quatre premiers caractères passés à la fin et les lettres remplacées par 10 à 35.
func isValidIBAN(value string) bool {
	var compact [34]byte
	n := 0
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c == ' ':
			continue
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		case (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'):
		default:
			return false
		}
		if n == len(compact) {
			return false
		}
		compact[n] = c
		n++
	}
	if n < 15 {
		return false
	}
	iban := compact[:n]
	if !isUpperLetter(iban[0]) || !isUpperLetter(iban[1]) || !isDigit(iban[2]) || !isDigit(iban[3]) {
		return false
	}
	if check := int(iban[2]-'0')*10 + int(iban[3]-'0'); check < 2 || check > 98 {
		return false
	}
	if want, known := ibanLengths[string(iban[:2])]; known && want != n {
		return false
	}
	remainder := 0
	for i := range n {
		c := iban[(i+4)%n]
		if isDigit(c) {
			remainder = (remainder*10 + int(c-'0')) % 97
		} else {
			remainder = (remainder*100 + int(c-'A') + 10) % 97
		}
	}
	return remainder == 1
}

// trimmers : validateurs dont la règle peut raccourcir la correspondance du motif avant le contrôle (nom du validateur
// → fonction rendant la longueur retenue, 0 pour aucune). Le motif de l'IBAN est volontairement générique (2 à 7 groupes
// de quatre caractères) : il peut absorber le mot de quatre caractères qui suit l'IBAN (« … 1332 pour »).
var trimmers = map[string]func(value []byte) int{
	validatorIBAN: ibanPrefixLength,
}

// ibanPrefixLength rend la longueur du plus long préfixe de value, fini à une fin de groupe (fin d'un mot, ou multiple
// de quatre caractères alphanumériques), qui est un IBAN valide ; 0 s'il n'y en a aucun.
func ibanPrefixLength(value []byte) int {
	var ends [16]int
	count, alphanumeric := 0, 0
	for i, c := range value {
		if c == ' ' {
			continue
		}
		alphanumeric++
		if (i+1 == len(value) || value[i+1] == ' ' || alphanumeric%4 == 0) && count < len(ends) {
			ends[count] = i + 1
			count++
		}
	}
	for i := count - 1; i >= 0; i-- {
		if isValidIBAN(string(value[:ends[i]])) {
			return ends[i]
		}
	}
	return 0
}

func isDigit(c byte) bool       { return c >= '0' && c <= '9' }
func isUpperLetter(c byte) bool { return c >= 'A' && c <= 'Z' }

// isValidNIR : numéro de sécurité sociale français (NIR) : 13 caractères (sexe, année, mois, département ou « 2A » /
// « 2B », commune, numéro d'ordre) puis une clé de deux chiffres égale à 97 − (nombre mod 97). Pour la Corse, « 2A »
// compte pour 19 et « 2B » pour 18 dans le calcul (règle de l'INSEE). Département, commune et numéro d'ordre ne sont
// jamais nuls. Espaces admis entre les éléments.
func isValidNIR(value string) bool {
	var compact [15]byte
	n := 0
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == ' ' {
			continue
		}
		if n == len(compact) {
			return false
		}
		compact[n] = c
		n++
	}
	if n != len(compact) {
		return false
	}
	body := compact[:13]
	department := string(body[5:7])
	number := make([]byte, 0, 13)
	number = append(number, body[:5]...)
	switch department {
	case "2A", "2a":
		number = append(number, '1', '9')
	case "2B", "2b":
		number = append(number, '1', '8')
	default:
		number = append(number, body[5:7]...)
	}
	number = append(number, body[7:]...)
	var total int64
	for _, c := range number {
		if !isDigit(c) {
			return false
		}
		total = total*10 + int64(c-'0')
	}
	if !isDigit(compact[13]) || !isDigit(compact[14]) {
		return false
	}
	if department == "00" || string(body[7:10]) == "000" || string(body[10:13]) == "000" {
		return false
	}
	return 97-total%97 == int64(compact[13]-'0')*10+int64(compact[14]-'0')
}

// isValidSiret : SIRET (14 chiffres, Luhn). Exception de La Poste (SIREN 356000000) : les SIRET de ses établissements
// ne passent pas Luhn, la somme de leurs chiffres est un multiple de 5. Un candidat compact qui se lit comme une date et
// une heure AAAAMMJJHHMMSS (journaux, horodatages) n'est pas un SIRET. Espaces admis.
func isValidSiret(value string) bool {
	digits, ok := compactDigits(value, false)
	if !ok || len(digits) != 14 || allSameDigit(digits) {
		return false
	}
	if looksLikeTimestamp(digits) {
		return false
	}
	if string(digits[:9]) == "356000000" {
		sum := 0
		for _, d := range digits {
			sum += int(d - '0')
		}
		return sum%5 == 0
	}
	return luhn(digits)
}

// looksLikeTimestamp : quatorze chiffres AAAAMMJJHHMMSS (années 1900 à 2099, mois, jour, heure, minute et seconde
// possibles).
func looksLikeTimestamp(digits []byte) bool {
	pair := func(i int) int { return int(digits[i]-'0')*10 + int(digits[i+1]-'0') }
	century := pair(0)
	month, day, hour, minute, second := pair(4), pair(6), pair(8), pair(10), pair(12)
	return (century == 19 || century == 20) && month >= 1 && month <= 12 && day >= 1 && day <= 31 &&
		hour <= 23 && minute <= 59 && second <= 59
}

// isValidSiren : SIREN (9 chiffres, Luhn), espaces admis.
func isValidSiren(value string) bool {
	digits, ok := compactDigits(value, false)
	return ok && len(digits) == 9 && !allSameDigit(digits) && luhn(digits)
}

// isValidPaymentCard : numéro de carte bancaire de 13 à 19 chiffres, écrit d'un bloc ou groupé par une espace ou un
// tiret (un seul des deux), contrôle de Luhn, puis préfixe et longueur d'un réseau courant (cardNetwork).
func isValidPaymentCard(value string) bool {
	digits, ok := compactDigits(value, true)
	if !ok || len(digits) < 13 || len(digits) > 19 || allSameDigit(digits) {
		return false
	}
	return luhn(digits) && cardNetwork(digits)
}

// cardNetwork : préfixe et longueur d'un réseau de cartes (Visa, Mastercard, American Express, Discover, Diners Club,
// JCB, UnionPay, Maestro). Les Visa de 13 chiffres, retirés, sont écartés : leur forme est celle des codes-barres EAN-13.
func cardNetwork(d []byte) bool {
	n := len(d)
	prefix := func(length int) int {
		value := 0
		for _, c := range d[:length] {
			value = value*10 + int(c-'0')
		}
		return value
	}
	p2, p3, p4 := prefix(2), prefix(3), prefix(4)
	switch {
	case d[0] == '4':
		return n == 16 || n == 19
	case p2 >= 51 && p2 <= 55, p4 >= 2221 && p4 <= 2720:
		return n == 16
	case p2 == 34, p2 == 37:
		return n == 15
	case p4 == 6011, p3 >= 644 && p3 <= 649, p2 == 65:
		return n >= 16
	case p3 >= 300 && p3 <= 305, p4 == 3095, p2 == 36, p2 == 38, p2 == 39:
		return n >= 14
	case p4 >= 3528 && p4 <= 3589, p2 == 62:
		return n >= 16
	case p4 == 5018, p4 == 5020, p4 == 5038, p4 == 5893, p4 == 6304, p4 == 6759, p4 >= 6761 && p4 <= 6763:
		return true
	}
	return false
}
