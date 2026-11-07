// Candidats base64 qui sont des noms : identifiants et chemins, jamais décodés.
//
// Écart avec Secret Guard (UPSTREAM.md) : la suite de caractères de BASE64_CANDIDATE prend tout mot de 20 caractères
// de l'alphabet base64, donc les identifiants de code (« AdminLogEntryViewActorKind », « refuse_append_only_change »)
// et les chemins. Chacun était décodé et débité du budget de l'analyse (maxDecodeAttempts) : relevé sur un Poste réel
// (xSOM Fleet, novembre 2026), 48 fichiers ordinaires sur 3 849 d'un dépôt, dont son CLAUDE.md et ses types générés,
// donnaient une analyse incomplète, donc un blocage. Le moteur ne décode plus un candidat qui a la forme d'un nom :
// son décodage n'est presque jamais du texte, et l'encodage base64 d'un texte n'a presque jamais cette forme.

package detect

import "bytes"

// isRedactLabelAt dit si le candidat qui commence à start est le nom d'un libellé de masquage (« <REDACTED_règle> ») :
// il reste décodé et débité comme dans l'origine, ce qui garde la parité du masquage (un texte masqué de nombreux
// libellés donne, comme l'origine, une nouvelle analyse incomplète).
func isRedactLabelAt(text []byte, start int) bool {
	return start > 0 && text[start-1] == '<' && bytes.HasPrefix(text[start:], []byte(redactLabelOpen[1:]))
}

// isNameCandidate dit si value, candidat base64, a la forme d'un nom : une empreinte hexadécimale (isHexCandidate),
// ou, sans « + » ni « = », une suite de mots séparés par « / », « - » ou « _ » qui sont chacun un mot de nom
// (isNameToken), dont un au moins de 4 lettres.
func isNameCandidate(value string) bool {
	if isHexCandidate(value) {
		return true
	}
	long := false
	start := 0
	for i := 0; i <= len(value); i++ {
		if i < len(value) {
			c := value[i]
			if c == '+' || c == '=' {
				return false
			}
			if c != '/' && c != '-' && c != '_' {
				continue
			}
		}
		if i > start {
			word := []byte(value[start:i])
			letters, ok := nameTokenLetters(word)
			if !ok {
				return false
			}
			long = long || letters >= 4
		}
		start = i + 1
	}
	return long
}

// isHexCandidate dit si value n'est fait que de chiffres hexadécimaux d'une même casse, dont un chiffre décimal au
// moins : une empreinte (SHA-256 d'un manifeste, identifiant de commit), dont le décodage base64 n'est jamais du
// texte ; l'encodage base64 d'octets n'a cette forme qu'avec une probabilité de l'ordre de 10⁻¹² pour 20 caractères.
func isHexCandidate(value string) bool {
	var lower, upper, digit bool
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'a' && c <= 'f':
			lower = true
		case c >= 'A' && c <= 'F':
			upper = true
		default:
			return false
		}
	}
	return digit && (!lower || !upper)
}

// nameDigitsMax : chiffres au plus d'un mot fait de chiffres (« 2026 ») ou à la fin d'un mot (« arm64 »).
const nameDigitsMax = 8

// nameTokenLetters dit si word est un mot de nom et rend son nombre de lettres. Un mot de nom est fait de chiffres
// seuls (« 2026 »), ou de lettres suivies d'au plus quatre chiffres, les lettres étant en minuscules (« refuse »,
// « arm64 »), avec une majuscule initiale suivie de deux minuscules au moins (« Documents »), en majuscules (« DEV »),
// ou en casse de chameau (isCamelLetters). Une suite aléatoire en base64 mêle chiffres, majuscules et minuscules sans
// cette régularité (TestNameCandidateRarelyMatchesBase64).
func nameTokenLetters(word []byte) (int, bool) {
	n := len(word)
	for n > 0 && word[n-1] >= '0' && word[n-1] <= '9' {
		n--
	}
	if n == 0 {
		return 0, len(word) <= nameDigitsMax
	}
	if len(word)-n > 4 {
		return 0, false
	}
	body := word[:n]
	var upper, lower int
	groups := 0
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case isUpper(c):
			upper++
		case isLower(c):
			lower++
		default:
			// Un ou deux chiffres entre une lettre et une majuscule (« DossierV1Piece », « Piece1Applied ») : lus
			// comme la lettre qui les précède, deux fois au plus par mot.
			end := i
			for end < len(body) && end-i < 2 && body[end] >= '0' && body[end] <= '9' {
				end++
			}
			// La lettre d'avant ferme une bosse (deux lettres de casse attendue avant elle) et une bosse s'ouvre
			// après (majuscule puis minuscule).
			if groups == 2 || i < 3 || end+1 >= len(body) || !isUpper(body[end]) || !isLower(body[end+1]) {
				return 0, false
			}
			if p := body[i-1]; isUpper(p) && !isLower(body[i-2]) || isLower(p) && (!isLower(body[i-2]) || !isLower(body[i-3])) {
				return 0, false
			}
			groups++
			if groups == 1 {
				body = append([]byte(nil), body...)
			}
			previous := body[i-1]
			for k := i; k < end; k++ {
				body[k] = previous
			}
			if isUpper(previous) {
				upper += end - i
			} else {
				lower += end - i
			}
			i = end - 1
		}
	}
	switch {
	case upper == 0:
		return n, n >= 2
	case lower == 0:
		return n, n >= 2
	case upper == 1 && isUpper(body[0]):
		return n, lower >= 2
	}
	return n, isCamelLetters(body)
}

// isCamelLetters dit si body, fait de lettres, est en casse de chameau : des minuscules en tête facultatives
// (« admin »), puis des bosses faites d'une majuscule suivie de deux minuscules au moins (« LogEntry ») ; la première
// bosse peut n'avoir qu'une minuscule (« SiInventory ») ; au plus un sigle de 2 à 5 majuscules (« HTTPSClient »,
// « SessionID »), ou une majuscule suivie d'un ou deux chiffres (« DossierV1Piece ») à la place du sigle.
func isCamelLetters(body []byte) bool {
	i := 0
	for i < len(body) && isLower(body[i]) {
		i++
	}
	leading := i > 0
	acronym := false
	first := true
	for i < len(body) {
		if !isUpper(body[i]) {
			return false
		}
		j := i
		for j < len(body) && isUpper(body[j]) {
			j++
		}
		if j-i > 1 {
			// Sigle : ses majuscules sauf la dernière si une minuscule suit (« HTTPSClient »).
			if j < len(body) {
				j--
			}
			if acronym || j-i < 2 || j-i > 5 {
				return false
			}
			acronym = true
			i = j
			first = false
			continue
		}
		k := j
		for k < len(body) && isLower(body[k]) {
			k++
		}
		lowers := k - j
		if lowers < 2 && (lowers != 1 || !first || leading) {
			return false
		}
		i = k
		first = false
	}
	return true
}

func isLower(c byte) bool { return c >= 'a' && c <= 'z' }
func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
