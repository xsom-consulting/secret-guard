// SPDX-License-Identifier: Apache-2.0

// Noms écartés de l'entropie : faux positifs relevés sur un Poste réel (xSOM Fleet, 11 novembre 2026), mesurés par
// l'agent « Bruit » sur un dépôt de 4 164 fichiers (2 008 constats d'entropie, dont 1 506 sur des identifiants de types
// générés en casse de chameau).
//
// Écart avec Secret Guard (UPSTREAM.md) : la suite de caractères de scanEntropy prend tout mot de 20 caractères de
// l'alphabet base64, donc un identifiant de code (« SubscriptionOverviewLinesElemVerificationsElem »), le nom d'un
// fichier de licence (« LICENSE-PolyForm-… »), un chemin dont un dossier porte un identifiant hexadécimal court
// (« worktrees/agent-a1b2c3… ») et l'identifiant public d'un objet d'un Fournisseur (« apikey_01… »). Le moteur les
// écarte : moins de constats d'entropie, jamais moins de constats d'une règle ancrée.
//
// Seconde mesure (15 novembre 2026, tools/bruit, même dépôt à 4 614 fichiers) : 868 constats d'entropie, dont 486 sur
// des identifiants en casse de chameau que la première forme laissait passer. Cause : nameTokenLetters n'admet une
// bosse d'une seule minuscule (« Ai », « Id », « Is ») qu'en tête de mot, un seul sigle par mot, et des chiffres
// seulement entre deux bosses ou à la fin ; hasAcronymHump écarte ensuite tout mot qui porte un sigle. Un nom de type
// généré depuis un schéma (« …ElemAiService… », « …CurrencyEUR », « …AlgEd25519 », « …BucketA2K ») ou un nom d'essai
// (« TestFR16… ») porte presque toujours l'un de ces morceaux. isGeneratedIdentifier les admet dans un identifiant
// long, sans rien changer aux mots courts.

package detect

import (
	"bytes"
	"regexp"
)

// entropyHexWordMax : longueur la plus grande d'un mot hexadécimal admis dans un nom (96 bits). Un identifiant de
// dossier (« a1b2c3d4e5f6 », 12 à 20 chiffres) est plus court qu'un secret hexadécimal (32 chiffres et plus), qui
// reste détecté.
const entropyHexWordMax = 24

// isEntropyName dit si value, candidat d'entropie, a la forme d'un nom : sans « + » ni « = », une suite de mots
// séparés par « / », « - » ou « _ », dont chacun est un mot de nom (nameTokenLetters : identifiant de code, mot de
// dossier, nombre), un identifiant généré long (isGeneratedIdentifier) ou un mot hexadécimal court (isShortHexWord),
// et dont un au moins est un mot de nom d'au moins 4 lettres ou un identifiant généré long. Une valeur faite seulement de chiffres hexadécimaux n'en est jamais un : elle garde le seuil de
// l'hexadécimal (hasStrongEntropy).
//
// Une suite aléatoire en base64 n'a presque jamais cette forme (TestEntropyNameRarelyMatchesTokens). Ce qu'elle fait
// perdre : l'avertissement d'entropie sur une phrase de passe écrite en casse de chameau (« Cheval… Agrafe… ») sans nom
// sensible devant elle ; ce constat était rare (l'entropie d'une phrase de mots dépasse rarement 4,3 bits), et le même
// texte affecté à un nom sensible reste détecté par la règle contextuelle.
func isEntropyName(value []byte) bool {
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
			word := value[start:i]
			if letters, ok := nameTokenLetters(word); ok && !hasAcronymHump(word) {
				long = long || letters >= 4 && hasNonHexLetter(word)
			} else if isGeneratedIdentifier(word) {
				long = true
			} else if !isShortHexWord(word) {
				return false
			}
		}
		start = i + 1
	}
	return long
}

// hasAcronymHump dit si word mêle un sigle (deux majuscules qui se suivent) et des minuscules (« VSCode »,
// « HTTPSClient ») : plus permissif que la casse de chameau simple, ce mot n'est pas admis pour l'entropie. Le corpus
// de l'origine garde un constat sur un chemin qui en porte un (« does not broadly exempt a path-shaped entropy
// candidate ») ; un mot tout en majuscules (« LICENSE ») reste admis.
func hasAcronymHump(word []byte) bool {
	lower, pair := false, false
	for i, c := range word {
		if isLower(c) {
			lower = true
		}
		if i > 0 && isUpper(c) && isUpper(word[i-1]) {
			pair = true
		}
	}
	return lower && pair
}

// Bornes d'un identifiant généré long (isGeneratedIdentifier).
const (
	// generatedMinWords : mots réguliers au moins.
	generatedMinWords = 4
	// generatedAcronymMax : majuscules au plus d'un sigle (« HTTPS »).
	generatedAcronymMax = 5
	// generatedDigitsMax : chiffres au plus d'une suite de chiffres (« Ed25519 », « Sha256 »).
	generatedDigitsMax = 5
)

// isGeneratedIdentifier dit si word est un identifiant généré long en casse de chameau : une suite de mots réguliers
// (une majuscule puis deux minuscules au moins : « Subscription », « Elem » ; ou trois minuscules au moins en tête)
// entre lesquels se glissent des morceaux irréguliers, que nameTokenLetters refuse ou que hasAcronymHump écarte :
//
//   - une bosse courte, une majuscule et une minuscule (« Ai », « Id », « Is », « Le »), ou deux minuscules en tête ;
//   - un sigle de 2 à 5 majuscules (« EUR », « FR », « HTTPS ») ;
//   - une majuscule seule (« A », « X ») ;
//   - une suite de 1 à 5 chiffres après une lettre (« FR16 », « Ed25519 », « Sha256 »), qui fait partie du morceau
//     irrégulier qu'elle suit, ou en est un à elle seule après un mot régulier ; une majuscule finale après elle
//     (« A2K », « Max20X ») est du même morceau.
//
// Il faut quatre mots réguliers au moins, et plus il y a de morceaux irréguliers ou plus les mots sont courts, plus il
// en faut :
//
//   - un morceau irrégulier au plus pour deux mots réguliers, de 6 lettres au moins en moyenne ;
//   - un pour trois, de 5 lettres en moyenne ;
//   - un pour trois, de 4,5 lettres en moyenne, avec sept mots réguliers au moins ;
//   - un pour trois, de 4 lettres en moyenne, avec huit mots réguliers au moins.
//
// C'est la forme des noms de types générés depuis un schéma (« …RequestItemsElemAiServiceMistralLeChat »,
// « …ElemCurrencyEUR », « …ElemAlgEd25519 ») et des noms d'essais (« TestFR16LoopbackListenerIsExclusive »), jamais
// celle d'un jeton : chacun de ses caractères devrait tomber dans la classe attendue, et ses « mots » feraient
// 3,7 lettres en moyenne. Mesure du 15 novembre 2026 sur 10 millions de suites alphanumériques aléatoires par
// longueur, comptées quand elles ont cette forme sans avoir déjà celle d'un nom (nameTokenLetters, entre
// parenthèses) : 20 caractères, 0 (1 439) ; 24, 146 (262) ; 28, 84 (34) ; 32, 16 (5) ; 36, 18 (0) ; 40, 7 (0) ;
// 48, 0 (0). TestEntropyNameRarelyMatchesTokens garde la borne : 1 pour 1 000 à 20 caractères, 1 pour 100 000 à 32,
// 1 pour un million à 48.
func isGeneratedIdentifier(word []byte) bool {
	regular, irregular, letters, ok := generatedWords(word)
	if !ok || regular < generatedMinWords {
		return false
	}
	if 2*irregular <= regular && letters >= 6*regular {
		return true
	}
	if 3*irregular > regular {
		return false
	}
	return letters >= 5*regular || regular >= 7 && 2*letters >= 9*regular || regular >= 8 && letters >= 4*regular
}

// generatedWords découpe word en mots réguliers et en morceaux irréguliers (isGeneratedIdentifier) : nombre de mots
// réguliers, nombre de morceaux irréguliers, lettres des mots réguliers. ok est faux si word n'a pas cette forme
// (caractère hors lettres et chiffres, minuscule isolée en tête, chiffre en tête, sigle de plus de 5 majuscules,
// suite de plus de 5 chiffres, deux suites de chiffres pour un même morceau).
func generatedWords(word []byte) (regular, irregular, letters int, ok bool) {
	n := len(word)
	i := 0
	for i < n && isLower(word[i]) {
		i++
	}
	switch {
	case i >= 3:
		regular++
		letters += i
	case i == 2:
		irregular++
	case i == 1 || n == 0 || !isUpper(word[0]):
		return 0, 0, 0, false
	}
	// afterRegular : le morceau qui précède est un mot régulier (une suite de chiffres est alors un morceau
	// irrégulier de plus) ; digits : il a déjà sa suite de chiffres.
	afterRegular, digits := i >= 3, false
	for i < n {
		if c := word[i]; c >= '0' && c <= '9' {
			j := i
			for j < n && word[j] >= '0' && word[j] <= '9' {
				j++
			}
			if digits || j-i > generatedDigitsMax {
				return 0, 0, 0, false
			}
			if afterRegular {
				irregular++
			}
			afterRegular, digits = false, true
			i = j
			continue
		}
		if !isUpper(word[i]) {
			return 0, 0, 0, false
		}
		j := i
		for j < n && isUpper(word[j]) {
			j++
		}
		k := j
		for k < n && isLower(word[k]) {
			k++
		}
		uppers, lowers := j-i, k-j
		switch {
		case uppers == 1 && lowers >= 2:
			regular++
			letters += 1 + lowers
			afterRegular, digits = true, false
			i = k
			continue
		case uppers == 1:
			// Bosse courte (« Ai ») ou majuscule seule (« A », devant un chiffre ou à la fin).
			i = k
			if lowers == 0 && digits && i == n {
				// Majuscule finale après des chiffres (« A2K », « Max20X ») : même morceau que les chiffres.
				continue
			}
		default:
			// Sigle : ses majuscules, sauf la dernière si une minuscule suit (elle ouvre le mot suivant).
			if lowers > 0 {
				uppers--
			}
			if uppers > generatedAcronymMax {
				return 0, 0, 0, false
			}
			i += uppers
		}
		irregular++
		afterRegular, digits = false, false
	}
	return regular, irregular, letters, true
}

// hasNonHexLetter dit si word porte une lettre qui n'est pas un chiffre hexadécimal (« agent », et non « deadbeef ») :
// une valeur hexadécimale coupée par des tirets n'est jamais un nom.
func hasNonHexLetter(word []byte) bool {
	for _, c := range word {
		if c >= 'g' && c <= 'z' || c >= 'G' && c <= 'Z' {
			return true
		}
	}
	return false
}

// isShortHexWord dit si word est un mot hexadécimal d'une même casse de entropyHexWordMax caractères au plus, avec un
// chiffre décimal au moins (« a439d0012d476115b », « d80f13b30bb3 ») : forme d'un identifiant court de dossier ou de
// commit abrégé.
func isShortHexWord(word []byte) bool {
	return len(word) <= entropyHexWordMax && isHexCandidate(string(word))
}

// providerObjectID : identifiant public d'un objet chez Anthropic (clé d'API, espace de travail, utilisateur, message,
// lot de messages), « <préfixe>_01 » suivi de 20 à 24 caractères alphanumériques. C'est le nom de l'objet que montrent
// la console et l'API d'administration, jamais la clé, qui a son propre préfixe (« sk-ant-… », règle anthropic_key).
// Même forme que reToolUseIdentifier de l'origine.
var providerObjectID = regexp.MustCompile(`^(?:apikey|wrkspc|user|msg|msgbatch)_01[A-Za-z0-9]{20,24}$`)

// isProviderObjectID dit si value est l'identifiant public d'un objet d'un Fournisseur (providerObjectID), précédé
// d'une frontière (début, ou caractère hors de la suite d'entropie) : jamais la fin d'une suite de plus de 512
// caractères coupée par le motif.
func isProviderObjectID(text []byte, start int, value []byte) bool {
	if start > 0 && (isASCIIAlphanumeric(text[start-1]) || bytes.IndexByte([]byte(entropyRunBytes), text[start-1]) >= 0) {
		return false
	}
	return providerObjectID.Match(value)
}

// entropyRunBytes : caractères de la suite d'entropie (motif de high_entropy) hors lettres et chiffres.
const entropyRunBytes = "+/_-="
