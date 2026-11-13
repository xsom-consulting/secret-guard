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
// dossier, nombre) ou un mot hexadécimal court (isShortHexWord), et dont un au moins est un mot de nom d'au moins
// 4 lettres. Une valeur faite seulement de chiffres hexadécimaux n'en est jamais un : elle garde le seuil de
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
