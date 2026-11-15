// SPDX-License-Identifier: Apache-2.0

// Règle composée AWS : un identifiant de clé d'accès et sa clé secrète dans la même fenêtre (v0.10.0).
//
// Famille propre à ce module, sans origine dans Secret Guard. Le moteur d'origine lit l'identifiant (AKIA…) comme un
// constat moyen (aws_access_key_id) et la clé secrète, qui n'a pas de préfixe, seulement si un nom de variable
// l'annonce ; écrites côte à côte sans nom (le fichier de clés téléchargé depuis la console, deux colonnes d'un
// tableur), elles ne donnaient que deux constats moyens. Ici, un identifiant AKIA ou ASIA et une valeur de 40
// caractères de base64 à 200 octets au plus l'un de l'autre, dans un ordre ou l'autre, forment un seul constat de la
// règle aws_access_key_pair, de l'un à l'autre : la déduplication des chevauchements (scan.go) y absorbe le constat
// de l'identifiant et celui de l'entropie. L'identifiant seul reste un constat de aws_access_key_id.
//
// L'idée d'un secret en plusieurs parties cherché dans une fenêtre vient de TruffleHog (AGPL-3.0) : aucune ligne n'en
// est reprise, ni motif, ni seuil, ni fenêtre (UPSTREAM.md). Le Pack porte la règle comme une règle « motif seul » dont le
// motif décrit la forme « identifiant, puis valeur » ; le moteur exécute cette famille à sa place pour toute règle du
// Pack qui porte cet identifiant, et ne garde du motif que sa porte littérale.
//
// Linéaire en la taille de la vue : une lecture pour les valeurs candidates, puis un parcours conjoint des
// identifiants et des candidates, tous deux en ordre croissant.

package detect

import "regexp"

const (
	// ruleAWSKeyPair : identifiant de la règle composée dans le Pack.
	ruleAWSKeyPair = "aws_access_key_pair"
	// awsPairWindowBytes : écart maximal, en octets de la vue, entre l'identifiant et la valeur.
	awsPairWindowBytes = 200
	// awsSecretLength : longueur d'une clé d'accès secrète AWS.
	awsSecretLength = 40
	// reasonAWSKeyPair : raison du constat.
	reasonAWSKeyPair = "aws_key_id_with_secret_in_window"
)

// awsKeyIDPattern : identifiant d'une clé d'accès à laquelle répond une clé secrète (AKIA : clé durable ; ASIA : clé
// temporaire). Les autres préfixes de aws_access_key_id désignent des utilisateurs, des rôles ou des groupes.
var awsKeyIDPattern = regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z2-7]{16}\b`)

// isAWSSecretByte : caractère d'une clé secrète AWS (alphabet du base64).
func isAWSSecretByte(c byte) bool {
	return isDigit(c) || isUpperLetter(c) || (c >= 'a' && c <= 'z') || c == '+' || c == '/'
}

// awsSecretShape dit si une suite de 40 caractères a la forme d'une clé secrète : au moins une minuscule, une
// majuscule et un chiffre, et pas seulement des chiffres hexadécimaux (empreinte SHA-1, identifiant de commit).
func awsSecretShape(run []byte) bool {
	lower, upper, digit, hexOnly := false, false, false, true
	for _, c := range run {
		switch {
		case isDigit(c):
			digit = true
		case c >= 'a' && c <= 'z':
			lower = true
			hexOnly = hexOnly && c <= 'f'
		case isUpperLetter(c):
			upper = true
			hexOnly = hexOnly && c <= 'F'
		default:
			hexOnly = false
		}
	}
	return lower && upper && digit && !hexOnly
}

// awsSecretCandidates rend, en ordre croissant, les étendues des suites maximales de caractères de base64 de text qui
// ont exactement 40 caractères et la forme d'une clé secrète.
func awsSecretCandidates(text []byte) [][2]int {
	var out [][2]int
	for i := 0; i < len(text); {
		if !isAWSSecretByte(text[i]) {
			i++
			continue
		}
		j := i
		for j < len(text) && isAWSSecretByte(text[j]) {
			j++
		}
		if j-i == awsSecretLength && awsSecretShape(text[i:j]) {
			out = append(out, [2]int{i, j})
		}
		i = j
	}
	return out
}

// scanAWSKeyPair exécute la règle composée r sur la vue : pour chaque identifiant, la valeur candidate la plus proche
// qui le suit dans la fenêtre, sinon la plus proche qui le précède ; un constat de l'un à l'autre. Identifiant ou
// valeur fictifs ou d'exemple public (safeLiteral) : aucun constat. Même signature que scanFixedPattern ; aucun
// budget n'est débité.
func scanAWSKeyPair(v *view, r *rule, _ *decodeBudget, findings []finding) ([]finding, error) {
	text := v.text
	if !r.gate.admits(text) {
		return findings, nil
	}
	ids := awsKeyIDPattern.FindAllIndex(text, -1)
	if len(ids) == 0 {
		return findings, nil
	}
	secrets := awsSecretCandidates(text)
	next := 0 // première candidate qui commence à la fin de l'identifiant ou après
	for _, id := range ids {
		for next < len(secrets) && secrets[next][0] < id[1] {
			next++
		}
		var partner [2]int
		found := false
		if next < len(secrets) && secrets[next][0]-id[1] <= awsPairWindowBytes {
			partner, found = secrets[next], true
		} else {
			// La candidate qui précède ; une candidate qui contient l'identifiant (au plus une) n'en est pas une.
			for k := next - 1; k >= 0 && k >= next-2 && !found; k-- {
				if secrets[k][1] <= id[0] {
					partner, found = secrets[k], id[0]-secrets[k][1] <= awsPairWindowBytes
					break
				}
			}
		}
		if !found || safeLiteral(text[id[0]:id[1]]) || safeLiteral(text[partner[0]:partner[1]]) {
			continue
		}
		start, end := min(id[0], partner[0]), max(id[1], partner[1])
		reasons := append(encodingReasons(v.encoding), reasonAWSKeyPair)
		findings = append(findings, newFinding(v, r, start, end, r.score-encodingPenalty(v.encoding), reasons))
	}
	return findings, nil
}

// fixedScanOf rend la fonction qui exécute une règle « motif seul » : scanJWT pour jwt, scanAWSKeyPair pour la règle
// composée AWS, scanFixedPattern sinon.
func fixedScanOf(r *rule) func(*view, *rule, *decodeBudget, []finding) ([]finding, error) {
	switch r.id {
	case ruleJWT:
		return scanJWT
	case ruleAWSKeyPair:
		return scanAWSKeyPair
	}
	return scanFixedPattern
}
