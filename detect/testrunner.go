// SPDX-License-Identifier: Apache-2.0

// Marque de résultat d'un lanceur de tests (écart d'analyse ajouté en v0.13.0, absent de Secret Guard ; UPSTREAM.md).
//
// La sortie de go test écrit, pour chaque test, une ligne faite de « --- », du résultat en majuscules (PASS, FAIL ou
// SKIP), de « : », du nom du test et de sa durée entre parenthèses ; un sous-test est décalé par des espaces. Lue par
// ASSIGNMENT, la ligne du résultat PASS devient l'affectation d'un mot de passe dont la valeur est le nom du test :
// relevé sur un Poste réel (xSOM Fleet, 27 novembre 2026), où chaque nom de test réussi était masqué. La forme est
// jugée en entier, sur sa ligne : un nom sensible en minuscules, un séparateur « = », une valeur entre guillemets, un
// texte après la durée ou une ligne sans « --- » restent des affectations.

package detect

// testRunnerResults : résultats qu'écrit un lanceur de tests, en majuscules.
var testRunnerResults = map[string]bool{"PASS": true, "FAIL": true, "SKIP": true}

// isTestRunnerResult dit si le nom text[keyStart:keyEnd], lu par une affectation ou comme indice d'une phrase, est la
// marque de résultat d'un lanceur de tests : de son début de ligne, des espaces ou tabulations, « --- », le résultat,
// « : », une espace, un nom de test (sous-tests après « / », un seul mot), une espace, une durée entre parenthèses,
// puis rien que des espaces ou tabulations jusqu'à la fin de la ligne. Ne lit que la ligne du nom, et seulement ce que
// la forme admet.
func isTestRunnerResult(text []byte, keyStart, keyEnd int) bool {
	if !testRunnerResults[string(text[keyStart:keyEnd])] {
		return false
	}
	const marker = "--- "
	if keyStart < len(marker) || string(text[keyStart-len(marker):keyStart]) != marker {
		return false
	}
	before := keyStart - len(marker) - 1
	for before >= 0 && (text[before] == ' ' || text[before] == '\t') {
		before--
	}
	if before >= 0 && !isLineEndByte(text[before]) {
		return false
	}
	i := keyEnd
	if i+1 >= len(text) || text[i] != ':' || text[i+1] != ' ' {
		return false
	}
	i = testName(text, i+2)
	if i < 0 || i+1 >= len(text) || text[i] != ' ' || text[i+1] != '(' {
		return false
	}
	i = testDuration(text, i+2)
	if i < 0 {
		return false
	}
	for i < len(text) && (text[i] == ' ' || text[i] == '\t') {
		i++
	}
	return i == len(text) || isLineEndByte(text[i])
}

func isLineEndByte(c byte) bool { return c == '\n' || c == '\r' }

// testName rend la position qui suit le nom de test lu à partir de i, ou -1 : un identifiant (une lettre ou « _ », puis
// lettres, chiffres et « _ »), puis, pour un sous-test, « / » et tout signe autre qu'un blanc jusqu'au premier blanc.
// go test remplace les espaces d'un nom de sous-test par « _ » : le nom est un seul mot, qui peut porter « / », « : »,
// « , », « - » et des parenthèses.
func testName(text []byte, i int) int {
	end := len(text)
	if i >= end || (!isASCIILetter(text[i]) && text[i] != '_') {
		return -1
	}
	for i < end && (isASCIIAlphanumeric(text[i]) || text[i] == '_') {
		i++
	}
	if i < end && text[i] == '/' {
		start := i + 1
		for i < end && text[i] != ' ' && text[i] != '\t' && !isLineEndByte(text[i]) {
			i++
		}
		if i == start {
			return -1
		}
	}
	return i
}

// testDuration rend la position qui suit la durée « 0.20s) » lue à partir de i (chiffres, partie décimale facultative,
// « s », parenthèse fermante), ou -1.
func testDuration(text []byte, i int) int {
	end := len(text)
	start := i
	for i < end && '0' <= text[i] && text[i] <= '9' {
		i++
	}
	if i == start {
		return -1
	}
	if i < end && text[i] == '.' {
		i++
		decimals := i
		for i < end && '0' <= text[i] && text[i] <= '9' {
			i++
		}
		if i == decimals {
			return -1
		}
	}
	if i+1 >= end || text[i] != 's' || text[i+1] != ')' {
		return -1
	}
	return i + 2
}
