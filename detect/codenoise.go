// SPDX-License-Identifier: Apache-2.0

// Valeurs d'affectation qui ne sont pas des littéraux (écart d'analyse ajouté en v0.10.0, absent de Secret Guard ;
// UPSTREAM.md, « Code ordinaire »).
//
// Après un nom sensible, l'origine tient pour la valeur d'un secret tout ce qui suit « : » ou « = », sauf une liste
// courte d'exceptions. Relevé sur des Postes réels (xSOM Fleet, novembre 2026) : une variable de shell suivie d'une
// autre option, une expression de CI, un tableau, un objet, un appel, un type, la ligne suivante d'un fichier YAML
// donnaient chacun un constat de score 70, donc un blocage. Ce fichier juge la forme de la valeur lue :
//
//   - palier 1, quel que soit le langage : la valeur est une référence (variable ou paramètre de shell, substitution
//     de commande, gabarit, chaîne à interpolation), une structure de code (tableau, objet, appel, type, fonction) ou
//     un texte sans guillemets lu à la ligne suivante. Elle n'est pas un constat. Une structure n'est pas écartée en
//     bloc : elle est parcourue, et un littéral qu'elle porte reste trouvé (walkStructure) ;
//   - palier 2, dans du code seulement : pour une clé d'API, un jeton ou un secret générique, une valeur dont aucun mot
//     n'a la forme d'un secret (secretShaped) n'est pas un constat.
//
// Garde-fous : jamais de filtre de structure ni de palier 2 dans un fichier dotenv ou sur une affectation nue
// d'environnement ; le défaut littéral d'une expansion de shell reste signalé ; un mot de passe n'est jamais jugé
// sur sa forme ; aucun marqueur de contournement n'est lu dans le texte. Travail borné par vue et par motif (spend) :
// budget épuisé, le filtre ne s'applique plus et le constat d'origine est gardé.

package detect

import (
	"bytes"
	"strings"
)

const (
	// structureWalkBytes : plus longue structure parcourue. Au-delà, elle n'est pas jugée : le constat d'origine reste.
	structureWalkBytes = 4_096
	// structureLiteralsMax : constats ajoutés au plus par structure parcourue.
	structureLiteralsMax = 16
	// referenceBytes : plus longue référence lue (« $(…) », « ${…} », gabarit) ; celle de isShellCommandSubstitution.
	referenceBytes = 512
)

// noiseVerdict est la décision de assignmentNoise sur une affectation à nom sensible que les filtres d'origine n'ont
// pas écartée.
type noiseVerdict struct {
	// drop : le constat d'origine n'est pas émis.
	drop bool
	// resume : position où reprend la recherche d'affectations (0 : là où l'origine reprend).
	resume int
	// literals : chaînes crédibles trouvées en parcourant une structure, après sa première ligne ; un constat chacune.
	literals [][2]int
}

var keepFinding = noiseVerdict{}

// resetNoiseBudget rend à la vue son budget de relecture, au début de chaque motif d'affectation : le même en analyse
// séquentielle (un contextualText pour tous les motifs) et en parallèle (un par motif).
func (ctx *contextualText) resetNoiseBudget() { ctx.noiseBudget = 8*len(ctx.text) + 1<<16 }

// spend débite n octets relus par les filtres de ce fichier ; faux quand le budget est épuisé.
func (ctx *contextualText) spend(n int) bool {
	if n > ctx.noiseBudget {
		ctx.noiseBudget = 0
		return false
	}
	ctx.noiseBudget -= n
	return true
}

func isIdentStart(c byte) bool { return c == '_' || c == '$' || isASCIILower(c) || isASCIIUpper(c) }
func isIdentByte(c byte) bool  { return isIdentStart(c) || isASCIIDigit(c) }

// identPathEnd rend la fin du chemin d'identifiants qui commence en i (« a », « a.b », « a?.b », « a::b », « a->b »),
// ou i s'il n'y en a pas.
func identPathEnd(text []byte, i int) int {
	end := i
	for i < len(text) && isIdentStart(text[i]) {
		for i < len(text) && isIdentByte(text[i]) {
			i++
		}
		end = i
		switch {
		case i+1 < len(text) && text[i] == '?' && text[i+1] == '.':
			i += 2
		case i < len(text) && text[i] == '.':
			i++
		case i+1 < len(text) && text[i] == ':' && text[i+1] == ':':
			i += 2
		case i+1 < len(text) && text[i] == '-' && text[i+1] == '>':
			i += 2
		default:
			return end
		}
	}
	return end
}

// valueClasses compte les classes de caractères de value : minuscules, majuscules, chiffres, autres. spaced : une
// espace de JavaScript y figure.
type valueClasses struct {
	lower, upper, other bool
	digits              int
	spaced              bool
}

func classesOf(value []byte) valueClasses {
	var c valueClasses
	for _, r := range string(value) {
		switch {
		case isJSWhitespace(r):
			c.spaced = true
		case 'a' <= r && r <= 'z':
			c.lower = true
		case 'A' <= r && r <= 'Z':
			c.upper = true
		case '0' <= r && r <= '9':
			c.digits++
		default:
			c.other = true
		}
	}
	return c
}

func (c valueClasses) count() int {
	n := 0
	for _, present := range []bool{c.lower, c.upper, c.digits > 0, c.other} {
		if present {
			n++
		}
	}
	return n
}

const (
	// shapeRunMin : plus courte suite de lettres et de chiffres tenue pour aléatoire quand elle n'est pas un mot de nom.
	shapeRunMin = 12
	// shapeWordMax : plus long mot d'une seule casse tenu pour un mot (les mots courants s'arrêtent à 15 lettres).
	shapeWordMax = 15
)

// secretShaped dit si v.text[start:end] a la forme d'un secret (seuil du palier 2, mesuré dans docs/bench.md) : au
// moins 8 unités UTF-16 sans espace, et l'une de ces formes :
//
//   - trois classes de caractères parmi minuscules, majuscules, chiffres et autres ;
//   - des lettres avec au moins deux chiffres, sur 10 unités ou plus ;
//   - une forte entropie (hasStrongEntropy) ;
//   - une suite de lettres et de chiffres d'au moins shapeRunMin caractères qui n'est pas un mot de nom
//     (nameTokenLetters : minuscules, majuscule initiale, majuscules, casse de chameau) : casse mêlée sans régularité,
//     chiffres au milieu ;
//   - une suite de lettres d'une seule casse de plus de shapeWordMax caractères.
//
// Ce qui n'a pas cette forme : un mot, un nom de variable ou de constante, un libellé, une valeur d'essai en mots
// (« test-key »). Perte acceptée, dans du code seulement : une suite aléatoire de moins de 12 caractères sans chiffre,
// ou de moins de 16 lettres d'une seule casse (TestSecretShapeThreshold).
func secretShaped(v *view, start, end int) bool {
	value := v.text[start:end]
	units := utf16Units(value)
	if units < 8 {
		return false
	}
	c := classesOf(value)
	if c.spaced {
		return false
	}
	if c.count() >= 3 || ((c.lower || c.upper) && c.digits >= 2 && units >= 10) || hasStrongEntropy(v, start, end) {
		return true
	}
	for i := 0; i < len(value); {
		if !isASCIIAlphanumeric(value[i]) {
			i++
			continue
		}
		runStart := i
		for i < len(value) && isASCIIAlphanumeric(value[i]) {
			i++
		}
		run := value[runStart:i]
		if len(run) < shapeRunMin {
			continue
		}
		if _, name := nameTokenLetters(run); !name || (len(run) > shapeWordMax && isSingleCaseWord(run)) {
			return true
		}
	}
	return false
}

// isSingleCaseWord dit si word n'est fait que de minuscules, ou que de majuscules.
func isSingleCaseWord(word []byte) bool {
	lower, upper := false, false
	for _, c := range word {
		switch {
		case isASCIILower(c):
			lower = true
		case isASCIIUpper(c):
			upper = true
		default:
			return false
		}
	}
	return lower != upper
}

// strictShaped : forme d'un secret pour un littéral porté par une structure (élément d'un tableau, valeur d'un objet,
// argument d'un appel, chaîne d'un gabarit), que rien ne relie au nom sensible : forte entropie, ou au moins 8 unités
// sans espace avec un chiffre et trois classes de caractères. Une adresse sans identifiants (« schéma://hôte/chemin »,
// ni « @ », ni « ? »), un nom de constante ou de variable d'environnement (« NOM_V2 ») et une date (« 2026-10-12 »,
// « 2026-10-12T10:00:00.000Z ») n'en sont pas.
func strictShaped(v *view, start, end int) bool {
	value := v.text[start:end]
	if utf16Units(value) < 8 {
		return false
	}
	c := classesOf(value)
	if c.spaced || isPlainLocator(value) || isConstantName(value) || isTimestamp(value) {
		return false
	}
	return hasStrongEntropy(v, start, end) || (c.digits > 0 && c.count() >= 3)
}

// isTimestamp dit si value est une date ISO 8601, avec ou sans heure : « AAAA-MM-JJ », puis « T » ou une espace,
// l'heure, et un décalage ou « Z ».
func isTimestamp(value []byte) bool {
	const date = "0000-00-00"
	if len(value) < len(date) {
		return false
	}
	for i := 0; i < len(date); i++ {
		if (date[i] == '0') != isASCIIDigit(value[i]) || (date[i] == '-' && value[i] != '-') {
			return false
		}
	}
	rest := value[len(date):]
	if len(rest) == 0 {
		return true
	}
	if rest[0] != 'T' || len(rest) < 6 {
		return false
	}
	for _, c := range rest[1:] {
		if !isASCIIDigit(c) && c != ':' && c != '.' && c != 'Z' && c != '+' && c != '-' {
			return false
		}
	}
	return true
}

// isConstantName dit si value est un nom en majuscules à mots séparés par « _ » (« E2E_PUBLISH_NAME », « DB_HOST_2 ») :
// une majuscule, puis majuscules et chiffres, avec au moins un « _ » entre deux mots.
func isConstantName(value []byte) bool {
	if len(value) == 0 || !isASCIIUpper(value[0]) {
		return false
	}
	separators := 0
	for i, c := range value {
		switch {
		case isASCIIUpper(c) || isASCIIDigit(c):
		case c == '_' && i+1 < len(value) && value[i-1] != '_':
			separators++
		default:
			return false
		}
	}
	return separators > 0
}

// isPlainLocator dit si value est une adresse « schéma://… » sans identifiants ni paramètres.
func isPlainLocator(value []byte) bool {
	scheme := bytes.Index(value, []byte("://"))
	if scheme <= 0 || bytes.ContainsAny(value, "@?") {
		return false
	}
	for _, c := range value[:scheme] {
		if !isASCIIAlphanumeric(c) && c != '+' && c != '.' && c != '-' {
			return false
		}
	}
	return isASCIILower(value[0]) || isASCIIUpper(value[0])
}

// credibleLiteral dit si la chaîne v.text[start:end], portée par une structure, peut être la valeur du nom sensible :
// forme stricte, ou, pour un mot de passe (qui peut être un mot) porté par une donnée (data : élément d'un tableau,
// valeur d'un objet), au moins 8 unités sans espace : le corpus d'origine garde l'objet JSON qui porte un mot de passe
// fait de mots (« allows a JSON Schema type descriptor but blocks a JSON secret object »). L'argument d'un appel et la
// chaîne d'un gabarit sont du code (nom d'une variable d'environnement, clé de traduction) : forme stricte seulement.
func credibleLiteral(v *view, start, end int, secretType string, data bool) bool {
	if strictShaped(v, start, end) {
		return true
	}
	if !data || secretType != "password" {
		return false
	}
	value := v.text[start:end]
	return utf16Units(value) >= 8 && !classesOf(value).spaced && !isPlainLocator(value)
}

// nesting suit l'imbrication des parenthèses, crochets et accolades d'une structure parcourue. data dit si la
// position courante est dans une donnée (tableau, objet) ou dans du code (liste d'arguments, gabarit).
type nesting struct {
	// kinds[k] : l'ouverture de rang k est un crochet ou une accolade.
	kinds [32]bool
	depth int
	// base : nature de la région avant toute ouverture.
	base bool
}

func (n *nesting) open(c byte) {
	if n.depth < len(n.kinds) {
		n.kinds[n.depth] = c != '('
	}
	n.depth++
}

func (n *nesting) close() {
	if n.depth > 0 {
		n.depth--
	}
}

func (n *nesting) data() bool {
	switch {
	case n.depth == 0:
		return n.base
	case n.depth > len(n.kinds):
		// Imbrication au-delà de la table : tenue pour une donnée (le littéral est gardé).
		return true
	}
	return n.kinds[n.depth-1]
}

// hasSecretWord dit si un mot de v.text[start:end] (coupé aux espaces, guillemets et ponctuation de bord retirés) a
// la forme d'un secret.
func hasSecretWord(v *view, start, end int) bool {
	text := v.text
	for i := start; i < end; {
		for i < end && isLineSpace(text[i]) {
			i++
		}
		wordStart := i
		for i < end && !isLineSpace(text[i]) {
			i++
		}
		wordEnd := i
		for wordStart < wordEnd && bytes.IndexByte([]byte("\"'`([{<"), text[wordStart]) >= 0 {
			wordStart++
		}
		for wordEnd > wordStart && bytes.IndexByte([]byte("\"'`)]}>,;.:"), text[wordEnd-1]) >= 0 {
			wordEnd--
		}
		if wordEnd > wordStart && secretShaped(v, wordStart, wordEnd) {
			return true
		}
	}
	return false
}

func isLineSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func isQuote(c byte) bool { return c == '"' || c == '\'' || c == '`' }

// closingQuote rend la position du guillemet qui ferme celui de text[open], avant limit et sur la même ligne (barre
// oblique inverse sautée) ; -1 sinon.
func closingQuote(text []byte, open, limit int) int {
	quote := text[open]
	for i := open + 1; i < limit; i++ {
		switch text[i] {
		case '\\':
			i++
		case '\n', '\r':
			return -1
		case quote:
			return i
		}
	}
	return -1
}

// balancedEnd rend la position qui suit la fermeture de l'ouverture text[open] (« ( », « [ », « { »), avant limit, sur
// la même ligne et à referenceBytes octets au plus, chaînes entre guillemets sautées ; faux sinon.
func balancedEnd(text []byte, open, limit int) (int, bool) {
	limit = min(limit, open+referenceBytes+1)
	depth := 0
	for i := open; i < limit; i++ {
		switch c := text[i]; c {
		case '\n', '\r':
			return 0, false
		case '"', '\'', '`':
			if closing := closingQuote(text, i, limit); closing >= 0 {
				i = closing
			}
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
	}
	return 0, false
}

// reference est une référence lue par referenceAt : end la suit ; inner est la position où la recherche d'affectations
// reprend (après l'ouverture d'une substitution de commande ou d'un gabarit, dont le contenu est relu ; end sinon).
type reference struct {
	end, inner int
}

// referenceAt lit la référence qui commence en i dans v.text[:limit] :
//
//   - variable ou paramètre de shell : « $NOM », « $1 », « $@ », « $* », « $# », « $? », « $! » ;
//   - expansion : « ${NOM} », « ${#NOM} », « ${!NOM} », « ${NOM:?message} », et « ${NOM:-défaut} » quand le défaut est
//     vide ou lui-même une référence (un défaut littéral n'est pas exempté, comme dans l'origine) ;
//   - substitution de commande : « $(commande) », accents graves ;
//   - gabarit : « ${{ expression }} », « {{ expression }} », « #{expression} », « %{nom} », sans chaîne crédible ;
//   - champ de format : « %s », « %v », « %d », « %q », non suivi d'une lettre ou d'un chiffre.
//
// Sur une seule ligne, referenceBytes octets au plus. secretType : type du nom sensible (credibleLiteral).
func referenceAt(v *view, i, limit int, secretType string) (reference, bool) {
	text := v.text
	if i >= limit {
		return reference{}, false
	}
	rest := text[i:limit]
	switch {
	case bytes.HasPrefix(rest, []byte("${{")):
		return templateReference(v, i+3, limit, "}}", secretType)
	case bytes.HasPrefix(rest, []byte("{{")):
		return templateReference(v, i+2, limit, "}}", secretType)
	case bytes.HasPrefix(rest, []byte("#{")), bytes.HasPrefix(rest, []byte("%{")):
		return templateReference(v, i+2, limit, "}", secretType)
	case bytes.HasPrefix(rest, []byte("$(")):
		end, ok := balancedEnd(text, i+1, limit)
		if !ok || hasCredibleLiteral(v, i+2, end-1, secretType, false, true) {
			return reference{}, false
		}
		return reference{end: end, inner: i + 2}, true
	case bytes.HasPrefix(rest, []byte("${")):
		return expansionReference(v, i, limit, secretType)
	case text[i] == '`':
		closing := closingQuote(text, i, min(limit, i+referenceBytes+1))
		if closing <= i+1 || hasCredibleLiteral(v, i+1, closing, secretType, false, true) {
			return reference{}, false
		}
		return reference{end: closing + 1, inner: i + 1}, true
	case text[i] == '$' && i+1 < limit:
		c := text[i+1]
		if isASCIIDigit(c) || c == '@' || c == '*' || c == '#' || c == '?' || c == '!' {
			return reference{end: i + 2, inner: i + 2}, true
		}
		if c == '_' || isASCIILower(c) || isASCIIUpper(c) {
			j := i + 2
			for j < limit && isWordByte(text[j]) {
				j++
			}
			return reference{end: j, inner: j}, true
		}
	case text[i] == '%' && i+1 < limit && bytes.IndexByte([]byte("svdq"), text[i+1]) >= 0:
		if i+2 < limit && isASCIIAlphanumeric(text[i+2]) {
			return reference{}, false
		}
		return reference{end: i + 2, inner: i + 2}, true
	}
	return reference{}, false
}

// templateReference lit le corps d'un gabarit depuis from jusqu'à closing, sur la même ligne : refusé s'il est vide
// ou porte une chaîne crédible (« {{ valeur | default("…") }} »).
func templateReference(v *view, from, limit int, closing string, secretType string) (reference, bool) {
	text := v.text
	limit = min(limit, from+referenceBytes)
	found := bytes.Index(text[from:limit], []byte(closing))
	if found <= 0 || bytes.ContainsAny(text[from:from+found], "\r\n") || len(jsTrim(text[from:from+found])) == 0 {
		return reference{}, false
	}
	if hasCredibleLiteral(v, from, from+found, secretType, false, false) {
		return reference{}, false
	}
	return reference{end: from + found + len(closing), inner: from}, true
}

// expansionReference lit « ${…} » en i.
func expansionReference(v *view, i, limit int, secretType string) (reference, bool) {
	text := v.text
	end, ok := balancedEnd(text, i+1, limit)
	if !ok {
		return reference{}, false
	}
	body := end - 1
	j := i + 2
	if j < body && (text[j] == '#' || text[j] == '!') {
		j++
	}
	nameStart := j
	for j < body && (isIdentByte(text[j]) || text[j] == '.') {
		j++
	}
	// Expression d'un gabarit de code (« ${f(x).y} », « ${'a'.repeat(3)} ») : relue, refusée si elle porte une chaîne
	// crédible.
	expression := func() (reference, bool) {
		if len(jsTrim(text[i+2:body])) == 0 || hasCredibleLiteral(v, i+2, body, secretType, false, false) {
			return reference{}, false
		}
		return reference{end: end, inner: i + 2}, true
	}
	if j == nameStart {
		return expression()
	}
	if j == body {
		return reference{end: end, inner: end}, true
	}
	// Opérateur d'expansion : « :- », « - », « := », « = », « :+ », « + », « :? », « ? ». Le message de « ? » n'est pas
	// une valeur ; l'opérande des autres est la valeur de repli : vide ou référence, sinon le constat reste.
	operator := j
	for j < body && bytes.IndexByte([]byte(":-=+?"), text[j]) >= 0 && j-operator < 2 {
		j++
	}
	if j == operator {
		// Autre forme de shell (« ${NOM[0]} », « ${NOM%suffixe} », « ${NOM/a/b} ») : aucune valeur de repli.
		if bytes.IndexByte([]byte("[%#/^,@"), text[j]) < 0 {
			return expression()
		}
		return reference{end: end, inner: end}, true
	}
	if bytes.IndexByte(text[operator:j], '?') >= 0 || j == body {
		return reference{end: end, inner: end}, true
	}
	operand, ok := referenceAt(v, j, body, secretType)
	if !ok || operand.end != body {
		return reference{}, false
	}
	return reference{end: end, inner: end}, true
}

// hasCredibleLiteral dit si v.text[start:end] porte une chaîne entre guillemets crédible (credibleLiteral) qui n'est
// pas le nom d'un champ. data : la région est une donnée (voir nesting). words : un mot nu de forme stricte compte
// aussi (commande de shell, où un mot sans guillemets est un littéral ; ailleurs, c'est un identifiant).
func hasCredibleLiteral(v *view, start, end int, secretType string, data, words bool) bool {
	text := v.text
	nest := nesting{base: data}
	for i := start; i < end; {
		c := text[i]
		switch {
		case isQuote(c):
			closing := closingQuote(text, i, end)
			if closing < 0 {
				i++
				continue
			}
			if !isFieldName(text, start, i, closing) && credibleLiteral(v, i+1, closing, secretType, nest.data()) {
				return true
			}
			i = closing + 1
		case isBareWordByte(c):
			wordStart := i
			for i < end && isBareWordByte(text[i]) {
				i++
			}
			if words && strictShaped(v, wordStart, i) {
				return true
			}
		default:
			switch c {
			case '(', '[', '{':
				nest.open(c)
			case ')', ']', '}':
				nest.close()
			}
			i++
		}
	}
	return false
}

// isBracketedWord dit si l'ouverture en open ne porte, jusqu'à sa fermeture sur la ligne, qu'un seul mot nu de forme
// stricte (« [Xy7…] », « (Xy7…) ») : un littéral écrit entre crochets ou parenthèses dans une phrase, pas une structure.
func isBracketedWord(v *view, open, lineEnd int) bool {
	text := v.text
	start := skipSpacesAndTabs(text, open+1)
	end := start
	for end < lineEnd && isBareWordByte(text[end]) {
		end++
	}
	closing := skipSpacesAndTabs(text, end)
	return end > start && closing < lineEnd && bytes.IndexByte([]byte(")]}"), text[closing]) >= 0 && strictShaped(v, start, end)
}

// isBareWordByte : octet d'un mot nu d'une structure (ni espace, ni guillemet, ni ponctuation de structure).
func isBareWordByte(c byte) bool {
	return !isLineSpace(c) && !isQuote(c) && bytes.IndexByte([]byte("()[]{},;:="), c) < 0
}

// isFieldName dit si la chaîne text[open:closing+1] est le nom d'un champ : suivie de « : » (pas « :: ») et précédée,
// espaces sautées, d'une accolade ouvrante, d'une virgule ou du début de la région ou de la ligne. La branche d'une
// condition (« c ? "a" : "b" ») n'en est pas un.
func isFieldName(text []byte, regionStart, open, closing int) bool {
	after := skipSpacesAndTabs(text, closing+1)
	if !isAt(text, after, ':') || isAt(text, after+1, ':') {
		return false
	}
	before := open - 1
	for before >= regionStart && (text[before] == ' ' || text[before] == '\t') {
		before--
	}
	if before < regionStart {
		return true
	}
	switch text[before] {
	case '{', ',', '\n', '\r':
		return true
	}
	return false
}

// sensitiveFieldBefore dit si la chaîne ouverte en open est la valeur d'un champ au nom sensible (« nom: "…" »,
// « "nom" = "…" ») : la recherche d'affectations, qui reprend dans la structure, la lit pour elle-même.
func sensitiveFieldBefore(text []byte, regionStart, open int) bool {
	i := open - 1
	for i >= regionStart && (text[i] == ' ' || text[i] == '\t') {
		i--
	}
	if i < regionStart || (text[i] != ':' && text[i] != '=') {
		return false
	}
	i--
	if i >= regionStart && text[i] == ':' {
		i--
	}
	for i >= regionStart && (text[i] == ' ' || text[i] == '\t') {
		i--
	}
	if i >= regionStart && (text[i] == '"' || text[i] == '\'') {
		i--
	}
	nameEnd := i + 1
	for i >= regionStart && (isWordByte(text[i]) || text[i] == '.' || text[i] == '-') {
		i--
	}
	if nameEnd == i+1 {
		return false
	}
	_, sensitive := typeForSensitiveKey(text[i+1 : nameEnd])
	return sensitive
}

// structureWalk est le résultat de walkStructure.
type structureWalk struct {
	// judged : la structure a été lue jusqu'à sa fermeture ou jusqu'à la fin du texte, dans les bornes.
	judged bool
	// firstLine : la première ligne porte un littéral crédible (le constat d'origine, qui la couvre, est gardé).
	firstLine bool
	// literals : chaînes crédibles des lignes suivantes.
	literals [][2]int
}

// walkStructure parcourt la structure ouverte en open (« [ », « { » ou « ( »).
//
// Première ligne, jusqu'à sa fin (ce que couvre le constat d'origine) : un littéral crédible, chaîne ou mot nu, garde
// ce constat. Lignes suivantes, jusqu'à la fermeture de la structure : chaque chaîne crédible qui n'est ni le nom d'un
// champ ni la valeur d'un champ au nom sensible est rendue pour un constat à elle. Bornes : structureWalkBytes, et
// le budget de la vue.
func (ctx *contextualText) walkStructure(v *view, open int, secretType string) structureWalk {
	text := ctx.text
	lineEnd := ctx.nextLineBreak(open)
	limit := min(len(text), open+structureWalkBytes)
	if !ctx.spend(min(lineEnd, limit) - open) {
		return structureWalk{}
	}
	if lineEnd > limit {
		// Ligne plus longue que la borne : non jugée.
		return structureWalk{}
	}
	if hasCredibleLiteral(v, open, lineEnd, secretType, true, false) || isBracketedWord(v, open, lineEnd) {
		return structureWalk{judged: true, firstLine: true}
	}
	walk := structureWalk{}
	nest := nesting{base: true}
	i := open
	for ; i < limit; i++ {
		switch c := text[i]; c {
		case '(', '[', '{':
			nest.open(c)
		case ')', ']', '}':
			nest.close()
			if nest.depth == 0 {
				ctx.spend(max(0, i-lineEnd))
				walk.judged = true
				return walk
			}
		case '"', '\'', '`':
			closing := closingQuote(text, i, limit)
			if closing < 0 {
				continue
			}
			if i > lineEnd && len(walk.literals) < structureLiteralsMax && !isFieldName(text, open, i, closing) &&
				!sensitiveFieldBefore(text, open, i) && credibleLiteral(v, i+1, closing, secretType, nest.data()) {
				walk.literals = append(walk.literals, [2]int{i + 1, closing})
			}
			i = closing
		}
	}
	ctx.spend(max(0, i-lineEnd))
	// Fin du texte avant la fermeture : tout ce qui existe a été lu. Borne atteinte : non jugée.
	walk.judged = limit == len(text)
	if !walk.judged {
		walk.literals = nil
	}
	return walk
}

// concatTail dit si ce qui suit cursor prolonge la valeur : caractère collé, ou opérateur de concaténation ou de
// repli (« + », « || », « ?? », « .. ») après des espaces. Le constat d'origine, qui couvre alors l'expression, est
// gardé.
func concatTail(text []byte, cursor int) bool {
	if cursor >= len(text) {
		return false
	}
	switch text[cursor] {
	case ' ', '\t':
	case ',', ';', '#', '}', ')', ']', '\r', '\n', '"', '\'', '`', '\\', '|', '&', '>', '<':
		return bytes.HasPrefix(text[cursor:], []byte("||"))
	default:
		return true
	}
	rest := text[skipSpacesAndTabs(text, cursor):]
	return bytes.HasPrefix(rest, []byte("+")) || bytes.HasPrefix(rest, []byte("||")) ||
		bytes.HasPrefix(rest, []byte("??")) || bytes.HasPrefix(rest, []byte(".."))
}

// interpolation juge le contenu v.text[start:end] d'une chaîne entre guillemets : vrai s'il porte au moins une
// référence et que ce qui reste, hors références, ne peut pas être le secret. Pour un mot de passe, qui peut être un
// mot, le reste ne doit porter ni lettre ni chiffre ; pour les autres types, aucun mot à forme de secret.
//
// Une variable nue (« $NOM », « %s ») ne compte que si elle ouvre la chaîne ou suit un séparateur : un mot de passe qui
// porte un « $ » en son milieu reste un littéral. fields : la chaîne est à champs (« f"…{nom}…" », « $"…{nom}…" »).
// inner est la position où reprendre la recherche.
func interpolation(v *view, start, end int, secretType string, fields bool) (int, bool) {
	text := v.text
	references := 0
	inner := end
	literalStart := start
	literalOK := func(from, to int) bool {
		if secretType == "password" {
			for _, r := range string(text[from:to]) {
				if r >= 0x80 || isASCIIAlphanumeric(byte(r)) {
					return false
				}
			}
			return true
		}
		return !hasSecretWord(v, from, to)
	}
	for i := start; i < end; {
		var ref reference
		ok := false
		switch c := text[i]; {
		case fields && c == '{' && !isAt(text, i+1, '{'):
			if closing, balanced := balancedEnd(text, i, end); balanced && closing > i+2 {
				ref, ok = reference{end: closing, inner: i + 1}, !hasCredibleLiteral(v, i+1, closing-1, secretType, false, false)
			}
		case c == '$' || c == '`' || c == '{' || c == '#' || c == '%':
			ref, ok = referenceAt(v, i, end, secretType)
			if ok && (c == '$' || c == '%') && ref.inner == ref.end && !isAt(text, i+1, '{') && i > start &&
				isASCIIAlphanumeric(text[i-1]) {
				// Variable nue collée à une lettre ou à un chiffre.
				ok = false
			}
		}
		if !ok {
			i++
			continue
		}
		if !literalOK(literalStart, i) {
			return 0, false
		}
		if references == 0 {
			inner = ref.inner
		}
		references++
		i = ref.end
		literalStart = i
	}
	if references == 0 || !literalOK(literalStart, end) {
		return 0, false
	}
	return inner, true
}

// crossesLine dit si une fin de ligne sépare le séparateur de l'affectation du début de la valeur.
func crossesLine(text []byte, from, valueStart int) bool {
	for i := valueStart - 1; i >= from; i-- {
		switch text[i] {
		case '\n', '\r':
			return true
		case ' ', '\t':
		default:
			return false
		}
	}
	return false
}

// expressionPrefixes : mots qui précèdent une expression sans en être la valeur.
var expressionPrefixes = [][]byte{
	[]byte("await"), []byte("new"), []byte("return"), []byte("yield"), []byte("typeof"), []byte("void"),
	[]byte("not"), []byte("throw"), []byte("delete"),
}

// functionKeywords : mots qui ouvrent une fonction.
var functionKeywords = [][]byte{[]byte("function"), []byte("async"), []byte("lambda"), []byte("func"), []byte("fn")}

// assignmentNoise juge la valeur d'une affectation à nom sensible que les filtres d'origine n'ont pas écartée (voir
// l'en-tête du fichier). secretType : type du nom ; lang : langage de l'analyse.
func (ctx *contextualText) assignmentNoise(v *view, m *assignmentMatch, p *parsedValue, secretType string, lang language) noiseVerdict {
	text := ctx.text
	if p.kind == kindRegex {
		return keepFinding
	}
	if p.kind == kindMultiline {
		// Bloc YAML, heredoc, chaîne à trois guillemets : seul l'en-tête d'une enveloppe chiffrée est lu.
		if isEncryptedBlock(text[p.start:p.valueEnd]) {
			return noiseVerdict{drop: true}
		}
		return keepFinding
	}
	lineEnd := ctx.nextLineBreak(p.start)
	if !ctx.spend(max(p.end, lineEnd) - m.start + 64) {
		return keepFinding
	}
	// Valeur chiffrée, partout (dotenv compris) : ce qui est écrit n'est pas le secret.
	if isEncryptedEnvelope(text, p, lineEnd) {
		return noiseVerdict{drop: true}
	}
	start, end := p.start, p.valueEnd

	// Valeur sans guillemets lue à la ligne suivante (clé de section YAML, « case … : » puis instruction) : la ligne
	// suivante est relue pour elle-même.
	// La forme est jugée sur toute la ligne : la lecture d'origine coupe la valeur à la première virgule ou au dièse.
	if p.kind == kindUnquoted && crossesLine(text, m.start, start) && !hasSecretWord(v, start, max(end, ctx.nextLineBreak(start))) {
		return noiseVerdict{drop: true, resume: ctx.lineStart(start)}
	}

	// Valeur publique connue (clé publiable, clé de site, jeton public d'essai : publicvalues.go), partout, sous un nom
	// de clé d'API ou de jeton seulement.
	if (secretType == "api_key" || secretType == "access_token") && isPublicValue(text, start, end) {
		return noiseVerdict{drop: true}
	}

	// Références et gabarits, partout (dotenv compris).
	if verdict, ok := ctx.referenceNoise(v, m, p, secretType, lang); ok {
		return verdict
	}

	bare := ctx.isBareEnvironmentAssignment(m, lang)
	if bare {
		return keepFinding
	}
	if p.kind == kindUnquoted {
		if verdict, ok := ctx.structureNoise(v, m, p, secretType, lang); ok {
			return verdict
		}
	}

	// Palier 2 : du code seulement, et pour une clé d'API, un jeton ou un secret générique (un mot de passe peut être
	// un mot). Le constat d'origine ne couvre aucun mot à forme de secret (valeur d'essai, nom de variable, libellé,
	// mot du langage).
	if !shapeJudgedTypes[secretType] || !ctx.codeContext(m, lang) || hasSecretWord(v, start, max(end, p.end)) {
		return keepFinding
	}
	if p.kind == kindQuoted && concatTail(text, min(end+1, len(text))) {
		// Chaîne prolongée par une concaténation : l'autre opérande peut porter le secret.
		return keepFinding
	}
	return noiseVerdict{drop: true, resume: start}
}

// shapeJudgedTypes : types de secret jugés sur la forme de la valeur par le palier 2.
var shapeJudgedTypes = map[string]bool{"api_key": true, "access_token": true, "generic_secret": true}

// codeContext dit si l'affectation est dans du code (palier 2) : langage de code déclaré, ou, sans langage, ligne qui
// porte avant le nom un mot-clé de déclaration (const, let, var, return, readonly, type…).
func (ctx *contextualText) codeContext(m *assignmentMatch, lang language) bool {
	if lang.set {
		return lang.isCodeLike()
	}
	return ctx.keywords(keywordsExternalCode).inSlice(ctx.text, ctx.matchLineStart(m), m.end)
}

// referenceNoise : la valeur est une référence, ou une chaîne faite de références.
func (ctx *contextualText) referenceNoise(v *view, m *assignmentMatch, p *parsedValue, secretType string, lang language) (noiseVerdict, bool) {
	text := ctx.text
	start, end := p.start, p.valueEnd
	switch p.kind {
	case kindPlaceholder:
		if ref, ok := referenceAt(v, start, p.end, secretType); ok && ref.end == p.end && !concatTail(text, p.end) {
			return noiseVerdict{drop: true, resume: max(ref.inner, start+1)}, true
		}
	case kindQuoted:
		closing := min(end+1, len(text))
		// Accents graves dans un script shell : substitution de commande (ailleurs, une chaîne littérale).
		if text[start-1] == '`' && ctx.shellLine(m, lang) && bytes.ContainsAny(text[start:end], " \t") &&
			!hasCredibleLiteral(v, start, end, secretType, false, true) && !concatTail(text, closing) {
			return noiseVerdict{drop: true, resume: start}, true
		}
		// Substitution de commande à guillemets imbriqués (« "$(cat "$HOME/x")" ») : la chaîne lue s'arrête au guillemet
		// intérieur.
		if bytes.HasPrefix(text[start:], []byte("$(")) {
			if ref, ok := referenceAt(v, start, ctx.nextLineBreak(start), secretType); ok && ref.end > end {
				after := ref.end
				if isAt(text, after, text[start-1]) {
					after++
				}
				if !concatTail(text, after) {
					return noiseVerdict{drop: true, resume: ref.inner}, true
				}
				return noiseVerdict{}, false
			}
		}
		from := start
		if scheme, ok := authSchemeEnd(text[start:end]); ok {
			from = start + scheme
		}
		if inner, ok := interpolation(v, from, end, secretType, isFieldString(text, start)); ok && !concatTail(text, closing) {
			return noiseVerdict{drop: true, resume: max(inner, start)}, true
		}
	case kindUnquoted:
		first := start
		if scheme, ok := authSchemeEnd(text[start:end]); ok {
			first = start + scheme
		}
		if ref, ok := referenceAt(v, first, ctx.nextLineBreak(first), secretType); ok && !concatTail(text, ref.end) {
			return noiseVerdict{drop: true, resume: max(ref.inner, first+1)}, true
		}
	}
	return noiseVerdict{}, false
}

// shellLine dit si l'affectation est une ligne de shell : langage de shell déclaré, ou, sans langage, affectation nue
// (« NOM=… », « nom=… ») sans espace autour du signe égal.
func (ctx *contextualText) shellLine(m *assignmentMatch, lang language) bool {
	if lang.set {
		return shellLanguages[lang.lowered()]
	}
	lineStart := ctx.matchLineStart(m)
	return m.pattern.plain && ctx.text[m.end-1] == '=' &&
		(ctx.prefixAssignment(prefixBareEnvironment, lineStart, m.end) || ctx.prefixAssignment(prefixShell, lineStart, m.end))
}

// isFieldString dit si la chaîne dont le contenu commence en start est à champs « {nom} » : préfixe « f » de Python
// (« f"…" », « rf"…" », « fr"…" ») ou « $ » de C# (« $"…" », « $@"…" »).
func isFieldString(text []byte, start int) bool {
	i := start - 2
	for k := 0; k < 2 && i >= 0; k, i = k+1, i-1 {
		switch text[i] {
		case 'f', 'F', '$':
			return i == 0 || !isIdentByte(text[i-1])
		case 'r', 'R', 'b', 'B', '@':
		default:
			return false
		}
	}
	return false
}

// structureNoise : la valeur sans guillemets est une structure de code. Hors affectation nue d'environnement
// (l'appelant l'a vérifié). Tableau et objet : partout ; appel, type, fonction : là où l'origine admet déjà une
// référence de code (referenceEligible).
func (ctx *contextualText) structureNoise(v *view, m *assignmentMatch, p *parsedValue, secretType string, lang language) (noiseVerdict, bool) {
	text := ctx.text
	start, end := p.start, p.valueEnd
	lineEnd := ctx.nextLineBreak(start)
	i := start
	for i < end && (text[i] == '!' || text[i] == '*' || text[i] == '&' || text[i] == '.') {
		i++
	}
	for _, word := range expressionPrefixes {
		if bytes.HasPrefix(text[i:end], word) && isSpaceOrTab(text, i+len(word)) {
			i = skipSpacesAndTabs(text, i+len(word))
			break
		}
	}
	if i >= len(text) {
		return noiseVerdict{}, false
	}
	walked := func(open int) (noiseVerdict, bool) {
		// Fermée sur la ligne et suivie d'un signe collé (« {a}b », « nom(1)! ») : ce n'est pas une structure reconnue,
		// le constat d'origine reste.
		if closing, ok := balancedEnd(text, open, lineEnd); ok && closing < len(text) && !isLineSpace(text[closing]) &&
			bytes.IndexByte([]byte(",;)]}.?:"), text[closing]) < 0 {
			return noiseVerdict{}, false
		}
		walk := ctx.walkStructure(v, open, secretType)
		if !walk.judged || walk.firstLine {
			return noiseVerdict{}, false
		}
		return noiseVerdict{drop: true, resume: open + 1, literals: walk.literals}, true
	}
	if text[i] == '[' || (text[i] == '{' && !isAt(text, i+1, '{')) {
		if _, substitute := substituteAt(text, i); substitute {
			// Un Substitut commence par « [ » : la lecture d'origine (résidu d'une expurgation) reste la règle.
			return noiseVerdict{}, false
		}
		return walked(i)
	}
	if !ctx.referenceEligible(m, lang) {
		return noiseVerdict{}, false
	}
	if text[i] == '(' {
		// Fonction fléchée, signature ou expression entre parenthèses : « (a, b) => … », « (a): T », « (await f()).x ».
		return walked(i)
	}
	for _, word := range functionKeywords {
		if bytes.HasPrefix(text[i:end], word) && i+len(word) < len(text) && !isIdentByte(text[i+len(word)]) {
			return noiseVerdict{drop: true, resume: i + len(word)}, true
		}
	}
	pathEnd := identPathEnd(text, i)
	if pathEnd == i || pathEnd >= len(text) {
		return noiseVerdict{}, false
	}
	switch next := text[pathEnd]; {
	case next == '(':
		// Appel : la liste d'arguments est parcourue.
		return walked(pathEnd)
	case next == '[' && bytes.IndexByte(text[i:pathEnd], '.') >= 0:
		// Accès indexé à une propriété : « a.b[c] ». Un nom seul suivi de crochets (« Optional[str] ») reste à
		// l'origine, dont le corpus garde le constat.
		return walked(pathEnd)
	case next == '<' && pathEnd+1 < len(text) && (isIdentStart(text[pathEnd+1]) || text[pathEnd+1] == '{'):
		// Type générique : « Map<string, Session> ».
		return noiseVerdict{drop: true, resume: pathEnd + 1}, true
	case next == ')':
		// Type d'un paramètre, suivi de la flèche, du type de retour ou du corps de la fonction : « nom: Type) => … »,
		// « nom: Type): Retour { », « nom: type) -> Retour: ».
		after := skipSpacesAndTabs(text, pathEnd+1)
		rest := text[after:]
		if bytes.HasPrefix(rest, []byte("=>")) || bytes.HasPrefix(rest, []byte("->")) || isAt(text, after, '{') ||
			(isAt(text, after, ':') && !isAt(text, after+1, ':')) {
			return noiseVerdict{drop: true, resume: pathEnd}, true
		}
	}
	return noiseVerdict{}, false
}

// basicAuthNoise dit si l'argument de l'option d'utilisateur (courte ou longue) n'est pas un couple utilisateur et mot
// de passe : deux nombres (identifiants d'utilisateur et de groupe d'un conteneur), ou un format de date (signe plus et
// pourcentage en tête : l'heure en temps universel de la commande date). Écart avec Secret Guard (UPSTREAM.md, « Code
// ordinaire ») : le motif d'origine lit tout couple séparé par deux-points après l'option, sans regarder la commande.
func basicAuthNoise(user, password []byte) bool {
	if len(user) > 1 && user[0] == '+' && user[1] == '%' {
		return true
	}
	return isDigits(user) && isDigits(password)
}

func isDigits(value []byte) bool {
	for _, c := range value {
		if !isASCIIDigit(c) {
			return false
		}
	}
	return len(value) > 0
}

// encryptedHeaders : en-têtes de valeurs chiffrées dont la suite n'est pas lue.
var encryptedHeaders = [][]byte{
	[]byte("$ANSIBLE_VAULT;"), []byte("!vault"), []byte("-----BEGIN AGE ENCRYPTED FILE-----"),
	[]byte("-----BEGIN PGP MESSAGE-----"), []byte("age-encryption.org/v"),
}

func hasEncryptedHeader(value []byte) bool {
	for _, header := range encryptedHeaders {
		if bytes.HasPrefix(value, header) {
			return true
		}
	}
	return false
}

// isEncryptedBlock dit si une valeur de plusieurs lignes est une enveloppe chiffrée : son début, ou sa première ligne
// après l'indicateur de bloc (« | », « <<FIN »), est un en-tête de encryptedHeaders.
func isEncryptedBlock(value []byte) bool {
	head := jsTrim(value[:min(len(value), 256)])
	if hasEncryptedHeader(head) {
		return true
	}
	lineBreak := bytes.IndexByte(head[:min(len(head), 64)], '\n')
	return lineBreak >= 0 && hasEncryptedHeader(jsTrim(head[lineBreak+1:]))
}

// isEncryptedEnvelope dit si la valeur d'une ligne est une enveloppe chiffrée : ce qui est écrit n'est pas le secret.
// Formes : sops (« ENC[AES256_GCM,data:…] »), Spring Cloud Config (« {cipher}… »), Ansible Vault (en-tête
// « $ANSIBLE_VAULT;… », étiquette YAML « !vault »), chiffrement de transit de Vault (« vault:v1:… »), age et PGP
// (en-tête d'armure). Idée et formes reprises de Betterleaks, rules/generic/password.go (MIT ; UPSTREAM.md, « Code
// ordinaire »), resserrées : le texte chiffré doit suivre la marque. Une valeur sans guillemets est lue jusqu'à la fin
// de sa ligne (la lecture d'origine la coupe à la première virgule ou accolade), puis réduite à son premier mot.
func isEncryptedEnvelope(text []byte, p *parsedValue, lineEnd int) bool {
	end := p.valueEnd
	if p.kind == kindUnquoted || p.kind == kindPlaceholder {
		end = max(end, lineEnd)
	}
	value := jsTrim(text[p.start:min(end, len(text))])
	if hasEncryptedHeader(value) {
		return true
	}
	if p.kind != kindQuoted {
		if space := bytes.IndexAny(value, " \t"); space >= 0 {
			value = value[:space]
		}
	}
	switch {
	case bytes.HasPrefix(value, []byte("ENC[")):
		// sops : « ENC[CHIFFRE,data:…,iv:…,tag:…,type:str] ».
		body := value[4:]
		cipher := 0
		for cipher < len(body) && (isASCIIUpper(body[cipher]) || isASCIIDigit(body[cipher]) || body[cipher] == '_') {
			cipher++
		}
		return cipher > 0 && bytes.HasPrefix(body[cipher:], []byte(",data:")) && body[len(body)-1] == ']'
	case len(value) > 8 && bytes.EqualFold(value[:8], []byte("{cipher}")):
		return isCipherText(value[8:], 16, "+/=")
	case bytes.HasPrefix(value, []byte("vault:v")):
		rest := value[7:]
		digits := 0
		for digits < len(rest) && isASCIIDigit(rest[digits]) {
			digits++
		}
		return digits > 0 && digits < len(rest) && rest[digits] == ':' && isCipherText(rest[digits+1:], 8, "+/=_-")
	}
	return false
}

// isCipherText dit si value est faite d'au moins minimum lettres, chiffres ou signes de extra, et de rien d'autre.
func isCipherText(value []byte, minimum int, extra string) bool {
	if len(value) < minimum {
		return false
	}
	for _, c := range value {
		if !isASCIIAlphanumeric(c) && strings.IndexByte(extra, c) < 0 {
			return false
		}
	}
	return true
}
