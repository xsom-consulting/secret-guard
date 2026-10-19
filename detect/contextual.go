// Affectations contextuelles du moteur de détection : nom de variable sensible suivi d'une
// valeur littérale (affectations, environnement, arguments de commande, .npmrc, en-têtes Cookie, « -u
// utilisateur:mot de passe », clé auth de Docker), avec les blocs YAML, heredoc, préfixes de chaînes des langages et
// les filtres de références de code.
//
// Portage en Go de scanContextualAssignments et de ses fonctions dans secret-guard/packages/core/src/rules.ts
// (Apache-2.0, origine, avis et modifications dans UPSTREAM.md). Même suite de correspondances que JavaScript
// (lastIndex compris : execFrom). Linéaire : là où l'origine relit un préfixe de ligne ou rescanne un texte à chaque
// correspondance (lastIndexOf, indexOf, test d'une expression sur text.slice(lineStart, …)), le portage garde par vue
// les fins de ligne, les mots-clés et les résultats par début de ligne (contextualText), et lit les heredoc et les
// littéraux d'expression régulière à la main.

package detect

import (
	"bytes"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// language est le languageId de l'analyse (absent : set faux, comme undefined en JavaScript).
type language struct {
	id  string
	set bool
}

// lowered est languageId.toLowerCase().
func (l language) lowered() string { return jsToLower([]byte(l.id)) }

var (
	codeLanguages = map[string]bool{
		"c": true, "cpp": true, "cs": true, "csharp": true, "go": true, "java": true, "javascript": true,
		"javascriptreact": true, "js": true, "jsx": true, "kotlin": true, "php": true, "py": true, "python": true,
		"rb": true, "ruby": true, "rs": true, "rust": true, "swift": true, "ts": true, "tsx": true, "typescript": true,
		"typescriptreact": true,
	}
	structuredLanguages = map[string]bool{
		"hcl": true, "json": true, "jsonc": true, "properties": true, "terraform": true, "toml": true, "yaml": true,
		"yml": true,
	}
	dotenvLanguages = map[string]bool{"dotenv": true, "env": true, "shell-env": true}
	shellLanguages  = map[string]bool{"bash": true, "fish": true, "shell": true, "shellscript": true, "sh": true, "zsh": true}
)

func (l language) isCodeLike() bool { return l.set && codeLanguages[l.lowered()] }

func (l language) isDotenv() bool { return l.set && dotenvLanguages[l.lowered()] }

// assignmentPattern est un motif d'affectation de scanContextualAssignments ; le groupe 1 est le nom de variable.
type assignmentPattern struct {
	re    *regexp.Regexp
	start startCondition
	// plain : ASSIGNMENT (affectation nue d'environnement possible).
	plain bool
	// keyUnits : borne en unités UTF-16 du nom (« {1,80} » sur une classe qui admet tout point de code), 0 sinon.
	keyUnits int
}

func isAssignmentBoundary(r rune) bool {
	return isJSWhitespace(r) || r == ',' || r == '{' || r == ';' || r == '?' || r == '&'
}

func isIndexedBoundary(r rune) bool { return isJSWhitespace(r) || r == ',' || r == '(' }

func isLineBreak(r rune) bool { return isJSLineTerminator(r) }

func isDockerBoundary(r rune) bool { return isJSWhitespace(r) || r == ',' || r == '{' }

// assignmentPatterns : ASSIGNMENT, INDEXED_ENV_ASSIGNMENT, POWERSHELL_ENV_ASSIGNMENT, CLI_ARGUMENT_ASSIGNMENT,
// FUNCTION_ENV_ASSIGNMENT, NPM_AUTH_TOKEN_ASSIGNMENT, dans l'ordre de Secret Guard.
var assignmentPatterns = []assignmentPattern{
	{re: regexp.MustCompile(reAssignment), start: lineStartOr(isAssignmentBoundary), plain: true},
	{re: regexp.MustCompile(reIndexedEnvAssignment), start: lineStartOr(isIndexedBoundary), keyUnits: 80},
	{re: regexp.MustCompile(rePowershellEnvAssignment), start: lineStartOr(isJSWhitespace)},
	{re: regexp.MustCompile(reCliArgumentAssignment), start: lineStartOr(isJSWhitespace)},
	{re: regexp.MustCompile(reFunctionEnvAssignment), start: wordStart{}, keyUnits: 80},
	{re: regexp.MustCompile(reNpmAuthTokenAssignment), start: lineStartOr(isLineBreak)},
}

var (
	cookieHeaderPattern = regexp.MustCompile(reCookieHeader)
	cookieSecretPattern = regexp.MustCompile(reCookieSecret)
)

// scanContextualAssignments suit scanContextualAssignments de Secret Guard. allowStructured faux : la clé auth de
// Docker (décodage base64) n'est pas lue. Budget de décodage épuisé : errDecodeBudgetExhausted.
func (r *Rules) scanContextualAssignments(v *view, budget *decodeBudget, lang language, allowStructured bool) ([]finding, error) {
	ctx := newContextualText(v.text)
	var findings []finding
	if r.hasContextualTypes() {
		for i := range assignmentPatterns {
			findings = r.scanAssignmentPattern(v, ctx, &assignmentPatterns[i], lang, findings)
		}
	}
	findings = r.scanCookieCredentials(v, findings)
	findings = r.scanBasicAuthArguments(v, findings)
	if allowStructured {
		var err error
		if findings, err = r.scanDockerAuth(v, ctx, budget, findings); err != nil {
			return nil, err
		}
	}
	return findings, nil
}

// hasContextualTypes dit si le Pack active au moins une règle contextual_<type>.
func (r *Rules) hasContextualTypes() bool {
	for _, secretType := range sensitiveKeyTypes {
		if r.contextualRuleFor(secretType) != nil {
			return true
		}
	}
	return false
}

// sensitiveKeyTypes : types que rend typeForSensitiveKey.
var sensitiveKeyTypes = []string{
	"password", "private_key", "cloud_credential", "api_key", "access_token", "generic_secret", "database_credentials",
}

// assignmentMatch est une correspondance d'un motif d'affectation.
type assignmentMatch struct {
	start, end     int
	keyStart       int
	keyEnd         int
	pattern        *assignmentPattern
	lineStartCache int
}

// scanAssignmentPattern suit scanAssignmentPattern de Secret Guard.
func (r *Rules) scanAssignmentPattern(v *view, ctx *contextualText, p *assignmentPattern, lang language, findings []finding) []finding {
	text := v.text
	for lastIndex := 0; lastIndex <= len(text); {
		m := execFrom(p.re, text, lastIndex, p.start)
		if m == nil {
			break
		}
		match := assignmentMatch{start: m[0], end: m[1], keyStart: m[2], keyEnd: m[3], pattern: p, lineStartCache: -1}
		key := text[m[2]:m[3]]
		if p.keyUnits > 0 && utf16Units(key) > p.keyUnits {
			// RE2 compte des points de code, JavaScript des unités UTF-16 : pas de correspondance à cette position.
			lastIndex = nextRune(text, m[0])
			continue
		}
		lastIndex = m[1]
		secretType, sensitive := typeForSensitiveKey(key)
		if !sensitive {
			// Reprise sur les espaces qui suivent le séparateur : « configuration : » ne masque pas l'affectation
			// sensible qui suit.
			trailing := m[1]
			for trailing > m[0] {
				c, width := utf8.DecodeLastRune(text[m[0]:trailing])
				if !isJSWhitespace(c) {
					break
				}
				trailing -= width
			}
			if trailing < m[1] {
				lastIndex = max(nextRune(text, m[0]), trailing)
			}
			continue
		}
		valueSyntaxOffset := lastIndex
		parsed := ctx.parseAssignmentValue(valueSyntaxOffset, lang)
		hasTail := parsed != nil && hasExpressionTail(text, parsed)
		findingStart, findingEnd := 0, -1
		if parsed != nil {
			findingStart, findingEnd = parsed.start, parsed.end
			if hasTail {
				findingStart = skipSpacesAndTabs(text, valueSyntaxOffset)
				findingEnd = expressionEnd(text, parsed.end)
			}
			lastIndex = max(lastIndex, findingEnd)
		}
		if parsed == nil || parsed.valueEnd == parsed.start {
			continue
		}
		value := text[parsed.start:parsed.valueEnd]
		if ctx.safeContextualValue(&match, parsed, lang) ||
			isJSONSchemaTypeDescriptor(parsed, value, lang) ||
			ctx.isSymbolicEnumValue(&match, key, parsed, value) ||
			(ctx.isClearlyNonLiteralExpression(&match, parsed, value, lang) && !numericLiteral.Match(jsTrim(value))) ||
			(isConnectionKey(key) && !connectionContainsCredential(value)) {
			continue
		}
		matched := r.contextualRuleFor(secretType)
		if matched == nil {
			continue
		}
		score := matched.score - encodingPenalty(v.encoding)
		reasons := []string{"sensitive_variable_name", "structured_assignment"}
		if hasStrongEntropy(v, parsed.start, parsed.valueEnd) {
			score += 5
			reasons = append(reasons, "value_shape_supports_secret")
		}
		reasons = append(reasons, decodingReasons(v.encoding)...)
		findings = append(findings, newFinding(v, matched, findingStart, findingEnd, score, reasons))
	}
	return findings
}

func skipSpacesAndTabs(text []byte, i int) int {
	for isSpaceOrTab(text, i) {
		i++
	}
	return i
}

// normalizeKey suit normalizeKey de Secret Guard : NFKC, minuscules, lettres et chiffres ASCII seuls.
func normalizeKey(key []byte) string {
	normalized := norm.NFKC.Bytes(validUTF8PerByte(key))
	lowered := jsToLower(normalized)
	var b []byte
	for i := 0; i < len(lowered); i++ {
		c := lowered[i]
		if 'a' <= c && c <= 'z' || '0' <= c && c <= '9' {
			b = append(b, c)
		}
	}
	return string(b)
}

// validUTF8PerByte remplace chaque octet hors séquence UTF-8 valide par U+FFFD, comme le texte que lit Secret Guard.
func validUTF8PerByte(text []byte) []byte {
	if utf8.Valid(text) {
		return text
	}
	out := make([]byte, 0, len(text)+8)
	for i := 0; i < len(text); {
		r, width := utf8.DecodeRune(text[i:])
		if r == utf8.RuneError && width == 1 {
			out = append(out, replacement...)
		} else {
			out = append(out, text[i:i+width]...)
		}
		i += width
	}
	return out
}

// typeForSensitiveKey suit typeForSensitiveKey de Secret Guard.
func typeForSensitiveKey(key []byte) (string, bool) {
	n := normalizeKey(key)
	has := func(suffix string) bool { return len(n) >= len(suffix) && n[len(n)-len(suffix):] == suffix }
	switch {
	case n == "password" || has("password") || n == "passwd" || has("passwd") || n == "passphrase" ||
		has("passphrase") || n == "pwd" || has("dbpass"):
		return "password", true
	case has("privatekey"):
		return "private_key", true
	case has("awssecretaccesskey") || has("azurestoragekey"):
		return "cloud_credential", true
	case has("apikey"):
		return "api_key", true
	case (has("token") && n != "jsonwebtoken") || n == "authorization":
		return "access_token", true
	case has("clientsecret") || n == "secret" || has("secret") || has("secretkey") ||
		(!strings.HasPrefix(n, "public") && has("signingkey")) || has("encryptionkey"):
		return "generic_secret", true
	case has("databaseurl") || has("connectionstring"):
		return "database_credentials", true
	}
	return "", false
}

// isConnectionKey suit isConnectionKey de Secret Guard.
func isConnectionKey(key []byte) bool {
	n := normalizeKey(key)
	return bytes.HasSuffix([]byte(n), []byte("databaseurl")) || bytes.HasSuffix([]byte(n), []byte("connectionstring"))
}

var (
	connectionUserinfo  = regexp.MustCompile(reConnectionUserinfo)
	connectionParameter = regexp.MustCompile(reConnectionParameter)
	connectionPassword  = regexp.MustCompile(reConnectionPassword)
)

// connectionContainsCredential suit connectionContainsCredential de Secret Guard.
func connectionContainsCredential(value []byte) bool {
	return connectionUserinfo.Match(value) || connectionParameter.Match(value) || connectionPassword.Match(value)
}

// valueKind est la forme d'une valeur (ParsedValue.kind de Secret Guard).
type valueKind int

const (
	kindPlaceholder valueKind = iota
	kindRegex
	kindQuoted
	kindUnquoted
	kindMultiline
)

// parsedValue est une valeur d'affectation : value = text[start:valueEnd], étendue du constat [start, end).
type parsedValue struct {
	start, end, valueEnd int
	kind                 valueKind
}

func parsed(start, end int, kind valueKind) *parsedValue {
	return &parsedValue{start: start, end: end, valueEnd: end, kind: kind}
}

// hasExpressionTail suit hasExpressionTail de Secret Guard.
func hasExpressionTail(text []byte, p *parsedValue) bool {
	if p.kind != kindQuoted && p.kind != kindPlaceholder {
		return false
	}
	cursor := p.end
	if p.kind == kindQuoted {
		cursor++
	}
	if cursor > len(text) {
		return false
	}
	cursor = skipSpacesAndTabs(text, cursor)
	if cursor >= len(text) {
		return false
	}
	switch text[cursor] {
	case ',', ';', '#', '}', ')', ']', '\r', '\n':
		return false
	}
	return true
}

// expressionEnd suit expressionEnd de Secret Guard : jusqu'au « ; » ou à la fin de ligne, espaces finaux retirés.
func expressionEnd(text []byte, start int) int {
	end := start
	for end < len(text) && text[end] != ';' && text[end] != '\r' && text[end] != '\n' {
		end++
	}
	for end > start && (text[end-1] == ' ' || text[end-1] == '\t') {
		end--
	}
	return end
}

var (
	pythonStringPrefix  = regexp.MustCompile(rePythonStringPrefix)
	csharpStringPrefix  = regexp.MustCompile(reCsharpStringPrefix)
	rustRawStringPrefix = regexp.MustCompile(reRustRawStringPrefix)
	yamlBlockStart      = regexp.MustCompile(reYamlBlockStart)
)

// placeholderDelimiters : gabarits de parseAssignmentValue, dans l'ordre de Secret Guard.
var placeholderDelimiters = [][2]string{{"${{", "}}"}, {"${", "}"}, {"{{", "}}"}, {"<", ">"}}

// parseAssignmentValue suit parseAssignmentValue de Secret Guard ; nil comme null.
func (ctx *contextualText) parseAssignmentValue(offset int, lang language) *parsedValue {
	text := ctx.text
	start := skipSpacesAndTabs(text, offset)
	if start >= len(text) {
		return nil
	}
	for _, d := range placeholderDelimiters {
		if !bytes.HasPrefix(text[start:], []byte(d[0])) {
			continue
		}
		if closing := ctx.indexOf(d[1], start+len(d[0])); closing >= 0 {
			return parsed(start, closing+len(d[1]), kindPlaceholder)
		}
	}
	if m := pythonStringPrefix.FindSubmatchIndex(text[start:]); m != nil {
		delimiter := text[start+m[2] : start+m[3]]
		valueStart := start + m[1]
		closing := valueStart
		escaped := false
		for closing < len(text) {
			if !escaped && bytes.HasPrefix(text[closing:], delimiter) {
				break
			}
			c := text[closing]
			escaped = c == '\\' && !escaped
			closing++
		}
		kind := kindQuoted
		if len(delimiter) == 3 {
			kind = kindMultiline
		}
		return parsed(valueStart, closing, kind)
	}
	if m := csharpStringPrefix.FindIndex(text[start:]); m != nil {
		valueStart := start + m[1]
		closing := valueStart
		for closing < len(text) {
			if text[closing] == '"' {
				if isAt(text, closing+1, '"') {
					closing += 2
					continue
				}
				break
			}
			closing++
		}
		return parsed(valueStart, min(closing, len(text)), kindQuoted)
	}
	if m := rustRawStringPrefix.FindSubmatchIndex(text[start:]); m != nil {
		valueStart := start + m[1]
		closing := append([]byte{'"'}, text[start+m[2]:start+m[3]]...)
		end := len(text)
		if found := bytes.Index(text[valueStart:], closing); found >= 0 {
			end = valueStart + found
		}
		return parsed(valueStart, end, kindQuoted)
	}
	if m := ctx.yamlBlockStart(start); m != nil {
		currentLineStart := ctx.lineStart(max(0, start-1))
		keyIndent := 0
		for isSpaceOrTab(text, currentLineStart+keyIndent) {
			keyIndent++
		}
		end := start + m[1]
		for end < len(text) {
			lineEnd := bytes.IndexByte(text[end:], '\n')
			boundedLineEnd, lineStop := len(text), len(text)
			if lineEnd >= 0 {
				boundedLineEnd, lineStop = end+lineEnd+1, end+lineEnd
			}
			line := text[end:lineStop]
			if isJSBlank(line) {
				end = boundedLineEnd
				continue
			}
			indentation := 0
			for isSpaceOrTab(line, indentation) {
				indentation++
			}
			if indentation <= keyIndent {
				break
			}
			end = boundedLineEnd
		}
		return parsed(start, end, kindMultiline)
	}
	if end, ok := ctx.heredoc(start); ok {
		return parsed(start, end, kindMultiline)
	}
	if bytes.HasPrefix(text[start:], []byte(`"""`)) || bytes.HasPrefix(text[start:], []byte(`'''`)) {
		valueStart := start + 3
		end := len(text)
		if found := bytes.Index(text[valueStart:], text[start:valueStart]); found >= 0 {
			end = valueStart + found
		}
		return parsed(valueStart, end, kindMultiline)
	}
	if text[start] == '/' && !isAt(text, start+1, '/') && !isAt(text, start+1, '*') {
		if closing, ok := ctx.regexLiteralClose(start); ok {
			flagsEnd := closing + 1
			for flagsEnd < len(text) && bytes.IndexByte([]byte("dgimsuvy"), text[flagsEnd]) >= 0 {
				flagsEnd++
			}
			return parsed(start, flagsEnd, kindRegex)
		}
	}
	if quote := text[start]; quote == '"' || quote == '\'' || quote == '`' {
		valueStart := start + 1
		escaped := false
		for end := valueStart; end < len(text); end++ {
			c := text[end]
			if c == quote && !escaped {
				return parsed(valueStart, end, kindQuoted)
			}
			escaped = c == '\\' && !escaped
		}
		return parsed(valueStart, len(text), kindQuoted)
	}
	valueEnd := start
	for valueEnd < len(text) && bytes.IndexByte([]byte(",;#}\r\n"), text[valueEnd]) < 0 {
		valueEnd++
	}
	for valueEnd > start && (text[valueEnd-1] == ' ' || text[valueEnd-1] == '\t') {
		valueEnd--
	}
	if valueEnd == start {
		return nil
	}
	// Prompt, texte non typé et dotenv : constat jusqu'à la fin de ligne (une virgule, un point-virgule, un dièse ou
	// une accolade peuvent appartenir à la valeur). « json » comparé tel quel, comme Secret Guard.
	end := valueEnd
	if !lang.isCodeLike() && (!lang.set || lang.id != "json") {
		end = len(text)
		if lineEnd := bytes.IndexByte(text[valueEnd:], '\n'); lineEnd >= 0 {
			end = valueEnd + lineEnd
		}
		for end > start && text[end-1] == '\r' {
			end--
		}
	}
	return &parsedValue{start: start, end: end, valueEnd: valueEnd, kind: kindUnquoted}
}

// heredocMaxPrefixUnits : « [^\r\n]{0,2048}? » de HEREDOC_START.
const heredocMaxPrefixUnits = 2_048

// heredoc suit HEREDOC_START (motif collant à start) et la recherche de son terminateur : rend la fin du bloc. Le
// motif est lu à la main : RE2 ne borne pas une répétition au-delà de 1 000. « [^\r\n]{0,2048}? » paresseux : le
// premier « << » de la ligne, à au plus 2 048 unités UTF-16 de start, suivi d'un marqueur ; « [^\r\n]*\r?\n » : la
// ligne doit finir par LF ou CRLF, sinon aucune position de la ligne ne convient.
func (ctx *contextualText) heredoc(start int) (int, bool) {
	text := ctx.text
	lineStop := ctx.nextLineBreak(start)
	p := ctx.nextHeredocStart(start)
	if p < 0 || p >= lineStop || ctx.unitsBetween(start, p) > heredocMaxPrefixUnits {
		return 0, false
	}
	bodyStart := 0
	switch {
	case lineStop < len(text) && text[lineStop] == '\n':
		bodyStart = lineStop + 1
	case lineStop+1 < len(text) && text[lineStop] == '\r' && text[lineStop+1] == '\n':
		bodyStart = lineStop + 2
	default:
		return 0, false
	}
	markerStart, _ := heredocMarkerAt(text, p)
	markerEnd := markerStart + 1
	for markerEnd < len(text) && isWordByte(text[markerEnd]) {
		markerEnd++
	}
	return heredocTerminator(text, bodyStart, text[markerStart:markerEnd]), true
}

// nextHeredocStart : première position ≥ from d'un « << » suivi d'un marqueur (heredocMarkerAt), -1 sinon ; reprend
// la recherche précédente.
func (ctx *contextualText) nextHeredocStart(from int) int {
	s := &ctx.heredocStart
	if s.valid && from >= s.from && (s.result < 0 || s.result >= from) {
		return s.result
	}
	result := -1
	for p := from; p < len(ctx.text); {
		found := bytes.Index(ctx.text[p:], []byte("<<"))
		if found < 0 {
			break
		}
		p += found
		if _, ok := heredocMarkerAt(ctx.text, p); ok {
			result = p
			break
		}
		p++
	}
	*s = lastSearch{from: from, result: result, valid: true}
	return result
}

// unitsBetween : longueur en unités UTF-16 de text[from:to] (une unité au plus par octet : la longueur en octets
// suffit quand elle ne dépasse pas la borne ; sinon, unités cumulées de la vue, calculées une fois).
func (ctx *contextualText) unitsBetween(from, to int) int {
	if to-from <= heredocMaxPrefixUnits {
		return to - from
	}
	if ctx.cumulativeUnits == nil {
		ctx.cumulativeUnits = make([]int32, len(ctx.text)+1)
		units := int32(0)
		for i := 0; i < len(ctx.text); {
			c, width := utf8.DecodeRune(ctx.text[i:])
			for k := 0; k < width; k++ {
				ctx.cumulativeUnits[i+k] = units
			}
			if c > 0xFFFF {
				units += 2
			} else {
				units++
			}
			i += width
		}
		ctx.cumulativeUnits[len(ctx.text)] = units
	}
	return int(ctx.cumulativeUnits[to] - ctx.cumulativeUnits[from])
}

// yamlBlockStart : YAML_BLOCK_START (motif collant à start). Aucune partie du motif avant « \r?\n » ne franchit une
// fin de ligne : il n'est évalué que sur une ligne qui finit par LF ou CRLF, bornée à cette ligne.
func (ctx *contextualText) yamlBlockStart(start int) []int {
	text := ctx.text
	lineStop := ctx.nextLineBreak(start)
	end := 0
	switch {
	case lineStop < len(text) && text[lineStop] == '\n':
		end = lineStop + 1
	case lineStop+1 < len(text) && text[lineStop] == '\r' && text[lineStop+1] == '\n':
		end = lineStop + 2
	default:
		return nil
	}
	return yamlBlockStart.FindIndex(text[start:end])
}

// heredocMarkerAt : « <<-?[ \t]*["']?[A-Za-z_] » en p ; rend le début du marqueur.
func heredocMarkerAt(text []byte, p int) (int, bool) {
	i := p + 2
	if isAt(text, i, '-') {
		i++
	}
	i = skipSpacesAndTabs(text, i)
	if isAt(text, i, '"') || isAt(text, i, '\'') {
		i++
	}
	if i < len(text) && (text[i] == '_' || 'A' <= text[i] && text[i] <= 'Z' || 'a' <= text[i] && text[i] <= 'z') {
		return i, true
	}
	return 0, false
}

// heredocTerminator : première ligne, après bodyStart, faite du marqueur entouré d'espaces ou de tabulations
// (/(?:^|\n)[\t ]*MARQUEUR[\t ]*(?:\r?\n|$)/g depuis bodyStart) ; rend la fin de la correspondance, ou la fin du texte.
func heredocTerminator(text []byte, bodyStart int, marker []byte) int {
	for q := bodyStart; q < len(text); {
		found := bytes.IndexByte(text[q:], '\n')
		if found < 0 {
			return len(text)
		}
		i := skipSpacesAndTabs(text, q+found+1)
		if bytes.HasPrefix(text[i:], marker) {
			i = skipSpacesAndTabs(text, i+len(marker))
			switch {
			case i == len(text):
				return i
			case text[i] == '\n':
				return i + 1
			case text[i] == '\r' && isAt(text, i+1, '\n'):
				return i + 2
			}
		}
		q += found + 1
	}
	return len(text)
}

// safeContextualValue suit safeContextualValue de Secret Guard.
func (ctx *contextualText) safeContextualValue(m *assignmentMatch, p *parsedValue, lang language) bool {
	text := ctx.text
	value := text[p.start:p.valueEnd]
	// Extension de ce module : un Substitut après un schéma d'authentification (« Bearer XXXX1 ») ou dans le corps d'un
	// bloc PEM est une valeur fictive, comme un Substitut seul (safeLiteral).
	if (safeLiteral(value) || isAuthSchemeSubstitute(value) || isSubstitutePEM(value)) && !hasExpressionTail(text, p) {
		return true
	}
	if ctx.isBareEnvironmentAssignment(m, lang) {
		return false
	}
	lowered := ""
	if lang.set {
		lowered = lang.lowered()
	}
	lineStart := ctx.matchLineStart(m)
	shell := lang.set && shellLanguages[lowered]
	inferredShell := !lang.set && ctx.prefixAssignment(prefixShell, lineStart, m.end)
	if (shell || inferredShell) && isShellCommandSubstitution(value) {
		return true
	}
	if p.kind == kindQuoted || p.kind == kindMultiline {
		return false
	}
	eligible := lang.isCodeLike() || (lang.set && structuredLanguages[lowered])
	if !eligible && !lang.set {
		eligible = bytes.IndexByte(text[m.start:m.end], ':') >= 0 ||
			ctx.prefixAssignment(prefixStructured, lineStart, m.end) ||
			ctx.keywords(keywordsInferredCode).inSlice(text, lineStart, m.end) ||
			ctx.codeDeclaration(lineStart, m.end)
	}
	return eligible && isSafeReference(value)
}

// isBareEnvironmentAssignment suit isBareEnvironmentAssignment de Secret Guard.
func (ctx *contextualText) isBareEnvironmentAssignment(m *assignmentMatch, lang language) bool {
	if lang.isDotenv() {
		return true
	}
	if !m.pattern.plain {
		return false
	}
	return ctx.prefixAssignment(prefixBareEnvironment, ctx.matchLineStart(m), m.end)
}

// matchLineStart : text.lastIndexOf("\n", match.index) + 1.
func (ctx *contextualText) matchLineStart(m *assignmentMatch) int {
	if m.lineStartCache < 0 {
		m.lineStartCache = ctx.lineStart(m.start)
	}
	return m.lineStartCache
}

// isShellCommandSubstitution suit isShellCommandSubstitution de Secret Guard (« $(…) » ou « `…` », 1 à 512 unités
// UTF-16 sans fin de ligne).
func isShellCommandSubstitution(value []byte) bool {
	trimmed := jsTrim(value)
	var inner []byte
	switch {
	case len(trimmed) >= 3 && trimmed[0] == '$' && trimmed[1] == '(' && trimmed[len(trimmed)-1] == ')':
		inner = trimmed[2 : len(trimmed)-1]
	case len(trimmed) >= 3 && trimmed[0] == '`' && trimmed[len(trimmed)-1] == '`':
		inner = trimmed[1 : len(trimmed)-1]
		if bytes.IndexByte(inner, '`') >= 0 {
			return false
		}
	default:
		return false
	}
	if len(inner) == 0 || bytes.IndexByte(inner, '\r') >= 0 || bytes.IndexByte(inner, '\n') >= 0 {
		return false
	}
	return utf16Units(inner) <= 512
}

var (
	safeLiteralWord   = regexp.MustCompile(reSafeLiteralWord)
	safeTypeName      = regexp.MustCompile(reSafeTypeName)
	safeNullableType  = regexp.MustCompile(reSafeNullableType)
	safeOptionalType  = regexp.MustCompile(reSafeOptionalType)
	regexClosing      = regexp.MustCompile(reRegexClosing)
	regexSyntax       = regexp.MustCompile(reRegexSyntax)
	propertyReference = regexp.MustCompile(rePropertyReference)
	codeReference     = regexp.MustCompile(reCodeReference)
	environmentGetter = regexp.MustCompile(reEnvironmentGetter)
)

// isSafeReference suit isSafeReference de Secret Guard : littéral, type, expression régulière, référence de
// propriété ou de code, lecture d'environnement.
func isSafeReference(value []byte) bool {
	trimmed := jsTrim(value)
	if safeLiteralWord.Match(trimmed) || safeTypeName.Match(trimmed) || safeNullableType.Match(trimmed) ||
		safeOptionalType.Match(trimmed) {
		return true
	}
	if len(trimmed) > 0 && trimmed[0] == '/' {
		if closing := regexClosing.FindIndex(trimmed); closing != nil {
			body := trimmed[1:max(1, closing[0])]
			if regexSyntax.Match(body) {
				return true
			}
		}
	}
	return propertyReference.Match(trimmed) || codeReference.Match(trimmed) || environmentGetter.Match(trimmed)
}

var jsonSchemaTypeDescriptor = regexp.MustCompile(reJSONSchemaTypeDescriptor)

// isJSONSchemaTypeDescriptor suit isJsonSchemaTypeDescriptor de Secret Guard.
func isJSONSchemaTypeDescriptor(p *parsedValue, value []byte, lang language) bool {
	if p.kind != kindUnquoted || !lang.set {
		return false
	}
	if lowered := lang.lowered(); lowered != "json" && lowered != "jsonc" {
		return false
	}
	return jsonSchemaTypeDescriptor.Match(value)
}

var (
	numericLiteral       = regexp.MustCompile(reNumericLiteral)
	expressionKeyword    = regexp.MustCompile(reExpressionKeyword)
	expressionOperator   = regexp.MustCompile(reExpressionOperator)
	typeObjectDescriptor = regexp.MustCompile(reTypeObjectDescriptor)
	typedDefault         = regexp.MustCompile(reTypedDefault)
	identifier           = regexp.MustCompile(reIdentifier)
	secretLikeIdentifier = regexp.MustCompile(reSecretLikeIdentifier)
)

// isClearlyNonLiteralExpression suit isClearlyNonLiteralExpression de Secret Guard.
func (ctx *contextualText) isClearlyNonLiteralExpression(m *assignmentMatch, p *parsedValue, raw []byte, lang language) bool {
	if p.kind != kindUnquoted {
		return false
	}
	text := ctx.text
	value := jsTrim(raw)
	lineStart := ctx.matchLineStart(m)
	if lang.set && !lang.isCodeLike() {
		return false
	}
	if !lang.set {
		externalCodeSyntax := ctx.keywords(keywordsExternalCode).inSlice(text, lineStart, m.end) ||
			bytes.IndexByte(text[m.start:m.end], '{') >= 0
		if !externalCodeSyntax {
			return false
		}
	}
	if numericLiteral.Match(value) {
		return false
	}
	if expressionKeyword.Match(value) || expressionOperator.Match(value) || safeNullableType.Match(value) ||
		safeOptionalType.Match(value) || typeObjectDescriptor.Match(value) ||
		(ctx.keywords(keywordsDeclaration).inSlice(text, lineStart, m.end) && typedDefault.Match(value)) {
		return true
	}
	if identifier.Match(value) {
		return secretLikeIdentifier.Match(value) || ctx.keywords(keywordsStatement).inSlice(text, lineStart, m.end)
	}
	return false
}

// isSymbolicEnumValue suit isSymbolicEnumValue de Secret Guard : membre d'enum dont la valeur est le nom.
func (ctx *contextualText) isSymbolicEnumValue(m *assignmentMatch, key []byte, p *parsedValue, value []byte) bool {
	if p.kind != kindQuoted {
		return false
	}
	if !ctx.keywords(keywordsEnum).inSlice(ctx.text, ctx.matchLineStart(m), m.start) {
		return false
	}
	return jsToLower(value) == symbolicKey(key)
}

func isASCIILower(c byte) bool { return 'a' <= c && c <= 'z' }
func isASCIIUpper(c byte) bool { return 'A' <= c && c <= 'Z' }
func isASCIIDigit(c byte) bool { return '0' <= c && c <= '9' }
func isASCIIAlphanumeric(c byte) bool {
	return isASCIILower(c) || isASCIIUpper(c) || isASCIIDigit(c)
}

// symbolicKey : key.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/[^A-Za-z0-9]+/g, "_").toLowerCase().
func symbolicKey(key []byte) string {
	split := make([]byte, 0, len(key)+8)
	for i := 0; i < len(key); i++ {
		c := key[i]
		if (isASCIILower(c) || isASCIIDigit(c)) && i+1 < len(key) && isASCIIUpper(key[i+1]) {
			split = append(split, c, '_', key[i+1])
			i++
			continue
		}
		split = append(split, c)
	}
	out := make([]byte, 0, len(split))
	for i := 0; i < len(split); {
		c := split[i]
		if isASCIIAlphanumeric(c) {
			if isASCIIUpper(c) {
				c += 'a' - 'A'
			}
			out = append(out, c)
			i++
			continue
		}
		// Une suite de caractères hors [A-Za-z0-9] devient un seul « _ » (un point de code non ASCII, quels que soient
		// ses octets, en fait partie).
		for i < len(split) && !isASCIIAlphanumeric(split[i]) {
			i++
		}
		out = append(out, '_')
	}
	return string(out)
}

// scanCookieCredentials suit scanCookieCredentials de Secret Guard.
func (r *Rules) scanCookieCredentials(v *view, findings []finding) []finding {
	cookie := r.engine[ruleCookie]
	if cookie == nil {
		return findings
	}
	text := v.text
	for _, header := range cookieHeaderPattern.FindAllSubmatchIndex(text, -1) {
		lineStart, line := header[2], text[header[2]:header[3]]
		for _, c := range cookieSecretPattern.FindAllSubmatchIndex(line, -1) {
			value := line[c[4]:c[5]]
			if len(value) == 0 || safeLiteral(value) {
				continue
			}
			findings = append(findings, contextualFinding(v, cookie, lineStart+c[4], lineStart+c[5], "credential_cookie_header"))
		}
	}
	return findings
}

// contextualFinding suit contextualFinding de Secret Guard.
func contextualFinding(v *view, r *rule, viewStart, viewEnd int, reason string) finding {
	reasons := append([]string{reason, "structured_assignment"}, decodingReasons(v.encoding)...)
	return newFinding(v, r, viewStart, viewEnd, r.score-encodingPenalty(v.encoding), reasons)
}

// Bornes de BASIC_AUTH_ARGUMENT (« ([^:\s"']{1,256}):([^\s"']{1,1024}) ») ; la seconde dépasse la limite de RE2.
const (
	basicAuthUserUnits     = 256
	basicAuthPasswordUnits = 1_024
)

// scanBasicAuthArguments suit scanBasicAuthArguments de Secret Guard. Le motif du Pack lit les trois formes de la
// rétro-référence d'origine (groupes 1-2 entre guillemets doubles, 3-4 simples, 5-6 sans guillemets) ; le mot de
// passe, borné à 1 024 unités : entre guillemets, au-delà, pas de correspondance à cette position ; sans guillemets,
// la correspondance s'arrête à la borne, comme la répétition gloutonne de JavaScript.
func (r *Rules) scanBasicAuthArguments(v *view, findings []finding) []finding {
	basic := r.engine[ruleCLIBasicAuth]
	if basic == nil {
		return findings
	}
	text := v.text
	start := lineStartOr(isJSWhitespace)
	for lastIndex := 0; lastIndex <= len(text); {
		m := execFrom(basic.pattern, text, lastIndex, start)
		if m == nil {
			break
		}
		pair := 0
		for pair < 3 && m[2+4*pair] < 0 {
			pair++
		}
		if pair == 3 {
			lastIndex = m[1]
			continue
		}
		userStart, userEnd := m[2+4*pair], m[3+4*pair]
		passwordStart, passwordEnd := m[4+4*pair], m[5+4*pair]
		quoted := pair < 2
		if utf16Units(text[userStart:userEnd]) > basicAuthUserUnits ||
			(quoted && utf16Units(text[passwordStart:passwordEnd]) > basicAuthPasswordUnits) {
			lastIndex = nextRune(text, m[0])
			continue
		}
		if !quoted {
			passwordEnd = passwordStart + prefixOfUnits(text[passwordStart:passwordEnd], basicAuthPasswordUnits)
			lastIndex = passwordEnd
		} else {
			lastIndex = m[1]
		}
		if safeLiteral(text[passwordStart:passwordEnd]) {
			continue
		}
		findings = append(findings, contextualFinding(v, basic, userStart, passwordEnd, "basic_auth_command_argument"))
	}
	return findings
}

// dockerAuthDecodedBytes : borne du décodage de la clé auth (4 096 octets).
const dockerAuthDecodedBytes = 4_096

// scanDockerAuth suit scanDockerAuth de Secret Guard : clé auth dont la valeur base64 décodée est
// « utilisateur:mot de passe » avec un mot de passe ni fictif ni d'exemple.
func (r *Rules) scanDockerAuth(v *view, ctx *contextualText, budget *decodeBudget, findings []finding) ([]finding, error) {
	docker := r.engine[ruleDockerAuth]
	if docker == nil {
		return findings, nil
	}
	text := v.text
	start := lineStartOr(isDockerBoundary)
	for lastIndex := 0; lastIndex <= len(text); {
		m := execFrom(docker.pattern, text, lastIndex, start)
		if m == nil {
			break
		}
		lastIndex = m[1]
		p := ctx.parseAssignmentValue(lastIndex, language{})
		if p != nil {
			lastIndex = max(lastIndex, p.end)
		}
		if p == nil || p.valueEnd == p.start {
			continue
		}
		decoded, ok, err := budget.decodeBase64(string(text[p.start:p.valueEnd]), dockerAuthDecodedBytes)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		separator := bytes.IndexByte([]byte(decoded), ':')
		if separator <= 0 || separator == len(decoded)-1 || safeLiteral([]byte(decoded[separator+1:])) {
			continue
		}
		findings = append(findings, contextualFinding(v, docker, p.start, p.end, "docker_auth_base64_credentials"))
	}
	return findings, nil
}

// contextualText garde, pour une vue, ce que les affectations relisent : fins de ligne, mots-clés, résultats par
// début de ligne, dernières positions cherchées. Chaque requête est en temps constant ou logarithmique, ou reprend une
// recherche là où la précédente s'est arrêtée (requêtes croissantes d'un même parcours).
type contextualText struct {
	text     []byte
	newlines []int
	scanned  bool
	// indexOf : dernière recherche par aiguille (début, résultat).
	searches  map[string]*lastSearch
	lineBreak lastSearch
	// Résultats par début de ligne.
	prefixes     map[prefixKey]prefixInterval
	declarations map[int]bool
	keywordSets  map[keywordSet]*keywordIndex
	// Littéraux d'expression régulière.
	regexEvent   lastSearch
	regexBracket lastBracketRun
	// Heredoc.
	heredocStart    lastSearch
	cumulativeUnits []int32
}

type lastSearch struct {
	from, result int
	valid        bool
}

func newContextualText(text []byte) *contextualText {
	return &contextualText{
		text: text, searches: map[string]*lastSearch{}, prefixes: map[prefixKey]prefixInterval{},
		declarations: map[int]bool{}, keywordSets: map[keywordSet]*keywordIndex{},
		regexBracket: lastBracketRun{bracket: -1},
	}
}

// lineStart : text.lastIndexOf("\n", at) + 1 (un « \n » en at compte).
func (ctx *contextualText) lineStart(at int) int {
	if !ctx.scanned {
		for i, c := range ctx.text {
			if c == '\n' {
				ctx.newlines = append(ctx.newlines, i)
			}
		}
		ctx.scanned = true
	}
	k := sort.SearchInts(ctx.newlines, at+1)
	if k == 0 {
		return 0
	}
	return ctx.newlines[k-1] + 1
}

// indexOf : text.indexOf(needle, from), en reprenant la recherche précédente de la même aiguille.
func (ctx *contextualText) indexOf(needle string, from int) int {
	s := ctx.searches[needle]
	if s == nil {
		s = &lastSearch{}
		ctx.searches[needle] = s
	}
	if s.valid && from >= s.from && (s.result < 0 || s.result >= from) {
		return s.result
	}
	result := -1
	if from <= len(ctx.text) {
		if found := bytes.Index(ctx.text[from:], []byte(needle)); found >= 0 {
			result = from + found
		}
	}
	*s = lastSearch{from: from, result: result, valid: true}
	return result
}

// nextLineBreak : première position ≥ from de « \r » ou « \n », len(text) sinon.
func (ctx *contextualText) nextLineBreak(from int) int {
	s := &ctx.lineBreak
	if s.valid && from >= s.from && s.result >= from {
		return s.result
	}
	result := len(ctx.text)
	for i := from; i < len(ctx.text); i++ {
		if ctx.text[i] == '\r' || ctx.text[i] == '\n' {
			result = i
			break
		}
	}
	*s = lastSearch{from: from, result: result, valid: true}
	return result
}

// prefixKind : expressions ancrées sur le début de ligne, lues à la main (refBareEnvironmentAssignment,
// refInferredShellAssignment, refInferredStructuredAssignment).
type prefixKind int

const (
	// ^\s*(?:(?:export|set)\s+)?[A-Z_][A-Z0-9_]*\s*=\s*$
	prefixBareEnvironment prefixKind = iota
	// ^\s*[a-z_][A-Za-z0-9_]*\s*=\s*$
	prefixShell
	// ^\s*[a-z_][A-Za-z0-9_.-]*\s*:?=\s*$
	prefixStructured
)

type prefixKey struct {
	kind      prefixKind
	lineStart int
}

// prefixInterval : positions de fin admises [low, high] ; ok faux si aucune.
type prefixInterval struct {
	low, high int
	ok        bool
}

// prefixAssignment dit si text[lineStart:end] correspond entièrement à l'expression de kind. Chacune décrit « espaces,
// nom, espaces, séparateur, espaces » sans ambiguïté : les fins admises forment un intervalle, calculé une fois par
// début de ligne.
func (ctx *contextualText) prefixAssignment(kind prefixKind, lineStart, end int) bool {
	key := prefixKey{kind, lineStart}
	interval, known := ctx.prefixes[key]
	if !known {
		interval = assignmentPrefix(ctx.text, lineStart, kind)
		ctx.prefixes[key] = interval
	}
	return interval.ok && end >= interval.low && end <= interval.high
}

func skipJSWhitespace(text []byte, i int) int {
	for i < len(text) {
		r, width := utf8.DecodeRune(text[i:])
		if !isJSWhitespace(r) {
			break
		}
		i += width
	}
	return i
}

func assignmentPrefix(text []byte, i int, kind prefixKind) prefixInterval {
	i = skipJSWhitespace(text, i)
	first := func(c byte) bool { return c == '_' || isASCIILower(c) }
	rest := func(c byte) bool { return isWordByte(c) }
	switch kind {
	case prefixBareEnvironment:
		for _, word := range []string{"export", "set"} {
			if bytes.HasPrefix(text[i:], []byte(word)) {
				if after := skipJSWhitespace(text, i+len(word)); after > i+len(word) {
					i = after
				}
				break
			}
		}
		first = func(c byte) bool { return c == '_' || isASCIIUpper(c) }
		rest = func(c byte) bool { return c == '_' || isASCIIUpper(c) || isASCIIDigit(c) }
	case prefixStructured:
		rest = func(c byte) bool { return isWordByte(c) || c == '.' || c == '-' }
	}
	if i >= len(text) || !first(text[i]) {
		return prefixInterval{}
	}
	i++
	for i < len(text) && rest(text[i]) {
		i++
	}
	i = skipJSWhitespace(text, i)
	if kind == prefixStructured && isAt(text, i, ':') {
		i++
	}
	if !isAt(text, i, '=') {
		return prefixInterval{}
	}
	i++
	return prefixInterval{low: i, high: skipJSWhitespace(text, i), ok: true}
}

var codeDeclaration = regexp.MustCompile(reInferredCodeDeclaration)

// codeDeclaration suit le second test de inferredCodeAssignment (reInferredCodeDeclaration) sur
// text[lineStart:end]. Aucune partie du motif avant « \s*=\s*$ » n'admet « = » : la tranche doit contenir un seul
// « = », le premier de la ligne, suivi d'espaces seulement ; l'expression est alors évaluée une fois par début de
// ligne, sur la tranche qui finit à ce « = ».
func (ctx *contextualText) codeDeclaration(lineStart, end int) bool {
	text := ctx.text
	equals := ctx.indexOf("=", lineStart)
	if equals < 0 || equals >= end || skipJSWhitespace(text, equals+1) < end {
		return false
	}
	result, known := ctx.declarations[lineStart]
	if !known {
		result = codeDeclaration.Match(surrogateWidened(text[lineStart : equals+1]))
		ctx.declarations[lineStart] = result
	}
	return result
}

// surrogateWidened remplace chaque point de code hors du plan multilingue de base par deux U+E000 : la répétition
// « {1,128} » d'une classe qui les admet tous deux compte alors des unités UTF-16, comme JavaScript. Aucune autre
// classe de reInferredCodeDeclaration n'admet l'un sans l'autre.
func surrogateWidened(text []byte) []byte {
	widened := false
	for _, c := range text {
		if c >= 0xF0 {
			widened = true
			break
		}
	}
	if !widened {
		return text
	}
	out := make([]byte, 0, len(text)+16)
	for i := 0; i < len(text); {
		r, width := utf8.DecodeRune(text[i:])
		if r > 0xFFFF {
			out = utf8.AppendRune(utf8.AppendRune(out, 0xE000), 0xE000)
		} else {
			out = append(out, text[i:i+width]...)
		}
		i += width
	}
	return out
}

// keywordSet : listes de mots-clés cherchés par \b(?:…)\b dans un préfixe de ligne.
type keywordSet int

const (
	keywordsInferredCode keywordSet = iota
	keywordsExternalCode
	keywordsDeclaration
	keywordsStatement
	keywordsEnum
)

var keywordLists = map[keywordSet][]string{
	keywordsInferredCode: {"const", "final", "let", "mut", "readonly", "return", "static", "type", "interface", "enum", "var"},
	keywordsExternalCode: {"const", "let", "var", "return", "readonly", "public", "private", "protected", "type", "interface", "enum"},
	keywordsDeclaration:  {"const", "let", "var", "readonly", "public", "private", "protected"},
	keywordsStatement:    {"const", "let", "var", "return", "readonly", "public", "private", "protected"},
	keywordsEnum:         {"enum"},
}

// keywordIndex : occurrences d'un mot-clé précédées d'une limite de mot ; « fortes » si suivies d'un caractère qui
// n'est pas de mot (limite dans toute tranche qui les contient). minStrongEnd[k] : plus petite fin d'une occurrence
// forte d'indice ≥ k.
type keywordIndex struct {
	words        []string
	starts       []int
	minStrongEnd []int
}

func (ctx *contextualText) keywords(set keywordSet) *keywordIndex {
	if index := ctx.keywordSets[set]; index != nil {
		return index
	}
	words := keywordLists[set]
	index := &keywordIndex{words: words}
	text := ctx.text
	var ends []int
	for i := 0; i < len(text); i++ {
		if !isASCIILower(text[i]) || (i > 0 && isWordByte(text[i-1])) {
			continue
		}
		for _, word := range words {
			end := i + len(word)
			if !bytes.HasPrefix(text[i:], []byte(word)) {
				continue
			}
			index.starts = append(index.starts, i)
			if end == len(text) || !isWordByte(text[end]) {
				ends = append(ends, end)
			} else {
				ends = append(ends, -1)
			}
		}
	}
	index.minStrongEnd = make([]int, len(ends)+1)
	index.minStrongEnd[len(ends)] = -1
	for k := len(ends) - 1; k >= 0; k-- {
		next := index.minStrongEnd[k+1]
		switch {
		case ends[k] < 0:
			index.minStrongEnd[k] = next
		case next < 0 || ends[k] < next:
			index.minStrongEnd[k] = ends[k]
		default:
			index.minStrongEnd[k] = next
		}
	}
	ctx.keywordSets[set] = index
	return index
}

// inSlice dit si \b(?:mots)\b reconnaît text[lineStart:end] (lineStart suit « \n » ou est 0 : la limite de début
// est celle du texte entier ; en fin de tranche, un mot-clé qui finit exactement en end est suivi d'une limite).
func (k *keywordIndex) inSlice(text []byte, lineStart, end int) bool {
	first := sort.SearchInts(k.starts, lineStart)
	if strong := k.minStrongEnd[first]; strong >= 0 && strong <= end {
		return true
	}
	for _, word := range k.words {
		at := end - len(word)
		if at >= lineStart && bytes.HasPrefix(text[at:end], []byte(word)) && (at == 0 || !isWordByte(text[at-1])) {
			return true
		}
	}
	return false
}

// lastBracketRun : dernier parcours d'un littéral d'expression régulière depuis un crochet.
type lastBracketRun struct {
	bracket, result int
	ok              bool
}

// regexLiteralClose suit la lecture d'un littéral d'expression régulière de parseAssignmentValue : depuis la barre en
// start, première barre non échappée hors classe ; échec à la première fin de ligne (« \r », « \n ») ou à la fin du
// texte. Linéaire : l'échappement d'un caractère ne dépend que des barres obliques inverses qui le précèdent, et
// l'état « dans une classe » après un crochet non échappé ne dépend que de ce crochet ; le parcours depuis un crochet
// est donc le même quel que soit le littéral qui l'atteint, et il est gardé.
func (ctx *contextualText) regexLiteralClose(start int) (int, bool) {
	event, kind := ctx.nextRegexEvent(start + 1)
	switch kind {
	case regexEventSlash:
		return event, true
	case regexEventBracket:
		if closing, ok := ctx.closeFromBracket(event); ok {
			return closing, true
		}
	}
	return 0, false
}

type regexEvent int

const (
	regexEventNone regexEvent = iota
	regexEventSlash
	regexEventBracket
	regexEventLineBreak
)

// escapedAt : nombre impair de « \ » juste avant i.
func escapedAt(text []byte, i int) bool {
	count := 0
	for k := i - 1; k >= 0 && text[k] == '\\'; k-- {
		count++
	}
	return count%2 == 1
}

// nextRegexEvent : première position ≥ from d'une barre ou d'un crochet non échappés, ou d'une fin de ligne.
func (ctx *contextualText) nextRegexEvent(from int) (int, regexEvent) {
	text := ctx.text
	s := &ctx.regexEvent
	position := -1
	if s.valid && from >= s.from && (s.result < 0 || s.result >= from) {
		position = s.result
	} else {
		for i := from; i < len(text); i++ {
			c := text[i]
			if c == '\r' || c == '\n' || ((c == '/' || c == '[' || c == ']') && !escapedAt(text, i)) {
				position = i
				break
			}
		}
		*s = lastSearch{from: from, result: position, valid: true}
	}
	if position < 0 {
		return 0, regexEventNone
	}
	switch text[position] {
	case '/':
		return position, regexEventSlash
	case '[', ']':
		return position, regexEventBracket
	}
	return position, regexEventLineBreak
}

// closeFromBracket : suite du parcours depuis le crochet en b (« [ » : dans une classe, « ] » : hors classe).
func (ctx *contextualText) closeFromBracket(b int) (int, bool) {
	run := &ctx.regexBracket
	if run.bracket >= 0 && b >= run.bracket && (b < run.result || (!run.ok && b <= run.result)) {
		return run.result, run.ok
	}
	text := ctx.text
	inClass := text[b] == '['
	result, ok := len(text), false
	for i := b + 1; i < len(text); i++ {
		c := text[i]
		if c == '\r' || c == '\n' {
			result = i
			break
		}
		if (c != '/' && c != '[' && c != ']') || escapedAt(text, i) {
			continue
		}
		if c == '[' {
			inClass = true
		} else if c == ']' {
			inClass = false
		} else if !inClass {
			result, ok = i, true
			break
		}
	}
	*run = lastBracketRun{bracket: b, result: result, ok: ok}
	return result, ok
}
