// Familles de règles du moteur de détection : règles « motif seul » et jwt, clés privées,
// URL à identifiants, entropie. Les affectations contextuelles sont dans contextual.go.
//
// Portage en Go de scanFixedRules, scanCredentialUrls et scanEntropy de secret-guard/packages/core/src/rules.ts
// (Apache-2.0, origine, avis et modifications dans UPSTREAM.md). Chaque fonction lit une vue, rend des constats en
// octets de la source et ne garde jamais la valeur détectée au-delà de l'analyse. Toutes sont linéaires en la taille
// de la vue (aucune recherche relancée depuis le début, aucun parcours répété d'une même suite de caractères).

package detect

import (
	"bytes"
	"regexp"
	"sort"
	"unicode/utf8"
)

// scanFixedRules suit scanFixedRules de Secret Guard : en-têtes de clé privée, puis règles « motif seul » dans
// l'ordre du Pack. allowStructured faux : les règles à validateur (décodage) ne s'exécutent pas. Budget de décodage
// épuisé par un validateur : errDecodeBudgetExhausted (analyse incomplète).
func (r *Rules) scanFixedRules(v *view, budget *decodeBudget, allowStructured bool) ([]finding, error) {
	findings := r.scanPrivateKeys(v)
	for _, fixed := range r.fixed {
		if fixed.validator != nil && !allowStructured {
			continue
		}
		var err error
		if fixed.id == ruleJWT {
			findings, err = scanJWT(v, fixed, budget, findings)
		} else {
			findings, err = scanFixedPattern(v, fixed, budget, findings)
		}
		if err != nil {
			return nil, err
		}
	}
	return findings, nil
}

// scanPrivateKeys : en-tête PEM de clé privée jusqu'à sa marque de fin, ou jusqu'à la fin du texte si elle manque
// (private_key_pem_incomplete), comme Secret Guard.
func (r *Rules) scanPrivateKeys(v *view) []finding {
	complete, incomplete := r.engine[rulePrivateKeyComplete], r.engine[rulePrivateKeyIncomplete]
	header := complete
	if header == nil {
		header = incomplete
	}
	if header == nil {
		return nil
	}
	var findings []finding
	text := v.text
	for lastIndex := 0; ; {
		m := execFrom(header.pattern, text, lastIndex, nil)
		if m == nil {
			return findings
		}
		lastIndex = m[1]
		endMarker := make([]byte, 0, 20+m[3]-m[2])
		endMarker = append(endMarker, "-----END "...)
		endMarker = append(endMarker, text[m[2]:m[3]]...)
		endMarker = append(endMarker, "-----"...)
		viewEnd := len(text)
		found := bytes.Index(text[lastIndex:], endMarker)
		matched, reason := incomplete, "private_key_header_without_bounded_end"
		if found >= 0 {
			viewEnd = lastIndex + found + len(endMarker)
			matched, reason = complete, "complete_private_key_block"
		}
		if matched != nil {
			reasons := append(encodingReasons(v.encoding), reason)
			findings = append(findings, newFinding(v, matched, m[0], viewEnd, matched.score-encodingPenalty(v.encoding), reasons))
		}
		lastIndex = max(lastIndex, viewEnd)
	}
}

// scanFixedPattern exécute une règle « motif seul » du Pack : chaque correspondance (matchAll), valeur détectée =
// groupe capturant 1 s'il a participé, sinon la correspondance entière (capturedRange de Secret Guard, qui la cherche
// par lastIndexOf) ; valeur fictive ou exemple public ignorés ; bornes minLength/maxLength (unités UTF-16, 0 =
// absente) ; validateur nommé.
func scanFixedPattern(v *view, r *rule, budget *decodeBudget, findings []finding) ([]finding, error) {
	text := v.text
	capture := r.pattern.NumSubexp() >= 1
	for _, m := range r.pattern.FindAllSubmatchIndex(text, -1) {
		start, end := m[0], m[1]
		if capture && m[2] >= 0 {
			value := text[m[2]:m[3]]
			start = m[0] + max(0, bytes.LastIndex(text[m[0]:m[1]], value))
			end = start + len(value)
		}
		value := text[start:end]
		if safeLiteral(value) || !withinBounds(value, r.minLength, r.maxLength) {
			continue
		}
		if r.validator != nil {
			ok, err := r.validator(string(value), budget)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
		}
		findings = append(findings, newFinding(v, r, start, end, r.score-encodingPenalty(v.encoding), encodingReasons(v.encoding)))
	}
	return findings, nil
}

// withinBounds applique les bornes minLength/maxLength du Pack à la valeur détectée, en unités UTF-16 (0 = absente).
func withinBounds(value []byte, minLength, maxLength int) bool {
	if minLength == 0 && maxLength == 0 {
		return true
	}
	units := utf16Units(value)
	return (minLength == 0 || units >= minLength) && (maxLength == 0 || units <= maxLength)
}

// Segments d'un JWT (motif d'origine /\beyJ[A-Za-z0-9_-]{4,2048}\.eyJ[A-Za-z0-9_-]{4,8192}\.[A-Za-z0-9_-]{8,4096}\b/g,
// au-delà de la limite de RE2 : le Pack porte la somme, 24 à 14 344 ; le moteur, chaque segment).
const (
	jwtHeaderMin, jwtHeaderMax       = 4, 2_048
	jwtPayloadMin, jwtPayloadMax     = 4, 8_192
	jwtSignatureMin, jwtSignatureMax = 8, 4_096
)

func isJWTCharacter(c byte) bool { return isWordByte(c) || c == '-' }

// runEnds rend la fin de la suite de caractères de JWT qui contient une position ; les requêtes d'une même instance
// sont croissantes, chaque suite n'est parcourue qu'une fois.
type runEnds struct {
	text     []byte
	low, end int
}

func (r *runEnds) at(i int) int {
	if i >= r.low && i < r.end {
		return r.end
	}
	end := i
	for end < len(r.text) && isJWTCharacter(r.text[end]) {
		end++
	}
	r.low, r.end = i, end
	return end
}

// jwtMatcher reconnaît le motif jwt d'origine à une position, segments bornés comme en JavaScript : les deux
// premiers segments sont des suites entières (le point qui suit n'est pas un caractère de JWT), la signature est la
// plus longue d'au plus 4 096 caractères qui finit sur une limite de mot.
type jwtMatcher struct {
	text                       []byte
	header, payload, signature runEnds
	// Dernière signature évaluée : début, fin rendue (-1 : aucune).
	signatureStart, signatureEnd int
}

func newJWTMatcher(text []byte) *jwtMatcher {
	return &jwtMatcher{
		text: text, header: runEnds{text: text}, payload: runEnds{text: text}, signature: runEnds{text: text},
		signatureStart: -1,
	}
}

// wordBoundaryAt dit si \b reconnaît la position q (ASCII, comme JavaScript sans drapeau u).
func wordBoundaryAt(text []byte, q int) bool {
	before := q > 0 && isWordByte(text[q-1])
	after := q < len(text) && isWordByte(text[q])
	return before != after
}

// at rend la fin de la correspondance qui commence en c (« eyJ » précédé d'une limite de mot), ou faux.
func (j *jwtMatcher) at(c int) (int, bool) {
	text := j.text
	i := c + 3
	end := j.header.at(i)
	if n := end - i; n < jwtHeaderMin || n > jwtHeaderMax || !isAt(text, end, '.') || !bytes.HasPrefix(text[end+1:], []byte("eyJ")) {
		return 0, false
	}
	i = end + 4
	end = j.payload.at(i)
	if n := end - i; n < jwtPayloadMin || n > jwtPayloadMax || !isAt(text, end, '.') {
		return 0, false
	}
	i = end + 1
	if i != j.signatureStart {
		j.signatureStart, j.signatureEnd = i, -1
		runEnd := j.signature.at(i)
		for k := min(runEnd-i, jwtSignatureMax); k >= jwtSignatureMin; k-- {
			if wordBoundaryAt(text, i+k) {
				j.signatureEnd = i + k
				break
			}
		}
	}
	return j.signatureEnd, j.signatureEnd >= 0
}

// nextJWT rend la prochaine correspondance du motif jwt d'origine à partir de pos (matchAll), ou faux.
func nextJWT(matcher *jwtMatcher, pos int) (int, int, bool) {
	text := matcher.text
	prefix := []byte("eyJ")
	for pos < len(text) {
		found := bytes.Index(text[pos:], prefix)
		if found < 0 {
			return 0, 0, false
		}
		c := pos + found
		if wordBoundaryBefore(text, c) {
			if end, ok := matcher.at(c); ok {
				return c, end, true
			}
		}
		pos = c + 1
	}
	return 0, 0, false
}

// scanJWT exécute la règle jwt : chaque correspondance du motif d'origine, valeur fictive ignorée, bornes du Pack,
// validateur de structure.
func scanJWT(v *view, r *rule, budget *decodeBudget, findings []finding) ([]finding, error) {
	text := v.text
	matcher := newJWTMatcher(text)
	for pos := 0; ; {
		c, end, ok := nextJWT(matcher, pos)
		if !ok {
			return findings, nil
		}
		pos = end
		value := text[c:end]
		if safeLiteral(value) || !withinBounds(value, r.minLength, r.maxLength) {
			continue
		}
		if r.validator != nil {
			valid, err := r.validator(string(value), budget)
			if err != nil {
				return nil, err
			}
			if !valid {
				continue
			}
		}
		findings = append(findings, newFinding(v, r, c, end, r.score-encodingPenalty(v.encoding), encodingReasons(v.encoding)))
	}
}

// credentialURLTailMax est la borne de la queue d'une URL à identifiants (« [^\s"'<>]{1,2048} »).
const credentialURLTailMax = 2_048

var (
	credentialURLPrefix = regexp.MustCompile(reCredentialURLPrefix)
	databaseScheme      = regexp.MustCompile(reDatabaseScheme)
)

func isCredentialURLTail(r rune) bool {
	return !isJSWhitespace(r) && r != '"' && r != '\'' && r != '<' && r != '>'
}

// scanCredentialURLs suit scanCredentialUrls de Secret Guard : URL dont le mot de passe (après analyse comme le
// constructeur URL de JavaScript, puis decodeURIComponent) n'est ni vide, ni fictif, ni un exemple public.
func (r *Rules) scanCredentialURLs(v *view) []finding {
	databaseRule, basicRule := r.engine[ruleDatabaseURL], r.engine[ruleBasicAuthURL]
	if databaseRule == nil && basicRule == nil {
		return nil
	}
	var findings []finding
	text := v.text
	for pos := 0; pos <= len(text); {
		m := execFrom(credentialURLPrefix, text, pos, wordStart{})
		if m == nil {
			break
		}
		tailStart := m[1]
		tailEnd := tailStart
		for units := 0; tailEnd < len(text); {
			c, width := utf8.DecodeRune(text[tailEnd:])
			u := 1
			if c > 0xFFFF {
				u = 2
			}
			if !isCredentialURLTail(c) || units+u > credentialURLTailMax {
				break
			}
			units += u
			tailEnd += width
		}
		if tailEnd == tailStart {
			// « {1,2048} » : rien après « :// » ; JavaScript reprend au caractère suivant.
			pos = nextRune(text, m[0])
			continue
		}
		pos = tailEnd
		candidate := stripTrailingURLPunctuation(text[m[0]:tailEnd])
		password, ok := urlPassword(candidate)
		if !ok || password == "" {
			continue
		}
		if decoded, ok := decodeURIComponent(password); ok {
			password = decoded
		}
		if safeLiteral([]byte(password)) {
			continue
		}
		matched := basicRule
		if databaseScheme.Match(candidate) {
			matched = databaseRule
		}
		if matched == nil {
			continue
		}
		reasons := append([]string{"credential_bearing_url"}, decodingReasons(v.encoding)...)
		findings = append(findings, newFinding(v, matched, m[0], m[0]+len(candidate), matched.score-encodingPenalty(v.encoding), reasons))
	}
	return findings
}

// stripTrailingURLPunctuation suit stripTrailingUrlPunctuation de Secret Guard (/[),;\]}]+$/).
func stripTrailingURLPunctuation(value []byte) []byte {
	end := len(value)
	for end > 0 {
		switch value[end-1] {
		case ')', ',', ';', ']', '}':
			end--
			continue
		}
		break
	}
	return value[:end]
}

// Exclusions de l'entropie (entropyExcluded de Secret Guard).
var (
	hexadecimalPattern       = regexp.MustCompile(reHexadecimal)
	uuidPattern              = regexp.MustCompile(reUUID)
	sriDigestPattern         = regexp.MustCompile(reSRIDigest)
	ulidPattern              = regexp.MustCompile(reULID)
	publicStripePattern      = regexp.MustCompile(rePublicStripeIdentifier)
	toolUsePattern           = regexp.MustCompile(reToolUseIdentifier)
	redactedMarkerPattern    = regexp.MustCompile(reRedactedMarker)
	pathLikePattern          = regexp.MustCompile(rePathLike)
	shellEnvironmentPathForm = regexp.MustCompile(reShellEnvironmentPath)
)

// base64Alphabet est la valeur exclue de l'entropie : l'alphabet base64 lui-même.
const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func entropyExcluded(value []byte) bool {
	if string(value) == base64Alphabet || uuidPattern.Match(value) {
		return true
	}
	if hexadecimalPattern.Match(value) {
		switch len(value) {
		case 32, 40, 64, 96, 128:
			return true
		}
	}
	return sriDigestPattern.Match(value) || ulidPattern.Match(value) || publicStripePattern.Match(value) ||
		toolUsePattern.Match(value) || redactedMarkerPattern.Match(value) || pathLikePattern.Match(value) ||
		safeLiteral(value)
}

// isShellEnvironmentPath suit isShellEnvironmentPath de Secret Guard : « $NOM/chemin » ou « $env:NOM/chemin ». Les
// cinq unités qui précèdent valent « $env: » sans la casse seulement si ce sont cinq octets ASCII.
func isShellEnvironmentPath(text []byte, start int, value []byte) bool {
	sigil := start > 0 && text[start-1] == '$'
	if !sigil && start >= 5 {
		sigil = string(bytes.ToLower(text[start-5:start])) == "$env:"
	}
	return sigil && shellEnvironmentPathForm.Match(value)
}

// entropyBits suit shannonEntropy de Secret Guard sur l'étendue [start, end) d'une vue : fréquence de chaque point de
// code (un substitut UTF-16 isolé est un caractère distinct de U+FFFD), divisée par la longueur en unités UTF-16,
// sommée dans l'ordre de première apparition comme l'itération d'une Map JavaScript.
func entropyBits(v *view, start, end int) float64 {
	length := 0
	type entry struct {
		key   int32
		count int
	}
	var order []entry
	index := map[int32]int{}
	// Premier substitut isolé de l'étendue, par recherche dichotomique : un parcours depuis le début de la vue serait
	// quadratique sur une vue riche en substituts (un parcours par candidat).
	lone := v.lone[sort.Search(len(v.lone), func(k int) bool { return int(v.lone[k].pos) >= start }):]
	for i := start; i < end; {
		c, width := utf8.DecodeRune(v.text[i:end])
		key := c
		if len(lone) > 0 && int(lone[0].pos) == i {
			key = unicode16Key(lone[0].unit)
			lone = lone[1:]
		}
		if c > 0xFFFF {
			length += 2
		} else {
			length++
		}
		if k, ok := index[key]; ok {
			order[k].count++
		} else {
			index[key] = len(order)
			order = append(order, entry{key: key, count: 1})
		}
		i += width
	}
	if length == 0 {
		return 0
	}
	entropy := 0.0
	for _, e := range order {
		probability := float64(e.count) / float64(length)
		entropy -= float64(probability * jsLog2(probability))
	}
	return entropy
}

// unicode16Key distingue un substitut isolé de tout point de code.
func unicode16Key(unit uint16) int32 { return 0x110000 + int32(unit) }

// hasStrongEntropy suit hasStrongEntropy de Secret Guard (16 unités au moins ; seuil 3 pour l'hexadécimal, 4,3 sinon).
func hasStrongEntropy(v *view, start, end int) bool {
	value := v.text[start:end]
	if utf16Units(value) < 16 {
		return false
	}
	threshold := 4.3
	if hexadecimalPattern.Match(value) {
		threshold = 3
	}
	return entropyBits(v, start, end) >= threshold
}

// scanEntropy suit scanEntropy de Secret Guard : suite de caractères base64 de forte entropie, avertissement seul.
func (r *Rules) scanEntropy(v *view) []finding {
	entropy := r.engine[ruleHighEntropy]
	if entropy == nil {
		return nil
	}
	var findings []finding
	text := v.text
	for _, m := range entropy.pattern.FindAllIndex(text, -1) {
		value := text[m[0]:m[1]]
		if entropyExcluded(value) || isShellEnvironmentPath(text, m[0], value) || !hasStrongEntropy(v, m[0], m[1]) {
			continue
		}
		score := entropy.score
		reasons := []string{"high_entropy_shape", "unanchored_entropy_is_warning_only"}
		if v.encoding == EncodingNormalized {
			reasons = append(reasons, "unicode_normalization")
		} else {
			score -= encodingPenalty(v.encoding)
		}
		findings = append(findings, newFinding(v, entropy, m[0], m[1], score, reasons))
	}
	return findings
}
