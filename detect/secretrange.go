// SPDX-License-Identifier: Apache-2.0

// Partie secrète d'un constat : ce qu'un Substitut remplace (SecretRange, Rules.FirstLineSecretEnd).
//
// Extension propre à ce module, sans origine dans Secret Guard (avis dans UPSTREAM.md). Ces primitives lisent les
// règles et la forme des valeurs (URL à identifiants, en-tête Authorization, bloc PEM, jeton coupé) : elles restent
// dans le moteur, sous Apache-2.0. L'expurgation qui les assemble (fusion, élargissements, Empreintes locales,
// positions UTF-16) est le module github.com/xsom-consulting/secret-guard/expurgation, sous une autre licence (README,
// « Licences »).

package detect

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// SecretRange rend la partie secrète [start, end) de l'étendue d'un constat f de content, en octets de content, celle
// que remplace un Substitut (module expurgation) :
//   - URL à identifiants : le mot de passe de l'information utilisateur ;
//   - cli_basic_auth : le mot de passe après le premier « : » ;
//   - contextual_access_token, ou constat qui suit une clé Authorization, dont la valeur commence par un schéma
//     d'authentification (« Bearer », « Basic », « Token », sans la casse, puis une espace) : ce qui suit le schéma,
//     jusqu'au premier guillemet ou à la première barre oblique inverse (authValueLength) ;
//   - private_key_pem : le corps entre la ligne BEGIN et la ligne END ; private_key_pem_incomplete : ce qui suit la
//     ligne BEGIN ;
//   - tout autre constat : l'étendue entière.
//
// Une étendue dont la forme n'est pas exactement celle de sa règle (étendue née de la fusion de plusieurs règles, ou
// trouvée dans une vue décodée ou normalisée) est remplacée en entière. Le schéma d'authentification, mot public, est
// gardé pour une étendue fusionnée qui suit une clé Authorization.
//
// L'étendue de f doit être dans content (0 ≤ ByteStart ≤ ByteEnd ≤ len(content)) ; sinon l'étendue de f est rendue
// telle quelle, sans lecture.
func SecretRange(content []byte, f Finding) (int, int) {
	if f.ByteStart < 0 || f.ByteEnd < f.ByteStart || f.ByteEnd > len(content) {
		return f.ByteStart, f.ByteEnd
	}
	span := content[f.ByteStart:f.ByteEnd]
	if f.RuleID == "contextual_access_token" || (!isCustomFinding(f) && followsAuthorizationKey(content, f.ByteStart)) {
		if end, ok := authSchemeEnd(span); ok {
			if length := authValueLength(span[end:]); length > 0 {
				return f.ByteStart + end, f.ByteStart + end + length
			}
			return f.ByteStart + end, f.ByteEnd
		}
	}
	var start, end int
	var ok bool
	switch f.RuleID {
	case ruleDatabaseURL, ruleBasicAuthURL:
		start, end, ok = urlPasswordRange(span)
		if !ok {
			start, end, ok = brokenURLPasswordRange(span)
		}
	case ruleCLIBasicAuth:
		start, end, ok = basicAuthPasswordRange(span)
	case rulePrivateKeyComplete:
		start, end, ok = pemBodySpan(span, true)
	case rulePrivateKeyIncomplete:
		start, end, ok = pemBodySpan(span, false)
	}
	if !ok || end <= start {
		return f.ByteStart, f.ByteEnd
	}
	return f.ByteStart + start, f.ByteStart + end
}

// FirstLineSecretEnd rend la fin de la première ligne de l'étendue d'un constat f de content, d'une règle « motif seul » de rules
// (constat représentatif d'une étendue fusionnée par dedupeOverlaps compris) quand l'étendue passe une fin de ligne
// (« \n », « \r ») et que :
//   - la partie avant la première fin de ligne est à elle seule, exactement, une valeur de la règle (scanFixedPattern ou
//     scanJWT sur cette seule partie : motif, valeur fictive, bornes, validateur) ;
//   - l'étendue s'arrête, dans content, devant un séparateur d'affectation ou de commande (« = », « : », espace,
//     tabulation) : ce qu'elle prend sur la ligne suivante est un mot de cette ligne (« export », nom d'une variable
//     d'un fichier .env), et non la suite d'un jeton coupé ; ou bien ce qu'elle prend après la fin de ligne (fins de
//     ligne et indentation de la vue jointe retirées) n'est fait que de caractères de jeton et n'a pas la forme d'une
//     suite de jeton (looksLikeWrappedTail) : mot seul sur sa ligne, comme « fi », « done », « EOF » ou « end », que
//     l'expurgation retirait avec le jeton (v0.5.2).
//
// L'étendue vient alors d'une vue jointe (lineWrappedFixedViews) qui a recollé à un jeton complet le premier mot de la
// ligne suivante : seule la première ligne est remplacée, la fin de ligne et la ligne suivante sont gardées. Sinon
// (secret réellement coupé par un retour à la ligne, règle sans motif, étendue d'une autre forme, analyse du segment en
// échec), faux : l'étendue entière est remplacée.
//
// Règles nil ou non chargées, constat d'un Pack de règles du client ou étendue hors de content : faux.
func (rules *Rules) FirstLineSecretEnd(content []byte, f Finding) (int, bool) {
	if rules == nil || !rules.loaded || isCustomFinding(f) || f.ByteStart < 0 || f.ByteEnd < f.ByteStart || f.ByteEnd > len(content) {
		return 0, false
	}
	span := content[f.ByteStart:f.ByteEnd]
	lineEnd := bytes.IndexAny(span, "\r\n")
	if lineEnd <= 0 {
		return 0, false
	}
	stopsAtSeparator := f.ByteEnd < len(content) && strings.IndexByte("=: \t", content[f.ByteEnd]) >= 0
	if !stopsAtSeparator {
		continuation, ok := joinedContinuation(span[lineEnd:])
		if !ok || looksLikeWrappedTail(continuation) {
			return 0, false
		}
	}
	var fixed *rule
	for _, r := range rules.fixed {
		if r.id == f.RuleID {
			fixed = r
			break
		}
	}
	if fixed == nil || fixed.pattern == nil {
		return 0, false
	}
	segment := span[:lineEnd]
	scanRule := scanFixedPattern
	if fixed.id == ruleJWT {
		scanRule = scanJWT
	}
	found, err := scanRule(identityView(segment), fixed, &decodeBudget{}, nil)
	if err != nil {
		return 0, false
	}
	for _, candidate := range found {
		if candidate.start == 0 && candidate.end == len(segment) {
			return f.ByteStart + lineEnd, true
		}
	}
	return 0, false
}

// joinedContinuation rend ce qu'une étendue prend après sa première fin de ligne, sans les fins de ligne ni
// l'indentation (au plus maxJoinedIndentation espaces ou tabulations après chaque fin de ligne) que retire la vue
// jointe. Faux si un autre caractère qu'un caractère de jeton (isFixedTokenCharacter) y figure : l'étendue n'est pas
// alors un jeton recollé à la suite de la ligne suivante.
func joinedContinuation(rest []byte) ([]byte, bool) {
	var out []byte
	for i := 0; i < len(rest); {
		if rest[i] == '\r' || rest[i] == '\n' {
			i = skipLineWrap(rest, i)
			continue
		}
		if !isFixedTokenCharacter(rest[i]) {
			return nil, false
		}
		out = append(out, rest[i])
		i++
	}
	return out, len(out) > 0
}

// looksLikeWrappedTail dit si une suite recollée à un jeton complet a la forme de la fin d'un jeton coupé plutôt que
// d'un mot de la ligne suivante : un chiffre, « + » ou « / » (base64), au moins trois changements de casse (sans
// compter celui d'une majuscule initiale : « aZqK » en a trois, un mot en casse de chameau deux par bosse jusqu'à la
// suivante, « camelCase » deux), ou 24 caractères ou plus. Un mot court en
// lettres d'une seule casse ou en majuscule initiale (« fi », « done », « EOF », « End ») n'a pas cette forme. Une
// suite de jeton qui ne l'a pas (quelques lettres) reste en clair : prix accepté pour ne pas retirer une ligne de code.
func looksLikeWrappedTail(tail []byte) bool {
	if len(tail) >= 24 {
		return true
	}
	changes := 0
	for i, c := range tail {
		switch {
		case '0' <= c && c <= '9', c == '+', c == '/':
			return true
		}
		if i >= 1 && isASCIILetter(c) && isASCIILetter(tail[i-1]) && isUpperASCII(c) != isUpperASCII(tail[i-1]) &&
			(i > 1 || !isUpperASCII(tail[0])) {
			changes++
		}
	}
	return changes >= 3
}

func isASCIILetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

func isUpperASCII(c byte) bool { return 'A' <= c && c <= 'Z' }

// urlPasswordRange rend l'étendue du mot de passe d'une URL à identifiants, si span est exactement un candidat de
// scanCredentialURLs (schéma, « :// », caractères de queue, sans ponctuation finale) dont le mot de passe est non vide.
func urlPasswordRange(span []byte) (int, int, bool) {
	colon := bytes.IndexByte(span, ':')
	if colon <= 0 || len(span) < colon+3 || span[colon+1] != '/' || span[colon+2] != '/' {
		return 0, 0, false
	}
	for _, c := range span[:colon] {
		if !isASCIIAlphanumeric(c) && c != '+' && c != '-' && c != '.' {
			return 0, 0, false
		}
	}
	for i := colon + 3; i < len(span); {
		r, width := utf8.DecodeRune(span[i:])
		if !isCredentialURLTail(r) {
			return 0, 0, false
		}
		i += width
	}
	if len(stripTrailingURLPunctuation(span)) != len(span) {
		return 0, 0, false
	}
	if password, ok := urlPassword(span); !ok || password == "" {
		return 0, 0, false
	}
	// Même lecture que urlPassword : autorité jusqu'à « / », « ? », « # » (« \ » d'un schéma spécial), après les
	// barres ignorées d'un schéma spécial ; information utilisateur jusqu'au dernier « @ » ; mot de passe après le
	// premier « : ».
	special := specialSchemes[strings.ToLower(string(span[:colon]))]
	restStart := colon + 3
	if special {
		for restStart < len(span) && (span[restStart] == '/' || span[restStart] == '\\') {
			restStart++
		}
	}
	authorityEnd := len(span)
	for i := restStart; i < len(span); i++ {
		if c := span[i]; c == '/' || c == '?' || c == '#' || (special && c == '\\') {
			authorityEnd = i
			break
		}
	}
	at := bytes.LastIndexByte(span[restStart:authorityEnd], '@')
	if at < 0 {
		return 0, 0, false
	}
	userinfoEnd := restStart + at
	separator := bytes.IndexByte(span[restStart:userinfoEnd], ':')
	if separator < 0 {
		return 0, 0, false
	}
	if !isPlainUsername(span[restStart : restStart+separator]) {
		// Nom d'utilisateur qui peut être un jeton (« https://<jeton>:x-oauth-basic@… ») : information utilisateur
		// entière.
		return restStart, userinfoEnd, true
	}
	return restStart + separator + 1, userinfoEnd, true
}

// maxPlainUsername : longueur la plus grande d'un nom d'utilisateur gardé en clair.
const maxPlainUsername = 16

// isPlainUsername dit si user est un nom d'utilisateur ordinaire, gardé en clair : 1 à 16 caractères de [a-z0-9._-].
// Tout autre nom (long, majuscules, autre caractère) peut être un jeton : il est remplacé avec le mot de passe.
func isPlainUsername(user []byte) bool {
	if len(user) == 0 || len(user) > maxPlainUsername {
		return false
	}
	for _, c := range user {
		if !isASCIILower(c) && !isASCIIDigit(c) && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// followsAuthorizationKey dit si l'étendue qui commence en start suit une clé Authorization (« Authorization: »,
// « authorization= », guillemets et espaces admis, sans la casse).
func followsAuthorizationKey(content []byte, start int) bool {
	i := start
	skip := func(chars string) {
		for i > 0 && strings.IndexByte(chars, content[i-1]) >= 0 {
			i--
		}
	}
	skip(" \t\"'")
	if i == 0 || (content[i-1] != ':' && content[i-1] != '=') {
		return false
	}
	i--
	skip(" \t\"'")
	const key = "authorization"
	if i < len(key) || !strings.EqualFold(string(content[i-len(key):i]), key) {
		return false
	}
	return i == len(key) || !isWordByte(content[i-len(key)-1])
}

// basicAuthPasswordRange rend l'étendue du mot de passe de « utilisateur:mot de passe » (cli_basic_auth), si span a
// exactement cette forme : utilisateur et mot de passe non vides, sans espace ni guillemet. Utilisateur qui n'est pas
// un nom ordinaire (isPlainUsername : une clé d'API passée comme utilisateur) : span entière.
func basicAuthPasswordRange(span []byte) (int, int, bool) {
	separator := bytes.IndexByte(span, ':')
	if separator <= 0 || separator == len(span)-1 {
		return 0, 0, false
	}
	for i := 0; i < len(span); {
		r, width := utf8.DecodeRune(span[i:])
		if isJSWhitespace(r) || r == '"' || r == '\'' {
			return 0, 0, false
		}
		i += width
	}
	if !isPlainUsername(span[:separator]) {
		return 0, len(span), true
	}
	return separator + 1, len(span), true
}

// pemBodySpan rend l'étendue du corps d'un bloc PEM : entre l'en-tête « -----BEGIN <étiquette>----- » et la marque de
// fin de même étiquette (complete), ou après l'en-tête jusqu'à la fin de span ; fins de ligne, espaces et fins de
// ligne échappées retirées aux deux bouts (pemBodyRange).
func pemBodySpan(span []byte, complete bool) (int, int, bool) {
	label, headerEnd, ok := pemLabelOf(span)
	if !ok {
		return 0, 0, false
	}
	bodyEnd := len(span)
	if complete {
		marker := pemEndMarker(label)
		if !bytes.HasSuffix(span, marker) || len(span)-len(marker) < headerEnd {
			return 0, 0, false
		}
		bodyEnd = len(span) - len(marker)
	}
	start, end := pemBodyRange(span, headerEnd, bodyEnd)
	return start, end, end > start
}
