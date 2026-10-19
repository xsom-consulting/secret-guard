// Expurgation : chaque secret détecté est remplacé par un Substitut typé (substitute.go), puis le texte expurgé est
// analysé de nouveau.
//
// Extension propre à ce module, sans origine dans Secret Guard (avis dans UPSTREAM.md). Contrairement au masquage
// (Redact, libellés <REDACTED_règle>), l'expurgation ne remplace que la partie secrète d'un constat (mot de passe d'une
// URL, corps d'une clé PEM, valeur après « Bearer »…) et garde la longueur de la valeur : le texte reste lisible et sa
// syntaxe intacte (shell, JSON, YAML). Un Substitut est reconnu par le moteur comme une valeur fictive : la nouvelle
// analyse ne s'y arrête pas. Elle sert à un programme qui réécrit un texte avant son envoi (un mod de Claude Code, par
// exemple) ; un hook, qui ne réécrit pas, ne peut qu'autoriser ou bloquer.

package detect

import (
	"bytes"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"
)

// SanitizeOrdinal : l'appelant n'a pas donné de numéro de Substitut valide (ExpurgateAndRescan). Aucun texte n'est
// rendu.
const SanitizeOrdinal SanitizeFailure = "ordinal_refused"

var (
	// ErrExpurgateIncomplete refuse d'expurger selon une analyse incomplète : elle n'a aucun constat, et rendre le
	// texte tel quel le ferait passer pour sûr.
	ErrExpurgateIncomplete = errors.New("expurgation refusée : analyse incomplète, aucune étendue n'est sûre")
	// ErrExpurgateSpan refuse un constat dont l'étendue sort du contenu (résultat d'un autre contenu) ou coupe un
	// caractère UTF-8.
	ErrExpurgateSpan = errors.New("expurgation refusée : étendue de constat hors du contenu ou dans un caractère")
	// ErrExpurgateEncoding refuse un contenu hors UTF-8 : ses positions UTF-16 ne seraient pas celles du texte que
	// l'appelant détient.
	ErrExpurgateEncoding = errors.New("expurgation refusée : contenu hors UTF-8")
)

// Substitution décrit un Substitut posé par Expurgate : règle et type de secret du constat représentatif (le premier
// de l'étendue fusionnée), étendue remplacée [ByteStart, ByteEnd) en octets du texte d'origine et [UTF16Start,
// UTF16End) en unités UTF-16 de ce texte (un octet hors UTF-8 compte pour une unité, comme U+FFFD), Empreinte locale
// du constat représentatif (vide sans clé), numéro donné par l'appelant et Substitut écrit (Replacement : préfixe
// public de la table fermée, des X et le numéro). Elle ne porte jamais la valeur : l'appelant, qui détient le texte
// d'origine, la lit lui-même à ces positions.
type Substitution struct {
	RuleID           string
	SecretType       string
	ByteStart        int
	ByteEnd          int
	UTF16Start       int
	UTF16End         int
	LocalFingerprint string
	Ordinal          int
	Replacement      string
}

// expurgatedSpan relie une étendue remplacée du texte d'origine [origStart, origEnd) à son Substitut dans le texte
// expurgé [outStart, outEnd).
type expurgatedSpan struct {
	origStart, origEnd, outStart, outEnd int
}

// Expurgate rend une copie de content où la partie secrète de chaque constat de result est remplacée par un Substitut
// (secretPart) : étendues triées par début, fin, puis score décroissant, fusionnées quand elles se chevauchent ou se
// touchent (comme Redact), représentées par le premier constat. Pour chaque étendue fusionnée, ordinal reçoit le
// constat représentatif, son étendue ramenée à la partie remplacée, et rend le numéro du Substitut (1 à 999) ; il peut
// être appelé plusieurs fois pour un même constat et doit alors rendre le même numéro. Les octets hors des étendues
// sont gardés tels quels. Rend aussi, pour chaque Substitut, sa Substitution (positions dans le texte d'origine).
//
// Expurgate n'a pas la clé d'Empreinte locale : il ne peut pas calculer l'Empreinte locale des octets qu'il remplace.
// Un Substitut garde l'Empreinte locale de son constat représentatif seulement si l'étendue remplacée est exactement
// celle de ce constat (ni rétrécie à la partie secrète, ni élargie par une fusion) ; sinon, un constat qui porte une
// Empreinte locale fait refuser l'expurgation (ErrExpurgateSpan) : jamais une Empreinte locale qui ne serait pas celle
// du texte remplacé, et que l'appelant prendrait pour numéroter. Un constat sans Empreinte locale donne une Substitution
// sans Empreinte locale. ExpurgateAndRescan, qui a la clé, donne à chaque Substitut l'Empreinte locale de ses octets.
//
// Expurgate ne prouve pas que le résultat est sûr ; ExpurgateAndRescan l'analyse de nouveau.
//
// Refus, sans texte : numéro absent (ordinal nil, ou qui rend faux) ou hors de 1 à 999 (ErrExpurgateOrdinal) ;
// analyse incomplète (ErrExpurgateIncomplete) ; contenu hors UTF-8 (ErrExpurgateEncoding) ; étendue hors du contenu ou
// qui coupe un caractère, ou étendue remplacée autre que celle de son constat qui porte une Empreinte locale
// (ErrExpurgateSpan).
func Expurgate(content []byte, result Result, ordinal func(Finding) (int, bool)) ([]byte, []Substitution, error) {
	if ordinal == nil {
		return nil, nil, ErrExpurgateOrdinal
	}
	if !result.Complete || result.Failure != FailureNone {
		return nil, nil, ErrExpurgateIncomplete
	}
	text, substitutions, _, err := expurgate(content, result.Findings, nil, nil, nil, ordinal)
	return text, substitutions, err
}

// expurgateScan est l'analyse d'ExpurgateAndRescan ; couture de test (résultat construit, panne).
var expurgateScan = scan

// widenings est l'échelle des résidus d'ExpurgateAndRescan : élargissement au jeton, puis à la ligne.
var widenings = []func(content []byte, start, end int) (int, int){widenToToken, widenToLine}

// ExpurgateAndRescan analyse content (avec l'Empreinte locale de chaque constat si key n'est pas nil), l'expurge
// (Expurgate), puis analyse le texte expurgé avec les mêmes règles, clé et options. S'il reste un constat (résidu), son
// étendue, ramenée au texte d'origine, est élargie au jeton qui la contient (suite de caractères sans espace), puis, au
// tour suivant, à sa ligne, et remplacée en entier ; un résidu après l'élargissement à la ligne fait échouer
// l'expurgation (SanitizeResidual).
//
// Avant ce remplacement, un constat d'une règle « motif seul » dont l'étendue prend, par la vue jointe des jetons
// coupés, le premier mot de la ligne suivante est ramené à sa première ligne quand elle est à elle seule une valeur de
// la règle (firstLineSecretEnd) : « export A=<jeton>\nexport B=x » garde « \nexport B=x ».
//
// Avec key, chaque Substitut (et le constat que reçoit ordinal) a l'Empreinte locale des octets d'origine qu'il remplace
// exactement, que l'étendue soit celle d'un constat, rétrécie, fusionnée ou élargie : même texte remplacé, même
// Empreinte locale, et deux Substituts d'Empreintes locales égales remplacent le même texte. Sans key, aucune
// Empreinte locale.
//
// Le texte et les Substitutions sont rendus seulement si les analyses sont complètes et que la dernière n'a aucun
// constat (SanitizeNone) ; sinon nil, avec SanitizeIncomplete (analyse incomplète, clé absente ou effacée, texte
// expurgé de plus de MaxInputBytes octets), SanitizeResidual ou SanitizeOrdinal (numéro refusé), et chaque copie
// expurgée est effacée. Sans constat dans l'entrée, le texte rendu est une copie de content, sans Substitution ni
// seconde analyse. La nouvelle analyse ne trouve que ce que les règles décrivent : l'expurgation réduit le risque, elle
// ne le supprime pas.
func ExpurgateAndRescan(content []byte, rules *Rules, key *FingerprintKey, options Options, ordinal func(Finding) (int, bool)) ([]byte, []Substitution, SanitizeResult) {
	analyze := func(text []byte) Result {
		if key != nil && !key.usable() {
			if len(text) > MaxInputBytes {
				return incomplete(FailureScanLimit)
			}
			return incomplete(FailureScanError)
		}
		return expurgateScan(text, rules, options, key)
	}
	initial := analyze(content)
	if !initial.Complete || initial.Failure != FailureNone {
		return nil, nil, SanitizeResult{Failure: SanitizeIncomplete, Initial: initial, Final: initial}
	}
	if !utf8.Valid(content) {
		// Positions UTF-16 sans correspondance sûre avec le texte de l'appelant (ErrExpurgateEncoding).
		return nil, nil, SanitizeResult{Failure: SanitizeIncomplete, Initial: initial, Final: incomplete(FailureScanError)}
	}
	if len(initial.Findings) == 0 {
		return append([]byte{}, content...), []Substitution{}, SanitizeResult{Failure: SanitizeNone, Initial: initial, Final: initial}
	}
	var widened []Finding
	for step := 0; ; step++ {
		text, substitutions, spans, err := expurgate(content, initial.Findings, widened, rules, key, ordinal)
		if err != nil {
			failure := SanitizeIncomplete
			if errors.Is(err, ErrExpurgateOrdinal) {
				failure = SanitizeOrdinal
			}
			return nil, nil, SanitizeResult{Failure: failure, Initial: initial, Final: incomplete(FailureScanError)}
		}
		final := analyze(text)
		failure := sanitizeFailure(final)
		switch {
		case failure == SanitizeNone:
			return text, substitutions, SanitizeResult{Failure: SanitizeNone, Initial: initial, Final: final}
		case failure != SanitizeResidual || step == len(widenings):
			clear(text)
			return nil, nil, SanitizeResult{Failure: failure, Initial: initial, Final: final}
		}
		clear(text)
		for _, r := range final.Findings {
			start, end := originalRange(spans, r.ByteStart, r.ByteEnd)
			start, end = widenings[step](content, start, end)
			w := Finding{
				RuleID: r.RuleID, SecretType: r.SecretType, Encoding: r.Encoding, Score: r.Score, Level: r.Level,
				ByteStart: start, ByteEnd: end,
			}
			widened = append(widened, w)
		}
	}
}

// expurgate est l'expurgation d'Expurgate et d'ExpurgateAndRescan : constats rétrécis à leur partie secrète (puis, avec
// rules, à leur première ligne quand elle est à elle seule un secret de leur règle : firstLineSecretEnd), étendues
// élargies (widened) gardées entières, fusion, Empreintes locales (substitutionFingerprint), numéros, puis texte écrit
// dans un seul tableau à sa taille exacte.
func expurgate(content []byte, findings, widened []Finding, rules *Rules, key *FingerprintKey, ordinal func(Finding) (int, bool)) ([]byte, []Substitution, []expurgatedSpan, error) {
	if !utf8.Valid(content) {
		return nil, nil, nil, ErrExpurgateEncoding
	}
	targets := make([]Finding, 0, len(findings)+len(widened))
	for _, f := range findings {
		if !validExpurgateSpan(content, f) {
			return nil, nil, nil, ErrExpurgateSpan
		}
		if f.ByteEnd == f.ByteStart {
			continue
		}
		f.ByteStart, f.ByteEnd = secretPart(content, f)
		if end, ok := firstLineSecretEnd(content, rules, f); ok {
			f.ByteEnd = end
		}
		targets = append(targets, f)
	}
	for _, f := range widened {
		if !validExpurgateSpan(content, f) {
			return nil, nil, nil, ErrExpurgateSpan
		}
		if f.ByteEnd > f.ByteStart {
			targets = append(targets, f)
		}
	}
	merged := mergeExpurgateTargets(targets)
	if key != nil && !key.usable() {
		return nil, nil, nil, ErrExpurgateIncomplete
	}
	substitutions := make([]Substitution, 0, len(merged))
	size := len(content)
	units, cursor := 0, 0
	for _, rep := range merged {
		if ordinal == nil {
			return nil, nil, nil, ErrExpurgateOrdinal
		}
		fingerprint, ok := substitutionFingerprint(content, findings, rep, key)
		if !ok {
			return nil, nil, nil, ErrExpurgateSpan
		}
		rep.LocalFingerprint = fingerprint
		number, ok := ordinal(rep)
		if !ok {
			return nil, nil, nil, ErrExpurgateOrdinal
		}
		replacement, err := substituteFor(content[rep.ByteStart:rep.ByteEnd], rep.RuleID, number)
		if err != nil {
			return nil, nil, nil, err
		}
		units += utf16Units(content[cursor:rep.ByteStart])
		start := units
		units += utf16Units(content[rep.ByteStart:rep.ByteEnd])
		cursor = rep.ByteEnd
		size += len(replacement) - (rep.ByteEnd - rep.ByteStart)
		substitutions = append(substitutions, Substitution{
			RuleID: rep.RuleID, SecretType: rep.SecretType, ByteStart: rep.ByteStart, ByteEnd: rep.ByteEnd,
			UTF16Start: start, UTF16End: units, LocalFingerprint: rep.LocalFingerprint, Ordinal: number,
			Replacement: replacement,
		})
	}
	out := make([]byte, 0, size)
	spans := make([]expurgatedSpan, 0, len(substitutions))
	cursor = 0
	for _, s := range substitutions {
		out = append(out, content[cursor:s.ByteStart]...)
		outStart := len(out)
		out = append(out, s.Replacement...)
		spans = append(spans, expurgatedSpan{origStart: s.ByteStart, origEnd: s.ByteEnd, outStart: outStart, outEnd: len(out)})
		cursor = s.ByteEnd
	}
	return append(out, content[cursor:]...), substitutions, spans, nil
}

// substitutionFingerprint rend l'Empreinte locale du Substitut de l'étendue fusionnée rep : avec key, celle des octets
// d'origine remplacés, content[rep.ByteStart:rep.ByteEnd] (calcul de ScanWithFingerprint). Sans key (Expurgate) :
// l'Empreinte locale du constat représentatif si l'un des constats reçus a exactement l'étendue remplacée et cette
// Empreinte locale ; vide si le représentant n'en porte pas ; sinon faux (ErrExpurgateSpan) : une Empreinte locale qui
// ne serait pas celle du texte remplacé n'est jamais rendue.
func substitutionFingerprint(content []byte, findings []Finding, rep Finding, key *FingerprintKey) (string, bool) {
	if key != nil {
		return localFingerprint(*key, content[rep.ByteStart:rep.ByteEnd]), true
	}
	if rep.LocalFingerprint == "" {
		return "", true
	}
	for _, f := range findings {
		if f.ByteStart == rep.ByteStart && f.ByteEnd == rep.ByteEnd && f.LocalFingerprint == rep.LocalFingerprint {
			return rep.LocalFingerprint, true
		}
	}
	return "", false
}

// validExpurgateSpan dit si l'étendue d'un constat est dans le contenu et ne coupe aucun caractère UTF-8.
func validExpurgateSpan(content []byte, f Finding) bool {
	if f.ByteStart < 0 || f.ByteEnd < f.ByteStart || f.ByteEnd > len(content) {
		return false
	}
	atBoundary := func(i int) bool { return i == len(content) || utf8.RuneStart(content[i]) }
	return atBoundary(f.ByteStart) && atBoundary(f.ByteEnd)
}

// mergeExpurgateTargets suit la fusion de mergeRedactSpans : tri par début, fin, puis score décroissant ; étendues
// qui se chevauchent ou se touchent fusionnées, représentées par la première, dont l'étendue devient celle de la
// fusion.
func mergeExpurgateTargets(targets []Finding) []Finding {
	sort.SliceStable(targets, func(i, j int) bool {
		a, b := targets[i], targets[j]
		if a.ByteStart != b.ByteStart {
			return a.ByteStart < b.ByteStart
		}
		if a.ByteEnd != b.ByteEnd {
			return a.ByteEnd < b.ByteEnd
		}
		return a.Score > b.Score
	})
	var merged []Finding
	for _, f := range targets {
		if n := len(merged); n > 0 && f.ByteStart <= merged[n-1].ByteEnd {
			merged[n-1].ByteEnd = max(merged[n-1].ByteEnd, f.ByteEnd)
			continue
		}
		merged = append(merged, f)
	}
	return merged
}

// secretPart rend la partie secrète de l'étendue d'un constat, celle que remplace le Substitut :
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
func secretPart(content []byte, f Finding) (int, int) {
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

// firstLineSecretEnd rend la fin de la première ligne de l'étendue d'un constat d'une règle « motif seul » de rules
// (constat représentatif d'une étendue fusionnée par dedupeOverlaps compris) quand l'étendue passe une fin de ligne
// (« \n », « \r ») et que :
//   - la partie avant la première fin de ligne est à elle seule, exactement, une valeur de la règle (scanFixedPattern ou
//     scanJWT sur cette seule partie : motif, valeur fictive, bornes, validateur) ;
//   - l'étendue s'arrête, dans content, devant un séparateur d'affectation ou de commande (« = », « : », espace,
//     tabulation) : ce qu'elle prend sur la ligne suivante est un mot de cette ligne (« export », nom d'une variable
//     d'un fichier .env), et non la suite d'un jeton coupé.
//
// L'étendue vient alors d'une vue jointe (lineWrappedFixedViews) qui a recollé à un jeton complet le premier mot de la
// ligne suivante : seule la première ligne est remplacée, la fin de ligne et la ligne suivante sont gardées. Sinon
// (secret réellement coupé par un retour à la ligne, règle sans motif, étendue d'une autre forme, analyse du segment en
// échec), faux : l'étendue entière est remplacée.
func firstLineSecretEnd(content []byte, rules *Rules, f Finding) (int, bool) {
	if rules == nil || !rules.loaded || isCustomFinding(f) {
		return 0, false
	}
	span := content[f.ByteStart:f.ByteEnd]
	lineEnd := bytes.IndexAny(span, "\r\n")
	if lineEnd <= 0 || f.ByteEnd >= len(content) || strings.IndexByte("=: \t", content[f.ByteEnd]) < 0 {
		return 0, false
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

// originalRange ramène l'étendue [start, end) du texte expurgé au texte d'origine : une borne dans un Substitut va à
// la borne de son étendue remplacée.
func originalRange(spans []expurgatedSpan, start, end int) (int, int) {
	return originalStart(spans, start), originalEnd(spans, end)
}

func originalStart(spans []expurgatedSpan, p int) int {
	offset := 0
	for _, s := range spans {
		if p < s.outStart {
			break
		}
		if p < s.outEnd {
			return s.origStart
		}
		offset = s.origEnd - s.outEnd
	}
	return p + offset
}

func originalEnd(spans []expurgatedSpan, p int) int {
	offset := 0
	for _, s := range spans {
		if p <= s.outStart {
			break
		}
		if p <= s.outEnd {
			return s.origEnd
		}
		offset = s.origEnd - s.outEnd
	}
	return p + offset
}

// widenToToken élargit [start, end) au jeton qui le contient : jusqu'aux espaces de JavaScript qui l'entourent.
func widenToToken(content []byte, start, end int) (int, int) {
	for start > 0 {
		r, width := utf8.DecodeLastRune(content[:start])
		if isJSWhitespace(r) {
			break
		}
		start -= width
	}
	for end < len(content) {
		r, width := utf8.DecodeRune(content[end:])
		if isJSWhitespace(r) {
			break
		}
		end += width
	}
	return start, end
}

// widenToLine élargit [start, end) à ses lignes entières, fins de ligne (LF, et CR qui le précède) exclues.
func widenToLine(content []byte, start, end int) (int, int) {
	for start > 0 && content[start-1] != '\n' {
		start--
	}
	lineEnd := end
	for lineEnd < len(content) && content[lineEnd] != '\n' {
		lineEnd++
	}
	if lineEnd > end && lineEnd < len(content) && content[lineEnd-1] == '\r' {
		lineEnd--
	}
	return start, lineEnd
}
