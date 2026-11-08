// SPDX-License-Identifier: PolyForm-Small-Business-1.0.0

// Package expurgation remplace chaque secret détecté par un Substitut typé, puis analyse de nouveau le texte expurgé.
//
// Module github.com/xsom-consulting/secret-guard/expurgation, sous PolyForm Small Business 1.0.0 (LICENSE de ce dossier,
// source disponible) ; le moteur qu'il appelle, github.com/xsom-consulting/secret-guard/detect, reste sous Apache-2.0.
// Le paquet n'appelle que l'API publique de detect (Scan, SecretRange, Rules.FirstLineSecretEnd, SubstituteText,
// Fingerprint) et la partie internal/ de ce dépôt.
//
// Extension propre à secret-guard, sans origine dans Secret Guard (avis dans UPSTREAM.md). Contrairement au masquage
// (detect.Redact, libellés <REDACTED_règle>), l'expurgation ne remplace que la partie secrète d'un constat (mot de passe d'une
// URL, corps d'une clé PEM, valeur après « Bearer »…) par un texte qui dit ce qu'il remplace (« [secret masqué par xSOM
// n°1 : mot de passe, pas la vraie valeur] ») : le texte reste lisible, sans rien de la valeur (ni sa longueur, ni un de
// ses caractères, hors préfixe public). Un Substitut est reconnu par le moteur comme une valeur fictive : la nouvelle
// analyse ne s'y arrête pas. Elle sert à un programme qui réécrit un texte avant son envoi (un mod de Claude Code, par
// exemple) ; un hook, qui ne réécrit pas, ne peut qu'autoriser ou bloquer.

package expurgation

import (
	"errors"
	"sort"
	"unicode/utf8"

	"github.com/xsom-consulting/secret-guard/detect"
	"github.com/xsom-consulting/secret-guard/internal/jstext"
)

// SanitizeOrdinal : l'appelant n'a pas donné de numéro de Substitut valide (ExpurgateAndRescan). Aucun texte n'est
// rendu.
const SanitizeOrdinal detect.SanitizeFailure = "ordinal_refused"

var (
	// ErrIncomplete refuse d'expurger selon une analyse incomplète : elle n'a aucun constat, et rendre le
	// texte tel quel le ferait passer pour sûr.
	ErrIncomplete = errors.New("expurgation refusée : analyse incomplète, aucune étendue n'est sûre")
	// ErrSpan refuse un constat dont l'étendue sort du contenu (résultat d'un autre contenu) ou coupe un
	// caractère UTF-8.
	ErrSpan = errors.New("expurgation refusée : étendue de constat hors du contenu ou dans un caractère")
	// ErrEncoding refuse un contenu hors UTF-8 : ses positions UTF-16 ne seraient pas celles du texte que
	// l'appelant détient.
	ErrEncoding = errors.New("expurgation refusée : contenu hors UTF-8")
	// ErrOrdinal refuse un numéro de Substitut hors de [detect.MinSubstituteOrdinal, detect.MaxSubstituteOrdinal], ou
	// que l'appelant ne donne pas.
	ErrOrdinal = errors.New("expurgation refusée : numéro de Substitut absent ou hors de 1 à 999")
	// ErrLanguage refuse une langue de Substitut autre que detect.SubstituteFrench, detect.SubstituteEnglish ou vide.
	ErrLanguage = errors.New("expurgation refusée : langue de Substitut inconnue")
)

// Options règle une expurgation : l'analyse (detect.Options, mêmes options pour l'analyse de l'entrée et pour celle du
// texte expurgé) et la langue des Substituts.
type Options struct {
	detect.Options
	// SubstituteLanguage est la langue des Substituts qu'écrit ExpurgateAndRescan (vide : detect.SubstituteFrench) ;
	// sans effet sur l'analyse. Une autre valeur que detect.SubstituteFrench, detect.SubstituteEnglish ou vide fait
	// échouer l'expurgation.
	SubstituteLanguage detect.SubstituteLanguage
}

// Substitution décrit un Substitut posé par Expurgate : règle et type de secret du constat représentatif (le premier
// de l'étendue fusionnée), étendue remplacée [ByteStart, ByteEnd) en octets du texte d'origine et [UTF16Start,
// UTF16End) en unités UTF-16 de ce texte (un octet hors UTF-8 compte pour une unité, comme U+FFFD), Empreinte locale
// du constat représentatif (vide sans clé), numéro donné par l'appelant et Substitut écrit (Replacement : préfixe
// public de la table fermée ou aucun, puis, entre crochets, le numéro et le type de secret dans la langue demandée). Elle ne porte jamais la valeur : l'appelant, qui détient le texte
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
// (detect.SecretRange) : étendues triées par début, fin, puis score décroissant, fusionnées quand elles se chevauchent ou se
// touchent (comme detect.Redact), représentées par le premier constat. Pour chaque étendue fusionnée, ordinal reçoit le
// constat représentatif, son étendue ramenée à la partie remplacée, et rend le numéro du Substitut (1 à 999) ; il peut
// être appelé plusieurs fois pour un même constat et doit alors rendre le même numéro. Les octets hors des étendues
// sont gardés tels quels. Rend aussi, pour chaque Substitut, sa Substitution (positions dans le texte d'origine).
//
// Expurgate n'a pas la clé d'Empreinte locale : il ne peut pas calculer l'Empreinte locale des octets qu'il remplace.
// Un Substitut garde l'Empreinte locale de son constat représentatif seulement si l'étendue remplacée est exactement
// celle de ce constat (ni rétrécie à la partie secrète, ni élargie par une fusion) ; sinon, un constat qui porte une
// Empreinte locale fait refuser l'expurgation (ErrSpan) : jamais une Empreinte locale qui ne serait pas celle
// du texte remplacé, et que l'appelant prendrait pour numéroter. Un constat sans Empreinte locale donne une Substitution
// sans Empreinte locale. ExpurgateAndRescan, qui a la clé, donne à chaque Substitut l'Empreinte locale de ses octets.
//
// Expurgate écrit ses Substituts en français (detect.SubstituteFrench) ; ExpurgateAndRescan suit
// Options.SubstituteLanguage.
//
// Expurgate ne prouve pas que le résultat est sûr ; ExpurgateAndRescan l'analyse de nouveau.
//
// Refus, sans texte : numéro absent (ordinal nil, ou qui rend faux) ou hors de 1 à 999 (ErrOrdinal) ;
// analyse incomplète (ErrIncomplete) ; contenu hors UTF-8 (ErrEncoding) ; étendue hors du contenu ou
// qui coupe un caractère, ou étendue remplacée autre que celle de son constat qui porte une Empreinte locale
// (ErrSpan).
func Expurgate(content []byte, result detect.Result, ordinal func(detect.Finding) (int, bool)) ([]byte, []Substitution, error) {
	if ordinal == nil {
		return nil, nil, ErrOrdinal
	}
	if !result.Complete || result.Failure != detect.FailureNone {
		return nil, nil, ErrIncomplete
	}
	text, substitutions, _, err := expurgate(content, result.Findings, nil, nil, nil, ordinal, detect.SubstituteFrench)
	return text, substitutions, err
}

// expurgateScan est l'analyse d'ExpurgateAndRescan ; couture de test (résultat construit, panne).
var expurgateScan = detect.ScanWith

// widenings est l'échelle des résidus d'ExpurgateAndRescan : élargissement au jeton, puis à la ligne.
var widenings = []func(content []byte, start, end int) (int, int){widenToToken, widenToLine}

// ExpurgateAndRescan analyse content (avec l'Empreinte locale de chaque constat si key n'est pas nil), l'expurge
// (Expurgate, Substituts dans la langue options.SubstituteLanguage : vide ou detect.SubstituteFrench,
// français ; detect.SubstituteEnglish, anglais ; toute autre valeur fait échouer l'expurgation,
// detect.SanitizeIncomplete), puis analyse le texte expurgé avec les mêmes règles, clé et options (detect.ScanWith). S'il reste un constat (résidu), son
// étendue, ramenée au texte d'origine, est élargie au jeton qui la contient (suite de caractères sans espace), puis, au
// tour suivant, à sa ligne, et remplacée en entier ; un résidu après l'élargissement à la ligne fait échouer
// l'expurgation (detect.SanitizeResidual).
//
// Avant ce remplacement, un constat d'une règle « motif seul » dont l'étendue prend, par la vue jointe des jetons
// coupés, le premier mot de la ligne suivante est ramené à sa première ligne quand elle est à elle seule une valeur de
// la règle (detect.Rules.FirstLineSecretEnd) : « export A=<jeton>\nexport B=x » garde « \nexport B=x ».
//
// Avec key, chaque Substitut (et le constat que reçoit ordinal) a l'Empreinte locale des octets d'origine qu'il remplace
// exactement, que l'étendue soit celle d'un constat, rétrécie, fusionnée ou élargie : même texte remplacé, même
// Empreinte locale, et deux Substituts d'Empreintes locales égales remplacent le même texte. Sans key, aucune
// Empreinte locale.
//
// Le texte et les Substitutions sont rendus seulement si les analyses sont complètes et que la dernière n'a aucun
// constat (detect.SanitizeNone) ; sinon nil, avec detect.SanitizeIncomplete (analyse incomplète, clé absente ou
// effacée, texte expurgé de plus de detect.MaxInputBytes octets), detect.SanitizeResidual ou SanitizeOrdinal (numéro refusé), et chaque copie
// expurgée est effacée. Sans constat dans l'entrée, le texte rendu est une copie de content, sans Substitution ni
// seconde analyse. La nouvelle analyse ne trouve que ce que les règles décrivent : l'expurgation réduit le risque, elle
// ne le supprime pas.
func ExpurgateAndRescan(content []byte, rules *detect.Rules, key *detect.FingerprintKey, options Options, ordinal func(detect.Finding) (int, bool)) ([]byte, []Substitution, detect.SanitizeResult) {
	analyze := func(text []byte) detect.Result {
		if key != nil && !key.Usable() {
			if len(text) > detect.MaxInputBytes {
				return incomplete(detect.FailureScanLimit)
			}
			return incomplete(detect.FailureScanError)
		}
		return expurgateScan(text, rules, options.Options, key)
	}
	if !options.SubstituteLanguage.Valid() {
		failed := incomplete(detect.FailureScanError)
		return nil, nil, detect.SanitizeResult{Failure: detect.SanitizeIncomplete, Initial: failed, Final: failed}
	}
	initial := analyze(content)
	if !initial.Complete || initial.Failure != detect.FailureNone {
		return nil, nil, detect.SanitizeResult{Failure: detect.SanitizeIncomplete, Initial: initial, Final: initial}
	}
	if !utf8.Valid(content) {
		// Positions UTF-16 sans correspondance sûre avec le texte de l'appelant (ErrEncoding).
		return nil, nil, detect.SanitizeResult{Failure: detect.SanitizeIncomplete, Initial: initial, Final: incomplete(detect.FailureScanError)}
	}
	if len(initial.Findings) == 0 {
		return append([]byte{}, content...), []Substitution{}, detect.SanitizeResult{Failure: detect.SanitizeNone, Initial: initial, Final: initial}
	}
	var widened []detect.Finding
	for step := 0; ; step++ {
		text, substitutions, spans, err := expurgate(content, initial.Findings, widened, rules, key, ordinal, options.SubstituteLanguage)
		if err != nil {
			failure := detect.SanitizeIncomplete
			if errors.Is(err, ErrOrdinal) {
				failure = SanitizeOrdinal
			}
			return nil, nil, detect.SanitizeResult{Failure: failure, Initial: initial, Final: incomplete(detect.FailureScanError)}
		}
		final := analyze(text)
		failure := sanitizeFailure(final)
		switch {
		case failure == detect.SanitizeNone:
			return text, substitutions, detect.SanitizeResult{Failure: detect.SanitizeNone, Initial: initial, Final: final}
		case failure != detect.SanitizeResidual || step == len(widenings):
			clear(text)
			return nil, nil, detect.SanitizeResult{Failure: failure, Initial: initial, Final: final}
		}
		clear(text)
		for _, r := range final.Findings {
			start, end := originalRange(spans, r.ByteStart, r.ByteEnd)
			start, end = widenings[step](content, start, end)
			w := detect.Finding{
				RuleID: r.RuleID, SecretType: r.SecretType, Encoding: r.Encoding, Score: r.Score, Level: r.Level,
				ByteStart: start, ByteEnd: end,
			}
			widened = append(widened, w)
		}
	}
}

// expurgate est l'expurgation d'Expurgate et d'ExpurgateAndRescan : constats rétrécis à leur partie secrète (puis, avec
// rules, à leur première ligne quand elle est à elle seule un secret de leur règle : Rules.FirstLineSecretEnd), étendues
// élargies (widened) gardées entières, fusion, Empreintes locales (substitutionFingerprint), numéros, puis texte écrit
// dans un seul tableau à sa taille exacte.
func expurgate(content []byte, findings, widened []detect.Finding, rules *detect.Rules, key *detect.FingerprintKey, ordinal func(detect.Finding) (int, bool), language detect.SubstituteLanguage) ([]byte, []Substitution, []expurgatedSpan, error) {
	if !utf8.Valid(content) {
		return nil, nil, nil, ErrEncoding
	}
	targets := make([]detect.Finding, 0, len(findings)+len(widened))
	for _, f := range findings {
		if !validExpurgateSpan(content, f) {
			return nil, nil, nil, ErrSpan
		}
		if f.ByteEnd == f.ByteStart {
			continue
		}
		f.ByteStart, f.ByteEnd = detect.SecretRange(content, f)
		if end, ok := rules.FirstLineSecretEnd(content, f); ok {
			f.ByteEnd = end
		}
		targets = append(targets, f)
	}
	for _, f := range widened {
		if !validExpurgateSpan(content, f) {
			return nil, nil, nil, ErrSpan
		}
		if f.ByteEnd > f.ByteStart {
			targets = append(targets, f)
		}
	}
	merged := mergeExpurgateTargets(targets)
	if key != nil && !key.Usable() {
		return nil, nil, nil, ErrIncomplete
	}
	substitutions := make([]Substitution, 0, len(merged))
	size := len(content)
	units, cursor := 0, 0
	for _, rep := range merged {
		if ordinal == nil {
			return nil, nil, nil, ErrOrdinal
		}
		fingerprint, ok := substitutionFingerprint(content, findings, rep, key)
		if !ok {
			return nil, nil, nil, ErrSpan
		}
		rep.LocalFingerprint = fingerprint
		number, ok := ordinal(rep)
		if !ok {
			return nil, nil, nil, ErrOrdinal
		}
		replacement, err := substituteText(content[rep.ByteStart:rep.ByteEnd], rep.RuleID, number, language)
		switch {
		case errors.Is(err, detect.ErrSubstituteOrdinal):
			return nil, nil, nil, ErrOrdinal
		case errors.Is(err, detect.ErrSubstituteLanguage):
			return nil, nil, nil, ErrLanguage
		case err != nil:
			// Refus inattendu de l'écrivain des Substituts : aucun texte n'est sûr.
			return nil, nil, nil, ErrIncomplete
		}
		units += jstext.UTF16Units(content[cursor:rep.ByteStart])
		start := units
		units += jstext.UTF16Units(content[rep.ByteStart:rep.ByteEnd])
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
// d'origine remplacés, content[rep.ByteStart:rep.ByteEnd] (detect.Fingerprint, calcul de
// detect.ScanWithFingerprint). Sans key (Expurgate) :
// l'Empreinte locale du constat représentatif si l'un des constats reçus a exactement l'étendue remplacée et cette
// Empreinte locale ; vide si le représentant n'en porte pas ; sinon faux (ErrSpan) : une Empreinte locale qui
// ne serait pas celle du texte remplacé n'est jamais rendue.
func substitutionFingerprint(content []byte, findings []detect.Finding, rep detect.Finding, key *detect.FingerprintKey) (string, bool) {
	if key != nil {
		return detect.Fingerprint(*key, content[rep.ByteStart:rep.ByteEnd])
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

// substituteText est l'écrivain des Substituts (detect.SubstituteText) ; couture de test (refus inattendu).
var substituteText = detect.SubstituteText

// incomplete est le résultat d'une analyse incomplète : aucun constat (Complete faux).
func incomplete(failure detect.Failure) detect.Result { return detect.Result{Failure: failure} }

// sanitizeFailure est l'issue d'une nouvelle analyse du texte expurgé, comme pour le masquage (detect.RedactAndRescan) :
// tout constat restant fait échouer l'expurgation.
func sanitizeFailure(final detect.Result) detect.SanitizeFailure {
	switch {
	case !final.Complete || final.Failure != detect.FailureNone:
		return detect.SanitizeIncomplete
	case len(final.Findings) > 0:
		return detect.SanitizeResidual
	}
	return detect.SanitizeNone
}

// validExpurgateSpan dit si l'étendue d'un constat est dans le contenu et ne coupe aucun caractère UTF-8.
func validExpurgateSpan(content []byte, f detect.Finding) bool {
	if f.ByteStart < 0 || f.ByteEnd < f.ByteStart || f.ByteEnd > len(content) {
		return false
	}
	atBoundary := func(i int) bool { return i == len(content) || utf8.RuneStart(content[i]) }
	return atBoundary(f.ByteStart) && atBoundary(f.ByteEnd)
}

// mergeExpurgateTargets suit la fusion du masquage (detect.Redact) : tri par début, fin, puis score décroissant ; étendues
// qui se chevauchent ou se touchent fusionnées, représentées par la première, dont l'étendue devient celle de la
// fusion.
func mergeExpurgateTargets(targets []detect.Finding) []detect.Finding {
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
	var merged []detect.Finding
	for _, f := range targets {
		if n := len(merged); n > 0 && f.ByteStart <= merged[n-1].ByteEnd {
			merged[n-1].ByteEnd = max(merged[n-1].ByteEnd, f.ByteEnd)
			continue
		}
		merged = append(merged, f)
	}
	return merged
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
		if jstext.IsWhitespace(r) {
			break
		}
		start -= width
	}
	for end < len(content) {
		r, width := utf8.DecodeRune(content[end:])
		if jstext.IsWhitespace(r) {
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
