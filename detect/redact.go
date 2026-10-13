// Masquage des constats d'une analyse, puis nouvelle analyse du texte masqué.
//
// Portage en Go de redact, placeholderName et redactAndRescan de secret-guard/packages/core/src/scanner.ts, et de la
// forme SanitizeResult de types.ts (Apache-2.0, origine, avis et modifications dans UPSTREAM.md). Les vecteurs
// vectors/redact.json, produits par le moteur d'origine, prouvent l'égalité (TestRedactParity).
//
// Le masquage sert quand l'utilisateur choisit d'envoyer une version expurgée d'un texte (presse-papiers, message
// d'un chat) ; il ne sert pas à un hook d'assistant, qui ne peut qu'autoriser ou bloquer l'envoi tel quel.

package detect

import (
	"errors"
	"sort"
	"strings"
)

// Libellé d'une étendue masquée : <REDACTED_règle>.
const (
	redactLabelOpen  = "<REDACTED_"
	redactLabelClose = ">"
)

// RedactOptions règle le masquage. Vide dans cette version : l'option neutralCustomNames de Secret Guard ne vise que
// les constats de règles propres à un client, que ce moteur n'a pas ; elle prendra place ici avec elles.
type RedactOptions struct{}

// SanitizeFailure est l'issue d'un masquage suivi d'une nouvelle analyse (RedactAndRescan), en liste fermée.
type SanitizeFailure string

// Issues d'un masquage suivi d'une nouvelle analyse.
const (
	// SanitizeNone : texte masqué rendu ; sa nouvelle analyse est complète et sans constat.
	SanitizeNone SanitizeFailure = "none"
	// SanitizeIncomplete : l'analyse de l'entrée, ou celle du texte masqué (plus de MaxInputBytes octets après
	// masquage compris), est incomplète. Aucun texte n'est rendu.
	SanitizeIncomplete SanitizeFailure = "incomplete"
	// SanitizeResidual : la nouvelle analyse du texte masqué trouve encore au moins un constat. Aucun texte n'est
	// rendu.
	SanitizeResidual SanitizeFailure = "residual"
)

// SanitizeResult décrit un masquage suivi d'une nouvelle analyse : l'issue, l'analyse de l'entrée (Initial) et celle
// du texte masqué (Final, égale à Initial quand Initial est incomplète ou sans constat). Il ne porte aucun texte : le
// texte masqué est rendu à part par RedactAndRescan, et seulement si Failure vaut SanitizeNone.
type SanitizeResult struct {
	Failure SanitizeFailure
	Initial Result
	Final   Result
}

var (
	// ErrRedactIncomplete refuse de masquer selon une analyse incomplète : elle n'a aucun constat, et rendre le texte
	// tel quel le ferait passer pour sûr.
	ErrRedactIncomplete = errors.New("masquage refusé : analyse incomplète, aucune étendue n'est sûre")
	// ErrRedactSpan refuse un constat dont l'étendue sort du contenu (résultat d'un autre contenu).
	ErrRedactSpan = errors.New("masquage refusé : étendue de constat hors du contenu")
)

// redactSpan est une étendue fusionnée [start, end) et le nom de son libellé.
type redactSpan struct {
	start, end int
	name       string
}

// Redact rend une copie de content où l'étendue de chaque constat de result est remplacée par le libellé
// <REDACTED_règle> (redact de Secret Guard) : étendues triées par début, fin, puis score décroissant, fusionnées
// quand elles se chevauchent ou se touchent, nommées d'après le premier constat ; étendue vide ignorée ; caractère
// d'un identifiant de règle hors de [A-Za-z0-9_] écrit « _ » (deux pour un caractère hors du plan multilingue de
// base, comme les unités UTF-16 de JavaScript). Les octets hors des étendues sont gardés tels quels.
//
// Le texte rendu est celui de l'appelant sans les valeurs détectées : un libellé ne dépend que de l'identifiant de
// règle. Redact ne prouve pas que le résultat est sûr ; RedactAndRescan l'analyse de nouveau.
//
// Refus, sans texte : analyse incomplète (ErrRedactIncomplete) ; étendue hors du contenu (ErrRedactSpan), là où
// Secret Guard ignorerait le constat. options est réservé.
func Redact(content []byte, result Result, options RedactOptions) ([]byte, error) {
	if !result.Complete || result.Failure != FailureNone {
		return nil, ErrRedactIncomplete
	}
	spans, ok := mergeRedactSpans(len(content), result.Findings)
	if !ok {
		return nil, ErrRedactSpan
	}
	return redactSpans(content, spans), nil
}

// redactScan est l'analyse de RedactAndRescan ; couture de test (résultat construit, panne).
var redactScan = Scan

// RedactAndRescan analyse content, masque chaque constat (Redact), puis analyse le texte masqué avec les mêmes règles
// et options (redactAndRescan de Secret Guard). Il rend le texte masqué seulement si les deux analyses sont
// complètes et que la seconde n'a aucun constat (SanitizeNone) ; sinon nil, avec SanitizeIncomplete ou
// SanitizeResidual, et la copie masquée est effacée. Sans constat dans l'entrée, le texte rendu est une copie de
// content, sans seconde analyse (le moteur est déterministe : elle rendrait la même chose).
//
// Le texte rendu est celui de l'appelant sans les valeurs détectées. La seconde analyse ne trouve que ce que les règles
// décrivent : le masquage réduit le risque, il ne le supprime pas.
func RedactAndRescan(content []byte, rules *Rules, options Options, redaction RedactOptions) ([]byte, SanitizeResult) {
	initial := redactScan(content, rules, options)
	if !initial.Complete || initial.Failure != FailureNone {
		return nil, SanitizeResult{Failure: SanitizeIncomplete, Initial: initial, Final: initial}
	}
	if len(initial.Findings) == 0 {
		return append([]byte{}, content...), SanitizeResult{Failure: SanitizeNone, Initial: initial, Final: initial}
	}
	redacted, err := Redact(content, initial, redaction)
	if err != nil {
		// Impossible pour un résultat de Scan sur content ; traité comme une analyse incomplète (fail-closed).
		return nil, SanitizeResult{Failure: SanitizeIncomplete, Initial: initial, Final: incomplete(FailureScanError)}
	}
	final := redactScan(redacted, rules, options)
	failure := SanitizeNone
	switch {
	case !final.Complete || final.Failure != FailureNone:
		failure = SanitizeIncomplete
	case len(final.Findings) > 0:
		failure = SanitizeResidual
	}
	if failure != SanitizeNone {
		clear(redacted)
		return nil, SanitizeResult{Failure: failure, Initial: initial, Final: final}
	}
	return redacted, SanitizeResult{Failure: SanitizeNone, Initial: initial, Final: final}
}

// mergeRedactSpans suit la fusion de redact de Secret Guard ; faux si une étendue sort du contenu. Les positions en
// octets gardent l'ordre et les égalités des positions UTF-16 de l'origine (étendues aux limites de caractères).
func mergeRedactSpans(length int, findings []Finding) ([]redactSpan, bool) {
	valid := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.ByteStart < 0 || f.ByteEnd < f.ByteStart || f.ByteEnd > length {
			return nil, false
		}
		if f.ByteEnd > f.ByteStart {
			valid = append(valid, f)
		}
	}
	sort.SliceStable(valid, func(i, j int) bool {
		a, b := valid[i], valid[j]
		if a.ByteStart != b.ByteStart {
			return a.ByteStart < b.ByteStart
		}
		if a.ByteEnd != b.ByteEnd {
			return a.ByteEnd < b.ByteEnd
		}
		return a.Score > b.Score
	})
	var merged []redactSpan
	for _, f := range valid {
		if n := len(merged); n > 0 && f.ByteStart <= merged[n-1].end {
			merged[n-1].end = max(merged[n-1].end, f.ByteEnd)
			continue
		}
		merged = append(merged, redactSpan{start: f.ByteStart, end: f.ByteEnd, name: placeholderName(f.RuleID)})
	}
	return merged, true
}

// placeholderName suit placeholderName de Secret Guard pour une règle intégrée : chaque unité UTF-16 hors de
// [A-Za-z0-9_] devient « _ » (expression sans drapeau u). Un octet hors UTF-8 compte pour un caractère.
func placeholderName(ruleID string) string {
	var name strings.Builder
	for _, r := range ruleID {
		switch {
		case 'A' <= r && r <= 'Z', 'a' <= r && r <= 'z', '0' <= r && r <= '9', r == '_':
			name.WriteRune(r)
		case r > 0xFFFF:
			name.WriteString("__")
		default:
			name.WriteByte('_')
		}
	}
	return name.String()
}

// redactSpans écrit le texte masqué dans un seul tableau, alloué à sa taille exacte : aucune copie intermédiaire.
func redactSpans(content []byte, spans []redactSpan) []byte {
	size := len(content)
	for _, s := range spans {
		size += len(redactLabelOpen) + len(s.name) + len(redactLabelClose) - (s.end - s.start)
	}
	out := make([]byte, 0, size)
	cursor := 0
	for _, s := range spans {
		out = append(out, content[cursor:s.start]...)
		out = append(out, redactLabelOpen...)
		out = append(out, s.name...)
		out = append(out, redactLabelClose...)
		cursor = s.end
	}
	return append(out, content[cursor:]...)
}
