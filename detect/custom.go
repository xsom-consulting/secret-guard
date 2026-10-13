// Détections d'un Pack de règles du client (Options.Custom), ajoutées aux constats des règles intégrées.
//
// Portage en Go de collectCustomFindings, customFinding et successfulResult de secret-guard/packages/core/src/scanner.ts
// (Apache-2.0, origine, avis et modifications dans UPSTREAM.md). Les détections du Pack ne retirent ni n'affaiblissent
// aucun constat des règles intégrées ; une analyse du Pack incomplète rend toute l'analyse incomplète.

package detect

import (
	"errors"
	"sort"
	"strings"
	"unicode"

	"github.com/xsom-consulting/secret-guard/custom"
	"golang.org/x/text/unicode/norm"
)

const (
	// customRulePrefix précède l'identifiant d'un détecteur du Pack dans le RuleID de son constat (« xsom_ » de
	// l'origine) : un détecteur ne peut pas prendre l'identifiant d'une règle intégrée.
	customRulePrefix = "xsom_"
	// customSecretType est le type de secret d'un constat du Pack.
	customSecretType = "custom_rule"
	// customBlockScore et customWarnScore sont les scores d'un détecteur d'action block et warn
	// (CUSTOM_BLOCK_SCORE, CUSTOM_WARN_SCORE).
	customBlockScore = 90
	customWarnScore  = 40
)

// withCustomFindings ajoute aux constats des règles intégrées (déjà dédupliqués, triés) les détections du Pack, puis
// trie le tout par étendue (tri stable : à étendue égale, les constats intégrés d'abord). Rend l'issue de l'analyse du
// Pack : budget épuisé ou plus de MaxFindings − len(builtIn) détections, l'analyse est incomplète.
func withCustomFindings(content []byte, p *custom.Pack, builtIn []Finding) ([]Finding, Failure) {
	matches, err := p.Analyze(content, nil, MaxFindings-len(builtIn))
	switch {
	case errors.Is(err, custom.ErrWorkBudget):
		return nil, FailureCustomBudget
	case errors.Is(err, custom.ErrTooManyMatches):
		return nil, FailureCustomTooMany
	case err != nil:
		return nil, FailureScanError
	}
	detectors := p.Detectors()
	findings := builtIn
	for _, m := range matches {
		d := detectors[m.Detector]
		score := customWarnScore
		if d.Action == custom.ActionBlock {
			score = customBlockScore
		}
		findings = append(findings, Finding{
			RuleID: customRulePrefix + d.ID, SecretType: customSecretType, Encoding: EncodingPlain, Score: score,
			Level: levelForScore(score), ByteStart: m.ByteStart, ByteEnd: m.ByteEnd,
		})
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].ByteStart != findings[j].ByteStart {
			return findings[i].ByteStart < findings[j].ByteStart
		}
		return findings[i].ByteEnd < findings[j].ByteEnd
	})
	return findings, FailureNone
}

// isCustomFinding dit si un constat vient d'un Pack de règles du client.
func isCustomFinding(f Finding) bool {
	return f.SecretType == customSecretType && strings.HasPrefix(f.RuleID, customRulePrefix)
}

func hasCustomFinding(result Result) bool {
	for _, f := range result.Findings {
		if isCustomFinding(f) {
			return true
		}
	}
	return false
}

const (
	// neutralCustomName est le libellé d'un constat du Pack sans libellé utilisable, ou masqué avec NeutralCustomNames.
	neutralCustomName = "custom_rule"
	// emptyDisplayLabel est le libellé affiché d'un détecteur dont le libellé ne garde aucun caractère visible
	// (displayLabel de Secret Guard).
	emptyDisplayLabel = "Règle xSOM"
	// maxPlaceholderLength borne le nom tiré d'un libellé (placeholderName de Secret Guard).
	maxPlaceholderLength = 48
)

// customPlaceholders rend le nommage des étendues masquées : identifiant de la règle pour une règle intégrée
// (placeholderName), libellé du détecteur pour un constat du Pack de règles du client.
func customPlaceholders(options RedactOptions) func(Finding) string {
	labels := map[string]string{}
	if options.Custom != nil && !options.NeutralCustomNames {
		for _, d := range options.Custom.Detectors() {
			labels[customRulePrefix+d.ID] = d.Label
		}
	}
	return func(f Finding) string {
		if !isCustomFinding(f) {
			return placeholderName(f.RuleID)
		}
		label, ok := labels[f.RuleID]
		if !ok {
			return neutralCustomName
		}
		return labelPlaceholder(displayLabel(label))
	}
}

// isJSSpace dit si r est un espace de \s (drapeau u) de JavaScript.
func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x00A0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return 0x2000 <= r && r <= 0x200A
}

// displayLabel suit displayLabel de Secret Guard : caractères de contrôle, de format et séparateurs de ligne ou de
// paragraphe remplacés par une espace, espaces regroupées, bords retirés ; libellé vide → emptyDisplayLabel.
func displayLabel(label string) string {
	var b strings.Builder
	space := false
	for _, r := range label {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) || isJSSpace(r) {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	if b.Len() == 0 {
		return emptyDisplayLabel
	}
	return b.String()
}

// labelPlaceholder suit placeholderName de Secret Guard pour un constat du Pack : NFKD, marques retirées, chaque
// suite de caractères hors de [A-Za-z0-9] remplacée par « _ », « _ » des bords retirés, 48 caractères au plus ;
// vide → neutralCustomName.
func labelPlaceholder(label string) string {
	var b strings.Builder
	separator := false
	for _, r := range norm.NFKD.String(label) {
		switch {
		case unicode.IsMark(r):
		case 'A' <= r && r <= 'Z', 'a' <= r && r <= 'z', '0' <= r && r <= '9':
			if separator && b.Len() > 0 {
				b.WriteByte('_')
			}
			separator = false
			b.WriteRune(r)
		default:
			separator = true
		}
	}
	name := b.String()
	if len(name) > maxPlaceholderLength {
		name = strings.TrimRight(name[:maxPlaceholderLength], "_")
	}
	if name == "" {
		return neutralCustomName
	}
	return name
}
