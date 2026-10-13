// Détections d'un Pack de règles du client (Options.Custom), ajoutées aux constats des règles intégrées.
//
// Portage en Go de collectCustomFindings, customFinding et successfulResult de secret-guard/packages/core/src/scanner.ts
// (Apache-2.0, origine, avis et modifications dans UPSTREAM.md). Les détections du Pack ne retirent ni n'affaiblissent
// aucun constat des règles intégrées ; une analyse du Pack incomplète rend toute l'analyse incomplète.

package detect

import (
	"errors"
	"sort"

	"github.com/xsom-consulting/secret-guard/custom"
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
