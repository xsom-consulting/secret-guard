// SPDX-License-Identifier: Apache-2.0

// Jeton fini par un tiret (écart d'analyse ajouté en v0.5.2, absent de Secret Guard).
//
// Les motifs à format fixe finissent par « \b ». Quand leur dernière classe admet « - » (GitLab, Google, OpenAI,
// Anthropic, OpenRouter, SendGrid, JWT…), un jeton dont le dernier caractère est un tiret n'a pas de frontière de mot
// à sa fin (« - » puis une espace, un guillemet ou la fin du texte) : l'expression revient en arrière jusqu'à la
// dernière frontière. Un jeton de longueur fixe (« glpat- » et 20 caractères, « AIza » et 35) ainsi fini n'est alors
// pas détecté : environ un sur 64. Relevé sur le banc de lecture d'images du 2026-11-08 (GitLab).
//
// Pour ces motifs, le moteur cherche aussi le motif sans le « \b » final (dashTail) et retient une correspondance qui
// finit par un tiret au bout de la suite de caractères du jeton, si le motif d'origine n'a rien trouvé qui la touche.
// Bornes, valeur fictive et validateur s'appliquent comme au motif d'origine.

package detect

import (
	"bytes"
	"regexp"
	"strings"
)

// dashTailPattern rend le motif sans son « \b » final si sa dernière classe de caractères, suivie d'une répétition,
// admet « - » ; nil sinon.
func dashTailPattern(pattern string) *regexp.Regexp {
	body, ok := strings.CutSuffix(pattern, `\b`)
	if !ok || !strings.HasSuffix(body, "}") {
		return nil
	}
	open := strings.LastIndexByte(body, '{')
	if open <= 0 || body[open-1] != ']' {
		return nil
	}
	class := body[strings.LastIndexByte(body[:open], '[') : open-1]
	if !strings.HasSuffix(class, "-") {
		return nil
	}
	compiled, err := regexp.Compile(body)
	if err != nil {
		return nil
	}
	return compiled
}

// scanDashTail ajoute les jetons finis par un tiret que le motif d'origine n'a pas trouvés (voir l'en-tête).
func scanDashTail(v *view, r *rule, budget *decodeBudget, found []finding, from int) ([]finding, error) {
	text := v.text
	for _, m := range dashTailCandidates(r, text) {
		start, end := m[0], m[1]
		if text[end-1] != '-' || end < len(text) && (isWordByte(text[end]) || text[end] == '-') || !tokenLikeDashTail(text[start:end]) {
			continue
		}
		sourceStart, sourceEnd := v.mapRange(start, end)
		overlaps := false
		for _, f := range found[from:] {
			if f.ruleID == r.id && f.start < sourceEnd && sourceStart < f.end {
				overlaps = true
				break
			}
		}
		value := text[start:end]
		if overlaps || safeLiteral(value) || isSubstituteBeforeJoin(v, start, end) || !withinBounds(value, r.minLength, r.maxLength) {
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
		found = append(found, newFinding(v, r, start, end, r.score-encodingPenalty(v.encoding), encodingReasons(v.encoding)))
	}
	return found, nil
}

// tokenLikeDashTail dit si une correspondance finie par un tiret a la forme d'un jeton : au plus trois tirets à la
// fin (un sur 64 caractères d'un jeton aléatoire en base64url : quatre de suite n'arrivent presque jamais) et au moins
// la moitié de caractères alphanumériques (« sk- » suivi de trente tirets n'est pas une clé).
func tokenLikeDashTail(match []byte) bool {
	dashes, alphanumeric := 0, 0
	for i := len(match) - 1; i >= 0 && match[i] == '-'; i-- {
		dashes++
	}
	for _, c := range match {
		if isASCIIAlphanumeric(c) {
			alphanumeric++
		}
	}
	return dashes <= 3 && 2*alphanumeric >= len(match)
}

// dashTailWindow borne la lecture après un littéral de la porte : plus longue que tout jeton des règles concernées
// (255 caractères après le préfixe au plus).
const dashTailWindow = 512

// dashTailCandidates rend les correspondances de r.dashTail qui commencent à un littéral de la porte de la règle
// (préfixe du jeton), cherchées dans une fenêtre qui suit chaque littéral : le motif n'est jamais lu sur tout le texte.
// Sans porte, toutes les correspondances.
func dashTailCandidates(r *rule, text []byte) [][]int {
	if r.gate == nil || r.gate.fold {
		// Sans porte, ou porte repliée (ses littéraux en minuscules ne disent pas où le jeton commence) : tout le texte.
		return r.dashTail.FindAllIndex(text, -1)
	}
	var out [][]int
	last := -1
	for _, literal := range r.gate.literals {
		for from := 0; from < len(text); {
			i := bytes.Index(text[from:], literal)
			if i < 0 {
				break
			}
			at := from + i
			from = at + 1
			if at <= last || at > 0 && isWordByte(text[at-1]) {
				continue
			}
			window := text[at:min(len(text), at+dashTailWindow)]
			if m := r.dashTail.FindIndex(window); m != nil && m[0] == 0 {
				out = append(out, []int{at, at + m[1]})
				last = at + m[1] - 1
			}
		}
	}
	return out
}
