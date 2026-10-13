// Analyse du moteur de détection : point d'entrée unique Scan.
//
// Portage en Go de scan, collectFindings, scanDetectors, scanDecodedText, scanBase64Candidates et dedupeOverlaps de
// secret-guard/packages/core/src/scanner.ts (Apache-2.0, origine, avis et modifications dans UPSTREAM.md). Les vues
// et décodages viennent de views.go et encoding.go, les règles de rules.go (Pack chargé par LoadRules).

package detect

import (
	"errors"
	"sort"

	"github.com/xsom-consulting/secret-guard/internal/limits"
)

const (
	// MaxInputBytes est la taille d'entrée la plus grande analysée (MAX_INPUT_BYTES de Secret Guard, 1 Mio), en
	// octets reçus. Au-delà, rien n'est analysé, pas même un préfixe (FailureScanLimit).
	MaxInputBytes = limits.MaxInputBytes
	// MaxFindings est le nombre de constats le plus grand avant déduplication (MAX_FINDINGS de Secret Guard) ; au-delà,
	// l'analyse est incomplète (FailureScanError).
	MaxFindings = limits.MaxFindings
)

var (
	errTooManyFindings = errors.New("détection : plus de 2 048 constats")
	errNoRules         = errors.New("détection : aucune règle chargée")
)

// Scan analyse content avec les règles d'un Pack chargé par LoadRules. Fonction pure et déterministe (même entrée,
// même résultat), sans E/S, horloge ni hasard, sûre pour des analyses concurrentes avec les mêmes règles.
//
// L'analyse est complète (Complete, FailureNone, constats dédupliqués triés par octet de début) ou incomplète, sans
// aucun constat : FailureScanLimit pour une entrée de plus de MaxInputBytes octets, FailureScanError pour un budget
// épuisé, plus de MaxFindings constats, des règles absentes ou une panique (rattrapée, jamais propagée). Une
// analyse incomplète est un blocage pour l'appelant. Une erreur d'exécution que Go ne rend pas rattrapable
// (mémoire épuisée, pile dépassée) arrête le processus : l'appelant doit alors conclure à un échec, jamais à une autorisation.
//
// Le travail est borné par les budgets du moteur (vues, fenêtres, décodages, constats), pas par une horloge : le
// délai d'un appel est tenu par l'appelant.
func Scan(content []byte, rules *Rules, options Options) Result {
	return scan(content, rules, options, nil)
}

// scan est l'analyse de Scan et de ScanWithFingerprint : avec key, chaque constat reçoit son Empreinte locale,
// calculée sur sa valeur avant l'effacement des tampons de l'analyse. Les tampons de texte relevés par le budget de
// vues (vues dérivées, textes décodés) sont effacés avant le retour, quelle que soit l'issue (panique comprise).
func scan(content []byte, rules *Rules, options Options, key *FingerprintKey) (result Result) {
	if len(content) > MaxInputBytes {
		return incomplete(FailureScanLimit)
	}
	s := scanStateFor(rules)
	defer s.views.wipe()
	defer func() {
		if recover() != nil {
			result = incomplete(FailureScanError)
		}
	}()
	findings, err := s.collect(content, options.language())
	if err != nil {
		return incomplete(FailureScanError)
	}
	public, ok := publicFindings(findings, key)
	if !ok {
		return incomplete(FailureScanError)
	}
	return Result{Complete: true, Failure: FailureNone, Findings: public}
}

// scanStateFor crée l'état d'une analyse ; couture de test (les tests relèvent l'état pour vérifier l'effacement de
// ses tampons après Scan et ScanWithFingerprint).
var scanStateFor = newScanState

func incomplete(failure Failure) Result { return Result{Failure: failure} }

// scanState porte les budgets partagés d'une analyse : un budget de vues, de fenêtres et de décodages, et
// l'ensemble des candidats base64 déjà vus, pour toute l'analyse (textes décodés compris).
type scanState struct {
	rules   *Rules
	views   *viewBudget
	windows *windowBudget
	decode  *decodeBudget
	seen    map[sourceRange]struct{}
}

func appendBounded(target []finding, additions []finding) ([]finding, error) {
	target = append(target, additions...)
	if len(target) > MaxFindings {
		return nil, errTooManyFindings
	}
	return target, nil
}

// fixed exécute les règles « motif seul » ; un budget de décodage épuisé pendant un validateur (qui rend alors
// « non valide ») rend l'analyse incomplète.
func (s *scanState) fixed(v *view, allowStructured bool) ([]finding, error) {
	found, err := s.rules.scanFixedRules(v, s.decode, allowStructured)
	if err == nil && s.decode.exhausted {
		err = errDecodeBudgetExhausted
	}
	return found, err
}

// detectors suit scanDetectors de Secret Guard.
func (s *scanState) detectors(v *view, entropy bool, lang language, allowStructured bool) ([]finding, error) {
	fixed, err := s.fixed(v, allowStructured)
	if err != nil {
		return nil, err
	}
	contextual, err := s.rules.scanContextualAssignments(v, s.decode, lang, allowStructured)
	if err == nil && s.decode.exhausted {
		err = errDecodeBudgetExhausted
	}
	if err != nil {
		return nil, err
	}
	out := append(fixed, s.rules.scanCredentialURLs(v)...)
	out = append(out, contextual...)
	if entropy {
		out = append(out, s.rules.scanEntropy(v)...)
	}
	return out, nil
}

// collect suit collectFindings de Secret Guard : détecteurs sur la vue d'identité, la vue normalisée et les vues
// transformées ; règles « motif seul » sur les fenêtres de lignes jointes ; candidats base64 (fenêtres puis vue) de
// la vue canonique et des vues transformées ; puis déduplication.
func collect(rules *Rules, content []byte, lang language) ([]finding, error) {
	s := newScanState(rules)
	defer s.views.wipe()
	return s.collect(content, lang)
}

func newScanState(rules *Rules) *scanState {
	return &scanState{rules: rules, views: newViewBudget(), windows: &windowBudget{}, decode: &decodeBudget{}, seen: map[sourceRange]struct{}{}}
}

// collect est l'analyse de collect dans l'état s, dont les tampons restent lisibles jusqu'à s.views.wipe.
func (s *scanState) collect(content []byte, lang language) ([]finding, error) {
	rules := s.rules
	if rules == nil || !rules.loaded {
		return nil, errNoRules
	}
	text, err := buildTextViews(content, s.views)
	if err != nil {
		return nil, err
	}
	var findings []finding
	views := []*view{text.identity}
	if text.normalized != nil {
		views = append(views, text.normalized)
	}
	views = append(views, text.transformed...)
	for _, v := range views {
		detected, err := s.detectors(v, true, lang, true)
		if err != nil {
			return nil, err
		}
		if findings, err = appendBounded(findings, detected); err != nil {
			return nil, err
		}
	}
	for _, v := range append([]*view{text.canonical}, text.transformed...) {
		fixedWindows, err := lineWrappedFixedViews(v, s.windows, s.views)
		if err != nil {
			return nil, err
		}
		for _, joined := range fixedWindows {
			detected, err := s.fixed(joined, true)
			if err != nil {
				return nil, err
			}
			if findings, err = appendBounded(findings, detected); err != nil {
				return nil, err
			}
		}
		base64Windows, err := lineWrappedBase64Views(v, s.windows, s.views)
		if err != nil {
			return nil, err
		}
		for _, joined := range append(base64Windows, v) {
			detected, err := s.base64Candidates(joined)
			if err != nil {
				return nil, err
			}
			if findings, err = appendBounded(findings, detected); err != nil {
				return nil, err
			}
		}
	}
	return dedupeOverlaps(content, findings), nil
}

// base64Candidates suit scanBase64Candidates de Secret Guard.
func (s *scanState) base64Candidates(v *view) ([]finding, error) {
	var findings []finding
	err := forEachBase64Candidate(v, s.decode, s.seen, func(start, end int, decoded string) error {
		// Texte décodé relevé par le budget de vues : la valeur d'un constat y est lue pour son Empreinte locale,
		// puis effacée à la fin de l'analyse.
		buffer := []byte(decoded)
		s.views.own(buffer)
		inner, err := s.decodedText(buffer)
		if err != nil {
			return err
		}
		for _, f := range inner {
			findings = append(findings, finding{
				ruleID: f.ruleID, secretType: f.secretType, start: start, end: end, score: boundedScore(f.score - 5),
				reasons: append(append([]string(nil), f.reasons...), "single_level_base64_decode"), encoding: EncodingBase64,
				value: f.value,
			})
		}
		if len(findings) > MaxFindings {
			return errTooManyFindings
		}
		return nil
	})
	return findings, err
}

// decodedText suit scanDecodedText de Secret Guard (une seule couche base64 : ni JWT ni Docker, ni entropie).
func (s *scanState) decodedText(decoded []byte) ([]finding, error) {
	text, err := buildTextViews(decoded, s.views)
	if err != nil {
		return nil, err
	}
	var findings []finding
	views := []*view{text.identity}
	if text.normalized != nil {
		views = append(views, text.normalized)
	}
	for _, v := range append(views, text.transformed...) {
		detected, err := s.detectors(v, false, language{}, false)
		if err != nil {
			return nil, err
		}
		if findings, err = appendBounded(findings, detected); err != nil {
			return nil, err
		}
	}
	for _, v := range append([]*view{text.canonical}, text.transformed...) {
		fixedWindows, err := lineWrappedFixedViews(v, s.windows, s.views)
		if err != nil {
			return nil, err
		}
		for _, joined := range fixedWindows {
			detected, err := s.fixed(joined, false)
			if err != nil {
				return nil, err
			}
			if findings, err = appendBounded(findings, detected); err != nil {
				return nil, err
			}
		}
	}
	return findings, nil
}

// boundedScore suit boundedScore de Secret Guard (scores entiers : arrondi sans effet).
func boundedScore(score int) int { return max(0, min(100, score)) }

// levelForScore suit levelForScore de Secret Guard.
func levelForScore(score int) Level {
	switch {
	case score >= 75:
		return LevelCritical
	case score >= 50:
		return LevelHigh
	case score >= 25:
		return LevelMedium
	}
	return LevelLow
}

var encodingRanks = map[Encoding]int{
	EncodingPlain: 0, EncodingNormalized: 1, EncodingPercent: 2, EncodingJSONEscaped: 3, EncodingWhitespaceJoined: 4,
	EncodingBase64: 5,
}

func specificityRank(f finding) int {
	switch {
	case f.ruleID == ruleHighEntropy:
		return 2
	case len(f.ruleID) >= len(contextualRulePrefix) && f.ruleID[:len(contextualRulePrefix)] == contextualRulePrefix:
		return 1
	}
	return 0
}

// localeOrder compare deux identifiants de règle ([a-z0-9_], seule forme admise) comme String.prototype.localeCompare
// (classement racine d'ICU) : « _ », puis chiffres, puis lettres. Hors de cette forme, l'ordre n'est pas celui d'ICU.
func localeOrder(a, b string) int {
	weight := func(c byte) int {
		switch {
		case '0' <= c && c <= '9':
			return 100 + int(c-'0')
		case 'a' <= c && c <= 'z':
			return 200 + int(c-'a')
		case 'A' <= c && c <= 'Z':
			return 200 + int(c-'A')
		}
		return int(c)
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if wa, wb := weight(a[i]), weight(b[i]); wa != wb {
			return wa - wb
		}
	}
	if len(a) != len(b) {
		return len(a) - len(b)
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return int(b[i]) - int(a[i])
		}
	}
	return 0
}

// dedupeOverlaps suit dedupeOverlaps de Secret Guard ; les longueurs des étendues sont comparées en unités UTF-16 de
// la source, comme en JavaScript.
func dedupeOverlaps(content []byte, findings []finding) []finding {
	// Longueur de chaque étendue mesurée une fois (et non à chaque comparaison du tri).
	type measured struct {
		finding
		units int
	}
	ranked := make([]measured, len(findings))
	for i, f := range findings {
		ranked[i] = measured{f, utf16Units(content[f.start:f.end])}
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		left, right := ranked[i], ranked[j]
		if d := specificityRank(left.finding) - specificityRank(right.finding); d != 0 {
			return d < 0
		}
		if left.score != right.score {
			return left.score > right.score
		}
		if left.units != right.units {
			return left.units > right.units
		}
		if d := encodingRanks[left.encoding] - encodingRanks[right.encoding]; d != 0 {
			return d < 0
		}
		return localeOrder(left.ruleID, right.ruleID) < 0
	})
	var kept []finding
	for _, m := range ranked {
		f := m.finding
		index := -1
		for k, existing := range kept {
			if existing.start < f.end && f.start < existing.end {
				index = k
				break
			}
		}
		if index < 0 {
			kept = append(kept, f)
			continue
		}
		kept[index].start = min(kept[index].start, f.start)
		kept[index].end = max(kept[index].end, f.end)
	}
	sort.SliceStable(kept, func(i, j int) bool {
		if kept[i].start != kept[j].start {
			return kept[i].start < kept[j].start
		}
		return kept[i].end < kept[j].end
	})
	return kept
}

// publicFindings rend les constats dans leur forme publique (score borné, niveau), sans les raisons internes ni la
// valeur ; avec key, chacun porte l'Empreinte locale de sa valeur. Avec key, un constat dont la valeur est vide
// (étendue hors de sa vue, ramenée à rien par view.slice) rend false : l'analyse est alors incomplète, jamais une
// Empreinte locale qui ne serait pas celle de la valeur détectée (fail-closed).
func publicFindings(findings []finding, key *FingerprintKey) ([]Finding, bool) {
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		score := boundedScore(f.score)
		public := Finding{
			RuleID: f.ruleID, SecretType: f.secretType, Encoding: f.encoding, Score: score, Level: levelForScore(score),
			ByteStart: f.start, ByteEnd: f.end,
		}
		if key != nil {
			if len(f.value) == 0 {
				return nil, false
			}
			public.LocalFingerprint = localFingerprint(*key, f.value)
		}
		out = append(out, public)
	}
	return out, true
}
