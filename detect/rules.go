// Règles du moteur de détection, chargées depuis un Pack de règles (package pack).
//
// Portage en Go de secret-guard/packages/core/src/rules.ts (Apache-2.0, origine, avis et modifications dans
// UPSTREAM.md). Les règles viennent du Pack, jamais d'un second catalogue : chaque motif non vide est compilé par
// regexp (RE2, aucun retour arrière) ; les règles « motif seul » (fixed_pattern) sont exécutées telles que le Pack
// les décrit (motif, type de secret, score, validateur nommé, bornes minLength/maxLength appliquées en code) ; les
// familles dont la logique n'est pas un motif seul (clés privées, URL à identifiants, affectations contextuelles,
// entropie) et la règle jwt (segments bornés au-delà de la limite de RE2) sont du code du moteur, activé par leur
// family et leur ruleId : le Pack doit alors décrire exactement ce que le moteur exécute (engineRules, généré avec le
// Pack initial), sinon il est refusé en entier.

package detect

import (
	"errors"
	"regexp"
	"regexp/syntax"

	"github.com/xsom-consulting/secret-guard/internal/limits"
	"github.com/xsom-consulting/secret-guard/pack"
)

// ErrPackUnusable : le Pack de règles ne peut pas être exécuté par ce moteur ; l'appelant le traite comme un Pack
// invalide (sans règles, aucune analyse ne peut conclure). Toute erreur de LoadRules l'enveloppe (errors.Is).
var ErrPackUnusable = errors.New("détection : Pack de règles inexploitable")

// PackRefusal est la raison, en liste fermée, d'un Pack refusé par le moteur.
type PackRefusal string

// Raisons d'un Pack refusé.
const (
	RefusalNoRule            PackRefusal = "no_rule"
	RefusalDuplicateRule     PackRefusal = "duplicate_rule"
	RefusalUnknownFamily     PackRefusal = "unknown_family"
	RefusalUnknownSecretType PackRefusal = "unknown_secret_type"
	RefusalUnknownValidator  PackRefusal = "unknown_validator"
	RefusalPatternRequired   PackRefusal = "pattern_required"
	RefusalPatternNotRE2     PackRefusal = "pattern_not_re2"
	RefusalInvalidBounds     PackRefusal = "invalid_bounds"
	RefusalInvalidScore      PackRefusal = "invalid_score"
	RefusalUnknownEngineRule PackRefusal = "unknown_engine_rule"
	RefusalEngineMismatch    PackRefusal = "engine_rule_mismatch"
	// RefusalPatternMatchesEmpty : un motif qui reconnaît le texte vide rendrait un constat vide à chaque position.
	RefusalPatternMatchesEmpty PackRefusal = "pattern_matches_empty"
	// RefusalIncompleteEngineFamily : une famille du moteur n'a qu'une partie de ses règles (le moteur les exécute
	// ensemble : une partie seule laisserait passer ce que l'autre aurait couvert).
	RefusalIncompleteEngineFamily PackRefusal = "incomplete_engine_family"
)

// PackError est l'erreur typée d'un Pack refusé : la raison et, s'il a une forme d'identifiant de règle, le ruleId
// fautif ; jamais un motif ni une valeur.
type PackError struct {
	RuleID string
	Reason PackRefusal
}

var ruleIDForm = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func (e *PackError) Error() string {
	message := "détection : Pack de règles inexploitable (" + string(e.Reason) + ")"
	if e.RuleID != "" {
		message += " : règle " + e.RuleID
	}
	return message
}

// Unwrap rattache le refus à ErrPackUnusable.
func (e *PackError) Unwrap() error { return ErrPackUnusable }

func refuse(ruleID string, reason PackRefusal) *PackError {
	if !ruleIDForm.MatchString(ruleID) {
		ruleID = ""
	}
	return &PackError{RuleID: ruleID, Reason: reason}
}

// Familles du Pack (RULE_FAMILIES, pack.Families).
const (
	familyFixedPattern         = "fixed_pattern"
	familyPrivateKey           = "private_key"
	familyCredentialURL        = "credential_url"
	familyContextualAssignment = "contextual_assignment"
	familyEntropy              = "entropy"
)

var knownFamilies = map[string]bool{
	familyFixedPattern: true, familyPrivateKey: true, familyCredentialURL: true, familyContextualAssignment: true,
	familyEntropy: true,
}

// knownSecretTypes : types de secret de Secret Guard (RULE_SECRET_TYPES).
var knownSecretTypes = map[string]bool{
	"private_key": true, "provider_token": true, "access_token": true, "jwt": true, "database_credentials": true,
	"cloud_credential": true, "password": true, "api_key": true, "generic_secret": true, "high_entropy": true,
}

// maxScore : score de base le plus élevé d'une règle (schéma RulePack).
const maxScore = limits.MaxScore

// engineRule est une règle dont le moteur porte la logique, telle qu'il l'exécute (engine_patterns.go, généré).
type engineRule struct {
	ruleID, family, secretType, validator, pattern string
	minLength, maxLength                           int
}

// Identifiants des règles dont le moteur porte la logique.
const (
	rulePrivateKeyComplete   = "private_key_pem"
	rulePrivateKeyIncomplete = "private_key_pem_incomplete"
	ruleJWT                  = "jwt"
	ruleDatabaseURL          = "database_url_credentials"
	ruleBasicAuthURL         = "basic_auth_url"
	ruleCookie               = "cookie_session_credential"
	ruleCLIBasicAuth         = "cli_basic_auth"
	ruleDockerAuth           = "docker_auth"
	ruleHighEntropy          = "high_entropy"
	contextualRulePrefix     = "contextual_"
)

// rule est une règle chargée du Pack.
type rule struct {
	id, family, secretType string
	score                  int
	validator              validator
	pattern                *regexp.Regexp
	// gate : porte littérale du motif (prefilter.go), nil sans porte (la règle s'exécute toujours).
	gate                 *literalGate
	minLength, maxLength int
}

// Rules est un Pack de règles chargé : règles « motif seul » dans l'ordre du Pack (jwt compris), règles dont le
// moteur porte la logique par identifiant. Immuable après LoadRules ; sûr pour des analyses concurrentes.
type Rules struct {
	fixed  []*rule
	engine map[string]*rule
	// ids : identifiants de toutes les règles du Pack chargé (Has).
	ids map[string]bool
	// loaded : posé par LoadRules seul ; une valeur zéro (ou construite hors de LoadRules) n'est jamais exécutée.
	loaded bool
}

// LoadRules compile le Pack (lu par pack.Decode, ou pack.Initial) pour le moteur. Il est refusé en entier
// (PackError, ErrPackUnusable) si une règle a une famille, un type de secret ou un validateur inconnus du moteur, un
// motif qui ne compile pas en RE2 ou qui reconnaît le texte vide, des bornes incohérentes, un score hors de 0..100,
// un identifiant en double, ou si une règle dont le moteur porte la logique diffère de ce qu'il exécute, ou si une
// famille du moteur n'a qu'une partie de ses règles. Le Pack n'est pas modifié ni retenu après l'appel.
func LoadRules(p *pack.Pack) (*Rules, error) {
	if p == nil || len(p.Rules) == 0 {
		return nil, refuse("", RefusalNoRule)
	}
	expected := map[string]engineRule{}
	for _, e := range engineRules {
		expected[e.ruleID] = e
	}
	loaded := &Rules{engine: map[string]*rule{}, ids: map[string]bool{}, loaded: true}
	seen := loaded.ids
	for _, elem := range p.Rules {
		spec := ruleSpec{
			RuleID: elem.RuleID, Family: string(elem.Family), SecretType: string(elem.SecretType),
			Validator: elem.Validator, Pattern: elem.Pattern, Score: elem.Score, MinLength: elem.MinLength,
			MaxLength: elem.MaxLength,
		}
		if seen[spec.RuleID] {
			return nil, refuse(spec.RuleID, RefusalDuplicateRule)
		}
		seen[spec.RuleID] = true
		r, err := loadRule(spec, expected)
		if err != nil {
			return nil, err
		}
		if _, isEngine := expected[spec.RuleID]; isEngine {
			loaded.engine[spec.RuleID] = r
		}
		if r.family == familyFixedPattern {
			loaded.fixed = append(loaded.fixed, r)
		}
	}
	for _, family := range engineFamilies {
		present := 0
		for _, id := range family {
			if loaded.engine[id] != nil {
				present++
			}
		}
		if present != 0 && present != len(family) {
			return nil, refuse(family[0], RefusalIncompleteEngineFamily)
		}
	}
	return loaded, nil
}

// Has dit si ruleID est l'identifiant d'une règle du Pack chargé (par exemple pour refuser un compte rendu qui cite
// une règle inconnue du Pack en vigueur). Faux pour un Pack non chargé par LoadRules.
func (r *Rules) Has(ruleID string) bool {
	return r != nil && r.loaded && r.ids[ruleID]
}

// engineFamilies : règles du moteur exécutées ensemble, toutes présentes ou toutes absentes du Pack.
var engineFamilies = [][]string{
	{rulePrivateKeyComplete, rulePrivateKeyIncomplete},
	{ruleDatabaseURL, ruleBasicAuthURL},
	{
		contextualRulePrefix + "password", contextualRulePrefix + "private_key", contextualRulePrefix + "cloud_credential",
		contextualRulePrefix + "api_key", contextualRulePrefix + "access_token", contextualRulePrefix + "generic_secret",
		contextualRulePrefix + "database_credentials",
	},
}

// minMatchLength : longueur minimale, en points de code, d'une correspondance de l'expression analysée.
func minMatchLength(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpLiteral:
		return len(re.Rune)
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 1
	case syntax.OpCapture, syntax.OpPlus:
		return minMatchLength(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min * minMatchLength(re.Sub[0])
	case syntax.OpConcat:
		total := 0
		for _, sub := range re.Sub {
			total += minMatchLength(sub)
		}
		return total
	case syntax.OpAlternate:
		least := -1
		for _, sub := range re.Sub {
			if n := minMatchLength(sub); least < 0 || n < least {
				least = n
			}
		}
		return max(least, 0)
	}
	// Assertions, texte vide, étoile, point d'interrogation, aucune correspondance.
	return 0
}

// ruleSpec est une règle du Pack (pack.Rule, schéma RulePack, docs/rule-pack.md), champs lus une fois.
type ruleSpec struct {
	RuleID, Family, SecretType, Validator, Pattern string
	Score, MinLength, MaxLength                    int
}

func loadRule(spec ruleSpec, expected map[string]engineRule) (*rule, error) {
	if !knownFamilies[spec.Family] {
		return nil, refuse(spec.RuleID, RefusalUnknownFamily)
	}
	if !knownSecretTypes[spec.SecretType] {
		return nil, refuse(spec.RuleID, RefusalUnknownSecretType)
	}
	check, known := validators[spec.Validator]
	if !known {
		return nil, refuse(spec.RuleID, RefusalUnknownValidator)
	}
	if spec.Score < 0 || spec.Score > maxScore {
		return nil, refuse(spec.RuleID, RefusalInvalidScore)
	}
	if spec.MinLength < 0 || spec.MaxLength < 0 || (spec.MinLength != 0 && spec.MaxLength != 0 && spec.MinLength > spec.MaxLength) ||
		(spec.Pattern == "" && (spec.MinLength != 0 || spec.MaxLength != 0)) {
		return nil, refuse(spec.RuleID, RefusalInvalidBounds)
	}
	if spec.Pattern == "" && spec.Family != familyContextualAssignment {
		return nil, refuse(spec.RuleID, RefusalPatternRequired)
	}
	var pattern *regexp.Regexp
	var gate *literalGate
	if spec.Pattern != "" {
		compiled, err := regexp.Compile(spec.Pattern)
		if err != nil {
			return nil, refuse(spec.RuleID, RefusalPatternNotRE2)
		}
		parsed, err := syntax.Parse(spec.Pattern, syntax.Perl)
		if err != nil || minMatchLength(parsed) == 0 {
			return nil, refuse(spec.RuleID, RefusalPatternMatchesEmpty)
		}
		pattern = compiled
		// Littéraux obligatoires, calculés une fois, depuis l'arbre analysé avec les drapeaux de regexp.Compile.
		gate = gateFor(parsed)
	}
	if e, isEngine := expected[spec.RuleID]; isEngine {
		if spec.Family != e.family || spec.SecretType != e.secretType || spec.Validator != e.validator ||
			spec.Pattern != e.pattern || spec.MinLength != e.minLength || spec.MaxLength != e.maxLength {
			return nil, refuse(spec.RuleID, RefusalEngineMismatch)
		}
	} else if spec.Family != familyFixedPattern {
		return nil, refuse(spec.RuleID, RefusalUnknownEngineRule)
	}
	return &rule{
		id: spec.RuleID, family: spec.Family, secretType: spec.SecretType, score: spec.Score, validator: check,
		pattern: pattern, gate: gate, minLength: spec.MinLength, maxLength: spec.MaxLength,
	}, nil
}

// finding est un constat d'une règle (InternalFinding de Secret Guard) : étendue d'octets de la source, score avant
// bornage, raisons, vue. value est la valeur dans la vue où la règle l'a trouvée (étendue du constat dans le texte de
// la vue, sans copie), lue seulement pour l'Empreinte locale puis effacée avec les tampons de l'analyse ;
// elle ne sort jamais du paquet.
type finding struct {
	ruleID     string
	secretType string
	start, end int
	score      int
	reasons    []string
	encoding   Encoding
	value      []byte
}

// encodingPenalty suit encodingPenalty de Secret Guard.
func encodingPenalty(encoding Encoding) int {
	switch encoding {
	case EncodingPercent, EncodingJSONEscaped, EncodingBase64, EncodingWhitespaceJoined:
		return 5
	}
	return 0
}

// encodingReasons suit encodingReasons de Secret Guard.
func encodingReasons(encoding Encoding) []string {
	switch encoding {
	case EncodingPlain:
		return []string{"fixed_format_match"}
	case EncodingNormalized:
		return []string{"fixed_format_match", "unicode_normalization"}
	case EncodingPercent:
		return []string{"fixed_format_match", "single_level_percent_decode"}
	case EncodingJSONEscaped:
		return []string{"fixed_format_match", "single_level_json_unicode_decode"}
	case EncodingWhitespaceJoined:
		return []string{"fixed_format_match", "bounded_line_join"}
	}
	return []string{"fixed_format_match", "single_level_base64_decode"}
}

// decodingReasons : raisons de la vue sans « fixed_format_match » (encodingReasons(…).slice(1) des règles
// contextuelles et des URL), vides pour la vue d'identité.
func decodingReasons(encoding Encoding) []string {
	if encoding == EncodingPlain {
		return nil
	}
	return encodingReasons(encoding)[1:]
}

// newFinding construit un constat dont l'étendue [viewStart, viewEnd) de la vue est ramenée à la source.
func newFinding(v *view, r *rule, viewStart, viewEnd, score int, reasons []string) finding {
	start, end := v.mapRange(viewStart, viewEnd)
	return finding{
		ruleID: r.id, secretType: r.secretType, start: start, end: end, score: score,
		reasons: append([]string(nil), reasons...), encoding: v.encoding,
		value: v.slice(viewStart, viewEnd),
	}
}

// contextualRuleFor rend la règle contextual_<type> du Pack, nil si elle en est absente (règle désactivée).
func (r *Rules) contextualRuleFor(secretType string) *rule {
	return r.engine[contextualRulePrefix+secretType]
}
