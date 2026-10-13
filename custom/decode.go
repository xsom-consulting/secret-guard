// Lecture stricte d'un Pack de règles du client : schéma schema/CustomPack.json (docs/custom-pack.md, §2 étape 1).
//
// Portage en Go de secret-guard/packages/core/src/custom/schema.ts (Apache-2.0, origine, avis et modifications dans
// UPSTREAM.md), qui juge une valeur JSON déjà lue ; ce portage lit les octets du document : JSON invalide, UTF-8
// invalide, substitut isolé, membre en double ou contenu après le document sont refusés comme un document hors
// schéma. Les longueurs de texte sont comptées en points de code, comme JSON Schema.

package custom

import (
	"encoding/json/v2"
	"math"
	"regexp"
	"slices"
	"unicode/utf8"
)

// MaxPackBytes est la taille la plus grande d'un document de Pack lu par Compile : au-delà, il est refusé avant
// toute lecture. Le plus grand Pack qui respecte le schéma, sans espace inutile, tient en moins de 12 Mio (essais de
// 2 000 points de code écrits en échappements \uXXXX).
const MaxPackBytes = 16 << 20

// Formes du schéma (même sens en RE2 qu'en JavaScript : ASCII seulement, « $ » en fin de texte).
var (
	identifierForm = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	timestampForm  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	keywordForm    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.@:/-]{1,39}$`)
	saltForm       = regexp.MustCompile(`^[A-Za-z0-9+/]{22}==$|^[A-Za-z0-9+/]{43}=$`)
	digestForm     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Valeurs fixes du schéma.
const (
	payloadKind = "xsom.secret-guard.rules-pack"
	maxVersion  = 2147483647
)

// Categories rend la liste fermée des catégories d'un détecteur, dans l'ordre du schéma.
func Categories() []string {
	return []string{"credential", "customer_data", "personal_data", "internal_infra", "project"}
}

type object = map[string]any

// hasOnly dit si value porte tous les membres required et aucun autre que required et optional.
func hasOnly(value object, required []string, optional ...string) bool {
	for _, key := range required {
		if _, ok := value[key]; !ok {
			return false
		}
	}
	for key := range value {
		if !slices.Contains(required, key) && !slices.Contains(optional, key) {
			return false
		}
	}
	return true
}

func isText(value any, minimum, maximum int) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	length := utf8.RuneCountInString(text)
	return length >= minimum && length <= maximum
}

// isInteger suit Number.isInteger de JavaScript et les bornes du schéma (1.0, 1e0 et -0 sont des entiers).
func isInteger(value any, minimum, maximum float64) bool {
	number, ok := value.(float64)
	return ok && number == math.Trunc(number) && !math.IsInf(number, 0) && number >= minimum && number <= maximum
}

func isArray(value any, minimum, maximum int) ([]any, bool) {
	items, ok := value.([]any)
	return items, ok && len(items) >= minimum && len(items) <= maximum
}

func matches(value any, form *regexp.Regexp) bool {
	text, ok := value.(string)
	return ok && form.MatchString(text)
}

// unique dit si les chaînes de items sont toutes différentes (items déjà jugés : des chaînes).
func unique(items []any) bool {
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		text, _ := item.(string)
		if seen[text] {
			return false
		}
		seen[text] = true
	}
	return true
}

func isContext(value any) bool {
	context, ok := value.(object)
	if !ok || !hasOnly(context, []string{"keywords", "window"}) {
		return false
	}
	keywords, ok := isArray(context["keywords"], 1, 20)
	if !ok {
		return false
	}
	for _, keyword := range keywords {
		if !matches(keyword, keywordForm) {
			return false
		}
	}
	return unique(keywords) && isInteger(context["window"], 1, 256)
}

func isPatternMatch(match object) bool {
	if !hasOnly(match, []string{"type", "pattern"}, "caseInsensitive", "minEntropyTenths") || match["type"] != "pattern" ||
		!isText(match["pattern"], 1, 256) {
		return false
	}
	if value, ok := match["caseInsensitive"]; ok {
		if _, isBool := value.(bool); !isBool {
			return false
		}
	}
	if value, ok := match["minEntropyTenths"]; ok && !isInteger(value, 0, 80) {
		return false
	}
	return true
}

func isTermsMatch(match object) bool {
	if !hasOnly(match, []string{"type", "salt", "digests", "maxWords"}) || match["type"] != "terms" ||
		!matches(match["salt"], saltForm) {
		return false
	}
	digests, ok := isArray(match["digests"], 1, 5000)
	if !ok {
		return false
	}
	for _, digest := range digests {
		if !matches(digest, digestForm) {
			return false
		}
	}
	return unique(digests) && isInteger(match["maxWords"], 1, 4)
}

func isDetector(value any) bool {
	d, ok := value.(object)
	if !ok || !hasOnly(d, []string{"id", "label", "category", "action", "match"}, "context") {
		return false
	}
	category, _ := d["category"].(string)
	match, ok := d["match"].(object)
	if !matches(d["id"], identifierForm) || !isText(d["label"], 1, 80) || !slices.Contains(Categories(), category) ||
		(d["action"] != "warn" && d["action"] != "block") || !ok || (!isPatternMatch(match) && !isTermsMatch(match)) {
		return false
	}
	if context, present := d["context"]; present && !isContext(context) {
		return false
	}
	return true
}

func isTests(value any) bool {
	tests, ok := value.(object)
	if !ok || !hasOnly(tests, []string{"positives", "negatives"}) {
		return false
	}
	positives, ok := isArray(tests["positives"], 0, 200)
	if !ok {
		return false
	}
	for _, item := range positives {
		positive, ok := item.(object)
		if !ok || !hasOnly(positive, []string{"detector", "text"}) || !matches(positive["detector"], identifierForm) ||
			!isText(positive["text"], 1, 2000) {
			return false
		}
	}
	negatives, ok := isArray(tests["negatives"], 0, 200)
	if !ok {
		return false
	}
	for _, negative := range negatives {
		if !isText(negative, 1, 2000) {
			return false
		}
	}
	return true
}

// isPayload suit isRulesPackPayload de l'origine.
func isPayload(value any) bool {
	p, ok := value.(object)
	if !ok || !hasOnly(p, []string{
		"schemaVersion", "kind", "packId", "tenantId", "version", "issuedAt", "expiresAt", "issuer", "detectors", "tests",
	}) {
		return false
	}
	if p["schemaVersion"] != float64(1) || p["kind"] != payloadKind || !matches(p["packId"], identifierForm) ||
		!isText(p["tenantId"], 1, 128) || !isInteger(p["version"], 1, maxVersion) ||
		!matches(p["issuedAt"], timestampForm) || !matches(p["expiresAt"], timestampForm) || !isText(p["issuer"], 1, 80) {
		return false
	}
	detectors, ok := isArray(p["detectors"], 1, 200)
	if !ok {
		return false
	}
	for _, d := range detectors {
		if !isDetector(d) {
			return false
		}
	}
	return isTests(p["tests"])
}

// payload est un document jugé conforme au schéma.
type payload struct {
	packID, tenantID, issuedAt, expiresAt, issuer string
	version                                       int64
	detectors                                     []detectorSpec
	positives                                     []positive
	negatives                                     []string
}

type detectorSpec struct {
	Detector
	pattern          string
	caseInsensitive  bool
	minEntropyTenths int // -1 : sans seuil
	terms            bool
	salt             string
	digests          []string
	maxWords         int
	context          *contextSpec
}

type contextSpec struct {
	keywords []string
	window   int
}

type positive struct {
	detector, text string
}

// decodePayload lit un document ; rend false s'il n'est pas un Pack du schéma.
func decodePayload(data []byte) (*payload, bool) {
	if len(data) > MaxPackBytes {
		return nil, false
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil || !isPayload(value) {
		return nil, false
	}
	p := value.(object)
	tests := p["tests"].(object)
	out := &payload{
		packID: p["packId"].(string), tenantID: p["tenantId"].(string), issuedAt: p["issuedAt"].(string),
		expiresAt: p["expiresAt"].(string), issuer: p["issuer"].(string), version: int64(p["version"].(float64)),
	}
	for _, item := range p["detectors"].([]any) {
		out.detectors = append(out.detectors, detectorSpecOf(item.(object)))
	}
	for _, item := range tests["positives"].([]any) {
		entry := item.(object)
		out.positives = append(out.positives, positive{detector: entry["detector"].(string), text: entry["text"].(string)})
	}
	for _, negative := range tests["negatives"].([]any) {
		out.negatives = append(out.negatives, negative.(string))
	}
	return out, true
}

// detectorSpecOf lit un détecteur déjà jugé conforme au schéma (isDetector).
func detectorSpecOf(d object) detectorSpec {
	match := d["match"].(object)
	spec := detectorSpec{
		Detector: Detector{
			ID: d["id"].(string), Label: d["label"].(string), Category: d["category"].(string), Action: d["action"].(string),
		},
		minEntropyTenths: -1,
	}
	if match["type"] == "terms" {
		spec.terms, spec.salt, spec.maxWords = true, match["salt"].(string), int(match["maxWords"].(float64))
		for _, digest := range match["digests"].([]any) {
			spec.digests = append(spec.digests, digest.(string))
		}
	} else {
		spec.pattern = match["pattern"].(string)
		spec.caseInsensitive = match["caseInsensitive"] == true
		if tenths, ok := match["minEntropyTenths"]; ok {
			spec.minEntropyTenths = int(tenths.(float64))
		}
	}
	if context, ok := d["context"].(object); ok {
		c := &contextSpec{window: int(context["window"].(float64))}
		for _, keyword := range context["keywords"].([]any) {
			c.keywords = append(c.keywords, keyword.(string))
		}
		spec.context = c
	}
	return spec
}
