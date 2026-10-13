// Validité (docs/custom-pack.md, §2) et compilation d'un Pack de règles du client.
//
// Portage en Go de secret-guard/packages/core/src/custom/pack.ts (Apache-2.0, origine, avis et modifications dans
// UPSTREAM.md). La vérification de la signature n'est pas ici : celui qui distribue des Packs signés la vérifie avant
// de passer les octets de la charge à Compile. Le moteur ne décide que de la validité et de l'exécution d'un Pack.

package custom

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// ErrInvalidPack : le document n'est pas un Pack de règles du client valide. Toute erreur de Compile l'enveloppe
// (errors.Is).
var ErrInvalidPack = errors.New("Pack de règles du client refusé")

// PackErrorCode est le code, en liste fermée, d'un Pack refusé (§2, et self_test_incomplete).
type PackErrorCode string

// Codes d'un Pack refusé, dans l'ordre des contrôles du §2.
const (
	PackSchema              PackErrorCode = "schema"
	PackDuplicateDetector   PackErrorCode = "duplicate_detector"
	PackValidityWindow      PackErrorCode = "validity_window"
	PackTooManyDigests      PackErrorCode = "too_many_digests"
	PackInvalidPattern      PackErrorCode = "invalid_pattern"
	PackUnknownTestDetector PackErrorCode = "unknown_test_detector"
	PackMissingPositive     PackErrorCode = "missing_positive"
	PackPositiveNotDetected PackErrorCode = "positive_not_detected"
	PackNegativeDetected    PackErrorCode = "negative_detected"
	// PackSelfTestIncomplete : un essai du Pack a dépassé son budget de travail ; la validité n'a pas pu être
	// établie en un temps borné.
	PackSelfTestIncomplete PackErrorCode = "self_test_incomplete"
)

// PackErrorCodes rend la liste fermée des codes d'un Pack refusé, dans l'ordre des contrôles.
func PackErrorCodes() []PackErrorCode {
	return []PackErrorCode{
		PackSchema, PackDuplicateDetector, PackValidityWindow, PackTooManyDigests, PackInvalidPattern,
		PackUnknownTestDetector, PackMissingPositive, PackPositiveNotDetected, PackNegativeDetected,
		PackSelfTestIncomplete,
	}
}

// PackError est le refus typé d'un Pack : son code seulement, jamais un motif, un terme ni un texte d'essai.
type PackError struct {
	Code PackErrorCode
}

func (e *PackError) Error() string { return ErrInvalidPack.Error() + " (" + string(e.Code) + ")" }

// Unwrap rattache le refus à ErrInvalidPack.
func (e *PackError) Unwrap() error { return ErrInvalidPack }

// maxTotalDigests est le nombre total de condensats des détecteurs de termes d'un Pack (§2, étape 4).
const maxTotalDigests = 20_000

// Actions d'un détecteur.
const (
	ActionWarn  = "warn"
	ActionBlock = "block"
)

// Detector est l'identité d'un détecteur du Pack : identifiant, libellé, catégorie (Categories) et action
// (ActionWarn, ActionBlock). Jamais son motif ni ses condensats.
type Detector struct {
	ID       string
	Label    string
	Category string
	Action   string
}

// Pack est un Pack de règles du client valide, compilé : immuable, sûr pour des analyses concurrentes.
type Pack struct {
	packID, tenantID, issuedAt, expiresAt, issuer string
	version                                       int64
	detectors                                     []*detector
	groups                                        []termGroup
}

// PackID rend l'identifiant du Pack.
func (p *Pack) PackID() string { return p.packID }

// TenantID rend le client à qui le Pack est destiné.
func (p *Pack) TenantID() string { return p.tenantID }

// Version rend la version du Pack.
func (p *Pack) Version() int64 { return p.version }

// IssuedAt rend l'horodatage d'émission (AAAA-MM-JJTHH:MM:SSZ).
func (p *Pack) IssuedAt() string { return p.issuedAt }

// ExpiresAt rend l'horodatage d'expiration (AAAA-MM-JJTHH:MM:SSZ). Un Pack expiré reste applicable (§5) : il
// n'ajoute que des détections ; le juger est l'affaire de l'appelant.
func (p *Pack) ExpiresAt() string { return p.expiresAt }

// Issuer rend l'émetteur du Pack.
func (p *Pack) Issuer() string { return p.issuer }

// Detectors rend l'identité des détecteurs, dans l'ordre du Pack (Match.Detector en est l'index).
func (p *Pack) Detectors() []Detector {
	out := make([]Detector, len(p.detectors))
	for i, d := range p.detectors {
		out[i] = d.spec
	}
	return out
}

func refusePack(code PackErrorCode) (*Pack, error) { return nil, &PackError{Code: code} }

// compileDetector compile un détecteur ; nil si son motif est invalide.
func compileDetector(spec detectorSpec) *detector {
	d := &detector{spec: spec.Detector, minEntropyTenths: spec.minEntropyTenths}
	if spec.context != nil {
		context := &compiledContext{window: spec.context.window}
		for _, keyword := range spec.context.keywords {
			context.keywords = append(context.keywords, asciiLower([]byte(keyword)))
		}
		d.context = context
	}
	if spec.terms {
		terms := &termsDetector{salt: spec.salt, maxWords: spec.maxWords, digests: map[[sha256.Size]byte]bool{}}
		for _, digest := range spec.digests {
			var sum [sha256.Size]byte
			_, _ = hex.Decode(sum[:], []byte(digest)) // forme ^[0-9a-f]{64}$ déjà vérifiée par le schéma
			terms.digests[sum] = true
		}
		d.terms = terms
		return d
	}
	pattern, failure := compilePattern(spec.pattern, spec.context != nil, spec.caseInsensitive)
	if failure != "" {
		return nil
	}
	d.pattern = pattern
	return d
}

// Compile lit un Pack de règles du client (octets de la charge, document JSON du schéma CustomPack), le juge selon
// le §2, dans l'ordre du contrat, et le compile pour l'analyse. Les essais positifs et négatifs du Pack sont exécutés
// ici : un Pack qui ne détecte pas ce pour quoi il a été réglé n'est jamais appliqué.
//
// Refus : *PackError (errors.Is(err, ErrInvalidPack)), dont le code dit le premier contrôle en échec.
func Compile(data []byte) (*Pack, error) {
	payload, ok := decodePayload(data)
	if !ok {
		return refusePack(PackSchema)
	}
	index := map[string]int{}
	for i, d := range payload.detectors {
		if _, duplicate := index[d.ID]; duplicate {
			return refusePack(PackDuplicateDetector)
		}
		index[d.ID] = i
	}
	if payload.expiresAt <= payload.issuedAt { // chaînes de même forme : ordre lexicographique de l'origine
		return refusePack(PackValidityWindow)
	}
	digests := 0
	for _, d := range payload.detectors {
		digests += len(d.digests)
	}
	if digests > maxTotalDigests {
		return refusePack(PackTooManyDigests)
	}
	p := &Pack{
		packID: payload.packID, tenantID: payload.tenantID, issuedAt: payload.issuedAt, expiresAt: payload.expiresAt,
		issuer: payload.issuer, version: payload.version,
	}
	for _, spec := range payload.detectors {
		d := compileDetector(spec)
		if d == nil {
			return refusePack(PackInvalidPattern)
		}
		p.detectors = append(p.detectors, d)
	}
	tested := map[string]bool{}
	for _, positive := range payload.positives {
		if _, known := index[positive.detector]; !known {
			return refusePack(PackUnknownTestDetector)
		}
		tested[positive.detector] = true
	}
	for _, d := range payload.detectors {
		if !d.terms && !tested[d.ID] {
			return refusePack(PackMissingPositive)
		}
	}
	p.groups = termGroups(p.detectors)
	if code := p.selfTests(payload, index); code != "" {
		return refusePack(code)
	}
	return p, nil
}

// selfTests exécute les essais du Pack (§2, étapes 8 et 9) : chaque positif doit être détecté par son détecteur,
// aucun négatif par aucun détecteur. Chaque texte a son budget (SelfTestWorkBudget), tous partagent
// SelfTestsTotalBudget.
func (p *Pack) selfTests(payload *payload, indexOf map[string]int) PackErrorCode {
	total := NewMeter(SelfTestsTotalBudget, nil)
	for _, positive := range payload.positives {
		index := indexOf[positive.detector]
		results, err := p.detect([]byte(positive.text), NewMeter(SelfTestWorkBudget, total), -1, map[int]bool{index: true})
		if err != nil {
			return PackSelfTestIncomplete
		}
		if len(results[index]) == 0 {
			return PackPositiveNotDetected
		}
	}
	for _, negative := range payload.negatives {
		results, err := p.detect([]byte(negative), NewMeter(SelfTestWorkBudget, total), -1, nil)
		if err != nil {
			return PackSelfTestIncomplete
		}
		for _, matches := range results {
			if len(matches) > 0 {
				return PackNegativeDetected
			}
		}
	}
	return ""
}
