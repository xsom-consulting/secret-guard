// Budget de travail du Pack de règles du client (docs/custom-pack.md, §5).
//
// Portage en Go de secret-guard/packages/core/src/custom/work.ts (Apache-2.0, origine, avis et modifications dans
// UPSTREAM.md). Une unité est un test de caractère ; une compression SHA-256 en vaut hashBlockCost. Le coût de chaque
// étape est celui de l'origine (mots, n-grammes, minuscules, contexte, entropie, recherche de l'ancre, texte
// visible), sauf la recherche des motifs : l'origine compte les pas de son automate à retour arrière, ce portage
// compte une borne du travail de RE2 (octets cherchés fois états du motif traduit, cost.go). Dépasser le budget rend
// l'analyse incomplète, jamais « rien trouvé ».

package custom

import "errors"

const (
	// ScanWorkBudget est le travail admis pour le Pack de règles du client dans une analyse
	// (CUSTOM_RULES_WORK_BUDGET de l'origine).
	ScanWorkBudget = 120_000_000
	// SelfTestWorkBudget est le travail admis pour un texte d'essai du Pack (SELF_TEST_WORK_BUDGET).
	SelfTestWorkBudget = 2_000_000
	// SelfTestsTotalBudget est le travail admis pour tous les textes d'essai d'un Pack (SELF_TESTS_TOTAL_BUDGET).
	SelfTestsTotalBudget = 150_000_000
	// hashBlockCost est le coût d'une compression SHA-256 (HASH_BLOCK_COST).
	hashBlockCost = 80
)

var (
	// ErrWorkBudget : l'analyse du Pack de règles du client a dépassé son budget de travail.
	ErrWorkBudget = errors.New("règles du client : budget de travail épuisé")
	// ErrTooManyMatches : les règles du client ont trouvé plus de correspondances que l'analyse n'en garde.
	ErrTooManyMatches = errors.New("règles du client : trop de correspondances")
)

// Meter compte le travail d'une analyse. Un compteur parent partage un budget plus grand entre plusieurs analyses
// (par exemple un prompt et les fichiers qu'il cite). Un Meter n'est pas sûr pour un usage concurrent.
type Meter struct {
	limit  int64
	used   int64
	parent *Meter
}

// NewMeter crée un compteur de limit unités, rattaché à parent (nil : aucun).
func NewMeter(limit int64, parent *Meter) *Meter { return &Meter{limit: limit, parent: parent} }

// Used rend le travail compté par ce compteur.
func (m *Meter) Used() int64 { return m.used }

// budgetExceeded et tooManyMatches sont levées pendant une analyse et rattrapées par Detect (exceptions de l'origine).
type budgetExceeded struct{}

type tooManyMatches struct{}

// spend compte units : le compteur, puis ses parents ; au-delà de la limite de l'un d'eux, l'analyse s'arrête.
func (m *Meter) spend(units int64) {
	m.used += units
	if m.parent != nil {
		m.parent.spend(units)
	}
	if m.used > m.limit {
		panic(budgetExceeded{})
	}
}
