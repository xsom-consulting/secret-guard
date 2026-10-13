// Package limits porte les limites du moteur de détection et du Pack de règles : seule source, lue par detect
// (taille d'entrée, constats) et par pack (bornes du schéma RulePack). Une valeur ne se change ici qu'avec le
// schéma (schema/RulePack.json, test de pack) et le corpus de parité.
package limits

const (
	// MaxInputBytes est la taille d'entrée la plus grande analysée, en octets reçus (MAX_INPUT_BYTES de Secret
	// Guard, 1 Mio). Au-delà, rien n'est analysé, pas même un préfixe.
	MaxInputBytes = 1 << 20
	// MaxFindings est le nombre de constats le plus grand avant déduplication (MAX_FINDINGS de Secret Guard) ;
	// au-delà, l'analyse est incomplète.
	MaxFindings = 2_048

	// MaxRules est le nombre de règles le plus grand d'un Pack (RULE_PACK_MAX_RULES).
	MaxRules = 1_000
	// MaxPatternUnits est la longueur la plus grande d'un motif, en unités UTF-16 (RULE_PATTERN_MAX_LENGTH).
	MaxPatternUnits = 4_096
	// MaxIdentifierLength est la longueur la plus grande d'un identifiant de règle ou d'un nom de validateur.
	MaxIdentifierLength = 64
	// MaxLengthBound est la plus grande valeur de minLength et maxLength : la taille d'entrée la plus grande
	// (RULE_LENGTH_BOUND_MAX).
	MaxLengthBound = MaxInputBytes
	// MaxScore est le score de base le plus élevé d'une règle.
	MaxScore = 100
	// MaxSchemaVersion est la plus grande version de schéma d'un Pack.
	MaxSchemaVersion = 1_000_000
	// MaxPackVersion est la plus grande version d'un Pack (Number.MAX_SAFE_INTEGER, 2^53 − 1).
	MaxPackVersion = 1<<53 - 1
	// MaxPackBytes est la taille la plus grande d'un document de Pack lu par pack.Decode : au-delà, il est refusé
	// avant toute lecture. Le plus grand Pack qui respecte le schéma, sans espace inutile, tient en moins de 26 Mio
	// (1 000 règles dont le motif de 4 096 unités est écrit en échappements \uXXXX).
	MaxPackBytes = 32 << 20
)
