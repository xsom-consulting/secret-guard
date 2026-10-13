// Résultat de l'analyse du moteur de détection.
//
// Forme portée de ScanResult et Finding de secret-guard/packages/core/src/types.ts (Apache-2.0, origine, avis et
// modifications dans UPSTREAM.md), réduite à ce qui peut sortir du moteur : aucun champ ne porte la valeur
// détectée, un extrait, un masque, un condensat ni une raison libre (test par réflexion « un constat ne porte jamais
// la valeur »).

package detect

import "github.com/xsom-consulting/secret-guard/custom"

// Failure est l'issue d'une analyse incomplète, en liste fermée (champ failure du corpus de parité).
type Failure string

// Issues d'une analyse.
const (
	// FailureNone : analyse complète.
	FailureNone Failure = "none"
	// FailureScanLimit : entrée de plus de MaxInputBytes octets, jamais analysée, même en partie.
	FailureScanLimit Failure = "scan_limit"
	// FailureScanError : budget de travail épuisé (vues, fenêtres, décodages), plus de MaxFindings constats, règles
	// absentes ou panique pendant l'analyse.
	FailureScanError Failure = "scan_error"
	// FailureCustomBudget : le Pack de règles du client (Options.Custom) a épuisé son budget de travail.
	FailureCustomBudget Failure = "custom_budget"
	// FailureCustomTooMany : le Pack de règles du client a trouvé plus de détections que l'analyse n'en garde
	// (MaxFindings moins les constats des règles intégrées).
	FailureCustomTooMany Failure = "custom_too_many"
)

// Level est le niveau d'un constat, déduit de son score (levelForScore de Secret Guard).
type Level string

// Niveaux d'un constat.
const (
	LevelLow      Level = "LOW"
	LevelMedium   Level = "MEDIUM"
	LevelHigh     Level = "HIGH"
	LevelCritical Level = "CRITICAL"
)

// Finding est un constat de l'analyse : règle, type de secret, vue où la valeur a été trouvée, score borné à
// [0, 100], niveau et étendue [ByteStart, ByteEnd) en octets du contenu analysé. Il ne porte jamais la valeur, ni un
// extrait, ni un masque, ni un condensat non salé. LocalFingerprint est l'Empreinte locale de la valeur (32
// caractères hexadécimaux minuscules, HMAC sous la clé de l'appelant, fingerprint.go), posée par ScanWithFingerprint
// seulement : vide après Scan.
type Finding struct {
	RuleID           string
	SecretType       string
	Encoding         Encoding
	Score            int
	Level            Level
	ByteStart        int
	ByteEnd          int
	LocalFingerprint string
}

// Result est le résultat d'une analyse. Complete est vrai si et seulement si Failure vaut FailureNone ; une analyse
// incomplète n'a aucun constat (jamais de verdict partiel) et doit être traitée comme un blocage.
type Result struct {
	Complete bool
	Failure  Failure
	Findings []Finding
}

// Options règle une analyse.
type Options struct {
	// LanguageID est l'identifiant de langage du contenu (languageId de Secret Guard : « typescript », « dotenv »…),
	// qui change la lecture des affectations ; vide : absent (undefined en JavaScript). Un identifiant vide mais
	// présent n'est pas représentable.
	LanguageID string
	// Custom est un Pack de règles du client compilé par custom.Compile (nil : aucun). Ses détections s'ajoutent aux
	// constats des règles intégrées (custom.go) ; il n'en retire ni n'en affaiblit aucun.
	Custom *custom.Pack
}

func (o Options) language() language {
	if o.LanguageID == "" {
		return language{}
	}
	return language{id: o.LanguageID, set: true}
}
