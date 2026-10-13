// Package report écrit le résultat d'une analyse dans la forme JSON commune à la ligne de commande et au module
// WebAssembly : issue, puis constats (règle, type de secret, vue, score, niveau, étendue en octets, Empreinte locale
// si elle a été calculée). Rien d'autre : ni valeur, ni extrait, ni masque, ni condensat non salé.
package report

import (
	"encoding/json"

	"github.com/xsom-consulting/secret-guard/detect"
)

// Codes de sortie de la ligne de commande, rendus aussi par le module WebAssembly.
const (
	// ExitClean : analyse complète, aucun constat.
	ExitClean = 0
	// ExitFindings : analyse complète, au moins un constat.
	ExitFindings = 1
	// ExitError : erreur (usage, lecture, Pack refusé) ou analyse incomplète (entrée de plus de 1 Mio, budget
	// épuisé) ; une analyse incomplète n'a aucun constat et ne doit jamais être lue comme « rien trouvé ».
	ExitError = 2
)

// Finding est un constat dans la forme JSON publique.
type Finding struct {
	RuleID           string `json:"ruleId"`
	SecretType       string `json:"secretType"`
	Encoding         string `json:"encoding"`
	Score            int    `json:"score"`
	Level            string `json:"level"`
	ByteStart        int    `json:"byteStart"`
	ByteEnd          int    `json:"byteEnd"`
	LocalFingerprint string `json:"localFingerprint,omitempty"`
}

// Document est le résultat d'une analyse dans la forme JSON publique.
type Document struct {
	Complete bool      `json:"complete"`
	Failure  string    `json:"failure"`
	Findings []Finding `json:"findings"`
}

// Of rend le document d'un résultat ; Findings n'est jamais nil (tableau vide en JSON).
func Of(result detect.Result) Document {
	document := Document{Complete: result.Complete, Failure: string(result.Failure), Findings: []Finding{}}
	for _, f := range result.Findings {
		document.Findings = append(document.Findings, Finding{
			RuleID: f.RuleID, SecretType: f.SecretType, Encoding: string(f.Encoding), Score: f.Score,
			Level: string(f.Level), ByteStart: f.ByteStart, ByteEnd: f.ByteEnd, LocalFingerprint: f.LocalFingerprint,
		})
	}
	return document
}

// JSON écrit le document d'un résultat sur une ligne, terminée par une fin de ligne.
func JSON(result detect.Result) []byte {
	data, err := json.Marshal(Of(result))
	if err != nil {
		// Chaînes et entiers seulement : l'écriture ne peut pas échouer.
		panic("report : écriture JSON impossible")
	}
	return append(data, '\n')
}

// ExitCode rend le code de sortie d'un résultat : ExitError pour une analyse incomplète, ExitFindings s'il y a au
// moins un constat, ExitClean sinon.
func ExitCode(result detect.Result) int {
	switch {
	case !result.Complete || result.Failure != detect.FailureNone:
		return ExitError
	case len(result.Findings) > 0:
		return ExitFindings
	}
	return ExitClean
}
