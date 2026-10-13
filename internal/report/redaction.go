package report

import (
	"encoding/json"

	"github.com/xsom-consulting/secret-guard/detect"
)

// Redaction est l'issue d'un masquage suivi d'une nouvelle analyse dans la forme JSON publique : issue
// (none, incomplete, residual), analyse de l'entrée, analyse du texte masqué. Il ne porte aucun texte : le texte
// masqué, quand il existe, est rendu à part.
type Redaction struct {
	Failure string   `json:"failure"`
	Initial Document `json:"initial"`
	Final   Document `json:"final"`
}

// RedactionOf rend le document d'un masquage.
func RedactionOf(result detect.SanitizeResult) Redaction {
	return Redaction{Failure: string(result.Failure), Initial: Of(result.Initial), Final: Of(result.Final)}
}

// RedactionJSON écrit le document d'un masquage sur une ligne, terminée par une fin de ligne.
func RedactionJSON(result detect.SanitizeResult) []byte {
	data, err := json.Marshal(RedactionOf(result))
	if err != nil {
		// Chaînes et entiers seulement : l'écriture ne peut pas échouer.
		panic("report : écriture JSON impossible")
	}
	return append(data, '\n')
}
