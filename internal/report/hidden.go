package report

import (
	"encoding/json"

	"github.com/xsom-consulting/secret-guard/hidden"
)

// HiddenFinding est une suite de caractères cachés dans la forme JSON publique : sorte, position, nombre, étendue en
// octets ; jamais ce que les caractères écrivent.
type HiddenFinding struct {
	Kind      string `json:"kind"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	Count     int    `json:"count"`
	ByteStart int    `json:"byteStart"`
	ByteEnd   int    `json:"byteEnd"`
}

// HiddenDocument est le rapport des instructions cachées dans la forme JSON publique (ligne de commande,
// WebAssembly).
type HiddenDocument struct {
	Complete bool            `json:"complete"`
	Hidden   int             `json:"hidden"`
	Findings []HiddenFinding `json:"findings"`
}

// HiddenOf rend le document d'un rapport ; Findings n'est jamais nil (tableau vide en JSON).
func HiddenOf(r hidden.Report) HiddenDocument {
	document := HiddenDocument{Complete: r.Complete, Hidden: r.Hidden, Findings: []HiddenFinding{}}
	for _, f := range r.Findings {
		document.Findings = append(document.Findings, HiddenFinding{
			Kind: string(f.Kind), Line: f.Line, Column: f.Column, Count: f.Count, ByteStart: f.ByteStart, ByteEnd: f.ByteEnd,
		})
	}
	return document
}

// HiddenJSON écrit le document d'un rapport sur une ligne, terminée par une fin de ligne.
func HiddenJSON(r hidden.Report) []byte {
	data, err := json.Marshal(HiddenOf(r))
	if err != nil {
		// Chaînes et entiers seulement : l'écriture ne peut pas échouer.
		panic("report : écriture JSON impossible")
	}
	return append(data, '\n')
}

// HiddenExitCode rend le code de sortie d'un rapport : ExitError s'il est incomplet (texte de plus de 1 Mio, jamais
// « rien trouvé »), ExitFindings s'il signale au moins un caractère, ExitClean sinon.
func HiddenExitCode(r hidden.Report) int {
	switch {
	case !r.Complete:
		return ExitError
	case r.Hidden > 0:
		return ExitFindings
	}
	return ExitClean
}
