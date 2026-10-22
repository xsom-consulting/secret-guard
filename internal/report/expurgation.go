package report

import (
	"encoding/json"

	"github.com/xsom-consulting/secret-guard/detect"
)

// Substitution est un Substitut posé par l'expurgation, dans la forme JSON publique : règle et type de secret du
// constat représentatif, étendue remplacée dans le texte d'origine (octets et unités UTF-16), Empreinte locale des
// octets remplacés, numéro et Substitut écrit. Jamais la valeur remplacée.
type Substitution struct {
	RuleID           string `json:"ruleId"`
	SecretType       string `json:"secretType"`
	ByteStart        int    `json:"byteStart"`
	ByteEnd          int    `json:"byteEnd"`
	UTF16Start       int    `json:"utf16Start"`
	UTF16End         int    `json:"utf16End"`
	LocalFingerprint string `json:"localFingerprint"`
	Ordinal          int    `json:"ordinal"`
	Replacement      string `json:"replacement"`
}

// Expurgation est l'issue d'une expurgation suivie d'une nouvelle analyse dans la forme JSON publique : issue
// (none, incomplete, residual, ordinal_refused), analyse de l'entrée, analyse du texte expurgé, Substituts posés
// (vide sauf pour l'issue none). Il ne porte aucun texte : le texte expurgé, quand il existe, est rendu à part.
type Expurgation struct {
	Failure       string         `json:"failure"`
	Initial       Document       `json:"initial"`
	Final         Document       `json:"final"`
	Substitutions []Substitution `json:"substitutions"`
}

// ExpurgationOf rend le document d'une expurgation ; Substitutions n'est jamais nil (tableau vide en JSON).
func ExpurgationOf(result detect.SanitizeResult, substitutions []detect.Substitution) Expurgation {
	document := Expurgation{
		Failure: string(result.Failure), Initial: Of(result.Initial), Final: Of(result.Final),
		Substitutions: []Substitution{},
	}
	for _, s := range substitutions {
		document.Substitutions = append(document.Substitutions, Substitution{
			RuleID: s.RuleID, SecretType: s.SecretType, ByteStart: s.ByteStart, ByteEnd: s.ByteEnd,
			UTF16Start: s.UTF16Start, UTF16End: s.UTF16End, LocalFingerprint: s.LocalFingerprint, Ordinal: s.Ordinal,
			Replacement: s.Replacement,
		})
	}
	return document
}

// ExpurgationJSON écrit le document d'une expurgation sur une ligne, terminée par une fin de ligne.
func ExpurgationJSON(result detect.SanitizeResult, substitutions []detect.Substitution) []byte {
	data, err := json.Marshal(ExpurgationOf(result, substitutions))
	if err != nil {
		// Chaînes et entiers seulement : l'écriture ne peut pas échouer.
		panic("report : écriture JSON impossible")
	}
	return append(data, '\n')
}
