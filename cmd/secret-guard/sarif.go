// SPDX-License-Identifier: Apache-2.0

// Sortie SARIF 2.1.0 de « secret-guard scan --format sarif » : le format que lisent les outils d'analyse statique
// des forges et des éditeurs. Chaque constat y est un résultat : règle, fichier, ligne et colonne de début et de fin,
// étendue en octets, niveau. Comme la sortie JSON, il ne porte jamais la valeur détectée ni un extrait : aucune
// région n'a de « snippet », aucun message ne cite le texte analysé.
//
// Idée lue dans ggshield (GitGuardian, MIT), qui a une sortie SARIF ; aucune ligne n'en est reprise (UPSTREAM.md).
// Forme écrite d'après la spécification OASIS « Static Analysis Results Interchange Format (SARIF) Version 2.1.0 ».

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strings"
	"unicode/utf8"

	"github.com/xsom-consulting/secret-guard/detect"
)

const (
	formatJSON  = "json"
	formatSARIF = "sarif"
	// sarifVersion et sarifSchema : version du format et schéma de la norme (errata 01).
	sarifVersion = "2.1.0"
	sarifSchema  = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	sarifToolURI = "https://github.com/xsom-consulting/secret-guard"
	// sarifStdin : nom de l'artefact quand le contenu vient de l'entrée standard.
	sarifStdin = "stdin"
	// sarifFingerprint : nom de l'Empreinte locale dans partialFingerprints (HMAC sous la clé de l'appelant).
	sarifFingerprint = "secretGuardLocalFingerprint/v1"
)

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	// ColumnKind : les colonnes comptent des points de code Unicode, pas des unités UTF-16.
	ColumnKind string        `json:"columnKind"`
	Results    []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	Properties       map[string]string `json:"properties"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool                `json:"executionSuccessful"`
	Notifications       []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Descriptor sarifDescriptor `json:"descriptor"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
}

type sarifDescriptor struct {
	ID string `json:"id"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          sarifProperties   `json:"properties"`
}

type sarifProperties struct {
	SecretType string `json:"secretType"`
	Encoding   string `json:"encoding"`
	Score      int    `json:"score"`
	Level      string `json:"level"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// sarifRegion est l'étendue d'un constat : lignes et colonnes à partir de 1 (endColumn : colonne qui suit le dernier
// caractère), et étendue en octets du contenu analysé. Sans champ « snippet » : la valeur n'y figure jamais.
type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine"`
	EndColumn   int `json:"endColumn"`
	ByteOffset  int `json:"byteOffset"`
	ByteLength  int `json:"byteLength"`
}

// sarifLevel rend le niveau SARIF d'un niveau de constat : « error » pour CRITICAL et HIGH, « warning » pour MEDIUM,
// « note » pour LOW.
func sarifLevel(level detect.Level) string {
	switch level {
	case detect.LevelCritical, detect.LevelHigh:
		return "error"
	case detect.LevelMedium:
		return "warning"
	}
	return "note"
}

// sarifDocument écrit le résultat d'une analyse en SARIF, sur une ligne terminée par une fin de ligne. name est le
// fichier analysé tel que l'utilisateur l'a nommé (vide ou « - » : entrée standard) ; content, le contenu analysé,
// ne sert qu'à convertir les étendues en lignes et colonnes.
func sarifDocument(result detect.Result, name string, content []byte) []byte {
	uri := sarifStdin
	if name != "" && name != "-" {
		uri = sarifURI(name)
	}
	run := sarifRun{
		Tool:        sarifTool{Driver: sarifDriver{Name: "secret-guard", Version: moduleVersion(), InformationURI: sarifToolURI, Rules: []sarifRule{}}},
		Invocations: []sarifInvocation{{ExecutionSuccessful: result.Complete}},
		ColumnKind:  "unicodeCodePoints",
		Results:     []sarifResult{},
	}
	if !result.Complete {
		// Analyse incomplète : aucun résultat, et une notification d'erreur ; jamais « rien trouvé ».
		run.Invocations[0].Notifications = []sarifNotification{{
			Descriptor: sarifDescriptor{ID: string(result.Failure)},
			Level:      "error",
			Message:    sarifMessage{Text: "Analyse incomplète (" + string(result.Failure) + ") : aucun verdict, le contenu doit être traité comme non analysé."},
		}}
	}
	index := map[string]int{}
	for _, f := range result.Findings {
		ruleIndex, known := index[f.RuleID]
		if !known {
			ruleIndex = len(run.Tool.Driver.Rules)
			index[f.RuleID] = ruleIndex
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID:               f.RuleID,
				ShortDescription: sarifMessage{Text: "Règle " + f.RuleID + " (type de secret " + f.SecretType + ")"},
				Properties:       map[string]string{"secretType": f.SecretType},
			})
		}
		entry := sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: ruleIndex,
			Level:     sarifLevel(f.Level),
			Message: sarifMessage{Text: fmt.Sprintf("Secret détecté par la règle %s (type %s, niveau %s, score %d). La valeur n'est pas reproduite.",
				f.RuleID, f.SecretType, f.Level, f.Score)},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: uri},
				Region:           regionOf(content, f.ByteStart, f.ByteEnd),
			}}},
			Properties: sarifProperties{SecretType: f.SecretType, Encoding: string(f.Encoding), Score: f.Score, Level: string(f.Level)},
		}
		if f.LocalFingerprint != "" {
			entry.PartialFingerprints = map[string]string{sarifFingerprint: f.LocalFingerprint}
		}
		run.Results = append(run.Results, entry)
	}
	data, err := json.Marshal(sarifLog{Version: sarifVersion, Schema: sarifSchema, Runs: []sarifRun{run}})
	if err != nil {
		// Chaînes et entiers seulement : l'écriture ne peut pas échouer.
		panic("sarif : écriture JSON impossible")
	}
	return append(data, '\n')
}

// regionOf convertit l'étendue [start, end) en octets de content en région SARIF. Une étendue hors du contenu est
// ramenée dans ses bornes ; une étendue vide tient sur une colonne.
func regionOf(content []byte, start, end int) sarifRegion {
	start = min(max(start, 0), len(content))
	end = min(max(end, start), len(content))
	startLine, startColumn := lineColumn(content, start)
	region := sarifRegion{
		StartLine: startLine, StartColumn: startColumn, EndLine: startLine, EndColumn: startColumn,
		ByteOffset: start, ByteLength: end - start,
	}
	if end > start {
		// Dernier caractère de l'étendue (lineColumn recule au début de son point de code).
		line, column := lineColumn(content, end-1)
		region.EndLine, region.EndColumn = line, column+1
	}
	return region
}

// lineColumn rend la ligne et la colonne (en points de code, à partir de 1) de l'octet offset de content ; un octet
// au milieu d'un caractère a la colonne de ce caractère.
func lineColumn(content []byte, offset int) (int, int) {
	line := 1 + bytes.Count(content[:offset], []byte("\n"))
	lineStart := bytes.LastIndexByte(content[:offset], '\n') + 1
	for offset > lineStart && offset < len(content) && !utf8.RuneStart(content[offset]) {
		offset--
	}
	return line, 1 + utf8.RuneCount(content[lineStart:offset])
}

// sarifURI rend la référence d'URI d'un nom de fichier : barres obliques, et tout octet hors lettres, chiffres,
// « - », « . », « _ », « ~ » et « / » écrit « %XX » ; un chemin Windows à lettre de lecteur (« C:\… ») devient
// « file:///C:/… ». Écrite à la main : le programme livré n'importe pas net/url.
func sarifURI(name string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	start := 0
	if len(name) >= 3 && name[1] == ':' && (name[2] == '\\' || name[2] == '/') &&
		(name[0] >= 'a' && name[0] <= 'z' || name[0] >= 'A' && name[0] <= 'Z') {
		b.WriteString("file:///" + name[:2])
		start = 2
	}
	for i := start; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '\\':
			b.WriteByte('/')
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~', c == '/':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0F])
		}
	}
	return b.String()
}

// moduleVersion rend la version du module de la commande (« (devel) » hors d'une version publiée).
func moduleVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}
