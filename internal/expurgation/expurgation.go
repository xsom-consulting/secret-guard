// Package expurgation est l'expurgation à la demande du module WebAssembly : lecture stricte de la demande (Substituts
// déjà connus de l'appelant), numérotation des Substituts par Empreinte locale, puis detect.ExpurgateAndRescan. Le même
// code sert au module (cmd/secret-guard-wasm) et à l'outil de parité (tools/wasmparity), qui l'exécute en Go natif :
// la parité compare donc le même programme compilé pour les deux cibles.
package expurgation

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/xsom-consulting/secret-guard/detect"
	"github.com/xsom-consulting/secret-guard/internal/report"
)

// MaxRequestBytes est la taille la plus grande d'une demande : 999 Substituts connus tiennent en moins de 64 Kio.
const MaxRequestBytes = 64 << 10

// Known est un Substitut que l'appelant connaît déjà : l'Empreinte locale de la valeur et son numéro.
type Known struct {
	LocalFingerprint string `json:"localFingerprint"`
	Ordinal          int    `json:"ordinal"`
}

// Request est la demande d'expurgation : Substituts connus (une Empreinte locale déjà vue reprend son numéro) et plus
// petit numéro d'un nouveau Substitut (0 : aucun minimum).
type Request struct {
	Known      []Known `json:"known"`
	MinOrdinal int     `json:"minOrdinal"`
}

// ParseRequest lit une demande en JSON strict : objet seul, aucun champ inconnu, Empreintes locales de 32 caractères
// hexadécimaux minuscules, numéros de 1 à 999, ni Empreinte locale ni numéro répétés, minOrdinal de 0 à 999. Une
// demande vide vaut {} (aucun Substitut connu). Faux pour toute autre forme.
func ParseRequest(data []byte) (Request, bool) {
	if len(data) == 0 {
		return Request{}, true
	}
	if trimmed := bytes.TrimSpace(data); len(data) > MaxRequestBytes || len(trimmed) == 0 || trimmed[0] != '{' {
		// null se lirait comme {} : seul un objet est admis.
		return Request{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		return Request{}, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Request{}, false
	}
	if request.MinOrdinal < 0 || request.MinOrdinal > detect.MaxSubstituteOrdinal {
		return Request{}, false
	}
	if _, ok := newNumbering(request); !ok {
		return Request{}, false
	}
	return request, true
}

// numbering attribue les numéros des Substituts, un par Empreinte locale : une Empreinte locale connue reprend son
// numéro ; une nouvelle prend le numéro suivant, à partir du plus petit numéro au-dessus du plus grand numéro connu et
// d'au moins MinOrdinal. Au-delà de 999 : refus (l'expurgation échoue, ordinal_refused).
type numbering struct {
	byFingerprint map[string]int
	next          int
}

func newNumbering(request Request) (*numbering, bool) {
	n := &numbering{
		byFingerprint: make(map[string]int, len(request.Known)),
		next:          max(detect.MinSubstituteOrdinal, request.MinOrdinal),
	}
	ordinals := make(map[int]bool, len(request.Known))
	for _, entry := range request.Known {
		if !isFingerprint(entry.LocalFingerprint) || entry.Ordinal < detect.MinSubstituteOrdinal ||
			entry.Ordinal > detect.MaxSubstituteOrdinal || ordinals[entry.Ordinal] {
			return nil, false
		}
		if _, seen := n.byFingerprint[entry.LocalFingerprint]; seen {
			return nil, false
		}
		ordinals[entry.Ordinal] = true
		n.byFingerprint[entry.LocalFingerprint] = entry.Ordinal
		n.next = max(n.next, entry.Ordinal+1)
	}
	return n, true
}

// ordinal rend le numéro du constat ; faux pour un constat sans Empreinte locale ou au-delà de 999.
func (n *numbering) ordinal(f detect.Finding) (int, bool) {
	if f.LocalFingerprint == "" {
		return 0, false
	}
	if number, known := n.byFingerprint[f.LocalFingerprint]; known {
		return number, true
	}
	if n.next > detect.MaxSubstituteOrdinal {
		return 0, false
	}
	number := n.next
	n.next++
	n.byFingerprint[f.LocalFingerprint] = number
	return number, true
}

func isFingerprint(value string) bool {
	if len(value) != 32 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Run expurge content (detect.ExpurgateAndRescan, avec la clé d'Empreinte locale key) selon la demande et rend le
// document JSON de l'expurgation (report.ExpurgationJSON, une ligne terminée par « \n ») et le texte expurgé (nil sauf
// pour l'issue none). Le texte appartient à l'appelant, qui l'efface après usage.
func Run(content []byte, rules *detect.Rules, key *detect.FingerprintKey, options detect.Options, request Request) ([]byte, []byte) {
	numbers, ok := newNumbering(request)
	if !ok {
		// ParseRequest a déjà refusé cette demande ; défense en profondeur : aucun numéro, l'expurgation échoue.
		numbers = &numbering{byFingerprint: map[string]int{}, next: detect.MaxSubstituteOrdinal + 1}
	}
	text, substitutions, result := detect.ExpurgateAndRescan(content, rules, key, options, numbers.ordinal)
	return report.ExpurgationJSON(result, substitutions), text
}
