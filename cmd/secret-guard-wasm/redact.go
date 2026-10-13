package main

import (
	"github.com/xsom-consulting/secret-guard/detect"
	"github.com/xsom-consulting/secret-guard/internal/report"
)

// redact masque le tampon (detect.RedactAndRescan) et rend, dans un nouveau tampon prêté (l'hôte le libère par
// free), le document JSON du masquage (internal/report, une ligne terminée par « \n ») suivi du texte masqué quand
// il est rendu (issue none) ; rien après la fin de ligne sinon. Faux pour une entrée ou un identifiant de langage
// hors d'un tampon prêté. La copie du texte masqué faite par le moteur est effacée.
func (m *module) redact(ptr uintptr, length uint32, languagePtr uintptr, languageLength uint32) (uintptr, uint32, bool) {
	content, ok := m.slice(ptr, length)
	if !ok {
		return 0, 0, false
	}
	var options detect.Options
	if languageLength > 0 {
		language, ok := m.slice(languagePtr, languageLength)
		if !ok {
			return 0, 0, false
		}
		options.LanguageID = string(language)
	}
	text, result := detect.RedactAndRescan(content, m.rules, options, detect.RedactOptions{})
	defer clear(text)
	document := report.RedactionJSON(result)
	size := uint32(len(document) + len(text))
	out := m.alloc(size)
	buffer, ok := m.slice(out, size)
	if !ok {
		return 0, 0, false
	}
	copy(buffer, document)
	copy(buffer[len(document):], text)
	return out, size, true
}
