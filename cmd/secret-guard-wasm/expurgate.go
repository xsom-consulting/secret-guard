package main

import (
	"github.com/xsom-consulting/secret-guard/detect"
	"github.com/xsom-consulting/secret-guard/internal/expurgation"
)

// expurgate expurge le tampon (detect.ExpurgateAndRescan, Substituts typés numérotés par Empreinte locale) et rend,
// dans un nouveau tampon prêté (l'hôte le libère par free), le document JSON de l'expurgation (une ligne terminée par
// « \n ») suivi du texte expurgé quand il est rendu (issue none) ; rien après la fin de ligne sinon. La demande
// (requestPtr, requestLength ; longueur nulle : aucune) donne les Substituts déjà connus (internal/expurgation) ;
// l'identifiant de langage (languagePtr, languageLength) est facultatif, comme pour scan. Faux pour une entrée, un
// identifiant de langage ou une demande hors d'un tampon prêté, une demande refusée, ou sans clé d'Empreinte locale (le
// numéro d'un Substitut suit l'Empreinte locale de sa valeur). La copie du texte expurgé faite par le moteur est
// effacée.
func (m *module) expurgate(ptr uintptr, length uint32, languagePtr uintptr, languageLength uint32, requestPtr uintptr, requestLength uint32) (uintptr, uint32, bool) {
	content, ok := m.slice(ptr, length)
	if !ok || m.key == nil {
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
	var data []byte
	if requestLength > 0 {
		if data, ok = m.slice(requestPtr, requestLength); !ok {
			return 0, 0, false
		}
	}
	request, ok := expurgation.ParseRequest(data)
	if !ok {
		return 0, 0, false
	}
	document, text := expurgation.Run(content, m.rules, m.key, options, request)
	defer clear(text)
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
