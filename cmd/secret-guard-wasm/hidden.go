package main

import (
	"github.com/xsom-consulting/secret-guard/hidden"
	"github.com/xsom-consulting/secret-guard/internal/report"
)

// findHidden relève les instructions cachées du tampon et rend le rapport JSON (internal/report, forme de
// « secret-guard hidden ») dans un nouveau tampon prêté. Faux pour une entrée hors d'un tampon prêté. Au-delà de
// 1 Mio, le rapport est incomplet (complete: false), jamais « rien trouvé ».
func (m *module) findHidden(ptr uintptr, length uint32) (uintptr, uint32, bool) {
	content, ok := m.slice(ptr, length)
	if !ok {
		return 0, 0, false
	}
	document := report.HiddenJSON(hidden.Find(content))
	out := m.alloc(uint32(len(document)))
	buffer, _ := m.slice(out, uint32(len(document)))
	copy(buffer, document)
	return out, uint32(len(document)), true
}
