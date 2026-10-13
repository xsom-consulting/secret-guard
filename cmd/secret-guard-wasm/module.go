// Commande secret-guard-wasm : le moteur de détection en module WebAssembly WASI (preview 1), en mode bibliothèque
// (« reactor ») : l'hôte instancie le module une fois, appelle _initialize, puis appelle ses fonctions exportées
// autant de fois qu'il veut. Construction :
//
//	GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o dist/secret-guard.wasm ./cmd/secret-guard-wasm
//
// Fonctions exportées (main_wasip1.go) ; un pointeur est une adresse de la mémoire linéaire du module, rendue par
// sg_alloc :
//
//	sg_alloc(taille i32) → pointeur i32 (0 : refus)          tampon que l'hôte remplit
//	sg_free(pointeur i32)                                    efface puis libère un tampon
//	sg_load_pack(pointeur, longueur) → i32                   0 : Pack chargé ; 2 : refusé (Pack précédent gardé)
//	sg_set_fingerprint_key(pointeur, longueur) → i32         0 : clé de 32 octets gardée ; 2 : refusée
//	sg_clear_fingerprint_key()                               efface la clé
//	sg_scan(pointeur, longueur, langage, longueur) → i64     résultat JSON : (pointeur << 32) | longueur, 0 : refus
//	sg_scan_with_fingerprint(pointeur, longueur) → i64       même chose, avec l'Empreinte locale de chaque constat
//	sg_redact(pointeur, longueur, langage, longueur) → i64   masquage : document JSON, « \n », texte masqué (redact.go)
//	sg_find_hidden(pointeur, longueur) → i64                 rapport JSON des instructions cachées (hidden.go)
//
// Le résultat est le document JSON de la ligne de commande (internal/report) : jamais la valeur détectée. Le module
// n'importe que les fonctions WASI que demande le runtime Go (mémoire, hasard des tables de hachage, horloge du
// ramasse-miettes, écriture des erreurs fatales) : ni fichier, ni réseau.
package main

import (
	"unsafe"

	"github.com/xsom-consulting/secret-guard/detect"
	"github.com/xsom-consulting/secret-guard/internal/limits"
	"github.com/xsom-consulting/secret-guard/internal/report"
	"github.com/xsom-consulting/secret-guard/pack"
)

// Codes rendus par sg_load_pack et sg_set_fingerprint_key (ceux de la ligne de commande).
const (
	statusOK      = report.ExitClean
	statusRefused = report.ExitError
)

// maxBuffer : plus grand tampon que l'hôte peut demander (un Pack) ; une entrée à analyser n'a jamais besoin de plus
// de MaxInputBytes + 1 octets.
const maxBuffer = limits.MaxPackBytes

// module est l'état du module : tampons prêtés à l'hôte (gardés vivants tant qu'il ne les libère pas), règles
// chargées et clé d'Empreinte locale.
type module struct {
	buffers map[uintptr][]byte
	rules   *detect.Rules
	key     *detect.FingerprintKey
}

// state est créé à l'initialisation du module (_initialize), avec le Pack initial embarqué. Si le Pack initial ne se
// charge pas, rules reste nil : toute analyse est alors incomplète (scan_error), jamais « rien trouvé ».
var state = newModule()

func newModule() *module {
	m := &module{buffers: map[uintptr][]byte{}}
	if initial, err := pack.Initial(); err == nil {
		m.rules, _ = detect.LoadRules(initial)
	}
	return m
}

func address(buffer []byte) uintptr { return uintptr(unsafe.Pointer(unsafe.SliceData(buffer))) }

// alloc prête un tampon de size octets ; 0 pour une taille nulle ou au-delà de maxBuffer.
func (m *module) alloc(size uint32) uintptr {
	if size == 0 || size > maxBuffer {
		return 0
	}
	buffer := make([]byte, size)
	ptr := address(buffer)
	m.buffers[ptr] = buffer
	return ptr
}

// free efface puis oublie un tampon prêté ; sans effet sur une adresse inconnue.
func (m *module) free(ptr uintptr) {
	if buffer, ok := m.buffers[ptr]; ok {
		clear(buffer)
		delete(m.buffers, ptr)
	}
}

// slice rend les length premiers octets d'un tampon prêté ; faux pour une adresse inconnue ou une longueur qui
// dépasse le tampon.
func (m *module) slice(ptr uintptr, length uint32) ([]byte, bool) {
	buffer, ok := m.buffers[ptr]
	if !ok || uint64(length) > uint64(len(buffer)) {
		return nil, false
	}
	return buffer[:length], true
}

// loadPack remplace les règles par celles du Pack du tampon ; un Pack refusé laisse les règles en place.
func (m *module) loadPack(ptr uintptr, length uint32) int32 {
	data, ok := m.slice(ptr, length)
	if !ok {
		return statusRefused
	}
	decoded, err := pack.Decode(data)
	if err != nil {
		return statusRefused
	}
	rules, err := detect.LoadRules(decoded)
	if err != nil {
		return statusRefused
	}
	m.rules = rules
	return statusOK
}

// setKey garde la clé d'Empreinte locale du tampon (32 octets), effacé dans tous les cas.
func (m *module) setKey(ptr uintptr, length uint32) int32 {
	data, ok := m.slice(ptr, length)
	if !ok {
		return statusRefused
	}
	key, err := detect.NewFingerprintKey(data) // efface data, refus compris.
	if err != nil {
		return statusRefused
	}
	m.clearKey()
	m.key = &key
	return statusOK
}

func (m *module) clearKey() {
	if m.key != nil {
		m.key.Wipe()
		m.key = nil
	}
}

// scan analyse le tampon et rend le document JSON du résultat dans un nouveau tampon prêté (l'hôte le libère par
// free). Faux pour une entrée ou un identifiant de langage hors d'un tampon prêté, ou pour withFingerprint sans clé.
func (m *module) scan(ptr uintptr, length uint32, languagePtr uintptr, languageLength uint32, withFingerprint bool) (uintptr, uint32, bool) {
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
	var result detect.Result
	switch {
	case withFingerprint && m.key == nil:
		return 0, 0, false
	case withFingerprint:
		result = detect.ScanWithFingerprint(content, m.rules, *m.key)
	default:
		result = detect.Scan(content, m.rules, options)
	}
	document := report.JSON(result)
	out := m.alloc(uint32(len(document)))
	buffer, _ := m.slice(out, uint32(len(document)))
	copy(buffer, document)
	return out, uint32(len(document)), true
}
