//go:build wasip1

// Exportations WebAssembly : chaque fonction ne fait que convertir les entiers de l'hôte (adresses de la mémoire
// linéaire, longueurs) pour l'état du module (module.go). Le linter « unused » ne voit pas les appels de l'hôte.

package main

// main n'est pas appelé en mode bibliothèque (-buildmode=c-shared) : _initialize n'exécute que les initialisations
// des paquets (state).
func main() {}

//go:wasmexport sg_alloc
func sgAlloc(size uint32) uint32 { //nolint:unused // appelée par l'hôte
	return uint32(state.alloc(size))
}

//go:wasmexport sg_free
func sgFree(ptr uint32) { //nolint:unused // appelée par l'hôte
	state.free(uintptr(ptr))
}

//go:wasmexport sg_load_pack
func sgLoadPack(ptr, length uint32) int32 { //nolint:unused // appelée par l'hôte
	return state.loadPack(uintptr(ptr), length)
}

//go:wasmexport sg_set_fingerprint_key
func sgSetFingerprintKey(ptr, length uint32) int32 { //nolint:unused // appelée par l'hôte
	return state.setKey(uintptr(ptr), length)
}

//go:wasmexport sg_clear_fingerprint_key
func sgClearFingerprintKey() { //nolint:unused // appelée par l'hôte
	state.clearKey()
}

//go:wasmexport sg_scan
func sgScan(ptr, length, languagePtr, languageLength uint32) uint64 { //nolint:unused // appelée par l'hôte
	return packed(state.scan(uintptr(ptr), length, uintptr(languagePtr), languageLength, false))
}

//go:wasmexport sg_scan_with_fingerprint
func sgScanWithFingerprint(ptr, length uint32) uint64 { //nolint:unused // appelée par l'hôte
	return packed(state.scan(uintptr(ptr), length, 0, 0, true))
}

// packed écrit un tampon de résultat en un seul entier : (pointeur << 32) | longueur ; 0 pour un refus.
func packed(ptr uintptr, length uint32, ok bool) uint64 { //nolint:unused // appelée par les exportations
	if !ok {
		return 0
	}
	return uint64(ptr)<<32 | uint64(length)
}
