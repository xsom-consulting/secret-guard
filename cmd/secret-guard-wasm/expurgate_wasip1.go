//go:build wasip1

package main

//go:wasmexport sg_expurgate
func sgExpurgate(ptr, length, languagePtr, languageLength, requestPtr, requestLength uint32) uint64 { //nolint:unused // appelée par l'hôte
	return packed(state.expurgate(uintptr(ptr), length, uintptr(languagePtr), languageLength, uintptr(requestPtr), requestLength))
}
