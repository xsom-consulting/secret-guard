// SPDX-License-Identifier: PolyForm-Small-Business-1.0.0

//go:build wasip1

package main

//go:wasmexport sg_find_hidden
func sgFindHidden(ptr, length uint32) uint64 { //nolint:unused // appelée par l'hôte
	return packed(state.findHidden(uintptr(ptr), length))
}
