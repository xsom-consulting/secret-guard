//go:build !wasip1

package main

import (
	"fmt"
	"os"
)

// main hors de WebAssembly : ce programme n'est qu'un module WASI ; il refuse de s'exécuter ailleurs.
func main() {
	_, _ = fmt.Fprintln(os.Stderr, "secret-guard-wasm : module WebAssembly ; construire avec GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared")
	os.Exit(2)
}
