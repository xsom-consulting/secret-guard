package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The test executable acts as a portable linter witness. Inspect the command
// actually spawned by lint, not a separate list of intended package patterns.
func TestMain(m *testing.M) {
	if os.Getenv("DEPGUARD_SCOPE_WITNESS") == "1" {
		want := []string{"run", "--config", filepath.Join(os.Getenv("DEPGUARD_SCOPE_DIR"), ".golangci.yml"), "./..."}
		if !slices.Equal(os.Args[1:], want) {
			os.Exit(1)
		}
		_, _ = fmt.Fprintln(os.Stdout, "scope verified")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestLintCoversWholeModule(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("témoin du linter indisponible")
	}
	dir := t.TempDir()
	t.Setenv("GOLANGCI_LINT", executable)
	t.Setenv("DEPGUARD_SCOPE_WITNESS", "1")
	t.Setenv("DEPGUARD_SCOPE_DIR", dir)
	output, err := lint(dir)
	if err != nil || output != "scope verified\n" {
		t.Fatal("le linter doit examiner tout le module")
	}
}
