package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/internal/report"
)

func TestRedactCommand(t *testing.T) {
	token := syntheticToken()
	password := "Xq7" + "Lm2Pz9" + "!Wr4Tn"
	files := memoryFiles{
		"propre.txt":  []byte("rien à signaler\n"),
		"secret.env":  []byte("TOKEN=" + token + "\nDB_PASSWORD=" + password + "\n"),
		"residu.env":  []byte("API_KEY=" + token + "\nNEXT=another"),
		"grand.bin":   append(bytes.Repeat([]byte("a"), 1<<20), []byte(" "+token)...),
		"pack-propre": []byte(`{"schemaVersion":1,"minAgentVersion":"0.1.0","packVersion":2,"issuedAt":"2026-10-07T00:00:00Z","rules":[{"ruleId":"demo_rule","family":"fixed_pattern","secretType":"api_key","score":80,"validator":"","pattern":"\\bdemo_[a-z]{8}\\b","minLength":0,"maxLength":0}]}`),
		"pack-vide":   []byte(`{}`),
	}
	t.Run("secrets masqués : code 1, texte masqué sur la sortie standard, sans la valeur", func(t *testing.T) {
		want := "TOKEN=<REDACTED_github_token>\nDB_PASSWORD=<REDACTED_contextual_password>\n"
		for _, args := range [][]string{{"redact", "secret.env"}, {"redact"}, {"redact", "-"}} {
			code, stdout, stderr := runCommand(t, files, string(files["secret.env"]), args...)
			if code != report.ExitFindings || stdout != want || stderr != "" {
				t.Fatalf("%v : code %d, %q, %q", args, code, stdout, stderr)
			}
			if leaks(stdout+stderr, token) || strings.Contains(stdout+stderr, password) {
				t.Fatalf("%v : la sortie contient la valeur", args)
			}
		}
	})
	t.Run("rien à masquer : code 0, texte recopié", func(t *testing.T) {
		code, stdout, stderr := runCommand(t, files, "", "redact", "propre.txt")
		if code != report.ExitClean || stdout != "rien à signaler\n" || stderr != "" {
			t.Fatalf("code %d, %q, %q", code, stdout, stderr)
		}
		if code, stdout, _ := runCommand(t, files, "", "redact"); code != report.ExitClean || stdout != "" {
			t.Fatalf("entrée vide : code %d, %q", code, stdout)
		}
	})
	t.Run("échecs du masquage : code 2, rien sur la sortie standard, raison sans la valeur", func(t *testing.T) {
		for name, c := range map[string]struct {
			file, want string
		}{
			"plus de 1 Mio": {"grand.bin", "analyse incomplète (scan_limit)"},
			"résidu":        {"residu.env", "subsiste après masquage (residual)"},
		} {
			code, stdout, stderr := runCommand(t, files, "", "redact", c.file)
			if code != report.ExitError || stdout != "" || !strings.Contains(stderr, c.want) || leaks(stderr, token) {
				t.Fatalf("%s : code %d, %q, %q", name, code, stdout, stderr)
			}
		}
	})
	t.Run("--pack et --language", func(t *testing.T) {
		code, stdout, _ := runCommand(t, files, "demo_abcdefgh "+token, "redact", "--pack", "pack-propre")
		if code != report.ExitFindings || stdout != "<REDACTED_demo_rule> "+token {
			t.Fatalf("code %d, %q", code, stdout)
		}
		code, stdout, _ = runCommand(t, files, "API_SECRET="+password+"#;tail\n", "redact", "--language", "dotenv")
		if code != report.ExitFindings || strings.Contains(stdout, password) {
			t.Fatalf("code %d, %q", code, stdout)
		}
	})
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"option inconnue", []string{"redact", "--fingerprint-key", "cle"}, "Usage"},
		{"deux fichiers", []string{"redact", "a", "b"}, "Usage"},
		{"fichier introuvable", []string{"redact", "absent.txt"}, "fichier à masquer : fichier introuvable"},
		{"fichier interdit", []string{"redact", "interdit"}, "accès refusé"},
		{"fichier illisible", []string{"redact", "illisible"}, "lecture impossible"},
		{"Pack hors schéma", []string{"redact", "--pack", "pack-vide", "propre.txt"}, "pack : document refusé"},
	} {
		t.Run("refus, code 2, rien sur la sortie standard : "+c.name, func(t *testing.T) {
			code, stdout, stderr := runCommand(t, files, "", c.args...)
			if code != report.ExitError || stdout != "" || !strings.Contains(stderr, c.want) || strings.Contains(stderr, "absent.txt") {
				t.Fatalf("code %d, stdout %q, stderr %q", code, stdout, stderr)
			}
		})
	}
}
