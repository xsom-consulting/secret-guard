package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/internal/report"
)

// memoryFiles est un système de fichiers en mémoire, en lecture seule : la commande ne peut rien y écrire.
type memoryFiles map[string][]byte

func (m memoryFiles) Open(name string) (io.ReadCloser, error) {
	switch name {
	case "interdit":
		return nil, fs.ErrPermission
	case "illisible":
		return io.NopCloser(failingReader{}), nil
	}
	data, ok := m[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("panne") }

// syntheticToken est une valeur synthétique de la règle github_token, construite à l'exécution.
func syntheticToken() string { return "gh" + "p_" + strings.Repeat("aB3d", 9) }

func runCommand(t *testing.T, files memoryFiles, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, strings.NewReader(stdin), &stdout, &stderr, files)
	return code, stdout.String(), stderr.String()
}

func decodeDocument(t *testing.T, text string) report.Document {
	t.Helper()
	if !strings.HasSuffix(text, "\n") || strings.Count(text, "\n") != 1 {
		t.Fatalf("sortie sur plusieurs lignes ou sans fin de ligne : %q", text)
	}
	var document report.Document
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("sortie illisible : %v", err)
	}
	return document
}

// leaks dit si text contient une fenêtre de 8 octets de value.
func leaks(text, value string) bool {
	for i := 0; i+8 <= len(value); i++ {
		if strings.Contains(text, value[i:i+8]) {
			return true
		}
	}
	return false
}

func TestScanCommand(t *testing.T) {
	token := syntheticToken()
	key := strings.Repeat("0123456789abcdef", 4)
	files := memoryFiles{
		"propre.txt":   []byte("rien à signaler\n"),
		"secret.env":   []byte("TOKEN=" + token + "\n"),
		"grand.bin":    bytes.Repeat([]byte("a"), 1<<20+1),
		"limite.bin":   bytes.Repeat([]byte("a"), 1<<20),
		"cle":          []byte(key + "\n"),
		"cle-crlf":     []byte(key + "\r\n"),
		"cle-courte":   []byte("0123"),
		"cle-nulle":    []byte(strings.Repeat("00", 32)),
		"cle-longue":   bytes.Repeat([]byte("0"), 200),
		"pack-vide":    []byte(`{}`),
		"pack-inconnu": []byte(`{"schemaVersion":1,"minAgentVersion":"0.1.0","packVersion":1,"issuedAt":"2026-10-07T00:00:00Z","rules":[{"ruleId":"r","family":"fixed_pattern","secretType":"api_key","score":80,"validator":"luhn","pattern":"x","minLength":0,"maxLength":0}]}`),
		"pack-propre":  []byte(`{"schemaVersion":1,"minAgentVersion":"0.1.0","packVersion":2,"issuedAt":"2026-10-07T00:00:00Z","rules":[{"ruleId":"demo_rule","family":"fixed_pattern","secretType":"api_key","score":80,"validator":"","pattern":"\\bdemo_[a-z]{8}\\b","minLength":0,"maxLength":0}]}`),
	}
	t.Run("analyse propre : code 0, document complet sans constat", func(t *testing.T) {
		code, stdout, stderr := runCommand(t, files, "", "scan", "propre.txt")
		document := decodeDocument(t, stdout)
		if code != report.ExitClean || !document.Complete || document.Failure != "none" || len(document.Findings) != 0 || stderr != "" {
			t.Fatalf("code %d, %+v, %q", code, document, stderr)
		}
		if !strings.Contains(stdout, `"findings":[]`) {
			t.Fatalf("tableau des constats absent : %s", stdout)
		}
	})
	t.Run("secret synthétique : code 1, constat sans la valeur", func(t *testing.T) {
		for _, args := range [][]string{{"scan", "secret.env"}, {"scan"}, {"scan", "-"}} {
			code, stdout, stderr := runCommand(t, files, "TOKEN="+token+"\n", args...)
			document := decodeDocument(t, stdout)
			if code != report.ExitFindings || len(document.Findings) != 1 {
				t.Fatalf("%v : code %d, %+v", args, code, document)
			}
			f := document.Findings[0]
			if f.RuleID != "github_token" || f.SecretType != "provider_token" || f.Encoding != "plain" || f.Level != "CRITICAL" ||
				f.ByteStart != 6 || f.ByteEnd != 6+len(token) || f.LocalFingerprint != "" {
				t.Fatalf("%v : constat %+v", args, f)
			}
			if leaks(stdout+stderr, token) {
				t.Fatalf("%v : la sortie contient la valeur", args)
			}
		}
	})
	t.Run("entrée de plus de 1 Mio : code 2, analyse incomplète scan_limit, aucun constat", func(t *testing.T) {
		code, stdout, _ := runCommand(t, files, "", "scan", "grand.bin")
		document := decodeDocument(t, stdout)
		if code != report.ExitError || document.Complete || document.Failure != "scan_limit" || len(document.Findings) != 0 {
			t.Fatalf("code %d, %+v", code, document)
		}
		code, stdout, _ = runCommand(t, files, "", "scan", "limite.bin")
		if document := decodeDocument(t, stdout); code != report.ExitClean || !document.Complete {
			t.Fatalf("1 Mio exactement : code %d, %+v", code, document)
		}
	})
	t.Run("clé d'Empreinte locale : Empreinte de 32 caractères hexadécimaux, stable, sans la valeur", func(t *testing.T) {
		code, first, _ := runCommand(t, files, "", "scan", "--fingerprint-key", "cle", "secret.env")
		_, second, _ := runCommand(t, files, "", "scan", "--fingerprint-key", "cle-crlf", "secret.env")
		document := decodeDocument(t, first)
		if code != report.ExitFindings || len(document.Findings) != 1 ||
			!regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(document.Findings[0].LocalFingerprint) || first != second {
			t.Fatalf("code %d, %s / %s", code, first, second)
		}
		if leaks(first, token) || strings.Contains(first, key[:16]) {
			t.Fatal("la sortie contient la valeur ou la clé")
		}
	})
	t.Run("Pack donné par --pack : ses règles seules", func(t *testing.T) {
		code, stdout, _ := runCommand(t, files, "demo_abcdefgh "+token, "scan", "--pack", "pack-propre")
		document := decodeDocument(t, stdout)
		if code != report.ExitFindings || len(document.Findings) != 1 || document.Findings[0].RuleID != "demo_rule" {
			t.Fatalf("code %d, %+v", code, document)
		}
	})
	t.Run("--language change la lecture des affectations", func(t *testing.T) {
		code, stdout, _ := runCommand(t, files, "password = hunter2secret\n", "scan", "--language", "dotenv")
		if code == report.ExitError || decodeDocument(t, stdout).Failure != "none" {
			t.Fatalf("code %d, %s", code, stdout)
		}
	})
	refusals := []struct {
		name string
		args []string
		want string
	}{
		{"sans commande", nil, "Usage"},
		{"commande inconnue", []string{"analyse"}, "Usage"},
		{"option inconnue", []string{"scan", "--inconnue"}, "Usage"},
		{"deux fichiers", []string{"scan", "a", "b"}, "Usage"},
		{"version avec argument", []string{"version", "x"}, "Usage"},
		{"fichier introuvable", []string{"scan", "absent.txt"}, "fichier introuvable"},
		{"fichier interdit", []string{"scan", "interdit"}, "accès refusé"},
		{"fichier illisible", []string{"scan", "illisible"}, "lecture impossible"},
		{"Pack introuvable", []string{"scan", "--pack", "absent.json", "propre.txt"}, "Pack : fichier introuvable"},
		{"Pack hors schéma", []string{"scan", "--pack", "pack-vide", "propre.txt"}, "pack : document refusé"},
		{"Pack inexploitable par le moteur", []string{"scan", "--pack", "pack-inconnu", "propre.txt"}, "unknown_validator"},
		{"clé trop courte", []string{"scan", "--fingerprint-key", "cle-courte", "propre.txt"}, "64 caractères"},
		{"clé nulle", []string{"scan", "--fingerprint-key", "cle-nulle", "propre.txt"}, "clé d'Empreinte locale refusée"},
		{"clé trop longue", []string{"scan", "--fingerprint-key", "cle-longue", "propre.txt"}, "fichier trop grand"},
		{"clé introuvable", []string{"scan", "--fingerprint-key", "absente", "propre.txt"}, "fichier introuvable"},
		{"clé et langage", []string{"scan", "--fingerprint-key", "cle", "--language", "dotenv", "propre.txt"}, "ne se combinent pas"},
	}
	for _, c := range refusals {
		t.Run("refus, code 2, rien sur la sortie standard : "+c.name, func(t *testing.T) {
			code, stdout, stderr := runCommand(t, files, "", c.args...)
			if code != report.ExitError || stdout != "" || !strings.Contains(stderr, c.want) {
				t.Fatalf("code %d, stdout %q, stderr %q", code, stdout, stderr)
			}
			for _, name := range []string{"absent.txt", "absent.json", "absente", "interdit"} {
				if strings.Contains(stderr, name) {
					t.Fatalf("le message cite le chemin : %q", stderr)
				}
			}
		})
	}
	t.Run("aide et version", func(t *testing.T) {
		if code, stdout, _ := runCommand(t, files, "", "--help"); code != 0 || !strings.Contains(stdout, "Codes de sortie") {
			t.Fatalf("aide : %d", code)
		}
		if code, stdout, _ := runCommand(t, files, "", "version"); code != 0 || !strings.Contains(stdout, "Pack initial : version 1, 35 règles") {
			t.Fatalf("version : %d %q", code, stdout)
		}
	})
}
