package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/custom"
	"github.com/xsom-consulting/secret-guard/internal/report"
)

// customPackJSON est un Pack de règles du client valide : un motif (bloquer) et des termes confidentiels.
func customPackJSON(t *testing.T) []byte {
	t.Helper()
	salt := "ZGVmZ2hpamtsbW5vcHFycw=="
	saltBytes, err := custom.DecodeSalt(salt)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := custom.DigestTerm(saltBytes, "Projet Faucon")
	return []byte(`{"schemaVersion":1,"kind":"xsom.secret-guard.rules-pack","packId":"essai","tenantId":"client-essai",` +
		`"version":1,"issuedAt":"2026-10-01T00:00:00Z","expiresAt":"2027-10-01T00:00:00Z","issuer":"essai",` +
		`"detectors":[{"id":"client-id","label":"Identifiant client","category":"customer_data","action":"block",` +
		`"match":{"type":"pattern","pattern":"CLI-[0-9]{8}"}},{"id":"codes","label":"Noms de code","category":"project",` +
		`"action":"warn","match":{"type":"terms","salt":"` + salt + `","digests":["` + digest + `"],"maxWords":2}}],` +
		`"tests":{"positives":[{"detector":"client-id","text":"client CLI-12345678"}],"negatives":["rien"]}}`)
}

func TestCustomPackOption(t *testing.T) {
	files := memoryFiles{
		"pack.json":     customPackJSON(t),
		"refuse.json":   []byte(`{"schemaVersion":2}`),
		"invalide.json": []byte(strings.Replace(string(customPackJSON(t)), `CLI-[0-9]{8}`, `CLI-\\d+`, 1)),
		"texte.txt":     []byte("Le client CLI-00421337 suit le projet faucon."),
		"beaucoup.txt":  []byte(strings.Repeat("CLI-00421337 ", 2100)),
		"cle":           []byte(strings.Repeat("0123456789abcdef", 4)),
	}
	t.Run("détections du Pack ajoutées aux constats, sans la valeur", func(t *testing.T) {
		code, stdout, stderr := runCommand(t, files, "", "scan", "--custom-pack", "pack.json", "texte.txt")
		document := decodeDocument(t, stdout)
		if code != report.ExitFindings || !document.Complete || len(document.Findings) != 2 || stderr != "" {
			t.Fatalf("code %d, %+v, %q", code, document, stderr)
		}
		first, second := document.Findings[0], document.Findings[1]
		if first.RuleID != "xsom_client-id" || first.SecretType != "custom_rule" || first.Score != 90 ||
			first.Level != "CRITICAL" || first.ByteStart != 10 || first.ByteEnd != 22 {
			t.Fatalf("%+v", first)
		}
		if second.RuleID != "xsom_codes" || second.Score != 40 || second.Level != "MEDIUM" {
			t.Fatalf("%+v", second)
		}
		if strings.Contains(stdout, "00421337") || strings.Contains(stdout, "faucon") {
			t.Fatal("la sortie contient une valeur détectée")
		}
	})
	t.Run("trop de détections : code 2, custom_too_many, aucun constat", func(t *testing.T) {
		code, stdout, _ := runCommand(t, files, "", "scan", "--custom-pack", "pack.json", "beaucoup.txt")
		document := decodeDocument(t, stdout)
		if code != report.ExitError || document.Complete || document.Failure != "custom_too_many" || len(document.Findings) != 0 {
			t.Fatalf("code %d, %+v", code, document)
		}
	})
	t.Run("Pack refusé : code 2, code du refus sans le contenu du fichier", func(t *testing.T) {
		for name, want := range map[string]string{"refuse.json": "(schema)", "invalide.json": "(invalid_pattern)", "absent.json": "fichier introuvable"} {
			code, stdout, stderr := runCommand(t, files, "", "scan", "--custom-pack", name, "texte.txt")
			if code != report.ExitError || stdout != "" || !strings.Contains(stderr, want) || strings.Contains(stderr, "CLI-") {
				t.Fatalf("%s : code %d, %q, %q", name, code, stdout, stderr)
			}
		}
	})
	t.Run("--custom-pack et --fingerprint-key ne se combinent pas", func(t *testing.T) {
		code, _, stderr := runCommand(t, files, "", "scan", "--custom-pack", "pack.json", "--fingerprint-key", "cle", "texte.txt")
		if code != report.ExitError || !strings.Contains(stderr, "ne se combinent pas") {
			t.Fatalf("code %d, %q", code, stderr)
		}
	})
}

func TestTermsDigestCommand(t *testing.T) {
	salt := "ZGVmZ2hpamtsbW5vcHFycw=="
	saltBytes, _ := custom.DecodeSalt(salt)
	confidential := "Projet Faucon\r\n\n  nébuleuse  \nPROJET-faucon\n"
	files := memoryFiles{
		"termes.txt":   []byte(confidential),
		"long.txt":     []byte("un deux trois quatre cinq\n"),
		"vide.txt":     []byte("\n \n"),
		"sans-mot.txt": []byte("alpha\n-- ! --\n"),
		"trop.txt": []byte(func() string {
			var b strings.Builder
			for i := range 5001 {
				b.WriteString("terme" + strconv.Itoa(i) + "\n")
			}
			return b.String()
		}()),
		"grand.txt": []byte(strings.Repeat("a", 1<<20+1)),
	}
	t.Run("condensats des termes normalisés, sans doublon, maxWords ; aucun terme en sortie", func(t *testing.T) {
		for _, args := range [][]string{{"terms", "digest", "--salt", salt, "termes.txt"}, {"terms", "digest", "--salt", salt}} {
			code, stdout, stderr := runCommand(t, files, confidential, args...)
			var match termsMatch
			if err := json.Unmarshal([]byte(stdout), &match); err != nil || code != report.ExitClean || stderr != "" {
				t.Fatalf("%v : code %d, %q, %q", args, code, stdout, stderr)
			}
			faucon, _ := custom.DigestTerm(saltBytes, "projet faucon")
			nebuleuse, _ := custom.DigestTerm(saltBytes, "Nébuleuse")
			if match.Type != "terms" || match.Salt != salt || match.MaxWords != 2 ||
				strings.Join(match.Digests, ",") != faucon+","+nebuleuse {
				t.Fatalf("%v : %+v", args, match)
			}
			if strings.Contains(strings.ToLower(stdout), "faucon") || strings.Contains(stdout, "buleuse") {
				t.Fatal("la sortie contient un terme")
			}
		}
	})
	t.Run("refus : sel, terme sans mot ou de plus de 4 mots, aucun terme, plus de 5 000, plus de 1 Mio", func(t *testing.T) {
		for _, c := range []struct {
			args []string
			want string
		}{
			{[]string{"terms", "digest", "--salt", "court==", "termes.txt"}, "sel refusé"},
			{[]string{"terms", "digest", "--salt", salt, "long.txt"}, "ligne 1 : terme sans mot ou de plus de 4 mots"},
			{[]string{"terms", "digest", "--salt", salt, "sans-mot.txt"}, "ligne 2 : terme sans mot"},
			{[]string{"terms", "digest", "--salt", salt, "vide.txt"}, "aucun terme"},
			{[]string{"terms", "digest", "--salt", salt, "trop.txt"}, "plus de 5 000 termes"},
			{[]string{"terms", "digest", "--salt", salt, "grand.txt"}, "plus de 1 Mio"},
			{[]string{"terms", "digest", "--salt", salt, "absent.txt"}, "fichier introuvable"},
		} {
			code, stdout, stderr := runCommand(t, files, "", c.args...)
			if code != report.ExitError || stdout != "" || !strings.Contains(stderr, c.want) ||
				strings.Contains(stderr, "quatre") || strings.Contains(stderr, "alpha") {
				t.Fatalf("%v : code %d, %q, %q", c.args, code, stdout, stderr)
			}
		}
	})
	t.Run("usage : sous-commande ou sel absents", func(t *testing.T) {
		for _, args := range [][]string{{"terms"}, {"terms", "hash"}, {"terms", "digest"}, {"terms", "digest", "--salt", salt, "a", "b"}} {
			if code, _, stderr := runCommand(t, files, "", args...); code != report.ExitError || !strings.Contains(stderr, "Usage") {
				t.Fatalf("%v : code %d", args, code)
			}
		}
	})
}
