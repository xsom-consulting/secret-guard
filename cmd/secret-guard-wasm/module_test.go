package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/internal/limits"
	"github.com/xsom-consulting/secret-guard/internal/report"
)

// Tests de l'état du module sur la machine de développement (mêmes fonctions que les exportations WebAssembly, qui ne
// font que convertir les entiers) ; l'essai réel du module est wasm/secret-guard.test.mjs, sous Node.

func put(t *testing.T, m *module, data []byte) uintptr {
	t.Helper()
	ptr := m.alloc(uint32(len(data)))
	buffer, ok := m.slice(ptr, uint32(len(data)))
	if ptr == 0 || !ok {
		t.Fatal("tampon refusé")
	}
	copy(buffer, data)
	return ptr
}

func scanDocument(t *testing.T, m *module, input string, withFingerprint bool) report.Document {
	t.Helper()
	ptr := put(t, m, []byte(input))
	defer m.free(ptr)
	out, length, ok := m.scan(ptr, uint32(len(input)), 0, 0, withFingerprint)
	if !ok {
		t.Fatal("analyse refusée")
	}
	defer m.free(out)
	data, _ := m.slice(out, length)
	var document report.Document
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func TestModule(t *testing.T) {
	token := "gh" + "p_" + strings.Repeat("aB3d", 9)
	t.Run("le module initialisé a le Pack initial ; un secret synthétique donne un constat sans la valeur", func(t *testing.T) {
		if state.rules == nil {
			t.Fatal("Pack initial non chargé")
		}
		document := scanDocument(t, newModule(), "TOKEN="+token, false)
		if !document.Complete || len(document.Findings) != 1 || document.Findings[0].RuleID != "github_token" {
			t.Fatalf("%+v", document)
		}
	})
	t.Run("tampons : taille nulle ou trop grande refusée, adresse inconnue refusée, libération qui efface", func(t *testing.T) {
		m := newModule()
		if m.alloc(0) != 0 || m.alloc(limits.MaxPackBytes+1) != 0 {
			t.Fatal("taille admise")
		}
		ptr := put(t, m, []byte("secret"))
		buffer, _ := m.slice(ptr, 6)
		if _, ok := m.slice(ptr, 7); ok {
			t.Fatal("longueur au-delà du tampon admise")
		}
		if _, ok := m.slice(ptr+1, 1); ok {
			t.Fatal("adresse inconnue admise")
		}
		m.free(ptr)
		m.free(ptr) // sans effet
		if string(buffer) != "\x00\x00\x00\x00\x00\x00" {
			t.Fatal("tampon libéré non effacé")
		}
		if _, _, ok := m.scan(ptr, 6, 0, 0, false); ok {
			t.Fatal("analyse d'un tampon libéré")
		}
	})
	t.Run("identifiant de langage lu dans un tampon prêté", func(t *testing.T) {
		m := newModule()
		input := put(t, m, []byte("password = hunter2secret\n"))
		language := put(t, m, []byte("dotenv"))
		if _, _, ok := m.scan(input, 25, language, 6, false); !ok {
			t.Fatal("analyse refusée")
		}
		if _, _, ok := m.scan(input, 25, language+1, 6, false); ok {
			t.Fatal("langage hors d'un tampon admis")
		}
	})
	t.Run("clé d'Empreinte locale : 32 octets non tous égaux, effacés dans le tampon ; analyse refusée sans clé", func(t *testing.T) {
		m := newModule()
		input := put(t, m, []byte("TOKEN="+token))
		if _, _, ok := m.scan(input, uint32(6+len(token)), 0, 0, true); ok {
			t.Fatal("analyse avec Empreinte locale sans clé")
		}
		if m.setKey(put(t, m, make([]byte, 32)), 32) != statusRefused || m.setKey(put(t, m, []byte("court")), 5) != statusRefused ||
			m.setKey(0, 32) != statusRefused {
			t.Fatal("clé refusée admise")
		}
		raw := []byte(strings.Repeat("0123456789abcdef", 2))
		keyPtr := put(t, m, raw)
		if m.setKey(keyPtr, 32) != statusOK {
			t.Fatal("clé refusée")
		}
		if buffer, _ := m.slice(keyPtr, 32); string(buffer) != string(make([]byte, 32)) {
			t.Fatal("clé non effacée du tampon")
		}
		document := scanDocument(t, m, "TOKEN="+token, true)
		if len(document.Findings) != 1 || len(document.Findings[0].LocalFingerprint) != 32 {
			t.Fatalf("%+v", document)
		}
		m.clearKey()
		m.clearKey()
		if m.key != nil {
			t.Fatal("clé gardée")
		}
	})
	t.Run("Pack : un Pack refusé laisse les règles en place, un Pack valide les remplace", func(t *testing.T) {
		m := newModule()
		before := m.rules
		bad := []byte(`{"schemaVersion":1}`)
		if m.loadPack(put(t, m, bad), uint32(len(bad))) != statusRefused || m.rules != before || m.loadPack(0, 1) != statusRefused {
			t.Fatal("Pack refusé admis")
		}
		unusable := []byte(`{"schemaVersion":1,"minAgentVersion":"0.1.0","packVersion":2,"issuedAt":"2026-10-13T00:00:00Z","rules":[{"ruleId":"r","family":"fixed_pattern","secretType":"api_key","score":80,"validator":"luhn","pattern":"x","minLength":0,"maxLength":0}]}`)
		if m.loadPack(put(t, m, unusable), uint32(len(unusable))) != statusRefused || m.rules != before {
			t.Fatal("Pack inexploitable admis")
		}
		good := []byte(`{"schemaVersion":1,"minAgentVersion":"0.1.0","packVersion":2,"issuedAt":"2026-10-13T00:00:00Z","rules":[{"ruleId":"demo_rule","family":"fixed_pattern","secretType":"api_key","score":80,"validator":"","pattern":"\\bdemo_[a-z]{8}\\b","minLength":0,"maxLength":0}]}`)
		if m.loadPack(put(t, m, good), uint32(len(good))) != statusOK || m.rules == before {
			t.Fatal("Pack valide refusé")
		}
		document := scanDocument(t, m, "demo_abcdefgh "+token, false)
		if len(document.Findings) != 1 || document.Findings[0].RuleID != "demo_rule" {
			t.Fatalf("%+v", document)
		}
	})
}
