package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/internal/report"
)

// expurgateBuffer expurge input par l'état du module et rend le document et le texte qui le suit ; ok faux si le
// module refuse.
func expurgateBuffer(t *testing.T, m *module, input []byte, request string) (report.Expurgation, []byte, bool) {
	t.Helper()
	ptr := put(t, m, input)
	defer m.free(ptr)
	var requestPtr uintptr
	if request != "" {
		requestPtr = put(t, m, []byte(request))
		defer m.free(requestPtr)
	}
	out, length, ok := m.expurgate(ptr, uint32(len(input)), 0, 0, requestPtr, uint32(len(request)))
	if !ok {
		return report.Expurgation{}, nil, false
	}
	defer m.free(out)
	data, _ := m.slice(out, length)
	line, text, found := bytes.Cut(data, []byte("\n"))
	if !found {
		t.Fatal("document sans fin de ligne")
	}
	var document report.Expurgation
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	return document, append([]byte(nil), text...), true
}

func keyedModule(t *testing.T) *module {
	t.Helper()
	m := newModule()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	ptr := put(t, m, key)
	defer m.free(ptr)
	if m.setKey(ptr, 32) != statusOK {
		t.Fatal("clé refusée")
	}
	return m
}

func TestModuleExpurgate(t *testing.T) {
	token := "gh" + "p_" + strings.Repeat("aB3d", 9)
	t.Run("sans clé d'Empreinte locale : refus", func(t *testing.T) {
		if _, _, ok := expurgateBuffer(t, newModule(), []byte("TOKEN="+token), ""); ok {
			t.Fatal("expurgation sans clé admise")
		}
	})
	m := keyedModule(t)
	t.Run("secret expurgé : Substitut typé, Substitution sans la valeur, texte après la fin de ligne", func(t *testing.T) {
		document, text, ok := expurgateBuffer(t, m, []byte("TOKEN="+token+"\n"), "")
		if !ok || document.Failure != "none" || len(document.Substitutions) != 1 || len(document.Final.Findings) != 0 {
			t.Fatalf("%+v %q", document, text)
		}
		s := document.Substitutions[0]
		want := "ghp_" + strings.Repeat("X", len(token)-5) + "1"
		if s.RuleID != "github_token" || s.Ordinal != 1 || s.Replacement != want || s.ByteStart != 6 ||
			s.ByteEnd != 6+len(token) || s.UTF16Start != 6 || len(s.LocalFingerprint) != 32 {
			t.Fatalf("%+v", s)
		}
		if string(text) != "TOKEN="+want+"\n" {
			t.Fatalf("%q", text)
		}
		line, _ := json.Marshal(document)
		if bytes.Contains(line, []byte(token[4:12])) {
			t.Fatal("valeur dans le document")
		}
	})
	t.Run("Empreinte locale connue : même numéro ; nouvelle : au-dessus du plus grand connu et de minOrdinal", func(t *testing.T) {
		first, _, _ := expurgateBuffer(t, m, []byte("TOKEN="+token), "")
		fingerprint := first.Substitutions[0].LocalFingerprint
		known, text, ok := expurgateBuffer(t, m, []byte("TOKEN="+token), `{"known":[{"localFingerprint":"`+fingerprint+`","ordinal":7}]}`)
		if !ok || known.Substitutions[0].Ordinal != 7 || !strings.HasSuffix(string(text), "7") {
			t.Fatalf("%+v %q", known, text)
		}
		other, _, ok := expurgateBuffer(t, m, []byte("TOKEN="+token), `{"known":[{"localFingerprint":"`+strings.Repeat("a", 32)+`","ordinal":7}],"minOrdinal":12}`)
		if !ok || other.Substitutions[0].Ordinal != 12 {
			t.Fatalf("%+v", other)
		}
		full, text, ok := expurgateBuffer(t, m, []byte("TOKEN="+token), `{"known":[{"localFingerprint":"`+strings.Repeat("b", 32)+`","ordinal":999}]}`)
		if !ok || full.Failure != "ordinal_refused" || len(text) != 0 || len(full.Substitutions) != 0 {
			t.Fatalf("%+v %q", full, text)
		}
	})
	t.Run("demande hors forme : refus", func(t *testing.T) {
		for _, request := range []string{
			`[]`, `{"known":[{"localFingerprint":"AB","ordinal":1}]}`, `{"other":1}`, `{"minOrdinal":1000}`,
			`{} {}`, `{"known":[{"localFingerprint":"` + strings.Repeat("a", 32) + `","ordinal":0}]}`,
		} {
			if _, _, ok := expurgateBuffer(t, m, []byte("TOKEN="+token), request); ok {
				t.Fatalf("demande admise : %s", request)
			}
		}
	})
	t.Run("rien à expurger : texte recopié ; analyse incomplète : aucun texte", func(t *testing.T) {
		document, text, ok := expurgateBuffer(t, m, []byte("rien\n"), "")
		if !ok || document.Failure != "none" || string(text) != "rien\n" || len(document.Substitutions) != 0 {
			t.Fatalf("%+v %q", document, text)
		}
		big := bytes.Repeat([]byte("a"), 1<<20+1)
		document, text, ok = expurgateBuffer(t, m, big, "")
		if !ok || document.Failure != "incomplete" || len(text) != 0 {
			t.Fatalf("%+v", document)
		}
	})
	t.Run("entrée ou demande hors d'un tampon prêté : refus", func(t *testing.T) {
		if _, _, ok := m.expurgate(12345, 4, 0, 0, 0, 0); ok {
			t.Fatal("entrée inconnue admise")
		}
		ptr := put(t, m, []byte("x"))
		defer m.free(ptr)
		if _, _, ok := m.expurgate(ptr, 1, 0, 0, 12345, 4); ok {
			t.Fatal("demande inconnue admise")
		}
		if _, _, ok := m.expurgate(ptr, 1, 12345, 4, 0, 0); ok {
			t.Fatal("identifiant de langage inconnu admis")
		}
		language := put(t, m, []byte("dotenv"))
		defer m.free(language)
		if _, _, ok := m.expurgate(ptr, 1, language, 6, 0, 0); !ok {
			t.Fatal("identifiant de langage refusé")
		}
	})
}
