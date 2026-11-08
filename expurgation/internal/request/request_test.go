// SPDX-License-Identifier: PolyForm-Small-Business-1.0.0

package request

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/detect"
	"github.com/xsom-consulting/secret-guard/pack"
)

func rules(t *testing.T) *detect.Rules {
	t.Helper()
	p, err := pack.Initial()
	if err != nil {
		t.Fatal(err)
	}
	r, err := detect.LoadRules(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func key(t *testing.T) *detect.FingerprintKey {
	t.Helper()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	k, err := detect.NewFingerprintKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &k
}

func TestParseRequest(t *testing.T) {
	fp := strings.Repeat("0a", 16)
	for _, accepted := range []string{"", `{}`, `{"known":[]}`, `{"known":null}`, `{"minOrdinal":0}`, `{"minOrdinal":999}`,
		`{"substituteLanguage":"fr"}`, `{"substituteLanguage":"en"}`, `{"substituteLanguage":""}`,
		`{"known":[{"localFingerprint":"` + fp + `","ordinal":1},{"localFingerprint":"` + strings.Repeat("b", 32) + `","ordinal":999}]}`} {
		if _, ok := ParseRequest([]byte(accepted)); !ok {
			t.Errorf("refusée : %q", accepted)
		}
	}
	for _, refused := range []string{`null`, `[]`, `1`, `{`, `{"x":1}`, `{} 1`, `{"minOrdinal":-1}`, `{"minOrdinal":1000}`,
		`{"substituteLanguage":"de"}`, `{"substituteLanguage":"FR"}`, `{"substituteLanguage":1}`,
		`{"known":[{"localFingerprint":"` + strings.ToUpper(fp) + `","ordinal":1}]}`,
		`{"known":[{"localFingerprint":"` + fp[:31] + `","ordinal":1}]}`,
		`{"known":[{"localFingerprint":"` + fp + `","ordinal":1000}]}`,
		`{"known":[{"localFingerprint":"` + fp + `","ordinal":1},{"localFingerprint":"` + fp + `","ordinal":2}]}`,
		`{"known":[{"localFingerprint":"` + fp + `","ordinal":1},{"localFingerprint":"` + strings.Repeat("c", 32) + `","ordinal":1}]}`,
		`{"known":[{"localFingerprint":"` + fp + `","ordinal":1,"value":"x"}]}`} {
		if _, ok := ParseRequest([]byte(refused)); ok {
			t.Errorf("admise : %q", refused)
		}
	}
	if _, ok := ParseRequest(bytes.Repeat([]byte(" "), MaxRequestBytes+1)); ok {
		t.Error("demande trop grande admise")
	}
}

func TestRun(t *testing.T) {
	token := "gh" + "p_" + strings.Repeat("aB3d", 9)
	content := []byte("A=" + token + "\nB=" + token + "\n")
	document, text := Run(content, rules(t), key(t), detect.Options{}, Request{MinOrdinal: 5})
	if !bytes.HasPrefix(document, []byte(`{"failure":"none"`)) || !bytes.HasSuffix(document, []byte("\n")) {
		t.Fatalf("%s", document)
	}
	if strings.Count(string(text), "n°5 : jeton GitHub, pas la vraie valeur]\n") != 2 || bytes.Contains(text, []byte(token)) || bytes.Contains(document, []byte(token[4:12])) {
		t.Fatalf("%q", text)
	}
	// Substituts en anglais à la demande.
	_, text = Run(content, rules(t), key(t), detect.Options{}, Request{MinOrdinal: 5, SubstituteLanguage: detect.SubstituteEnglish})
	if strings.Count(string(text), "#5: GitHub token, not the real value]\n") != 2 {
		t.Fatalf("%q", text)
	}
	// Langue inconnue (demande non lue par ParseRequest) : échec, aucun texte.
	document, text = Run(content, rules(t), key(t), detect.Options{}, Request{SubstituteLanguage: "de"})
	if text != nil || !bytes.HasPrefix(document, []byte(`{"failure":"incomplete"`)) {
		t.Fatalf("%s %q", document, text)
	}
	// Numérotation refusée par défense en profondeur (demande non lue par ParseRequest).
	bad := Request{Known: []Known{{LocalFingerprint: "x", Ordinal: 1}}}
	document, text = Run(content, rules(t), key(t), detect.Options{}, bad)
	if text != nil || !bytes.HasPrefix(document, []byte(`{"failure":"ordinal_refused"`)) {
		t.Fatalf("%s %q", document, text)
	}
	// Sans clé : aucun numéro (constat sans Empreinte locale), échec.
	document, text = Run(content, rules(t), nil, detect.Options{}, Request{})
	if text != nil || bytes.HasPrefix(document, []byte(`{"failure":"none"`)) {
		t.Fatalf("%s", document)
	}
}
