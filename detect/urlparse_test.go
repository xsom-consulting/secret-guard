package detect

import (
	"encoding/json"
	"testing"
)

// urlCases : résultats du constructeur URL et de decodeURIComponent de Node 26 (relevés une fois par un script hors du
// dépôt) : [entrée, analyse réussie, mot de passe ou texte décodé].
const urlCases = `{"out": [["https://u:p@h/x", true, "p"], ["http:///u:p@h", true, "p"], ["https://u:p@", false, ""], ["postgres://u:p@", false, ""], ["postgres://u:p@/db", false, ""], ["redis://:pw@h:6379", true, "pw"], ["https://u:p@h:65535", true, "p"], ["https://u:p@h:65536", false, ""], ["https://u:p@h:12a", false, ""], ["https://a@b:c@h", true, "c"], ["https://u:p:q@h", true, "p%3Aq"], ["https://u:p%zz@h", true, "p%zz"], ["https://u:p{x}@h", true, "p%7Bx%7D"], ["https://u:p@[::1]", true, "p"], ["https://u:p@[::1", false, ""], ["https://u:p@[1:2:3:4:5:6:7:8:9]", false, ""], ["https://u:p@[::ffff:1.2.3.4]", true, "p"], ["https://u:p@[1::2::3]", false, ""], ["https://u:p@foo.123", false, ""], ["https://u:p@1.2.3.4.5", false, ""], ["https://u:p@256.1.1.1", false, ""], ["https://u:p@0x7f.1", true, "p"], ["https://u:p@1.2.3", true, "p"], ["https://u:p@4294967296", false, ""], ["https://u:p@0x", true, "p"], ["https://u:p@a..b", true, "p"], ["https://u:p@exa%41mple.com", true, "p"], ["https://u:p@ex%zzample.com", false, ""], ["https://u:p@h|x", false, ""], ["postgres://u:p@h|x", false, ""], ["postgres://u:p@h^x", false, ""], ["https://u:p@h\\x", true, "p"], ["postgres://u:p@h\\x", false, ""], ["mongodb+srv://u:p@h", true, "p"], ["https://u:p@h#frag", true, "p"], ["https://u:p@h?q", true, "p"], ["postgres://u@h", true, ""], ["ftp://\\:p@h", true, "p"], ["https://u:p@HOST.Example", true, "p"], ["https://u:p@%80.test", false, ""]], "decs": [["abc", true, "abc"], ["%41", true, "A"], ["%zz", false, ""], ["%E9", false, ""], ["%C3%A9", true, "é"], ["%ED%A0%80", false, ""], ["%F0%9F%98%80", true, "😀"], ["%", false, ""], ["%4", false, ""], ["%EF%BF%BD", true, "�"], ["%C0%AF", false, ""]]}`

func TestURLPassword(t *testing.T) {
	var cases struct {
		Out  [][3]any `json:"out"`
		Decs [][3]any `json:"decs"`
	}
	if err := json.Unmarshal([]byte(urlCases), &cases); err != nil {
		t.Fatal(err)
	}
	t.Run("l'analyse d'URL rend l'échec et le mot de passe du constructeur URL de JavaScript", func(t *testing.T) {
		for _, c := range cases.Out {
			input, ok, password := c[0].(string), c[1].(bool), c[2].(string)
			got, gotOK := urlPassword([]byte(input))
			if !gotOK {
				got = ""
			}
			// Sans « @ », le moteur rend faux sans analyser : aucun mot de passe, comme un échec.
			if (gotOK && got != password) || (!gotOK && ok && password != "") || (gotOK && !ok) {
				t.Errorf("%q : (%q, %v), JavaScript (%q, %v)", input, got, gotOK, password, ok)
			}
		}
	})
	t.Run("decodeURIComponent échoue et décode comme JavaScript", func(t *testing.T) {
		for _, c := range cases.Decs {
			input, ok, decoded := c[0].(string), c[1].(bool), c[2].(string)
			got, gotOK := decodeURIComponent(input)
			if gotOK != ok || (ok && got != decoded) {
				t.Errorf("%q : (%q, %v), JavaScript (%q, %v)", input, got, gotOK, decoded, ok)
			}
		}
	})
}
