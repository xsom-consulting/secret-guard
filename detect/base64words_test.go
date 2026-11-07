package detect

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestIsNameCandidate(t *testing.T) {
	for value, want := range map[string]bool{
		"AdminLogEntryViewActorKind":             true,
		"SiInventoryElementsElemCertainty":       true,
		"EvidenceDossierV1ChainsCheckpointsElem": true,
		"refuse_append_only_change":              true,
		"HTTPSClientSessionTimeout":              true,
		"server/packages/domain/src":             true,
		"policy_keys_one_per_group":              true,
		strings.Repeat("0123456789abcdef", 4):    true, // empreinte SHA-256
		strings.Repeat("0123456789ABCDEF", 2):    true,
		"0123456789abcdefABCDEF0123":             false, // hexadécimal de casse mêlée
		"aGVsbG8gd29ybGQgaGVsbG8gd29ybGQ":        false, // base64 d'un texte
		"HTTPSAPIClientSessionID":                false, // deux sigles
		"AbcDefGhi+JklMnoPqrStu":                 false, // « + »
		"xK9mQ2vL7nR4wP8sT3yB":                   false,
		"ab/cd/ef/gh/ij/kl/mn/op":                false, // aucun mot de 3 lettres
	} {
		if got := isNameCandidate(value); got != want {
			t.Errorf("isNameCandidate(%q) = %v, attendu %v", value, got, want)
		}
	}
}

// TestNameCandidateRarelyMatchesBase64 : l'encodage base64 d'octets aléatoires, ou d'un texte, n'a presque jamais la
// forme d'un nom ; un tel candidat garde son décodage.
func TestNameCandidateRarelyMatchesBase64(t *testing.T) {
	const samples = 100_000
	for _, c := range []struct{ bytes, limit int }{{15, 2 * samples / 1000}, {24, 2 * samples / 20_000}, {48, 0}} {
		matched := 0
		raw := make([]byte, c.bytes)
		for i := 0; i < samples; i++ {
			if _, err := rand.Read(raw); err != nil {
				t.Fatal(err)
			}
			for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
				if isNameCandidate(encoding.EncodeToString(raw)) {
					matched++
				}
			}
		}
		t.Logf("%d caractères : %d candidats aléatoires sur %d ont la forme d'un nom", c.bytes*4/3, matched, 2*samples)
		if matched > c.limit {
			t.Fatalf("%d caractères : %d candidats aléatoires sur %d ont la forme d'un nom", c.bytes*4/3, matched, 2*samples)
		}
	}
	text := "Printable candidate prefix with varied ASCII. "
	for i := 0; i < len(text); i++ {
		if isNameCandidate(base64.StdEncoding.EncodeToString([]byte(text[i:] + text[:i]))) {
			t.Fatalf("base64 d'un texte pris pour un nom (rotation %d)", i)
		}
	}
}

// TestNamesKeepAnalysisComplete : un fichier de types générés (des centaines d'identifiants distincts de plus de 20
// caractères) donne une analyse complète ; auparavant chacun était décodé et le budget s'épuisait (analyse
// incomplète, donc blocage).
func TestNamesKeepAnalysisComplete(t *testing.T) {
	rules := loadInitialRules(t)
	var b strings.Builder
	words := []string{"Inventory", "Elements", "Elem", "Evidence", "Certainty", "Checked", "By", "Fleet", "Kind", "Zone"}
	for i := 0; i < 400; i++ {
		name := "Si" + words[i%len(words)] + words[(i/len(words))%len(words)] + words[(i/7)%len(words)] + "Elem"
		fmt.Fprintf(&b, "type %s%d struct{ Kind string `json:\"kind\"` }\nconst refuse_append_only_change_%d = \"%x\"\n", name, i%97, i, i*7919)
	}
	b.WriteString(strings.Repeat("sha256:"+strings.Repeat("0123456789abcdef", 4)+"\n", 200))
	result := Scan([]byte(b.String()), rules, Options{})
	if !result.Complete {
		t.Fatalf("analyse incomplète : %v", result.Failure)
	}
}

// TestBase64SecretStillDecoded : un secret encodé en base64 reste trouvé dans son décodage.
func TestBase64SecretStillDecoded(t *testing.T) {
	rules := loadInitialRules(t)
	secret := "ghp_" + randomToken(t, 36)
	content := "data: " + base64.StdEncoding.EncodeToString([]byte("token="+secret)) + "\n"
	result := Scan([]byte(content), rules, Options{})
	if !result.Complete {
		t.Fatalf("analyse incomplète : %v", result.Failure)
	}
	for _, f := range result.Findings {
		if f.Encoding != "plain" {
			return
		}
	}
	t.Fatal("secret encodé en base64 non trouvé")
}
