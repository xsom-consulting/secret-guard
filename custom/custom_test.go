package custom

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"
)

const testSalt = "ZGVmZ2hpamtsbW5vcHFycw=="

// testPack est un Pack valide : un motif (bloquer), un motif à contexte (avertir), des termes confidentiels.
func testPack(t *testing.T) *Pack {
	t.Helper()
	salt, err := DecodeSalt(testSalt)
	if err != nil {
		t.Fatal(err)
	}
	faucon, words := DigestTerm(salt, "Projet Faucon")
	if words != 2 {
		t.Fatalf("%d mots", words)
	}
	p, err := Compile([]byte(`{"schemaVersion":1,"kind":"xsom.secret-guard.rules-pack","packId":"essai","tenantId":"client",` +
		`"version":7,"issuedAt":"2026-10-01T00:00:00Z","expiresAt":"2027-10-01T00:00:00Z","issuer":"émetteur",` +
		`"detectors":[{"id":"cli","label":"Identifiant","category":"customer_data","action":"block",` +
		`"match":{"type":"pattern","pattern":"CLI-[0-9]{8}"}},` +
		`{"id":"siret","label":"SIRET","category":"customer_data","action":"warn","match":{"type":"pattern",` +
		`"pattern":"[0-9]{14}"},"context":{"keywords":["siret"],"window":24}},` +
		`{"id":"codes","label":"Noms de code","category":"project","action":"block","match":{"type":"terms",` +
		`"salt":"` + testSalt + `","digests":["` + faucon + `"],"maxWords":2}}],` +
		`"tests":{"positives":[{"detector":"cli","text":"CLI-12345678"},{"detector":"siret","text":"siret 55210055400013"}],` +
		`"negatives":["rien"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPackAccessors(t *testing.T) {
	p := testPack(t)
	if p.PackID() != "essai" || p.TenantID() != "client" || p.Version() != 7 || p.IssuedAt() != "2026-10-01T00:00:00Z" ||
		p.ExpiresAt() != "2027-10-01T00:00:00Z" || p.Issuer() != "émetteur" {
		t.Fatalf("%+v", p)
	}
	detectors := p.Detectors()
	if len(detectors) != 3 || detectors[0] != (Detector{ID: "cli", Label: "Identifiant", Category: "customer_data", Action: ActionBlock}) ||
		detectors[1].Action != ActionWarn {
		t.Fatalf("%+v", detectors)
	}
	detectors[0].ID = "autre"
	if p.Detectors()[0].ID != "cli" {
		t.Fatal("Detectors rend une copie partagée")
	}
}

func TestErrors(t *testing.T) {
	_, err := Compile([]byte(`{}`))
	var refusal *PackError
	if !errors.As(err, &refusal) || refusal.Code != PackSchema || !errors.Is(err, ErrInvalidPack) ||
		err.Error() != "Pack de règles du client refusé (schema)" {
		t.Fatalf("%v", err)
	}
	err = ValidatePattern("ab", false, false)
	var patternErr *PatternError
	if !errors.As(err, &patternErr) || patternErr.Code != PatternTooShort || !errors.Is(err, ErrInvalidPattern) ||
		err.Error() != "motif refusé (too_short)" {
		t.Fatalf("%v", err)
	}
	if ValidatePattern("CLI-[0-9]{8}", false, true) != nil {
		t.Fatal("motif valide refusé")
	}
	if _, err := DecodeSalt("court"); !errors.Is(err, ErrInvalidSalt) {
		t.Fatalf("%v", err)
	}
	if len(PackErrorCodes()) != 10 || len(PatternErrorCodes()) != 23 || len(Categories()) != 5 {
		t.Fatal("listes fermées")
	}
	if _, err := Compile(bytes.Repeat([]byte(" "), MaxPackBytes+1)); !errors.Is(err, ErrInvalidPack) {
		t.Fatal("document trop grand accepté")
	}
}

func TestAnalyze(t *testing.T) {
	p := testPack(t)
	t.Run("texte tel quel puis texte visible : étendues ramenées au contenu, doublons retirés", func(t *testing.T) {
		text := "CLI-12345678 et CLI-1234\u200b5678, le projet\u00adfaucon, siret 55210055400013"
		content := []byte(text)
		matches, err := p.Analyze(content, nil, -1)
		if err != nil {
			t.Fatal(err)
		}
		at := func(part string) (int, int) {
			start := strings.Index(text, part)
			return start, start + len(part)
		}
		hiddenStart, hiddenEnd := at("CLI-1234\u200b5678")
		termStart, termEnd := at("projet\u00adfaucon")
		siretStart, siretEnd := at("55210055400013")
		// Texte tel quel (le trait d'union conditionnel sépare déjà les mots) : détecteurs dans l'ordre ; puis texte
		// visible : seules les détections nouvelles.
		want := []Match{
			{Detector: 0, ByteStart: 0, ByteEnd: 12},
			{Detector: 1, ByteStart: siretStart, ByteEnd: siretEnd},
			{Detector: 2, ByteStart: termStart, ByteEnd: termEnd},
			{Detector: 0, ByteStart: hiddenStart, ByteEnd: hiddenEnd},
		}
		if len(matches) != len(want) {
			t.Fatalf("%+v", matches)
		}
		for i := range want {
			if matches[i] != want[i] {
				t.Fatalf("%d : %+v, attendu %+v", i, matches[i], want[i])
			}
		}
	})
	t.Run("octet invalide voisin d'un caractère ignorable : jamais de séquence UTF-8 formée par le retrait", func(t *testing.T) {
		content := append([]byte("CLI-1234"), 0xE2, 0x82)
		content = append(content, "\u200b"...)
		content = append(content, 0xAC)
		content = append(content, "5678 CLI-12345678"...)
		matches, err := p.Analyze(content, nil, -1)
		if err != nil || len(matches) != 1 || matches[0].ByteStart != 19 {
			t.Fatalf("%+v %v", matches, err)
		}
	})
	t.Run("limite de détections : ErrTooManyMatches, aucune détection", func(t *testing.T) {
		content := []byte(strings.Repeat("CLI-12345678 ", 5))
		if matches, err := p.Analyze(content, nil, 4); !errors.Is(err, ErrTooManyMatches) || matches != nil {
			t.Fatalf("%+v %v", matches, err)
		}
		if matches, err := p.Analyze(content, nil, 5); err != nil || len(matches) != 5 {
			t.Fatalf("%+v %v", matches, err)
		}
		// Second passage (texte visible) : la limite porte sur les détections après retrait des doublons.
		hidden := []byte(strings.Repeat("CLI-12345678 ", 3) + "CLI-1234\u200b5678")
		if _, err := p.Analyze(hidden, nil, 3); !errors.Is(err, ErrTooManyMatches) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("budget de travail : ErrWorkBudget, compté aussi par le compteur parent", func(t *testing.T) {
		parent := NewMeter(1<<40, nil)
		meter := NewMeter(10, parent)
		if matches, err := p.Analyze([]byte("le projet faucon CLI-12345678"), meter, -1); !errors.Is(err, ErrWorkBudget) || matches != nil {
			t.Fatalf("%+v %v", matches, err)
		}
		if parent.Used() == 0 || parent.Used() != meter.Used() {
			t.Fatalf("parent %d, compteur %d", parent.Used(), meter.Used())
		}
		// Budget épuisé par le passage au texte visible lui-même.
		content := []byte("\u200b" + strings.Repeat("x", 200))
		probe := NewMeter(1<<40, nil)
		if _, err := p.Analyze(content, probe, -1); err != nil {
			t.Fatal(err)
		}
		first := NewMeter(1<<40, nil)
		if _, err := p.detect(content, first, -1, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Analyze(content, NewMeter(first.Used()+1, nil), -1); !errors.Is(err, ErrWorkBudget) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("panique d'une autre cause : propagée", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("panique absorbée")
			}
		}()
		_, _ = p.detect([]byte("x"), nil, -1, nil)
	})
	t.Run("contenu non modifié", func(t *testing.T) {
		content := []byte("CLI-12345678 projet\u200bfaucon")
		before := append([]byte(nil), content...)
		if _, err := p.Analyze(content, nil, -1); err != nil || !bytes.Equal(before, content) {
			t.Fatal("contenu modifié")
		}
	})
}

func TestTerms(t *testing.T) {
	salt, _ := DecodeSalt(testSalt)
	for term, want := range map[string]string{
		"  PROJET   faucon  ": "projet faucon",
		"ΑΣ ΣΑΣ":              "ας σας",
		"İstanbul":            "istanbul",
		"½":                   "1⁄2",
		"\u0301 seul":         "seul",
		"Côte-d’Ivoire 2026":  "cote d ivoire 2026",
		"ﬁnance":              "finance",
		"":                    "",
	} {
		if got := NormalizeTerm(term); got != want {
			t.Errorf("%q → %q, attendu %q", term, got, want)
		}
	}
	digest, words := DigestTerm(salt, "Projet Faucon")
	if words != 2 || digest != TermDigest(salt, "projet faucon") || len(digest) != 64 {
		t.Fatal(digest)
	}
	if _, words := DigestTerm(salt, "-- !"); words != 0 {
		t.Fatal("terme sans mot")
	}
	// Un même mot normalisé deux fois a le même numéro ; un mot devenu vide est ignoré.
	words2 := textWords([]byte("Alpha alpha ALPHA \u0301 beta"), NewMeter(1<<40, nil))
	if len(words2) != 4 || words2[0].id != 0 || words2[2].id != 0 || words2[3].id != 1 {
		t.Fatalf("%+v", words2)
	}
}

func TestMeterSpendSafely(t *testing.T) {
	m := NewMeter(5, nil)
	if err := spendSafely(m, 5); err != nil {
		t.Fatal(err)
	}
	if err := spendSafely(m, 1); !errors.Is(err, ErrWorkBudget) {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("panique absorbée")
		}
	}()
	_ = spendSafely(nil, 1)
}

func TestJSLog2(t *testing.T) {
	// Valeurs exactes et cas limites de __ieee754_log2 (Math.log2 de V8).
	for x, want := range map[float64]float64{1: 0, 0.5: -1, 0.25: -2, 0.125: -3, 1024: 10} {
		if got := jsLog2(x); got != want {
			t.Errorf("log2(%v) = %v", x, got)
		}
	}
	if got := jsLog2(0); got > -1e308 {
		t.Error("log2(0)")
	}
	if got := jsLog2(-1); !math.IsNaN(got) {
		t.Error("log2(-1) n'est pas NaN")
	}
	if got := jsLog2(5e-324); got != -1074 {
		t.Errorf("log2(dénormal) = %v", got)
	}
	if inf := jsLog2(math.Inf(1)); !math.IsInf(inf, 1) {
		t.Error("log2(+Inf)")
	}
	if got := shannonEntropy([]byte("ABCDABCD")); got != 2 {
		t.Errorf("entropie %v", got)
	}
}
