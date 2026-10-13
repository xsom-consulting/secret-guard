// Tests portés de secret-guard/packages/core (Apache-2.0) : origine, avis et modifications dans UPSTREAM.md.

package detect

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// Tests des décodages bornés, portés de encoding.test.ts et des tests de budget de scan.test.ts (Secret Guard) ;
// les valeurs qui ressembleraient à un secret sont construites à l'exécution.

func b64(s string) string    { return base64.StdEncoding.EncodeToString([]byte(s)) }
func b64url(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// buildJWT construit un jeton de forme JWT (en-tête, charge, signature) à l'exécution.
func buildJWT(header, payload, signature string) string {
	return b64url(header) + "." + b64url(payload) + "." + signature
}

func TestDecodeBase64(t *testing.T) {
	for _, value := range []string{"A", "@@@=", "A===", "A=B=", "AAAAA", "====", "", "AA=A", "aGVs bG8=", "aGVsbG8=\n"} {
		t.Run("base64 — entrée mal formée refusée : "+value, func(t *testing.T) {
			if text, ok := decodeBase64(value, maxCandidateDecodedBytes); ok {
				t.Fatalf("%q décodé en %q", value, text)
			}
		})
	}

	t.Run("base64 — alphabets standard et URL, remplissage facultatif", func(t *testing.T) {
		cases := map[string]string{
			"aGVsbG8=":        "hello",
			"eyJvayI6dHJ1ZX0": `{"ok":true}`,
			"Pz8/Pj4+":        "???>>>",
			"Pz8_Pj4-":        "???>>>",
			"YQ":              "a",
			"YWI":             "ab",
			"YWI=":            "ab",
		}
		for value, want := range cases {
			if text, ok := decodeBase64(value, maxCandidateDecodedBytes); !ok || text != want {
				t.Fatalf("%q → %q (%v), attendu %q", value, text, ok, want)
			}
		}
	})

	t.Run("base64 — sortie au-delà de la borne de l'appelant refusée", func(t *testing.T) {
		if _, ok := decodeBase64("aGVsbG8=", 4); ok {
			t.Fatal("cinq octets pour une borne de quatre")
		}
		if text, ok := decodeBase64("aGVsbG8=", 5); !ok || text != "hello" {
			t.Fatal("borne exacte")
		}
	})

	t.Run("base64 — UTF-8 invalide, NUL ou caractères de contrôle refusés", func(t *testing.T) {
		for _, value := range []string{"/w==", "AA==", "AQIDBA==", b64("abcdefgh\x01\x02"), b64("\xed\xa0\x80abc")} {
			if text, ok := decodeBase64(value, maxCandidateDecodedBytes); ok {
				t.Fatalf("%q décodé en %q", value, text)
			}
		}
	})

	t.Run("base64 — imprimable à 90 % au moins, point de code hors BMP imprimable", func(t *testing.T) {
		for _, plain := range []string{"abcdefghi\x01", "\xf0\x9f\x98\x80", "a\tb\r\nc\x7f"} {
			if text, ok := decodeBase64(b64(plain), maxCandidateDecodedBytes); !ok || text != plain {
				t.Fatalf("%q refusé", plain)
			}
		}
	})

	t.Run("base64 — marque d'ordre d'octets initiale retirée comme par TextDecoder", func(t *testing.T) {
		if text, ok := decodeBase64(b64("\xef\xbb\xbfhello"), maxCandidateDecodedBytes); !ok || text != "hello" {
			t.Fatalf("%q", text)
		}
		if _, ok := decodeBase64(b64("\xef\xbb\xbf"), maxCandidateDecodedBytes); ok {
			t.Fatal("texte vide après la marque")
		}
	})
}

func TestJWTStructure(t *testing.T) {
	t.Run("la validité structurelle d'un JWT suit isStructurallyValidJwt", func(t *testing.T) {
		valid := buildJWT(`{"alg":"HS256","typ":"JWT"}`, `{"sub":"corpus"}`, "abcdefghij")
		cases := []struct {
			value string
			want  bool
		}{
			{"one.two", false},
			{"eyJ9.eyJ9.short", false},
			{"W10.W10.abcdefgh", false},
			{valid, true},
			{buildJWT(`{}`, `{}`, "abcdefgh"), true},
			{buildJWT(`{}`, `{}`, "abcdefg"), false},
			{buildJWT(`{}`, `[]`, "abcdefgh"), false},
			{buildJWT(`null`, `{}`, "abcdefgh"), false},
			{buildJWT(`{bad`, `{}`, "abcdefgh"), false},
			{buildJWT(" \n{\"a\":[1,{\"b\":null}]} ", `{}`, "abcdefgh"), true},
			{"\xef\xbb\xbf" + valid, false},
			{valid + ".x", false},
		}
		for _, c := range cases {
			if got, err := isStructurallyValidJWT(c.value, nil); got != c.want || err != nil {
				t.Fatalf("%q → %v (%v), attendu %v", c.value, got, err, c.want)
			}
		}
	})

	t.Run("JWT — en-tête décodé qui n'est pas du JSON : charge non décodée, budget non débité", func(t *testing.T) {
		budget := &decodeBudget{}
		if ok, err := isStructurallyValidJWT(buildJWT(`{bad`, `{}`, "abcdefgh"), budget); ok || err != nil || budget.candidates != 1 {
			t.Fatalf("%v %v, %d décodages", ok, err, budget.candidates)
		}
		if ok, err := isStructurallyValidJWT("@@@@."+b64url(`{}`)+".abcdefgh", budget); ok || err != nil || budget.candidates != 3 {
			t.Fatalf("en-tête illisible : %v %v, %d décodages", ok, err, budget.candidates)
		}
	})

	t.Run("JWT — budget épuisé : jeton non reconnu et analyse incomplète", func(t *testing.T) {
		budget := &decodeBudget{candidates: maxDecodeAttempts - 1}
		valid := buildJWT(`{}`, `{}`, "abcdefgh")
		if ok, err := isStructurallyValidJWT(valid, budget); ok || !errors.Is(err, errDecodeBudgetExhausted) {
			t.Fatalf("%v %v", ok, err)
		}
		if ok, err := isStructurallyValidJWT(valid, budget); ok || !errors.Is(err, errDecodeBudgetExhausted) {
			t.Fatalf("budget déjà épuisé : %v %v", ok, err)
		}
	})
}

func TestDecodeBudget(t *testing.T) {
	password := "PASS" + "WORD=" + "hunter" + "2"
	rules := loadInitialRules(t)
	// scanErr passe par l'assemblage de Scan (budgets partagés de toute l'analyse) et rend l'erreur qui la rend
	// incomplète.
	scanErr := func(content string) error {
		_, err := collect(rules, []byte(content), language{})
		if result := Scan([]byte(content), rules, Options{}); (err == nil) != result.Complete {
			t.Fatalf("Scan %+v, assemblage %v", result.Failure, err)
		}
		return err
	}

	t.Run("un budget de décodage épuisé rend l'analyse incomplète", func(t *testing.T) {
		// 129 candidats base64 (scan.test.ts : « fails closed when Base64 decoding budgets are exhausted »).
		content := strings.Repeat(b64(password)+"\n", 129)
		if err := scanErr(content); !errors.Is(err, errDecodeBudgetExhausted) {
			t.Fatalf("129 candidats : %v", err)
		}
		if err := scanErr(strings.Repeat(b64(password)+"\n", 128)); err != nil {
			t.Fatalf("128 candidats : %v", err)
		}
		// Candidats refusés au décodage débités aussi (« charges rejected Base64 candidates »).
		rejected := b64(strings.Repeat("Printable candidate prefix with varied ASCII. ", 3) + "\xff\xfe")
		if err := scanErr(strings.Repeat(rejected+" ", 129)); !errors.Is(err, errDecodeBudgetExhausted) {
			t.Fatalf("candidats refusés : %v", err)
		}
	})

	t.Run("budget — 128 décodages au plus, puis épuisé sans nouveau débit", func(t *testing.T) {
		budget := &decodeBudget{}
		for i := 0; i < maxDecodeAttempts; i++ {
			if _, ok, err := budget.decodeBase64("aGVsbG8=", maxCandidateDecodedBytes); !ok || err != nil {
				t.Fatalf("décodage %d : %v", i, err)
			}
		}
		if _, _, err := budget.decodeBase64("aGVsbG8=", maxCandidateDecodedBytes); !errors.Is(err, errDecodeBudgetExhausted) || !budget.exhausted {
			t.Fatalf("129e : %v", err)
		}
		before := *budget
		if _, _, err := budget.decodeBase64("aGVsbG8=", maxCandidateDecodedBytes); !errors.Is(err, errDecodeBudgetExhausted) || *budget != before {
			t.Fatal("budget épuisé débité")
		}
	})

	t.Run("budget — 262 144 octets décodés au plus, longueur débitée avant le décodage", func(t *testing.T) {
		budget := &decodeBudget{}
		large := strings.Repeat("A", 4*maxCandidateDecodedBytes) // 49 152 octets annoncés, débit borné à 16 385
		for i := 0; i < maxDecodedBytes/(maxCandidateDecodedBytes+1); i++ {
			if _, _, err := budget.decodeBase64(large, maxCandidateDecodedBytes); err != nil {
				t.Fatalf("décodage %d : %v", i, err)
			}
		}
		if _, _, err := budget.decodeBase64(large, maxCandidateDecodedBytes); !errors.Is(err, errDecodeBudgetExhausted) {
			t.Fatalf("au-delà de 262 144 octets : %v (%d)", err, budget.bytes)
		}
		// La longueur débitée est celle de JavaScript (unités UTF-16).
		budget = &decodeBudget{}
		_, _, _ = budget.decodeBase64("\xf0\x9f\x98\x80abc", maxCandidateDecodedBytes)
		if budget.bytes != 4 {
			t.Fatalf("débit %d, attendu ceil(5 × 3 / 4) = 4", budget.bytes)
		}
	})

	t.Run("une empreinte SRI exacte ne débite pas le budget", func(t *testing.T) {
		sri := "sha512-" + strings.Repeat("Ab3+", 21) + "Ab=="
		if err := scanErr(strings.Repeat(sri+"\n", 200)); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("fenêtres de jetons fixes et base64 partagent un budget", func(t *testing.T) {
		fixed := "g\nhp_" + strings.Repeat("aB3", 12)
		encoded := b64(password)
		wrapped := encoded[:12] + "\n" + encoded[12:]
		parts := append(repeatString(fixed, 64), repeatString(wrapped, 65)...)
		if err := scanErr(strings.Join(parts, "\n!")); !errors.Is(err, errJoinedWindowBudgetExhausted) {
			t.Fatalf("129 fenêtres : %v", err)
		}
	})
}

func repeatString(s string, n int) []string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = s
	}
	return parts
}

func collectCandidates(text string) [][2]int {
	var got [][2]int
	_ = base64Candidates([]byte(text), func(start, end int) error {
		got = append(got, [2]int{start, end})
		return nil
	})
	return got
}

func TestBase64Candidates(t *testing.T) {
	t.Run("candidats base64 — 20 à 16 384 caractères, puis jusqu'à deux « = »", func(t *testing.T) {
		long := strings.Repeat("Ab3+", 4103) // 16 412 caractères
		cases := []struct {
			text string
			want [][2]int
		}{
			{strings.Repeat("a", 19), nil},
			{"x " + strings.Repeat("a", 20) + "=== y", [][2]int{{2, 24}}},
			{long + "==", [][2]int{{0, 16384}, {16384, 16414}}},
			{strings.Repeat("a", 16384+19), [][2]int{{0, 16384}}},
			{"é" + strings.Repeat("a", 20) + "é", [][2]int{{2, 22}}},
		}
		for _, c := range cases {
			if got := collectCandidates(c.text); len(got) != len(c.want) || (len(got) > 0 && got[0] != c.want[0]) || (len(got) > 1 && got[1] != c.want[1]) {
				t.Fatalf("%.30q… → %v, attendu %v", c.text, got, c.want)
			}
		}
		stop := errors.New("arrêt")
		if err := base64Candidates([]byte(strings.Repeat("a", 40)), func(int, int) error { return stop }); !errors.Is(err, stop) {
			t.Fatal("erreur du visiteur perdue")
		}
	})

	t.Run("candidats base64 — charge plausible seulement", func(t *testing.T) {
		cases := map[string]bool{
			"sha256-" + strings.Repeat("A", 43):    false,
			"SHA384-" + strings.Repeat("Ab3+", 16): false,
			"sha512-" + strings.Repeat("Ab3+", 22): false,
			"sha256-" + strings.Repeat("Abc3", 9):  true,
			strings.Repeat("abc", 10):              false,
			strings.Repeat("abcd", 5) + "e":        false,
			strings.Repeat("ab+d", 5) + "_x":       false,
			strings.Repeat("ab+d", 6):              true,
			strings.Repeat("ab-d", 6):              true,
		}
		for value, want := range cases {
			if got := isPlausibleBase64Payload(value); got != want {
				t.Fatalf("%q → %v, attendu %v", value, got, want)
			}
		}
	})

	t.Run("candidats base64 — une étendue de la source déjà vue n'est ni décodée ni débitée deux fois", func(t *testing.T) {
		budget := &decodeBudget{}
		seen := map[sourceRange]struct{}{}
		v := identityView([]byte(b64("one two three four") + " %41"))
		var decoded []string
		visit := func(_, _ int, text string) error {
			decoded = append(decoded, text)
			return nil
		}
		for range 2 {
			if err := forEachBase64Candidate(v, budget, seen, visit); err != nil {
				t.Fatal(err)
			}
		}
		if len(decoded) != 1 || decoded[0] != "one two three four" || budget.candidates != 1 {
			t.Fatalf("%q, %d débits", decoded, budget.candidates)
		}
	})
}

func TestJWTBudgetAlreadyExhausted(t *testing.T) {
	t.Run("JWT — budget déjà épuisé : erreur rendue même pour un jeton hors forme", func(t *testing.T) {
		for _, value := range []string{"a.b", "a.b.c", "x"} {
			if ok, err := isStructurallyValidJWT(value, &decodeBudget{exhausted: true}); ok || !errors.Is(err, errDecodeBudgetExhausted) {
				t.Fatalf("%q : %v %v", value, ok, err)
			}
		}
	})
}
