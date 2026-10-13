package detect

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // condensat non salé calculé pour prouver que l'Empreinte locale n'en est jamais un.
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // idem.
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Tests de l'Empreinte locale. Aucune clé ni valeur réelle : clés et valeurs sont
// tirées à l'exécution, ou synthétiques et décrites par les vecteurs (vectors/fingerprint.json).

const fingerprintVectorsPath = "../vectors/fingerprint.json"

// localFingerprintForm est la forme d'une Empreinte locale : 32 caractères hexadécimaux minuscules.
var localFingerprintForm = regexp.MustCompile(`^[0-9a-f]{32}$`)

// randomKey tire une clé d'Empreinte locale.
func randomKey(t testing.TB) FingerprintKey {
	t.Helper()
	raw := make([]byte, FingerprintKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	key, err := NewFingerprintKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// randomGitHubToken tire à l'exécution une valeur de la forme de la règle github_token (jamais écrite dans le dépôt).
func randomGitHubToken(t testing.TB) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	raw := make([]byte, 36)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	for i, b := range raw {
		raw[i] = alphabet[int(b)%len(alphabet)]
	}
	return "gh" + "p_" + string(raw)
}

// syntheticKey construit la clé des vecteurs : octet i = (from + i) mod 256.
func syntheticKey(t testing.TB, from int) FingerprintKey {
	t.Helper()
	raw := make([]byte, FingerprintKeyBytes)
	for i := range raw {
		raw[i] = byte((from + i) % 256)
	}
	key, err := NewFingerprintKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// onlyFinding analyse content et exige un seul constat de la règle ruleID, avec son Empreinte locale.
func onlyFinding(t *testing.T, rules *Rules, content []byte, key FingerprintKey, ruleID string) Finding {
	t.Helper()
	result := ScanWithFingerprint(content, rules, key)
	if !result.Complete || len(result.Findings) != 1 || result.Findings[0].RuleID != ruleID {
		t.Fatalf("analyse : complète %t, %d constats", result.Complete, len(result.Findings))
	}
	if !localFingerprintForm.MatchString(result.Findings[0].LocalFingerprint) {
		t.Fatal("Empreinte locale hors de la forme du contrat")
	}
	return result.Findings[0]
}

func TestLocalFingerprintVectors(t *testing.T) {
	t.Run("Empreinte locale HMAC-SHA256 tronquée à 16 octets", func(t *testing.T) {
		data, err := os.ReadFile(fingerprintVectorsPath)
		if err != nil {
			t.Fatal(err)
		}
		var vectors struct {
			FormatVersion int `json:"formatVersion"`
			Cases         []struct {
				Name        string  `json:"name"`
				KeyFrom     int     `json:"keyFrom"`
				Value       *string `json:"value"`
				ValueHex    *string `json:"valueHex"`
				Fingerprint string  `json:"fingerprint"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(data, &vectors); err != nil || vectors.FormatVersion != 1 || len(vectors.Cases) == 0 {
			t.Fatalf("vecteurs illisibles : %v", err)
		}
		names := map[string]bool{}
		for _, c := range vectors.Cases {
			if names[c.Name] || c.KeyFrom < 0 || c.KeyFrom > 255 || !localFingerprintForm.MatchString(c.Fingerprint) {
				t.Fatalf("%s : nom en double, keyFrom hors de 0..255 ou Empreinte locale hors forme", c.Name)
			}
			names[c.Name] = true
			var value []byte
			switch {
			case c.Value != nil && c.ValueHex == nil:
				value = []byte(*c.Value)
			case c.ValueHex != nil && c.Value == nil:
				if value, err = hex.DecodeString(*c.ValueHex); err != nil {
					t.Fatalf("%s : valueHex illisible", c.Name)
				}
			default:
				t.Fatalf("%s : value ou valueHex attendu", c.Name)
			}
			if got := localFingerprint(syntheticKey(t, c.KeyFrom), value); got != c.Fingerprint {
				t.Errorf("%s : %s, attendu %s", c.Name, got, c.Fingerprint)
			}
		}
	})
}

func TestLocalFingerprintViews(t *testing.T) {
	rules := loadInitialRules(t)

	t.Run("une même clé synthétique collée en clair puis en base64 a la même Empreinte locale sous une même clé", func(t *testing.T) {
		for range 8 {
			key := randomKey(t)
			token := randomGitHubToken(t)
			plain := onlyFinding(t, rules, []byte("export TOKEN_VALUE "+token+"\n"), key, "github_token")
			encoded := onlyFinding(t, rules, []byte("blob "+base64.StdEncoding.EncodeToString([]byte(token))+" fin\n"), key, "github_token")
			if plain.Encoding != EncodingPlain || encoded.Encoding != EncodingBase64 {
				t.Fatalf("vues %s et %s", plain.Encoding, encoded.Encoding)
			}
			if plain.LocalFingerprint != encoded.LocalFingerprint {
				t.Fatal("clair et base64 : Empreintes locales différentes")
			}
			// La valeur normalisée est la valeur sans délimiteurs : l'Empreinte locale est celle de la valeur seule.
			if plain.LocalFingerprint != localFingerprint(key, []byte(token)) {
				t.Fatal("Empreinte locale qui n'est pas celle de la valeur")
			}
			other := onlyFinding(t, rules, []byte("export TOKEN_VALUE "+token+"\n"), randomKey(t), "github_token")
			if other.LocalFingerprint == plain.LocalFingerprint {
				t.Fatal("deux clés : même Empreinte locale")
			}
		}
	})

	t.Run("vues pourcentage, JSON, normalisée, lignes jointes et base64 coupé : Empreinte locale de la valeur décodée, NFKC ou jointe", func(t *testing.T) {
		key := randomKey(t)
		token := randomGitHubToken(t)
		want := localFingerprint(key, []byte(token))
		encoded := base64.StdEncoding.EncodeToString([]byte(token))
		// Vue pourcentage : chaque caractère encodé.
		var percent strings.Builder
		for _, b := range []byte(token) {
			fmt.Fprintf(&percent, "%%%02X", b)
		}
		// Vue JSON : chaque caractère en \uXXXX.
		var escaped strings.Builder
		for _, r := range token {
			fmt.Fprintf(&escaped, `\u%04x`, r)
		}
		// Vue normalisée : chiffres et lettres pleine chasse (NFKC → ASCII).
		var wide strings.Builder
		for _, r := range token {
			if r == '_' {
				wide.WriteRune(r)
				continue
			}
			wide.WriteRune(r - 0x21 + 0xFF01)
		}
		for _, c := range []struct {
			content  string
			encoding Encoding
		}{
			{"q=" + percent.String() + "&x=1\n", EncodingPercent},
			{`{"v":"` + escaped.String() + `"}` + "\n", EncodingJSONEscaped},
			{"note " + wide.String() + "\n", EncodingNormalized},
			// Valeur coupée sur deux lignes : vue des lignes jointes, sans saut de ligne ni retrait.
			{"note " + token[:20] + "\n    " + token[20:] + "\n", EncodingWhitespaceJoined},
			// Base64 coupé sur deux lignes : octets décodés de la fenêtre jointe.
			{"blob " + encoded[:24] + "\n" + encoded[24:] + " fin\n", EncodingBase64},
		} {
			got := onlyFinding(t, rules, []byte(c.content), key, "github_token")
			if got.Encoding != c.encoding {
				t.Fatalf("vue %s, attendu %s", got.Encoding, c.encoding)
			}
			if got.LocalFingerprint != want {
				t.Fatalf("vue %s : Empreinte locale qui n'est pas celle de la valeur décodée", c.encoding)
			}
		}
	})
}

// unsaltedForms rend toutes les écritures d'un condensat non salé de value qu'un champ de 32 caractères hexadécimaux
// minuscules (forme d'une Empreinte locale) ou qu'une base64 pourraient porter.
func unsaltedForms(value []byte) (hexForms, base64Forms []string, raw [][]byte) {
	md := md5.Sum(value)  //nolint:gosec // preuve d'absence, jamais une protection.
	s1 := sha1.Sum(value) //nolint:gosec // idem.
	s256 := sha256.Sum256(value)
	for _, digest := range [][]byte{md[:], s1[:], s256[:]} {
		raw = append(raw, digest, digest[:16])
		hexForms = append(hexForms, hex.EncodeToString(digest), strings.ToUpper(hex.EncodeToString(digest)))
		for _, part := range [][]byte{digest, digest[:16]} {
			for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
				base64Forms = append(base64Forms, encoding.EncodeToString(part))
			}
		}
	}
	return hexForms, base64Forms, raw
}

func TestLocalFingerprintNeverUnsaltedHash(t *testing.T) {
	rules := loadInitialRules(t)

	assertSalted := func(t *testing.T, fingerprint string, values ...[]byte) {
		t.Helper()
		got, err := hex.DecodeString(fingerprint)
		if err != nil || len(got) != 16 {
			t.Fatal("Empreinte locale hors forme")
		}
		for _, value := range values {
			hexForms, base64Forms, raw := unsaltedForms(value)
			// Toute fenêtre de 32 caractères des écritures hexadécimales (troncatures comprises).
			for _, form := range hexForms {
				if strings.Contains(strings.ToLower(form), fingerprint) {
					t.Fatal("Empreinte locale égale à une écriture hexadécimale d'un condensat non salé")
				}
			}
			for _, form := range base64Forms {
				if strings.Contains(form, fingerprint) || form == fingerprint {
					t.Fatal("Empreinte locale égale à une écriture base64 d'un condensat non salé")
				}
			}
			for _, digest := range raw {
				if bytes.Contains(digest, got) {
					t.Fatal("octets de l'Empreinte locale égaux à ceux d'un condensat non salé")
				}
			}
		}
	}

	t.Run("l'Empreinte locale diffère de SHA-256, SHA-1 et MD5 de la valeur sous toutes leurs écritures", func(t *testing.T) {
		for range 256 {
			key := randomKey(t)
			value := make([]byte, 1+int(randomByte(t))%64)
			if _, err := rand.Read(value); err != nil {
				t.Fatal(err)
			}
			assertSalted(t, localFingerprint(key, value), value, []byte(hex.EncodeToString(value)))
		}
		// Par l'analyse complète : valeur détectée en clair et en base64, condensats de la valeur, de son écriture base64
		// et du contenu entier.
		for range 16 {
			key := randomKey(t)
			token := randomGitHubToken(t)
			encoded := base64.StdEncoding.EncodeToString([]byte(token))
			for _, content := range []string{"x " + token + "\n", "blob " + encoded + " fin\n"} {
				finding := onlyFinding(t, rules, []byte(content), key, "github_token")
				assertSalted(t, finding.LocalFingerprint, []byte(token), []byte(encoded), []byte(content))
			}
		}
	})

	t.Run("l'Empreinte locale change quand la clé change", func(t *testing.T) {
		token := []byte(randomGitHubToken(t))
		seen := map[string]bool{}
		for range 64 {
			fingerprint := localFingerprint(randomKey(t), token)
			if seen[fingerprint] {
				t.Fatal("deux clés : même Empreinte locale")
			}
			seen[fingerprint] = true
		}
		// Une clé qui ne diffère que d'un bit donne une autre Empreinte locale.
		raw := make([]byte, FingerprintKeyBytes)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		flipped := bytes.Clone(raw)
		flipped[31] ^= 1
		first, err := NewFingerprintKey(bytes.Clone(raw))
		if err != nil {
			t.Fatal(err)
		}
		second, err := NewFingerprintKey(flipped)
		if err != nil {
			t.Fatal(err)
		}
		if localFingerprint(first, token) == localFingerprint(second, token) {
			t.Fatal("clés voisines : même Empreinte locale")
		}
		// Recalcul indépendant : HMAC-SHA256 de la bibliothèque standard, tronqué.
		mac := hmac.New(sha256.New, raw)
		mac.Write(token)
		if want := hex.EncodeToString(mac.Sum(nil)[:16]); localFingerprint(first, token) != want {
			t.Fatal("Empreinte locale différente de HMAC-SHA256 tronqué")
		}
	})
}

func randomByte(t testing.TB) byte {
	t.Helper()
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return b[0]
}

func TestFingerprintKey(t *testing.T) {
	t.Run("NewFingerprintKey refuse une longueur autre que 32 octets et des octets tous égaux, et efface l'entrée", func(t *testing.T) {
		random := func(n int) []byte {
			raw := make([]byte, n)
			if _, err := rand.Read(raw); err != nil {
				t.Fatal(err)
			}
			return raw
		}
		for _, input := range [][]byte{nil, random(31), random(33), random(64), make([]byte, 32), bytes.Repeat([]byte{0xa5}, 32)} {
			if _, err := NewFingerprintKey(input); !errors.Is(err, ErrFingerprintKeyInvalid) {
				t.Fatalf("%d octets : %v", len(input), err)
			}
			if !bytes.Equal(input, make([]byte, len(input))) {
				t.Fatal("entrée refusée non effacée")
			}
		}
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		raw[1] = ^raw[0] // jamais tous égaux
		input := bytes.Clone(raw)
		key, err := NewFingerprintKey(input)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(input, make([]byte, 32)) {
			t.Fatal("entrée acceptée non effacée")
		}
		if !bytes.Equal(key.secret.bytes[:], raw) {
			t.Fatal("clé différente de l'entrée")
		}
	})

	t.Run("la clé ne s'affiche jamais, ni seule ni dans une structure", func(t *testing.T) {
		key := randomKey(t)
		secretHex := hex.EncodeToString(key.secret.bytes[:])
		decimal := strings.Trim(fmt.Sprintf("%d", key.secret.bytes[:6]), "[]")
		holder := struct {
			name string
			key  FingerprintKey
			Ptr  *FingerprintKey
		}{"x", key, &key}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
			for _, arg := range []any{key, &key, holder, &holder} {
				text := fmt.Sprintf(verb, arg)
				if strings.Contains(strings.ToLower(text), secretHex[:16]) || strings.Contains(text, string(key.secret.bytes[:8])) ||
					strings.Contains(text, decimal) {
					t.Fatalf("%s : clé affichée", verb)
				}
			}
		}
		if key.String() != maskedFingerprintKey || key.GoString() != maskedFingerprintKey {
			t.Fatal("texte non masqué")
		}
	})

	t.Run("une clé absente ou effacée rend l'analyse incomplète, sans constat", func(t *testing.T) {
		rules := loadInitialRules(t)
		content := []byte("x " + randomGitHubToken(t) + "\n")
		key := randomKey(t)
		if result := ScanWithFingerprint(content, rules, key); !result.Complete || len(result.Findings) != 1 {
			t.Fatal("clé valide : constat attendu")
		}
		key.Wipe()
		var zero FingerprintKey
		zero.Wipe()
		for _, k := range []FingerprintKey{key, zero} {
			result := ScanWithFingerprint(content, rules, k)
			if result.Complete || result.Failure != FailureScanError || result.Findings != nil {
				t.Fatalf("clé inutilisable : %+v", result)
			}
		}
		if result := ScanWithFingerprint(bytes.Repeat([]byte("a"), MaxInputBytes+1), rules, zero); result.Failure != FailureScanLimit {
			t.Fatalf("entrée trop grande : %+v", result)
		}
	})

	t.Run("Scan ne pose aucune Empreinte locale ; ScanWithFingerprint ne modifie pas le contenu", func(t *testing.T) {
		rules := loadInitialRules(t)
		content := []byte("x " + randomGitHubToken(t) + " " + base64.StdEncoding.EncodeToString([]byte(randomGitHubToken(t))) + "\n")
		before := bytes.Clone(content)
		for _, f := range Scan(content, rules, Options{}).Findings {
			if f.LocalFingerprint != "" {
				t.Fatal("Empreinte locale posée par Scan")
			}
		}
		result := ScanWithFingerprint(content, rules, randomKey(t))
		if len(result.Findings) != 2 || !bytes.Equal(content, before) {
			t.Fatalf("%d constats, contenu modifié : %t", len(result.Findings), !bytes.Equal(content, before))
		}
	})
}

func TestScanWipesBuffers(t *testing.T) {
	t.Run("les tampons de l'analyse (vues dérivées, textes décodés) sont effacés à la fin", func(t *testing.T) {
		rules := loadInitialRules(t)
		token := randomGitHubToken(t)
		encoded := base64.StdEncoding.EncodeToString([]byte(token))
		content := []byte("a\r\nq=" + url.QueryEscape("é"+token) + " blob " + encoded + " ＡＢ " + token + "\n")
		s := newScanState(rules)
		findings, err := s.collect(content, language{})
		if err != nil || len(findings) == 0 {
			t.Fatalf("analyse : %v, %d constats", err, len(findings))
		}
		if len(s.views.builders) == 0 || len(s.views.owned) == 0 {
			t.Fatal("aucun tampon relevé")
		}
		builders, owned := s.views.builders, s.views.owned
		s.views.wipe()
		for _, b := range builders {
			if bytes.ContainsFunc(b.text[:cap(b.text)], func(r rune) bool { return r != 0 }) {
				t.Fatal("vue dérivée non effacée")
			}
		}
		for _, buffer := range owned {
			if !bytes.Equal(buffer[:cap(buffer)], make([]byte, cap(buffer))) {
				t.Fatal("texte décodé non effacé")
			}
		}
		if !bytes.Contains(content, []byte(token)) {
			t.Fatal("contenu de l'appelant modifié")
		}
	})

	// assertWiped exige que tous les tampons relevés par l'analyse (vues dérivées, textes décodés) soient effacés.
	assertWiped := func(t *testing.T, s *scanState) {
		t.Helper()
		if s == nil || len(s.views.builders)+len(s.views.owned) == 0 {
			t.Fatal("aucun tampon relevé")
		}
		for _, b := range s.views.builders {
			if !bytes.Equal(b.text[:cap(b.text)], make([]byte, cap(b.text))) {
				t.Fatal("vue dérivée non effacée")
			}
		}
		for _, buffer := range s.views.owned {
			if !bytes.Equal(buffer[:cap(buffer)], make([]byte, cap(buffer))) {
				t.Fatal("texte décodé non effacé")
			}
		}
	}
	// capture relève l'état créé par scan (couture scanStateFor).
	capture := func(t *testing.T) **scanState {
		t.Helper()
		captured := new(*scanState)
		original := scanStateFor
		scanStateFor = func(rules *Rules) *scanState {
			*captured = original(rules)
			return *captured
		}
		t.Cleanup(func() { scanStateFor = original })
		return captured
	}

	t.Run("Scan et ScanWithFingerprint effacent les tampons de l'analyse avant de rendre la main", func(t *testing.T) {
		rules := loadInitialRules(t)
		token := randomGitHubToken(t)
		content := []byte("a\r\nq=" + url.QueryEscape("é"+token) + " blob " + base64.StdEncoding.EncodeToString([]byte(token)) + " ＡＢ " + token + "\n")
		for _, run := range []func() Result{
			func() Result { return ScanWithFingerprint(content, rules, randomKey(t)) },
			func() Result { return Scan(content, rules, Options{}) },
		} {
			captured := capture(t)
			if result := run(); !result.Complete || len(result.Findings) == 0 {
				t.Fatalf("analyse : %+v", result)
			}
			assertWiped(t, *captured)
		}
	})

	t.Run("une analyse qui panique efface aussi ses tampons", func(t *testing.T) {
		captured := capture(t)
		result := ScanWithFingerprint([]byte("p\u0061ss zz%5Fq7k2m\r\n"), panickingRules(), randomKey(t))
		if result.Failure != FailureScanError {
			t.Fatalf("issue %+v", result)
		}
		assertWiped(t, *captured)
	})
}

func TestLocalFingerprintFailClosed(t *testing.T) {
	t.Run("un constat sans valeur rend l'analyse incomplète, jamais l'Empreinte locale du texte vide", func(t *testing.T) {
		key := randomKey(t)
		if _, ok := publicFindings([]finding{{ruleID: "github_token", start: 0, end: 4, value: nil}}, &key); ok {
			t.Fatal("constat sans valeur accepté")
		}
		if out, ok := publicFindings([]finding{{ruleID: "github_token", start: 0, end: 4, value: nil}}, nil); !ok || len(out) != 1 {
			t.Fatal("Scan sans clé : le constat reste")
		}
		v := identityView([]byte("abc"))
		if got := v.slice(5, 9); len(got) != 0 || cap(got) != 0 {
			t.Fatal("étendue hors de la vue")
		}
	})

	t.Run("un constructeur de vue ne garde que le texte, effacé à la fin de l'analyse", func(t *testing.T) {
		budget := newViewBudget()
		b := newBuilder(4, budget)
		for _, c := range []byte("abcdefgh") {
			if err := b.pushByte(c, 0, 1); err != nil {
				t.Fatal(err)
			}
		}
		v := b.finish(budget, EncodingNormalized)
		if b.starts != nil || b.ends != nil || len(v.starts) != 8 || string(v.text) != "abcdefgh" {
			t.Fatal("tables de correspondance gardées par le constructeur")
		}
		budget.wipe()
		if !bytes.Equal(v.text, make([]byte, 8)) {
			t.Fatal("texte de la vue non effacé")
		}
	})
}

func TestNoExportedFunctionReturnsValue(t *testing.T) {
	t.Run("aucune fonction exportée ne rend les octets de la valeur", func(t *testing.T) {
		entries, err := os.ReadDir(".")
		if err != nil {
			t.Fatal(err)
		}
		// Seules fonctions exportées qui rendent du texte : messages d'erreur et clé masquée.
		textAllowed := map[string]bool{"Error": true, "String": true, "GoString": true}
		checked := 0
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || !fn.Name.IsExported() || fn.Type.Results == nil {
					continue
				}
				checked++
				for _, result := range fn.Type.Results.List {
					switch r := result.Type.(type) {
					case *ast.ArrayType:
						t.Errorf("%s : rend un tableau ou une tranche", fn.Name.Name)
					case *ast.Ident:
						if (r.Name == "string" && !textAllowed[fn.Name.Name]) || r.Name == "byte" || r.Name == "any" {
							t.Errorf("%s : rend %s", fn.Name.Name, r.Name)
						}
					case *ast.InterfaceType, *ast.FuncType, *ast.ChanType, *ast.MapType:
						t.Errorf("%s : rend un type non contrôlé", fn.Name.Name)
					}
				}
			}
		}
		if checked == 0 {
			t.Fatal("aucune fonction relevée")
		}
	})
}
