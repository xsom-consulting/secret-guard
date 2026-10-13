// Tests portés de secret-guard/packages/core (Apache-2.0) : origine, avis et modifications dans UPSTREAM.md.

package detect

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Tests des vues de texte, portés de text.test.ts et des comportements de mapping.ts (Secret Guard) ; les entrées
// qui ressembleraient à un secret sont construites à l'exécution.

func mustViews(t *testing.T, content []byte) *textViews {
	t.Helper()
	views, err := buildTextViews(content, newViewBudget())
	if err != nil {
		t.Fatalf("vues refusées : %v", err)
	}
	return views
}

// spanOf ramène toute la vue à la source.
func spanOf(v *view) [2]int {
	s, e := v.mapRange(0, len(v.text))
	return [2]int{s, e}
}

// spanAt ramène l'étendue [start, end) de la vue à la source.
func spanAt(v *view, start, end int) [2]int {
	s, e := v.mapRange(start, end)
	return [2]int{s, e}
}

func viewWith(t *testing.T, views []*view, encoding Encoding) *view {
	t.Helper()
	for _, v := range views {
		if v.encoding == encoding {
			return v
		}
	}
	t.Fatalf("aucune vue %s", encoding)
	return nil
}

func TestTextViews(t *testing.T) {
	t.Run("un texte UTF-8 est analysé tel quel (vue d'identité, aucune vue inutile)", func(t *testing.T) {
		content := []byte("# Notes\nclé = é")
		views := mustViews(t, content)
		if !bytes.Equal(views.identity.text, content) || views.identity.encoding != EncodingPlain {
			t.Fatalf("identité %q", views.identity.text)
		}
		if views.normalized != nil || views.canonical != views.identity || len(views.transformed) != 0 {
			t.Fatal("vue dérivée d'un texte que la normalisation ne change pas")
		}
	})

	t.Run("contenu binaire, NUL et UTF-8 invalide sont conservés et analysés, sans erreur ni troncature", func(t *testing.T) {
		for _, content := range [][]byte{{0x89, 'P', 'N', 'G', 0}, {0xFF, 0xFE, 'A'}, {'a', 0, 'b', 0xC3}} {
			views := mustViews(t, content)
			if !bytes.Equal(views.identity.text, content) || views.normalized != nil {
				t.Fatalf("%x : identité %x, normalisée %v", content, views.identity.text, views.normalized != nil)
			}
		}
		// Dans une vue dérivée, chaque octet invalide vaut U+FFFD (comme dans le texte analysé par Secret Guard) et
		// garde son étendue d'un octet.
		views := mustViews(t, []byte("\xff%41\x00"))
		percent := viewWith(t, views.transformed, EncodingPercent)
		if string(percent.text) != "\uFFFDA\x00" {
			t.Fatalf("pourcentage %q", percent.text)
		}
		if spanAt(percent, 0, 3) != [2]int{0, 1} || spanAt(percent, 3, 4) != [2]int{1, 4} || spanAt(percent, 4, 5) != [2]int{4, 5} {
			t.Fatal("correspondance des octets invalides")
		}
	})

	t.Run("deux octets invalides rendus adjacents par un retrait ne forment jamais un point de code", func(t *testing.T) {
		// E2 (invalide), U+200B (retiré), 80 80 (invalides) : Secret Guard voit trois U+FFFD, jamais U+2000.
		views := mustViews(t, []byte("\xe2\u200B\x80\x80"))
		if string(views.normalized.text) != strings.Repeat("\uFFFD", 3) {
			t.Fatalf("normalisée %q", views.normalized.text)
		}
		if spanAt(views.normalized, 3, 6) != [2]int{4, 5} {
			t.Fatal("correspondance")
		}
	})
}

func TestNormalizedView(t *testing.T) {
	t.Run("normalisée — retrait des ignorables par défaut, correspondance vers la source", func(t *testing.T) {
		views := mustViews(t, []byte("a\u200Bb\u2060c\u00ADd"))
		n := views.normalized
		if string(n.text) != "abcd" || n.encoding != EncodingNormalized {
			t.Fatalf("normalisée %q", n.text)
		}
		if spanAt(n, 1, 2) != [2]int{4, 5} || spanAt(n, 0, 4) != [2]int{0, 12} {
			t.Fatalf("correspondance %v %v", spanAt(n, 1, 2), spanAt(n, 0, 4))
		}
	})

	t.Run("normalisée — NFKC point de code par point de code, sans composition entre points de code", func(t *testing.T) {
		views := mustViews(t, []byte("\uFF47\u210C\u017F e\u0301\r\n"))
		// Pleine chasse, lettre mathématique, s long, puis e et accent combinant non composés, CRLF → LF.
		if string(views.normalized.text) != "gHs e\u0301\n" {
			t.Fatalf("normalisée %q", views.normalized.text)
		}
		if spanAt(views.normalized, 0, 1) != [2]int{0, 3} || spanAt(views.normalized, len(views.normalized.text)-1, len(views.normalized.text)) != [2]int{12, 14} {
			t.Fatal("correspondance")
		}
	})

	t.Run("normalisée — CRLF devient LF, CR seul et LF seul restent", func(t *testing.T) {
		views := mustViews(t, []byte("a\r\nb\rc\nd"))
		if string(views.normalized.text) != "a\nb\rc\nd" || spanAt(views.normalized, 1, 2) != [2]int{1, 3} {
			t.Fatalf("normalisée %q", views.normalized.text)
		}
	})

	t.Run("normalisée — absente pour un texte ASCII sans CRLF, ou que la normalisation ne change pas", func(t *testing.T) {
		for _, content := range []string{"", "plain ascii\n", "déjà normalisé", "\uFFFD"} {
			if views := mustViews(t, []byte(content)); views.normalized != nil {
				t.Fatalf("%q : vue normalisée inutile", content)
			}
		}
	})
}

func TestPercentView(t *testing.T) {
	cases := []struct {
		name, input, want string
	}{
		{"une seule couche", "%2541", "%41"},
		{"séquence UTF-8 validée", "caf%C3%A9", "café"},
		{"séquence invalide gardée telle quelle, les autres décodées", "%C3%28%41", "%C3(A"},
		{"forme trop longue refusée", "%C0%AF%41", "%C0%AFA"},
		{"substitut refusé", "%ED%A0%80%41", "%ED%A0%80A"},
		{"au-delà de U+10FFFF refusé", "%F4%90%80%80%41", "%F4%90%80%80A"},
		{"séquence tronquée", "%E2%82%41", "%E2%82A"},
		{"minuscules", "%5f%5F", "__"},
	}
	for _, c := range cases {
		t.Run("pourcentage — "+c.name, func(t *testing.T) {
			views := mustViews(t, []byte(c.input))
			if got := string(viewWith(t, views.transformed, EncodingPercent).text); got != c.want {
				t.Fatalf("%q → %q, attendu %q", c.input, got, c.want)
			}
		})
	}

	t.Run("pourcentage — correspondance de chaque point de code décodé vers sa séquence", func(t *testing.T) {
		percent := viewWith(t, mustViews(t, []byte("x%C3%A9y")).transformed, EncodingPercent)
		if spanAt(percent, 1, 3) != [2]int{1, 7} || spanAt(percent, 3, 4) != [2]int{7, 8} {
			t.Fatal("correspondance")
		}
	})

	t.Run("pourcentage — aucune vue sans séquence décodée", func(t *testing.T) {
		for _, input := range []string{"100%", "%zz", "%C3", "%4"} {
			if views := mustViews(t, []byte(input)); len(views.transformed) != 0 {
				t.Fatalf("%q : vue inutile", input)
			}
		}
	})
}

func TestJSONEscapedView(t *testing.T) {
	t.Run("JSON — une seule couche, \\uXXXX et \\/", func(t *testing.T) {
		json := viewWith(t, mustViews(t, []byte(`a\u005fb\/c\\u0041`)).transformed, EncodingJSONEscaped)
		// Comme Secret Guard, un antislash échappé n'empêche pas le décodage de l'échappement qui le suit.
		if string(json.text) != `a_b/c\A` {
			t.Fatalf("JSON %q", json.text)
		}
		if spanAt(json, 1, 2) != [2]int{1, 7} || spanAt(json, 3, 4) != [2]int{8, 10} {
			t.Fatal("correspondance")
		}
	})

	t.Run("JSON — paire de substitution décodée en un point de code", func(t *testing.T) {
		json := viewWith(t, mustViews(t, []byte(`x\ud83d\ude00y`)).transformed, EncodingJSONEscaped)
		if string(json.text) != "x\U0001F600y" || len(json.lone) != 0 || spanAt(json, 1, 5) != [2]int{1, 13} {
			t.Fatalf("JSON %q", json.text)
		}
	})

	t.Run("JSON — substitut isolé écrit U+FFFD, recombiné si une vue dérivée le rend adjacent à son pendant", func(t *testing.T) {
		views := mustViews(t, []byte(`\ud83d\ude01x\ud83d\u200b\ude00`))
		var json *view
		for _, v := range views.transformed {
			json = v
		}
		// Vue JSON canonicalisée : U+200B retiré, les deux substituts isolés deviennent adjacents et forment U+1F600,
		// comme dans la chaîne JavaScript de Secret Guard.
		if string(json.text) != "\U0001F601x\U0001F600" || len(json.lone) != 0 {
			t.Fatalf("JSON %q (%d isolés)", json.text, len(json.lone))
		}
		if spanAt(json, 5, 9) != [2]int{13, 31} {
			t.Fatalf("correspondance %v", spanAt(json, 5, 9))
		}
		raw, err := jsonEscapedView(identityView([]byte(`\ud83d\u200b\ude00`)), newViewBudget())
		if err != nil || string(raw.text) != "\uFFFD\u200B\uFFFD" || len(raw.lone) != 2 {
			t.Fatalf("vue JSON brute %q", raw.text)
		}
	})

	t.Run("JSON — un substitut bas avant un haut, ou séparé par un caractère, reste isolé", func(t *testing.T) {
		for _, input := range []string{`\ude00\ud83d`, `\ud83dA\ude00`, `\ud83d\ud83d`} {
			json := viewWith(t, mustViews(t, []byte(input)).transformed, EncodingJSONEscaped)
			if !bytes.Contains(json.text, replacement) || len(json.lone) < 2 {
				t.Fatalf("%s → %q", input, json.text)
			}
		}
	})
}

func TestTransformedViews(t *testing.T) {
	t.Run("pourcentage puis JSON, et JSON puis pourcentage, une couche chacun", func(t *testing.T) {
		views := mustViews(t, []byte(`%5Cu0041 \u0025\u0034\u0031`))
		var got []string
		for _, v := range views.transformed {
			got = append(got, string(v.encoding)+"="+string(v.text))
		}
		want := []string{
			`percent=\u0041 \u0025\u0034\u0031`,
			`json-escaped=A %41`,
			`json-escaped=%5Cu0041 %41`,
			`percent=\u0041 A`,
		}
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Fatalf("vues %q", got)
		}
		last := views.transformed[3]
		if spanAt(last, len(last.text)-1, len(last.text)) != [2]int{9, 27} {
			t.Fatal("correspondance à travers deux couches")
		}
	})

	t.Run("une vue transformée est canonicalisée (NFKC) sans perdre son encodage", func(t *testing.T) {
		views := mustViews(t, []byte("%EF%BD%87hp"))
		percent := viewWith(t, views.transformed, EncodingPercent)
		if string(percent.text) != "ghp" || spanAt(percent, 0, 1) != [2]int{0, 9} {
			t.Fatalf("pourcentage %q", percent.text)
		}
	})
}

func TestJoinedLineView(t *testing.T) {
	t.Run("lignes jointes — saut de ligne et jusqu'à quatre espaces ou tabulations retirés", func(t *testing.T) {
		joined, err := joinedLineView(identityView([]byte("ab\n    cd\r\n\t\t\t\t\tef\rg")), newViewBudget())
		if err != nil || string(joined.text) != "abcd\tefg" || joined.encoding != EncodingWhitespaceJoined {
			t.Fatalf("jointe %q", joined.text)
		}
		if spanAt(joined, 2, 3) != [2]int{7, 8} || spanAt(joined, 4, 5) != [2]int{15, 16} {
			t.Fatal("correspondance")
		}
	})

	t.Run("lignes jointes — absente sans CR ni LF", func(t *testing.T) {
		if joined, err := joinedLineView(identityView([]byte("abc")), newViewBudget()); err != nil || joined != nil {
			t.Fatal("vue inutile")
		}
	})

	t.Run("fenêtre de jeton fixe coupé par un retour à la ligne", func(t *testing.T) {
		body := strings.Repeat("aB3", 12)
		content := []byte("token g\n    hp_" + body + "\n! suite")
		windows, err := lineWrappedFixedViews(identityView(content), &windowBudget{}, newViewBudget())
		if err != nil || len(windows) != 1 {
			t.Fatalf("fenêtres %d (%v)", len(windows), err)
		}
		if string(windows[0].text) != "ghp_"+body || spanOf(windows[0]) != [2]int{6, 15 + len(body)} {
			t.Fatalf("fenêtre %q %v", windows[0].text, spanOf(windows[0]))
		}
	})

	t.Run("fenêtre de jeton fixe — préfixe précédé d'un caractère de mot ignoré, préfixe sans saut ignoré", func(t *testing.T) {
		for _, content := range []string{"xg\nhp_" + strings.Repeat("a", 40), "ghp_" + strings.Repeat("a", 40) + "\n"} {
			windows, err := lineWrappedFixedViews(identityView([]byte(content)), &windowBudget{}, newViewBudget())
			if err != nil || len(windows) != 0 {
				t.Fatalf("%q : %d fenêtres", content, len(windows))
			}
		}
	})

	t.Run("fenêtre base64 coupée par un retour à la ligne, prolongée jusqu'au remplissage", func(t *testing.T) {
		content := []byte("x QUJDREVGR0hJ\n  SktMTU5PUFFS\nU1RVVg==\nfin")
		windows, err := lineWrappedBase64Views(identityView(content), &windowBudget{}, newViewBudget())
		if err != nil || len(windows) != 1 || string(windows[0].text) != "QUJDREVGR0hJSktMTU5PUFFSU1RVVg==" {
			t.Fatalf("fenêtres %d (%v)", len(windows), err)
		}
		if spanOf(windows[0]) != [2]int{2, 38} {
			t.Fatalf("correspondance %v", spanOf(windows[0]))
		}
	})

	t.Run("au-delà de 128 fenêtres de lignes jointes, l'analyse est incomplète", func(t *testing.T) {
		line := "g\nhp_" + strings.Repeat("aB3", 12)
		windows := &windowBudget{}
		content := []byte(strings.Repeat(line+"\n!", 128))
		if _, err := lineWrappedFixedViews(identityView(content), windows, newViewBudget()); err != nil || windows.windows != 128 {
			t.Fatalf("128 fenêtres : %v (%d)", err, windows.windows)
		}
		_, err := lineWrappedBase64Views(identityView([]byte("QUJDREVGR0hJ\nSktMTU5PUFFS")), windows, newViewBudget())
		if !errors.Is(err, errJoinedWindowBudgetExhausted) {
			t.Fatalf("129e fenêtre : %v", err)
		}
	})
}

func TestViewBudget(t *testing.T) {
	t.Run("une vue au-delà du budget de vues rend l'analyse incomplète", func(t *testing.T) {
		// U+FDFA se normalise en 18 caractères (33 octets).
		if _, err := buildTextViews([]byte("\uFDFA"), &viewBudget{remaining: 32}); !errors.Is(err, errViewBudgetExhausted) {
			t.Fatalf("normalisée : %v", err)
		}
		if _, err := buildTextViews([]byte("\uFDFA"), &viewBudget{remaining: 33}); err != nil {
			t.Fatalf("dans le budget : %v", err)
		}
		budget := &viewBudget{remaining: 4}
		for _, build := range []func(*view, *viewBudget) (*view, error){percentDecodedView, jsonEscapedView, joinedLineView} {
			if _, err := build(identityView([]byte("%41\\u0041\n%41\\/x")), budget); !errors.Is(err, errViewBudgetExhausted) {
				t.Fatalf("budget dépassé : %v", err)
			}
		}
		if _, err := buildTextViews(make([]byte, maxViewBytes+1), newViewBudget()); !errors.Is(err, errViewBudgetExhausted) {
			t.Fatal("entrée au-delà du budget de vues")
		}
	})

	t.Run("le budget de vues est partagé et débité des seules vues gardées", func(t *testing.T) {
		budget := newViewBudget()
		views, err := buildTextViews([]byte("a\u200Bb %41"), budget)
		if err != nil {
			t.Fatal(err)
		}
		used := len(views.normalized.text)
		for _, v := range views.transformed {
			used += len(v.text)
		}
		if budget.remaining != maxViewBytes-used {
			t.Fatalf("budget %d, attendu %d", budget.remaining, maxViewBytes-used)
		}
	})
}

func TestOriginalBounds(t *testing.T) {
	t.Run("correspondance — étendue vide et index hors vue comme Secret Guard", func(t *testing.T) {
		v := mustViews(t, []byte("a\u200Bbc")).normalized
		cases := []struct {
			start, end int
			want       [2]int
		}{
			{1, 1, [2]int{4, 4}},
			{3, 3, [2]int{6, 6}},
			{9, 9, [2]int{0, 0}},
			{-1, 1, [2]int{0, 1}},
			{0, 9, [2]int{0, 3}},
		}
		for _, c := range cases {
			if got := spanAt(v, c.start, c.end); got != c.want {
				t.Fatalf("[%d, %d) → %v, attendu %v", c.start, c.end, got, c.want)
			}
		}
		if spanAt(identityView([]byte("abc")), 1, 2) != [2]int{1, 2} {
			t.Fatal("identité")
		}
	})
}

func TestReviewFixes(t *testing.T) {
	t.Run("pourcentage — « %EF%BB%BF » ne laisse rien, comme TextDecoder (CRLF reformé puis normalisé)", func(t *testing.T) {
		cases := map[string]string{"a\r%EF%BB%BF\nb": "a\nb", "x\r%EF%BB%BF%0Ay": "x\ny", "%EF%BB%BF%41": "A"}
		for input, want := range cases {
			percent := viewWith(t, mustViews(t, []byte(input)).transformed, EncodingPercent)
			if string(percent.text) != want {
				t.Fatalf("%q → %q, attendu %q", input, percent.text, want)
			}
		}
		percent := viewWith(t, mustViews(t, []byte("%EF%BB%BF%41")).transformed, EncodingPercent)
		if spanOf(percent) != [2]int{9, 12} {
			t.Fatalf("correspondance %v", spanOf(percent))
		}
	})

	t.Run("une vue que Secret Guard n'aurait pas (rien à décoder ni à normaliser) ne consomme aucun budget", func(t *testing.T) {
		budget := &viewBudget{remaining: 4}
		views, err := buildTextViews([]byte("%FF %C0%AF d\xc3\xa9j\xc3\xa0 \\x \xff"), budget)
		if err != nil || views.normalized != nil || len(views.transformed) != 0 || budget.remaining != 4 {
			t.Fatalf("%v, budget %d", err, budget.remaining)
		}
	})

	t.Run("une vue gardée est à sa taille exacte (mémoire comptée par le budget)", func(t *testing.T) {
		views := mustViews(t, []byte("a\xe2\x80\x8bb %41 "+strings.Repeat("\xef\xb7\xba", 50)))
		for _, v := range append([]*view{views.normalized}, views.transformed...) {
			if cap(v.text) != len(v.text) || cap(v.starts) != len(v.text) || cap(v.ends) != len(v.text) {
				t.Fatalf("%s : capacité %d pour %d octets", v.encoding, cap(v.text), len(v.text))
			}
		}
	})

	t.Run("fenêtres de lignes jointes bornées à 16 384 caractères et seuil de huit caractères (comme Secret Guard)", func(t *testing.T) {
		fixed, err := lineWrappedFixedViews(identityView([]byte("g\nhp_"+strings.Repeat("a", 20000)+"\n")), &windowBudget{}, newViewBudget())
		if err != nil || len(fixed) != 1 || len(fixed[0].text) != maxJoinedCandidateCharacters || spanOf(fixed[0]) != [2]int{0, 16385} {
			t.Fatalf("jeton fixe : %v", err)
		}
		cases := []struct {
			text string
			want [][3]int // longueur, début, fin dans la source
		}{
			{"x " + strings.Repeat("A", 20000) + "\n" + strings.Repeat("B", 20000) + " ", nil},
			{"x " + strings.Repeat("A", 10000) + "\n" + strings.Repeat("B", 10000) + "\n" + strings.Repeat("C", 100) + "==", [][3]int{{16384, 2, 16387}, {10102, 10003, 20106}}},
			{"x AAAAAAA\nBBBBBBBB ", nil},
			{"x AAAAAAAA\nBBBBBBBB ", [][3]int{{16, 2, 19}}},
			{"x AAAAAAAA\nBBBBBBB ", nil},
		}
		for _, c := range cases {
			windows, err := lineWrappedBase64Views(identityView([]byte(c.text)), &windowBudget{}, newViewBudget())
			if err != nil || len(windows) != len(c.want) {
				t.Fatalf("%.20q… : %d fenêtres (%v), attendu %d", c.text, len(windows), err, len(c.want))
			}
			for i, w := range windows {
				if got := [3]int{len(w.text), spanOf(w)[0], spanOf(w)[1]}; got != c.want[i] {
					t.Fatalf("%.20q… fenêtre %d : %v, attendu %v", c.text, i, got, c.want[i])
				}
			}
		}
	})
}
