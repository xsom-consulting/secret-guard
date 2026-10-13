package custom

// Pires cas : analyses de 1 Mio bornées en temps, achevées ou arrêtées par le budget (ErrWorkBudget) ou la limite de
// détections (ErrTooManyMatches), jamais un résultat partiel. La borne de temps est large (machines de CI) ; les
// durées mesurées sont écrites au journal du test.

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	worstCaseBytes = 1 << 20
	worstCaseLimit = 20 * time.Second
)

// largestPack rend le plus grand Pack du contrat (200 détecteurs, 20 000 condensats), repris des tests d'origine.
func largestPack(t *testing.T) *Pack {
	t.Helper()
	for _, c := range readCases[packCase](t, "packs.json") {
		data := decodeVectorInput(t, c.Pack, c.PackEncoding)
		if !bytes.Contains(data, []byte(`"packId":"benchmark-largest"`)) || !c.Expected.Valid {
			continue
		}
		p, err := Compile(data)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Detectors()) != 200 {
			t.Fatalf("%d détecteurs", len(p.Detectors()))
		}
		return p
	}
	t.Fatal("plus grand Pack absent des vecteurs")
	return nil
}

func fill(unit string) []byte {
	return []byte(strings.Repeat(unit, worstCaseBytes/len(unit)+1)[:worstCaseBytes])
}

// pseudoRandomASCII rend des octets ASCII imprimables tirés d'un générateur congruentiel (déterministe).
func pseudoRandomASCII(size int) []byte {
	out := make([]byte, size)
	state := uint32(0x5eed)
	for i := range out {
		state = state*1664525 + 1013904223
		out[i] = byte(0x20 + (state>>24)%95)
	}
	return out
}

func distinctWordsText(size int) []byte {
	var b strings.Builder
	for i := 0; b.Len() < size; i++ {
		b.WriteString("m" + strconv.FormatInt(int64(i), 36) + " ")
	}
	return []byte(b.String()[:size])
}

func patternPack(t *testing.T, pattern string, context string) *Pack {
	t.Helper()
	p := &Pack{}
	spec := detectorSpec{Detector: Detector{ID: "p", Label: "p", Category: "project", Action: ActionWarn}, pattern: pattern, minEntropyTenths: -1}
	if context != "" {
		spec.context = &contextSpec{keywords: []string{context}, window: 256}
	}
	d := compileDetector(spec)
	if d == nil {
		t.Fatalf("motif refusé : %s", pattern)
	}
	p.detectors = []*detector{d}
	return p
}

func runWorstCase(t *testing.T, p *Pack, content []byte) {
	t.Helper()
	start := time.Now()
	matches, err := p.Analyze(content, nil, 2048)
	elapsed := time.Since(start)
	if err != nil && (!errors.Is(err, ErrWorkBudget) && !errors.Is(err, ErrTooManyMatches) || matches != nil) {
		t.Fatalf("%v, %d détections", err, len(matches))
	}
	issue := "complète"
	if err != nil {
		issue = err.Error()
	}
	t.Logf("%s : %s, %d détections", elapsed.Round(time.Millisecond), issue, len(matches))
	if elapsed > worstCaseLimit {
		t.Fatalf("%s au-delà de %s", elapsed, worstCaseLimit)
	}
}

func TestWorstCases(t *testing.T) {
	if testing.Short() {
		t.Skip("pires cas : sans -short")
	}
	largest := largestPack(t)
	for name, content := range map[string][]byte{
		"plus grand Pack, ancres denses":          fill("CLI0-0042133 "),
		"plus grand Pack, chiffres":               fill("0123456789"),
		"plus grand Pack, mots-clés et chiffres":  fill("siret2 55210055400013 "),
		"plus grand Pack, mots distincts":         distinctWordsText(worstCaseBytes),
		"plus grand Pack, ASCII pseudo-aléatoire": pseudoRandomASCII(worstCaseBytes),
		"plus grand Pack, invisibles":             fill("a\u200b"),
	} {
		t.Run(name, func(t *testing.T) { runWorstCase(t, largest, content) })
	}
	t.Run("motif pathologique pour un automate à retour arrière", func(t *testing.T) {
		runWorstCase(t, patternPack(t, "aaa"+strings.Repeat("[a-z]{0,8}", 20)+"z", ""), fill("a"))
		runWorstCase(t, patternPack(t, "ACME"+strings.Repeat("[a-z]{0,8}", 20)+"Z", ""), append([]byte("ACME"), fill("a")[4:]...))
	})
	t.Run("plus grand programme RE2 : alternatives et classes longues, sans ancre, mot-clé présent", func(t *testing.T) {
		pattern := "(?:a[a-z]{2,64}|b[a-z]{2,64}|c[a-z]{2,64}|d[a-z]{2,64}|e[a-z]{2,64}|f[a-z]{2,64}|g[a-z]{2,64}|h[a-z]{2,64}|i[a-z]{2,64}|j[a-z]{2,64}|k[a-z]{2,64}|l[a-z]{2,64}|m[a-z]{2,64}|n[a-z]{2,64}|o[a-z]{2,64})"
		runWorstCase(t, patternPack(t, pattern, "motcle"), append([]byte("motcle "), fill("abcdefghijklmno")[7:]...))
	})
}
