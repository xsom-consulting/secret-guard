// SPDX-License-Identifier: PolyForm-Small-Business-1.0.0

package expurgation

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xsom-consulting/secret-guard/detect"
)

// TestProviderRuleExpurgation : la valeur trouvée par une règle de fournisseur (v0.8.1) est remplacée par un Substitut
// qui nomme le fournisseur, le texte autour est gardé et le texte expurgé est relu sans constat. Valeurs assemblées à
// l'exécution, jamais relevées.
func TestProviderRuleExpurgation(t *testing.T) {
	rules := loadInitialRules(t)
	hex := strings.Repeat("0a1b2c3d", 4)
	for _, c := range []struct{ name, before, value, after, label string }{
		// Clé hexadécimale sans préfixe : invisible pour l'entropie, trouvée par le nom du fournisseur.
		{"clé d'API Datadog dans un fichier .env", "DD_API" + "_KEY=", hex, "\nDD_SITE=datadoghq.eu\n", "clé d’API Datadog"},
		{"jeton Docker Hub dans une commande", "docker login -p ", "dckr" + "_pat_" + "Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1", " registry.example.test", "jeton d’accès personnel Docker Hub"},
		{"clé d'API Linear dans une phrase", "voici ma clé Linear : ", "lin" + "_api_" + strings.Repeat("a1B2c3D4", 5), ", merci", "clé d’API Linear"},
	} {
		t.Run(c.name, func(t *testing.T) {
			input := c.before + c.value + c.after
			text, subs, sanitized := expurgateBoth(t, []byte(input), rules, nil, Options{}, func() func(detect.Finding) (int, bool) { return fixedOrdinal(1) })
			if sanitized.Failure != detect.SanitizeNone || bytes.Contains(text, []byte(c.value)) || len(subs) != 1 {
				t.Fatalf("expurgation : %s, %d Substituts", sanitized.Failure, len(subs))
			}
			want := "[secret masqué par xSOM n°1 : " + c.label + ", pas la vraie valeur]"
			if !strings.Contains(string(text), want) || !strings.HasSuffix(string(text), c.after) {
				t.Fatalf("texte expurgé %q, Substitut attendu %q", text, want)
			}
		})
	}
}
