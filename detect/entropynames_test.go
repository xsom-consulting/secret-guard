// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestIsEntropyName(t *testing.T) {
	for value, want := range map[string]bool{
		"SubscriptionOverviewLinesElemVerificationsElem":          true,
		"AdminLogPageEntriesElem_ActorKindUser":                   true,
		"LICENSE-PolyForm-Small-Business-1":                       true,
		"claude/worktrees/agent-a3f9c2e1b7d40568e/agent":          true,
		"exemple-fleet-4e7b19a0c2d5/9b31f04e6c87d2a5e01f/step-01": true,
		"USERPROFILE/Downloads/Install-VSCode-1":                  false, // sigle dans un mot : cas de l'origine
		"deadbeef-0123456789abcdef01234567":                       false, // hexadécimal coupé : aucun mot de nom
		"0123456789abcdef0123456789abcdef01":                      false, // hexadécimal seul
		"secrets/0123456789abcdef0123456789abcdef":                false, // hexadécimal de 32 : trop long
		"cp-out/Zq8Lr2Vx9Mn4Kp7Tw3Yb6Hc1Jd5":                      false,
		"aGVsbG8gd29ybGQgaGVsbG8gd29ybGQ":                         false,
		"PolyForm+Small":                                          false,
		// Identifiants générés longs (isGeneratedIdentifier), seuls ou dans un nom à soulignés.
		"JobFamilySubscriptionTemplateSetRequestItemsElemAiServiceMistralLeChat": true,
		"TestFR16LoopbackListenerIsExclusive":                                    true,
		"UsageBatchRecordsElemSizeBucketA2K":                                     true,
		"enumValues_SubscriptionFlowListFlowsElemOfferId":                        true,
	} {
		if got := isEntropyName([]byte(value)); got != want {
			t.Errorf("isEntropyName(%q) = %v, attendu %v", value, got, want)
		}
	}
}

func TestGeneratedWords(t *testing.T) {
	for _, c := range []struct {
		word                        string
		regular, irregular, letters int
		ok                          bool
	}{
		{"SubscriptionOverviewLinesElem", 4, 0, 29, true},
		{"jobFamilyAiService", 3, 1, 16, true},       // « job » en tête, bosse courte « Ai »
		{"idTokenClaims", 2, 1, 11, true},            // deux minuscules en tête : morceau irrégulier
		{"TestFR16Loopback", 2, 1, 12, true},         // sigle et ses chiffres : un seul morceau
		{"ElemAlgEd25519", 2, 1, 7, true},            // bosse courte et ses chiffres
		{"ElemSha256Sum", 3, 1, 10, true},            // chiffres après un mot régulier : un morceau
		{"SizeBucketA2K", 2, 1, 10, true},            // « A2K » : majuscule finale du même morceau
		{"ClaudeMax20X", 2, 1, 9, true},              // « 20X » après un mot régulier
		{"CurrencyEUR", 1, 1, 8, true},               // sigle final
		{"HTTPSClientID", 1, 2, 6, true},             // sigle, mot, sigle
		{"PlanBService", 2, 1, 11, true},             // majuscule seule devant un mot
		{"xToken", 0, 0, 0, false},                   // minuscule isolée en tête
		{"9Lives", 0, 0, 0, false},                   // chiffre en tête
		{"ABCDEFGElem", 0, 0, 0, false},              // sigle de plus de 5 majuscules
		{"Elem123456Sum", 0, 0, 0, false},            // plus de 5 chiffres
		{"Sha2X56Sum", 2, 2, 6, true},                // « Sha », « 2 », « X56 », « Sum »
		{"Elem-Sum", 0, 0, 0, false},                 // caractère hors lettres et chiffres
		{"", 0, 0, 0, false},                         // vide
		{"aB3xK9LmQ2pR7sT1", 0, 0, 0, false},         // jeton : minuscule isolée en tête
		{"Ab3xK9LmQ2pR7sT1", 0, 0, 0, false},         // jeton : minuscule où une majuscule est attendue
		{"Usage2Batch3Records4Elem", 4, 3, 21, true}, // chiffres après chaque mot : autant de morceaux
	} {
		regular, irregular, letters, ok := generatedWords([]byte(c.word))
		if ok != c.ok || ok && (regular != c.regular || irregular != c.irregular || letters != c.letters) {
			t.Errorf("generatedWords(%q) = %d, %d, %d, %v ; attendu %d, %d, %d, %v", c.word, regular, irregular, letters, ok,
				c.regular, c.irregular, c.letters, c.ok)
		}
	}
}

func TestIsGeneratedIdentifier(t *testing.T) {
	for word, want := range map[string]bool{
		// Les trois identifiants relevés sur un Poste réel (15 novembre 2026).
		"JobFamilySubscriptionTemplateSetRequestItemsElemAiServiceMistralLeChat": true, // 11 mots, 2 morceaux
		"TestFR16LoopbackListenerIsExclusive":                                    true, // 4 mots de 7 lettres, 2 morceaux
		"UsageBatchRecordsElemSizeBucketA2K":                                     true, // 6 mots de 5 lettres, 1 morceau
		// Noms de types générés : sigle final, chiffres, bosses courtes.
		"SubscriptionOverviewTotalsElemCurrencyEUR":     true,
		"InstallProfileTrustPolicyKeysElemAlgEd25519":   true,
		"SubscriptionFlowCreateRequestOfferIdChatgptGo": true,
		"AdminLogPageEntriesElemObjectTypeAiUseCase":    true, // 9 mots de 4 lettres en moyenne, 1 morceau
		"IpcFrameUsageBatchRecordsElemSizeBucketA256K":  true, // 8 mots, 1 morceau
		// Trop peu de mots réguliers, ou trop de morceaux irréguliers pour leur longueur.
		"TestFR13HookIPCNearDeadline": false, // 4 mots de 5 lettres, 2 morceaux
		"GetHTTPSClientIDForURL":      false, // 3 mots
		"AbcDefGhiJkl":                false, // 4 mots de 3 lettres
		"AbcDefGhiJklMnoPqrStu":       false, // 7 mots de 3 lettres
		"AbcdeFghijKlmnoPqrstX9Y8Z7":  false, // 4 mots de 5 lettres, 3 morceaux
		// Sans morceau irrégulier, le mot est déjà un mot de nom (nameTokenLetters) ; il a aussi cette forme.
		"SubscriptionOverviewLinesElemVerificationsElem": true,
	} {
		if got := isGeneratedIdentifier([]byte(word)); got != want {
			t.Errorf("isGeneratedIdentifier(%q) = %v, attendu %v", word, got, want)
		}
	}
}

// TestEntropyNameRarelyMatchesTokens : une suite aléatoire (jeton alphanumérique, base64, base64url) n'a presque
// jamais la forme d'un nom ; un tel jeton garde son constat d'entropie.
func TestEntropyNameRarelyMatchesTokens(t *testing.T) {
	// 500 000 tirages de trois suites par longueur : assez pour que la borne ne dépende pas du tirage (le taux mesuré
	// sur 10 millions de jetons alphanumériques est de 1,4 pour 10 000 à 20 caractères, 3 pour un million à 32, et
	// aucun à 48 : entropynames.go).
	const samples = 500_000
	for _, n := range []int{20, 32, 48} {
		matched := 0
		for i := 0; i < samples; i++ {
			if isEntropyName([]byte(randomToken(t, n))) {
				matched++
			}
			raw := make([]byte, n*3/4)
			if _, err := rand.Read(raw); err != nil {
				t.Fatal(err)
			}
			for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
				if isEntropyName([]byte(encoding.EncodeToString(raw))) {
					matched++
				}
			}
		}
		t.Logf("%d caractères : %d suites aléatoires sur %d ont la forme d'un nom", n, matched, 3*samples)
		// Au plus 1 pour 1 000 à 20 caractères, 1 pour 100 000 à 32, 1 pour un million à 48.
		if limit := map[int]int{20: 3 * samples / 1000, 32: 3 * samples / 100_000, 48: 3 * samples / 1_000_000}[n]; matched > limit {
			t.Fatalf("%d caractères : %d suites aléatoires sur %d ont la forme d'un nom", n, matched, 3*samples)
		}
	}
}

// TestEntropyNameRarelyMatchesLetters : une suite aléatoire de lettres seules en casse mêlée (un jeton sans aucun
// chiffre) a plus souvent la forme d'un nom qu'un jeton alphanumérique, surtout depuis isGeneratedIdentifier. La
// perte est bornée : 2 pour 1 000 à 24 caractères, 1 pour 1 000 à 32, 40 et 48 (taux mesurés sur 5 millions de
// suites : 1,1 pour 1 000 à 24 caractères, 3 pour 10 000 à 32 et à 40, 1,4 pour 10 000 à 48 : entropynames.go).
func TestEntropyNameRarelyMatchesLetters(t *testing.T) {
	const samples = 200_000
	for _, n := range []int{24, 32, 40, 48} {
		matched := 0
		for i := 0; i < samples; i++ {
			if isEntropyName([]byte(uniformLetters(t, n))) {
				matched++
			}
		}
		t.Logf("%d lettres : %d suites aléatoires sur %d ont la forme d'un nom", n, matched, samples)
		limit := samples / 1000
		if n == 24 {
			limit = 2 * samples / 1000
		}
		if matched > limit {
			t.Fatalf("%d lettres : %d suites aléatoires sur %d ont la forme d'un nom, %d au plus", n, matched, samples, limit)
		}
		// La borne mesure bien quelque chose : la forme n'est pas inatteignable pour une suite de lettres.
		if n <= 40 && matched == 0 {
			t.Fatalf("%d lettres : aucune suite sur %d n'a la forme d'un nom, mesure à revoir", n, samples)
		}
	}
}

func TestEntropyIgnoresNames(t *testing.T) {
	rules := loadInitialRules(t)
	for name, content := range map[string]string{
		"type généré":                    "type SubscriptionOverviewLinesElemVerificationsElem struct {",
		"nom de fichier de licence":      "cp expurgation/LICENSE-PolyForm-Small-Business-1.0.0 deploy/licenses/",
		"dossier d'un agent de worktree": ".claude/worktrees/agent-a3f9c2e1b7d40568e/agent/internal/domain/hook/tool.go",
		"identifiant de clé d'API":       "apikey_01Xk7Pq2Rm9Tz4Lw8Nb3Vc6H",
		// Identifiants générés longs (15 novembre 2026).
		"constante générée à bosses courtes": "const JobFamilySubscriptionTemplateSetRequestItemsElemAiServiceMistralLeChat JobFamily = \"x\"",
		"nom d'essai à sigle et chiffres":    "func TestFR16LoopbackListenerIsExclusive(t *testing.T) {",
		"constante générée à suffixe A2K":    "const UsageBatchRecordsElemSizeBucketA2K UsageBatch = 1",
		"constante générée à sigle final":    "const SubscriptionOverviewLinesElemVerificationsElemCurrencyEUR Currency = \"EUR\"",
		"table générée à souligné":           "var enumValues_SubscriptionOverviewLinesElemReplacementTargetOfferId = []interface{}{",
	} {
		if n := entropyFindings(t, rules, content); n != 0 {
			t.Errorf("%s : %d constat(s) d'entropie", name, n)
		}
	}
}

func TestEntropyKeepsTokensBesideNames(t *testing.T) {
	rules := loadInitialRules(t)
	for i := 0; i < 20; i++ {
		token := randomToken(t, 40)
		hex := strings.Repeat("0123456789abcdef", 3)[:40]
		for name, content := range map[string]string{
			"jeton dans un chemin de worktree":           ".claude/worktrees/agent-" + token + "/agent",
			"jeton après un nom de licence":              "LICENSE-PolyForm-" + token,
			"jeton préfixé comme un identifiant d'objet": "apikey_01" + token,
			"hexadécimal de 40 dans un chemin":           "secrets/" + hex + "/" + token,
			"jeton après un identifiant généré":          "SubscriptionOverviewLinesElemCurrencyEUR_" + token,
			"jeton devant un identifiant généré":         token + "_TestFR16LoopbackListenerIsExclusive",
		} {
			if n := entropyFindings(t, rules, content); n == 0 {
				t.Fatalf("%s : jeton non détecté", name)
			}
		}
	}
}

func TestIsProviderObjectID(t *testing.T) {
	id := "apikey_01" + strings.Repeat("Xk7Pq2Rm9T", 3)[:22]
	for _, c := range []struct {
		text  string
		start int
		want  bool
	}{
		{id, 0, true},
		{"id: " + id, 4, true},
		{"x" + id, 1, false},   // fin d'un mot plus long
		{"_" + id, 1, false},   // suite d'entropie coupée
		{id + "Zz9", 0, false}, // 25 caractères après « 01 »
		{"apikey_02" + id[9:], 0, false},
		{"sk_live_01" + id[9:], 0, false},
	} {
		value := []byte(c.text[c.start:])
		if got := isProviderObjectID([]byte(c.text), c.start, value); got != c.want {
			t.Errorf("isProviderObjectID(%q) = %v, attendu %v", c.text, got, c.want)
		}
	}
}

func TestComparisonIsNotAssignment(t *testing.T) {
	rules := loadInitialRules(t)
	count := func(content, language string) int {
		result := Scan([]byte(content), rules, Options{LanguageID: language})
		if !result.Complete {
			t.Fatalf("analyse incomplète : %v", result.Failure)
		}
		return len(result.Findings)
	}
	for _, content := range []string{"token === undefined", "token==undefined", "apiKey == null", "token === expectedToken", "x && secret === undefined"} {
		for _, language := range []string{"", "typescript"} {
			if n := count(content, language); n != 0 {
				t.Errorf("comparaison %q (%q) : %d constat(s)", content, language, n)
			}
		}
	}
	// Une valeur littérale comparée, ou collée à l'opérateur, reste détectée.
	for i := 0; i < 10; i++ {
		token := randomToken(t, 32)
		for _, content := range []string{"token === \"" + token + "\"", "TOKEN==" + token, "if (x && token == '" + token + "')"} {
			if count(content, "") == 0 {
				t.Fatalf("littéral comparé non détecté")
			}
		}
	}
}

func TestAfterComparison(t *testing.T) {
	for _, c := range []struct {
		text       string
		end, want  int
		comparison bool
	}{
		{"t ===x", 3, 5, true},
		{"t ==x", 3, 4, true},
		{"t ====x", 3, 5, true},
		{"t =x", 3, 3, false},
		{"t := =x", 5, 5, false},
		{"t :==x", 4, 4, false},
		{"t =", 3, 3, false},
	} {
		got, comparison := afterComparison([]byte(c.text), 0, c.end)
		if got != c.want || comparison != c.comparison {
			t.Errorf("afterComparison(%q, %d) = %d, %v ; attendu %d, %v", c.text, c.end, got, comparison, c.want, c.comparison)
		}
	}
}
