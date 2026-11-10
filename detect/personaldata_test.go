// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// Numéros de ces essais : calculés (clé de contrôle recalculée), jamais ceux d'une personne. L'IBAN et les cartes sont
// les exemples publics des documentations bancaires et des réseaux.

// luhnDigit rend le chiffre de contrôle de Luhn à ajouter à prefix.
func luhnDigit(prefix string) string {
	for c := 0; c < 10; c++ {
		if luhn([]byte(prefix + strconv.Itoa(c))) {
			return strconv.Itoa(c)
		}
	}
	return ""
}

// ibanFor calcule l'IBAN du pays dont le BBAN est donné (chiffres de contrôle de l'ISO 13616).
func ibanFor(country, bban string) string {
	remainder := 0
	for _, c := range []byte(bban + country + "00") {
		if c >= '0' && c <= '9' {
			remainder = (remainder*10 + int(c-'0')) % 97
		} else {
			remainder = (remainder*100 + int(c-'A') + 10) % 97
		}
	}
	return fmt.Sprintf("%s%02d%s", country, 98-remainder, bban)
}

// spaced écrit une suite par groupes de quatre caractères.
func spaced(value string) string {
	var groups []string
	for len(value) > 4 {
		groups, value = append(groups, value[:4]), value[4:]
	}
	return strings.Join(append(groups, value), " ")
}

// nirFor rend le NIR dont body (13 caractères) reçoit sa clé ; 2A et 2B comptent pour 19 et 18.
func nirFor(body string) string {
	number := strings.NewReplacer("2A", "19", "2B", "18").Replace(body)
	value, _ := strconv.ParseInt(number, 10, 64)
	return fmt.Sprintf("%s%02d", body, 97-value%97)
}

func TestPersonalDataValidators(t *testing.T) {
	siren8 := "12345678"
	siren := siren8 + luhnDigit(siren8)
	siret13 := siren + "0001"
	siret := siret13 + luhnDigit(siret13)
	// La Poste : SIREN 356000000, somme des chiffres multiple de 5, clé de Luhn invalide.
	postSiret := "35600000000001"
	cases := []struct {
		name      string
		validator string
		value     string
		want      bool
	}{
		{"IBAN français d'exemple", validatorIBAN, "FR76 3000 6000 0112 3456 7890 189", true},
		{"IBAN d'exemple britannique", validatorIBAN, "GB82WEST12345698765432", true},
		{"IBAN d'exemple allemand en minuscules", validatorIBAN, "de89 3704 0044 0532 0130 00", true},
		{"IBAN d'exemple néerlandais", validatorIBAN, "NL91ABNA0417164300", true},
		{"IBAN dont la clé est fausse", validatorIBAN, "FR76 3000 6000 0112 3456 7890 188", false},
		{"IBAN français trop court", validatorIBAN, "FR76 3000 6000 0112 3456 7890 18", false},
		{"IBAN dont les chiffres de contrôle sont 00", validatorIBAN, ibanFor("FR", "30006000011234567890189")[:2] + "00" + "30006000011234567890189", false},
		{"IBAN trop long (35 caractères)", validatorIBAN, "BR" + strings.Repeat("1", 33), false},
		{"IBAN avec une ponctuation", validatorIBAN, "FR76-3000-6000-0112-3456-7890-189", false},
		{"IBAN d'un pays hors de la table, 29 caractères", validatorIBAN, ibanFor("BR", "00360305000010009795493C1"), true},
		{"NIR calculé", validatorNIR, nirFor("1841276451089"), true},
		{"NIR en groupes", validatorNIR, "1 84 12 76 451 089 46", true},
		{"NIR de Corse du Sud (2A)", validatorNIR, nirFor("155082A004080"), true},
		{"NIR de Haute-Corse (2B)", validatorNIR, nirFor("255082B004080"), true},
		{"NIR de Corse en minuscules", validatorNIR, strings.ToLower(nirFor("255082B004080")), true},
		{"NIR dont la clé est fausse", validatorNIR, "184127645108947", false},
		{"NIR dont la clé 2A est calculée comme un département 20", validatorNIR, "15508" + "2A" + "004080" + "00", false},
		{"NIR de département 00", validatorNIR, nirFor("1550800004080"), false},
		{"NIR de commune 000", validatorNIR, nirFor("1550844000080"), false},
		{"NIR de numéro d'ordre 000", validatorNIR, nirFor("1550844004000"), false},
		{"NIR de quatorze chiffres", validatorNIR, "18412764510894", false},
		{"SIRET calculé", validatorSiret, siret, true},
		{"SIRET en groupes de trois et cinq", validatorSiret, siret[:3] + " " + siret[3:6] + " " + siret[6:9] + " " + siret[9:], true},
		{"SIRET dont la clé est fausse", validatorSiret, siret[:13] + "9", false},
		{"SIRET de La Poste (somme multiple de 5)", validatorSiret, postSiret, true},
		{"SIRET de La Poste dont la somme n'est pas un multiple de 5", validatorSiret, "35600000000048", false},
		{"SIRET qui se lit AAAAMMJJHHMMSS", validatorSiret, "20261110103000", false},
		{"SIRET de chiffres répétés", validatorSiret, "00000000000000", false},
		{"SIRET de treize chiffres", validatorSiret, siret[:13], false},
		{"SIREN calculé", validatorSiren, siren, true},
		{"SIREN en groupes de trois", validatorSiren, siren[:3] + " " + siren[3:6] + " " + siren[6:], true},
		{"SIREN dont la clé est fausse", validatorSiren, siren[:8] + "0", false},
		{"SIREN de neuf zéros", validatorSiren, "000000000", false},
		{"carte Visa d'essai", validatorCard, "4111111111111111", true},
		{"carte Visa d'essai par groupes", validatorCard, "4111 1111 1111 1111", true},
		{"carte Visa d'essai avec tirets", validatorCard, "4111-1111-1111-1111", true},
		{"carte Mastercard d'essai", validatorCard, "5555555555554444", true},
		{"carte American Express d'essai", validatorCard, "378282246310005", true},
		{"carte American Express d'essai en 4-6-5", validatorCard, "3782 822463 10005", true},
		{"carte Discover d'essai", validatorCard, "6011111111111117", true},
		{"carte JCB d'essai", validatorCard, "3530111333300000", true},
		{"carte Diners d'essai (14 chiffres)", validatorCard, "30569309025904", true},
		{"carte à séparateurs mêlés", validatorCard, "4111 1111-1111 1111", false},
		{"carte dont la clé est fausse", validatorCard, "4111111111111112", false},
		{"carte de réseau inconnu", validatorCard, "9" + strings.Repeat("1", 14) + luhnDigit("9"+strings.Repeat("1", 14)), false},
		{"carte American Express de seize chiffres", validatorCard, "34" + strings.Repeat("1", 13) + luhnDigit("34"+strings.Repeat("1", 13)), false},
		{"Visa de treize chiffres (forme d'un code-barres EAN-13)", validatorCard, "4" + strings.Repeat("1", 11) + luhnDigit("4"+strings.Repeat("1", 11)), false},
		{"carte de chiffres répétés", validatorCard, "0000000000000000", false},
		{"carte avec une lettre", validatorCard, "4111 1111 1111 111a", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			check := validators[c.validator]
			if check == nil {
				t.Fatalf("validateur %s absent", c.validator)
			}
			got, err := check(c.value, &decodeBudget{})
			if err != nil || got != c.want {
				t.Fatalf("%s : %v (erreur %v), attendu %v", c.validator, got, err, c.want)
			}
		})
	}
}

// TestIBANEveryCountry : pour chaque pays de la table, un IBAN calculé est trouvé en entier, écrit par groupes de
// quatre ou d'un bloc, seul, suivi d'un mot ou d'un nombre de quatre caractères, ou suivi d'une ponctuation ; un IBAN
// d'un caractère de trop ne l'est pas.
func TestIBANEveryCountry(t *testing.T) {
	rules := loadInitialRules(t)
	for country, length := range ibanLengths {
		iban := ibanFor(country, strings.Repeat("1", length-4))
		short := ibanFor(country, strings.Repeat("1", length-5))
		for _, form := range []struct {
			name, value string
		}{{"par groupes", spaced(iban)}, {"d'un bloc", iban}} {
			for _, suffix := range []string{"", " pour", " 2026", ".", ", merci", ")"} {
				input := "IBAN " + form.value + suffix
				got := ruleSpans(Scan([]byte(input), rules, Options{}), input, "iban")
				if len(got) != 1 || got[0] != form.value {
					t.Errorf("%s, %s, suffixe %q : %q", country, form.name, suffix, got)
				}
			}
		}
		if got := ruleSpans(Scan([]byte("IBAN "+spaced(short)), rules, Options{}), "IBAN "+spaced(short), "iban"); len(got) != 0 {
			t.Errorf("%s : IBAN trop court trouvé %q", country, got)
		}
	}
}

// ruleSpans rend les textes que les constats de la règle désignent dans input.
func ruleSpans(result Result, input, ruleID string) []string {
	var out []string
	for _, f := range result.Findings {
		if f.RuleID == ruleID {
			out = append(out, input[f.ByteStart:f.ByteEnd])
		}
	}
	return out
}

func TestIBANPrefixLength(t *testing.T) {
	es := spaced(ibanFor("ES", strings.Repeat("2", 20)))
	cases := []struct {
		name, value string
		want        int
	}{
		{"IBAN seul", es, len(es)},
		{"mot de quatre caractères absorbé", es + " pour", len(es)},
		{"groupe de quatre chiffres absorbé", es + " 2026", len(es)},
		{"IBAN d'un bloc suivi d'un mot collé", strings.ReplaceAll(es, " ", "") + "pour", 24},
		{"rien de valide", "AB12 CDEF GHIJ KLMN", 0},
		{"vide", "", 0},
	}
	for _, c := range cases {
		if got := ibanPrefixLength([]byte(c.value)); got != c.want {
			t.Errorf("%s : %d, attendu %d", c.name, got, c.want)
		}
	}
}

// TestPersonalDataScan : un constat par numéro, avec le type, le score et le niveau de sa règle, l'étendue du seul
// numéro (le mot SIREN, un séparateur, la ponctuation voisine n'en font pas partie).
func TestPersonalDataScan(t *testing.T) {
	rules := loadInitialRules(t)
	nir := nirFor("1841276451089")
	siren := "12345678" + luhnDigit("12345678")
	siret := siren + "0001" + luhnDigit(siren+"0001")
	cases := []struct {
		name, input, value, rule, secretType string
		score                                int
		level                                Level
	}{
		{"IBAN", "IBAN : FR76 3000 6000 0112 3456 7890 189.", "FR76 3000 6000 0112 3456 7890 189", "iban", "iban", 45, LevelMedium},
		{"NIR", "né sous le numéro (" + spaced15(nir) + ") hier", spaced15(nir), "fr_nir", "fr_social_security_number", 60, LevelHigh},
		{"NIR compact", "NIR=" + nir, nir, "fr_nir", "fr_social_security_number", 60, LevelHigh},
		{"SIRET", "établissement " + siret + ",", siret, "fr_siret", "fr_siret", 35, LevelMedium},
		{"SIREN", `{"siren": "` + siren + `"}`, siren, "fr_siren", "fr_siren", 35, LevelMedium},
		{"SIREN en groupes", "SIREN n° " + siren[:3] + " " + siren[3:6] + " " + siren[6:], siren[:3] + " " + siren[3:6] + " " + siren[6:], "fr_siren", "fr_siren", 35, LevelMedium},
		{"carte", "carte 4111 1111 1111 1111 exp 12/29", "4111 1111 1111 1111", "payment_card", "payment_card_number", 70, LevelHigh},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := Scan([]byte(c.input), rules, Options{})
			if !result.Complete {
				t.Fatalf("analyse incomplète : %v", result.Failure)
			}
			if len(result.Findings) != 1 {
				t.Fatalf("%d constats : %+v", len(result.Findings), result.Findings)
			}
			f := result.Findings[0]
			if f.RuleID != c.rule || f.SecretType != c.secretType || f.Score != c.score || f.Level != c.level || f.Encoding != EncodingPlain {
				t.Fatalf("constat %+v", f)
			}
			if got := c.input[f.ByteStart:f.ByteEnd]; got != c.value {
				t.Fatalf("étendue %q, attendu %q", got, c.value)
			}
		})
	}
}

// spaced15 écrit un NIR par groupes officiels.
func spaced15(nir string) string {
	return nir[:1] + " " + nir[1:3] + " " + nir[3:5] + " " + nir[5:7] + " " + nir[7:10] + " " + nir[10:13] + " " + nir[13:]
}

// TestPersonalDataNoFalsePositives : numéros de téléphone, de commande, horodatages, versions et identifiants courants.
func TestPersonalDataNoFalsePositives(t *testing.T) {
	rules := loadInitialRules(t)
	for _, input := range []string{
		"tél 01 23 45 67 89 ou +33 6 12 34 56 78, fax 0145678901",
		"commande 20261110103000 expédiée, suivi 1Z999AA10123456784",
		"commit 5f0bbfa and build 4294967296, ts 1699999999999 ms",
		"version 1.2.3, port 8080, année 2026, montant 1 234,56 EUR",
		"uuid 550e8400-e29b-41d4-a716-446655440000",
		"SIREN : abc, Sirène 123456782, siren (inconnu)",
		"IBAN : FR76, IBAN FR76 3000 6000, ab12 cd34 ef56",
		"nombre 0000 0000 0000 0000 et 1111 1111 1111 1111",
		"EAN 4006381333931 et ISBN 978-2-07-036002-4",
	} {
		result := Scan([]byte(input), rules, Options{})
		for _, f := range result.Findings {
			switch f.RuleID {
			case "iban", "fr_nir", "fr_siret", "fr_siren", "payment_card":
				t.Errorf("%q : faux positif %s", input, f.RuleID)
			}
		}
	}
}

// TestPersonalDataViews : un numéro codé en pourcentage ou en échappements JSON est trouvé (validateurs actifs dans
// ces vues), au score diminué de 5 ; dans un texte décodé de base64, les règles à validateur ne s'exécutent pas
// (comme jwt), ce qui est une limite connue.
func TestPersonalDataViews(t *testing.T) {
	rules := loadInitialRules(t)
	iban := "FR76 3000 6000 0112 3456 7890 189"
	cases := []struct {
		name, input string
		encoding    Encoding
		found       bool
	}{
		{"pourcentage", "x=" + strings.ReplaceAll(iban, " ", "%20"), EncodingPercent, true},
		{"échappements JSON", `"` + strings.ReplaceAll(iban, "F", `\`+"u0046") + `"`, EncodingJSONEscaped, true},
		{"base64", "data=" + b64("IBAN "+iban+" fin de message"), EncodingBase64, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := Scan([]byte(c.input), rules, Options{})
			found := false
			for _, f := range result.Findings {
				if f.RuleID == "iban" {
					found = true
					if f.Encoding != c.encoding || f.Score != 40 {
						t.Errorf("constat %+v", f)
					}
				}
			}
			if found != c.found {
				t.Fatalf("trouvé : %v, attendu %v (%+v)", found, c.found, result.Findings)
			}
		})
	}
}

// TestPersonalDataRedaction : le masquage retire le numéro, nomme la règle, et la nouvelle analyse ne trouve plus rien.
func TestPersonalDataRedaction(t *testing.T) {
	rules := loadInitialRules(t)
	input := "IBAN FR76 3000 6000 0112 3456 7890 189 et carte 4111 1111 1111 1111, SIREN 123456782 fin"
	text, outcome := RedactAndRescan([]byte(input), rules, Options{}, RedactOptions{})
	if outcome.Failure != SanitizeNone {
		t.Fatalf("issue %q", outcome.Failure)
	}
	want := "IBAN <REDACTED_iban> et carte <REDACTED_payment_card>, SIREN <REDACTED_fr_siren> fin"
	if string(text) != want {
		t.Fatalf("texte masqué %q", text)
	}
	if len(outcome.Final.Findings) != 0 {
		t.Fatalf("constats après masquage : %+v", outcome.Final.Findings)
	}
}

// TestPersonalDataSubstitutes : un type de Substitut par règle, dans les deux langues ; le texte écrit est reconnu comme
// une valeur fictive (jamais détecté de nouveau) et ne porte rien de la valeur.
func TestPersonalDataSubstitutes(t *testing.T) {
	rules := loadInitialRules(t)
	cases := []struct {
		rule, value, french, english string
	}{
		{"iban", "FR76 3000 6000 0112 3456 7890 189", "IBAN", "IBAN"},
		{"fr_nir", "1 84 12 76 451 089 46", "numéro de sécurité sociale", "social security number"},
		{"fr_siret", "123 456 782 00010", "numéro SIRET", "SIRET number"},
		{"fr_siren", "123456782", "numéro SIREN", "SIREN number"},
		{"payment_card", "4111 1111 1111 1111", "numéro de carte bancaire", "payment card number"},
	}
	for _, c := range cases {
		french, err := SubstituteText([]byte(c.value), c.rule, 3, SubstituteFrench)
		if err != nil || french != "[secret masqué par xSOM n°3 : "+c.french+", pas la vraie valeur]" {
			t.Errorf("%s en français : %q (%v)", c.rule, french, err)
		}
		english, err := SubstituteText([]byte(c.value), c.rule, 3, SubstituteEnglish)
		if err != nil || english != "[secret masked by xSOM #3: "+c.english+", not the real value]" {
			t.Errorf("%s en anglais : %q (%v)", c.rule, english, err)
		}
		for _, substitute := range []string{french, english} {
			if strings.ContainsAny(substitute, "0123456789") && !strings.Contains(substitute, "3") {
				t.Errorf("%s : chiffres de la valeur dans le Substitut %q", c.rule, substitute)
			}
			if got := Scan([]byte("note "+substitute+" fin"), rules, Options{}); len(got.Findings) != 0 {
				t.Errorf("%s : Substitut détecté %+v", c.rule, got.Findings)
			}
		}
	}
}
