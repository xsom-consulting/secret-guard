// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// TestProviderRules : règles de fournisseurs du Pack initial (v0.8.1).
func TestProviderRules(t *testing.T) {
	rules := loadInitialRules(t)
	p := loadInitialPack(t)
	byID := map[string]*rule{}
	for _, r := range rules.fixed {
		byID[r.id] = r
	}
	t.Run("chaque règle de fournisseur est une règle « motif seul » à porte, avec un libellé de Substitut dans les deux langues", func(t *testing.T) {
		if len(providerSubstituteLabels) != 294 {
			t.Fatalf("%d règles de fournisseurs", len(providerSubstituteLabels))
		}
		// Les règles de fournisseurs ferment le Pack, dans l'ordre de leur table.
		tail := p.Rules[len(p.Rules)-len(providerSubstituteLabels):]
		for i, label := range providerSubstituteLabels {
			spec := tail[i]
			if spec.RuleID != label.RuleID {
				t.Fatalf("règle %d : %s dans le Pack, %s dans la table des libellés", i, spec.RuleID, label.RuleID)
			}
			r := byID[spec.RuleID]
			if r == nil || string(spec.Family) != familyFixedPattern || string(spec.SecretType) != "provider_token" || spec.Validator != "" {
				t.Fatalf("%s : famille %s, type %s, validateur %q", spec.RuleID, spec.Family, spec.SecretType, spec.Validator)
			}
			if spec.Score != 95 && spec.Score != 80 {
				t.Errorf("%s : score %d (95 : préfixe fixe ; 80 : nom du fournisseur à proximité)", spec.RuleID, spec.Score)
			}
			if r.gate == nil {
				t.Errorf("%s : aucune porte littérale (la règle s'exécuterait sur tout texte)", spec.RuleID)
			}
			if r.pattern.NumSubexp() > 1 {
				t.Errorf("%s : %d groupes capturants (un seul : la valeur)", spec.RuleID, r.pattern.NumSubexp())
			}
			for _, text := range []string{label.French, label.English} {
				if text == "" || text == SubstituteDefaultLabel || strings.ContainsAny(text, "[]\n\r\t,:") || strings.TrimSpace(text) != text {
					t.Errorf("%s : libellé %q refusé", spec.RuleID, text)
				}
			}
			if got, err := SubstituteText([]byte("x"), spec.RuleID, 7, SubstituteFrench); err != nil || got != "[secret masqué par xSOM n°7 : "+label.French+", pas la vraie valeur]" {
				t.Errorf("%s : Substitut %q, %v", spec.RuleID, got, err)
			}
		}
	})
	t.Run("un Substitut de fournisseur est reconnu par la grammaire : le texte expurgé ne bloque pas", func(t *testing.T) {
		for _, label := range providerSubstituteLabels {
			for _, language := range []SubstituteLanguage{SubstituteFrench, SubstituteEnglish} {
				substitute, err := SubstituteText([]byte("x"), label.RuleID, 12, language)
				if err != nil {
					t.Fatal(err)
				}
				found := FindSubstitutes([]byte("valeur : " + substitute + " fin"))
				if len(found) != 1 {
					t.Fatalf("%s (%s) : %d Substituts reconnus dans %q", label.RuleID, language, len(found), substitute)
				}
			}
		}
	})
}

// TestLiteralIndex : l'index des portes admet au moins chaque règle que sa porte admet, sur des textes variés.
func TestLiteralIndex(t *testing.T) {
	rules := loadInitialRules(t)
	if rules.index == nil || rules.index.count != len(rules.fixed) {
		t.Fatal("index absent")
	}
	gated := 0
	for _, r := range rules.fixed {
		if r.gate != nil {
			gated++
		}
	}
	if gated < 300 {
		t.Fatalf("%d règles à porte", gated)
	}
	random := rand.New(rand.NewPCG(7, 11))
	var texts [][]byte
	texts = append(texts, nil, []byte("x"), benchText(16<<10, true), benchText(16<<10, false), []byte("K ſ K ſ"))
	// Chaque littéral de chaque porte, tel quel, en majuscules, coupé, et entouré de bruit.
	for _, r := range rules.fixed {
		if r.gate == nil {
			continue
		}
		for _, literal := range r.gate.literals {
			s := string(literal)
			texts = append(texts, []byte(s), []byte(strings.ToUpper(s)), []byte("zz"+s+"zz"), []byte(s[:len(s)-1]), []byte(s[1:]))
		}
	}
	for i := 0; i < 200; i++ {
		buffer := make([]byte, random.IntN(512))
		for k := range buffer {
			buffer[k] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.:/= \n"[random.IntN(70)]
		}
		texts = append(texts, buffer)
	}
	admittedAtLeastOnce := 0
	for _, text := range texts {
		admitted := rules.index.admitted(text)
		for i, r := range rules.fixed {
			if r.gate.admits(text) && !admitted.has(i) {
				t.Fatalf("%s : la porte admet un texte de %d octets que l'index écarte", r.id, len(text))
			}
			if r.gate != nil && admitted.has(i) {
				admittedAtLeastOnce++
			}
		}
	}
	if admittedAtLeastOnce == 0 {
		t.Fatal("aucune règle à porte admise")
	}
	// L'index écarte la plupart des règles sur un texte ordinaire.
	ordinary := rules.index.admitted([]byte("La réunion de mardi est reportée ; le compte rendu suit.\n"))
	count := 0
	for i := range rules.fixed {
		if ordinary.has(i) {
			count++
		}
	}
	if count > 12 {
		t.Fatalf("%d règles admises sur un texte ordinaire", count)
	}
}
