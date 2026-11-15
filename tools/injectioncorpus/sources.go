// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"unicode/utf8"
)

// sourceSpec épingle une source : dépôt, commit, licence relue (empreinte du fichier de licence) et empreinte de ce
// qui est lu. Changer de commit demande de relire la licence et les fichiers, puis de mettre à jour NOTICE et
// UPSTREAM.md.
type sourceSpec struct {
	ID            string
	Clone         string // nom du dossier du clone
	Repository    string
	Commit        string
	License       string
	Copyright     string
	LicenseFile   string
	LicenseSHA256 string
	Path          string // fichier ou dossier lu, relatif au clone
	SHA256        string // empreinte du fichier, ou de la liste des fichiers du dossier (treeFiles)
	Note          string
	read          func(path string) (cases []Case, digest string, err error)
}

var sources = []sourceSpec{
	{
		ID: "llm-guard", Clone: "llm-guard", Repository: "https://github.com/protectai/llm-guard",
		Commit: "168c1034ffdb33837e7ae6fd6a16b80567c1be03", License: "MIT", Copyright: "Copyright (c) Protect AI. All rights reserved.",
		LicenseFile: "LICENSE", LicenseSHA256: "31dcbe8e380febbbe677c74631d0d84108bb48fc9de5f8ac2cac5c9862741822",
		Path: "tests/input_scanners/test_prompt_injection.py", SHA256: "f0d6e1755f4e541d74cd685fc2b9f505d75b7505c9fd57a9f0c805872c78a13f",
		Note: "Jeu d'essai du détecteur d'injection : textes étiquetés par leur auteur (sain ou injection). Projet archivé.",
		read: readLLMGuard,
	},
	{
		ID: "promptfoo", Clone: "promptfoo", Repository: "https://github.com/promptfoo/promptfoo",
		Commit: "5fac53eefdd26141a45c52ab77f533a7d30884e3", License: "MIT", Copyright: "Copyright (c) Promptfoo 2025",
		LicenseFile: "LICENSE", LicenseSHA256: "bf813686553f451e1b833fbd827488aee49b60b189626915bf3108d10b754e44",
		Path: "src/redteam/strategies/promptInjections/data.ts", SHA256: "4280c91c66b8261696e53f808813cc2bb4d4d8cde491e782f2b25f1c2c45a7df",
		Note: "Gabarits de contournement (jailbreak) visant un chatbot ; en partie repris de LLM Guard (MIT, Copyright (c) Protect AI), d'après le README du même dossier.",
		read: readPromptfoo,
	},
	{
		ID: "akto", Clone: "akto", Repository: "https://github.com/akto-api-security/akto",
		Commit: "f69427472ebf57cac9dd1b70bbcfb542ba2189d8", License: "MIT", Copyright: "Copyright (c) 2023 Akto.io.",
		LicenseFile: "LICENSE.md", LicenseSHA256: "3a56669cbf8d31c121ecdaa8df65e022eee0d4695fe90873c339d69bb814ed33",
		Path: "apps/dashboard/src/main/resources/inbuilt_llm_test_yaml_files", SHA256: "78d4a995180083d20dc962f3432913a0a1bc4540c1827db25c700c0b83fe9a8b",
		Note: "Charges des gabarits de test LLM embarqués, décodées de leur forme en pourcentages ; beaucoup demandent du code malveillant et ne sont pas des injections. La plupart des gabarits citent garak (Apache-2.0) en référence. Les charges qui portent une signature d'essai d'antivirus ou d'antispam ne sont pas copiées.",
		read: readAkto,
	},
	{
		ID: "skill-scanner", Clone: "skill-scanner", Repository: "https://github.com/cisco-ai-defense/skill-scanner",
		Commit: "c558c421157c546ec417cf23778ce81a3a8f35fd", License: "Apache-2.0", Copyright: "Copyright 2026 Cisco Systems, Inc. and its affiliates",
		LicenseFile: "LICENSE", LicenseSHA256: "6f8bdae6c2bf096c697839ce3b6305d0c2aab22c14fb761b94c9962a79ae5998",
		Path: "evals/skills", SHA256: "b044b48da467c0c2baccca3315ae69518bdd028cc836e1c94ee335cf5a1bde5f",
		Note: "Skills d'évaluation et leur résultat attendu (_expected.json, fixtures de l'éditeur, Apache-2.0) : un cas par fichier. Étiquette « consigne » si le résultat attendu porte prompt_injection, « sain » si le paquet est tenu pour bénin, « autre » sinon (risque de code ou de dépendance, hors du périmètre du paquet injection). Une catégorie n'est pas copiée : celle dont le skill porte une valeur à forme de secret.",
		read: readSkillScanner,
	},
}

func readLLMGuard(file string) ([]Case, string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, "", err
	}
	texts, skipped, err := llmGuardCases(string(data))
	if err != nil {
		return nil, "", err
	}
	if skipped != 0 {
		return nil, "", fmt.Errorf("%d cas dont le texte n'est pas un littéral", skipped)
	}
	cases := make([]Case, 0, len(texts))
	for i, text := range texts {
		label := LabelInjection
		if text.valid {
			label = LabelBenign
		}
		cases = append(cases, Case{ID: fmt.Sprintf("llm-guard/%03d", i+1), Label: label, Text: text.text})
	}
	return cases, fileSHA256(data), nil
}

func readPromptfoo(file string) ([]Case, string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, "", err
	}
	texts, err := jsLiteralLines(string(data))
	if err != nil {
		return nil, "", err
	}
	cases := make([]Case, 0, len(texts))
	for i, text := range texts {
		cases = append(cases, Case{ID: fmt.Sprintf("promptfoo/%03d", i+1), Label: LabelInjection, Text: text})
	}
	return cases, fileSHA256(data), nil
}

// testSignatureMarkers : une charge qui porte l'un de ces mots porte une signature d'essai d'antivirus ou
// d'antispam ; copiée, elle ferait signaler le corpus par les outils de sécurité des postes. Les mots sont assemblés
// ici pour que ce fichier ne les porte pas non plus.
var testSignatureMarkers = []string{"EIC" + "AR", "GTU" + "BE"}

func readAkto(dir string) ([]Case, string, error) {
	paths, contents, digest, err := treeFiles(dir)
	if err != nil {
		return nil, "", err
	}
	var cases []Case
	for _, name := range paths {
		if !strings.HasSuffix(name, ".yml") {
			return nil, "", fmt.Errorf("fichier inattendu %s", name)
		}
		index := 0
		for _, line := range strings.Split(string(contents[name]), "\n") {
			line = strings.TrimSpace(line)
			if !strings.Contains(line, "%20") || strings.HasPrefix(line, "#") {
				continue
			}
			text := percentDecode(line)
			id := fmt.Sprintf("akto/%s/%d", strings.TrimSuffix(name, ".yml"), index)
			index++
			if containsAny(text, testSignatureMarkers) {
				continue
			}
			cases = append(cases, Case{ID: id, Label: LabelInjection, Text: text})
		}
	}
	return cases, digest, nil
}

func containsAny(text string, words []string) bool {
	for _, word := range words {
		if strings.Contains(text, word) {
			return true
		}
	}
	return false
}

// skippedSkillCategories ne sont pas copiées (voir la note de la source).
var skippedSkillCategories = map[string]bool{"hardcoded-secrets": true}

type skillExpectation struct {
	PackageLabel     string `json:"package_label"`
	ExpectedFindings []struct {
		Category string `json:"category"`
	} `json:"expected_findings"`
	Provenance struct {
		License string `json:"license"`
	} `json:"provenance"`
}

func readSkillScanner(dir string) ([]Case, string, error) {
	paths, contents, digest, err := treeFiles(dir)
	if err != nil {
		return nil, "", err
	}
	labels := map[string]string{}
	for _, name := range paths {
		if path.Base(name) != "_expected.json" {
			continue
		}
		var expectation skillExpectation
		if err := json.Unmarshal(contents[name], &expectation); err != nil {
			return nil, "", fmt.Errorf("%s : %w", name, err)
		}
		// Licence relue fixture par fixture : chacune déclare la sienne.
		if expectation.Provenance.License != "Apache-2.0" {
			return nil, "", fmt.Errorf("%s : licence %q, attendue Apache-2.0", name, expectation.Provenance.License)
		}
		label := LabelOther
		if expectation.PackageLabel == "benign" && len(expectation.ExpectedFindings) == 0 {
			label = LabelBenign
		}
		for _, finding := range expectation.ExpectedFindings {
			if finding.Category == "prompt_injection" {
				label = LabelInjection
			}
		}
		labels[path.Dir(name)] = label
	}
	var cases []Case
	for _, name := range paths {
		if path.Base(name) == "_expected.json" || skippedSkillCategories[strings.SplitN(name, "/", 2)[0]] {
			continue
		}
		skill := name
		for skill != "." && labels[skill] == "" {
			skill = path.Dir(skill)
		}
		if skill == "." {
			return nil, "", fmt.Errorf("%s : aucun résultat attendu pour ce fichier", name)
		}
		if !utf8.Valid(contents[name]) {
			return nil, "", errors.New(name + " : pas de l'UTF-8")
		}
		cases = append(cases, Case{ID: "skill-scanner/" + name, Label: labels[skill], Text: string(contents[name])})
	}
	return cases, digest, nil
}
