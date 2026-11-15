// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/xsom-consulting/secret-guard/detect"
	"github.com/xsom-consulting/secret-guard/internal/report"
)

// sarifKeys : liste fermée des propriétés que la sortie SARIF peut écrire, à toute profondeur. « snippet »,
// « contextRegion », « text » hors d'un message et tout champ libre n'y sont pas : rien ne peut porter un extrait.
var sarifKeys = map[string]bool{
	"version": true, "$schema": true, "runs": true, "tool": true, "driver": true, "name": true, "informationUri": true,
	"rules": true, "id": true, "shortDescription": true, "text": true, "properties": true, "secretType": true,
	"invocations": true, "executionSuccessful": true, "toolExecutionNotifications": true, "descriptor": true,
	"level": true, "message": true, "columnKind": true, "results": true, "ruleId": true, "ruleIndex": true,
	"locations": true, "physicalLocation": true, "artifactLocation": true, "uri": true, "region": true,
	"startLine": true, "startColumn": true, "endLine": true, "endColumn": true, "byteOffset": true, "byteLength": true,
	"partialFingerprints": true, sarifFingerprint: true, "encoding": true, "score": true,
}

// assigned : début d'une ligne d'affectation d'essai, assemblé à l'exécution.
var assigned = "TOK" + "EN" + "="

// decodeSARIF lit une sortie SARIF, vérifie sa forme (une ligne, document strict, propriétés de la liste fermée,
// contraintes de SARIF 2.1.0 sur ce que la commande écrit) et rend son unique exécution.
func decodeSARIF(t *testing.T, text string) sarifRun {
	t.Helper()
	if !strings.HasSuffix(text, "\n") || strings.Count(text, "\n") != 1 {
		t.Fatalf("sortie sur plusieurs lignes ou sans fin de ligne : %q", text)
	}
	var generic any
	if err := json.Unmarshal([]byte(text), &generic); err != nil {
		t.Fatalf("sortie illisible : %v", err)
	}
	var walk func(value any)
	walk = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			for key, child := range v {
				if !sarifKeys[key] {
					t.Errorf("propriété hors de la liste fermée : %q", key)
				}
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(generic)
	var log sarifLog
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&log); err != nil {
		t.Fatalf("document SARIF hors de la forme attendue : %v", err)
	}
	if log.Version != "2.1.0" || !strings.HasSuffix(log.Schema, "/sarif-schema-2.1.0.json") || len(log.Runs) != 1 {
		t.Fatalf("version %q, schéma %q, %d exécution(s)", log.Version, log.Schema, len(log.Runs))
	}
	run := log.Runs[0]
	driver := run.Tool.Driver
	if driver.Name != "secret-guard" || driver.Version == "" || !strings.HasPrefix(driver.InformationURI, "https://") {
		t.Fatalf("outil : %+v", driver)
	}
	if run.ColumnKind != "unicodeCodePoints" || len(run.Invocations) != 1 {
		t.Fatalf("columnKind %q, %d invocation(s)", run.ColumnKind, len(run.Invocations))
	}
	// Tableaux présents même vides : « results » absent voudrait dire « non calculé » en SARIF.
	if run.Results == nil || driver.Rules == nil || !strings.Contains(text, `"results":[`) || !strings.Contains(text, `"rules":[`) {
		t.Fatal("results ou rules absent")
	}
	seen := map[string]bool{}
	for _, rule := range driver.Rules {
		if rule.ID == "" || seen[rule.ID] || rule.ShortDescription.Text == "" || rule.Properties["secretType"] == "" {
			t.Errorf("règle mal formée ou en double : %+v", rule)
		}
		seen[rule.ID] = true
	}
	for _, result := range run.Results {
		if result.RuleIndex < 0 || result.RuleIndex >= len(driver.Rules) || driver.Rules[result.RuleIndex].ID != result.RuleID {
			t.Errorf("ruleIndex %d ne désigne pas %s", result.RuleIndex, result.RuleID)
		}
		if result.Level != "error" && result.Level != "warning" && result.Level != "note" {
			t.Errorf("niveau %q", result.Level)
		}
		if result.Message.Text == "" || len(result.Locations) != 1 {
			t.Errorf("message ou emplacement absent : %+v", result)
			continue
		}
		location := result.Locations[0].PhysicalLocation
		region := location.Region
		if location.ArtifactLocation.URI == "" || region.StartLine < 1 || region.StartColumn < 1 || region.EndLine < region.StartLine ||
			region.EndColumn < 1 || (region.EndLine == region.StartLine && region.EndColumn < region.StartColumn) ||
			region.ByteOffset < 0 || region.ByteLength < 0 {
			t.Errorf("emplacement mal formé : %+v", location)
		}
		if result.Properties.SecretType == "" || result.Properties.Encoding == "" || result.Properties.Level == "" {
			t.Errorf("propriétés du constat : %+v", result.Properties)
		}
	}
	for _, notification := range run.Invocations[0].Notifications {
		if notification.Descriptor.ID == "" || notification.Level != "error" || notification.Message.Text == "" {
			t.Errorf("notification mal formée : %+v", notification)
		}
	}
	return run
}

// expectedRegion calcule la région d'une étendue sans le code de la commande : lignes par découpage du texte,
// colonnes par conversion en points de code.
func expectedRegion(content string, start, end int) sarifRegion {
	position := func(offset int) (int, int) {
		lines := strings.Split(content[:offset], "\n")
		return len(lines), len([]rune(lines[len(lines)-1])) + 1
	}
	last := end - 1
	for !utf8.RuneStart(content[last]) {
		last--
	}
	startLine, startColumn := position(start)
	endLine, endColumn := position(last)
	return sarifRegion{StartLine: startLine, StartColumn: startColumn, EndLine: endLine, EndColumn: endColumn + 1, ByteOffset: start, ByteLength: end - start}
}

func TestScanSARIF(t *testing.T) {
	token := syntheticToken()
	other := strings.Repeat("Xk7Pq2Rm9T", 2)
	key := strings.Repeat("0123456789abcdef", 4)
	// Deuxième ligne : des caractères de 2 et 3 octets devant le jeton (colonnes en points de code).
	sample := "# en-tête\néà€ " + assigned + token + "\nrien ici\nautre=" + token + "\n"
	files := memoryFiles{
		"propre.txt":         []byte("rien à signaler\n"),
		"src/exemple.env":    []byte(sample),
		"mes notes/été.env":  []byte(assigned + token + "\n"),
		"grand.bin":          bytes.Repeat([]byte("a"), 1<<20+1),
		"cle":                []byte(key + "\n"),
		"deux-regles.txt":    []byte(assigned + token + "\n" + "pass" + "word = \"" + other + "\"\n"),
		"fin-sans-ligne.txt": []byte(assigned + token),
	}

	t.Run("cas positif : règle, fichier, lignes, colonnes, niveau ; jamais la valeur ni un extrait", func(t *testing.T) {
		code, stdout, stderr := runCommand(t, files, "", "scan", "--format", "sarif", "src/exemple.env")
		if code != report.ExitFindings || stderr != "" {
			t.Fatalf("code %d, erreur %q", code, stderr)
		}
		run := decodeSARIF(t, stdout)
		if leaks(stdout, token) {
			t.Fatal("la sortie SARIF porte la valeur")
		}
		for _, excerpt := range []string{"en-tête", "éà€", "rien", "ici", "autre"} {
			if strings.Contains(stdout, excerpt) {
				t.Fatalf("la sortie SARIF porte un extrait du contenu : %q", excerpt)
			}
		}
		if !run.Invocations[0].ExecutionSuccessful || len(run.Invocations[0].Notifications) != 0 {
			t.Fatalf("invocation : %+v", run.Invocations[0])
		}
		if len(run.Tool.Driver.Rules) != 1 || run.Tool.Driver.Rules[0].ID != "github_token" || len(run.Results) != 2 {
			t.Fatalf("règles %+v, %d résultats", run.Tool.Driver.Rules, len(run.Results))
		}
		first := run.Results[0]
		if first.RuleID != "github_token" || first.RuleIndex != 0 || first.Level != "error" ||
			first.Properties != (sarifProperties{SecretType: "provider_token", Encoding: "plain", Score: 95, Level: "CRITICAL"}) {
			t.Fatalf("premier résultat : %+v", first)
		}
		if first.PartialFingerprints != nil {
			t.Fatal("Empreinte locale sans clé")
		}
		// Début du premier constat : ligne 2, après 10 points de code (13 octets) ; du second : ligne 4, après 6.
		location := first.Locations[0].PhysicalLocation
		if location.ArtifactLocation.URI != "src/exemple.env" || location.Region.StartLine != 2 || location.Region.StartColumn != 11 ||
			location.Region.ByteOffset != strings.Index(sample, token) {
			t.Fatalf("premier emplacement : %+v", location)
		}
		second := run.Results[1].Locations[0].PhysicalLocation.Region
		if second.StartLine != 4 || second.StartColumn != 7 || second.ByteOffset != strings.LastIndex(sample, token) {
			t.Fatalf("second emplacement : %+v", second)
		}
		// La sortie JSON du même contenu donne les mêmes constats ; chaque région est celle de l'étendue du constat,
		// recalculée ici sans le code de la commande.
		_, jsonOut, _ := runCommand(t, files, "", "scan", "src/exemple.env")
		document := decodeDocument(t, jsonOut)
		if len(document.Findings) != len(run.Results) {
			t.Fatalf("%d constats en JSON, %d résultats en SARIF", len(document.Findings), len(run.Results))
		}
		for i, f := range document.Findings {
			region := run.Results[i].Locations[0].PhysicalLocation.Region
			if f.RuleID != run.Results[i].RuleID || region != expectedRegion(sample, f.ByteStart, f.ByteEnd) {
				t.Fatalf("constat %d : JSON %+v, région %+v, attendue %+v", i, f, region, expectedRegion(sample, f.ByteStart, f.ByteEnd))
			}
		}
	})

	t.Run("cas sans constat : document complet, tableaux vides, code 0", func(t *testing.T) {
		code, stdout, stderr := runCommand(t, files, "", "scan", "--format", "sarif", "propre.txt")
		if code != report.ExitClean || stderr != "" {
			t.Fatalf("code %d, erreur %q", code, stderr)
		}
		run := decodeSARIF(t, stdout)
		if len(run.Results) != 0 || len(run.Tool.Driver.Rules) != 0 || !run.Invocations[0].ExecutionSuccessful ||
			len(run.Invocations[0].Notifications) != 0 {
			t.Fatalf("exécution : %+v", run)
		}
		if strings.Contains(stdout, "signaler") {
			t.Fatal("la sortie SARIF porte un extrait du contenu")
		}
	})

	t.Run("entrée standard : artefact « stdin »", func(t *testing.T) {
		for _, args := range [][]string{{"scan", "--format", "sarif"}, {"scan", "--format=sarif", "-"}} {
			code, stdout, _ := runCommand(t, files, assigned+token+"\n", args...)
			run := decodeSARIF(t, stdout)
			if code != report.ExitFindings || len(run.Results) != 1 || run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "stdin" {
				t.Fatalf("%v : code %d, %+v", args, code, run.Results)
			}
		}
	})

	t.Run("nom de fichier : référence d'URI, octets hors ASCII et espaces en %XX", func(t *testing.T) {
		_, stdout, _ := runCommand(t, files, "", "scan", "--format", "sarif", "mes notes/été.env")
		run := decodeSARIF(t, stdout)
		if got := run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "mes%20notes/%C3%A9t%C3%A9.env" {
			t.Fatalf("URI %q", got)
		}
	})

	t.Run("deux règles : une entrée par règle", func(t *testing.T) {
		code, stdout, _ := runCommand(t, files, "", "scan", "--format", "sarif", "deux-regles.txt")
		run := decodeSARIF(t, stdout)
		if code != report.ExitFindings || len(run.Tool.Driver.Rules) < 2 || len(run.Results) < 2 {
			t.Fatalf("code %d, %d règles, %d résultats", code, len(run.Tool.Driver.Rules), len(run.Results))
		}
		if leaks(stdout, token) || leaks(stdout, other) {
			t.Fatal("la sortie SARIF porte une valeur")
		}
	})

	t.Run("constat en fin de contenu sans fin de ligne", func(t *testing.T) {
		_, stdout, _ := runCommand(t, files, "", "scan", "--format", "sarif", "fin-sans-ligne.txt")
		region := decodeSARIF(t, stdout).Results[0].Locations[0].PhysicalLocation.Region
		want := sarifRegion{StartLine: 1, StartColumn: 7, EndLine: 1, EndColumn: 7 + len(token), ByteOffset: 6, ByteLength: len(token)}
		if region != want {
			t.Fatalf("région : %+v, attendu %+v", region, want)
		}
	})

	t.Run("analyse incomplète : notification d'erreur, aucun résultat, code 2", func(t *testing.T) {
		code, stdout, _ := runCommand(t, files, "", "scan", "--format", "sarif", "grand.bin")
		run := decodeSARIF(t, stdout)
		invocation := run.Invocations[0]
		if code != report.ExitError || invocation.ExecutionSuccessful || len(run.Results) != 0 || len(invocation.Notifications) != 1 ||
			invocation.Notifications[0].Descriptor.ID != string(detect.FailureScanLimit) {
			t.Fatalf("code %d, invocation %+v, %d résultats", code, invocation, len(run.Results))
		}
	})

	t.Run("Empreinte locale : partialFingerprints, 32 caractères hexadécimaux", func(t *testing.T) {
		code, stdout, _ := runCommand(t, files, "", "scan", "--fingerprint-key", "cle", "--format", "sarif", "src/exemple.env")
		run := decodeSARIF(t, stdout)
		if code != report.ExitFindings || len(run.Results) != 2 {
			t.Fatalf("code %d, %d résultats", code, len(run.Results))
		}
		for _, result := range run.Results {
			if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(result.PartialFingerprints[sarifFingerprint]) {
				t.Fatalf("Empreinte locale : %q", result.PartialFingerprints[sarifFingerprint])
			}
		}
		if leaks(stdout, token) || leaks(stdout, key) {
			t.Fatal("la sortie SARIF porte la valeur ou la clé")
		}
	})

	t.Run("format : json par défaut, valeur inconnue refusée", func(t *testing.T) {
		_, byDefault, _ := runCommand(t, files, "", "scan", "src/exemple.env")
		_, explicit, _ := runCommand(t, files, "", "scan", "--format", "json", "src/exemple.env")
		if byDefault != explicit || len(decodeDocument(t, byDefault).Findings) != 2 {
			t.Fatalf("sortie JSON : %q, %q", byDefault, explicit)
		}
		code, stdout, stderr := runCommand(t, files, "", "scan", "--format", "xml", "src/exemple.env")
		if code != report.ExitError || stdout != "" || !strings.Contains(stderr, "--format") {
			t.Fatalf("format inconnu : code %d, %q, %q", code, stdout, stderr)
		}
	})
}

func TestSARIFLevel(t *testing.T) {
	for level, want := range map[detect.Level]string{
		detect.LevelCritical: "error", detect.LevelHigh: "error", detect.LevelMedium: "warning", detect.LevelLow: "note",
		detect.Level("AUTRE"): "note",
	} {
		if got := sarifLevel(level); got != want {
			t.Errorf("sarifLevel(%s) = %s, attendu %s", level, got, want)
		}
	}
}

func TestRegionOf(t *testing.T) {
	// Octets : « ab » 0-1, fin de ligne 2, « c » 3, « d » 4, « é » 5-6, « € » 7-9, « f » 10, fins de ligne 11 et 12,
	// « gh » 13-14. Colonnes de la ligne 2 : c 1, d 2, é 3, € 4, f 5, fin de ligne 6.
	content := []byte("ab\ncdé€f\n\ngh")
	for _, c := range []struct {
		start, end int
		want       sarifRegion
	}{
		{0, 2, sarifRegion{1, 1, 1, 3, 0, 2}},
		{4, 10, sarifRegion{2, 2, 2, 5, 4, 6}},    // « dé€ » : finit sur un caractère de 3 octets
		{5, 7, sarifRegion{2, 3, 2, 4, 5, 2}},     // « é » seul
		{1, 5, sarifRegion{1, 2, 2, 3, 1, 4}},     // sur deux lignes
		{10, 12, sarifRegion{2, 5, 2, 7, 10, 2}},  // « f » et la fin de ligne, caractère de la colonne 6
		{11, 13, sarifRegion{2, 6, 3, 2, 11, 2}},  // deux fins de ligne
		{12, 13, sarifRegion{3, 1, 3, 2, 12, 1}},  // ligne vide
		{13, 15, sarifRegion{4, 1, 4, 3, 13, 2}},  // dernière ligne, sans fin de ligne
		{0, 15, sarifRegion{1, 1, 4, 3, 0, 15}},   // tout le contenu
		{3, 3, sarifRegion{2, 1, 2, 1, 3, 0}},     // étendue vide
		{0, 0, sarifRegion{1, 1, 1, 1, 0, 0}},     // étendue vide au début
		{15, 15, sarifRegion{4, 3, 4, 3, 15, 0}},  // étendue vide à la fin
		{9, 10, sarifRegion{2, 4, 2, 5, 9, 1}},    // dernier octet de « € » : colonne de « € »
		{6, 11, sarifRegion{2, 3, 2, 6, 6, 5}},    // commence au milieu de « é »
		{8, 8, sarifRegion{2, 4, 2, 4, 8, 0}},     // étendue vide au milieu de « € »
		{14, 99, sarifRegion{4, 2, 4, 3, 14, 1}},  // fin hors du contenu
		{-5, 1, sarifRegion{1, 1, 1, 2, 0, 1}},    // début hors du contenu
		{99, 120, sarifRegion{4, 3, 4, 3, 15, 0}}, // tout hors du contenu
		{7, 5, sarifRegion{2, 4, 2, 4, 7, 0}},     // fin avant le début
	} {
		if got := regionOf(content, c.start, c.end); got != c.want {
			t.Errorf("regionOf(%d, %d) = %+v, attendu %+v", c.start, c.end, got, c.want)
		}
		// Hors des bornes ramenées, la région est celle que recalcule expectedRegion.
		if c.start >= 0 && c.end <= len(content) && c.end > c.start && utf8.RuneStart(content[c.start]) {
			if want := expectedRegion(string(content), c.start, c.end); want != c.want {
				t.Errorf("attente incohérente pour (%d, %d) : %+v, recalculé %+v", c.start, c.end, c.want, want)
			}
		}
	}
}

func TestSARIFURI(t *testing.T) {
	for name, want := range map[string]string{
		"src/app.ts":         "src/app.ts",
		"/abs/chemin/x.go":   "/abs/chemin/x.go",
		"mes notes/été.env":  "mes%20notes/%C3%A9t%C3%A9.env",
		`src\win\x.go`:       "src/win/x.go",
		`C:\src\x.go`:        "file:///C:/src/x.go",
		"c:/src/x y.go":      "file:///c:/src/x%20y.go",
		"a:b.txt":            "a%3Ab.txt",
		"100%#?.txt":         "100%25%23%3F.txt",
		"./rel/../x_y-z~.md": "./rel/../x_y-z~.md",
	} {
		if got := sarifURI(name); got != want {
			t.Errorf("sarifURI(%q) = %q, attendu %q", name, got, want)
		}
	}
}

// TestSARIFNeverCarriesContent : la sortie SARIF d'un contenu fait d'une marque absente de tout texte fixe de la
// sortie ne porte ni cette marque ni la valeur détectée.
func TestSARIFNeverCarriesContent(t *testing.T) {
	marker := "ZQJXZQJX"
	content := []byte(strings.Repeat(marker+" ", 4) + assigned + syntheticToken() + " " + strings.Repeat(marker, 3) + "\n")
	rules, problem := loadRules("", memoryFiles{})
	if problem != "" {
		t.Fatal(problem)
	}
	result := detect.Scan(content, rules, detect.Options{})
	if !result.Complete || len(result.Findings) == 0 {
		t.Fatalf("résultat inattendu : complet %v, %d constats", result.Complete, len(result.Findings))
	}
	out := string(sarifDocument(result, "x.txt", content))
	if strings.Contains(out, marker[:4]) || leaks(out, syntheticToken()) {
		t.Fatal("la sortie SARIF porte un extrait du contenu")
	}
}
