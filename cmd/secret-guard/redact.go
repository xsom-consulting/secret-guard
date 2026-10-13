package main

import (
	"flag"
	"io"

	"github.com/xsom-consulting/secret-guard/detect"
	"github.com/xsom-consulting/secret-guard/internal/limits"
	"github.com/xsom-consulting/secret-guard/internal/report"
)

// redact masque le fichier donné, ou l'entrée standard, et écrit le texte masqué sur la sortie standard : 0 si rien
// n'est à masquer (le texte est recopié), 1 si au moins une étendue est masquée. Échec du masquage (analyse
// incomplète, secret qui subsiste après masquage) ou erreur : 2, et rien sur la sortie standard.
func redact(args []string, stdin io.Reader, stdout, stderr io.Writer, opener files) int {
	flags := flag.NewFlagSet("redact", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	packFile := flags.String("pack", "", "")
	language := flags.String("language", "", "")
	if err := flags.Parse(args); err != nil || flags.NArg() > 1 {
		_, _ = io.WriteString(stderr, usage)
		return report.ExitError
	}
	rules, problem := loadRules(*packFile, opener)
	if problem != "" {
		return fail(stderr, problem)
	}
	content, problem := readContent(flags.Arg(0), stdin, opener)
	defer clear(content)
	if problem != "" {
		return fail(stderr, problem)
	}
	text, result := detect.RedactAndRescan(content, rules, detect.Options{LanguageID: *language}, detect.RedactOptions{})
	defer clear(text)
	switch result.Failure {
	case detect.SanitizeNone:
		if _, err := stdout.Write(text); err != nil {
			return report.ExitError
		}
		if len(result.Initial.Findings) == 0 {
			return report.ExitClean
		}
		return report.ExitFindings
	case detect.SanitizeResidual:
		return fail(stderr, "masquage impossible : un secret subsiste après masquage (residual) ; aucun texte écrit")
	}
	return fail(stderr, "masquage impossible : analyse incomplète ("+string(result.Final.Failure)+") ; aucun texte écrit")
}

// readContent lit le fichier nommé, ou l'entrée standard (sans nom, ou « - »), au plus MaxInputBytes + 1 octets :
// au-delà de la limite, le moteur rend scan_limit sans rien analyser. Le message d'un refus ne cite pas le chemin.
func readContent(name string, stdin io.Reader, opener files) ([]byte, string) {
	input := stdin
	if name != "" && name != "-" {
		file, err := opener.Open(name)
		if err != nil {
			return nil, "fichier à masquer : " + fileProblem(err)
		}
		defer func() { _ = file.Close() }()
		input = file
	}
	content, err := io.ReadAll(io.LimitReader(input, limits.MaxInputBytes+1))
	if err != nil {
		clear(content)
		return nil, "lecture impossible"
	}
	return content, ""
}
