package main

import (
	"encoding/json"
	"flag"
	"io"

	"github.com/xsom-consulting/secret-guard/hidden"
	"github.com/xsom-consulting/secret-guard/internal/limits"
	"github.com/xsom-consulting/secret-guard/internal/report"
	"github.com/xsom-consulting/secret-guard/mentions"
)

// readContent lit le fichier nommé, ou l'entrée standard (sans nom, ou « - »), au plus MaxInputBytes + 1 octets :
// au-delà de la limite, l'appelant le sait sans tout lire. Le message d'un échec ne cite jamais le chemin.
func readContent(name string, stdin io.Reader, opener files) ([]byte, string) {
	input := stdin
	if name != "" && name != "-" {
		file, err := opener.Open(name)
		if err != nil {
			return nil, "fichier à lire : " + fileProblem(err)
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

// hiddenCommand : secret-guard hidden [--strip] [fichier|-]. Sans --strip, écrit le rapport JSON des instructions
// cachées ; avec --strip, écrit le texte sans les caractères signalés (rien au-delà de 1 Mio). Codes de sortie : 0
// rien de caché, 1 au moins un caractère signalé (retiré avec --strip), 2 erreur ou texte de plus de 1 Mio.
func hiddenCommand(args []string, stdin io.Reader, stdout, stderr io.Writer, opener files) int {
	flags := flag.NewFlagSet("hidden", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	strip := flags.Bool("strip", false, "")
	if err := flags.Parse(args); err != nil || flags.NArg() > 1 {
		_, _ = io.WriteString(stderr, usage)
		return report.ExitError
	}
	content, problem := readContent(flags.Arg(0), stdin, opener)
	if problem != "" {
		return fail(stderr, problem)
	}
	defer clear(content)
	found := hidden.Find(content)
	if !*strip {
		if _, err := stdout.Write(report.HiddenJSON(found)); err != nil {
			return report.ExitError
		}
		return report.HiddenExitCode(found)
	}
	if !found.Complete {
		return fail(stderr, "texte de plus de 1 Mio : rien n'est lu ni écrit")
	}
	if _, err := stdout.Write(hidden.Strip(content)); err != nil {
		return report.ExitError
	}
	return report.HiddenExitCode(found)
}

// mentionDocument est une mention dans la forme JSON publique.
type mentionDocument struct {
	Path      string `json:"path"`
	Lines     string `json:"lines,omitempty"`
	ByteStart int    `json:"byteStart"`
	ByteEnd   int    `json:"byteEnd"`
}

// mentionsCommand : secret-guard mentions [fichier|-]. Écrit sur une ligne {"mentions": [{"path", "lines",
// "byteStart", "byteEnd"}]} ; aucun fichier n'est lu ni résolu. Codes de sortie : 0, ou 2 (erreur, prompt de plus de
// 1 Mio).
func mentionsCommand(args []string, stdin io.Reader, stdout, stderr io.Writer, opener files) int {
	flags := flag.NewFlagSet("mentions", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil || flags.NArg() > 1 {
		_, _ = io.WriteString(stderr, usage)
		return report.ExitError
	}
	content, problem := readContent(flags.Arg(0), stdin, opener)
	if problem != "" {
		return fail(stderr, problem)
	}
	defer clear(content)
	if len(content) > limits.MaxInputBytes {
		return fail(stderr, "prompt de plus de 1 Mio")
	}
	document := struct {
		Mentions []mentionDocument `json:"mentions"`
	}{Mentions: []mentionDocument{}}
	for _, m := range mentions.Parse(content) {
		document.Mentions = append(document.Mentions, mentionDocument{Path: m.Path, Lines: m.Lines, ByteStart: m.ByteStart, ByteEnd: m.ByteEnd})
	}
	data, err := json.Marshal(document)
	if err != nil {
		return fail(stderr, "écriture JSON impossible")
	}
	if _, err := stdout.Write(append(data, '\n')); err != nil {
		return report.ExitError
	}
	return report.ExitClean
}
