package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"strconv"
	"strings"

	"github.com/xsom-consulting/secret-guard/custom"
	"github.com/xsom-consulting/secret-guard/internal/limits"
	"github.com/xsom-consulting/secret-guard/internal/report"
)

// loadCustomPack lit et compile un Pack de règles du client ; le message d'un refus donne son code, jamais le
// contenu du fichier.
func loadCustomPack(name string, opener files) (*custom.Pack, string) {
	data, problem := readBounded(name, opener, custom.MaxPackBytes)
	if problem != "" {
		return nil, "Pack de règles du client : " + problem
	}
	p, err := custom.Compile(data)
	if err != nil {
		return nil, err.Error()
	}
	return p, ""
}

// Bornes du schéma d'un détecteur de termes (schema/CustomPack.json).
const (
	maxTermDigests = 5000
	maxTermWords   = 4
)

// termsMatch est le champ match d'un détecteur de termes.
type termsMatch struct {
	Type     string   `json:"type"`
	Salt     string   `json:"salt"`
	Digests  []string `json:"digests"`
	MaxWords int      `json:"maxWords"`
}

// termsCommand : secret-guard terms digest --salt <sel> [fichier|-]. Lit un terme par ligne et écrit le champ match
// d'un détecteur de termes : condensats SHA-256 salés des termes normalisés (sans doublon, dans l'ordre), maxWords =
// plus grand nombre de mots d'un terme. Aucun terme n'est écrit : un refus donne le numéro de ligne, jamais le terme.
func termsCommand(args []string, stdin io.Reader, stdout, stderr io.Writer, opener files) int {
	if len(args) == 0 || args[0] != "digest" {
		_, _ = io.WriteString(stderr, usage)
		return report.ExitError
	}
	flags := flag.NewFlagSet("terms digest", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	salt := flags.String("salt", "", "")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() > 1 || *salt == "" {
		_, _ = io.WriteString(stderr, usage)
		return report.ExitError
	}
	saltBytes, err := custom.DecodeSalt(*salt)
	if err != nil {
		return fail(stderr, err.Error())
	}
	content, problem := readContent(flags.Arg(0), stdin, opener)
	if problem != "" {
		return fail(stderr, problem)
	}
	defer clear(content)
	if len(content) > limits.MaxInputBytes {
		return fail(stderr, "liste de termes de plus de 1 Mio")
	}
	match := termsMatch{Type: "terms", Salt: *salt, Digests: []string{}}
	seen := map[string]bool{}
	lines := bufio.NewScanner(bytes.NewReader(content))
	lines.Buffer(make([]byte, 0, 4096), limits.MaxInputBytes+1)
	for number := 1; lines.Scan(); number++ {
		line := strings.TrimSuffix(lines.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		digest, words := custom.DigestTerm(saltBytes, line)
		if words == 0 || words > maxTermWords {
			return fail(stderr, "ligne "+strconv.Itoa(number)+" : terme sans mot ou de plus de 4 mots")
		}
		match.MaxWords = max(match.MaxWords, words)
		if !seen[digest] {
			seen[digest] = true
			match.Digests = append(match.Digests, digest)
		}
		if len(match.Digests) > maxTermDigests {
			return fail(stderr, "plus de 5 000 termes")
		}
	}
	if err := lines.Err(); err != nil {
		return fail(stderr, "lecture impossible")
	}
	if len(match.Digests) == 0 {
		return fail(stderr, "aucun terme")
	}
	data, err := json.Marshal(match)
	if err != nil {
		return fail(stderr, "écriture JSON impossible")
	}
	if _, err := stdout.Write(append(data, '\n')); err != nil {
		return report.ExitError
	}
	return report.ExitClean
}
