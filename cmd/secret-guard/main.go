// Commande secret-guard : analyse un fichier ou l'entrée standard avec le moteur de détection, localement, sans
// réseau, et écrit les constats en JSON, jamais la valeur détectée ; relève aussi les instructions cachées d'un texte
// et les fichiers cités par « @ » dans un prompt.
//
//	secret-guard scan [--pack <fichier>] [--language <id>] [--fingerprint-key <fichier>] [fichier|-]
//	secret-guard hidden [--strip] [fichier|-]
//	secret-guard mentions [fichier|-]
//	secret-guard version
//
// Codes de sortie : 0 analyse complète sans constat ; 1 au moins un constat ; 2 erreur (usage, lecture, Pack refusé)
// ou analyse incomplète (entrée de plus de 1 Mio, budget de travail épuisé), qui ne vaut jamais « rien trouvé ».
package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime/debug"

	"github.com/xsom-consulting/secret-guard/detect"
	"github.com/xsom-consulting/secret-guard/internal/limits"
	"github.com/xsom-consulting/secret-guard/internal/report"
	"github.com/xsom-consulting/secret-guard/pack"
)

const usage = `Usage :
  secret-guard scan [--pack <fichier>] [--language <id>] [--fingerprint-key <fichier>] [fichier|-]
  secret-guard hidden [--strip] [fichier|-]
  secret-guard mentions [fichier|-]
  secret-guard version

scan analyse le fichier donné, ou l'entrée standard (sans fichier, ou « - »), avec le Pack initial embarqué
(--pack : un autre Pack, document JSON du schéma RulePack). Les options précèdent le fichier. Sortie : un document
JSON sur une ligne, {"complete", "failure", "findings": [{"ruleId", "secretType", "encoding", "score", "level",
"byteStart", "byteEnd"}]} ; jamais la valeur détectée.

  --language <id>            identifiant de langage du contenu (« typescript », « dotenv »…), qui change la
                             lecture des affectations
  --fingerprint-key <fichier> clé d'Empreinte locale : 64 caractères hexadécimaux (32 octets), lue, jamais écrite ;
                             chaque constat porte alors localFingerprint (HMAC-SHA256 tronqué). Incompatible avec
                             --language.

Codes de sortie : 0 aucun constat ; 1 au moins un constat ; 2 erreur ou analyse incomplète (entrée de plus de
1 Mio, budget épuisé), qui ne vaut jamais « rien trouvé ».

hidden relève les instructions cachées (caractères d'étiquette Unicode, contrôles bidirectionnels, suites de
caractères invisibles, suites de sélecteurs de variante) : {"complete", "hidden", "findings": [{"kind", "line",
"column", "count", "byteStart", "byteEnd"}]}, jamais ce que les caractères écrivent. --strip écrit à la place le texte
sans ces caractères. Codes de sortie : 0 rien ; 1 au moins un caractère signalé ; 2 erreur ou texte de plus de 1 Mio.

mentions relève les fichiers cités par « @ » dans un prompt (« @chemin », « @"chemin" », « @chemin#L10-20 ») :
{"mentions": [{"path", "lines", "byteStart", "byteEnd"}]}, sans lire ni résoudre aucun fichier. Codes de sortie : 0 ;
2 erreur ou prompt de plus de 1 Mio.
`

// maxKeyFileBytes borne la lecture du fichier de clé : 64 caractères hexadécimaux et une fin de ligne.
const maxKeyFileBytes = 128

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, osFiles{}))
}

// files ouvre les fichiers nommés par l'utilisateur (couture de test).
type files interface {
	Open(name string) (io.ReadCloser, error)
}

type osFiles struct{}

func (osFiles) Open(name string) (io.ReadCloser, error) { return os.Open(name) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, opener files) int {
	if len(args) == 0 {
		_, _ = io.WriteString(stderr, usage)
		return report.ExitError
	}
	switch args[0] {
	case "scan":
		return scan(args[1:], stdin, stdout, stderr, opener)
	case "hidden":
		return hiddenCommand(args[1:], stdin, stdout, stderr, opener)
	case "mentions":
		return mentionsCommand(args[1:], stdin, stdout, stderr, opener)
	case "version":
		if len(args) != 1 {
			_, _ = io.WriteString(stderr, usage)
			return report.ExitError
		}
		return version(stdout, stderr)
	case "help", "-h", "--help", "-help":
		_, _ = io.WriteString(stdout, usage)
		return report.ExitClean
	}
	_, _ = io.WriteString(stderr, usage)
	return report.ExitError
}

func fail(stderr io.Writer, message string) int {
	_, _ = fmt.Fprintf(stderr, "secret-guard : %s\n", message)
	return report.ExitError
}

func scan(args []string, stdin io.Reader, stdout, stderr io.Writer, opener files) int {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	packFile := flags.String("pack", "", "")
	language := flags.String("language", "", "")
	keyFile := flags.String("fingerprint-key", "", "")
	if err := flags.Parse(args); err != nil {
		_, _ = io.WriteString(stderr, usage)
		return report.ExitError
	}
	if flags.NArg() > 1 {
		_, _ = io.WriteString(stderr, usage)
		return report.ExitError
	}
	if *keyFile != "" && *language != "" {
		return fail(stderr, "--fingerprint-key et --language ne se combinent pas")
	}
	rules, problem := loadRules(*packFile, opener)
	if problem != "" {
		return fail(stderr, problem)
	}
	var key *detect.FingerprintKey
	if *keyFile != "" {
		loaded, problem := loadKey(*keyFile, opener)
		if problem != "" {
			return fail(stderr, problem)
		}
		defer loaded.Wipe()
		key = &loaded
	}
	input := stdin
	if name := flags.Arg(0); name != "" && name != "-" {
		file, err := opener.Open(name)
		if err != nil {
			return fail(stderr, "fichier à analyser : "+fileProblem(err))
		}
		defer func() { _ = file.Close() }()
		input = file
	}
	// Au plus MaxInputBytes + 1 octets : au-delà de la limite, le moteur rend scan_limit sans rien analyser.
	content, err := io.ReadAll(io.LimitReader(input, limits.MaxInputBytes+1))
	defer clear(content)
	if err != nil {
		return fail(stderr, "lecture impossible")
	}
	var result detect.Result
	if key != nil {
		result = detect.ScanWithFingerprint(content, rules, *key)
	} else {
		result = detect.Scan(content, rules, detect.Options{LanguageID: *language})
	}
	if _, err := stdout.Write(report.JSON(result)); err != nil {
		return report.ExitError
	}
	return report.ExitCode(result)
}

// loadRules charge le Pack initial embarqué, ou le Pack du fichier nommé ; le message d'un refus ne cite jamais le
// contenu du fichier.
func loadRules(name string, opener files) (*detect.Rules, string) {
	var (
		p   *pack.Pack
		err error
	)
	if name == "" {
		p, err = pack.Initial()
	} else {
		data, problem := readBounded(name, opener, limits.MaxPackBytes)
		if problem != "" {
			return nil, "Pack : " + problem
		}
		p, err = pack.Decode(data)
	}
	if err != nil {
		return nil, err.Error()
	}
	rules, err := detect.LoadRules(p)
	if err != nil {
		return nil, err.Error()
	}
	return rules, ""
}

// loadKey lit la clé d'Empreinte locale : 64 caractères hexadécimaux, une fin de ligne admise. Toutes les copies
// des octets de la clé sont effacées ; la clé n'est jamais écrite.
func loadKey(name string, opener files) (detect.FingerprintKey, string) {
	data, problem := readBounded(name, opener, maxKeyFileBytes)
	defer clear(data)
	if problem != "" {
		return detect.FingerprintKey{}, "clé d'Empreinte locale : " + problem
	}
	text := bytes.TrimSuffix(bytes.TrimSuffix(data, []byte("\n")), []byte("\r"))
	raw := make([]byte, hex.DecodedLen(len(text)))
	defer clear(raw)
	if _, err := hex.Decode(raw, text); err != nil || len(raw) != detect.FingerprintKeyBytes {
		return detect.FingerprintKey{}, "clé d'Empreinte locale : 64 caractères hexadécimaux attendus"
	}
	key, err := detect.NewFingerprintKey(raw)
	if err != nil {
		return detect.FingerprintKey{}, err.Error()
	}
	return key, ""
}

// readBounded lit au plus limit octets d'un fichier ; au-delà, le fichier est refusé.
func readBounded(name string, opener files, limit int) ([]byte, string) {
	file, err := opener.Open(name)
	if err != nil {
		return nil, fileProblem(err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		clear(data)
		return nil, "lecture impossible"
	}
	if len(data) > limit {
		clear(data)
		return nil, "fichier trop grand"
	}
	return data, ""
}

// fileProblem nomme l'échec d'ouverture d'un fichier sans recopier son chemin.
func fileProblem(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "fichier introuvable"
	case errors.Is(err, fs.ErrPermission):
		return "accès refusé"
	}
	return "ouverture impossible"
}

func version(stdout, stderr io.Writer) int {
	moduleVersion := "(devel)"
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		moduleVersion = info.Main.Version
	}
	initial, err := pack.Initial()
	if err != nil {
		return fail(stderr, err.Error())
	}
	_, _ = fmt.Fprintf(stdout, "secret-guard %s\nPack initial : version %d, %d règles\n", moduleVersion,
		initial.PackVersion, len(initial.Rules))
	return report.ExitClean
}
