// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// blob est un fichier d'un commit : chemin (barres obliques), objet git, taille en octets.
type blob struct {
	path, object string
	size         int
}

// languages : extensions analysées, et l'identifiant de langage de chacune pour l'option -language (vide : aucun).
// Code et documentation ; les images, archives et binaires n'y sont pas.
var languages = map[string]string{
	".ts": "typescript", ".mts": "typescript", ".tsx": "typescriptreact", ".js": "javascript", ".mjs": "javascript",
	".go": "go", ".py": "python", ".sh": "shellscript", ".yml": "yaml", ".yaml": "yaml", ".json": "json",
	".toml": "toml", ".tf": "terraform", ".md": "", ".sql": "", ".ps1": "", ".html": "", ".css": "",
}

// skippedPaths : fichiers écartés de la mesure. Corpus, vecteurs et jeux d'essai portent des valeurs à forme de
// secret voulues ; les fichiers de verrou, les instantanés et les dossiers de dépendances ne sont pas du code écrit à
// la main.
var skippedPaths = regexp.MustCompile(`(^|/)(vectors|corpus|testdata|fixtures|node_modules|dist|_bmad|\.git)/|` +
	`pack\.json$|oracle\.json$|package-lock\.json$|pnpm-lock\.yaml$|go\.sum$|\.snap$|provider-rules\.json$|i18n/`)

func languageOf(file string) string { return languages[path.Ext(file)] }

func git(dir string, args ...string) ([]byte, error) {
	command := exec.Command("git", append([]string{"-C", dir}, args...)...)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	out, err := command.Output()
	if err != nil {
		// Message de git seulement (nom de révision, dépôt absent) : jamais un contenu de fichier.
		return nil, fmt.Errorf("git %s : %s", args[0], strings.TrimSpace(firstLine(stderr.String())))
	}
	return out, nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// resolveCommit rend l'identifiant complet du commit que rev désigne.
func resolveCommit(dir, rev string) (string, error) {
	if strings.HasPrefix(rev, "-") {
		return "", errors.New("révision refusée")
	}
	out, err := git(dir, "rev-parse", "--verify", "--quiet", rev+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("commit %s introuvable dans le dépôt", rev)
	}
	return strings.TrimSpace(string(out)), nil
}

// listBlobs rend les fichiers ordinaires du commit (ni lien symbolique, ni sous-module), triés par chemin.
func listBlobs(dir, commit string) ([]blob, error) {
	out, err := git(dir, "ls-tree", "-r", "-l", "-z", commit)
	if err != nil {
		return nil, err
	}
	var blobs []blob
	for _, entry := range bytes.Split(out, []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		meta, file, ok := strings.Cut(string(entry), "\t")
		fields := strings.Fields(meta)
		if !ok || len(fields) != 4 {
			return nil, errors.New("git ls-tree : ligne inattendue")
		}
		if fields[1] != "blob" || fields[0] == "120000" {
			continue
		}
		size, err := strconv.Atoi(fields[3])
		if err != nil {
			return nil, errors.New("git ls-tree : taille inattendue")
		}
		blobs = append(blobs, blob{path: file, object: fields[2], size: size})
	}
	sort.Slice(blobs, func(i, j int) bool { return blobs[i].path < blobs[j].path })
	return blobs, nil
}

// selectBlobs garde les fichiers analysés : extension connue, chemin non écarté, 1 Mio au plus. Avec limit, il en
// garde limit par un tirage déterministe (ordre du SHA-256 du chemin) : le même sur toute machine, à tout moment.
func selectBlobs(blobs []blob, limit int) []blob {
	var kept []blob
	for _, b := range blobs {
		if _, known := languages[path.Ext(b.path)]; !known || skippedPaths.MatchString(b.path) || b.size > maxFileBytes {
			continue
		}
		kept = append(kept, b)
	}
	if limit <= 0 || len(kept) <= limit {
		return kept
	}
	rank := func(b blob) string {
		sum := sha256.Sum256([]byte("bruit:" + b.path))
		return string(sum[:])
	}
	sort.Slice(kept, func(i, j int) bool { return rank(kept[i]) < rank(kept[j]) })
	kept = kept[:limit]
	sort.Slice(kept, func(i, j int) bool { return kept[i].path < kept[j].path })
	return kept
}

// readBlobs lit le contenu de chaque fichier dans la base d'objets de git (« git cat-file --batch » : l'octet exact
// du commit, sans filtre ni conversion de fin de ligne) et le passe à visit, dans l'ordre.
func readBlobs(dir string, blobs []blob, visit func(index int, content []byte)) (err error) {
	command := exec.Command("git", "-C", dir, "cat-file", "--batch")
	stdin, err := command.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return errors.New("git cat-file : lancement impossible")
	}
	defer func() {
		_ = stdin.Close()
		if waitErr := command.Wait(); err == nil && waitErr != nil {
			err = errors.New("git cat-file : échec")
		}
	}()
	reader := bufio.NewReaderSize(stdout, 1<<16)
	for i, b := range blobs {
		if _, err := io.WriteString(stdin, b.object+"\n"); err != nil {
			return errors.New("git cat-file : écriture impossible")
		}
		header, err := reader.ReadString('\n')
		if err != nil {
			return errors.New("git cat-file : lecture impossible")
		}
		fields := strings.Fields(header)
		if len(fields) != 3 || fields[1] != "blob" {
			return errors.New("git cat-file : objet inattendu")
		}
		size, err := strconv.Atoi(fields[2])
		if err != nil || size != b.size {
			return errors.New("git cat-file : taille inattendue")
		}
		content := make([]byte, size+1)
		if _, err := io.ReadFull(reader, content); err != nil {
			return errors.New("git cat-file : lecture impossible")
		}
		visit(i, content[:size])
	}
	return nil
}
