// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/xsom-consulting/secret-guard/detect"
)

// Sortes de constats classés par forme.
const (
	shapeKindAssignment = "assignment"
	shapeKindEntropy    = "entropy"
)

// Formes de la valeur d'un constat d'affectation (règles « contextual_… »). Les treize premières sont des valeurs
// sans guillemets : du code, pas un littéral.
const (
	shapeCITemplate     = "gabarit de CI ${{ … }}"
	shapeCommand        = "substitution de commande"
	shapeShellReference = "référence de variable de shell"
	shapeTemplate       = "gabarit {{ … }}"
	shapeArray          = "tableau"
	shapeObject         = "objet"
	shapeKeyword        = "mot-clé de code"
	shapeType           = "annotation de type"
	shapeCall           = "appel de fonction"
	shapeMember         = "référence de code (a.b, a[b])"
	shapeExpression     = "expression"
	shapeIdentifier     = "identifiant nu"
	shapeNumber         = "nombre"
	shapeOtherUnquoted  = "autre valeur sans guillemets"
	shapeInterpolation  = "chaîne à interpolation"
	shapeQuotedShell    = "chaîne qui commence par une référence de shell"
	shapeWeakLiteral    = "littéral court ou banal"
	shapeProse          = "littéral en langue naturelle"
	shapeCodeWord       = "littéral mot de code"
	shapeSingleWord     = "littéral d'un seul mot"
	shapeSecretLike     = "littéral à forme possible de secret"
	shapeEncodedView    = "vue décodée"
)

// Formes de la valeur d'un constat d'entropie (règle high_entropy).
const (
	shapeCamel        = "identifiant en casse de chameau"
	shapeURLPath      = "chemin d'URL"
	shapePath         = "chemin"
	shapeUnderscores  = "nom à soulignés"
	shapeDashes       = "nom à tirets"
	shapeHexadecimal  = "hexadécimal"
	shapeBase64Signs  = "base64 à signes (+, =)"
	shapeAlphanumeric = "autre suite alphanumérique"
)

var (
	reCITemplate     = regexp.MustCompile(`^\$\{\{`)
	reCommand        = regexp.MustCompile("^(?:\\$\\(|`)")
	reShellReference = regexp.MustCompile(`^(?:"?\$\{?[A-Za-z_0-9@#?*!]|"\$)`)
	reTemplate       = regexp.MustCompile(`^\{\{`)
	reKeyword        = regexp.MustCompile(`^(?:return|await|new|yield|throw|typeof|not|lambda|if|else|for|while|function|async|def|class)\b`)
	reType           = regexp.MustCompile(`^(?:str|int|bool|bytes|float|string|number|boolean|unknown|any|never|void|object|Optional|Union|` +
		`List|Dict|Annotated|Literal|Secret[A-Za-z]*|Buffer|Uint8Array|Promise|Record|Map|Set|Array|` +
		`Readonly[A-Za-z]*|[A-Z][A-Za-z0-9_]*)(?:\[|<|\)|\s*[|;,=)]|\s*$|\s*\||\s+\|)`)
	reCall           = regexp.MustCompile(`^[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)*\s*\(`)
	reMember         = regexp.MustCompile(`^[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*|\[[^\]]*\])+\s*(?:[,;)\]}]|$|\s)`)
	reExpression     = regexp.MustCompile(`^(?:\(|=>|<[A-Za-z])`)
	reIdentifier     = regexp.MustCompile(`^([A-Za-z_$][\w$]*)\s*(?:[,;)\]}]|$)`)
	reNumber         = regexp.MustCompile(`^[+-]?\d+(?:\.\d+)?\s*(?:[,;)\]}]|$)`)
	reBraceReference = regexp.MustCompile(`\{[A-Za-z_][\w.]*\}`)
	reLowerCodeWord  = regexp.MustCompile(`^[a-z]+(?:[_-][a-z]+)*$`)
	reUpperCodeWord  = regexp.MustCompile(`^[A-Z]+(?:_[A-Z0-9]+)*$`)
	reLetters        = regexp.MustCompile(`^[A-Za-z]+$`)
	reQuote          = regexp.MustCompile("[\"'`]")
	reHexadecimal    = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	reCamel          = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)
)

// weakLiterals : littéraux banals, qu'aucun lecteur ne prend pour un secret. Écrits en une suite de mots : ce
// fichier ne porte aucune affectation à un nom sensible.
var weakLiterals = func() map[string]bool {
	set := map[string]bool{}
	for _, word := range strings.Fields("test tests testing password passwd pass secret token changeme admin root " +
		"postgres postgresql mysql redis example dummy fake mock foo bar baz none null string user guest default key " +
		"apikey api_key api-key value xxx abc abc123 123456 1234 12345 12345678 qwerty letmein demo sample placeholder") {
		set[word] = true
	}
	return set
}()

// shapeOf classe un constat par la forme de sa valeur : sorte (affectation, entropie, ou vide pour les autres règles)
// et forme. Il lit la valeur dans content et n'en rend jamais rien.
func shapeOf(content []byte, f detect.Finding) (kind, shape string) {
	switch {
	case strings.HasPrefix(f.RuleID, "contextual_"):
		kind = shapeKindAssignment
	case f.RuleID == "high_entropy":
		kind = shapeKindEntropy
	default:
		return "", ""
	}
	if f.Encoding != detect.EncodingPlain || f.ByteStart < 0 || f.ByteEnd > len(content) || f.ByteStart > f.ByteEnd {
		return kind, shapeEncodedView
	}
	value := content[f.ByteStart:f.ByteEnd]
	if kind == shapeKindEntropy {
		return kind, entropyShape(content[:f.ByteStart], value)
	}
	var before byte
	if f.ByteStart > 0 {
		before = content[f.ByteStart-1]
	}
	return kind, assignmentShape(before, value)
}

// assignmentShape classe la valeur d'une affectation ; before est l'octet qui la précède (un guillemet : la valeur
// est un littéral).
func assignmentShape(before byte, value []byte) string {
	s := strings.TrimSpace(string(value))
	if before != '"' && before != '\'' && before != '`' {
		switch {
		case reCITemplate.MatchString(s):
			return shapeCITemplate
		case reCommand.MatchString(s):
			return shapeCommand
		case reShellReference.MatchString(s):
			return shapeShellReference
		case reTemplate.MatchString(s):
			return shapeTemplate
		case strings.HasPrefix(s, "["):
			return shapeArray
		case strings.HasPrefix(s, "{"):
			return shapeObject
		case reKeyword.MatchString(s):
			return shapeKeyword
		case reType.MatchString(s):
			return shapeType
		case reCall.MatchString(s):
			return shapeCall
		case reMember.MatchString(s):
			return shapeMember
		case reExpression.MatchString(s):
			return shapeExpression
		case reNumber.MatchString(s):
			return shapeNumber
		}
		if m := reIdentifier.FindStringSubmatch(s); m != nil && len(m[1]) < 40 {
			return shapeIdentifier
		}
		return shapeOtherUnquoted
	}
	if strings.Contains(s, "${") || reBraceReference.MatchString(s) || strings.Contains(s, "%s") || strings.Contains(s, "{}") {
		return shapeInterpolation
	}
	if strings.HasPrefix(s, "$") {
		return shapeQuotedShell
	}
	first := reQuote.Split(s, 2)[0]
	switch {
	case weakLiterals[strings.ToLower(first)] || len(first) < 8:
		return shapeWeakLiteral
	case strings.Contains(strings.TrimSpace(first), " "):
		return shapeProse
	case reLowerCodeWord.MatchString(first) || reUpperCodeWord.MatchString(first):
		return shapeCodeWord
	case reLetters.MatchString(first):
		return shapeSingleWord
	}
	return shapeSecretLike
}

// urlLookBehind borne la recherche d'un schéma d'URL avant une suite d'entropie.
const urlLookBehind = 256

// entropyShape classe la valeur d'un constat d'entropie ; before est le texte qui la précède.
func entropyShape(before, value []byte) string {
	switch {
	case bytes.ContainsAny(value, "+="):
		return shapeBase64Signs
	case reHexadecimal.Match(value):
		return shapeHexadecimal
	case inURL(before):
		return shapeURLPath
	case bytes.IndexByte(value, '/') >= 0:
		return shapePath
	case bytes.IndexByte(value, '_') >= 0:
		return shapeUnderscores
	case bytes.IndexByte(value, '-') >= 0:
		return shapeDashes
	case reCamel.Match(value) && isCamel(value):
		return shapeCamel
	}
	return shapeAlphanumeric
}

// inURL dit si la suite qui commence après before fait partie d'une URL : « :// » dans le mot qui la précède, sans
// blanc ni guillemet entre les deux.
func inURL(before []byte) bool {
	from := max(0, len(before)-urlLookBehind)
	word := before[from:]
	if cut := bytes.LastIndexAny(word, " \t\r\n\"'`<>()"); cut >= 0 {
		word = word[cut+1:]
	}
	return bytes.Contains(word, []byte("://"))
}

// isCamel dit si value, faite de lettres et de chiffres, a la forme d'un identifiant en casse de chameau : au moins
// deux bosses (une majuscule suivie d'une minuscule), ou une minuscule en tête et une bosse, et au plus un chiffre
// pour six caractères.
func isCamel(value []byte) bool {
	humps, digits := 0, 0
	for i, c := range value {
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'A' && c <= 'Z' && i+1 < len(value) && value[i+1] >= 'a' && value[i+1] <= 'z':
			humps++
		}
	}
	if value[0] >= 'a' && value[0] <= 'z' {
		humps++
	}
	return humps >= 2 && digits*6 <= len(value)
}
