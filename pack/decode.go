// Décodage strict d'un Pack de règles : schéma RulePack appliqué en entier, sans tolérance.

package pack

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/xsom-consulting/secret-guard/internal/limits"
)

// ErrInvalidPack : le document n'est pas un Pack qui respecte le schéma RulePack. Toute erreur de Decode l'enveloppe
// (errors.Is) ; son message donne le chemin JSON et la raison, jamais une valeur du document.
var ErrInvalidPack = errors.New("pack : document refusé")

// DecodeError est l'erreur typée d'un document refusé : chemin JSON (pointeur RFC 6901, vide pour le document) et
// raison en texte fixe.
type DecodeError struct {
	Path   string
	Reason string
}

func (e *DecodeError) Error() string {
	if e.Path == "" {
		return ErrInvalidPack.Error() + " : " + e.Reason
	}
	return ErrInvalidPack.Error() + " : " + e.Path + " : " + e.Reason
}

// Unwrap rattache le refus à ErrInvalidPack.
func (e *DecodeError) Unwrap() error { return ErrInvalidPack }

func refuse(path, reason string) error { return &DecodeError{Path: path, Reason: reason} }

// Motifs du schéma RulePack (écrits tels quels dans schema/RulePack.json ; même sens en RE2 qu'en JavaScript).
const (
	identifierPattern = `^[a-z][a-z0-9_]*$`
	validatorPattern  = `^(?:[a-z][a-z0-9_]*)?$`
	semVerPattern     = `^(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})$`
	timestampPattern  = `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3})?Z$`
)

var (
	identifierForm = regexp.MustCompile(identifierPattern)
	validatorForm  = regexp.MustCompile(validatorPattern)
	semVerForm     = regexp.MustCompile(semVerPattern)
	timestampForm  = regexp.MustCompile(timestampPattern)
)

// rawPack et rawRule reçoivent le document : un pointeur nil est un champ absent ou null, refusé.
type rawPack struct {
	SchemaVersion   *int64      `json:"schemaVersion"`
	MinAgentVersion *string     `json:"minAgentVersion"`
	PackVersion     *int64      `json:"packVersion"`
	IssuedAt        *string     `json:"issuedAt"`
	Rules           *[]*rawRule `json:"rules"`
}

type rawRule struct {
	RuleID     *string `json:"ruleId"`
	Family     *string `json:"family"`
	SecretType *string `json:"secretType"`
	Score      *int64  `json:"score"`
	Validator  *string `json:"validator"`
	Pattern    *string `json:"pattern"`
	MinLength  *int64  `json:"minLength"`
	MaxLength  *int64  `json:"maxLength"`
}

// Decode lit un Pack de règles et le refuse (ErrInvalidPack) s'il ne respecte pas exactement le schéma RulePack :
// document de plus de limits.MaxPackBytes octets, JSON invalide (UTF-8 invalide, substitut isolé, contenu après le
// document), membre inconnu ou en double (noms comparés à la casse près), champ absent ou null, type différent,
// nombre non entier, énumération, motif ou borne du schéma non respectés, horodatage issuedAt qui n'existe pas.
//
// Decode ne juge pas l'exécution des règles (motif RE2, validateur, règles du moteur) : c'est le rôle de
// detect.LoadRules.
func Decode(data []byte) (*Pack, error) {
	if len(data) > limits.MaxPackBytes {
		return nil, refuse("", "document trop grand")
	}
	var raw rawPack
	if err := json.Unmarshal(data, &raw, json.RejectUnknownMembers(true)); err != nil {
		return nil, jsonRefusal(err)
	}
	return raw.pack()
}

// jsonRefusal rend une erreur de lecture sans le texte de encoding/json, qui peut citer le document : chemin JSON et
// raison fixe. Pour un membre inconnu ou en double, le chemin est celui de l'objet, sans le nom du membre.
func jsonRefusal(err error) error {
	var semantic *json.SemanticError
	if errors.As(err, &semantic) {
		if errors.Is(err, json.ErrUnknownName) {
			return refuse(parent(semantic.JSONPointer), "membre inconnu")
		}
		return refuse(string(semantic.JSONPointer), "type ou nombre invalide")
	}
	var syntactic *jsontext.SyntacticError
	if errors.As(err, &syntactic) {
		if errors.Is(err, jsontext.ErrDuplicateName) {
			return refuse(parent(syntactic.JSONPointer), "membre en double")
		}
		return refuse(string(syntactic.JSONPointer), "JSON invalide")
	}
	return refuse("", "JSON invalide")
}

// parent rend le pointeur JSON de l'objet qui contient le membre désigné (un « / » d'un nom est écrit « ~1 »).
func parent(pointer jsontext.Pointer) string {
	text := string(pointer)
	if i := strings.LastIndexByte(text, '/'); i >= 0 {
		return text[:i]
	}
	return ""
}

func (raw rawPack) pack() (*Pack, error) {
	switch {
	case raw.SchemaVersion == nil:
		return nil, refuse("/schemaVersion", "champ absent ou null")
	case raw.MinAgentVersion == nil:
		return nil, refuse("/minAgentVersion", "champ absent ou null")
	case raw.PackVersion == nil:
		return nil, refuse("/packVersion", "champ absent ou null")
	case raw.IssuedAt == nil:
		return nil, refuse("/issuedAt", "champ absent ou null")
	case raw.Rules == nil:
		return nil, refuse("/rules", "champ absent ou null")
	}
	if *raw.SchemaVersion < 1 || *raw.SchemaVersion > limits.MaxSchemaVersion {
		return nil, refuse("/schemaVersion", "hors bornes")
	}
	if !semVerForm.MatchString(*raw.MinAgentVersion) {
		return nil, refuse("/minAgentVersion", "forme invalide")
	}
	if *raw.PackVersion < 1 || *raw.PackVersion > limits.MaxPackVersion {
		return nil, refuse("/packVersion", "hors bornes")
	}
	if !timestampForm.MatchString(*raw.IssuedAt) || !timestampExists(*raw.IssuedAt) {
		return nil, refuse("/issuedAt", "horodatage invalide")
	}
	rules := *raw.Rules
	if len(rules) < 1 || len(rules) > limits.MaxRules {
		return nil, refuse("/rules", "nombre de règles hors bornes")
	}
	p := &Pack{
		SchemaVersion: int(*raw.SchemaVersion), MinAgentVersion: *raw.MinAgentVersion, PackVersion: *raw.PackVersion,
		IssuedAt: *raw.IssuedAt, Rules: make([]Rule, 0, len(rules)),
	}
	for i, r := range rules {
		rule, err := r.rule(rulePath(i))
		if err != nil {
			return nil, err
		}
		p.Rules = append(p.Rules, rule)
	}
	return p, nil
}

func rulePath(i int) string { return "/rules/" + strconv.Itoa(i) }

func (r *rawRule) rule(path string) (Rule, error) {
	if r == nil {
		return Rule{}, refuse(path, "règle null")
	}
	for _, field := range []struct {
		name    string
		present bool
	}{
		{"ruleId", r.RuleID != nil}, {"family", r.Family != nil}, {"secretType", r.SecretType != nil},
		{"score", r.Score != nil}, {"validator", r.Validator != nil}, {"pattern", r.Pattern != nil},
		{"minLength", r.MinLength != nil}, {"maxLength", r.MaxLength != nil},
	} {
		if !field.present {
			return Rule{}, refuse(path+"/"+field.name, "champ absent ou null")
		}
	}
	if len(*r.RuleID) > limits.MaxIdentifierLength || !identifierForm.MatchString(*r.RuleID) {
		return Rule{}, refuse(path+"/ruleId", "forme invalide")
	}
	family := Family(*r.Family)
	if !knownFamily(family) {
		return Rule{}, refuse(path+"/family", "famille inconnue")
	}
	secretType := SecretType(*r.SecretType)
	if !knownSecretType(secretType) {
		return Rule{}, refuse(path+"/secretType", "type de secret inconnu")
	}
	if *r.Score < 0 || *r.Score > limits.MaxScore {
		return Rule{}, refuse(path+"/score", "hors bornes")
	}
	if len(*r.Validator) > limits.MaxIdentifierLength || !validatorForm.MatchString(*r.Validator) {
		return Rule{}, refuse(path+"/validator", "forme invalide")
	}
	if utf16Units(*r.Pattern) > limits.MaxPatternUnits {
		return Rule{}, refuse(path+"/pattern", "motif trop long")
	}
	for _, bound := range []struct {
		name  string
		value int64
	}{{"minLength", *r.MinLength}, {"maxLength", *r.MaxLength}} {
		if bound.value < 0 || bound.value > limits.MaxLengthBound {
			return Rule{}, refuse(path+"/"+bound.name, "hors bornes")
		}
	}
	return Rule{
		RuleID: *r.RuleID, Family: family, SecretType: secretType, Score: int(*r.Score), Validator: *r.Validator,
		Pattern: *r.Pattern, MinLength: int(*r.MinLength), MaxLength: int(*r.MaxLength),
	}, nil
}

func knownFamily(f Family) bool {
	for _, known := range Families() {
		if f == known {
			return true
		}
	}
	return false
}

func knownSecretType(s SecretType) bool {
	for _, known := range SecretTypes() {
		if s == known {
			return true
		}
	}
	return false
}

// utf16Units compte les unités UTF-16 de s (longueur d'une chaîne JavaScript), UTF-8 déjà vérifié par la lecture.
func utf16Units(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

// timestampExists vérifie qu'un horodatage de la forme du schéma désigne un instant qui existe (mois, jour du mois,
// année bissextile, heure, minute, seconde), sans horloge.
func timestampExists(s string) bool {
	number := func(from, to int) int {
		n := 0
		for _, c := range s[from:to] {
			n = n*10 + int(c-'0')
		}
		return n
	}
	year, month, day := number(0, 4), number(5, 7), number(8, 10)
	hour, minute, second := number(11, 13), number(14, 16), number(17, 19)
	if month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59 {
		return false
	}
	days := [...]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}[month-1]
	if month == 2 && year%4 == 0 && (year%100 != 0 || year%400 == 0) {
		days = 29
	}
	return day <= days
}
