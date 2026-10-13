// Package pack est le Pack de règles lu par le moteur de détection : mêmes champs et mêmes noms JSON que le schéma
// RulePack (schema/RulePack.json, spécification docs/rule-pack.md), décodage strict par Decode, et Pack initial
// embarqué (Initial, InitialJSON), traduit du catalogue de règles de Secret Guard.
//
// Le moteur n'a qu'une copie du contrat : celui qui signe et distribue des Packs reste la source du schéma. Un test
// compare ce paquet à schema/RulePack.json (champs, obligation, énumérations, bornes, motifs).
//
// Le paquet est pur : ni E/S, ni réseau, ni horloge, ni hasard.
package pack

// Family est la famille de détection d'une règle (RULE_FAMILIES).
type Family string

// Familles de détection.
const (
	FamilyFixedPattern         Family = "fixed_pattern"
	FamilyPrivateKey           Family = "private_key"
	FamilyCredentialURL        Family = "credential_url"
	FamilyContextualAssignment Family = "contextual_assignment"
	FamilyEntropy              Family = "entropy"
)

// Families rend la liste fermée des familles, dans l'ordre du schéma.
func Families() []Family {
	return []Family{FamilyFixedPattern, FamilyPrivateKey, FamilyCredentialURL, FamilyContextualAssignment, FamilyEntropy}
}

// SecretType est le type de secret que produit une règle (RULE_SECRET_TYPES).
type SecretType string

// Types de secret.
const (
	SecretTypePrivateKey          SecretType = "private_key"
	SecretTypeProviderToken       SecretType = "provider_token"
	SecretTypeAccessToken         SecretType = "access_token"
	SecretTypeJWT                 SecretType = "jwt"
	SecretTypeDatabaseCredentials SecretType = "database_credentials"
	SecretTypeCloudCredential     SecretType = "cloud_credential"
	SecretTypePassword            SecretType = "password"
	SecretTypeAPIKey              SecretType = "api_key"
	SecretTypeGenericSecret       SecretType = "generic_secret"
	SecretTypeHighEntropy         SecretType = "high_entropy"
)

// SecretTypes rend la liste fermée des types de secret, dans l'ordre du schéma.
func SecretTypes() []SecretType {
	return []SecretType{
		SecretTypePrivateKey, SecretTypeProviderToken, SecretTypeAccessToken, SecretTypeJWT,
		SecretTypeDatabaseCredentials, SecretTypeCloudCredential, SecretTypePassword, SecretTypeAPIKey,
		SecretTypeGenericSecret, SecretTypeHighEntropy,
	}
}

// Pack est un Pack de règles : version du schéma, version minimale du programme qui l'exécute, version du Pack,
// date d'émission et règles, dans l'ordre du catalogue.
type Pack struct {
	SchemaVersion   int    `json:"schemaVersion"`
	MinAgentVersion string `json:"minAgentVersion"`
	PackVersion     int64  `json:"packVersion"`
	IssuedAt        string `json:"issuedAt"`
	Rules           []Rule `json:"rules"`
}

// Rule est une règle du Pack. Pattern est un motif RE2 (regexp de Go), vide quand la logique de la règle est du code
// du moteur ; Validator est un validateur nommé, vide sinon ; MinLength et MaxLength sont des bornes de longueur de
// la valeur détectée, en unités UTF-16, 0 si absentes.
type Rule struct {
	RuleID     string     `json:"ruleId"`
	Family     Family     `json:"family"`
	SecretType SecretType `json:"secretType"`
	Score      int        `json:"score"`
	Validator  string     `json:"validator"`
	Pattern    string     `json:"pattern"`
	MinLength  int        `json:"minLength"`
	MaxLength  int        `json:"maxLength"`
}
