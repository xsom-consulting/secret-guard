// SPDX-License-Identifier: Apache-2.0

// Code généré par generator/rule-pack/generate-initial-pack.ts (npm run pack:initial) ; ne pas modifier.

package detect

// contextSubstituteLabels : types de secret des règles de données à contexte du Pack initial (v0.9.0, puis
// identifiants européens et français et règle composée AWS de la v0.10.0), dans l'ordre du Pack. Source :
// generator/rule-pack/context-data.ts.
var contextSubstituteLabels = []SubstituteLabel{
	{"email_address", "adresse \u00e9lectronique", "email address"},
	{"phone_number", "num\u00e9ro de t\u00e9l\u00e9phone", "phone number"},
	{"passport_number", "num\u00e9ro de passeport", "passport number"},
	{"payment_card_security_code", "cryptogramme de carte bancaire", "payment card security code"},
	{"one_time_code", "code \u00e0 usage unique", "one-time code"},
	{"azure_shared_access_key", "cl\u00e9 d\u2019acc\u00e8s partag\u00e9 Azure", "Azure shared access key"},
	{"internal_ip_address", "adresse IP interne", "internal IP address"},
	{"aws_arn", "ARN AWS", "AWS ARN"},
	{"aws_s3_bucket", "adresse de bucket S3", "S3 bucket address"},
	{"aws_rds_endpoint", "adresse de base RDS", "RDS endpoint"},
	{"aws_dynamodb_endpoint", "adresse DynamoDB", "DynamoDB endpoint"},
	{"es_nif", "num\u00e9ro d\u2019identit\u00e9 espagnol", "Spanish identity number"},
	{"es_nie", "num\u00e9ro d\u2019\u00e9tranger espagnol", "Spanish foreigner identity number"},
	{"it_fiscal_code", "code fiscal italien", "Italian fiscal code"},
	{"it_vat", "num\u00e9ro de TVA italien", "Italian VAT number"},
	{"de_tax_id", "identifiant fiscal allemand", "German tax identification number"},
	{"de_vat", "num\u00e9ro de TVA allemand", "German VAT number"},
	{"pl_pesel", "num\u00e9ro PESEL", "PESEL number"},
	{"uk_nhs", "num\u00e9ro NHS", "NHS number"},
	{"se_personnummer", "num\u00e9ro personnel su\u00e9dois", "Swedish personal identity number"},
	{"fi_personal_identity_code", "identifiant personnel finlandais", "Finnish personal identity code"},
	{"fr_vat", "num\u00e9ro de TVA intracommunautaire", "French VAT number"},
	{"fr_rib", "relev\u00e9 d\u2019identit\u00e9 bancaire", "French bank account details"},
	{"fr_license_plate", "plaque d\u2019immatriculation", "vehicle registration plate"},
	{"fr_postal_address", "adresse postale", "postal address"},
	{"aws_access_key_pair", "paire de cl\u00e9s d\u2019acc\u00e8s AWS", "AWS access key pair"},
}

// contextOptInRuleIDs : règles « à activer » (optin.go), dans l'ordre du Pack. Même source.
var contextOptInRuleIDs = []string{"email_address", "fr_postal_address"}
