// SPDX-License-Identifier: Apache-2.0

// Code généré par generator/rule-pack/generate-initial-pack.ts (npm run pack:initial) ; ne pas modifier.

package detect

// contextSubstituteLabels : types de secret des règles de données à contexte du Pack initial (v0.9.0), dans
// l'ordre du Pack. Source : generator/rule-pack/context-data.ts.
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
}

// contextOptInRuleIDs : règles « à activer » (optin.go), dans l'ordre du Pack. Même source.
var contextOptInRuleIDs = []string{"email_address"}
