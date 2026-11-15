// SPDX-License-Identifier: Apache-2.0
import { z } from 'zod';

/**
 * Pack de règles (spécification : `docs/rule-pack.md`) : copie du schéma Zod du contrat signé, dont
 * `schema/RulePack.json` est le JSON Schema. Le générateur s'en sert pour valider le Pack initial ; le moteur Go en a
 * sa propre copie (package `pack`), comparée au JSON Schema par un test. Objets fermés, chaînes et entiers seulement ;
 * valeurs fixes en `z.enum`. Aucun objet indexé par une donnée : les règles sont un tableau.
 */

/**
 * Familles de détection du catalogue Secret Guard (`secret-guard/packages/core/src/rules.ts`) :
 * motif seul, clé privée, URL à identifiants, affectation contextuelle, entropie.
 */
export const RULE_FAMILIES = ['fixed_pattern', 'private_key', 'credential_url', 'contextual_assignment', 'entropy'] as const;
export const RuleFamily = z.enum(RULE_FAMILIES);
export type RuleFamily = z.infer<typeof RuleFamily>;

/**
 * Types de secret que produisent les règles du catalogue (`SecretType` de Secret Guard, hors types d'échec), puis, depuis
 * la v0.7.0, les types des règles de données personnelles ajoutées par xSOM, et, depuis la v0.9.0, ceux des règles de
 * données à contexte (données personnelles annoncées, identifiants d'infrastructure), et, depuis la v0.10.0, ceux des
 * identifiants européens et français.
 */
export const RULE_SECRET_TYPES = [
  'private_key',
  'provider_token',
  'access_token',
  'jwt',
  'database_credentials',
  'cloud_credential',
  'password',
  'api_key',
  'generic_secret',
  'high_entropy',
  // Données personnelles (v0.7.0, `rule-pack/personal-data.ts`).
  'iban',
  'fr_social_security_number',
  'fr_siret',
  'fr_siren',
  'payment_card_number',
  // Données à contexte (v0.9.0, `rule-pack/context-data.ts`).
  'email_address',
  'phone_number',
  'passport_number',
  'payment_card_security_code',
  'one_time_code',
  'internal_ip_address',
  'cloud_resource_address',
  // Identifiants européens et français (v0.10.0, `rule-pack/context-data.ts`) : identifiant national d'une personne,
  // numéro de TVA, compte bancaire (RIB), plaque d'immatriculation, adresse postale.
  'national_identifier',
  'vat_number',
  'bank_account_number',
  'vehicle_registration_plate',
  'postal_address',
] as const;
export const RuleSecretType = z.enum(RULE_SECRET_TYPES);
export type RuleSecretType = z.infer<typeof RuleSecretType>;

/**
 * Validateurs nommés connus (`docs/rule-pack.md`) ; `''` : aucun validateur. Liste fermée appliquée en code (par le
 * moteur Go, `LoadRules`, qui la compare à cette liste dans ses tests) plutôt qu'en `z.enum` : le générateur de types
 * Go du contrat ne produit pas d'énumération qui contient la chaîne vide.
 */
export const RULE_VALIDATORS = [
  '',
  'jwt_structure',
  // Données personnelles (v0.7.0) : IBAN (modulo 97), NIR (clé), SIRET et SIREN (Luhn), carte bancaire (Luhn, réseau).
  'iban_mod97',
  'fr_nir_key',
  'fr_siret_luhn',
  'fr_siren_luhn',
  'payment_card_luhn',
  // Identifiants européens (v0.10.0), contrôles repris de Presidio (MIT) : NIF et NIE espagnols (lettre, modulo 23),
  // code fiscal italien (caractère de contrôle), TVA italienne (Luhn), identifiant fiscal et TVA allemands
  // (ISO 7064 MOD 11,10), PESEL, NHS (modulo 11), personnummer suédois (Luhn), identifiant finlandais (modulo 31).
  'es_nif_mod23',
  'es_nie_mod23',
  'it_fiscal_code_check',
  'it_vat_luhn',
  'de_tax_id_iso7064',
  'de_vat_iso7064',
  'pl_pesel_check',
  'uk_nhs_mod11',
  'se_personnummer_luhn',
  'fi_hetu_mod31',
  // Identifiants français (v0.10.0) : TVA intracommunautaire (clé dérivée du SIREN), RIB (clé modulo 97).
  'fr_vat_key',
  'fr_rib_key',
  // Vraisemblance d'un jeton de fournisseur (v0.10.0) : au moins 6 octets distincts et une entropie de Shannon d'au
  // moins NN dixièmes de bit par octet (`rule-pack/provider-rules.ts`, `detect/validators.go`).
  'token_entropy_25', 'token_entropy_26', 'token_entropy_27', 'token_entropy_28',
  'token_entropy_29', 'token_entropy_30', 'token_entropy_31', 'token_entropy_32',
  'token_entropy_33', 'token_entropy_34', 'token_entropy_35', 'token_entropy_36',
  'token_entropy_37', 'token_entropy_38', 'token_entropy_39', 'token_entropy_40',
  'token_entropy_41', 'token_entropy_42', 'token_entropy_43', 'token_entropy_44',
  'token_entropy_45',
] as const;
export type RuleValidator = (typeof RULE_VALIDATORS)[number];

/**
 * Familles dont chaque règle porte un motif (`pattern` non vide). Seule `contextual_assignment` peut avoir un motif
 * vide (règle qui combine plusieurs motifs : logique du moteur).
 */
export const RULE_FAMILIES_WITH_PATTERN = ['fixed_pattern', 'private_key', 'credential_url', 'entropy'] as const satisfies readonly RuleFamily[];

/** Nombre maximal de règles d'un Pack. */
export const RULE_PACK_MAX_RULES = 1_000;

/** Longueur maximale d'un motif RE2, en unités UTF-16. */
export const RULE_PATTERN_MAX_LENGTH = 4_096;

/** Borne maximale de `minLength` / `maxLength` : la taille maximale d'une entrée analysée (1 Mio). */
export const RULE_LENGTH_BOUND_MAX = 1_048_576;

/** Identifiant de règle ou nom de validateur : minuscules ASCII, chiffres et `_`, 64 caractères au plus. */
const Identifier = z
  .string()
  .max(64)
  .regex(/^[a-z][a-z0-9_]*$/);

const LengthBound = z.int().min(0).max(RULE_LENGTH_BOUND_MAX);

/**
 * Règle du Pack. `pattern` : motif en syntaxe RE2 (`regexp` de Go), chaîne vide quand la logique de la règle est du
 * code du moteur. `validator` : validateur nommé, chaîne vide sinon. `minLength` / `maxLength` : bornes de longueur
 * contrôlées en code (reportées des répétitions de plus de 1 000 du motif d'origine), 0 si absentes.
 */
export const RulePackRule = z.strictObject({
  ruleId: Identifier,
  family: RuleFamily,
  secretType: RuleSecretType,
  score: z.int().min(0).max(100),
  validator: z
    .string()
    .max(64)
    .regex(/^(?:[a-z][a-z0-9_]*)?$/),
  pattern: z.string().max(RULE_PATTERN_MAX_LENGTH),
  minLength: LengthBound,
  maxLength: LengthBound,
});
export type RulePackRule = z.infer<typeof RulePackRule>;

/** Version d'agent minimale : semver `MAJEUR.MINEUR.CORRECTIF`, sans pré-version ni métadonnées. */
export const SemVer = z.string().regex(/^(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})$/);

/** Horodatage UTC `AAAA-MM-JJTHH:MM:SSZ` ou `AAAA-MM-JJTHH:MM:SS.mmmZ` (forme ; l'existence est vérifiée en code). */
export const UtcTimestamp = z.string().regex(/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3})?Z$/);

/** Pack de règles : `schemaVersion` et `minAgentVersion` permettent à un lecteur de refuser un Pack trop récent. */
export const RulePack = z.strictObject({
  schemaVersion: z.int().min(1).max(1_000_000),
  minAgentVersion: SemVer,
  packVersion: z.int().min(1).max(Number.MAX_SAFE_INTEGER),
  issuedAt: UtcTimestamp,
  rules: z.array(RulePackRule).min(1).max(RULE_PACK_MAX_RULES),
});
export type RulePack = z.infer<typeof RulePack>;
