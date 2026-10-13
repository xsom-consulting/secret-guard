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

/** Types de secret que produisent les règles du catalogue (`SecretType` de Secret Guard, hors types d'échec). */
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
] as const;
export const RuleSecretType = z.enum(RULE_SECRET_TYPES);
export type RuleSecretType = z.infer<typeof RuleSecretType>;

/**
 * Validateurs nommés connus (`docs/rule-pack.md`) ; `''` : aucun validateur. Liste fermée appliquée en code (par le
 * moteur Go, `LoadRules`, qui la compare à cette liste dans ses tests) plutôt qu'en `z.enum` : le générateur de types
 * Go du contrat ne produit pas d'énumération qui contient la chaîne vide.
 */
export const RULE_VALIDATORS = ['', 'jwt_structure'] as const;
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
