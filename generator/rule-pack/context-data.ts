// SPDX-License-Identifier: Apache-2.0
/**
 * Règles de données à contexte du Pack initial (v0.9.0) : données personnelles annoncées par un mot-clé (adresse
 * électronique, téléphone, passeport, cryptogramme de carte, code à usage unique) et identifiants d'infrastructure
 * (clé d'accès partagé d'une chaîne de connexion Azure, adresse IP privée annoncée comme interne, adresses de
 * ressources AWS : ARN, bucket S3, point d'accès RDS, point d'accès DynamoDB). Extension propre à ce dépôt, sans
 * origine dans Secret Guard : ces règles viennent après les règles de fournisseurs.
 *
 * Chaque règle est une règle « motif seul » (`fixed_pattern`), sans validateur : le moteur l'exécute telle que le Pack
 * la décrit, la valeur détectée est son unique groupe capturant (la correspondance entière s'il n'en a pas).
 *
 * Technique : une forme générique (une adresse, dix chiffres, trois chiffres…) n'est un constat que si un mot-clé de
 * contexte la précède de près, sur la même ligne. C'est la technique des motifs de données personnelles d'Akto
 * (akto-api-security/akto, `PiiPatterns.java`, MIT : avis dans NOTICE, détail dans UPSTREAM.md). Les motifs sont écrits
 * ici, en RE2, sans reprise de texte : mots-clés français et anglais, liaison bornée (« : », « = », « est », « is »)
 * au lieu d'un intervalle libre pour les valeurs numériques, formes des valeurs propres à ce dépôt. Pour les adresses
 * de ressources AWS et la clé Azure, le contexte est le littéral fixe du fournisseur (`arn:aws`, `s3://`,
 * `amazonaws.com`, `SharedAccessKey=`).
 *
 * Portes littérales (`detect/prefilter.go`) : un motif qui replie la casse (`(?i:…)`) n'a de porte que si ses littéraux
 * sont en ASCII ; une lettre accentuée d'un mot-clé y est donc écrite « . » (un caractère quelconque), et la règle du
 * téléphone, dont le mot-clé « tél » est trop court pour cela, écrit ses casses une à une sans replier.
 *
 * Ce fichier tient aussi la lecture de référence du corpus (`corpus/context-data.ts`) : chaque motif exécuté par le
 * moteur d'expressions de JavaScript, sans RE2 ni le moteur Go.
 */
import type { RulePackRule, RuleSecretType } from '../src/rule-pack.ts';

/** Dépôt, commit et fichier d'Akto dont la technique du mot-clé de contexte est reprise (MIT). */
export const CONTEXT_UPSTREAM_REPOSITORY = 'akto-api-security/akto';
export const CONTEXT_UPSTREAM_COMMIT = '6b7de940c28037d726776bc5f201fd9e572133a3';
export const CONTEXT_UPSTREAM_PATH = 'apps/dashboard/src/main/java/com/akto/service/insights/PiiPatterns.java';

/** Espaces d'une ligne : espace, tabulation, espace insécable, espace fine insécable (typographie française). */
const SP = '[ \\t\u00a0\u202f]';

/**
 * Liaison entre un mot-clé et une valeur numérique : guillemet fermant du nom, puis « : », « = », « est » ou « is »,
 * puis « le » (« est le 123456 »), puis guillemet ouvrant de la valeur ; tout est facultatif, rien d'autre n'est admis.
 */
const LINK = `["']?${SP}*(?:(?:[:=]|is|est)${SP}*)?(?:le${SP}+)?["']?`;

/** Octet d'adresse IPv4 (0 à 255). */
const OCTET = '(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})';

/** Région AWS (`eu-west-3`, `us-gov-west-1`, `ap-southeast-2`). */
const AWS_REGION = '[a-z]{2}(?:-[a-z]+){1,2}-[0-9]';

/** Nom de bucket S3 : 3 à 63 minuscules, chiffres, points et tirets, bornés par une lettre ou un chiffre. */
const S3_BUCKET = '[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]';

/**
 * Adresse électronique : après « email », « e-mail », « courriel », « mail » ou « adresse électronique », à 24
 * caractères au plus sur la même ligne, sans « @ » ni point entre les deux (une adresse dont le domaine porte « mail »
 * n'annonce pas la suivante).
 */
const EMAIL_BODY = String.raw`(?:e-?mail|courriel|\bmail\b|adresse .lectronique)[^\n@.]{0,24}?\b([a-z0-9][a-z0-9._%+-]{0,63}@(?:[a-z0-9][a-z0-9-]{0,62}\.){1,8}[a-z]{2,24})`;

/**
 * Téléphone : après « tél », « tel », « phone » (« téléphone », « telephone »), « mobile », « portable » ou « fax »,
 * à 20 caractères au plus sans chiffre ni « + ». Numéro international (« + » ou « 00 », indicatif, 8 à 15 chiffres,
 * séparés d'une espace, d'un point ou d'un tiret, « (0) » admis) ou numéro français de dix chiffres (d'un bloc, ou par
 * paires séparées toutes de la même façon : une date « 01.02.2024 10 » n'en est pas un). Casses écrites une à une,
 * sans classe « [Tt] » (que l'analyseur de RE2 lit comme un littéral replié) : seize littéraux, le plus que porte une
 * porte.
 */
const PHONE_PATTERN =
  String.raw`(?:\b(?:Tel|tel|TEL|Tél|tél|TÉL)|Phone|phone|PHONE|Mobile|mobile|MOBILE|Portable|portable|Fax|fax)[^\n0-9+]{0,20}?` +
  String.raw`((?:\+|00)[1-9](?:[ .-]?\(?[0-9]\)?){7,14}|0[1-9](?:[0-9]{8}|(?: [0-9]{2}){4}|(?:\.[0-9]{2}){4}|(?:-[0-9]{2}){4}))\b`;

/**
 * Passeport : après « passport » ou « passeport » (puis « number », « numéro », « no », « n° », « # », « id »
 * facultatifs) et la liaison. Numéro français (2 chiffres, 2 lettres, 5 chiffres), 1 ou 2 lettres et 6 à 8 chiffres,
 * ou 9 chiffres.
 */
const PASSPORT_BODY =
  `pass(?:e)?ports?(?:[ \\t_-]*(?:number|num.ro|num|no|n°|#|id))?\\.?${LINK}` +
  String.raw`([0-9]{2}[a-z]{2}[0-9]{5}|[a-z]{1,2}[0-9]{6,8}|[0-9]{9})`;

/**
 * Cryptogramme de carte : après « cvv », « cvc » (« cvv2 », « cvc2 »), « cryptogramme (visuel) », « security code »
 * ou « code de sécurité » (puis « code » ou « number » facultatifs) et la liaison ; 3 ou 4 chiffres.
 */
const CARD_CODE_BODY =
  `(?:cvv2?|cvc2?|cryptogramme(?: visuel)?|security code|code de s.curit.)(?:[ _-]?(?:code|number))?${LINK}` +
  String.raw`([0-9]{3,4})`;

/**
 * Code à usage unique : après « otp » (« totp », « hotp »), « one-time password/passcode/code/pin », « verification code »,
 * « confirmation code », « validation code », « authentication code », « 2fa code », « code de vérification »,
 * « code de confirmation », « code de validation », « code d'authentification » ou « code à usage unique » (puis
 * « code », « sms », « reçu », « received » facultatifs) et la liaison ; 4 à 8 chiffres, ou deux groupes de trois.
 * « otp » n'est pas écrit à côté de « one.time » : l'analyseur de RE2 mettrait leur « o » en facteur, et la branche
 * « tp » restante, trop courte, retirerait la porte littérale.
 */
const ONE_TIME_CODE_BODY =
  String.raw`(?:one.time (?:password|passcode|code|pin)|(?:verification|confirmation|validation|authentication|2fa) code|otp|` +
  String.raw`code (?:de |d.)?(?:v.rification|confirmation|validation|authentification)|code . usage unique)` +
  `(?:[ _-]?(?:code|sms|re.u|received))?${LINK}` +
  String.raw`([0-9]{3}[ -][0-9]{3}|[0-9]{4,8})`;

/** Clé d'accès partagé d'une chaîne de connexion Azure (Service Bus, Event Hubs, IoT Hub) : 32 octets en base64. */
const AZURE_SHARED_ACCESS_KEY_PATTERN = String.raw`\bSharedAccessKey=([A-Za-z0-9+/]{43}=)`;

/**
 * Adresse IP privée (RFC 1918 : 10/8, 172.16/12, 192.168/16) annoncée comme interne : après « internal », « interne »,
 * « intranet », « private », « privé(e) », « vpn » ou « bastion », à 24 caractères au plus sans chiffre.
 */
const INTERNAL_IP_BODY =
  String.raw`(?:\b(?:internal|interne|intranet|private|vpn|bastion)s?\b|\bpriv.e?s?)[^\n0-9]{0,24}?` +
  String.raw`\b(10(?:\.${OCTET}){3}|172\.(?:1[6-9]|2[0-9]|3[01])(?:\.${OCTET}){2}|192\.168(?:\.${OCTET}){2})`;

/**
 * ARN d'une ressource AWS : partition, service, région, compte de 12 chiffres (ou vide : S3), ressource. Un ARN de
 * politique gérée par AWS (compte « aws ») ou dont la ressource est une variable n'en est pas un.
 */
const AWS_ARN_PATTERN = String.raw`\barn:aws(?:-cn|-us-gov)?:[a-z0-9-]{2,32}:[a-z0-9-]{0,24}:(?:[0-9]{12})?:[A-Za-z0-9](?:[A-Za-z0-9_+=,.@/:-]{0,126}[A-Za-z0-9_])?`;

/** Bucket S3 : `s3://nom`, `nom.s3.région.amazonaws.com` (ou `s3-website-…`), `s3.région.amazonaws.com/nom`. */
const AWS_S3_PATTERN =
  String.raw`\bs3://${S3_BUCKET}\b|\b${S3_BUCKET}\.s3[.-](?:[a-z0-9-]{1,24}\.)?amazonaws\.com\b|` +
  String.raw`\bs3[.-][a-z0-9-]{1,24}\.amazonaws\.com/${S3_BUCKET}\b`;

/** Point d'accès RDS : `instance.identifiant.région.rds.amazonaws.com` (grappe et proxy compris). */
const AWS_RDS_PATTERN = String.raw`\b[a-z0-9][a-z0-9-]{0,62}\.[a-z0-9-]{6,40}\.${AWS_REGION}\.rds\.amazonaws\.com(?:\.cn)?\b`;

/** Point d'accès DynamoDB d'une région : `dynamodb.région.amazonaws.com`. */
const AWS_DYNAMODB_PATTERN = String.raw`\b(?:streams\.)?dynamodb\.${AWS_REGION}\.amazonaws\.com(?:\.cn)?\b`;

/** Règle de données à contexte : règle du Pack, libellé de Substitut (français, anglais), activation. */
export interface ContextRule {
  readonly rule: RulePackRule;
  readonly labelFr: string;
  readonly labelEn: string;
  /**
   * Vrai : règle « à activer ». Le moteur ne l'exécute que si l'appelant la nomme (`detect.LoadRulesWithOptIn`), parce
   * qu'elle se déclenche sur des textes ordinaires du corpus de bruit (`vectors/noise.json`).
   */
  readonly optIn: boolean;
  /** Le même motif pour le moteur d'expressions de JavaScript (lecture de référence) : source et drapeaux. */
  readonly reference: { readonly source: string; readonly flags: string };
}

/** Motif d'une règle et son écriture pour la lecture de référence. */
interface ContextPattern {
  readonly pattern: string;
  readonly reference: { readonly source: string; readonly flags: string };
}

/** Motif sensible à la casse : le même texte pour RE2 et pour JavaScript. */
const exact = (pattern: string): ContextPattern => ({ pattern, reference: { source: pattern, flags: 'dg' } });

/**
 * Motif qui replie la casse, fini par une limite de mot : `(?i:corps)\b` pour RE2, le corps sous le drapeau `i` pour
 * JavaScript (Node 26.0 n'applique pas un repli écrit `(?i:…)` à toutes les branches d'une alternance capturée).
 */
const folded = (body: string): ContextPattern => ({ pattern: `(?i:${body})\\b`, reference: { source: `${body}\\b`, flags: 'dgi' } });

function contextRule(
  ruleId: string,
  secretType: RuleSecretType,
  score: number,
  pattern: ContextPattern,
  labelFr: string,
  labelEn: string,
  optIn = false,
): ContextRule {
  return {
    rule: { ruleId, family: 'fixed_pattern', secretType, score, validator: '', pattern: pattern.pattern, minLength: 0, maxLength: 0 },
    labelFr,
    labelEn,
    optIn,
    reference: pattern.reference,
  };
}

/**
 * Règles de données à contexte, dans l'ordre du Pack (après les règles de fournisseurs). Scores (niveau) : cryptogramme
 * 70 et passeport 60 (HIGH, comme la carte et le NIR), code à usage unique 45, adresse électronique, téléphone, adresse
 * IP interne, ARN, bucket S3 et point d'accès RDS 30, point d'accès DynamoDB 25 (MEDIUM : une adresse de région,
 * publique) ; clé d'accès partagé Azure 95 (CRITICAL, comme `azure_storage_key`).
 *
 * `email_address` est « à activer » : une adresse annoncée par son champ (`email: …`) est courante dans les jeux
 * d'essai et la configuration d'un dépôt (78 constats sur 58 Mo de quatre dépôts réels le 14 novembre 2026, aucun pour
 * les autres règles personnelles hors des cas d'essai de ce dépôt).
 */
export const CONTEXT_RULE_SOURCES: readonly ContextRule[] = [
  contextRule('email_address', 'email_address', 30, folded(EMAIL_BODY), 'adresse électronique', 'email address', true),
  contextRule('phone_number', 'phone_number', 30, exact(PHONE_PATTERN), 'numéro de téléphone', 'phone number'),
  contextRule('passport_number', 'passport_number', 60, folded(PASSPORT_BODY), 'numéro de passeport', 'passport number'),
  contextRule('payment_card_security_code', 'payment_card_security_code', 70, folded(CARD_CODE_BODY), 'cryptogramme de carte bancaire', 'payment card security code'),
  contextRule('one_time_code', 'one_time_code', 45, folded(ONE_TIME_CODE_BODY), 'code à usage unique', 'one-time code'),
  contextRule('azure_shared_access_key', 'cloud_credential', 95, exact(AZURE_SHARED_ACCESS_KEY_PATTERN), 'clé d’accès partagé Azure', 'Azure shared access key'),
  contextRule('internal_ip_address', 'internal_ip_address', 30, folded(INTERNAL_IP_BODY), 'adresse IP interne', 'internal IP address'),
  contextRule('aws_arn', 'cloud_resource_address', 30, exact(AWS_ARN_PATTERN), 'ARN AWS', 'AWS ARN'),
  contextRule('aws_s3_bucket', 'cloud_resource_address', 30, exact(AWS_S3_PATTERN), 'adresse de bucket S3', 'S3 bucket address'),
  contextRule('aws_rds_endpoint', 'cloud_resource_address', 30, exact(AWS_RDS_PATTERN), 'adresse de base RDS', 'RDS endpoint'),
  contextRule('aws_dynamodb_endpoint', 'cloud_resource_address', 25, exact(AWS_DYNAMODB_PATTERN), 'adresse DynamoDB', 'DynamoDB endpoint'),
];

/** Règles « à activer », dans l'ordre du Pack (`detect.OptInRuleIDs`). */
export const CONTEXT_OPT_IN_RULE_IDS: readonly string[] = CONTEXT_RULE_SOURCES.filter((source) => source.optIn).map((source) => source.rule.ruleId);

/** Règles du Pack, dans l'ordre. */
export const CONTEXT_DATA_RULES: readonly RulePackRule[] = CONTEXT_RULE_SOURCES.map((source) => source.rule);

/** Étendue d'une valeur trouvée par la lecture de référence (indices UTF-16 du texte). */
export interface ContextMatch {
  readonly rule: RulePackRule;
  readonly start: number;
  readonly end: number;
}

/**
 * Lecture de référence : chaque motif exécuté par le moteur d'expressions de JavaScript (seconde exécution,
 * indépendante de RE2 et du moteur Go) ; la valeur est le premier groupe capturant s'il a participé, sinon la
 * correspondance entière. La syntaxe des motifs est commune aux deux moteurs, au repli de casse près (`folded`). À
 * n'utiliser que sur un texte sans U+212A ni U+017F (que RE2 replie sur « k » et « s ») ni fin de ligne autre que
 * « \n » (« . » de JavaScript).
 */
export function contextReferenceFindings(text: string): ContextMatch[] {
  const found: ContextMatch[] = [];
  for (const { rule, reference } of CONTEXT_RULE_SOURCES) {
    for (const match of text.matchAll(new RegExp(reference.source, reference.flags))) {
      const [start, end] = match.indices?.[1] ?? match.indices?.[0] ?? [0, 0];
      if (end > start) found.push({ rule, start, end });
    }
  }
  return found;
}

function goString(text: string): string {
  return JSON.stringify(text).replace(/[\u007f-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

/**
 * Source Go des règles de données à contexte (`detect/context_rules.go`) : libellés de Substitut et règles « à
 * activer », écrite avec le Pack par `npm run pack:initial`.
 */
export function buildContextRulesGo(): string {
  const lines = CONTEXT_RULE_SOURCES.map((source) => `\t{${goString(source.rule.ruleId)}, ${goString(source.labelFr)}, ${goString(source.labelEn)}},`);
  return [
    '// SPDX-License-Identifier: Apache-2.0',
    '',
    '// Code généré par generator/rule-pack/generate-initial-pack.ts (npm run pack:initial) ; ne pas modifier.',
    '',
    'package detect',
    '',
    '// contextSubstituteLabels : types de secret des règles de données à contexte du Pack initial (v0.9.0), dans',
    "// l'ordre du Pack. Source : generator/rule-pack/context-data.ts.",
    'var contextSubstituteLabels = []SubstituteLabel{',
    ...lines,
    '}',
    '',
    "// contextOptInRuleIDs : règles « à activer » (optin.go), dans l'ordre du Pack. Même source.",
    `var contextOptInRuleIDs = []string{${CONTEXT_OPT_IN_RULE_IDS.map(goString).join(', ')}}`,
    '',
  ].join('\n');
}
