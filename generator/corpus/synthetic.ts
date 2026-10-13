/**
 * Cas synthétiques du corpus de parité. Fonction pure et déterministe : chaque valeur de
 * secret est tirée de SHA-256 sur une étiquette fixe (`synth`), jamais copiée d'un vrai secret ; les seules valeurs
 * écrites ici sont les trois exemples publics que Secret Guard filtre (`PUBLIC_EXAMPLES` de `rules.ts`), écrits en
 * morceaux comme à l'origine. Le résultat attendu de chaque cas vient du moteur d'origine (`main.ts`) ; le test
 * `test/detection-corpus.test.ts` reconstruit ces cas et les compare aux fichiers commités.
 */
import { createHash } from 'node:crypto';
import { MAX_INPUT_BYTES, type FindingEncoding } from './model.ts';

/** Intention d'un cas, contrôlée par le générateur sur le résultat du moteur (`coverageProblems` de `corpus.ts`) ; jamais écrite. */
export type CaseIntent =
  | { readonly kind: 'positive'; readonly rule: string }
  | { readonly kind: 'negative'; readonly rule: string }
  | { readonly kind: 'placeholder'; readonly rule: string; readonly value: string }
  | { readonly kind: 'public_example'; readonly rule: string; readonly value: string }
  | { readonly kind: 'view'; readonly rule: string; readonly view: FindingEncoding };

export interface SyntheticCase {
  readonly file: string;
  readonly id: string;
  readonly bytes: Uint8Array;
  readonly languageId?: string;
  readonly intent?: CaseIntent;
}

/** Client HTTP en ligne de commande des cas `-u utilisateur:mot de passe` (nommé une seule fois). */
const HTTP_CLIENT = 'curl';

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';
const ALNUM = UPPER + LOWER + DIGITS;
const HEX = '0123456789abcdef';
const B64 = `${ALNUM}+/`;
const URL_SAFE = `${ALNUM}_-`;

/** Chaîne de `length` caractères de `alphabet`, tirée de SHA-256 sur l'étiquette (déterministe). */
export function synth(label: string, alphabet: string, length: number): string {
  let out = '';
  for (let block = 0; out.length < length; block += 1) {
    // Étiquette historique du corpus : la changer changerait toutes les valeurs synthétiques.
    const digest = createHash('sha256').update(`xsom-fleet/detection-corpus/v1/${label}/${String(block)}`).digest();
    for (const byte of digest) {
      if (out.length === length) break;
      out += alphabet[byte % alphabet.length] ?? '';
    }
  }
  return out;
}

/** Mot de passe synthétique : lettres, chiffres et ponctuation sans guillemets ni séparateurs. */
function password(label: string): string {
  return `${synth(`${label}/a`, ALNUM, 10)}!${synth(`${label}/b`, ALNUM, 6)}`;
}

function base64(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64');
}

function base64Url(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64url');
}

/** Exemples publics filtrés par Secret Guard (`PUBLIC_EXAMPLES`), écrits en morceaux comme à l'origine. */
export const PUBLIC_EXAMPLES = {
  awsAccessKeyId: ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join(''),
  awsSecretAccessKey: ['wJalrXUtnFEMI', 'K7MDENG', 'bPxRfiCYEXAMPLEKEY'].join('/'),
  stripeTestKey: ['sk', 'test', '4eC39HqLyjWDarjtT1zdp7dc'].join('_'),
} as const;

/**
 * Règles dont aucune valeur fictive (`isPlaceholder`) ne peut être reconnue, avec la raison : leur valeur détectée
 * est la correspondance entière, qui commence par un préfixe fixe que les formes de `isPlaceholder` n'admettent pas
 * (`${…}`, `$NOM`, `{{…}}`, `<…>`, `YOUR…`/`INSERT…`/`REPLACE…`/`CHANGE…`, `xxxx`, `****`, `...`, `example`…), ou
 * elles ne filtrent rien (clés privées).
 */
export const PLACEHOLDER_NOT_APPLICABLE: Readonly<Record<string, string>> = {
  private_key_pem: 'aucun filtre de valeur (bloc de clé privée)',
  private_key_pem_incomplete: 'aucun filtre de valeur (en-tête de clé privée)',
  github_fine_grained_pat: 'correspondance entière à préfixe fixe github_pat_',
  github_token: 'correspondance entière à préfixe fixe gh[pousr]_',
  gitlab_pat: 'correspondance entière à préfixe fixe glpat-',
  openrouter_key: 'correspondance entière à préfixe fixe sk-or-v1-',
  anthropic_key: 'correspondance entière à préfixe fixe sk-ant-',
  openai_key: 'correspondance entière à préfixe fixe sk-',
  stripe_secret_key: 'correspondance entière à préfixe fixe sk_/rk_',
  slack_token: 'correspondance entière à préfixe fixe xox',
  slack_webhook: 'correspondance entière à préfixe fixe https://hooks.slack.com/services/',
  google_api_key: 'correspondance entière à préfixe fixe AIza',
  google_oauth_token: 'correspondance entière à préfixe fixe ya29.',
  sendgrid_key: 'correspondance entière à préfixe fixe SG.',
  npm_token: 'correspondance entière à préfixe fixe npm_',
  huggingface_token: 'correspondance entière à préfixe fixe hf_',
  databricks_pat: 'correspondance entière à préfixe fixe dapi',
  digitalocean_token: 'correspondance entière à préfixe fixe dop_v1_',
  shopify_token: 'correspondance entière à préfixe fixe shp',
  aws_access_key_id: 'correspondance entière à préfixe fixe AKIA/ASIA/…',
  jwt: 'correspondance entière à préfixe fixe eyJ',
};

/**
 * Règles dont aucun des trois exemples publics ne peut être la valeur détectée (préfixe fixe différent de
 * `AKIA`/`sk_test_` et forme incompatible avec la clé secrète AWS d'exemple), ou qui ne filtrent rien.
 */
export const PUBLIC_EXAMPLE_NOT_APPLICABLE: Readonly<Record<string, string>> = {
  private_key_pem: 'aucun filtre de valeur (bloc de clé privée)',
  private_key_pem_incomplete: 'aucun filtre de valeur (en-tête de clé privée)',
  github_fine_grained_pat: 'préfixe github_pat_ : aucun exemple public de cette forme',
  github_token: 'préfixe gh[pousr]_ : aucun exemple public de cette forme',
  gitlab_pat: 'préfixe glpat- : aucun exemple public de cette forme',
  openrouter_key: 'préfixe sk-or-v1- : aucun exemple public de cette forme',
  anthropic_key: 'préfixe sk-ant- : aucun exemple public de cette forme',
  openai_key: 'préfixe sk- (tiret) : l’exemple Stripe est en sk_ (souligné)',
  slack_token: 'préfixe xox : aucun exemple public de cette forme',
  slack_webhook: 'préfixe https://hooks.slack.com/ : aucun exemple public de cette forme',
  google_api_key: 'préfixe AIza : aucun exemple public de cette forme',
  google_oauth_token: 'préfixe ya29. : aucun exemple public de cette forme',
  sendgrid_key: 'préfixe SG. : aucun exemple public de cette forme',
  npm_token: 'préfixe npm_ : aucun exemple public de cette forme',
  huggingface_token: 'préfixe hf_ : aucun exemple public de cette forme',
  databricks_pat: 'préfixe dapi : aucun exemple public de cette forme',
  digitalocean_token: 'préfixe dop_v1_ : aucun exemple public de cette forme',
  shopify_token: 'préfixe shp : aucun exemple public de cette forme',
  jwt: 'préfixe eyJ : aucun exemple public de cette forme',
};

interface Builder {
  readonly cases: SyntheticCase[];
  add(file: string, id: string, text: string, options?: { languageId?: string; intent?: CaseIntent }): void;
  addBytes(file: string, id: string, bytes: Uint8Array): void;
}

function builder(): Builder {
  const cases: SyntheticCase[] = [];
  const ids = new Set<string>();
  const push = (value: SyntheticCase): void => {
    if (ids.has(value.id)) throw new Error(`identifiant de cas en double : ${value.id}`);
    ids.add(value.id);
    cases.push(value);
  };
  return {
    cases,
    add(file, id, text, options = {}) {
      push({
        file,
        id,
        bytes: new TextEncoder().encode(text),
        ...(options.languageId === undefined ? {} : { languageId: options.languageId }),
        ...(options.intent === undefined ? {} : { intent: options.intent }),
      });
    },
    addBytes(file, id, bytes) {
      push({ file, id, bytes });
    },
  };
}

/** Vues obtenues en déguisant un caractère de l'entrée (position `pivot`), ou l'entrée entière (base64). */
function viewVariants(text: string, pivot: number): readonly (readonly [FindingEncoding, string])[] {
  const character = text[pivot] ?? '';
  if (!/^[A-Za-z0-9_-]$/.test(character)) throw new Error(`pivot hors d’un caractère de jeton : ${String(pivot)}`);
  const code = character.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0');
  const before = text.slice(0, pivot);
  const after = text.slice(pivot + 1);
  return [
    ['normalized', `${before}\u200b${character}${after}`],
    ['percent', `${before}%${code}${after}`],
    ['json-escaped', `${before}\\u00${code.toLowerCase()}${after}`],
    ['base64', `payload ${base64(text)}\n`],
    ['whitespace-joined', `${before}\n    ${character}${after}`],
  ];
}

/** Valeurs positives des règles à motif fixe, par variante. */
function fixedTokens(rule: string, label: string): readonly (readonly [string, string])[] {
  const s = (suffix: string, alphabet: string, length: number): string => synth(`${label}/${suffix}`, alphabet, length);
  switch (rule) {
    case 'github_fine_grained_pat':
      return [['base', `github_pat_${s('a', ALNUM, 22)}_${s('b', ALNUM, 59)}`]];
    case 'github_token':
      return ['ghp', 'gho', 'ghu', 'ghs', 'ghr'].map((prefix) => [prefix, `${prefix}_${s(prefix, ALNUM, 36)}`] as const);
    case 'gitlab_pat':
      return [['base', `glpat-${s('a', URL_SAFE, 20)}`]];
    case 'openrouter_key':
      return [['base', `sk-or-v1-${s('a', HEX, 64)}`]];
    case 'anthropic_key':
      return [
        ['api03', `sk-ant-api03-${s('a', URL_SAFE, 93)}AA`],
        ['short', `sk-ant-${s('b', ALNUM, 24)}`],
      ];
    case 'openai_key':
      return [
        ['proj', `sk-proj-${s('a', URL_SAFE, 48)}`],
        ['svcacct', `sk-svcacct-${s('b', ALNUM, 40)}`],
        ['legacy', `sk-${s('c', ALNUM, 48)}`],
      ];
    case 'stripe_secret_key':
      return [
        ['live', `sk_live_${s('a', ALNUM, 24)}`],
        ['restricted', `rk_test_${s('b', ALNUM, 32)}`],
      ];
    case 'slack_token':
      return [
        ['bot', `xoxb-${s('a', DIGITS, 12)}-${s('b', DIGITS, 13)}-${s('c', ALNUM, 24)}`],
        ['user', `xoxp-${s('d', DIGITS, 12)}-${s('e', ALNUM, 20)}`],
      ];
    case 'slack_webhook':
      return [['base', `https://hooks.slack.com/services/T${s('a', UPPER + DIGITS, 8)}/B${s('b', UPPER + DIGITS, 10)}/${s('c', ALNUM, 24)}`]];
    case 'google_api_key':
      return [['base', `AIza${s('a', URL_SAFE, 35)}`]];
    case 'google_oauth_token':
      return [['base', `ya29.${s('a', URL_SAFE, 60)}`]];
    case 'sendgrid_key':
      return [['base', `SG.${s('a', URL_SAFE, 22)}.${s('b', URL_SAFE, 43)}`]];
    case 'npm_token':
      return [['base', `npm_${s('a', ALNUM, 36)}`]];
    case 'huggingface_token':
      return [['base', `hf_${s('a', ALNUM, 34)}`]];
    case 'databricks_pat':
      return [['base', `dapi${s('a', HEX, 32)}`]];
    case 'digitalocean_token':
      return [['base', `dop_v1_${s('a', HEX, 64)}`]];
    case 'shopify_token':
      return ['shpat', 'shpss', 'shpca', 'shppa'].map((prefix) => [prefix, `${prefix}_${s(prefix, HEX, 32)}`] as const);
    case 'azure_storage_key':
      return [['base', `AccountKey=${s('a', B64, 86)}==`]];
    case 'aws_access_key_id':
      return [
        ['akia', `AKIA${s('a', UPPER + DIGITS, 16)}`],
        ['asia', `ASIA${s('b', UPPER + DIGITS, 16)}`],
      ];
    case 'jwt':
      return [['base', jwt(label, 1, 1, 43)]];
    default:
      throw new Error(`règle à motif fixe inconnue : ${rule}`);
  }
}

/**
 * JWT synthétique : en-tête et charge JSON en base64url, signature tirée au hasard. `headerPad` et `payloadPad`
 * allongent les champs JSON pour obtenir des segments de plus de 1 000 caractères.
 */
function jwt(label: string, headerPad: number, payloadPad: number, signatureLength: number): string {
  const header = base64Url(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: synth(`${label}/kid`, ALNUM, headerPad) }));
  const payload = base64Url(JSON.stringify({ sub: `corpus-${label}`, scope: synth(`${label}/scope`, ALNUM, payloadPad) }));
  return `${header}.${payload}.${synth(`${label}/sig`, URL_SAFE, signatureLength)}`;
}

/** Règles à motif fixe, dans l'ordre de `FIXED_RULES` de `rules.ts`. */
export const FIXED_RULE_ORDER = [
  'github_fine_grained_pat',
  'github_token',
  'gitlab_pat',
  'openrouter_key',
  'anthropic_key',
  'openai_key',
  'stripe_secret_key',
  'slack_token',
  'slack_webhook',
  'google_api_key',
  'google_oauth_token',
  'sendgrid_key',
  'npm_token',
  'huggingface_token',
  'databricks_pat',
  'digitalocean_token',
  'shopify_token',
  'azure_storage_key',
  'aws_access_key_id',
  'jwt',
] as const;

/** Préfixe fixe de chaque règle (déguisements « vue » placés juste après). */
const FIXED_PREFIX_LENGTH: Readonly<Record<string, number>> = {
  github_fine_grained_pat: 11,
  github_token: 4,
  gitlab_pat: 6,
  openrouter_key: 9,
  anthropic_key: 13,
  openai_key: 8,
  stripe_secret_key: 8,
  slack_token: 5,
  slack_webhook: 33,
  google_api_key: 4,
  google_oauth_token: 5,
  sendgrid_key: 3,
  npm_token: 4,
  huggingface_token: 3,
  databricks_pat: 4,
  digitalocean_token: 7,
  shopify_token: 6,
  azure_storage_key: 11,
  aws_access_key_id: 4,
  jwt: 3,
};

/** Entrées négatives (près de la forme, refusées par la règle). */
function fixedNegatives(rule: string, label: string): readonly (readonly [string, string])[] {
  const s = (suffix: string, alphabet: string, length: number): string => synth(`${label}/neg/${suffix}`, alphabet, length);
  switch (rule) {
    case 'github_fine_grained_pat':
      return [
        ['too-short', `github_pat_${s('a', ALNUM, 29)}`],
        ['glued', `xgithub_pat_${s('b', ALNUM, 40)}`],
      ];
    case 'github_token':
      return [
        ['too-short', `ghp_${s('a', ALNUM, 35)}`],
        ['unknown-letter', `ghx_${s('b', ALNUM, 36)}`],
        ['glued', `aghp_${s('c', ALNUM, 36)}`],
      ];
    case 'gitlab_pat':
      return [['too-short', `glpat-${s('a', ALNUM, 19)}`]];
    case 'openrouter_key':
      return [['too-short', `sk-or-v1-${s('a', HEX, 31)}`]];
    case 'anthropic_key':
      return [['too-short', `sk-ant-${s('a', ALNUM, 12)}`]];
    case 'openai_key':
      return [
        ['too-short', `sk-${s('a', ALNUM, 19)}`],
        ['glued', `ask-proj-${s('b', ALNUM, 40)}`],
      ];
    case 'stripe_secret_key':
      return [
        ['publishable', `pk_live_${s('a', ALNUM, 24)}`],
        ['too-short', `sk_live_${s('b', ALNUM, 19)}`],
      ];
    case 'slack_token':
      return [['unknown-letter', `xoxz-${s('a', DIGITS, 12)}-${s('b', ALNUM, 20)}`]];
    case 'slack_webhook':
      return [['http', `http://hooks.slack.com/services/T${s('a', UPPER, 8)}/B${s('b', UPPER, 10)}/${s('c', ALNUM, 24)}`]];
    case 'google_api_key':
      return [['too-short', `AIza${s('a', ALNUM, 34)}`]];
    case 'google_oauth_token':
      return [['too-short', `ya29.${s('a', ALNUM, 19)}`]];
    case 'sendgrid_key':
      return [['short-segment', `SG.${s('a', ALNUM, 21)}.${s('b', ALNUM, 43)}`]];
    case 'npm_token':
      return [['too-short', `npm_${s('a', ALNUM, 35)}`]];
    case 'huggingface_token':
      return [['too-short', `hf_${s('a', ALNUM, 33)}`]];
    case 'databricks_pat':
      return [['not-hex', `dapi${s('a', 'ghijklmnopqrstuvwxyz', 32)}`]];
    case 'digitalocean_token':
      return [['too-short', `dop_v1_${s('a', HEX, 63)}`]];
    case 'shopify_token':
      return [['unknown-kind', `shpxx_${s('a', HEX, 32)}`]];
    case 'azure_storage_key':
      return [['too-short', `AccountKey=${s('a', ALNUM, 39)}`]];
    case 'aws_access_key_id':
      return [
        ['lowercase', `AKIA${s('a', LOWER + DIGITS, 16)}`],
        ['unknown-prefix', `AKIB${s('b', UPPER + DIGITS, 16)}`],
      ];
    case 'jwt':
      return [
        ['not-json', `eyJ${s('a', ALNUM, 20)}.eyJ${s('b', ALNUM, 30)}.${s('c', URL_SAFE, 43)}`],
        ['short-signature', `${base64Url('{"alg":"none"}')}.${base64Url('{"sub":"x"}')}.${s('d', ALNUM, 7)}`],
      ];
    default:
      throw new Error(`règle à motif fixe inconnue : ${rule}`);
  }
}

function addFixedRules(b: Builder): void {
  const file = 'rules-fixed.json';
  for (const rule of FIXED_RULE_ORDER) {
    const tokens = fixedTokens(rule, rule);
    tokens.forEach(([variant, token], index) => {
      b.add(file, `${rule}/positive/${variant}`, token, { intent: { kind: 'positive', rule } });
      if (index === 0) {
        b.add(file, `${rule}/positive/${variant}-in-sentence`, `please rotate ${token} before friday\n`, {
          intent: { kind: 'positive', rule },
        });
        b.add(file, `${rule}/positive/${variant}-quoted`, `"${token}"`, { intent: { kind: 'positive', rule } });
      }
    });
    for (const [variant, input] of fixedNegatives(rule, rule)) {
      b.add(file, `${rule}/negative/${variant}`, input, { intent: { kind: 'negative', rule } });
    }
  }
  // Valeurs fictives et exemples publics des règles à motif fixe qui les filtrent.
  const azurePlaceholder = 'x'.repeat(44);
  b.add(file, 'azure_storage_key/placeholder/xxxx', `AccountKey=${azurePlaceholder}`, {
    intent: { kind: 'placeholder', rule: 'azure_storage_key', value: azurePlaceholder },
  });
  const azureYour = `YOURSTORAGEACCOUNTKEY${'X'.repeat(24)}`;
  b.add(file, 'azure_storage_key/placeholder/your', `AccountKey=${azureYour}`, {
    intent: { kind: 'placeholder', rule: 'azure_storage_key', value: azureYour },
  });
  b.add(file, 'azure_storage_key/public-example/aws-secret', `AccountKey=${PUBLIC_EXAMPLES.awsSecretAccessKey}`, {
    intent: { kind: 'public_example', rule: 'azure_storage_key', value: PUBLIC_EXAMPLES.awsSecretAccessKey },
  });
  b.add(file, 'aws_access_key_id/public-example/akia', `aws_access_key_id ${PUBLIC_EXAMPLES.awsAccessKeyId}`, {
    intent: { kind: 'public_example', rule: 'aws_access_key_id', value: PUBLIC_EXAMPLES.awsAccessKeyId },
  });
  b.add(file, 'stripe_secret_key/public-example/test-key', `stripe ${PUBLIC_EXAMPLES.stripeTestKey}`, {
    intent: { kind: 'public_example', rule: 'stripe_secret_key', value: PUBLIC_EXAMPLES.stripeTestKey },
  });
  // Validateur structurel du JWT (en-tête et charge JSON objets).
  b.add(file, 'jwt/negative/array-payload', `${base64Url('{"alg":"HS256"}')}.${base64Url('["x"]')}.${synth('jwt/arr', URL_SAFE, 43)}`, {
    intent: { kind: 'negative', rule: 'jwt' },
  });
}

/** Ligne d'encadrement PEM (`-----BEGIN <étiquette>-----`). */
function pemLine(marker: 'BEGIN' | 'END', label: string): string {
  return `-----${marker} ${label}-----`;
}

/** Corps de clé privée synthétique : lignes base64 de 64 caractères. */
function keyBody(label: string, lines: number): string {
  return Array.from({ length: lines }, (_, index) => synth(`${label}/${String(index)}`, B64, 64)).join('\n');
}

function addPrivateKeys(b: Builder): void {
  const file = 'rules-private-key.json';
  const labels = ['RSA PRIVATE KEY', 'EC PRIVATE KEY', 'DSA PRIVATE KEY', 'OPENSSH PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'PRIVATE KEY', 'PGP PRIVATE KEY BLOCK'];
  for (const label of labels) {
    const slug = label.toLowerCase().replaceAll(' ', '-');
    const block = `${pemLine('BEGIN', label)}\n${keyBody(slug, 4)}\n${pemLine('END', label)}`;
    b.add(file, `private_key_pem/positive/${slug}`, `${block}\n`, { intent: { kind: 'positive', rule: 'private_key_pem' } });
  }
  const rsa = `${pemLine('BEGIN', 'RSA PRIVATE KEY')}\n${keyBody('rsa-ctx', 3)}\n${pemLine('END', 'RSA PRIVATE KEY')}`;
  b.add(file, 'private_key_pem/positive/in-text', `config:\n${rsa}\ntrailing text\n`, {
    intent: { kind: 'positive', rule: 'private_key_pem' },
  });
  b.add(file, 'private_key_pem/positive/two-blocks', `${rsa}\n\n${rsa.replaceAll('RSA', 'EC')}\n`, {
    intent: { kind: 'positive', rule: 'private_key_pem' },
  });
  b.add(file, 'private_key_pem/positive/crlf', `${rsa.replaceAll('\n', '\r\n')}\r\n`, {
    intent: { kind: 'positive', rule: 'private_key_pem' },
  });
  b.add(file, 'private_key_pem_incomplete/positive/no-end', `${pemLine('BEGIN', 'PRIVATE KEY')}\n${keyBody('incomplete', 3)}\n`, {
    intent: { kind: 'positive', rule: 'private_key_pem_incomplete' },
  });
  b.add(file, 'private_key_pem_incomplete/positive/other-end', `${pemLine('BEGIN', 'RSA PRIVATE KEY')}\n${keyBody('mismatch', 2)}\n${pemLine('END', 'EC PRIVATE KEY')}\n`, {
    intent: { kind: 'positive', rule: 'private_key_pem_incomplete' },
  });
  b.add(file, 'private_key_pem_incomplete/positive/header-only', pemLine('BEGIN', 'OPENSSH PRIVATE KEY'), {
    intent: { kind: 'positive', rule: 'private_key_pem_incomplete' },
  });
  for (const rule of ['private_key_pem', 'private_key_pem_incomplete']) {
    b.add(file, `${rule}/negative/public-key`, `${pemLine('BEGIN', 'PUBLIC KEY')}\n${keyBody(`${rule}/pub`, 2)}\n${pemLine('END', 'PUBLIC KEY')}\n`, {
      intent: { kind: 'negative', rule },
    });
    b.add(file, `${rule}/negative/certificate`, `${pemLine('BEGIN', 'CERTIFICATE')}\nMIIB\n${pemLine('END', 'CERTIFICATE')}\n`, {
      intent: { kind: 'negative', rule },
    });
    b.add(file, `${rule}/negative/lowercase`, `${pemLine('BEGIN', 'RSA PRIVATE KEY').toLowerCase()}\n${keyBody(`${rule}/lc`, 1)}\n`, {
      intent: { kind: 'negative', rule },
    });
  }
}

function addCredentialUrls(b: Builder): void {
  const file = 'rules-credential-url.json';
  const db = 'database_url_credentials';
  const basic = 'basic_auth_url';
  const schemes: readonly (readonly [string, string, string])[] = [
    [db, 'postgres', 'postgres://app:%s@db.corpus.test:5432/app'],
    [db, 'postgresql', 'postgresql://app:%s@db.corpus.test/app?sslmode=require'],
    [db, 'mysql', 'mysql://root:%s@127.0.0.1:3306/shop'],
    [db, 'mariadb', 'mariadb://svc:%s@mariadb.corpus.test/x'],
    [db, 'mongodb', 'mongodb://admin:%s@mongo.corpus.test:27017'],
    [db, 'mongodb-srv', 'mongodb+srv://admin:%s@cluster0.corpus.test/db'],
    [db, 'redis-empty-user', 'redis://:%s@cache.corpus.test:6379/0'],
    [db, 'rediss', 'rediss://default:%s@cache.corpus.test:6380'],
    [db, 'amqp', 'amqp://guest:%s@mq.corpus.test:5672/'],
    [db, 'amqps-uppercase', 'AMQPS://worker:%s@mq.corpus.test'],
    [basic, 'https', 'https://deploy:%s@git.corpus.test/repo.git'],
    [basic, 'http', 'http://admin:%s@intranet.corpus.test/'],
    [basic, 'ftp', 'ftp://upload:%s@ftp.corpus.test/in'],
    [basic, 'https-mixed-case', 'HtTpS://deploy:%s@git.corpus.test'],
  ];
  for (const [rule, variant, template] of schemes) {
    const url = template.replace('%s', password(`url/${variant}`));
    b.add(file, `${rule}/positive/${variant}`, `clone ${url} now\n`, { intent: { kind: 'positive', rule } });
  }
  const pw = password('url/punct');
  b.add(file, `${basic}/positive/trailing-punctuation`, `(see https://bot:${pw}@ci.corpus.test/x),`, {
    intent: { kind: 'positive', rule: basic },
  });
  b.add(file, `${db}/positive/percent-encoded-password`, `postgres://app:${encodeURIComponent(`${pw}/@:`)}@db.corpus.test/app`, {
    intent: { kind: 'positive', rule: db },
  });
  b.add(file, `${db}/positive/invalid-escape`, `postgres://app:%ZZ${pw}@db.corpus.test/app`, {
    intent: { kind: 'positive', rule: db },
  });
  for (const rule of [db, basic]) {
    const scheme = rule === db ? 'postgres' : 'https';
    b.add(file, `${rule}/negative/no-password`, `${scheme}://user@host.corpus.test/path`, { intent: { kind: 'negative', rule } });
    b.add(file, `${rule}/negative/empty-password`, `${scheme}://user:@host.corpus.test/path`, { intent: { kind: 'negative', rule } });
    b.add(file, `${rule}/negative/plain-url`, `${scheme}://host.corpus.test/a?b=c`, { intent: { kind: 'negative', rule } });
    b.add(file, `${rule}/placeholder/xxxx`, `${scheme}://user:xxxx@host.corpus.test/`, {
      intent: { kind: 'placeholder', rule, value: 'xxxx' },
    });
    b.add(file, `${rule}/placeholder/env`, `${scheme}://user:\${DB_PASSWORD}@host.corpus.test/`, {
      intent: { kind: 'placeholder', rule, value: '${DB_PASSWORD}' },
    });
    b.add(file, `${rule}/placeholder/changeme`, `${scheme}://user:changeme@host.corpus.test/`, {
      intent: { kind: 'placeholder', rule, value: 'changeme' },
    });
    b.add(file, `${rule}/public-example/stripe`, `${scheme}://user:${PUBLIC_EXAMPLES.stripeTestKey}@host.corpus.test/`, {
      intent: { kind: 'public_example', rule, value: PUBLIC_EXAMPLES.stripeTestKey },
    });
    b.add(file, `${rule}/public-example/aws-secret-encoded`, `${scheme}://user:${encodeURIComponent(PUBLIC_EXAMPLES.awsSecretAccessKey)}@host.corpus.test/`, {
      intent: { kind: 'public_example', rule, value: PUBLIC_EXAMPLES.awsSecretAccessKey },
    });
  }
  b.add(file, `${basic}/negative/unknown-scheme`, `ssh://git:${password('url/ssh')}@host.corpus.test/`, {
    intent: { kind: 'negative', rule: basic },
  });
}

/** Valeur synthétique d'une affectation : assez longue et variée pour le bonus d'entropie selon le cas. */
function secretValue(label: string, length = 24): string {
  return synth(label, ALNUM, length);
}

function addContextual(b: Builder): void {
  const file = 'rules-contextual.json';
  type Row = readonly [rule: string, variant: string, text: string, languageId?: string];
  const v = (label: string, length?: number): string => secretValue(`ctx/${label}`, length);
  const pw = (label: string): string => password(`ctx/${label}`);
  const positives: readonly Row[] = [
    // Affectation (`ASSIGNMENT`) : séparateurs, préfixes export/set, guillemets.
    ['contextual_password', 'dotenv-upper', `DB_PASSWORD=${pw('1')}\n`],
    ['contextual_password', 'dotenv-language', `PASSWORD=${pw('2')}\n`, 'dotenv'],
    ['contextual_password', 'colon', `password: ${pw('3')}\n`],
    ['contextual_password', 'walrus', `db_pass := "${pw('4')}"\n`, 'go'],
    ['contextual_password', 'passwd', `passwd=${pw('5')}`],
    ['contextual_password', 'passphrase', `ssh_passphrase = '${pw('6')}'`],
    ['contextual_password', 'pwd', `PWD=${pw('7')}`, 'dotenv'],
    ['contextual_password', 'json', `{"password": "${pw('8')}"}`, 'json'],
    ['contextual_password', 'yaml-nested', `db:\n  password: ${pw('9')}\n`, 'yaml'],
    ['contextual_password', 'numeric', `const password = 918273645;\n`, 'typescript'],
    ['contextual_password', 'expression-tail', `password = "${pw('10')}" + suffix\n`],
    ['contextual_password', 'after-label', `configuration : password=${pw('11')}\n`],
    ['contextual_password', 'crlf', `PASSWORD=${pw('12')}\r\nUSER=app\r\n`],
    ['contextual_password', 'quoted-reference', `PASSWORD="process.env.PASSWORD"\n`],
    ['contextual_password', 'dotenv-reference', `PASSWORD=process.env.PASSWORD\n`, 'dotenv'],
    ['contextual_password', 'query-string', `?user=app&password=${pw('13')}`],
    ['contextual_password', 'unquoted-to-eol', `password = ${pw('14')}, ${pw('15')}; # note\n`],
    ['contextual_api_key', 'export-quoted', `export API_KEY="${v('api1')}"\n`],
    ['contextual_api_key', 'camel-case', `const apiKey = "${v('api2')}";\n`, 'typescript'],
    ['contextual_api_key', 'kebab', `x-api-key: ${v('api3')}\n`],
    ['contextual_access_token', 'auth-token', `auth_token = ${v('tok1')}\n`],
    ['contextual_access_token', 'authorization', `Authorization: Bearer ${v('tok2', 40)}\n`],
    ['contextual_access_token', 'backtick', 'refresh_token = `' + v('tok3') + '`\n'],
    ['contextual_access_token', 'brace-object', `{access_token: '${v('tok4')}'}`],
    ['contextual_generic_secret', 'set', `set CLIENT_SECRET=${v('sec1')}\n`],
    ['contextual_generic_secret', 'secret', `secret = r"${v('sec2')}"\n`, 'python'],
    ['contextual_generic_secret', 'signing-key', `jwt_signing_key: ${v('sec3')}\n`],
    ['contextual_generic_secret', 'encryption-key', `let encryption_key = r#"${v('sec4')}"#;\n`, 'rust'],
    ['contextual_generic_secret', 'csharp-verbatim', `var clientSecret = @"${v('sec5')}";\n`, 'csharp'],
    ['contextual_generic_secret', 'csharp-interpolated', `var appSecret = $"${v('sec6')}";\n`, 'csharp'],
    ['contextual_generic_secret', 'yaml-block', `app_secret: |\n  ${v('sec7')}\n  ${v('sec8')}\nnext: 1\n`, 'yaml'],
    ['contextual_generic_secret', 'yaml-folded', `secret_key: >-\n  ${v('sec9')}\n`],
    ['contextual_generic_secret', 'heredoc', `SECRET=<<EOF\n${v('sec10')}\nEOF\n`, 'shellscript'],
    ['contextual_generic_secret', 'python-triple', `secret = """${v('sec11')}\n${v('sec12')}"""\n`, 'python'],
    ['contextual_generic_secret', 'python-prefix', `secret_key = f'${v('sec13')}'\n`, 'python'],
    ['contextual_generic_secret', 'regex-literal', `secret = /${v('sec14')}/\n`],
    ['contextual_private_key', 'quoted', `private_key = "${v('pk1', 40)}"\n`],
    ['contextual_private_key', 'camel', `privateKey: '${v('pk2', 40)}'\n`],
    ['contextual_cloud_credential', 'aws', `aws_secret_access_key = ${synth('ctx/aws', B64, 40)}\n`],
    ['contextual_cloud_credential', 'azure', `AZURE_STORAGE_KEY=${synth('ctx/azure', ALNUM, 30)}\n`],
    ['contextual_database_credentials', 'connection-string', `connection_string = "Server=db;User Id=app;Password=${pw('cs1')};"\n`],
    ['contextual_database_credentials', 'database-url-query', `DATABASE_URL=sqlserver://db?user=app&password=${pw('cs2')}\n`],
    // Affectations indexées, PowerShell, arguments, fonctions, npm.
    ['contextual_password', 'process-env-index', `process.env["DB_PASSWORD"] = "${pw('i1')}";\n`],
    ['contextual_access_token', 'os-environ-index', `os.environ['API_TOKEN'] = '${v('i2')}'\n`],
    ['contextual_generic_secret', 'deno-env-index', `(Deno.env["APP_SECRET"] = "${v('i3')}")\n`],
    ['contextual_access_token', 'powershell', `$env:GITHUB_TOKEN = "${v('ps1')}"\n`],
    ['contextual_password', 'cli-password-equals', `deploy --password=${pw('cli1')}\n`],
    ['contextual_api_key', 'cli-api-key-space', `tool --api-key ${v('cli2')}\n`],
    ['contextual_api_key', 'cli-apikey', `tool --apikey=${v('cli3')}\n`],
    ['contextual_generic_secret', 'cli-client-secret', `oauth --client_secret=${v('cli4')}\n`],
    ['contextual_access_token', 'cli-token', `gh --token ${v('cli5')}\n`],
    ['contextual_password', 'cli-passphrase', `gpg --passphrase ${pw('cli6')}\n`],
    ['contextual_generic_secret', 'cli-secret', `vault --secret=${v('cli7')}\n`],
    ['contextual_password', 'cli-passwd', `mysql --passwd=${pw('cli8')}\n`],
    ['contextual_api_key', 'deno-env-set', `Deno.env.set("API_KEY", "${v('fn1')}");\n`],
    ['contextual_password', 'os-environ-set', `os.environ.set('DB_PASSWORD', '${pw('fn2')}')\n`],
    ['contextual_access_token', 'npm-auth-token', `//registry.npmjs.org/:_authToken=${v('npm1', 36)}\n`],
    ['contextual_access_token', 'npm-auth-token-bare', `_authToken = ${v('npm2', 36)}\n`],
    // Cookies, authentification de base en ligne de commande, Docker.
    ['cookie_session_credential', 'cookie', `Cookie: theme=dark; sessionid=${v('ck1', 32)}\n`],
    ['cookie_session_credential', 'set-cookie', `Set-Cookie: refresh_token=${v('ck2', 32)}; Path=/; HttpOnly\n`],
    ['cookie_session_credential', 'jwt-cookie', `cookie: jwt=${v('ck3', 32)}; sid=${v('ck4', 16)}\n`],
    ['cli_basic_auth', 'curl-u', `${HTTP_CLIENT} -u deploy:${pw('ba1')} https://api.corpus.test\n`],
    ['cli_basic_auth', 'curl-user-equals', `${HTTP_CLIENT} --user=deploy:${pw('ba2')} https://api.corpus.test\n`],
    ['docker_auth', 'docker-config', `{"auths":{"registry.corpus.test":{"auth":"${base64(`robot:${pw('dk1')}`)}"}}}`],
    ['docker_auth', 'yaml', `auth: ${base64(`ci:${pw('dk2')}`)}\n`],
  ];
  for (const [rule, variant, text, languageId] of positives) {
    b.add(file, `${rule}/positive/${variant}`, text, {
      ...(languageId === undefined ? {} : { languageId }),
      intent: { kind: 'positive', rule },
    });
  }
  const negatives: readonly Row[] = [
    ['contextual_password', 'process-env', 'password = process.env.DB_PASSWORD\n'],
    ['contextual_password', 'getenv', 'const password = os.getenv("DB_PASSWORD")\n', 'python'],
    ['contextual_password', 'type-annotation', 'password: string;\n', 'typescript'],
    ['contextual_private_key', 'path', 'private_key_path = ./keys/id_ed25519\n'],
    ['contextual_private_key', 'env-reference', 'private_key = process.env.PRIVATE_KEY\n'],
    ['contextual_cloud_credential', 'environ-reference', 'aws_secret_access_key = os.environ["AWS_SECRET_ACCESS_KEY"]\n'],
    ['contextual_cloud_credential', 'access-key-id-name', 'aws_access_key_id = corpus-identifier\n'],
    ['contextual_password', 'null', 'password = null\n'],
    ['contextual_password', 'json-schema', '"password": {"type": "string"}', 'json'],
    ['contextual_password', 'enum', 'enum Field { Password = "password" }\n', 'typescript'],
    ['contextual_password', 'await', 'const password = await vault.get()\n', 'typescript'],
    ['contextual_password', 'command-substitution', 'password=$(vault read -field=value secret/app)\n', 'shellscript'],
    ['contextual_password', 'empty', 'password=\n'],
    ['contextual_password', 'not-sensitive', `username=${pw('neg1')}\n`],
    ['contextual_access_token', 'jsonwebtoken', `jsonwebtoken = ${v('neg2')}\n`],
    ['contextual_generic_secret', 'public-signing-key', `public_signing_key = ${v('neg3')}\n`],
    ['contextual_database_credentials', 'no-credential', 'connection_string = "Server=db;Database=app"\n'],
    ['contextual_api_key', 'config-get', 'api_key = config.get("api_key")\n', 'python'],
    ['contextual_api_key', 'property-reference', 'apiKey: import.meta.env.VITE_API_KEY\n', 'typescript'],
    ['cookie_session_credential', 'harmless-cookie', 'Cookie: theme=dark; lang=fr\n'],
    ['cookie_session_credential', 'empty-session', 'Cookie: sessionid=; theme=dark\n'],
    ['cli_basic_auth', 'no-password', `${HTTP_CLIENT} -u deploy https://api.corpus.test\n`],
    ['cli_basic_auth', 'glued-flag', `${HTTP_CLIENT}-u deploy:${pw('neg4')}\n`],
    ['docker_auth', 'not-a-pair', `{"auth":"${base64('not-a-pair')}"}`],
    ['docker_auth', 'empty-password', `{"auth":"${base64('robot:')}"}`],
  ];
  for (const [rule, variant, text, languageId] of negatives) {
    b.add(file, `${rule}/negative/${variant}`, text, {
      ...(languageId === undefined ? {} : { languageId }),
      intent: { kind: 'negative', rule },
    });
  }
  // Valeurs fictives et exemples publics, pour chaque règle contextuelle.
  const keys: Readonly<Record<string, string>> = {
    contextual_password: 'DB_PASSWORD',
    contextual_private_key: 'PRIVATE_KEY',
    contextual_cloud_credential: 'AWS_SECRET_ACCESS_KEY',
    contextual_api_key: 'API_KEY',
    contextual_access_token: 'ACCESS_TOKEN',
    contextual_generic_secret: 'CLIENT_SECRET',
    contextual_database_credentials: 'CONNECTION_STRING',
  };
  const placeholders = ['${SECRET_VALUE}', '<YOUR_SECRET>', 'changeme', '{{ secret }}', 'REDACTED'];
  for (const [rule, key] of Object.entries(keys)) {
    for (const value of placeholders) {
      const slug = value.replace(/[^A-Za-z]+/g, '-').replace(/^-|-$/g, '').toLowerCase();
      b.add(file, `${rule}/placeholder/${slug}`, `${key}=${value}\n`, { intent: { kind: 'placeholder', rule, value } });
    }
    for (const [slug, value] of Object.entries(PUBLIC_EXAMPLES)) {
      b.add(file, `${rule}/public-example/${slug}`, `${key}=${value}\n`, { intent: { kind: 'public_example', rule, value } });
    }
  }
  b.add(file, 'cookie_session_credential/placeholder/redacted', 'Cookie: sessionid=REDACTED\n', {
    intent: { kind: 'placeholder', rule: 'cookie_session_credential', value: 'REDACTED' },
  });
  b.add(file, 'cookie_session_credential/public-example/stripe', `Cookie: token=${PUBLIC_EXAMPLES.stripeTestKey}\n`, {
    intent: { kind: 'public_example', rule: 'cookie_session_credential', value: PUBLIC_EXAMPLES.stripeTestKey },
  });
  b.add(file, 'cli_basic_auth/placeholder/xxxx', `${HTTP_CLIENT} -u admin:xxxx https://api.corpus.test\n`, {
    intent: { kind: 'placeholder', rule: 'cli_basic_auth', value: 'xxxx' },
  });
  b.add(file, 'cli_basic_auth/public-example/aws-secret', `${HTTP_CLIENT} -u admin:${PUBLIC_EXAMPLES.awsSecretAccessKey} https://api.corpus.test\n`, {
    intent: { kind: 'public_example', rule: 'cli_basic_auth', value: PUBLIC_EXAMPLES.awsSecretAccessKey },
  });
  b.add(file, 'docker_auth/placeholder/redacted', `{"auth":"${base64('robot:<REDACTED>')}"}`, {
    intent: { kind: 'placeholder', rule: 'docker_auth', value: '<REDACTED>' },
  });
  b.add(file, 'docker_auth/public-example/stripe', `{"auth":"${base64(`robot:${PUBLIC_EXAMPLES.stripeTestKey}`)}"}`, {
    intent: { kind: 'public_example', rule: 'docker_auth', value: PUBLIC_EXAMPLES.stripeTestKey },
  });
}

function addEntropy(b: Builder): void {
  const file = 'rules-entropy.json';
  const rule = 'high_entropy';
  b.add(file, `${rule}/positive/mixed`, `checksum ${synth('ent/1', ALNUM, 32)}\n`, { intent: { kind: 'positive', rule } });
  b.add(file, `${rule}/positive/base64-like`, `blob ${synth('ent/2', B64, 44)}==\n`, { intent: { kind: 'positive', rule } });
  b.add(file, `${rule}/positive/hex-odd-length`, `id ${synth('ent/3', HEX, 30)}\n`, { intent: { kind: 'positive', rule } });
  b.add(file, `${rule}/positive/long`, `${synth('ent/4', URL_SAFE, 600)}\n`, { intent: { kind: 'positive', rule } });
  const negatives: readonly (readonly [string, string])[] = [
    ['uuid', '550e8400-e29b-41d4-a716-446655440000'],
    ['sha256-hex', synth('ent/n1', HEX, 64)],
    ['sha1-hex', synth('ent/n2', HEX, 40)],
    ['sri', `sha512-${synth('ent/n3', B64, 86)}==`],
    ['ulid', '01ARZ3NDEKTSV4RRFFQ69G5FAV'],
    ['stripe-publishable', `pk_live_${synth('ent/n4', ALNUM, 24)}`],
    ['tool-use-id', `toolu_${synth('ent/n5', ALNUM, 24)}`],
    ['absolute-path', '/usr/local/lib/node_modules/corpus/dist/index.js'],
    ['shell-env-path', '$HOME/projects/corpus/build/output.log'],
    ['low-entropy', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
    ['too-short', synth('ent/n6', ALNUM, 19)],
    ['alphabet', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'],
    ['redacted-marker', 'REDACTED_PASSWORD_VALUE'],
  ];
  for (const [variant, text] of negatives) b.add(file, `${rule}/negative/${variant}`, `${text}\n`, { intent: { kind: 'negative', rule } });
  const placeholder = `YOUR_${synth('ent/p1', ALNUM, 24)}`;
  b.add(file, `${rule}/placeholder/your-prefix`, `${placeholder}\n`, { intent: { kind: 'placeholder', rule, value: placeholder } });
  b.add(file, `${rule}/public-example/aws-secret`, `${PUBLIC_EXAMPLES.awsSecretAccessKey}\n`, {
    intent: { kind: 'public_example', rule, value: PUBLIC_EXAMPLES.awsSecretAccessKey },
  });
}

/** Une entrée par règle et par vue : la valeur positive de base déguisée (voir `viewVariants`). */
function addViews(b: Builder): void {
  const file = 'views.json';
  const github = fixedTokens('github_token', 'views')[0]?.[1] ?? '';
  // Cas de référence, un par vue, contrôlés par le générateur.
  const reference: readonly (readonly [FindingEncoding, string])[] = [
    ['plain', `token ${github}\n`],
    ['normalized', `token ${github.slice(0, 4)}\u200b${github.slice(4)}\n`],
    ['percent', `token ghp%5F${github.slice(4)}\n`],
    ['json-escaped', `{"token":"ghp\\u005f${github.slice(4)}"}`],
    ['base64', `payload ${base64(`token ${github}`)}\n`],
    ['whitespace-joined', `token ${github.slice(0, 10)}\n    ${github.slice(10)}\n`],
  ];
  for (const [view, text] of reference) {
    b.add(file, `github_token/view/${view}`, text, { intent: { kind: 'view', rule: 'github_token', view } });
  }
  b.add(file, 'github_token/view/normalized-fullwidth', `token ${github.slice(0, 2)}\uff50${github.slice(3)}\n`);
  b.add(file, 'github_token/view/percent-then-json', `token ghp%5Cu005f${github.slice(4)}\n`);
  b.add(file, 'github_token/view/json-then-percent', `{"t":"ghp\\u00255F${github.slice(4)}"}`);
  b.add(file, 'github_token/view/base64url', `payload ${base64Url(`token ${github}`)}\n`);
  b.add(file, 'github_token/view/base64-wrapped', `payload ${base64(`token ${github}`).replace(/(.{24})/g, '$1\n')}\n`);
  for (const rule of FIXED_RULE_ORDER) {
    const token = fixedTokens(rule, `views/${rule}`)[0]?.[1] ?? '';
    const text = `value ${token}\n`;
    const pivot = 'value '.length + (FIXED_PREFIX_LENGTH[rule] ?? 0) + 1;
    for (const [view, variant] of viewVariants(text, pivot)) b.add(file, `${rule}/variant/${view}`, variant);
  }
  const others: readonly (readonly [string, string, number])[] = [
    ['private_key_pem', `${pemLine('BEGIN', 'RSA PRIVATE KEY')}\n${keyBody('views/pem', 2)}\n${pemLine('END', 'RSA PRIVATE KEY')}\n`, 12],
    ['database_url_credentials', `postgres://app:${password('views/db')}@db.corpus.test/app\n`, 16],
    ['basic_auth_url', `https://deploy:${password('views/basic')}@git.corpus.test/\n`, 16],
    ['contextual_password', `DB_PASSWORD=${password('views/ctx')}\n`, 13],
    ['cookie_session_credential', `Cookie: sessionid=${secretValue('views/cookie', 32)}\n`, 20],
    ['cli_basic_auth', `${HTTP_CLIENT} -u deploy:${password('views/cli')} https://api.corpus.test\n`, 17],
    ['docker_auth', `{"auth":"${base64(`robot:${password('views/docker')}`)}"}`, 10],
    ['high_entropy', `checksum ${synth('views/entropy', ALNUM, 32)}\n`, 12],
  ];
  for (const [rule, text, pivot] of others) {
    for (const [view, variant] of viewVariants(text, pivot)) b.add(file, `${rule}/variant/${view}`, variant);
  }
}

/** Espaces que `\s` de JavaScript reconnaît et que `\s` de RE2 ne reconnaît pas. */
export const JS_ONLY_SPACES: Readonly<Record<string, string>> = {
  u00a0: '\u00a0',
  u2028: '\u2028',
  ufeff: '\ufeff',
  u3000: '\u3000',
};

/** Caractères ignorables par défaut (`Default_Ignorable_Code_Point`). */
export const DEFAULT_IGNORABLES: Readonly<Record<string, string>> = { u200b: '\u200b', u2060: '\u2060' };

function addEdgeCases(b: Builder): void {
  const file = 'edge-cases.json';
  const github = fixedTokens('github_token', 'edge')[0]?.[1] ?? '';
  const pw = password('edge/pw');
  // Hors BMP : positions UTF-16 ≠ positions en octets.
  b.add(file, 'non-bmp/emoji-before-token', `\u{1f600}\u{1f511} ${github}\n`);
  b.add(file, 'non-bmp/emoji-in-password', `DB_PASSWORD=\u{1f600}${pw}\u{1f512}\n`);
  b.add(file, 'non-bmp/math-bold-prefix', `token \u{1d420}\u{1d421}\u{1d429}_${github.slice(4)}\n`);
  b.add(file, 'non-bmp/emoji-around-entropy', `\u{1f9ea}${synth('edge/ent', ALNUM, 32)}\u{1f9ea}\n`);
  b.add(file, 'non-bmp/emoji-in-url-password', `postgres://app:${pw}\u{1f600}@db.corpus.test/app\n`);
  b.add(file, 'non-bmp/cjk-and-emoji-context', `\u5bc6\u7801 ${'\u{1f642}'.repeat(10)} password = "${pw}"\n`);
  // Espaces reconnus par `\s` de JavaScript et pas par celui de RE2.
  for (const [name, space] of Object.entries(JS_ONLY_SPACES)) {
    b.add(file, `js-space/${name}/before-cli-basic-auth`, `${HTTP_CLIENT}${space}-u deploy:${pw} https://api.corpus.test\n`);
    b.add(file, `js-space/${name}/before-assignment`, `note${space}password=${pw}\n`);
    b.add(file, `js-space/${name}/around-separator`, `password${space}=${space}${pw}\n`);
    b.add(file, `js-space/${name}/cli-argument`, `deploy${space}--token${space}${secretValue('edge/cli')}\n`);
    b.add(file, `js-space/${name}/powershell`, `${space}$env:API_TOKEN${space}=${space}${secretValue('edge/ps')}\n`);
    b.add(file, `js-space/${name}/before-token`, `token${space}${github}\n`);
    b.add(file, `js-space/${name}/in-cookie`, `Cookie: theme=dark;${space}sessionid=${secretValue('edge/cookie', 32)}\n`);
    b.add(file, `js-space/${name}/before-docker-auth`, `x${space}auth: ${base64(`ci:${pw}`)}\n`);
  }
  b.add(file, 'line-start/u2029-before-assignment', `note\u2029password=${pw}\n`);
  b.add(file, 'line-start/cr-before-cli-basic-auth', `x\r${HTTP_CLIENT} -u deploy:${pw} https://api.corpus.test\n`);
  b.add(file, 'line-start/cr-before-npm-auth-token', `x\r_authToken=${secretValue('edge/npm', 36)}\n`);
  // Caractères ignorables par défaut, dans un jeton, une clé et devant une valeur.
  for (const [name, character] of Object.entries(DEFAULT_IGNORABLES)) {
    b.add(file, `ignorable/${name}/in-token`, `token ${github.slice(0, 12)}${character}${github.slice(12)}\n`);
    b.add(file, `ignorable/${name}/in-key`, `pass${character}word = ${pw}\n`);
    b.add(file, `ignorable/${name}/before-value`, `password = ${character}${pw}\n`);
    b.add(file, `ignorable/${name}/in-private-key-header`, `${pemLine('BEGIN', `RSA PRI${character}VATE KEY`)}\n${keyBody('edge/ign', 1)}\n`);
  }
  // Repliement de casse : JavaScript sans `u` ne replie ni U+017F (s long) ni U+212A (signe kelvin).
  b.add(file, 'case-fold/long-s-in-scheme', `po\u017ftgres://app:${pw}@db.corpus.test/app\n`);
  b.add(file, 'case-fold/kelvin-in-aws-key', `\u212aEY AKIA${synth('edge/kelvin', UPPER + DIGITS, 16)}\n`);
  b.add(file, 'case-fold/kelvin-in-cookie-header', `Coo\u212aie: sessionid=${secretValue('edge/kc', 32)}\n`);
  // JWT de plus de 1 000 répétitions par segment, et au-delà des bornes JavaScript (2 048, 8 192, 4 096).
  b.add(file, 'long-jwt/segments-over-1000', `Authorization: ${jwt('edge/jwt1', 900, 2_400, 1_500)}\n`);
  b.add(file, 'long-jwt/header-over-2048', `${jwt('edge/jwt2', 1_600, 10, 43)}\n`);
  b.add(file, 'long-jwt/payload-over-8192', `${jwt('edge/jwt3', 1, 6_300, 43)}\n`);
  b.add(file, 'long-jwt/signature-over-4096', `${jwt('edge/jwt4', 1, 10, 4_200)}\n`);
  b.add(file, 'long-jwt/signature-4096', `${jwt('edge/jwt5', 1, 10, 4_096)}\n`);
  // `-u utilisateur:mot de passe` : guillemets doubles, simples, sans, dépareillés (ancienne rétro-référence).
  const forms: Readonly<Record<string, string>> = {
    'double-quotes': `"deploy:${pw}"`,
    'single-quotes': `'deploy:${pw}'`,
    'no-quotes': `deploy:${pw}`,
    'mismatched-double-single': `"deploy:${pw}'`,
    'mismatched-single-double': `'deploy:${pw}"`,
    'opening-double-only': `"deploy:${pw}`,
    'closing-single-only': `deploy:${pw}'`,
  };
  const matching = new Set(['double-quotes', 'single-quotes', 'no-quotes']);
  for (const [name, credential] of Object.entries(forms)) {
    b.add(file, `cli-basic-auth-quotes/${name}`, `${HTTP_CLIENT} -u ${credential} https://api.corpus.test\n`, {
      ...(matching.has(name) ? { intent: { kind: 'positive', rule: 'cli_basic_auth' } as const } : {}),
    });
    b.add(file, `cli-basic-auth-quotes/${name}-user-flag`, `${HTTP_CLIENT} --user ${credential} https://api.corpus.test\n`);
  }
  // Fins de ligne et mélanges.
  b.add(file, 'contextual/optional-type-annotation', 'password: Optional[str] = None\n', { languageId: 'python' });
  b.add(file, 'line-endings/crlf-yaml-block', `secret: |\r\n  ${secretValue('edge/crlf')}\r\nnext: 1\r\n`, { languageId: 'yaml' });
  b.add(file, 'mixed/several-rules', `${github}\nDB_PASSWORD=${pw}\npostgres://app:${pw}@db.corpus.test/app\n`);
  b.add(file, 'mixed/nul-byte', `before\u0000${github}\u0000after`);
  b.add(file, 'empty/empty-input', '');
  b.addBytes(file, 'invalid-utf8/lone-continuation-before-token', Uint8Array.from([0x80, ...new TextEncoder().encode(` ${github}`)]));
  b.addBytes(file, 'invalid-utf8/truncated-sequence-in-password', Uint8Array.from([...new TextEncoder().encode(`DB_PASSWORD=${pw}`), 0xe2, 0x82, 0x0a]));
  const encoded = (text: string): number[] => [...new TextEncoder().encode(text)];
  b.addBytes(file, 'invalid-utf8/overlong-slash-before-token', Uint8Array.from([0xc0, 0xaf, 0xe0, 0x80, 0xaf, ...encoded(` ${github}`)]));
  b.addBytes(file, 'invalid-utf8/above-u10ffff-before-token', Uint8Array.from([0xf4, 0x90, 0x80, 0x80, ...encoded(` ${github}`)]));
  b.addBytes(file, 'invalid-utf8/truncated-at-end', Uint8Array.from([...encoded(`token ${github} `), 0xf0, 0x9f, 0x98]));
  b.addBytes(file, 'invalid-utf8/inside-token', Uint8Array.from([...encoded(`token ${github.slice(0, 20)}`), 0xff, ...encoded(`${github.slice(20)}\n`)]));
  b.addBytes(file, 'invalid-utf8/inside-password', Uint8Array.from([...encoded(`DB_PASSWORD=${pw.slice(0, 6)}`), 0xfe, ...encoded(`${pw.slice(6)}\n`)]));
  b.addBytes(file, 'invalid-utf8/surrogate-encoding', Uint8Array.from([0xed, 0xa0, 0x80, ...new TextEncoder().encode(` ${github}`)]));
}

/** Contenu de `bytes` octets : remplissage neutre, puis `tail`. */
function filled(bytes: number, tail: string): string {
  const tailBytes = new TextEncoder().encode(tail).length;
  const line = 'lorem ipsum dolor sit amet consectetur\n';
  const fill = bytes - tailBytes;
  return `${line.repeat(Math.floor(fill / line.length))}${'.'.repeat(fill % line.length)}${tail}`;
}

function addLimits(b: Builder): void {
  const file = 'limits.json';
  const github = fixedTokens('github_token', 'limits')[0]?.[1] ?? '';
  const tail = `\ntoken ${github}\n`;
  b.add(file, 'limit/exactly-1mib-with-token-at-end', filled(MAX_INPUT_BYTES, tail));
  b.add(file, 'limit/1mib-plus-one-with-token-at-end', filled(MAX_INPUT_BYTES + 1, tail));
  // Dernier caractère sur quatre octets : la limite porte sur les octets, pas sur les unités UTF-16.
  b.add(file, 'limit/exactly-1mib-ending-non-bmp', filled(MAX_INPUT_BYTES, `${tail}\u{1f600}`));
  b.add(file, 'limit/1mib-plus-one-ending-non-bmp', filled(MAX_INPUT_BYTES + 1, `${tail}\u{1f600}`));
}

/** Tous les cas synthétiques, dans l'ordre d'écriture. */
export function syntheticCases(): SyntheticCase[] {
  const b = builder();
  addFixedRules(b);
  addPrivateKeys(b);
  addCredentialUrls(b);
  addContextual(b);
  addEntropy(b);
  addViews(b);
  addEdgeCases(b);
  addLimits(b);
  return b.cases;
}
