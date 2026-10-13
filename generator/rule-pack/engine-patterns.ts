/**
 * Motifs du moteur de détection Go : `detect/engine_patterns.go`, écrit par `npm run pack:initial` avec
 * `pack/initial/pack.json`, depuis la même copie figée de `rules.ts`.
 *
 * Deux contenus, tous deux dérivés et jamais écrits à la main :
 *   - les motifs auxiliaires du moteur (affectations, préfixes de chaînes, filtres de valeurs fictives…) : chaque
 *     littéral JavaScript cité ici doit figurer tel quel dans `rules.ts` ; il est traduit en RE2 par la même
 *     traduction que le Pack (`translateJsPattern`, règles de `docs/rule-pack.md`) ;
 *   - les règles dont le moteur porte la logique (familles autres que « motif seul », et `jwt`) : le moteur refuse un
 *     Pack dont ces règles diffèrent de ce qu'il exécute (motif, bornes, famille, type de secret, validateur).
 * Fonctions pures ; `test/engine-patterns.test.ts` compare le fichier commité au résultat.
 */
import type { RulePackRule } from '../src/rule-pack.ts';
import { buildInitialPack } from './catalog.ts';
import { translateJsPattern } from './js-to-re2.ts';

/**
 * Usage d'un motif auxiliaire dans le moteur Go :
 *   - `regexp` : compilé et exécuté par `regexp` (RE2) ;
 *   - `reference` : la logique est écrite à la main dans le moteur (linéaire, bornes en unités UTF-16) ; le motif
 *     traduit sert d'oracle aux tests de fuzz.
 */
type Use = 'regexp' | 'reference';

interface AuxiliaryPattern {
  /** Nom de la constante Go. */
  readonly name: string;
  /** Littéral JavaScript, tel qu'il figure dans `rules.ts`. */
  readonly literal: string;
  readonly use: Use;
  /**
   * Début de ligne de JavaScript (drapeau `m`) : `^` reconnaît aussi la position qui suit U+2028 et U+2029, ce que
   * `(?m)^` de RE2 ne fait pas. Pour un motif `(?:^|X)…` dont la suite ne commence jamais par U+2028 ni U+2029, la
   * traduction ajoute l'alternative `[\x{2028}\x{2029}]`, qui consomme ce séparateur : même suite, même groupes ; seul
   * le début de la correspondance recule d'un caractère (le moteur n'en lit que les groupes).
   */
  readonly lineSeparators?: true;
}

/** Littéraux auxiliaires de `rules.ts`, dans l'ordre du fichier. */
export const AUXILIARY_PATTERNS: readonly AuxiliaryPattern[] = [
  { name: 'reDatabaseScheme', literal: String.raw`/^(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?):/i`, use: 'regexp' },
  {
    name: 'reAssignment',
    literal: String.raw`/(?:^|[\s,{;?&])(?:(?:export|set)\s+)?["']?([A-Za-z_][A-Za-z0-9_.-]{0,80})["']?\s*(?::=|[:=])\s*/gim`,
    use: 'regexp',
  },
  {
    name: 'reIndexedEnvAssignment',
    literal: String.raw`/(?:^|[\s,(])(?:process\.env|Deno\.env|os\.environ)\s*\[\s*["']([^"']{1,80})["']\s*\]\s*=\s*/gim`,
    use: 'regexp',
  },
  { name: 'rePowershellEnvAssignment', literal: String.raw`/(?:^|\s)\$env:([A-Za-z_][A-Za-z0-9_.-]{0,80})\s*=\s*/gim`, use: 'regexp' },
  {
    name: 'reCliArgumentAssignment',
    literal: String.raw`/(?:^|\s)--((?:api[-_]?key)|password|passwd|passphrase|token|client[-_]?secret|secret)(?:=|\s+)/gim`,
    use: 'regexp',
  },
  {
    name: 'reFunctionEnvAssignment',
    literal: String.raw`/\b(?:Deno\.env\.set|process\.env\.set|os\.environ\.set)\(\s*["']([^"']{1,80})["']\s*,\s*/gim`,
    use: 'regexp',
  },
  {
    name: 'reNpmAuthTokenAssignment',
    literal: String.raw`/(?:^|[\r\n])\s*(?:(?:\/\/|https?:\/\/)[^\s=]*:)?(_authToken)\s*=\s*/gim`,
    use: 'regexp',
    lineSeparators: true,
  },
  { name: 'reCookieHeader', literal: String.raw`/(?:^|[\r\n])(?:Cookie|Set-Cookie)\s*:\s*([^\r\n]*)/gim`, use: 'regexp', lineSeparators: true },
  {
    name: 'reCookieSecret',
    literal: String.raw`/(?:^|;\s*)(session(?:id|_id|token)?|auth(?:token)?|access_token|refresh_token|token|jwt|sid)\s*=\s*([^;\s]*)/gim`,
    use: 'regexp',
    lineSeparators: true,
  },
  {
    name: 'reYamlBlockStart',
    literal: String.raw`/(?:(?:!!?[A-Za-z0-9_:.-]+|&[A-Za-z0-9_.-]+)[ \t]+)*(?:[|>](?:(?:[1-9][+-]?)|(?:[+-][1-9]?))?)[ \t]*(?:#[^\r\n]*)?\r?\n/y`,
    use: 'regexp',
  },
  {
    name: 'refHeredocStart',
    literal: String.raw`/[^\r\n]{0,2048}?<<-?[ \t]*["']?([A-Za-z_][A-Za-z0-9_]*)["']?[^\r\n]*\r?\n/y`,
    use: 'reference',
  },
  { name: 'rePythonStringPrefix', literal: String.raw`/(?:u8|[rRuUbBfFL]{1,2})("""|'''|"|')/y`, use: 'regexp' },
  { name: 'reCsharpStringPrefix', literal: String.raw`/(?:\$@|@\$|@|\$)(")/y`, use: 'regexp' },
  { name: 'reRustRawStringPrefix', literal: String.raw`/(?:br|rb|r)(#{0,16})"/y`, use: 'regexp' },
  {
    name: 'rePlaceholder',
    literal: String.raw`/^(?:\$\{[A-Z_][A-Z0-9_.]*\}|\$\{\{\s*(?:secrets|vars)\.[A-Z_][A-Z0-9_.-]*\s*\}\}|\$[A-Z_][A-Z0-9_]*|\{\{\s*[A-Z_][A-Z0-9_.-]{0,80}\s*\}\}|<(?:(?:YOUR|INSERT|REPLACE|CHANGE)[_-]?[A-Z0-9_.-]+|REDACTED(?:_[A-Z0-9_.-]+)?|[A-Z0-9_.-]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY)[A-Z0-9_.-]*)>|(?:YOUR|INSERT|REPLACE|CHANGE)[_-]?(?:ME|THIS|[A-Z0-9_-]+)|(?:x{4,}|\*{4,}|\.{3,}))$/i`,
    use: 'regexp',
  },
  { name: 'rePlaceholderWord', literal: String.raw`/^(?:example|placeholder|redacted)$/i`, use: 'regexp' },
  { name: 'reConnectionUserinfo', literal: String.raw`/:\/\/[^\s/@]*:[^\s/@]+@/`, use: 'regexp' },
  { name: 'reConnectionParameter', literal: String.raw`/(?:^|[?;&])(?:password|passwd|pwd|token|sslkey)=([^&;\s]+)/i`, use: 'regexp' },
  { name: 'reConnectionPassword', literal: String.raw`/(?:^|;)\s*(?:password|passwd|pwd)\s*=\s*[^;\s]+/i`, use: 'regexp' },
  { name: 'reSafeLiteralWord', literal: String.raw`/^(?:null|undefined|true|false|none|nil)$/i`, use: 'regexp' },
  { name: 'reSafeTypeName', literal: String.raw`/^(?:string|number|boolean|unknown|never|any)(?:\[\])?$/`, use: 'regexp' },
  {
    name: 'reSafeNullableType',
    literal: String.raw`/^(?:string|number|boolean|unknown|never|any|str|String|SecretStr)(?:\[\])?(?:\s*\|\s*(?:null|undefined|None))*!?$/`,
    use: 'regexp',
  },
  { name: 'reSafeOptionalType', literal: String.raw`/^Optional\s*\[\s*(?:str|string|String|SecretStr)\s*\]$/`, use: 'regexp' },
  { name: 'reRegexClosing', literal: String.raw`/\/[dgimsuvy]*$/`, use: 'regexp' },
  { name: 'reRegexSyntax', literal: String.raw`/[\][{}()*+?|^$]/`, use: 'regexp' },
  {
    name: 'rePropertyReference',
    literal: String.raw`/^(?:(?:process\.env|import\.meta\.env|Deno\.env|os\.environ|secrets|vars|var|local|module|config)(?:(?:\??\.[A-Za-z_$][\w$-]*)|(?:\[\s*["'][^"']+["']\s*\]))+)(?:\s*(?:\?\?|\|\|)\s*(?:["']{2}|null|undefined))?$/`,
    use: 'regexp',
  },
  {
    name: 'reCodeReference',
    literal: String.raw`/^[A-Za-z_$][\w$]*(?:(?:\??\.[A-Za-z_$][\w$]*)|(?:\[(?:\d+|["'][^"']+["'])\])|(?:\([^"'` + '`' + String.raw`\r\n]*\)))+(?:\s*(?:\?\?|\|\|)\s*(?:["']{2}|null|undefined))?$/`,
    use: 'regexp',
  },
  {
    name: 'reEnvironmentGetter',
    literal: String.raw`/^(?:(?:(?:Deno\.env|os\.environ|config|secrets|vault)\.(?:get|require)|os\.getenv|os\.Getenv|System\.getenv|Environment\.GetEnvironmentVariable|std::env::var|std::getenv|getenv|env|getSecret|loadSecret|readSecret|resolveSecret)\(\s*["'][^"']+["']\s*\)\??)(?:\s*(?:\?\?|\|\|)\s*(?:["']{2}|null|undefined))?$/`,
    use: 'regexp',
  },
  { name: 'refShellDollarSubstitution', literal: String.raw`/^\$\([^\r\n]{1,512}\)$/`, use: 'reference' },
  { name: 'refShellBacktickSubstitution', literal: '/^`[^`\\r\\n]{1,512}`$/', use: 'reference' },
  { name: 'refBareEnvironmentAssignment', literal: String.raw`/^\s*(?:(?:export|set)\s+)?[A-Z_][A-Z0-9_]*\s*=\s*$/`, use: 'reference' },
  { name: 'refInferredShellAssignment', literal: String.raw`/^\s*[a-z_][A-Za-z0-9_]*\s*=\s*$/`, use: 'reference' },
  { name: 'refInferredStructuredAssignment', literal: String.raw`/^\s*[a-z_][A-Za-z0-9_.-]*\s*:?=\s*$/`, use: 'reference' },
  {
    name: 'refInferredCodeKeyword',
    literal: String.raw`/\b(?:const|final|let|mut|readonly|return|static|type|interface|enum|var)\b/`,
    use: 'reference',
  },
  {
    name: 'reInferredCodeDeclaration',
    literal: String.raw`/^\s*(?:[A-Za-z_$][\w$]*(?:::[A-Za-z_$][\w$]*)?(?:<[^\r\n=;]{1,128}>)?[*&?]?\s+)+[A-Za-z_$][\w$]*\s*=\s*$/`,
    use: 'regexp',
  },
  {
    name: 'reJSONSchemaTypeDescriptor',
    literal: String.raw`/^\{\s*"type"\s*:\s*"(?:array|boolean|integer|null|number|object|string)"(?:\s*[,}]|\s*$)/`,
    use: 'regexp',
  },
  {
    name: 'refExternalCodeKeyword',
    literal: String.raw`/\b(?:const|let|var|return|readonly|public|private|protected|type|interface|enum)\b/`,
    use: 'reference',
  },
  { name: 'reNumericLiteral', literal: String.raw`/^[+-]?(?:\d+(?:\.\d+)?|0x[0-9a-f]+)$/i`, use: 'regexp' },
  { name: 'reExpressionKeyword', literal: String.raw`/^(?:await\s+|new\s+|typeof\s+|this\.|super\.)/`, use: 'regexp' },
  {
    name: 'reExpressionOperator',
    literal: String.raw`/(?:={2,3}|!={1,2}|=>|\?[^:]|\s+as\s+|\s+satisfies\s+|\?\?|\|\||&&)/`,
    use: 'regexp',
  },
  { name: 'reTypeObjectDescriptor', literal: String.raw`/^\{\s*["']?type["']?\s*:\s*["'](?:string|number|boolean)["']/`, use: 'regexp' },
  {
    name: 'refDeclarationKeyword',
    literal: String.raw`/\b(?:const|let|var|readonly|public|private|protected)\b/`,
    use: 'reference',
  },
  {
    name: 'reTypedDefault',
    literal: String.raw`/^(?:string|number|boolean|unknown|never|any|str|String|SecretStr)(?:\[\])?\s*=/`,
    use: 'regexp',
  },
  { name: 'reIdentifier', literal: String.raw`/^[A-Za-z_$][\w$]*$/`, use: 'regexp' },
  { name: 'reSecretLikeIdentifier', literal: String.raw`/(?:password|passwd|token|secret|credential|apiKey|value)$/i`, use: 'regexp' },
  {
    name: 'refStatementKeyword',
    literal: String.raw`/\b(?:const|let|var|return|readonly|public|private|protected)\b/`,
    use: 'reference',
  },
  { name: 'refEnumKeyword', literal: String.raw`/\benum\b/`, use: 'reference' },
  { name: 'reHexadecimal', literal: String.raw`/^[0-9a-fA-F]+$/`, use: 'regexp' },
  {
    name: 'reUUID',
    literal: String.raw`/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/`,
    use: 'regexp',
  },
  { name: 'reSRIDigest', literal: String.raw`/^sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}$/i`, use: 'regexp' },
  { name: 'reULID', literal: String.raw`/^[0-9A-HJKMNP-TV-Z]{26}$/`, use: 'regexp' },
  { name: 'rePublicStripeIdentifier', literal: String.raw`/^(?:pk_(?:live|test)_|acct_|cus_|price_|prod_|pi_)[A-Za-z0-9_-]+$/`, use: 'regexp' },
  { name: 'reToolUseIdentifier', literal: String.raw`/^(?:srv)?toolu_[A-Za-z0-9]{24}$/`, use: 'regexp' },
  { name: 'reRedactedMarker', literal: String.raw`/^REDACTED_[A-Za-z0-9_]+$/`, use: 'regexp' },
  { name: 'rePathLike', literal: String.raw`/^(?:\/|node_modules\/)[A-Za-z0-9._/-]+$/`, use: 'regexp' },
  { name: 'reShellEnvironmentPath', literal: String.raw`/^[A-Za-z_][A-Za-z0-9_]*\/[A-Za-z0-9._/-]+$/`, use: 'regexp' },
];

/** Queue de `URL_WITH_CREDENTIALS` lue à la main par le moteur (répétition de 2 048, au-delà de RE2). */
const CREDENTIAL_URL_TAIL = String.raw`[^\s"'<>]{1,2048}/gi`;

/** Règles du Pack dont le moteur porte la logique : familles autres que « motif seul », et `jwt` (segments bornés). */
export function isEngineRule(rule: RulePackRule): boolean {
  return rule.family !== 'fixed_pattern' || rule.ruleId === 'jwt';
}

function literalParts(literal: string): { readonly source: string; readonly flags: string } {
  const close = literal.lastIndexOf('/');
  if (!literal.startsWith('/') || close <= 0) {
    throw new Error(`Motif auxiliaire mal formé : ${literal}`);
  }
  return { source: literal.slice(1, close), flags: literal.slice(close + 1) };
}

function translateAuxiliary(pattern: AuxiliaryPattern): { readonly re2: string; readonly opened: string } {
  const { source, flags } = literalParts(pattern.literal);
  const translation = translateJsPattern(source, flags);
  if (translation.openedRepetitions.length > 0 && pattern.use === 'regexp') {
    throw new Error(`Motif auxiliaire ${pattern.name} : répétition au-delà de RE2, à lire à la main.`);
  }
  let re2 = translation.pattern;
  if (pattern.lineSeparators === true) {
    const head = '(?m)(?:^|';
    if (!re2.startsWith(head)) {
      throw new Error(`Motif auxiliaire ${pattern.name} : début de ligne attendu.`);
    }
    re2 = `${head}[\\x{2028}\\x{2029}]|${re2.slice(head.length)}`;
  }
  const opened = translation.openedRepetitions.map((repetition) => `{${String(repetition.min)},${String(repetition.max)}}`).join(' ');
  return { re2, opened };
}

/** Préfixe de `URL_WITH_CREDENTIALS` (schéma et `://`), sans sa queue lue à la main. */
function credentialURLPrefix(upstream: string): string {
  const match = /^const URL_WITH_CREDENTIALS =\s*(\/.*\/gi);$/m.exec(upstream);
  const literal = match?.[1];
  if (literal?.endsWith(CREDENTIAL_URL_TAIL) !== true) {
    throw new Error('URL_WITH_CREDENTIALS : queue attendue introuvable.');
  }
  return translateJsPattern(literal.slice(1, -CREDENTIAL_URL_TAIL.length), 'gi').pattern;
}

function goString(value: string): string {
  return JSON.stringify(value);
}

/** Texte de `detect/engine_patterns.go`. */
export function buildEnginePatternsGo(upstream: string): string {
  const lines: string[] = [
    '// Code generated by `npm run pack:initial` (generator/rule-pack/engine-patterns.ts). DO NOT EDIT.',
    '',
    '// Motifs du moteur de détection, traduits de secret-guard/packages/core/src/rules.ts',
    '// (Apache-2.0, origine et avis dans UPSTREAM.md) par la traduction du Pack (docs/rule-pack.md).',
    '',
    'package detect',
    '',
  ];
  for (const pattern of AUXILIARY_PATTERNS) {
    if (!upstream.includes(pattern.literal)) {
      throw new Error(`Motif auxiliaire ${pattern.name} absent de rules.ts.`);
    }
    const { re2, opened } = translateAuxiliary(pattern);
    const role = pattern.use === 'regexp' ? 'exécuté par RE2' : 'oracle des tests, logique écrite à la main';
    const details = `${opened === '' ? '' : `, répétition ouverte ${opened}`}${pattern.lineSeparators === true ? ', U+2028 et U+2029 en début de ligne' : ''}`;
    // Littéral en bloc de code : gofmt ne le réécrit pas.
    lines.push(`// ${pattern.name} : ${role}${details}.`, '//', `//\t${pattern.literal}`, `const ${pattern.name} = ${goString(re2)}`, '');
  }
  lines.push(
    '// reCredentialURLPrefix : schéma et « :// » de URL_WITH_CREDENTIALS ; la queue est lue à la main.',
    '//',
    `//\t${CREDENTIAL_URL_TAIL.slice(0, -3)}`,
    `const reCredentialURLPrefix = ${goString(credentialURLPrefix(upstream))}`,
    '',
    '// engineRules : règles du Pack initial dont le moteur porte la logique ; un Pack dont ces règles diffèrent est refusé.',
    'var engineRules = []engineRule{',
  );
  for (const rule of buildInitialPack(upstream).rules.filter(isEngineRule)) {
    lines.push(
      `\t{ruleID: ${goString(rule.ruleId)}, family: ${goString(rule.family)}, secretType: ${goString(rule.secretType)}, validator: ${goString(rule.validator)}, pattern: ${goString(rule.pattern)}, minLength: ${String(rule.minLength)}, maxLength: ${String(rule.maxLength)}},`,
    );
  }
  lines.push('}', '');
  return lines.join('\n');
}
