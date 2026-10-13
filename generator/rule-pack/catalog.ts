/**
 * Pack de règles initial : extraction déterministe du catalogue Secret Guard depuis sa copie figée
 * (`pack/initial/upstream/rules.ts.txt`, commit `UPSTREAM_COMMIT`), puis traduction en RE2.
 * Fonctions pures : `generate-initial-pack.ts` écrit le résultat, `test/rule-pack.test.ts` le compare au fichier
 * commité. Toute correction du Pack (parité prouvée par le corpus) passe par ce fichier.
 */
import type { RuleFamily, RulePack, RulePackRule, RuleSecretType } from '../src/rule-pack.ts';
import { RULE_FAMILIES, RULE_SECRET_TYPES } from '../src/rule-pack.ts';
import { translateJsPattern, type Translation } from './js-to-re2.ts';

/** Dépôt, commit et chemin d'origine du catalogue (Apache-2.0). */
export const UPSTREAM_REPOSITORY = 'jt33120/poc-AI_guard';
export const UPSTREAM_COMMIT = 'c177a447b8cdf8ce07e0c3160ea45dace99b6dc9';
export const UPSTREAM_PATH = 'secret-guard/packages/core/src/rules.ts';

/** En-tête du Pack initial. */
export const INITIAL_PACK_HEADER = {
  schemaVersion: 1,
  minAgentVersion: '0.0.0',
  packVersion: 1,
  issuedAt: '2026-10-09T00:00:00Z',
} as const;

/** Validateurs nommés : fonction de `rules.ts` → nom dans le Pack. */
export const VALIDATOR_NAMES: Readonly<Record<string, string>> = { isStructurallyValidJwt: 'jwt_structure' };

/**
 * Bornes de longueur de la valeur détectée (étendue du constat), reportées des répétitions de plus de 1 000 que la
 * traduction ouvre. Calculées sur le motif d'origine :
 *   - `jwt` : `eyJ` + 4..2048 + `.eyJ` + 4..8192 + `.` + 8..4096 → 24..14 344 (jeton entier) ;
 *   - URL à identifiants : schéma (3 à 11 caractères) + `://` + 1..2048 → 7..2 062 (correspondance entière, avant
 *     retrait de la ponctuation finale) ;
 *   - `cli_basic_auth` : `utilisateur:mot de passe`, 1..256 + `:` + 1..1024 → 3..1 281.
 */
export const VALUE_BOUNDS: Readonly<Record<string, readonly [number, number]>> = {
  jwt: [24, 14_344],
  database_url_credentials: [7, 2_062],
  basic_auth_url: [7, 2_062],
  cli_basic_auth: [3, 1_281],
};

/** Famille de chaque fonction d'analyse de `rules.ts` qui produit des constats. */
const FUNCTION_FAMILIES: Readonly<Record<string, RuleFamily>> = {
  scanFixedRules: 'private_key',
  scanCredentialUrls: 'credential_url',
  scanAssignmentPattern: 'contextual_assignment',
  scanCookieCredentials: 'contextual_assignment',
  scanBasicAuthArguments: 'contextual_assignment',
  scanDockerAuth: 'contextual_assignment',
  scanEntropy: 'entropy',
};

/** Règle du catalogue, telle que lue dans `rules.ts`. */
export interface CatalogRule {
  readonly ruleId: string;
  readonly family: RuleFamily;
  readonly secretType: RuleSecretType;
  readonly score: number;
  /** Nom de la fonction de validation de `rules.ts`, vide sans validateur. */
  readonly validatorFunction: string;
  /** Motif JavaScript d'origine, absent quand la règle combine plusieurs motifs (logique du moteur). */
  readonly source: { readonly name: string; readonly pattern: string; readonly flags: string } | undefined;
  /** Groupe capturant qui porte la valeur (`capture` d'une règle fixe), 0 : correspondance entière. */
  readonly capture: number;
}

/** Littéral d'expression régulière JavaScript : `/…/drapeaux`, classes comprises (une `/` y est littérale). */
const REGEX_LITERAL = String.raw`\/((?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\[\n])+)\/([a-z]*)`;

function required<T>(value: T | undefined | null, what: string): T {
  if (value === undefined || value === null) {
    throw new Error(`Catalogue Secret Guard : ${what} introuvable.`);
  }
  return value;
}

function secretTypeOf(value: string | undefined): RuleSecretType {
  const found = RULE_SECRET_TYPES.find((type) => type === value);
  return required(found, `type de secret « ${String(value)} »`);
}

function scoreOf(value: string | undefined): number {
  return Number(required(value, 'score'));
}

/** Corps de `function name(` jusqu'à la première ligne `}` qui suit. */
function functionBody(text: string, name: string): string {
  const start = text.indexOf(`function ${name}(`);
  const end = text.indexOf('\n}\n', start);
  if (start < 0 || end < 0) {
    throw new Error(`Catalogue Secret Guard : fonction ${name} introuvable.`);
  }
  return text.slice(start, end + 2);
}

/** Motifs constants (`const NOM = /…/drapeaux;`) du fichier. */
function constantPatterns(text: string): ReadonlyMap<string, { readonly pattern: string; readonly flags: string }> {
  const patterns = new Map<string, { pattern: string; flags: string }>();
  for (const match of text.matchAll(new RegExp(String.raw`^const ([A-Z_]+) =\s*${REGEX_LITERAL};`, 'gm'))) {
    patterns.set(required(match[1], 'nom de motif'), { pattern: required(match[2], 'motif'), flags: match[3] ?? '' });
  }
  return patterns;
}

/**
 * Motif d'une règle produite par la fonction `name` : le seul motif constant que la fonction clone
 * (`clonePattern(NOM)`), ou aucun si elle en combine plusieurs ou les reçoit en paramètre (logique du moteur).
 */
function sourceOf(
  text: string,
  name: string,
  patterns: ReadonlyMap<string, { readonly pattern: string; readonly flags: string }>,
): CatalogRule['source'] {
  const names = [...functionBody(text, name).matchAll(/clonePattern\(([A-Z_]+)\)/g)].map((match) => required(match[1], 'motif cloné'));
  const [only] = names;
  if (names.length !== 1 || only === undefined) {
    return undefined;
  }
  return { name: only, ...required(patterns.get(only), `motif ${only}`) };
}

function family(name: string): RuleFamily {
  return required(FUNCTION_FAMILIES[name], `famille de ${name}`);
}

/** Règles fixes (`FIXED_RULES`), famille « motif seul ». */
function fixedRules(text: string): CatalogRule[] {
  const start = text.indexOf('const FIXED_RULES: readonly FixedRule[] = [');
  const end = text.indexOf('\n];\n', start);
  if (start < 0 || end < 0) {
    throw new Error('Catalogue Secret Guard : FIXED_RULES introuvable.');
  }
  const block = text.slice(start, end);
  const entry = new RegExp(
    String.raw`\{\s*ruleId: "([a-z0-9_]+)",\s*secretType: "([a-z_]+)",\s*pattern:\s*${REGEX_LITERAL},\s*(?:capture: (\d+),\s*)?score: (\d+),\s*(?:validator: ([A-Za-z]+),\s*)?\}`,
    'g',
  );
  const rules = [...block.matchAll(entry)].map(
    (match): CatalogRule => ({
      ruleId: required(match[1], 'ruleId'),
      family: 'fixed_pattern',
      secretType: secretTypeOf(match[2]),
      score: scoreOf(match[6]),
      validatorFunction: match[7] ?? '',
      source: { name: 'FIXED_RULES', pattern: required(match[3], 'motif'), flags: match[4] ?? '' },
      capture: match[5] === undefined ? 0 : Number(match[5]),
    }),
  );
  if (rules.length !== [...block.matchAll(/ruleId: /g)].length) {
    throw new Error('Catalogue Secret Guard : une règle fixe n’a pas la forme attendue.');
  }
  return rules;
}

/** Deux règles choisies par une condition (`ruleId: cond ? "a" : "b"`), même ordre que la condition. */
function conditionalRules(
  text: string,
  name: string,
  condition: string,
  patterns: ReadonlyMap<string, { readonly pattern: string; readonly flags: string }>,
): CatalogRule[] {
  const body = functionBody(text, name);
  const pair = String.raw`${condition} \? "([a-z_]+)" : "([a-z_]+)"`;
  const ids = required(new RegExp(String.raw`ruleId: ${pair},`).exec(body), `règles de ${name}`);
  const types = new RegExp(String.raw`secretType: ${pair},`).exec(body);
  const singleType = /secretType: "([a-z_]+)",/.exec(body);
  const scores = required(new RegExp(String.raw`score: \(${condition} \? (\d+) : (\d+)\)`).exec(body), `scores de ${name}`);
  const source = sourceOf(text, name, patterns);
  return [1, 2].map(
    (index): CatalogRule => ({
      ruleId: required(ids[index], 'ruleId'),
      family: family(name),
      secretType: secretTypeOf(types === null ? singleType?.[1] : types[index]),
      score: scoreOf(scores[index]),
      validatorFunction: '',
      source,
      capture: 0,
    }),
  );
}

/** Affectations contextuelles `contextual_<type>` : un identifiant par type de `typeForSensitiveKey`. */
function contextualRules(text: string): CatalogRule[] {
  const body = functionBody(text, 'scanAssignmentPattern');
  required(/ruleId: `contextual_\$\{secretType\}`,/.exec(body), 'règle contextual_<type>');
  const score = scoreOf(required(/score: (\d+) \+ entropyBonus/.exec(body), 'score contextuel')[1]);
  const types = [...new Set([...functionBody(text, 'typeForSensitiveKey').matchAll(/return "([a-z_]+)"/g)].map((match) => match[1]))];
  return types.map(
    (type): CatalogRule => ({
      ruleId: `contextual_${String(type)}`,
      family: 'contextual_assignment',
      secretType: secretTypeOf(type),
      score,
      validatorFunction: '',
      source: undefined,
      capture: 0,
    }),
  );
}

/** Règles produites par `contextualFinding(view, "<ruleId>", "<type>", …)`, dans l'ordre du fichier. */
function contextualFindingRules(
  text: string,
  patterns: ReadonlyMap<string, { readonly pattern: string; readonly flags: string }>,
): CatalogRule[] {
  const score = scoreOf(required(/score: (\d+) - encodingPenalty/.exec(functionBody(text, 'contextualFinding')), 'score de contextualFinding')[1]);
  const rules: CatalogRule[] = [];
  for (const name of ['scanCookieCredentials', 'scanBasicAuthArguments', 'scanDockerAuth']) {
    for (const match of functionBody(text, name).matchAll(/contextualFinding\(\s*view,\s*"([a-z_]+)",\s*"([a-z_]+)",/g)) {
      rules.push({
        ruleId: required(match[1], 'ruleId'),
        family: family(name),
        secretType: secretTypeOf(match[2]),
        score,
        validatorFunction: '',
        source: sourceOf(text, name, patterns),
        capture: 0,
      });
    }
  }
  return rules;
}

function entropyRule(
  text: string,
  patterns: ReadonlyMap<string, { readonly pattern: string; readonly flags: string }>,
): CatalogRule {
  const body = functionBody(text, 'scanEntropy');
  const match = required(/ruleId: "([a-z_]+)",\s*secretType: "([a-z_]+)",[\s\S]*?score:\s*(\d+) -/.exec(body), 'règle d’entropie');
  return {
    ruleId: required(match[1], 'ruleId'),
    family: family('scanEntropy'),
    secretType: secretTypeOf(match[2]),
    score: scoreOf(match[3]),
    validatorFunction: '',
    source: sourceOf(text, 'scanEntropy', patterns),
    capture: 0,
  };
}

/**
 * Règles du catalogue, dans l'ordre de `rules.ts` : clés privées, règles fixes, URL à identifiants, affectations
 * contextuelles, entropie.
 */
export function extractCatalog(text: string): CatalogRule[] {
  const patterns = constantPatterns(text);
  const rules = [
    ...conditionalRules(text, 'scanFixedRules', 'complete', patterns),
    ...fixedRules(text),
    ...conditionalRules(text, 'scanCredentialUrls', 'database', patterns),
    ...contextualRules(text),
    ...contextualFindingRules(text, patterns),
    entropyRule(text, patterns),
  ];
  if (new Set(rules.map((rule) => rule.ruleId)).size !== rules.length) {
    throw new Error('Catalogue Secret Guard : identifiant de règle en double.');
  }
  for (const rule of rules) {
    if (!RULE_FAMILIES.includes(rule.family)) {
      throw new Error(`Catalogue Secret Guard : famille inconnue pour ${rule.ruleId}.`);
    }
  }
  return rules;
}

/** Traduction RE2 du motif d'une règle (motif vide sans motif d'origine). */
export function translationOf(rule: CatalogRule): Translation {
  return rule.source === undefined
    ? { pattern: '', openedRepetitions: [], backreferenceRewritten: false }
    : translateJsPattern(rule.source.pattern, rule.source.flags);
}

/** Règle du Pack issue d'une règle du catalogue. */
export function packRuleOf(rule: CatalogRule): RulePackRule {
  const translation = translationOf(rule);
  const bounds = VALUE_BOUNDS[rule.ruleId];
  if ((translation.openedRepetitions.length > 0) !== (bounds !== undefined)) {
    throw new Error(`Pack initial : bornes de longueur de ${rule.ruleId} incohérentes avec sa traduction.`);
  }
  const validator = rule.validatorFunction === '' ? '' : required(VALIDATOR_NAMES[rule.validatorFunction], `validateur ${rule.validatorFunction}`);
  return {
    ruleId: rule.ruleId,
    family: rule.family,
    secretType: rule.secretType,
    score: rule.score,
    validator,
    pattern: translation.pattern,
    minLength: bounds?.[0] ?? 0,
    maxLength: bounds?.[1] ?? 0,
  };
}

/** Pack de règles initial, construit depuis le texte figé de `rules.ts`. */
export function buildInitialPack(text: string): RulePack {
  return { ...INITIAL_PACK_HEADER, rules: extractCatalog(text).map(packRuleOf) };
}

/** Écriture du Pack sur disque : JSON indenté de deux espaces, fin de ligne finale. */
export function serializePack(pack: RulePack): string {
  return `${JSON.stringify(pack, null, 2)}\n`;
}
