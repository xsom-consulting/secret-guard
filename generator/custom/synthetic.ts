/**
 * Cas synthétiques des vecteurs du Pack de règles du client : chaque code d'erreur de validité et de motif, chaque
 * construction de motif admise et refusée, comparaison différentielle aléatoire des motifs (graine fixe), termes et
 * normalisation Unicode, n-grammes à la frontière, texte visible, budgets et limites. Aucune valeur n'est copiée d'un
 * vrai secret : identifiants et termes inventés, octets écrits ici.
 */
import { createHash } from 'node:crypto';
import type { CustomEngine } from './engine.ts';

/** Écart déclaré entre le moteur d'origine et le portage Go : raison (liste fermée de UPSTREAM.md) et résultat Go. */
export interface Divergence<T> {
  readonly reason: string;
  readonly go: T;
}

export interface PatternValidationSource {
  readonly id: string;
  readonly pattern: string;
  readonly hasContext: boolean;
  readonly caseInsensitive: boolean;
}

export interface PatternMatchingSource {
  readonly id: string;
  readonly pattern: string;
  readonly caseInsensitive: boolean;
  readonly bytes: Uint8Array;
}

export interface PackSource {
  readonly id: string;
  readonly bytes: Uint8Array;
  readonly divergence?: Divergence<{ readonly valid: boolean; readonly error: string }>;
}

export interface DetectionSource {
  readonly id: string;
  readonly detectors: string;
  readonly bytes: Uint8Array;
}

export interface ScanSource {
  readonly id: string;
  /** Charge du Pack (JSON), absente : analyse sans Pack. */
  readonly pack: Uint8Array | undefined;
  readonly bytes: Uint8Array;
  readonly divergence?: Divergence<{ readonly complete: boolean; readonly failure: string; readonly findings: readonly unknown[] }>;
}

export interface TermSource {
  readonly id: string;
  readonly kind: 'term' | 'digest';
  readonly input: string;
  readonly salt: string;
}

export interface Sources {
  readonly patternValidation: PatternValidationSource[];
  readonly patternMatching: PatternMatchingSource[];
  readonly packs: PackSource[];
  readonly detection: DetectionSource[];
  readonly scans: ScanSource[];
  readonly terms: TermSource[];
}

export function emptySources(): Sources {
  return { patternValidation: [], patternMatching: [], packs: [], detection: [], scans: [], terms: [] };
}

const encoder = new TextEncoder();
const utf8 = (text: string): Uint8Array => encoder.encode(text);
const json = (value: unknown): Uint8Array => utf8(JSON.stringify(value));

function concat(...parts: (Uint8Array | string)[]): Uint8Array {
  const chunks = parts.map((part) => (typeof part === 'string' ? utf8(part) : part));
  const out = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.length, 0));
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.length;
  }
  return out;
}

/** Sels synthétiques : 16 octets (22 caractères et « == ») ou 32 octets (43 et « = »), tirés de SHA-256. */
export function syntheticSalt(label: string, bytes: 16 | 32 = 16): string {
  return createHash('sha256').update(`secret-guard/custom-vectors/v1/salt/${label}`).digest().subarray(0, bytes).toString('base64');
}

type Json = Record<string, unknown>;

/** Pack valide minimal autour de détecteurs ; positifs et négatifs donnés. */
export function payload(detectors: Json[], positives: { detector: string; text: string }[] = [], negatives: string[] = [], overrides: Json = {}): Json {
  return {
    schemaVersion: 1,
    kind: 'xsom.secret-guard.rules-pack',
    packId: 'synthetic',
    tenantId: '00000000-0000-4000-8000-0000000000aa',
    version: 1,
    issuedAt: '2026-10-01T00:00:00Z',
    expiresAt: '2027-10-01T00:00:00Z',
    issuer: 'Secret Guard synthetic',
    detectors,
    tests: { positives, negatives },
    ...overrides,
  };
}

export function patternDetector(id: string, pattern: string, extra: Json = {}, action = 'block'): Json {
  const { context, ...match } = extra;
  return {
    id,
    label: `Détecteur ${id}`,
    category: 'customer_data',
    action,
    match: { type: 'pattern', pattern, ...match },
    ...(context === undefined ? {} : { context }),
  };
}

export function termsDetector(
  engine: CustomEngine,
  id: string,
  terms: readonly string[],
  salt: string,
  maxWords: number,
  context?: Json,
  action = 'block',
): Json {
  const saltBytes = engine.decodeSalt(salt);
  return {
    id,
    label: `Termes ${id}`,
    category: 'project',
    action,
    match: { type: 'terms', salt, digests: terms.map((term) => engine.termDigest(saltBytes, engine.normalizeTerm(term))), maxWords },
    ...(context === undefined ? {} : { context }),
  };
}

// --- Motifs --------------------------------------------------------------------------------------------------------

/** Un cas par code d'erreur de motif (ordre du contrat), plus les ordres de contrôle. */
const PATTERN_REFUSALS: readonly (readonly [string, string, boolean?])[] = [
  ['length', 'A'.repeat(257)],
  ['length-empty', ''],
  ['length-before-character', `${'é'.repeat(300)}`],
  ['invalid_character', 'CLI-é{3}'],
  ['invalid_character-tab', 'CLI-\t[0-9]'],
  ['invalid_character-del', 'CLI-\u007f12'],
  ['invalid_character-before-syntax', 'CLI-(é'],
  ['empty_alternative-leading', '|ABC'],
  ['empty_alternative-trailing', 'ABC|'],
  ['empty_alternative-middle', 'ABC||DEF'],
  ['empty_alternative-group', 'ABC(?:)'],
  ['empty_alternative-group-branch', 'ABC(?:x|)'],
  ['empty_alternative-unterminated-group', 'ABC(?:'],
  ['too_deep', 'ABC(?:(?:(?:(?:(?:x)))))'],
  ['empty_class', 'ABC[]'],
  ['negated_class', 'ABC[^a]'],
  ['bad_class_char-open', 'ABC[[]'],
  ['bad_class_char-caret', 'ABC[a^]'],
  ['bad_class_char-dash-first', 'ABC[-a]'],
  ['bad_class_char-dash-last', 'ABC[a-]'],
  ['bad_class_char-range-to-class', 'ABC[a-\\d]'],
  ['bad_class_char-class-then-dash', 'ABC[\\d-z]'],
  ['bad_range', 'ABC[z-a]'],
  ['bad_escape-end', 'ABC\\'],
  ['bad_escape-class-end', 'ABC[\\'],
  ['bad_escape-b', 'ABC\\b'],
  ['bad_escape-D', 'ABC\\D'],
  ['bad_escape-n', 'ABC\\n'],
  ['bad_escape-x', 'ABC\\x41'],
  ['bad_escape-u', 'ABC\\u0041'],
  ['bad_escape-p', 'ABC\\p{L}'],
  ['bad_escape-backref', 'ABC(?:x)\\1'],
  ['bad_escape-class-W', 'ABC[\\W]'],
  ['bad_escape-letter', 'ABC\\q'],
  ['dot_not_allowed', 'ABC.'],
  ['anchor_not_allowed-caret', '^ABC'],
  ['anchor_not_allowed-dollar', 'ABC$'],
  ['group_not_allowed-capture', '(ABC)'],
  ['group_not_allowed-lookahead', '(?=ABC)ABC'],
  ['group_not_allowed-lookbehind', '(?<=x)ABC'],
  ['group_not_allowed-named', 'ABC(?<n>x)'],
  ['group_not_allowed-flags', '(?i)ABC'],
  ['group_not_allowed-truncated', 'ABC(?'],
  ['unbounded_quantifier-star', 'ABCx*'],
  ['unbounded_quantifier-plus', 'ABCx+'],
  ['unbounded_quantifier-open', 'ABCx{2,}'],
  ['unbounded_quantifier-atom-star', 'ABC*x'],
  ['unbounded_quantifier-group-plus', 'ABC(?:xy)+'],
  ['dangling_quantifier-question', '?ABC'],
  ['dangling_quantifier-brace', '{2}ABC'],
  ['dangling_quantifier-after-bar', 'ABC|?x'],
  ['stacked_quantifier-lazy', 'ABCx??'],
  ['stacked_quantifier-brace-question', 'ABCx{2}?'],
  ['stacked_quantifier-brace-brace', 'ABCx{2}{3}'],
  ['stacked_quantifier-question-plus', 'ABCx?+'],
  ['stacked_quantifier-question-star', 'ABCx?*'],
  ['bad_quantifier-zero', 'ABCx{0}'],
  ['bad_quantifier-leading-zero', 'ABCx{01}'],
  ['bad_quantifier-double-zero', 'ABCx{00}'],
  ['bad_quantifier-65', 'ABCx{65}'],
  ['bad_quantifier-max-65', 'ABCx{0,65}'],
  ['bad_quantifier-max-zero', 'ABCx{0,0}'],
  ['bad_quantifier-inverted', 'ABCx{5,2}'],
  ['bad_quantifier-space', 'ABCx{1, 3}'],
  ['bad_quantifier-no-min', 'ABCx{,3}'],
  ['bad_quantifier-four-digits', 'ABCx{1000}'],
  ['bad_quantifier-letters', 'ABCx{a}'],
  ['bad_quantifier-unterminated', 'ABCx{2'],
  ['bad_quantifier-unterminated-max', 'ABCx{1,2'],
  ['unbalanced_class', 'ABC[a-z'],
  ['unbalanced_class-escape', 'ABC[a\\]'],
  ['unbalanced_group-close', 'ABC)'],
  ['unbalanced_group-open', 'ABC(?:x'],
  ['unbalanced_group-nested', 'ABC(?:x(?:y)'],
  ['bad_literal-bracket', 'ABC]'],
  ['bad_literal-brace', 'ABC}'],
  ['nested_repetition-quantified', 'ABC(?:x{2}){2}'],
  ['nested_repetition-optional', 'ABC(?:x?){2}'],
  ['nested_repetition-branch', 'ABC(?:x|y){2}'],
  ['nested_repetition-deep', 'ABC(?:(?:x|y)){2}'],
  ['nested_repetition-range', 'ABC(?:x?y){0,2}'],
  ['nested_repetition-before-stacked', 'ABC(?:x|y){2}{2}'],
  ['too_short', 'ab'],
  ['too_short-optional', 'ab(?:c)?'],
  ['too_short-alternative', 'ABC|ab', true],
  ['too_short-zero-min', 'x{0,8}y?z?', true],
  ['too_long', 'ABC[a-z]{64}[a-z]{64}[a-z]{64}[a-z]{62}'],
  ['too_long-group', 'ABC(?:[a-z]{2}){64}x{64}x{64}'],
  ['no_anchor', '[0-9]{14}'],
  ['no_anchor-short-run', 'AB[0-9]{4}CD'],
  ['no_anchor-quantified-run', 'A{3}BC?D'],
  ['no_anchor-alternative', 'ABC|DEF'],
  ['no_anchor-group', '(?:ABCD)x'],
  ['no_anchor-classes', '[A][B][C]x'],
];

/** Constructions admises (contexte présent ou ancre). */
const PATTERN_ADMITTED: readonly (readonly [string, string, boolean, boolean?])[] = [
  ['literal-run', 'ABC', false],
  ['min-length-3', 'ab[c]', true],
  ['max-length-256', 'ABC[a-z]{64}[a-z]{64}[a-z]{64}[a-z]{61}', false],
  ['escapes', 'ABC\\\\\\^\\$\\.\\|\\?\\*\\+\\(\\)\\[\\]\\{\\}\\-\\/', false],
  ['escaped-anchor', '\\.\\-\\/x', false],
  ['classes-ascii', 'ID-\\d\\w\\s', false],
  ['class-escapes', 'ABC[\\]\\[\\^\\-\\\\]', false],
  ['class-metacharacters', 'ABC[.*+?(){}|$/]', false],
  ['class-range-across-case', 'ABC[Z-a]', false, true],
  ['class-printable-range', 'ABC[ -~]{2}', false],
  ['class-mixed', 'ABC[\\d\\s_a-fA-F-]', false],
  ['class-dash-after-range', 'ABC[a-c-]', false],
  ['class-repeated-members', 'ABC[aaa\\d0-9]', false],
  ['group-alternatives', 'ABC(?:x|yz|0)', false],
  ['group-depth-4', 'ABC(?:(?:(?:(?:x))))', false],
  ['group-optional-nullable', 'XYZ(?:a?|b)?', false],
  ['group-zero-one-nullable', 'XYZ(?:a?|b){0,1}c', false],
  ['group-one', 'XYZ(?:a|b){1}', false],
  ['group-one-one', 'XYZ(?:a?b?){1,1}', false],
  ['group-repeated-fixed', 'ABC(?:x[0-9]){2,5}', false],
  ['group-repeated-optional-min', 'ABC(?:xy){0,3}', false],
  ['group-nested-optional', 'XYZ(?:(?:a?)?b?|c)?d', false],
  ['quantifiers', 'ABCa?b{2}c{0,3}d{1,64}e{64}', false],
  ['quantifier-zero-one', 'ABCa{0,1}', false],
  ['quantifier-three-digits-allowed-as-bound', 'ABCa{1,064}', false],
  ['alternatives-with-context', 'ABC|DEF', true],
  ['no-anchor-with-context', '[0-9]{14}', true],
  ['case-insensitive', 'acme-(?:prod|staging)-db[0-9]{1,2}', false, true],
  ['anchor-longest', 'AB-CDEF-GH', false],
  ['anchor-after-optional', 'x?y{0,2}ABCD', false],
  ['anchor-escaped-literals', '\\(\\)\\[x', false],
  ['space-literal', 'A B C', false],
  ['slash-and-comma', 'a/b,c', false],
];

/** Motifs et textes de la sémantique de correspondance (ECMAScript, matchAll, sans drapeau u). */
const MATCHING: readonly (readonly [string, string, boolean, readonly (string | Uint8Array)[]])[] = [
  ['empty-iteration', 'XYZ(?:a?|b)?', false, ['XYZb', 'XYZ', 'XYZa', 'XYZab', 'XYZbb']],
  ['empty-iteration-zero-one', 'XYZ(?:a?|b){0,1}c', false, ['XYZbc', 'XYZc', 'XYZac', 'XYZb']],
  ['empty-iteration-nested', 'XYZ(?:(?:a?)?b?|c)?d', false, ['XYZcd', 'XYZd', 'XYZad', 'XYZbd', 'XYZabd', 'XYZac']],
  ['empty-iteration-sequence', 'XYZ(?:a?b?c?|d)?', false, ['XYZd', 'XYZc', 'XYZbd', 'XYZcd', 'XYZabcd']],
  ['empty-iteration-classes', 'ABC(?:[0-9]{0,2}|x)?y', false, ['ABCxy', 'ABCy', 'ABC1y', 'ABC12y', 'ABC123y']],
  ['leftmost-first', 'XYZ(?:a)?(?:ab)?', false, ['XYZab', 'XYZaab']],
  ['alternation-backtrack', 'PRJ-(?:A|AB)[0-9]{2}', false, ['PRJ-AB12', 'PRJ-A12', 'PRJ-AB1']],
  ['greedy-bound', 'acme-(?:prod|staging)-db[0-9]{1,2}', true, ['ACME-Prod-DB7 acme-staging-db123', 'aCmE-PROD-db99']],
  ['non-overlapping', 'ABA', false, ['ABABABA', 'ABAABA']],
  ['case-folding-ascii-only', 'kelvin-[a-z]{2}', true, ['KELVIN-OK', 'Kelvin-ok', 'kelvin-Kk', 'kelvin-ſs', 'KELVİN-ok']],
  ['case-folding-range', 'ABC[Z-a]', true, ['abcz', 'ABC[', 'abc`', 'ABC{', 'abcA']],
  ['ascii-word', 'REF-\\w{4}', false, ['REF-été1 REF-ab_9', 'REF-ＡＢＣＤ', 'REF-a²b3']],
  ['ascii-space', 'ACME\\s[0-9]{3}', false, ['ACME 123 ACME 456', 'ACME\t789', 'ACME\u000b111', 'ACME\u000c222', 'ACME 333', 'ACME　444']],
  ['ascii-digit', 'NUM\\d{3}', false, ['NUM١٢٣ NUM123', 'NUM１２３']],
  ['astral', 'CLI-[0-9]{4}', false, ['🔒CLI-1234🔒 CLI-5678', '𝟏CLI-0000']],
  ['invalid-bytes', 'CLI-[0-9]{4}', false, [Uint8Array.from([0xff, ...utf8('CLI-1234'), 0xc3, ...utf8('CLI-5678'), 0xe2, 0x82])]],
  ['nul-bytes', 'A\\sB[ -~]{2}', false, [Uint8Array.from([0x41, 0x20, 0x42, 0x00, 0x41, 0x0a, 0x42, 0x7e, 0x7e, 0x00])]],
  ['repeated-group', 'ABC(?:x[0-9]){2,3}', false, ['ABCx1x2x3x4', 'ABCx1x', 'ABCx1x2']],
  ['optional-group-repeated-zero', 'ABC(?:xy){0,3}z', false, ['ABCz', 'ABCxyz', 'ABCxyxyxyz', 'ABCxyxyxyxyz']],
  ['escapes', '\\(\\)\\[x', false, ['()[x ()[y', '(()[x']],
  ['class-escapes', 'ABC[\\]\\[\\^\\-\\\\]', false, ['ABC] ABC[ ABC^ ABC- ABC\\ ABCx']],
  ['long-max', 'ACME[a-z]{64}[a-z]{64}[a-z]{60}', false, [`ACME${'a'.repeat(200)}`, `ACME${'b'.repeat(188)}`, `ACME${'c'.repeat(187)}`]],
];

/** Générateur pseudo-aléatoire déterministe (mulberry32). */
function random(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

function pick<T>(next: () => number, items: readonly T[]): T {
  return items[Math.floor(next() * items.length)] as T;
}

const RANDOM_ATOMS = ['a', 'b', 'A', 'z', '-', '0', '\\d', '\\w', '\\s', '[ab]', '[a-c0-1]', '\\.', '[\\]\\^\\-\\\\a]', '[Z-a]', '[!-/]', '[\\d\\s]', '\\[', '\\^', ' '];
const RANDOM_QUANTIFIERS = ['', '', '', '?', '{2}', '{0,3}', '{1,2}', '{0,64}', '{3}', '{0,1}'];
const RANDOM_GROUP_QUANTIFIERS = ['', '?', '?', '{0,1}', '{1}', '{2}', '{1,3}', '{0,2}'];

function randomSequence(next: () => number, depth: number): string {
  const length = 1 + Math.floor(next() * 4);
  let sequence = '';
  for (let index = 0; index < length; index += 1) {
    if (depth < 3 && next() < 0.3) {
      const branches = 1 + Math.floor(next() * 3);
      const inner = Array.from({ length: branches }, () => randomSequence(next, depth + 1)).join('|');
      sequence += `(?:${inner})${pick(next, RANDOM_GROUP_QUANTIFIERS)}`;
    } else sequence += pick(next, RANDOM_ATOMS) + pick(next, RANDOM_QUANTIFIERS);
  }
  return sequence;
}

const RANDOM_TEXT = ['a', 'b', 'A', 'B', 'c', 'z', 'Z', '-', '0', '1', ' ', '.', '\t', 'é', ' ', '_', '😀', '[', '\\', ']', '^', '`', '/', '!', 'K', 'ſ'];

function randomText(next: () => number): Uint8Array {
  const length = Math.floor(next() * 40);
  const parts: (Uint8Array | string)[] = [];
  for (let index = 0; index < length; index += 1) {
    parts.push(next() < 0.03 ? Uint8Array.from([pick(next, [0xff, 0xc3, 0xe2, 0x80])]) : pick(next, RANDOM_TEXT));
  }
  return concat(...parts);
}

/** Motifs et textes aléatoires (graine fixe), seuls ceux que le motif valide (avec contexte) gardés. */
function randomMatching(engine: CustomEngine, count: number): PatternMatchingSource[] {
  const next = random(0x5ec2e7);
  const out: PatternMatchingSource[] = [];
  for (let round = 0; out.length < count; round += 1) {
    const pattern = randomSequence(next, 0);
    const caseInsensitive = next() < 0.3;
    if (!engine.validatePattern(pattern, true, caseInsensitive).ok) continue;
    for (let sample = 0; sample < 3; sample += 1) {
      out.push({ id: `synthetic/random/${String(round)}-${String(sample)}`, pattern, caseInsensitive, bytes: randomText(next) });
    }
  }
  return out;
}

// --- Packs ---------------------------------------------------------------------------------------------------------

/** Remplace un champ à un chemin (clés et index) d'une copie profonde. */
function withField(value: Json, path: readonly (string | number)[], replacement: unknown): Json {
  const copy = structuredClone(value);
  let target: Record<string | number, unknown> = copy;
  for (const key of path.slice(0, -1)) target = target[key] as Record<string | number, unknown>;
  const last = path[path.length - 1] as string | number;
  if (replacement === REMOVE) delete target[last];
  else target[last] = replacement;
  return copy;
}

const REMOVE = Symbol('remove');

/** Pack JSON écrit à la main (formes que JSON.stringify n'écrit pas). */
function rawPack(text: string): Uint8Array {
  return utf8(text);
}

function schemaVariants(base: Json): [string, Json][] {
  const variants: [string, Json][] = [];
  const top = ['schemaVersion', 'kind', 'packId', 'tenantId', 'version', 'issuedAt', 'expiresAt', 'issuer', 'detectors', 'tests'];
  for (const key of top) variants.push([`missing-${key}`, withField(base, [key], REMOVE)]);
  const set = (name: string, path: (string | number)[], value: unknown): void => {
    variants.push([name, withField(base, path, value)]);
  };
  set('extra-member', ['extra'], true);
  set('schemaVersion-2', ['schemaVersion'], 2);
  set('schemaVersion-string', ['schemaVersion'], '1');
  set('kind-other', ['kind'], 'xsom.secret-guard.rules-pack.v2');
  set('packId-uppercase', ['packId'], 'Synthetic');
  set('packId-empty', ['packId'], '');
  set('packId-65', ['packId'], `p${'a'.repeat(64)}`);
  set('packId-64', ['packId'], `p${'a'.repeat(63)}`);
  set('packId-leading-dot', ['packId'], '.synthetic');
  set('packId-newline', ['packId'], 'synthetic\n');
  set('tenantId-empty', ['tenantId'], '');
  set('tenantId-129', ['tenantId'], 't'.repeat(129));
  set('tenantId-128-astral', ['tenantId'], '😀'.repeat(128));
  set('tenantId-number', ['tenantId'], 7);
  set('version-zero', ['version'], 0);
  set('version-max', ['version'], 2147483647);
  set('version-over-max', ['version'], 2147483648);
  set('version-fraction', ['version'], 1.5);
  set('version-string', ['version'], '1');
  set('issuedAt-date-only', ['issuedAt'], '2026-10-01');
  set('issuedAt-milliseconds', ['issuedAt'], '2026-10-01T00:00:00.000Z');
  set('issuedAt-offset', ['issuedAt'], '2026-10-01T00:00:00+00:00');
  set('issuedAt-impossible-date', ['issuedAt'], '2026-13-45T99:99:99Z');
  set('issuer-empty', ['issuer'], '');
  set('issuer-81', ['issuer'], 'i'.repeat(81));
  set('issuer-80-astral', ['issuer'], '𝒳'.repeat(80));
  set('detectors-empty', ['detectors'], []);
  set('detectors-object', ['detectors'], {});
  set('detector-extra', ['detectors', 0, 'extra'], 1);
  set('detector-missing-label', ['detectors', 0, 'label'], REMOVE);
  set('detector-label-empty', ['detectors', 0, 'label'], '');
  set('detector-label-81', ['detectors', 0, 'label'], 'l'.repeat(81));
  set('detector-label-80-astral', ['detectors', 0, 'label'], '😀'.repeat(80));
  set('detector-id-uppercase', ['detectors', 0, 'id'], 'Cli');
  set('detector-id-underscore', ['detectors', 0, 'id'], 'cli_id');
  set('detector-category-unknown', ['detectors', 0, 'category'], 'secret');
  set('detector-action-unknown', ['detectors', 0, 'action'], 'allow');
  set('detector-match-null', ['detectors', 0, 'match'], null);
  set('detector-match-array', ['detectors', 0, 'match'], []);
  set('detector-match-type-unknown', ['detectors', 0, 'match', 'type'], 'regex');
  set('pattern-extra', ['detectors', 0, 'match', 'extra'], 1);
  set('pattern-empty', ['detectors', 0, 'match', 'pattern'], '');
  set('pattern-257', ['detectors', 0, 'match', 'pattern'], 'A'.repeat(257));
  set('pattern-salt-member', ['detectors', 0, 'match', 'salt'], syntheticSalt('x'));
  set('caseInsensitive-string', ['detectors', 0, 'match', 'caseInsensitive'], 'true');
  set('caseInsensitive-false', ['detectors', 0, 'match', 'caseInsensitive'], false);
  set('minEntropyTenths-81', ['detectors', 0, 'match', 'minEntropyTenths'], 81);
  set('minEntropyTenths-negative', ['detectors', 0, 'match', 'minEntropyTenths'], -1);
  set('minEntropyTenths-zero', ['detectors', 0, 'match', 'minEntropyTenths'], 0);
  set('minEntropyTenths-fraction', ['detectors', 0, 'match', 'minEntropyTenths'], 2.5);
  set('minEntropyTenths-null', ['detectors', 0, 'match', 'minEntropyTenths'], null);
  set('context-null', ['detectors', 0, 'context'], null);
  set('context-extra', ['detectors', 0, 'context'], { keywords: ['client'], window: 8, extra: 1 });
  set('context-keywords-empty', ['detectors', 0, 'context'], { keywords: [], window: 8 });
  set('context-keywords-21', ['detectors', 0, 'context'], { keywords: Array.from({ length: 21 }, (_, i) => `kw${String(i)}`), window: 8 });
  set('context-keywords-20', ['detectors', 0, 'context'], { keywords: Array.from({ length: 20 }, (_, i) => `kw${String(i)}`), window: 8 });
  set('context-keyword-short', ['detectors', 0, 'context'], { keywords: ['k'], window: 8 });
  set('context-keyword-41', ['detectors', 0, 'context'], { keywords: [`k${'w'.repeat(40)}`], window: 8 });
  set('context-keyword-40', ['detectors', 0, 'context'], { keywords: [`k${'w'.repeat(39)}`], window: 8 });
  set('context-keyword-leading-space', ['detectors', 0, 'context'], { keywords: [' client'], window: 8 });
  set('context-keyword-symbols', ['detectors', 0, 'context'], { keywords: ['a _.@:/-z'], window: 8 });
  set('context-keyword-accent', ['detectors', 0, 'context'], { keywords: ['clié'], window: 8 });
  set('context-keywords-duplicate', ['detectors', 0, 'context'], { keywords: ['client', 'client'], window: 8 });
  set('context-keywords-case-distinct', ['detectors', 0, 'context'], { keywords: ['client', 'CLIENT'], window: 8 });
  set('context-window-zero', ['detectors', 0, 'context'], { keywords: ['client'], window: 0 });
  set('context-window-257', ['detectors', 0, 'context'], { keywords: ['client'], window: 257 });
  set('context-window-256', ['detectors', 0, 'context'], { keywords: ['client'], window: 256 });
  set('tests-missing-negatives', ['tests', 'negatives'], REMOVE);
  set('tests-extra', ['tests', 'extra'], []);
  set('tests-positives-object', ['tests', 'positives'], {});
  set('positive-extra', ['tests', 'positives', 0, 'extra'], 1);
  set('positive-text-empty', ['tests', 'positives', 0, 'text'], '');
  set('positive-text-2001', ['tests', 'positives', 0, 'text'], `CLI-12345678${'x'.repeat(1989)}`);
  set('positive-text-2000-astral', ['tests', 'positives', 0, 'text'], `CLI-12345678${'😀'.repeat(1988)}`);
  set('positive-detector-uppercase', ['tests', 'positives', 0, 'detector'], 'CLI');
  set('negatives-number', ['tests', 'negatives'], [1]);
  set('negatives-201', ['tests', 'negatives'], Array.from({ length: 201 }, () => 'rien'));
  set('negatives-200', ['tests', 'negatives'], Array.from({ length: 200 }, () => 'rien'));
  set('negative-empty', ['tests', 'negatives'], ['']);
  return variants;
}

function termsSchemaVariants(base: Json): [string, Json][] {
  const variants: [string, Json][] = [];
  const set = (name: string, path: (string | number)[], value: unknown): void => {
    variants.push([name, withField(base, ['detectors', 0, 'match', ...path], value)]);
  };
  set('salt-21', ['salt'], 'A'.repeat(21) + '==');
  set('salt-no-padding', ['salt'], 'A'.repeat(22));
  set('salt-32-bytes', ['salt'], syntheticSalt('long', 32));
  set('salt-url-alphabet', ['salt'], `${'A'.repeat(21)}-==`);
  set('salt-trailing-bits', ['salt'], `${'A'.repeat(21)}B==`);
  set('digests-empty', ['digests'], []);
  set('digest-uppercase', ['digests'], ['A'.repeat(64)]);
  set('digest-63', ['digests'], ['a'.repeat(63)]);
  set('digests-duplicate', ['digests'], ['a'.repeat(64), 'a'.repeat(64)]);
  set('digests-5001', ['digests'], Array.from({ length: 5001 }, (_, i) => i.toString(16).padStart(64, '0')));
  set('maxWords-zero', ['maxWords'], 0);
  set('maxWords-5', ['maxWords'], 5);
  set('maxWords-4', ['maxWords'], 4);
  set('terms-extra', ['extra'], 1);
  set('terms-pattern-member', ['pattern'], 'ABC');
  set('terms-missing-maxWords', ['maxWords'], REMOVE);
  return variants;
}

/** Packs synthétiques : schéma, chaque code de validité, ordre des contrôles, écarts déclarés. */
function syntheticPacks(engine: CustomEngine): PackSource[] {
  const packs: PackSource[] = [];
  const add = (name: string, value: Json | Uint8Array, divergence?: PackSource['divergence']): void => {
    packs.push({ id: `synthetic/pack/${name}`, bytes: value instanceof Uint8Array ? value : json(value), ...(divergence === undefined ? {} : { divergence }) });
  };
  const cli = patternDetector('cli', 'CLI-[0-9]{8}');
  const base = payload([cli], [{ detector: 'cli', text: 'Le client CLI-12345678 a appelé.' }], ['Le ticket JIRA-12345678 est clos.']);
  add('valid-pattern', base);
  for (const [name, variant] of schemaVariants(base)) add(`schema/${name}`, variant);
  const terms = termsDetector(engine, 'codes', ['Projet Faucon'], syntheticSalt('codes'), 2);
  const termsBase = payload([terms], [], ['rien de confidentiel']);
  add('valid-terms', termsBase);
  for (const [name, variant] of termsSchemaVariants(termsBase)) add(`schema/${name}`, variant);

  // Formes du document JSON.
  const text = JSON.stringify(base);
  add('json/pretty', rawPack(JSON.stringify(base, null, 2)));
  add('json/surrounding-whitespace', rawPack(` \n${text}\t\r\n`));
  add('json/number-forms', rawPack(text.replace('"version":1', '"version":1.0').replace('"schemaVersion":1', '"schemaVersion":1e0')));
  add('json/negative-zero-entropy', rawPack(JSON.stringify(withField(base, ['detectors', 0, 'match', 'minEntropyTenths'], 0)).replace('"minEntropyTenths":0', '"minEntropyTenths":-0')));
  add('json/underflow-entropy', rawPack(JSON.stringify(withField(base, ['detectors', 0, 'match', 'minEntropyTenths'], 0)).replace('"minEntropyTenths":0', '"minEntropyTenths":1e-400')));
  add('json/exponent-window', rawPack(JSON.stringify(withField(base, ['detectors', 0, 'context'], { keywords: ['client'], window: 24 })).replace('"window":24', '"window":2.4e1')));
  add('json/escaped-strings', rawPack(text.replace('"label":"Détecteur cli"', '"label":"D\\u00e9tecteur \\/ cli"')));
  add('json/proto-member', rawPack(text.replace('{"schemaVersion"', '{"__proto__":{},"schemaVersion"')));
  add('json/top-level-array', rawPack(`[${text}]`));
  add('json/top-level-null', rawPack('null'));
  add('json/trailing-content', rawPack(`${text} {}`));
  add('json/byte-order-mark', concat(Uint8Array.from([0xef, 0xbb, 0xbf]), text));
  add('json/truncated', rawPack(text.slice(0, -1)));
  add('json/duplicate-member', rawPack(text.replace('"issuer":', '"issuer":"double","issuer":')), {
    reason: 'json_duplicate_member',
    go: { valid: false, error: 'schema' },
  });
  add('json/lone-surrogate', rawPack(text.replace('"label":"Détecteur cli"', '"label":"Détecteur \\ud800 cli"')), {
    reason: 'json_lone_surrogate',
    go: { valid: false, error: 'schema' },
  });
  add('json/invalid-utf8', concat(text.slice(0, text.indexOf('Détecteur cli') + 1), Uint8Array.from([0xff]), text.slice(text.indexOf('Détecteur cli') + 1)), {
    reason: 'json_invalid_utf8',
    go: { valid: false, error: 'schema' },
  });

  // Codes de validité, dans l'ordre du §2.
  add('duplicate_detector', payload([cli, patternDetector('cli', 'ABC[0-9]{3}')], [{ detector: 'cli', text: 'CLI-12345678' }]));
  add('validity_window-equal', withField(base, ['expiresAt'], base['issuedAt']));
  add('validity_window-before', withField(base, ['expiresAt'], '2026-09-30T23:59:59Z'));
  add('validity_window-lexicographic', withField(withField(base, ['issuedAt'], '2026-13-45T99:99:99Z'), ['expiresAt'], '2026-13-46T00:00:00Z'));
  const digests = (label: string, count: number): Json =>
    withField(terms, ['match', 'digests'], Array.from({ length: count }, (_, i) => createHash('sha256').update(`${label}/${String(i)}`).digest('hex')));
  // 20 001 condensats et un motif invalide : le nombre de condensats est jugé avant les motifs (le plus grand Pack du
  // contrat, repris des tests d'origine, en a exactement 20 000).
  add('too_many_digests', payload([
    ...[0, 1, 2, 3].map((i) => withField(digests(`d${String(i)}`, 5000), ['id'], `t${String(i)}`)),
    withField(digests('d4', 1), ['id'], 't4'),
    patternDetector('p', 'ABC*'),
  ]));
  for (const [name, pattern, hasContext] of PATTERN_REFUSALS) {
    if (pattern === '' || pattern.length > 256 || /[^\x20-\x7e]/.test(pattern)) continue; // déjà refusé par le schéma ou cas de motif seul
    const detector = patternDetector('p', pattern, hasContext === true ? { context: { keywords: ['client'], window: 16 } } : {});
    add(`invalid_pattern/${name}`, payload([detector], [{ detector: 'p', text: 'client x' }]));
  }
  add('invalid_pattern-context-removed', payload([patternDetector('siret', '[0-9]{14}')], [{ detector: 'siret', text: 'siret 55210055400013' }]));
  add('invalid_pattern-before-unknown-test', payload([patternDetector('p', 'ABC*')], [{ detector: 'inconnu', text: 'x' }]));
  add('unknown_test_detector', payload([cli], [{ detector: 'cli', text: 'CLI-12345678' }, { detector: 'autre', text: 'x' }]));
  add('unknown_test_detector-before-missing', payload([cli, patternDetector('abc', 'ABC[0-9]{3}')], [{ detector: 'autre', text: 'x' }]));
  add('missing_positive', payload([cli, patternDetector('abc', 'ABC[0-9]{3}')], [{ detector: 'cli', text: 'CLI-12345678' }]));
  add('missing_positive-terms-exempt', payload([cli, terms], [{ detector: 'cli', text: 'CLI-12345678' }]));
  add('positive_not_detected', payload([cli], [{ detector: 'cli', text: 'CLI-1234567' }]));
  add('positive_not_detected-other-detector', payload([cli, patternDetector('abc', 'ABC[0-9]{3}')], [
    { detector: 'cli', text: 'ABC123' },
    { detector: 'abc', text: 'ABC123' },
  ]));
  add('positive_not_detected-context', payload([patternDetector('siret', '[0-9]{14}', { context: { keywords: ['siret'], window: 4 } })], [
    { detector: 'siret', text: 'siret      55210055400013' },
  ]));
  add('positive_not_detected-entropy', payload([patternDetector('tok', 'tok_[a-z]{8}', { minEntropyTenths: 30 })], [{ detector: 'tok', text: 'tok_aaaaaaaa' }]));
  add('positive-terms-detected', payload([terms], [{ detector: 'codes', text: 'le projet faucon' }]));
  add('positive_not_detected-terms', payload([terms], [{ detector: 'codes', text: 'le projet aigle' }]));
  add('negative_detected', withField(base, ['tests', 'negatives'], ['rien', 'CLI-87654321']));
  add('negative_detected-terms', payload([cli, terms], [{ detector: 'cli', text: 'CLI-12345678' }], ['Le PROJET-faucon avance']));
  add('negative-context-not-detected', payload([patternDetector('siret', '[0-9]{14}', { context: { keywords: ['siret'], window: 4 } })], [
    { detector: 'siret', text: 'siret 55210055400013' },
  ], ['Commande 55210055400013 livrée']));
  add('positive_not_detected-before-negative', payload([cli], [{ detector: 'cli', text: 'nothing' }], ['CLI-87654321']));

  // Essais en budget : 200 détecteurs de termes à sels distincts et un négatif de 1 000 mots distincts (travail
  // compté à l'identique : refus des deux côtés).
  const words = Array.from({ length: 1000 }, (_, i) => String.fromCodePoint(0x4e00 + i)).join(' ');
  add('self_test_incomplete-terms', payload(
    Array.from({ length: 200 }, (_, i) => termsDetector(engine, `t${String(i)}`, ['inconnu'], syntheticSalt(`budget-${String(i)}`), 4)),
    [],
    [words],
  ));
  // Motif pathologique dans un essai positif : l'automate de l'origine épuise son budget, RE2 finit et constate
  // l'absence de correspondance.
  const slow = patternDetector('slow', `ACME${'[a-z]{0,8}'.repeat(20)}Z`, {}, 'warn');
  add('self_test_incomplete-pattern', payload([slow], [{ detector: 'slow', text: `ACME${'a'.repeat(160)}` }]), {
    reason: 'backtracking_budget',
    go: { valid: false, error: 'positive_not_detected' },
  });

  // Ordre des contrôles quand plusieurs défauts coexistent.
  add('order/schema-before-duplicate', withField(payload([cli, cli]), ['version'], 0));
  add('order/duplicate-before-window', withField(payload([cli, cli]), ['expiresAt'], '2000-01-01T00:00:00Z'));
  return packs;
}

// --- Termes ---------------------------------------------------------------------------------------------------------

const TERM_INPUTS: readonly string[] = [
  'Projet Faucon',
  '  PROJET   faucon  ',
  'projet-faucon',
  'PROJET_FAUCON',
  "l'opération « Nébuleuse »",
  'ＦＡＵＣＯＮ ２０２６',
  'ﬁnance ﬂux ﬀ',
  'Ⅻ ⅻ ½ ² ⑴ ⒈',
  'Straße STRASSE ß ẞ',
  'İstanbul ıi İı',
  'ΣΑΣ σας ΌΣΟΣ ΜΆΪΟΣ Σ ΑΣ ΑΣ1 ΑΣʹ ΑΣͅ',
  'ΑΣ·Β ΑΣ’Β ΑΣ.Β',
  'ǅungla ǈubljana ǋ',
  '東京 タワー ｶﾀｶﾅ',
  '한국어 단어',
  'مَرْحَبًا بِكُمْ',
  'שָׁלוֹם',
  'क्षत्रिय हिन्दी',
  'ภาษาไทย',
  'Ελληνικά ά έ',
  'café café CAFÉ',
  'é̂ ą́',
  '́̂ seul',
  '١٢٣ ٤٥٦ ۷۸۹',
  '𝐁𝐨𝐥𝐝 𝔉𝔯𝔞𝔨𝔱𝔲𝔯',
  '😀 emoji 👍🏽 mot',
  'mot​coupé soft­hyphen',
  'Côte-d’Ivoire 2026',
  'ǰ ǈ ŉ',
  'ꭰꭱ ᏸᏹ',
  'Ⓐⓑ ⒜',
  '',
  '   ',
  '\u0000 nul \u0007',
];

/** Termes synthétiques : normalisation Unicode, séparateurs, cas vides ; avec et sans sel. */
function syntheticTerms(): TermSource[] {
  const out: TermSource[] = [];
  TERM_INPUTS.forEach((input, index) => {
    out.push({ id: `synthetic/term/${String(index)}`, kind: 'term', input, salt: syntheticSalt('terms') });
    out.push({ id: `synthetic/term-salt32/${String(index)}`, kind: 'term', input, salt: syntheticSalt('terms', 32) });
  });
  out.push({ id: 'synthetic/digest/empty', kind: 'digest', input: '', salt: syntheticSalt('terms') });
  out.push({ id: 'synthetic/digest/non-normalized', kind: 'digest', input: 'Projet Faucon', salt: syntheticSalt('terms') });
  return out;
}

// --- Analyses -------------------------------------------------------------------------------------------------------

/** Valeur synthétique de la règle github_token (assemblée à l'exécution, comme dans les tests d'origine). */
const GITHUB_TOKEN = ['ghp', 'aB3d'.repeat(9)].join('_');

/** Mots distincts de quatre lettres (base 26), séparés par une espace. */
export function distinctWords(count: number, letter = 'q'): string {
  const words: string[] = [];
  for (let i = 0; i < count; i += 1) {
    let n = i;
    let word = '';
    for (let k = 0; k < 4; k += 1) {
      word = String.fromCharCode(97 + (n % 26)) + word;
      n = Math.floor(n / 26);
    }
    words.push(letter + word);
  }
  return words.join(' ');
}

/** Pack de trois détecteurs de termes à sels distincts, n-grammes de 4 mots (travail des termes compté à l'identique). */
export function hashingPack(engine: CustomEngine): Json {
  return payload([0, 1, 2].map((i) => termsDetector(engine, `h${String(i)}`, ['terme absent'], syntheticSalt(`hashing-${String(i)}`), 4)));
}

export interface ScanContext {
  readonly reference: Json;
  /** Plus grand nombre de mots distinctWords que le Pack hashingPack analyse dans le budget (calculé par l'origine). */
  readonly hashingWords: number;
}

function syntheticScans(engine: CustomEngine, context: ScanContext): ScanSource[] {
  const scans: ScanSource[] = [];
  const add = (name: string, pack: Json | undefined, bytes: Uint8Array | string, divergence?: ScanSource['divergence']): void => {
    scans.push({
      id: `synthetic/scan/${name}`,
      pack: pack === undefined ? undefined : json(pack),
      bytes: typeof bytes === 'string' ? utf8(bytes) : bytes,
      ...(divergence === undefined ? {} : { divergence }),
    });
  };
  const ref = context.reference;
  // Pack de référence du contrat.
  add('reference/customer-id', ref, 'Le client CLI-00421337 a appelé.');
  add('reference/no-pack', undefined, 'Le client CLI-00421337 a appelé.');
  add('reference/siret-context', ref, 'SIRET : 12345678901234. Commande 98765432109876 livrée.');
  add('reference/siret-no-keyword', ref, 'Commande 98765432109876 livrée.');
  add('reference/codenames', ref, 'Le projet-FAUCON avance ; la nebuleuse aussi. Projet Faucons non. Nébuleuse ! projet ＦＡＵＣＯＮ et PROJET_FAUCON.');
  add('reference/builtin-and-custom', ref, `token ${GITHUB_TOKEN} pour CLI-00421337`);
  const sameSpan = payload([patternDetector('gh', 'ghp_[A-Za-z0-9]{36}')], [{ detector: 'gh', text: `x ${GITHUB_TOKEN} y` }]);
  add('same-span-builtin-and-custom', sameSpan, `x ${GITHUB_TOKEN} y ${GITHUB_TOKEN}`);
  add('reference/invisible', ref, 'Le client CLI-0042­1337 et le Projet Fau​con.');
  add('reference/invisible-both-passes', ref, 'CLI-00421337 ​ CLI-1234​5678 projet⁠faucon projet faucon');
  add('reference/byte-order-mark', ref, '﻿CLI-00421337 projet faucon﻿');
  add('reference/only-invisible', ref, '​‌‍⁠﻿');
  add('reference/invisible-at-ends', ref, '­CLI-00421337­');
  add('reference/invisible-and-invalid-bytes', ref, concat('CLI-0042', Uint8Array.from([0xe2, 0x82]), '​', Uint8Array.from([0xac]), '1337 projet', Uint8Array.from([0xff]), '​faucon'));
  add('reference/invalid-bytes', ref, concat(Uint8Array.from([0xff, 0xfe]), 'CLI-00421337', Uint8Array.from([0xc3]), 'projet faucon', Uint8Array.from([0x80])));
  add('reference/empty', ref, '');
  add('reference/marks-between-words', ref, 'le projet ́ faucon');
  add('reference/combining-in-word', ref, 'nébuleuse NÉBULEUSE');
  add('reference/emoji-window', ref, `siret ${'😀'.repeat(17)} 12345678901234`);
  add('reference/emoji-window-outside', ref, `siret ${'😀'.repeat(18)} 12345678901234`);
  add('reference/keyword-after', ref, '12345678901234 est notre SIRET.');
  add('reference/keyword-window-edge-bytes', ref, concat('siret', Uint8Array.from([0xff, 0xfe, 0xfd]), ' '.repeat(16), '12345678901234'));

  // Détecteurs et options.
  const ci = payload([patternDetector('db', 'acme-(?:prod|staging)-db[0-9]{1,2}', { caseInsensitive: true }, 'warn')], [{ detector: 'db', text: 'ACME-Prod-DB7' }]);
  add('case-insensitive', ci, 'connect to ACME-Prod-DB7 then acme-staging-db12x, KCME-prod-db1 and acme-prod-db١');
  const entropy = (tenths: number): Json =>
    payload([patternDetector('e', 'ABCD[ABCD]{4}', { minEntropyTenths: tenths })], [{ detector: 'e', text: 'ABCDABCD' }]);
  add('entropy-boundary-equal', entropy(20), 'ABCDABCD ABCDAAAA ABCDDCBA');
  add('entropy-boundary-above', entropy(19), 'ABCDABCD ABCDAAAA');
  const entropyThird = payload([patternDetector('e', 'ABC[ABC]{6}', { minEntropyTenths: 15 })], [{ detector: 'e', text: 'ABCABCABC' }]);
  add('entropy-thirds', entropyThird, 'ABCABCABC ABCAAAAAA ABCCBACBA');
  const contexts = payload([
    patternDetector('a', '[0-9]{6}', { context: { keywords: ['ref.', 'ref', 'id:client'], window: 6 } }),
    patternDetector('b', 'XYZ[0-9]{3}', { context: { keywords: ['Code Client'], window: 12 } }),
  ], [
    { detector: 'a', text: 'ref 123456' },
    { detector: 'b', text: 'code client XYZ123' },
  ]);
  add('contexts', contexts, 'REF 123456 id:client:654321 réf 111111 ref.222222 code client XYZ123 CODE CLIENTXYZ456 code clien XYZ789');
  add('context-window-text-edges', contexts, '123456ref');
  add('context-many-keywords', payload([patternDetector('k', 'ZZZ[0-9]{2}', { context: { keywords: Array.from({ length: 20 }, (_, i) => `motcle${String(i)}`), window: 256 } })], [
    { detector: 'k', text: 'motcle19 ZZZ12' },
  ]), `${'x'.repeat(300)} motcle19 ${'y'.repeat(200)} ZZZ01 ${'z'.repeat(300)} ZZZ02`);
  const shared = payload([
    patternDetector('one', '[0-9]{14}', { context: { keywords: ['siret'], window: 24 } }),
    patternDetector('two', '[0-9]{14}', { context: { keywords: ['facture'], window: 24 } }, 'warn'),
    patternDetector('three', 'CLI-[0-9]{8}'),
    patternDetector('four', 'cli-[0-9]{8}', { caseInsensitive: true }, 'warn'),
  ], [
    { detector: 'one', text: 'siret 55210055400013' },
    { detector: 'two', text: 'facture 55210055400013' },
    { detector: 'three', text: 'CLI-12345678' },
    { detector: 'four', text: 'CLI-12345678' },
  ]);
  add('shared-patterns', shared, 'siret 55210055400013 et facture 98765432109876, CLI-12345678 cli-87654321');

  // Termes : frontières de n-grammes, maxWords par détecteur, contexte, chevauchements.
  const salt = syntheticSalt('scan-terms');
  const termPack = payload([
    termsDetector(engine, 'one', ['alpha', 'omega'], salt, 1),
    termsDetector(engine, 'two', ['alpha beta', 'beta gamma', 'gamma'], salt, 2),
    termsDetector(engine, 'four', ['alpha beta gamma delta', 'beta gamma delta'], salt, 4, undefined, 'warn'),
    termsDetector(engine, 'ctx', ['epsilon'], syntheticSalt('scan-terms-ctx'), 1, { keywords: ['code'], window: 8 }),
    termsDetector(engine, 'same-salt-other-string', ['alpha'], `${salt.slice(0, 21)}${String.fromCharCode(salt.charCodeAt(21) ^ 1)}==`, 1),
  ]);
  add('terms/ngrams', termPack, 'alpha beta gamma delta. alpha. omega,beta gamma—delta; gamma');
  add('terms/start-end', termPack, 'alpha');
  add('terms/maxwords-boundary', termPack, 'xx alpha beta gamma delta yy beta gamma delta');
  add('terms/context', termPack, 'code : epsilon. epsilon sans le mot');
  add('terms/separators', termPack, 'alpha_beta alpha-beta alpha.beta alpha beta alpha\tbeta alpha\nbeta ALPHA BETA Alpha  Beta');
  add('terms/marks-only-words', termPack, 'alpha ́́ beta');
  add('terms/unicode-forms', termPack, 'ＡＬＰＨＡ ＢＥＴＡ ålpha ălpha alphá beta');
  add('terms/overlap-resolution', payload([termsDetector(engine, 'ov', ['b c', 'a b', 'c d', 'b'], salt, 2)]), 'a b c d b c');

  // Limites : trop de détections, exactement la limite, constats intégrés comptés.
  const ids = (count: number, from = 10_000_000): string => Array.from({ length: count }, (_, i) => `CLI-${String(from + i)}`).join(' ');
  add('too-many/exactly-limit', ref, ids(2048));
  add('too-many/limit-plus-one', ref, ids(2049));
  add('too-many/builtin-counted', ref, `${ids(2040)} ${Array.from({ length: 10 }, (_, i) => `t${String(i)} ${['ghp', `${String(i)}B3d`.repeat(9)].join('_')}`).join(' ')}`);
  add('too-many/builtin-at-limit', ref, `${ids(2038)} ${Array.from({ length: 10 }, (_, i) => `t${String(i)} ${['ghp', `${String(i)}B3d`.repeat(9)].join('_')}`).join(' ')}`);
  add('too-many/terms', payload([termsDetector(engine, 'w', ['mot'], salt, 1)]), Array.from({ length: 2049 }, () => 'mot').join(' '));
  add('too-many/visible-pass', ref, `${ids(1500)}​`);

  // Budget : travail des termes compté à l'identique, au plus juste.
  const hashing = hashingPack(engine);
  add('budget/terms-within', hashing, distinctWords(context.hashingWords));
  add('budget/terms-exceeded', hashing, distinctWords(context.hashingWords + 1));
  return scans;
}

/** Détecteurs seuls (sans essais), comme les vecteurs « detection » du contrat. */
function syntheticDetection(engine: CustomEngine): DetectionSource[] {
  const out: DetectionSource[] = [];
  const add = (name: string, detectors: Json[], text: string | Uint8Array): void => {
    out.push({ id: `synthetic/detection/${name}`, detectors: JSON.stringify(detectors), bytes: typeof text === 'string' ? utf8(text) : text });
  };
  add('anchor-offsets', [patternDetector('a', 'x?y{0,2}ABCD[0-9]{2}')], 'ABCD12 yyABCD34 xyABCD56 zABCD7 xyyABCD89');
  add('anchor-case-insensitive', [patternDetector('a', 'ab(?:CD|ef)GHI', { caseInsensitive: true })], 'ABCDGHI abefghi ABcdGhI abEFghi');
  add('anchor-overlapping-occurrences', [patternDetector('a', 'AAA[0-9]')], 'AAAAAA1AAA2');
  add('context-only-no-keyword', [patternDetector('c', '[0-9]{4}', { context: { keywords: ['code'], window: 4 } })], '1234 5678');
  add('context-only-keyword', [patternDetector('c', '[0-9]{4}', { context: { keywords: ['code'], window: 4 } })], 'code 1234 5678 code');
  add('terms-and-patterns', [
    patternDetector('p', 'CLI-[0-9]{4}'),
    termsDetector(engine, 't', ['projet faucon'], syntheticSalt('detection'), 2),
  ], 'CLI-1234 projet faucon CLI-5678');
  return out;
}

export function syntheticSources(engine: CustomEngine, context: ScanContext): Sources {
  const sources = emptySources();
  for (const [name, pattern, hasContext] of PATTERN_REFUSALS) {
    sources.patternValidation.push({ id: `synthetic/refused/${name}`, pattern, hasContext: hasContext === true, caseInsensitive: false });
  }
  for (const [name, pattern, hasContext, caseInsensitive] of PATTERN_ADMITTED) {
    sources.patternValidation.push({ id: `synthetic/admitted/${name}`, pattern, hasContext, caseInsensitive: caseInsensitive === true });
    if (!hasContext) {
      sources.patternValidation.push({ id: `synthetic/admitted-with-context/${name}`, pattern, hasContext: true, caseInsensitive: caseInsensitive === true });
    }
  }
  for (const [name, pattern, caseInsensitive, inputs] of MATCHING) {
    inputs.forEach((input, index) => {
      sources.patternMatching.push({
        id: `synthetic/matching/${name} #${String(index + 1)}`,
        pattern,
        caseInsensitive,
        bytes: typeof input === 'string' ? utf8(input) : input,
      });
    });
  }
  sources.patternMatching.push(...randomMatching(engine, 3000));
  sources.packs.push(...syntheticPacks(engine));
  sources.detection.push(...syntheticDetection(engine));
  sources.scans.push(...syntheticScans(engine, context));
  sources.terms.push(...syntheticTerms());
  return sources;
}
