// SPDX-License-Identifier: Apache-2.0
/**
 * Banc de comparaison Betterleaks : `node corpus/betterleaks.ts --clone <clone de betterleaks/betterleaks>` (dans
 * `generator/`) écrit `vectors/comparison/betterleaks.json` ; `--check` régénère en mémoire et compare octet pour
 * octet, sans rien écrire.
 *
 * Chaque règle de Betterleaks porte ses cas d'essai dans son fichier source Go (`rulebuilder.Match`,
 * `rulebuilder.NoMatch` et leurs variantes « composant »). Ce générateur les **lit** : il analyse le texte des
 * fichiers `rules/*.go` et `rules/generic/*.go` (littéraux de chaîne Go joints par `+`), sans compiler ni exécuter
 * une ligne de Betterleaks, et sans rien installer. Un appel dont un argument n'est pas un littéral est compté, pas
 * repris.
 *
 * Le clone doit être au commit épinglé : l'empreinte de l'ensemble des fichiers lus est vérifiée
 * (`BETTERLEAKS_RULES_DIGEST`). Betterleaks est sous licence MIT (Copyright (c) 2026 Zachary Rice) : avis dans
 * NOTICE, détail dans UPSTREAM.md, « Règles reprises de Betterleaks ».
 *
 * C'est un banc, pas un corpus de parité : le fichier ne porte aucun résultat attendu de Secret Guard. Le test Go
 * `TestComparisonBetterleaks` (`detect/comparison_test.go`) y mesure quatre chiffres et refuse une baisse.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { jsonString } from './json.ts';

export const BETTERLEAKS_REPOSITORY = 'betterleaks/betterleaks';
export const BETTERLEAKS_COMMIT = 'b4b1c4455987636400ce693bd9d8a8e2cf375ed9';
export const BETTERLEAKS_LICENSE = 'MIT';
/**
 * SHA-256 de la liste « chemin relatif, NUL, SHA-256 du fichier, saut de ligne » des fichiers lus, triés par chemin :
 * prouve que le clone est au commit épinglé sans exécuter git.
 */
export const BETTERLEAKS_RULES_DIGEST = 'fcfde73581b6eb98fda1493afdc39c0b30e0687bb57d7e1bb67e005a6862f393';
export const COMPARISON_FORMAT_VERSION = 1;

const OUTPUT_DIRECTORY = fileURLToPath(new URL('../../vectors/comparison/', import.meta.url));
export const COMPARISON_FILE = 'betterleaks.json';

/** Nature d'un cas : positif (`match`), négatif (`no_match`), et les mêmes pour une règle « composant ». */
export type ComparisonKind = 'match' | 'no_match' | 'match_component' | 'no_match_component';

export interface ComparisonCase {
  readonly id: string;
  /** Identifiant de la règle de Betterleaks qui porte le cas. */
  readonly rule: string;
  /** Fichier source du cas, relatif à la racine du clone. */
  readonly file: string;
  readonly kind: ComparisonKind;
  readonly name: string;
  readonly input: string;
  /** Valeur que Betterleaks attend pour un cas positif ; chaîne vide pour un cas négatif. */
  readonly secret: string;
}

export class BetterleaksError extends Error {}

const KINDS: Readonly<Record<string, ComparisonKind>> = {
  Match: 'match',
  NoMatch: 'no_match',
  MatchComponent: 'match_component',
  NoMatchComponent: 'no_match_component',
};

const SIMPLE_ESCAPES: Readonly<Record<string, number>> = {
  n: 0x0a,
  t: 0x09,
  r: 0x0d,
  '\\': 0x5c,
  '"': 0x22,
  "'": 0x27,
  a: 0x07,
  b: 0x08,
  f: 0x0c,
  v: 0x0b,
};

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

/**
 * Lit un littéral de chaîne Go à `source[at]` : chaîne brute entre accents graves (les retours chariot en sont
 * retirés, comme le fait Go) ou chaîne interprétée entre guillemets. Rend ses octets et la position qui suit, ou
 * `undefined` si ce n'est pas un littéral de chaîne.
 */
export function parseGoString(source: string, at: number): { bytes: number[]; next: number } | undefined {
  const open = source.charAt(at);
  if (open === '`') {
    const close = source.indexOf('`', at + 1);
    if (close < 0) throw new BetterleaksError('chaîne brute non fermée');
    return { bytes: [...encoder.encode(source.slice(at + 1, close).replaceAll('\r', ''))], next: close + 1 };
  }
  if (open !== '"') return undefined;
  const bytes: number[] = [];
  let index = at + 1;
  for (;;) {
    if (index >= source.length) throw new BetterleaksError('chaîne non fermée');
    const character = source.charAt(index);
    if (character === '"') return { bytes, next: index + 1 };
    if (character === '\n') throw new BetterleaksError('saut de ligne dans une chaîne interprétée');
    if (character !== '\\') {
      const codePoint = source.codePointAt(index) ?? 0;
      const text = String.fromCodePoint(codePoint);
      bytes.push(...encoder.encode(text));
      index += text.length;
      continue;
    }
    const escaped = source.charAt(index + 1);
    const simple = SIMPLE_ESCAPES[escaped];
    if (simple !== undefined) {
      bytes.push(simple);
      index += 2;
    } else if (escaped === 'x') {
      bytes.push(hexValue(source.slice(index + 2, index + 4), 2));
      index += 4;
    } else if (escaped === 'u') {
      bytes.push(...encoder.encode(String.fromCodePoint(hexValue(source.slice(index + 2, index + 6), 4))));
      index += 6;
    } else if (escaped === 'U') {
      bytes.push(...encoder.encode(String.fromCodePoint(hexValue(source.slice(index + 2, index + 10), 8))));
      index += 10;
    } else if (/^[0-7]$/.test(escaped)) {
      const digits = source.slice(index + 1, index + 4);
      if (!/^[0-7]{3}$/.test(digits)) throw new BetterleaksError('échappement octal incomplet');
      bytes.push(Number.parseInt(digits, 8) & 0xff);
      index += 4;
    } else {
      throw new BetterleaksError(`échappement inconnu : \\${escaped}`);
    }
  }
}

function hexValue(digits: string, length: number): number {
  if (digits.length !== length || !/^[0-9a-fA-F]+$/.test(digits)) throw new BetterleaksError('échappement hexadécimal incomplet');
  return Number.parseInt(digits, 16);
}

/** Saute les blancs et les commentaires Go. */
function skipBlank(source: string, at: number): number {
  let index = at;
  for (;;) {
    const character = source.charAt(index);
    if (character === ' ' || character === '\t' || character === '\r' || character === '\n') index += 1;
    else if (source.startsWith('//', index)) {
      const end = source.indexOf('\n', index);
      index = end < 0 ? source.length : end;
    } else if (source.startsWith('/*', index)) {
      const end = source.indexOf('*/', index);
      if (end < 0) throw new BetterleaksError('commentaire non fermé');
      index = end + 2;
    } else return index;
  }
}

/**
 * Arguments d'un appel, à partir de la position qui suit sa parenthèse ouvrante : chacun doit être un littéral de
 * chaîne, ou plusieurs joints par `+`. Rend `undefined` dès qu'un argument est autre chose (variable, appel…).
 */
export function parseLiteralArguments(source: string, at: number): string[] | undefined {
  const values: string[] = [];
  let current: number[] | undefined;
  let index = at;
  for (;;) {
    index = skipBlank(source, index);
    if (index >= source.length) throw new BetterleaksError('appel non fermé');
    const character = source.charAt(index);
    if (character === ')' || character === ',') {
      if (current === undefined) {
        // Virgule finale avant la parenthèse : admise par Go ; argument vide : pas un littéral.
        if (character === ')' && values.length > 0) return values;
        return undefined;
      }
      values.push(decodeBytes(current));
      current = undefined;
      if (character === ')') return values;
      index += 1;
      continue;
    }
    if (character === '+') {
      if (current === undefined) return undefined;
      index += 1;
      continue;
    }
    const literal = parseGoString(source, index);
    if (literal === undefined) return undefined;
    current = [...(current ?? []), ...literal.bytes];
    index = literal.next;
  }
}

function decodeBytes(bytes: readonly number[]): string {
  try {
    return decoder.decode(Uint8Array.from(bytes));
  } catch {
    throw new BetterleaksError('cas hors UTF-8 : le format du banc ne le porte pas');
  }
}

const CALL = /rulebuilder\.(MatchComponent|NoMatchComponent|Match|NoMatch)\(/g;
const RULE_ID = /\bID:\s*"([^"]+)"/g;

/** Cas d'un fichier source ; `unread` compte les appels dont un argument n'est pas un littéral. */
export function casesOfSource(file: string, source: string): { cases: Omit<ComparisonCase, 'id'>[]; unread: number } {
  const ids = [...source.matchAll(RULE_ID)].map((match) => ({ at: match.index, id: match[1] ?? '' }));
  const cases: Omit<ComparisonCase, 'id'>[] = [];
  let unread = 0;
  for (const call of source.matchAll(CALL)) {
    const kind = KINDS[call[1] ?? ''];
    const owner = ids.findLast((entry) => entry.at < call.index)?.id;
    const values = parseLiteralArguments(source, call.index + call[0].length);
    const positive = kind === 'match' || kind === 'match_component';
    if (kind === undefined || owner === undefined || values === undefined || values.length !== (positive ? 3 : 2)) {
      unread += 1;
      continue;
    }
    const [name = '', input = '', secret = ''] = values;
    cases.push({ rule: owner, file, kind, name, input, secret });
  }
  return { cases, unread };
}

/** Fichiers lus dans le clone : `rules/*.go` et `rules/generic/*.go`, hors essais, triés par chemin. */
export function ruleFiles(clone: string): string[] {
  const list = (directory: string): string[] =>
    readdirSync(join(clone, directory), { withFileTypes: true })
      .filter((entry) => entry.isFile() && entry.name.endsWith('.go') && !entry.name.endsWith('_test.go'))
      .map((entry) => `${directory}/${entry.name}`);
  return [...list('rules'), ...list('rules/generic')].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/** Empreinte de l'ensemble des fichiers lus (voir `BETTERLEAKS_RULES_DIGEST`). */
export function rulesDigest(files: readonly (readonly [string, Uint8Array])[]): string {
  const hash = createHash('sha256');
  for (const [file, content] of files) hash.update(`${file}\0${createHash('sha256').update(content).digest('hex')}\n`);
  return hash.digest('hex');
}

export interface ComparisonCorpus {
  readonly cases: ComparisonCase[];
  readonly unread: number;
  readonly digest: string;
}

/** Lit les cas du clone, dans l'ordre des fichiers puis des appels. */
export function readBetterleaksCases(clone: string): ComparisonCorpus {
  const contents = ruleFiles(clone).map((file) => [file, readFileSync(join(clone, file))] as const);
  const cases: ComparisonCase[] = [];
  const perRule = new Map<string, number>();
  let unread = 0;
  for (const [file, content] of contents) {
    const read = casesOfSource(file, decoder.decode(content));
    unread += read.unread;
    for (const entry of read.cases) {
      const rank = (perRule.get(entry.rule) ?? 0) + 1;
      perRule.set(entry.rule, rank);
      cases.push({ id: `${entry.rule}/${String(rank)}`, ...entry });
    }
  }
  return { cases, unread, digest: rulesDigest(contents) };
}

/** Fichier du banc : en-tête d'origine, puis un cas par ligne. */
export function serializeComparison(corpus: ComparisonCorpus): string {
  const lines = corpus.cases.map(
    (entry) =>
      `    {"id":${jsonString(entry.id)},"rule":${jsonString(entry.rule)},"file":${jsonString(entry.file)},` +
      `"kind":${jsonString(entry.kind)},"name":${jsonString(entry.name)},"input":${jsonString(entry.input)},` +
      `"secret":${jsonString(entry.secret)}}`,
  );
  return (
    `{\n  "formatVersion": ${String(COMPARISON_FORMAT_VERSION)},\n` +
    `  "source": {"repository": ${jsonString(BETTERLEAKS_REPOSITORY)}, "commit": ${jsonString(BETTERLEAKS_COMMIT)}, ` +
    `"license": ${jsonString(BETTERLEAKS_LICENSE)}, "rulesDigest": ${jsonString(corpus.digest)}, ` +
    `"unreadCalls": ${String(corpus.unread)}},\n` +
    `  "cases": [\n${lines.join(',\n')}\n  ]\n}\n`
  );
}

function main(): number {
  const { values } = parseArgs({
    options: { clone: { type: 'string' }, check: { type: 'boolean', default: false } },
    strict: true,
    allowPositionals: false,
  });
  if (values.clone === undefined) {
    process.stderr.write('Usage : node corpus/betterleaks.ts --clone <clone de betterleaks/betterleaks> [--check]\n');
    return 1;
  }
  const corpus = readBetterleaksCases(values.clone);
  if (corpus.digest !== BETTERLEAKS_RULES_DIGEST) {
    process.stderr.write(
      `Banc refusé, rien n’est écrit : le clone n’est pas au commit ${BETTERLEAKS_COMMIT} (empreinte des règles ${corpus.digest})\n`,
    );
    return 1;
  }
  const content = serializeComparison(corpus);
  const target = join(OUTPUT_DIRECTORY, COMPARISON_FILE);
  if (values.check) {
    let present = '';
    try {
      present = readFileSync(target, 'utf8');
    } catch {
      present = '';
    }
    if (present !== content) {
      process.stderr.write(`Banc différent : ${COMPARISON_FILE}\n`);
      return 1;
    }
    process.stdout.write(`Banc identique : ${String(corpus.cases.length)} cas, ${String(corpus.unread)} appels non lus\n`);
    return 0;
  }
  mkdirSync(OUTPUT_DIRECTORY, { recursive: true });
  const temporary = join(OUTPUT_DIRECTORY, `.${COMPARISON_FILE}.tmp-generate`);
  try {
    writeFileSync(temporary, content);
    renameSync(temporary, target);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
  process.stdout.write(`Banc de comparaison écrit : ${String(corpus.cases.length)} cas, ${String(corpus.unread)} appels non lus\n`);
  return 0;
}

if (process.argv[1] !== undefined && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])) {
  try {
    process.exitCode = main();
  } catch (error) {
    process.stderr.write(`Banc refusé : ${error instanceof Error ? error.message : 'erreur inattendue'}\n`);
    process.exitCode = 1;
  }
}
