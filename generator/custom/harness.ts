/**
 * Reprise des tests des règles du client : chaque fichier de test repris est exécuté sur le moteur transpilé avec le
 * `expect` de Vitest (une assertion d'origine qui échoue arrête le générateur), et chaque entrée passée au moteur est
 * relevée avec le test qui l'a passée : motifs validés, textes passés à l'automate d'un motif, Packs compilés,
 * analyses, détections par un Pack construit à la main, termes normalisés et condensés.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect } from 'vitest';
import { CUSTOM_TEST_FILES, UpstreamError, type CustomTestFile } from './upstream.ts';

const HARNESS_KEY = 'secret-guard.custom-vectors.harness';

/** Entrée relevée. */
export type RecordedInput =
  | { readonly kind: 'pattern'; readonly pattern: string; readonly hasContext: boolean; readonly caseInsensitive: boolean }
  | { readonly kind: 'match'; readonly pattern: string; readonly caseInsensitive: boolean; readonly text: string }
  | { readonly kind: 'pack'; readonly json: string }
  | { readonly kind: 'scan'; readonly content: string; readonly pack: string | undefined; readonly sharedMeter: boolean }
  | { readonly kind: 'detect'; readonly detectors: string; readonly text: string }
  | { readonly kind: 'term'; readonly term: string }
  | { readonly kind: 'digest'; readonly salt: string; readonly normalized: string };

export interface RecordedTest {
  readonly file: CustomTestFile;
  readonly suite: readonly string[];
  readonly title: string;
  readonly row: number | undefined;
  readonly inputs: readonly RecordedInput[];
}

interface RegisteredTest {
  readonly file: CustomTestFile;
  readonly suite: readonly string[];
  readonly title: string;
  readonly row: number | undefined;
  readonly run: () => unknown;
}

type TestFunction = (...args: unknown[]) => unknown;

const HEADER = `const harness = globalThis[Symbol.for(${JSON.stringify(HARNESS_KEY)})];\n`;

/** Modules d'interception écrits dans la copie transpilée. */
const HARNESS_MODULES: Readonly<Record<string, string>> = {
  'vitest.js': `${HEADER}export const describe = harness.describe;\nexport const it = harness.it;\nexport const expect = harness.expect;\n`,
  'core-index.js':
    `${HEADER}export * from "../packages/core/src/index.js";\n` +
    `import * as real from "../packages/core/src/index.js";\n` +
    `export function validatePattern(source, hasContext, caseInsensitive) {\n` +
    `  harness.recordPattern(source, hasContext, caseInsensitive);\n` +
    `  const result = real.validatePattern(source, hasContext, caseInsensitive);\n` +
    `  return result.ok ? { ok: true, pattern: harness.watchPattern(result.pattern, source, caseInsensitive === true) } : result;\n` +
    `}\n` +
    `export function compileRulesPack(payload, ...rest) { harness.recordPack(payload); return real.compileRulesPack(payload, ...rest); }\n` +
    `export function scan(input) { harness.recordScan(input); return real.scan(input); }\n` +
    `export function redactAndRescan(input) { harness.recordScan(input); return real.redactAndRescan(input); }\n` +
    `export function normalizeTerm(term) { harness.recordTerm(term); return real.normalizeTerm(term); }\n` +
    `export function termDigest(salt, normalized) { harness.recordDigest(salt, normalized); return real.termDigest(salt, normalized); }\n`,
  'core-pack.js':
    `${HEADER}export * from "../packages/core/src/custom/pack.js";\n` +
    `import * as real from "../packages/core/src/custom/pack.js";\n` +
    `export class CompiledRulesPack extends real.CompiledRulesPack {\n` +
    `  detect(text, ...rest) { harness.recordDetect(this, text); return super.detect(text, ...rest); }\n` +
    `}\n`,
};

/** Clés admises dans l'entrée de `scan` d'un test repris. */
const SCAN_INPUT_KEYS = new Set(['content', 'sourceKind', 'rules', 'workMeter']);

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === 'object' && value !== null;
}

/** Charge d'un Pack compilé par le moteur d'origine (`CompiledRulesPack.payload`), en JSON. */
function packJson(rules: unknown): string {
  if (!isRecord(rules) || !isRecord(rules['payload'])) throw new UpstreamError('Pack compilé hors forme');
  return JSON.stringify(rules['payload']);
}

/** Exécute les tests repris et relève leurs entrées. `directory` : copie de `transpileCustomUpstream`. */
export async function recordCustomTests(directory: string): Promise<RecordedTest[]> {
  mkdirSync(join(directory, 'harness'), { recursive: true });
  for (const [name, code] of Object.entries(HARNESS_MODULES)) writeFileSync(join(directory, 'harness', name), code);

  const registered: RegisteredTest[] = [];
  const suite: string[] = [];
  let file: CustomTestFile | undefined;
  let current: RecordedInput[] | undefined;
  const seen = new Set<string>();

  const record = (input: RecordedInput): void => {
    if (current === undefined) return; // appel du moteur hors d'un test (préparation d'un fichier) : non relevé
    const key = JSON.stringify(input);
    if (seen.has(key)) return;
    seen.add(key);
    current.push(input);
  };

  const register = (title: unknown, run: () => unknown, row: number | undefined): void => {
    if (file === undefined || typeof title !== 'string') throw new UpstreamError('test d’origine hors forme');
    registered.push({ file, suite: [...suite], title, row, run });
  };
  // it(titre, fn), it(titre, options, fn), it(titre, fn, délai).
  const it = (title: unknown, second: unknown, third?: unknown): void => {
    const fn = typeof second === 'function' ? second : third;
    if (typeof fn !== 'function') throw new UpstreamError('test d’origine sans fonction');
    register(title, () => (fn as TestFunction)(), undefined);
  };
  it.each =
    (rows: readonly unknown[]) =>
    (title: unknown, fn: TestFunction): void => {
      rows.forEach((row, index) => {
        register(title, () => (Array.isArray(row) ? fn(...(row as unknown[])) : fn(row)), index);
      });
    };
  const describe = (title: unknown, fn: () => unknown): void => {
    if (typeof title !== 'string') throw new UpstreamError('suite d’origine hors forme');
    suite.push(title);
    try {
      if (fn() instanceof Promise) throw new UpstreamError('suite asynchrone non prise en charge');
    } finally {
      suite.pop();
    }
  };

  const patternSources = new WeakMap<object, { source: string; caseInsensitive: boolean }>();
  const harness = {
    describe,
    it,
    expect,
    recordPattern: (source: unknown, hasContext: unknown, caseInsensitive: unknown): void => {
      if (typeof source !== 'string' || typeof hasContext !== 'boolean') throw new UpstreamError('motif hors forme');
      record({ kind: 'pattern', pattern: source, hasContext, caseInsensitive: caseInsensitive === true });
    },
    watchPattern: (pattern: object, source: string, caseInsensitive: boolean): object => {
      const recorded = { source, caseInsensitive };
      const proxy = new Proxy(pattern, {
        get(target, property, receiver) {
          if (property === 'matchAt') {
            return (text: unknown, ...rest: unknown[]): unknown => {
              const known = patternSources.get(proxy);
              if (typeof text === 'string' && known !== undefined) {
                record({ kind: 'match', pattern: known.source, caseInsensitive: known.caseInsensitive, text });
              }
              return (target as { matchAt: Fn }).matchAt(text, ...rest);
            };
          }
          return Reflect.get(target, property, receiver) as unknown;
        },
      });
      patternSources.set(proxy, recorded);
      return proxy;
    },
    recordPack: (payload: unknown): void => {
      record({ kind: 'pack', json: JSON.stringify(payload) });
    },
    recordScan: (input: unknown): void => {
      if (!isRecord(input) || typeof input['content'] !== 'string') throw new UpstreamError('entrée de scan hors forme');
      for (const key of Object.keys(input)) {
        if (!SCAN_INPUT_KEYS.has(key)) throw new UpstreamError(`entrée de scan non reprise : ${key}`);
      }
      record({
        kind: 'scan',
        content: input['content'],
        pack: input['rules'] === undefined ? undefined : packJson(input['rules']),
        sharedMeter: input['workMeter'] !== undefined,
      });
    },
    recordDetect: (pack: unknown, text: unknown): void => {
      if (!isRecord(pack) || !Array.isArray(pack['detectors']) || typeof text !== 'string') {
        throw new UpstreamError('détection hors forme');
      }
      const specs = (pack['detectors'] as readonly unknown[]).map((detector) => (isRecord(detector) ? detector['spec'] : undefined));
      record({ kind: 'detect', detectors: JSON.stringify(specs), text });
    },
    recordTerm: (term: unknown): void => {
      if (typeof term !== 'string') throw new UpstreamError('terme hors forme');
      record({ kind: 'term', term });
    },
    recordDigest: (salt: unknown, normalized: unknown): void => {
      if (!(salt instanceof Uint8Array) || typeof normalized !== 'string') throw new UpstreamError('condensat hors forme');
      record({ kind: 'digest', salt: Buffer.from(salt).toString('base64'), normalized });
    },
  };
  type Fn = (...args: unknown[]) => unknown;

  const key = Symbol.for(HARNESS_KEY);
  const holder = globalThis as unknown as Record<symbol, unknown>;
  holder[key] = harness;
  try {
    for (const testFile of CUSTOM_TEST_FILES) {
      file = testFile;
      await import(pathToFileURL(join(directory, 'tests/core', testFile.replace(/\.ts$/, '.js'))).href);
    }
    file = undefined;
    const recorded: RecordedTest[] = [];
    for (const test of registered) {
      current = [];
      seen.clear();
      try {
        await test.run();
      } catch (error) {
        const kind = error instanceof Error ? error.name : 'erreur';
        throw new UpstreamError(`test d’origine en échec sur la copie transpilée : ${testLabel(test)} (${kind})`);
      }
      recorded.push({ file: test.file, suite: test.suite, title: test.title, row: test.row, inputs: current });
      current = undefined;
    }
    return recorded;
  } finally {
    Reflect.deleteProperty(holder, key);
  }
}

/** Libellé d'un test d'origine : fichier, suites, titre, rang de ligne. */
export function testLabel(test: Pick<RecordedTest, 'file' | 'suite' | 'title' | 'row'>): string {
  const row = test.row === undefined ? '' : ` [${String(test.row)}]`;
  return `${test.file} > ${[...test.suite, test.title].join(' > ')}${row}`;
}
