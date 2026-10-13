/**
 * Reprise des tests de Secret Guard dans le corpus : chaque fichier de test repris est exécuté sur le
 * moteur transpilé, avec le `expect` de Vitest (une assertion d'origine qui échoue arrête le générateur : la copie
 * transpilée se comporte comme l'origine), et chaque entrée passée au moteur (`scan`, `redactAndRescan`,
 * `decodeBase64`, `isStructurallyValidJwt`, `decodeScannableText`) est relevée avec le test qui l'a passée.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect } from 'vitest';
import { UPSTREAM_TEST_FILES, UpstreamError, type UpstreamTestFile } from './upstream.ts';

/** Clé globale par laquelle les modules de la copie transpilée joignent l'enregistreur. */
const HARNESS_KEY = 'secret-guard.detection-corpus.harness';

/** Entrée relevée : texte (avec son langage déclaré) ou octets. */
export type RecordedInput =
  | { readonly kind: 'text'; readonly content: string; readonly languageId: string | undefined }
  | { readonly kind: 'bytes'; readonly bytes: Uint8Array };

/** Test d'origine et entrées qu'il a passées au moteur, dans l'ordre, sans doublon. */
export interface RecordedTest {
  readonly file: UpstreamTestFile;
  readonly suite: readonly string[];
  readonly title: string;
  /** Rang de la ligne de `it.each`, absent pour `it`. */
  readonly row: number | undefined;
  readonly inputs: readonly RecordedInput[];
  /** Appels du moteur avec un argument hors forme (`scan(null)`…), sans entrée d'octets. */
  readonly unrepresentable: number;
}

interface RegisteredTest {
  readonly file: UpstreamTestFile;
  readonly suite: readonly string[];
  readonly title: string;
  readonly row: number | undefined;
  readonly run: () => unknown;
}

type TestFunction = (...args: unknown[]) => unknown;

/** Imports des tests repris → module de la copie transpilée (chemin relatif à `tests/core/`). */
const TEST_IMPORTS: Readonly<Record<string, string>> = {
  vitest: '../../harness/vitest.js',
  '../../packages/core/src/index': '../../harness/core-index.js',
  '../../packages/core/src/encoding.js': '../../harness/core-encoding.js',
  '../../packages/core/src/text.js': '../../harness/core-text.js',
  '../../packages/core/src/types.js': '../../packages/core/src/types.js',
};

export function testImport(_file: UpstreamTestFile, specifier: string): string | undefined {
  return TEST_IMPORTS[specifier];
}

const HEADER = `const harness = globalThis[Symbol.for(${JSON.stringify(HARNESS_KEY)})];\n`;

/** Modules d'interception écrits dans la copie transpilée. */
const HARNESS_MODULES: Readonly<Record<string, string>> = {
  'vitest.js': `${HEADER}export const describe = harness.describe;\nexport const it = harness.it;\nexport const expect = harness.expect;\n`,
  'core-index.js':
    `${HEADER}export * from "../packages/core/src/index.js";\n` +
    `import * as real from "../packages/core/src/index.js";\n` +
    `export function scan(input) { harness.recordScan(input); return real.scan(input); }\n` +
    `export function redactAndRescan(input) { harness.recordScan(input); return real.redactAndRescan(input); }\n`,
  'core-encoding.js':
    `${HEADER}export * from "../packages/core/src/encoding.js";\n` +
    `import * as real from "../packages/core/src/encoding.js";\n` +
    `export function decodeBase64(value, ...rest) { harness.recordText(value); return real.decodeBase64(value, ...rest); }\n` +
    `export function isStructurallyValidJwt(value, ...rest) { harness.recordText(value); return real.isStructurallyValidJwt(value, ...rest); }\n`,
  'core-text.js':
    `${HEADER}export * from "../packages/core/src/text.js";\n` +
    `import * as real from "../packages/core/src/text.js";\n` +
    `export function decodeScannableText(bytes) { harness.recordBytes(bytes); return real.decodeScannableText(bytes); }\n`,
};

/** Clés admises dans l'entrée de `scan` d'un test repris (`rules` et `workMeter` changeraient le résultat). */
const SCAN_INPUT_KEYS = new Set(['content', 'languageId', 'sourceKind']);

/** Exécute les tests repris et relève leurs entrées. `directory` : copie transpilée par `transpileUpstream`. */
export async function recordUpstreamTests(directory: string): Promise<RecordedTest[]> {
  mkdirSync(join(directory, 'harness'), { recursive: true });
  for (const [name, code] of Object.entries(HARNESS_MODULES)) writeFileSync(join(directory, 'harness', name), code);

  const registered: RegisteredTest[] = [];
  const suite: string[] = [];
  let file: UpstreamTestFile | undefined;
  let current: RecordedInput[] | undefined;
  let unrepresentable = 0;

  const record = (input: RecordedInput): void => {
    if (current === undefined) throw new UpstreamError('entrée passée au moteur hors d’un test');
    const same = current.some((seen) =>
      seen.kind === 'text' && input.kind === 'text'
        ? seen.content === input.content && seen.languageId === input.languageId
        : seen.kind === 'bytes' && input.kind === 'bytes' && Buffer.from(seen.bytes).equals(Buffer.from(input.bytes)),
    );
    if (!same) current.push(input);
  };

  const register = (title: unknown, run: () => unknown, row: number | undefined): void => {
    if (file === undefined || typeof title !== 'string') throw new UpstreamError('test d’origine hors forme');
    registered.push({ file, suite: [...suite], title, row, run });
  };

  const it = (title: unknown, fn: TestFunction): void => {
    register(title, () => fn(), undefined);
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

  const harness = {
    describe,
    it,
    expect,
    recordScan: (input: unknown): void => {
      // Argument hors forme (`scan(null)`…) : le test éprouve le refus du moteur, sans entrée d'octets possible.
      if (typeof input !== 'object' || input === null || typeof (input as { content?: unknown }).content !== 'string') {
        if (current === undefined) throw new UpstreamError('entrée passée au moteur hors d’un test');
        unrepresentable += 1;
        return;
      }
      const fields = input as Readonly<Record<string, unknown>>;
      for (const key of Object.keys(fields)) {
        if (!SCAN_INPUT_KEYS.has(key)) throw new UpstreamError(`entrée de scan non reprise : ${key}`);
      }
      const content = fields['content'];
      const languageId = fields['languageId'];
      if (typeof content !== 'string' || (languageId !== undefined && typeof languageId !== 'string')) {
        throw new UpstreamError('entrée de scan hors forme');
      }
      record({ kind: 'text', content, languageId });
    },
    recordText: (value: unknown): void => {
      if (typeof value !== 'string') throw new UpstreamError('entrée de décodage hors forme');
      record({ kind: 'text', content: value, languageId: undefined });
    },
    recordBytes: (value: unknown): void => {
      if (!(value instanceof Uint8Array)) throw new UpstreamError('entrée d’octets hors forme');
      record({ kind: 'bytes', bytes: Uint8Array.from(value) });
    },
  };

  const key = Symbol.for(HARNESS_KEY);
  const holder = globalThis as unknown as Record<symbol, unknown>;
  holder[key] = harness;
  try {
    for (const testFile of UPSTREAM_TEST_FILES) {
      file = testFile;
      await import(pathToFileURL(join(directory, 'tests/core', testFile.replace(/\.ts$/, '.js'))).href);
    }
    file = undefined;
    const recorded: RecordedTest[] = [];
    for (const test of registered) {
      current = [];
      unrepresentable = 0;
      try {
        await test.run();
      } catch (error) {
        // Type de l'erreur seulement : le message d'une assertion recopie les valeurs comparées.
        const kind = error instanceof Error ? error.name : 'erreur';
        throw new UpstreamError(`test d’origine en échec sur la copie transpilée : ${testLabel(test)} (${kind})`);
      }
      recorded.push({
        file: test.file,
        suite: test.suite,
        title: test.title,
        row: test.row,
        inputs: current,
        unrepresentable,
      });
      current = undefined;
    }
    return recorded;
  } finally {
    Reflect.deleteProperty(holder, key);
  }
}

/** Libellé d'un test d'origine : fichier, suites, titre (gabarit de `it.each` non rempli), rang de ligne. */
export function testLabel(test: Pick<RecordedTest, 'file' | 'suite' | 'title' | 'row'>): string {
  const row = test.row === undefined ? '' : ` [${String(test.row)}]`;
  return `${test.file} > ${[...test.suite, test.title].join(' > ')}${row}`;
}
