/**
 * `hidden.ts` et `mentionedPaths` d'origine pour les vecteurs de parité des instructions cachées et des mentions.
 *
 * Comme le corpus de détection (`../corpus/upstream.ts`) : le générateur lit un checkout du dépôt d'origine, vérifie
 * le SHA-256 de chaque fichier lu, les transpile avec le TypeScript de ce dépôt dans un répertoire temporaire (aucune
 * dépendance du dépôt d'origine n'est installée ni exécutée), puis exécute le test d'origine repris avec un `expect`
 * de Vitest et relève chaque texte passé à `findHidden`/`stripHidden` et chaque prompt passé à `mentionedPaths`.
 *
 * Fichiers lus : tout le moteur `secret-guard/packages/core/src` (déjà épinglé pour le corpus), quatre fichiers de
 * `secret-guard/packages/cli/src` (`file-guard.ts` et ce que charge son test) et le test
 * `secret-guard/tests/cli/file-guard.test.ts`, tous dans le périmètre Apache-2.0 de `LICENSING.md` du dépôt
 * d'origine. Les tests `tests/core/hidden.test.ts` et `tests/cli/instructions.test.ts` n'y sont pas : ils ne sont ni
 * lus ni repris (les cas synthétiques couvrent chaque porteur et chaque exception). `tests/cli/hook.test.ts` n'est
 * pas repris : ses prompts ne portent ni caractère caché ni mention, et deux portent une valeur synthétique de jeton
 * que la recherche de secrets relèverait dans les vecteurs.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, posix } from 'node:path';
import { pathToFileURL } from 'node:url';
import ts from 'typescript';
import { expect } from 'vitest';
import { moduleImports, rewriteImports, transpile, UPSTREAM_COMMIT, UPSTREAM_FILES, UpstreamError } from '../corpus/upstream.ts';

export { UPSTREAM_COMMIT, UpstreamError };

const ROOT = 'secret-guard';
const CORE = `${ROOT}/packages/core/src/`;
const CLI = `${ROOT}/packages/cli/src/`;

/** Fichiers de la ligne de commande d'origine lus (chemin → SHA-256). */
export const CLI_FILES: Readonly<Record<string, string>> = {
  'secret-guard/packages/cli/src/file-guard.ts': 'd6a29932509fe6b74ad2bce0fcffd30f8456e5cced4f48e1eeb8784966babcce',
  'secret-guard/packages/cli/src/hook.ts': '6b700cb47f66da23d0c4f38140d7addeeafec1b6973e85e636e18db74d0efc0f',
  'secret-guard/packages/cli/src/instructions.ts': 'fc9566e3a0e6ce14cfd9e01e7ffc1924529c95822c05fb569a8388b0f2532e2d',
  'secret-guard/packages/cli/src/report.ts': 'bd5991994b165554a0cdaf176bb9e0ec966eb1b2de06d587ca544ee3adfcf0d3',
};

/** Test d'origine repris (chemin → SHA-256). */
export const TEST_FILE = 'secret-guard/tests/cli/file-guard.test.ts';
export const TEST_FILE_SHA256 = '2804cd6eb96488f3956b3132120823879647841ece96f94eab0ba6318ec2b583';

/** Tous les fichiers lus : moteur (épinglé pour le corpus), ligne de commande, test. */
export function hiddenUpstreamFiles(): Readonly<Record<string, string>> {
  const files: Record<string, string> = {};
  for (const [path, sha] of Object.entries(UPSTREAM_FILES)) if (path.startsWith(CORE)) files[path] = sha;
  return { ...files, ...CLI_FILES, [TEST_FILE]: TEST_FILE_SHA256 };
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** Lit et vérifie chaque fichier épinglé ; refuse un fichier absent ou différent. */
export function readHiddenPinnedFiles(checkout: string): ReadonlyMap<string, string> {
  const files = new Map<string, string>();
  for (const [path, expected] of Object.entries(hiddenUpstreamFiles())) {
    let bytes: Buffer;
    try {
      bytes = readFileSync(join(checkout, path));
    } catch {
      throw new UpstreamError(`fichier d'origine introuvable dans le checkout : ${path}`);
    }
    if (sha256(bytes) !== expected) throw new UpstreamError(`fichier d'origine différent du commit ${UPSTREAM_COMMIT} : ${path}`);
    files.set(path, bytes.toString('utf8'));
  }
  return files;
}

/** Expression régulière littérale d'un source TypeScript : corps et drapeaux. */
export interface RegexLiteral {
  readonly source: string;
  readonly flags: string;
}

/** Expressions régulières littérales d'un source TypeScript (ou d'une de ses fonctions), dans l'ordre d'écriture. */
export function regexLiterals(source: string, fileName: string, functionName?: string): RegexLiteral[] {
  const file = ts.createSourceFile(fileName, source, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TS);
  let root: ts.Node = file;
  if (functionName !== undefined) {
    const declarations = file.statements.filter(
      (statement): statement is ts.FunctionDeclaration => ts.isFunctionDeclaration(statement) && statement.name?.text === functionName,
    );
    const declaration = declarations[0];
    if (declarations.length !== 1 || declaration === undefined) throw new UpstreamError(`fonction ${functionName} introuvable : ${fileName}`);
    root = declaration;
  }
  const found: RegexLiteral[] = [];
  const visit = (node: ts.Node): void => {
    if (node.kind === ts.SyntaxKind.RegularExpressionLiteral) {
      const text = node.getText(file);
      const close = text.lastIndexOf('/');
      found.push({ source: text.slice(1, close), flags: text.slice(close + 1) });
    }
    ts.forEachChild(node, visit);
  };
  visit(root);
  return found;
}

/** Point d'entrée d'un test d'origine relevé. */
export type HiddenRecord =
  | { readonly kind: 'hidden'; readonly text: string }
  | { readonly kind: 'mentions'; readonly prompt: string };

export interface RecordedTest {
  readonly suite: readonly string[];
  readonly title: string;
  readonly inputs: readonly HiddenRecord[];
}

/** Fonctions d'origine employées par le générateur. */
export interface HiddenUpstream {
  findHidden(text: string): unknown;
  stripHidden(text: string): unknown;
  mentionedPaths(prompt: string, cwd: string): unknown;
  readonly maxHiddenFindings: number;
  readonly scatteredInvisibleThreshold: number;
  readonly maxInputBytes: number;
  /** Expressions de `hidden.ts` et de `mentionedPaths`, lues dans les sources vérifiées. */
  readonly hiddenRegexes: readonly RegexLiteral[];
  readonly mentionRegexes: readonly RegexLiteral[];
  readonly tests: readonly RecordedTest[];
}

const HARNESS_KEY = 'secret-guard.hidden-vectors.harness';
const HEADER = `const harness = globalThis[Symbol.for(${JSON.stringify(HARNESS_KEY)})];\n`;

/** Modules d'interception, écrits dans `harness/` de la copie transpilée. */
const HARNESS_MODULES: Readonly<Record<string, string>> = {
  'vitest.js':
    `${HEADER}export const describe = harness.describe;\nexport const it = harness.it;\nexport const expect = harness.expect;\n` +
    'export const afterEach = harness.afterEach;\nexport const beforeEach = harness.beforeEach;\n',
  'core-index.js':
    `${HEADER}export * from "../packages/core/src/index.js";\n` +
    'import * as real from "../packages/core/src/index.js";\n' +
    'export function findHidden(text) { harness.recordHidden(text); return real.findHidden(text); }\n' +
    'export function stripHidden(text) { harness.recordHidden(text); return real.stripHidden(text); }\n',
  'file-guard.js':
    `${HEADER}export * from "../packages/cli/src/file-guard.js";\n` +
    'import * as real from "../packages/cli/src/file-guard.js";\n' +
    'export function mentionedPaths(prompt, cwd) { harness.recordMentions(prompt); return real.mentionedPaths(prompt, cwd); }\n',
};

/** Imports admis dans les modules de la ligne de commande transpilés (spécificateur → cible, `undefined` : tel quel). */
function cliImport(file: string, specifier: string): string | undefined | null {
  if (['node:fs', 'node:path', 'node:process'].includes(specifier)) return undefined;
  if (specifier === '@xsom/secret-guard-core') return '../../../harness/core-index.js';
  // Le hook passe par l'enregistreur pour relever les prompts de ses mentions.
  if (specifier === './file-guard.js') return file.endsWith('/hook.ts') ? '../../../harness/file-guard.js' : undefined;
  if (['./hook.js', './instructions.js', './report.js'].includes(specifier)) return undefined;
  return null;
}

function testImport(specifier: string): string | undefined | null {
  if (['node:fs', 'node:os', 'node:path'].includes(specifier)) return undefined;
  if (specifier === 'vitest') return '../../harness/vitest.js';
  if (specifier === '../../packages/cli/src/file-guard.js') return '../../harness/file-guard.js';
  if (specifier === '../../packages/cli/src/hook.js') return undefined;
  return null;
}

function writeModule(directory: string, relative: string, code: string): void {
  const target = join(directory, relative);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, code);
}

function transpileWith(source: string, path: string, rewrite: (specifier: string) => string | undefined | null): string {
  const code = transpile(source, path);
  const imports = moduleImports(code, path);
  for (const entry of imports) {
    if (rewrite(entry.specifier) === null) throw new UpstreamError(`import inattendu : ${path} → ${entry.specifier}`);
  }
  return rewriteImports(code, imports, (specifier) => rewrite(specifier) ?? specifier);
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === 'object' && value !== null;
}

function functionOf(module: unknown, key: string): (...args: unknown[]) => unknown {
  const field = isRecord(module) ? module[key] : undefined;
  if (typeof field !== 'function') throw new UpstreamError(`export absent : ${key}`);
  return field as (...args: unknown[]) => unknown;
}

function numberOf(module: unknown, key: string): number {
  const field = isRecord(module) ? module[key] : undefined;
  if (typeof field !== 'number' || !Number.isInteger(field)) throw new UpstreamError(`export absent : ${key}`);
  return field;
}

type TestFunction = (...args: unknown[]) => unknown;

/** Exécute le test repris et relève ses entrées (copie transpilée dans `directory`). */
async function recordTests(directory: string): Promise<RecordedTest[]> {
  const registered: { suite: string[]; title: string; run: () => unknown }[] = [];
  const after: (() => unknown)[] = [];
  const before: (() => unknown)[] = [];
  const suite: string[] = [];
  let current: HiddenRecord[] | undefined;
  const record = (input: HiddenRecord): void => {
    if (current === undefined) throw new UpstreamError('entrée passée hors d’un test');
    const same = current.some((seen) =>
      seen.kind === 'hidden' && input.kind === 'hidden' ? seen.text === input.text : seen.kind === 'mentions' && input.kind === 'mentions' && seen.prompt === input.prompt,
    );
    if (!same) current.push(input);
  };
  const it = (title: unknown, fn: TestFunction): void => {
    if (typeof title !== 'string') throw new UpstreamError('test d’origine hors forme');
    registered.push({ suite: [...suite], title, run: () => fn() });
  };
  const harness = {
    describe: (title: unknown, fn: () => unknown): void => {
      if (typeof title !== 'string') throw new UpstreamError('suite d’origine hors forme');
      suite.push(title);
      try {
        if (fn() instanceof Promise) throw new UpstreamError('suite asynchrone non prise en charge');
      } finally {
        suite.pop();
      }
    },
    it,
    expect,
    afterEach: (fn: () => unknown): void => {
      after.push(fn);
    },
    beforeEach: (fn: () => unknown): void => {
      before.push(fn);
    },
    recordHidden: (text: unknown): void => {
      if (typeof text !== 'string') throw new UpstreamError('texte hors forme');
      record({ kind: 'hidden', text });
    },
    recordMentions: (prompt: unknown): void => {
      if (typeof prompt !== 'string') throw new UpstreamError('prompt hors forme');
      record({ kind: 'mentions', prompt });
    },
  };
  const key = Symbol.for(HARNESS_KEY);
  const holder = globalThis as unknown as Record<symbol, unknown>;
  holder[key] = harness;
  try {
    await import(pathToFileURL(join(directory, 'tests/cli/file-guard.test.js')).href);
    const recorded: RecordedTest[] = [];
    for (const test of registered) {
      current = [];
      try {
        for (const hook of before) await hook();
        await test.run();
        for (const hook of after) await hook();
      } catch (error) {
        const kind = error instanceof Error ? error.name : 'erreur';
        throw new UpstreamError(`test d’origine en échec sur la copie transpilée : ${[...test.suite, test.title].join(' > ')} (${kind})`);
      }
      recorded.push({ suite: test.suite, title: test.title, inputs: current });
      current = undefined;
    }
    return recorded;
  } finally {
    Reflect.deleteProperty(holder, key);
  }
}

/**
 * Transpile le moteur, la ligne de commande et le test repris dans un répertoire temporaire, exécute le test, puis
 * rend les fonctions d'origine. Le répertoire est supprimé avant le retour.
 */
export async function loadHiddenUpstream(checkout: string): Promise<HiddenUpstream> {
  if (process.platform === 'win32') throw new UpstreamError('générateur POSIX seulement (résolution de chemin de mentionedPaths)');
  const files = readHiddenPinnedFiles(checkout);
  const directory = mkdtempSync(join(tmpdir(), 'secret-guard-hidden-vectors-'));
  try {
    for (const [path, source] of files) {
      if (path.startsWith(CORE)) {
        const relative = path.slice(`${ROOT}/`.length).replace(/\.ts$/, '.js');
        const code = transpile(source, path);
        for (const entry of moduleImports(code, path)) {
          const resolved = posix.normalize(posix.join(posix.dirname(relative), entry.specifier));
          if (!/^\.\.?\/[A-Za-z0-9_/.-]+\.js$/.test(entry.specifier) || !resolved.startsWith('packages/core/src/')) {
            throw new UpstreamError(`import inattendu dans le moteur : ${path} → ${entry.specifier}`);
          }
        }
        writeModule(directory, relative, code);
      } else if (path.startsWith(CLI)) {
        const relative = path.slice(`${ROOT}/`.length).replace(/\.ts$/, '.js');
        writeModule(directory, relative, transpileWith(source, path, (specifier) => cliImport(path, specifier)));
      } else {
        writeModule(directory, 'tests/cli/file-guard.test.js', transpileWith(source, path, testImport));
      }
    }
    for (const [name, code] of Object.entries(HARNESS_MODULES)) writeModule(directory, `harness/${name}`, code);

    const tests = await recordTests(directory);
    const core: unknown = await import(pathToFileURL(join(directory, 'packages/core/src/index.js')).href);
    const fileGuard: unknown = await import(pathToFileURL(join(directory, 'packages/cli/src/file-guard.js')).href);
    const hidden = files.get(`${CORE}hidden.ts`) ?? '';
    const guard = files.get(`${CLI}file-guard.ts`) ?? '';
    return {
      findHidden: functionOf(core, 'findHidden'),
      stripHidden: functionOf(core, 'stripHidden'),
      mentionedPaths: functionOf(fileGuard, 'mentionedPaths'),
      maxHiddenFindings: numberOf(core, 'MAX_HIDDEN_FINDINGS'),
      scatteredInvisibleThreshold: numberOf(core, 'SCATTERED_INVISIBLE_THRESHOLD'),
      maxInputBytes: numberOf(core, 'MAX_INPUT_BYTES'),
      hiddenRegexes: regexLiterals(hidden, `${CORE}hidden.ts`),
      mentionRegexes: regexLiterals(guard, `${CLI}file-guard.ts`, 'mentionedPaths'),
      tests,
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}
