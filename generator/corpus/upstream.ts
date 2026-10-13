/**
 * Moteur TypeScript de Secret Guard pour le corpus de parité. Le générateur lit un checkout du
 * dépôt d'origine au commit de `UPSTREAM.md`, vérifie le SHA-256 de chaque fichier lu,
 * les transpile avec le TypeScript de ce dépôt dans un répertoire temporaire (aucune dépendance du dépôt d'origine
 * n'est installée ni exécutée), puis charge le moteur. Tout écart : arrêt, rien n'est écrit.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, posix } from 'node:path';
import { pathToFileURL } from 'node:url';
import ts from 'typescript';

/** Commit d'origine (identique à `UPSTREAM_COMMIT` du Pack initial). */
export const UPSTREAM_COMMIT = 'c177a447b8cdf8ce07e0c3160ea45dace99b6dc9';

/** Racine du paquet d'origine dans le checkout. */
const ROOT = 'secret-guard';

/**
 * Fichiers lus, chemin relatif au checkout → SHA-256. Moteur : tout `packages/core/src` (Apache-2.0) ; tests :
 * les quatre fichiers que la story reprend (Apache-2.0, `LICENSING.md` du dépôt d'origine).
 */
export const UPSTREAM_FILES: Readonly<Record<string, string>> = {
  'secret-guard/packages/core/src/custom/detect.ts': '554992f995777cfbb99a19db045f15041202773cbd9e26160b5a7c34293c97c3',
  'secret-guard/packages/core/src/custom/pack.ts': '2ff85e14461c3ba6b342cebe548c1f12f730ee6a4e63da50f71856d262977285',
  'secret-guard/packages/core/src/custom/pattern.ts': 'd3f30e83d21546c24462d22bfbbfeb82dc68c81e27cf5e489ca579bf8ce1081f',
  'secret-guard/packages/core/src/custom/schema.ts': 'b6c0cc2521ca2d922f6836116ab4ff474a3b70119e000823cd6a573aa67b5836',
  'secret-guard/packages/core/src/custom/terms.ts': '33913b355b3bc94dbfcbe3e8fc3e6c769432817a5ea475b27a076988a06f546f',
  'secret-guard/packages/core/src/custom/work.ts': 'a16e01b16f3a89074b42240438ea35db13960253d423684624ce19548b3eed18',
  'secret-guard/packages/core/src/encoding.ts': 'e7eedea817282bf801e655a9cfc0f99234f1b0e2c49406653701f86bef54efd0',
  'secret-guard/packages/core/src/hidden.ts': 'b148532f7573b83afb457eedc639e1a3c512f62434691c24a3add45b8e3c7914',
  'secret-guard/packages/core/src/index.ts': 'e684f4f289a246461c6d88a80b59252939bbea030b97e5e6201a9ca205db29dc',
  'secret-guard/packages/core/src/mapping.ts': '6f32fffb85cadb3209405b5befd04f9f32f6c5298cf2541eaed51f58ed522f70',
  'secret-guard/packages/core/src/risk.ts': '1f65736ad6dd032ccb4ed15edbccbb24f631e05f7940b201cfe02a1e2ef54e40',
  'secret-guard/packages/core/src/rules.ts': 'f7ec4603f9184d773b0bdf18227994df785cb7522dced50163c27231f8853499',
  'secret-guard/packages/core/src/scanner.ts': '80ba8d74d90bd3fd045542fadfd8792171d5b7beaa2ac1067edbacbaee77cafc',
  'secret-guard/packages/core/src/sha256.ts': '646ceca41eb40416bdfd9d9675d3b9ef72c1a89073a76d19970528af26fdb5da',
  'secret-guard/packages/core/src/text.ts': 'b3284399a7ce364b1937946d46f5317fbbeee9d14f5d433c1a1882aa101b85bf',
  'secret-guard/packages/core/src/types.ts': '5dba44ed269730dd761ce1ec244681667ff01add4da4f5fbb22ae8a258608ceb',
  'secret-guard/tests/core/encoding.test.ts': 'c4facee2ff59797cd5e6e00be006d2cbc3fdf2ace32a3f5e5bd6a23c8ed62aaa',
  'secret-guard/tests/core/scan.test.ts': '2c75e6c999b47a57858f8502a6fbd8f619bba6581b95724f29aecbe8edac8873',
  'secret-guard/tests/core/security.test.ts': '35743ee86a44b4a42939b2eb057ae3b1c13f1c5df78104aef45462b98405b8d2',
  'secret-guard/tests/core/text.test.ts': 'f011aa164336a518ef8ef081ab05123db2c318d97e69f3d5939c076976757a9b',
};

/** Fichiers de test repris, dans l'ordre d'écriture du corpus. */
export const UPSTREAM_TEST_FILES = ['scan.test.ts', 'security.test.ts', 'encoding.test.ts', 'text.test.ts'] as const;
export type UpstreamTestFile = (typeof UPSTREAM_TEST_FILES)[number];

/** Constat de Secret Guard, réduit aux champs du corpus (positions UTF-16). */
export interface EngineFinding {
  readonly ruleId: string;
  readonly secretType: string;
  readonly encoding: string;
  readonly score: number;
  readonly level: string;
  readonly start: number;
  readonly end: number;
}

export interface EngineResult {
  readonly complete: boolean;
  readonly findings: readonly EngineFinding[];
}

/** Ce que le générateur utilise du moteur d'origine. */
export interface UpstreamEngine {
  scan(content: string, languageId: string | undefined): EngineResult;
  readonly fixedRuleIds: readonly string[];
  isPlaceholder(value: string): boolean;
  isExactPublicExample(value: string): boolean;
  readonly maxInputBytes: number;
}

/** Copie transpilée du checkout, à supprimer par `dispose`. */
export interface TranspiledUpstream {
  readonly directory: string;
  readonly engine: UpstreamEngine;
  dispose(): void;
}

export class UpstreamError extends Error {
  override readonly name = 'UpstreamError';
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** Lit et vérifie chaque fichier épinglé ; refuse un checkout d'un autre commit (ou modifié). */
export function readPinnedFiles(checkout: string): ReadonlyMap<string, string> {
  const files = new Map<string, string>();
  for (const [path, expected] of Object.entries(UPSTREAM_FILES)) {
    let bytes: Buffer;
    try {
      bytes = readFileSync(join(checkout, path));
    } catch {
      throw new UpstreamError(`fichier d'origine introuvable dans le checkout : ${path}`);
    }
    if (sha256(bytes) !== expected) {
      throw new UpstreamError(`fichier d'origine différent du commit ${UPSTREAM_COMMIT} : ${path}`);
    }
    files.set(path, bytes.toString('utf8'));
  }
  return files;
}

/** TypeScript → JavaScript (module ES), sans vérification de types. */
export function transpile(source: string, fileName: string): string {
  const output = ts.transpileModule(source, {
    fileName,
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
      verbatimModuleSyntax: false,
      sourceMap: false,
    },
    reportDiagnostics: true,
  });
  if ((output.diagnostics ?? []).length > 0) throw new UpstreamError(`transpilation refusée : ${fileName}`);
  return output.outputText;
}

/** Import statique d'un module transpilé : spécificateur et position de sa chaîne (guillemets compris). */
export interface ModuleImport {
  readonly specifier: string;
  readonly start: number;
  readonly end: number;
}

/**
 * Imports statiques d'un module transpilé, lus dans l'arbre syntaxique (imports sans liaison `import "x"` compris).
 * Refuse `import(…)`, `require(…)`, `eval(…)` et `Function(…)` : seuls les imports listés sont chargés. Le contrôle
 * principal reste le SHA-256 de chaque fichier lu ; celui-ci arrête un écart de forme avant toute exécution.
 */
export function moduleImports(code: string, fileName: string): ModuleImport[] {
  const source = ts.createSourceFile(fileName, code, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
  const imports: ModuleImport[] = [];
  const refuse = (what: string): never => {
    throw new UpstreamError(`${what} refusé : ${fileName}`);
  };
  const visit = (node: ts.Node): void => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier !== undefined) {
      const literal = node.moduleSpecifier;
      if (!ts.isStringLiteral(literal)) refuse('spécificateur d’import calculé');
      imports.push({ specifier: (literal as ts.StringLiteral).text, start: literal.getStart(source), end: literal.getEnd() });
    }
    if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
      const callee = node.expression;
      if (callee.kind === ts.SyntaxKind.ImportKeyword) refuse('import dynamique');
      if (ts.isIdentifier(callee) && ['require', 'eval', 'Function'].includes(callee.text)) refuse(`appel de ${callee.text}`);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return imports;
}

/** Spécificateurs des imports statiques d'un module transpilé (voir `moduleImports`). */
export function importSpecifiers(code: string, fileName: string): string[] {
  return moduleImports(code, fileName).map((entry) => entry.specifier);
}

/** Remplace chaque spécificateur d'import par sa cible, à sa position seulement (jamais une autre chaîne égale). */
export function rewriteImports(code: string, imports: readonly ModuleImport[], target: (specifier: string) => string): string {
  let out = '';
  let cursor = 0;
  for (const entry of [...imports].sort((left, right) => left.start - right.start)) {
    out += code.slice(cursor, entry.start) + JSON.stringify(target(entry.specifier));
    cursor = entry.end;
  }
  return out + code.slice(cursor);
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === 'object' && value !== null;
}

function stringField(value: Readonly<Record<string, unknown>>, key: string): string {
  const field = value[key];
  if (typeof field !== 'string') throw new UpstreamError(`résultat du moteur hors forme : ${key}`);
  return field;
}

function integerField(value: Readonly<Record<string, unknown>>, key: string): number {
  const field = value[key];
  if (typeof field !== 'number' || !Number.isInteger(field)) {
    throw new UpstreamError(`résultat du moteur hors forme : ${key}`);
  }
  return field;
}

/** Lit un `ScanResult` de Secret Guard sans lui faire confiance. */
export function readScanResult(value: unknown): EngineResult {
  if (!isRecord(value) || typeof value['complete'] !== 'boolean' || !Array.isArray(value['findings'])) {
    throw new UpstreamError('résultat du moteur hors forme');
  }
  const findings = (value['findings'] as readonly unknown[]).map((item): EngineFinding => {
    if (!isRecord(item) || !isRecord(item['span'])) throw new UpstreamError('constat du moteur hors forme');
    const span = item['span'];
    if (!isRecord(span['start']) || !isRecord(span['end'])) throw new UpstreamError('étendue du moteur hors forme');
    return {
      ruleId: stringField(item, 'ruleId'),
      secretType: stringField(item, 'secretType'),
      encoding: stringField(item, 'encoding'),
      score: integerField(item, 'score'),
      level: stringField(item, 'level'),
      start: integerField(span['start'], 'offset'),
      end: integerField(span['end'], 'offset'),
    };
  });
  return { complete: value['complete'], findings };
}

function functionField(module: Readonly<Record<string, unknown>>, key: string): (...args: unknown[]) => unknown {
  const field = module[key];
  if (typeof field !== 'function') throw new UpstreamError(`export absent du moteur : ${key}`);
  return field as (...args: unknown[]) => unknown;
}

/** Moteur typé à partir du module `index.js` transpilé. */
export function engineOf(module: unknown): UpstreamEngine {
  if (!isRecord(module)) throw new UpstreamError('module du moteur hors forme');
  const scan = functionField(module, 'scan');
  const isPlaceholder = functionField(module, 'isPlaceholder');
  const isExactPublicExample = functionField(module, 'isExactPublicExample');
  const fixedRuleIds = module['FIXED_RULE_IDS'];
  const maxInputBytes = module['MAX_INPUT_BYTES'];
  if (!Array.isArray(fixedRuleIds) || !fixedRuleIds.every((id): id is string => typeof id === 'string')) {
    throw new UpstreamError('FIXED_RULE_IDS hors forme');
  }
  if (typeof maxInputBytes !== 'number') throw new UpstreamError('MAX_INPUT_BYTES hors forme');
  const truth = (value: unknown, name: string): boolean => {
    if (typeof value !== 'boolean') throw new UpstreamError(`${name} hors forme`);
    return value;
  };
  return {
    scan: (content, languageId) =>
      readScanResult(scan(languageId === undefined ? { content } : { content, languageId })),
    fixedRuleIds: [...fixedRuleIds],
    isPlaceholder: (value) => truth(isPlaceholder(value), 'isPlaceholder'),
    isExactPublicExample: (value) => truth(isExactPublicExample(value), 'isExactPublicExample'),
    maxInputBytes,
  };
}

/** Écrit `relative` (chemin `.js`) dans la copie transpilée. */
function writeModule(directory: string, relative: string, code: string): void {
  const target = join(directory, relative);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, code);
}

/**
 * Transpile le moteur et les tests repris dans un répertoire temporaire. Les imports des tests sont redirigés
 * (`vitest`, modules du moteur) par `testImports` ; tout autre import fait échouer la préparation.
 */
export async function transpileUpstream(
  checkout: string,
  testImports: (testFile: UpstreamTestFile, specifier: string) => string | undefined,
): Promise<TranspiledUpstream> {
  const files = readPinnedFiles(checkout);
  const directory = mkdtempSync(join(tmpdir(), 'secret-guard-detection-corpus-'));
  try {
    for (const [path, source] of files) {
      if (!path.startsWith(`${ROOT}/packages/core/src/`)) continue;
      const relative = path.slice(`${ROOT}/`.length).replace(/\.ts$/, '.js');
      const code = transpile(source, path);
      for (const specifier of importSpecifiers(code, path)) {
        // Import relatif vers un module du moteur, sans sortir de `packages/core/src`.
        const resolved = posix.normalize(posix.join(posix.dirname(relative), specifier));
        if (!/^\.\.?\/[A-Za-z0-9_/.-]+\.js$/.test(specifier) || !resolved.startsWith('packages/core/src/')) {
          throw new UpstreamError(`import inattendu dans le moteur : ${path} → ${specifier}`);
        }
      }
      writeModule(directory, relative, code);
    }
    for (const testFile of UPSTREAM_TEST_FILES) {
      const path = `${ROOT}/tests/core/${testFile}`;
      const code = transpile(files.get(path) ?? '', path);
      const imports = moduleImports(code, path);
      const rewritten = rewriteImports(code, imports, (specifier) => {
        const target = testImports(testFile, specifier);
        if (target === undefined) throw new UpstreamError(`import inattendu dans ${testFile} : ${specifier}`);
        return target;
      });
      writeModule(directory, `tests/core/${testFile.replace(/\.ts$/, '.js')}`, rewritten);
    }
    const module: unknown = await import(pathToFileURL(join(directory, 'packages/core/src/index.js')).href);
    const engine = engineOf(module);
    return {
      directory,
      engine,
      dispose: () => {
        rmSync(directory, { recursive: true, force: true });
      },
    };
  } catch (error) {
    rmSync(directory, { recursive: true, force: true });
    throw error;
  }
}
