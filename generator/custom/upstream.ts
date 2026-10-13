/**
 * Moteur TypeScript d'origine pour les vecteurs du Pack de règles du client. Même principe que le corpus de parité
 * (`corpus/upstream.ts`) : checkout au commit de `UPSTREAM.md`, SHA-256 de chaque fichier lu vérifié, transpilation
 * par le TypeScript de ce dépôt dans un répertoire temporaire, aucune dépendance du dépôt d'origine installée ni
 * exécutée. Fichiers lus en plus du moteur : les trois tests des règles du client, les vecteurs du contrat et le
 * script du plus grand Pack (aucun n'est copié dans ce dépôt ; seules leurs entrées et les résultats du moteur le
 * sont).
 */
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, posix } from 'node:path';
import { pathToFileURL } from 'node:url';
import { importSpecifiers, moduleImports, rewriteImports, transpile, UPSTREAM_COMMIT, UPSTREAM_FILES, UpstreamError } from '../corpus/upstream.ts';

export { UPSTREAM_COMMIT, UpstreamError };

/** Fichiers lus en plus du moteur (`UPSTREAM_FILES`), chemin relatif au checkout → SHA-256. */
export const CUSTOM_UPSTREAM_FILES: Readonly<Record<string, string>> = {
  'secret-guard/tests/core/rules-pack-contract.test.ts': '42a9bed907ff0648f75cae0e27995271236bf338afcbb35c6488c32b3f0c527c',
  'secret-guard/tests/core/rules-pattern.test.ts': '8150edf919da35dd1074dc85a03b80acc165e61a927a1bf476bd7ee097487780',
  'secret-guard/tests/core/rules-scan.test.ts': '190fc4fbbd5bcfca88bd983f2668933e48d2ee655e44f7672a19559b5a4bb071',
  'secret-guard/contracts/fixtures/rules-pack-vectors.json': '247d7f1f846649c81267a20a550add4c7cd3663851c4dc77419d26d400f9909b',
  'secret-guard/contracts/RULES-PACK.md': '37c26d75ad98aca155a4adbd32b3ef6c80b36215486a4a46545b25cbf0e782b0',
  'secret-guard/contracts/rules-pack.schema.json': '43fb935003d799098c1751894ad9cbd7b150e12756244f4bcb15c01d8c9aa545',
  'secret-guard/scripts/largest-rules-pack.mjs': '2c46da7f05386014cc1b7d0abfc3c45b0078deb8c67c59738d45d94ecdb18ace',
};

/** Tests repris, dans l'ordre d'écriture des vecteurs. */
export const CUSTOM_TEST_FILES = ['rules-pack-contract.test.ts', 'rules-pattern.test.ts', 'rules-scan.test.ts'] as const;
export type CustomTestFile = (typeof CUSTOM_TEST_FILES)[number];

const ROOT = 'secret-guard';

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** Lit et vérifie le moteur et les fichiers des règles du client ; refuse un checkout d'un autre commit (ou modifié). */
export function readCustomPinnedFiles(checkout: string): ReadonlyMap<string, string> {
  const engine = Object.entries(UPSTREAM_FILES).filter(([path]) => path.startsWith(`${ROOT}/packages/core/src/`));
  const files = new Map<string, string>();
  for (const [path, expected] of [...engine, ...Object.entries(CUSTOM_UPSTREAM_FILES)]) {
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

/** Copie transpilée du moteur et des tests, à supprimer par `dispose`. */
export interface TranspiledCustom {
  readonly directory: string;
  /** Contenu du fichier d'origine `path` (vérifié). */
  file(path: string): string;
  dispose(): void;
}

function writeModule(directory: string, relative: string, code: string): void {
  const target = join(directory, relative);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, code);
}

/**
 * Imports des tests repris → module de la copie transpilée (chemin relatif à `tests/core/`). Les modules
 * `harness/*` relèvent les entrées passées au moteur (`harness.ts`).
 */
const TEST_IMPORTS: Readonly<Record<string, string>> = {
  vitest: '../../harness/vitest.js',
  '@xsom/secret-guard-core': '../../harness/core-index.js',
  '../../packages/core/src/custom/pack.js': '../../harness/core-pack.js',
  '../../packages/core/src/custom/terms.js': '../../packages/core/src/custom/terms.js',
  '../../packages/core/src/custom/schema.js': '../../packages/core/src/custom/schema.js',
  '../../scripts/largest-rules-pack.mjs': '../../harness/largest-rules-pack.js',
  'node:fs': 'node:fs',
};

/** Transpile le moteur et les tests des règles du client dans un répertoire temporaire. */
export function transpileCustomUpstream(checkout: string): TranspiledCustom {
  const files = readCustomPinnedFiles(checkout);
  const directory = mkdtempSync(join(tmpdir(), 'secret-guard-custom-vectors-'));
  try {
    for (const [path, source] of files) {
      if (!path.startsWith(`${ROOT}/packages/core/src/`)) continue;
      const relative = path.slice(`${ROOT}/`.length).replace(/\.ts$/, '.js');
      const code = transpile(source, path);
      for (const specifier of importSpecifiers(code, path)) {
        const resolved = posix.normalize(posix.join(posix.dirname(relative), specifier));
        if (!/^\.\.?\/[A-Za-z0-9_/.-]+\.js$/.test(specifier) || !resolved.startsWith('packages/core/src/')) {
          throw new UpstreamError(`import inattendu dans le moteur : ${path} → ${specifier}`);
        }
      }
      writeModule(directory, relative, code);
    }
    const fixture = `${ROOT}/contracts/fixtures/rules-pack-vectors.json`;
    writeModule(directory, 'contracts/fixtures/rules-pack-vectors.json', files.get(fixture) ?? '');
    for (const testFile of CUSTOM_TEST_FILES) {
      const path = `${ROOT}/tests/core/${testFile}`;
      const code = transpile(files.get(path) ?? '', path);
      const rewritten = rewriteImports(code, moduleImports(code, path), (specifier) => {
        const target = TEST_IMPORTS[specifier];
        if (target === undefined) throw new UpstreamError(`import inattendu dans ${testFile} : ${specifier}`);
        return target;
      });
      writeModule(directory, `tests/core/${testFile.replace(/\.ts$/, '.js')}`, rewritten);
    }
    // Script du plus grand Pack : JavaScript tel quel ; son seul import (le moteur) pointe vers le moteur transpilé,
    // sans relevé (ses 20 000 termes ne sont pas des entrées des tests).
    const scriptPath = `${ROOT}/scripts/largest-rules-pack.mjs`;
    const script = files.get(scriptPath) ?? '';
    const scriptImports = moduleImports(script, scriptPath);
    const rewrittenScript = rewriteImports(script, scriptImports, (specifier) => {
      if (specifier !== '@xsom/secret-guard-core') throw new UpstreamError(`import inattendu dans le script : ${specifier}`);
      return '../packages/core/src/index.js';
    });
    writeModule(directory, 'harness/largest-rules-pack.js', rewrittenScript);
    return {
      directory,
      file: (path) => {
        const content = files.get(path);
        if (content === undefined) throw new UpstreamError(`fichier non lu : ${path}`);
        return content;
      },
      dispose: () => {
        rmSync(directory, { recursive: true, force: true });
      },
    };
  } catch (error) {
    rmSync(directory, { recursive: true, force: true });
    throw error;
  }
}

/** Charge un module de la copie transpilée. */
export async function loadModule(directory: string, relative: string): Promise<Readonly<Record<string, unknown>>> {
  const module: unknown = await import(pathToFileURL(join(directory, relative)).href);
  if (typeof module !== 'object' || module === null) throw new UpstreamError(`module hors forme : ${relative}`);
  return module as Readonly<Record<string, unknown>>;
}
