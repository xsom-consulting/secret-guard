/**
 * `npm run vectors:redact -- --upstream <checkout>` (dans `generator/`) : écrit `vectors/redact.json` (masquage) et
 * `vectors/decision.json` (niveaux et décisions) avec le moteur TypeScript de Secret Guard (`redact`,
 * `redactAndRescan`, `levelForScore`, `boundedScore`, `decisionForLevel`). `--check` régénère en mémoire et compare
 * octet pour octet, sans rien écrire. Même checkout, même commit et même transpilation que le corpus de parité
 * (`corpus/upstream.ts`, SHA-256 de chaque fichier vérifié).
 *
 * Cas : chaque cas du corpus de parité commité (`vectors/detection/`) dont l'analyse a au moins un constat ou est
 * incomplète, par renvoi (son entrée n'est pas recopiée), puis les cas synthétiques (`cases.ts`). Tout contrôle en
 * échec : sortie 1, rien n'est écrit.
 */
import { readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { decodeInput } from '../corpus/bytes.ts';
import { testImport } from '../corpus/harness.ts';
import { MANIFEST_FILE, type CorpusCase } from '../corpus/model.ts';
import { readScanResult, transpileUpstream, UPSTREAM_COMMIT, UpstreamError } from '../corpus/upstream.ts';
import { intentProblem, redactSources, spanSources } from './cases.ts';
import { DECISION_FILE, REDACT_FILE, REDACT_FORMAT_VERSION, type RedactCase, type RedactVectors } from './model.ts';
import {
  decisionVectors,
  redactExpectedFor,
  serializeDecisionVectors,
  serializeRedactVectors,
  spanCaseOf,
  type RedactEngine,
  type RiskEngine,
  type Utf16Finding,
} from './vectors.ts';

const VECTORS = fileURLToPath(new URL('../../vectors/', import.meta.url));
const CORPUS = join(VECTORS, 'detection');

type Fn = (...args: unknown[]) => unknown;

function functionOf(module: unknown, key: string): Fn {
  const field = typeof module === 'object' && module !== null ? (module as Record<string, unknown>)[key] : undefined;
  if (typeof field !== 'function') throw new UpstreamError(`export absent du moteur : ${key}`);
  return field as Fn;
}

/** Constat de Secret Guard construit pour `redact` (seuls l'étendue, le score et la règle comptent). */
function upstreamFinding(f: Utf16Finding): unknown {
  const position = (offset: number): unknown => ({ offset, line: 1, column: offset + 1 });
  return {
    ruleId: f.ruleId,
    secretType: 'generic_secret',
    span: { start: position(f.start), end: position(f.end) },
    score: f.score,
    level: 'HIGH',
    reasons: [],
    encoding: 'plain',
  };
}

/** Masquage d'origine, à partir du module `index.js` transpilé. */
export function redactEngineOf(module: unknown): RedactEngine {
  const redact = functionOf(module, 'redact');
  const redactAndRescan = functionOf(module, 'redactAndRescan');
  const text = (value: unknown): string => {
    if (typeof value !== 'string') throw new UpstreamError('texte du masquage hors forme');
    return value;
  };
  return {
    redact: (content, findings) => text(redact(content, findings.map(upstreamFinding))),
    redactAndRescan: (content, languageId) => {
      const result = redactAndRescan(languageId === undefined ? { content } : { content, languageId }) as Record<string, unknown>;
      const initial = readScanResult(result['initial']);
      const raw = (result['initial'] as Record<string, unknown>)['findings'];
      return {
        content: text(result['content']),
        initial,
        final: readScanResult(result['final']),
        ...(initial.complete ? { redacted: text(redact(content, raw)) } : {}),
      };
    },
  };
}

/** Fonctions de `risk.ts` d'origine. */
export function riskEngineOf(module: unknown): RiskEngine {
  const levelForScore = functionOf(module, 'levelForScore');
  const decisionForLevel = functionOf(module, 'decisionForLevel');
  const boundedScore = functionOf(module, 'boundedScore');
  const text = (value: unknown): string => {
    if (typeof value !== 'string') throw new UpstreamError('niveau ou décision hors forme');
    return value;
  };
  return {
    levelForScore: (score) => text(levelForScore(score)),
    decisionForLevel: (level) => text(decisionForLevel(level)),
    boundedScore: (score) => {
      const value = boundedScore(score);
      if (typeof value !== 'number') throw new UpstreamError('score borné hors forme');
      return value;
    },
  };
}

/** Cas du corpus de parité commité, par fichier du manifeste. */
export function committedCorpus(): { file: string; value: CorpusCase }[] {
  const manifest = JSON.parse(readFileSync(join(CORPUS, MANIFEST_FILE), 'utf8')) as { files: { file: string }[] };
  return manifest.files.flatMap(({ file }) =>
    (JSON.parse(readFileSync(join(CORPUS, file), 'utf8')) as CorpusCase[]).map((value) => ({ file, value })),
  );
}

/** Le cas du corpus est-il repris : au moins un constat, ou analyse incomplète. */
export function corpusCaseSelected(value: CorpusCase): boolean {
  return !value.expected.complete || value.expected.findings.length > 0;
}

export function corpusInput(value: CorpusCase): Uint8Array {
  return value.inputEncoding === 'utf8' ? new TextEncoder().encode(value.input) : Uint8Array.from(Buffer.from(value.input, 'base64'));
}

async function main(): Promise<number> {
  const { values } = parseArgs({
    options: { upstream: { type: 'string' }, check: { type: 'boolean', default: false } },
    strict: true,
    allowPositionals: false,
  });
  if (values.upstream === undefined) {
    process.stderr.write('Usage : vectors:redact --upstream <checkout de poc-AI_guard> [--check]\n');
    return 1;
  }
  const upstream = await transpileUpstream(values.upstream, testImport);
  try {
    const index: unknown = await import(pathToFileURL(join(upstream.directory, 'packages/core/src/index.js')).href);
    const risk: unknown = await import(pathToFileURL(join(upstream.directory, 'packages/core/src/risk.js')).href);
    const engine = redactEngineOf(index);
    const problems: string[] = [];

    const cases: RedactCase[] = [];
    for (const { file, value } of committedCorpus()) {
      if (!corpusCaseSelected(value)) continue;
      const { initial, ...expected } = redactExpectedFor(upstream.engine, engine, corpusInput(value), value.languageId).expected;
      if (JSON.stringify(initial) !== JSON.stringify(value.expected)) problems.push(`${value.id} : analyse initiale différente du corpus`);
      cases.push({ id: value.id, corpusFile: file, expected });
    }
    for (const source of redactSources()) {
      const { expected, redacted } = redactExpectedFor(upstream.engine, engine, source.bytes, source.languageId);
      const problem = intentProblem(source, expected, redacted);
      if (problem !== undefined) problems.push(problem);
      const decoded = decodeInput(source.rest);
      cases.push({
        id: source.id,
        input: decoded.validUtf8 ? decoded.text : Buffer.from(source.rest).toString('base64'),
        inputEncoding: decoded.validUtf8 ? 'utf8' : 'base64',
        ...(source.repeat === undefined ? {} : { repeat: source.repeat }),
        ...(source.languageId === undefined ? {} : { languageId: source.languageId }),
        expected,
      });
    }
    const ids = new Set<string>();
    for (const value of cases) {
      if (ids.has(value.id)) problems.push(`identifiant de cas en double : ${value.id}`);
      ids.add(value.id);
    }
    const spanCases = spanSources().map((source) => spanCaseOf(engine, source.id, source.bytes, source.findings));
    if (problems.length > 0) {
      process.stderr.write(`Vecteurs refusés, rien n’est écrit :\n${problems.map((problem) => `- ${problem}`).join('\n')}\n`);
      return 1;
    }
    const vectors: RedactVectors = { formatVersion: REDACT_FORMAT_VERSION, upstreamCommit: UPSTREAM_COMMIT, spanCases, cases };
    const files = new Map([
      [REDACT_FILE, serializeRedactVectors(vectors)],
      [DECISION_FILE, serializeDecisionVectors(decisionVectors(riskEngineOf(risk), UPSTREAM_COMMIT))],
    ]);
    if (values.check) {
      const differing = [...files].filter(([name, content]) => {
        try {
          return readFileSync(join(VECTORS, name), 'utf8') !== content;
        } catch {
          return true;
        }
      });
      if (differing.length > 0) {
        process.stderr.write(`Vecteurs différents : ${differing.map(([name]) => name).join(', ')}\n`);
        return 1;
      }
      process.stdout.write(`Vecteurs identiques : ${String(cases.length)} cas, ${String(spanCases.length)} cas d’étendues\n`);
      return 0;
    }
    const temporary = (name: string): string => join(VECTORS, `.${name}.tmp-generate`);
    try {
      for (const [name, content] of files) writeFileSync(temporary(name), content);
    } catch (error) {
      for (const name of files.keys()) rmSync(temporary(name), { force: true });
      throw error;
    }
    for (const name of files.keys()) renameSync(temporary(name), join(VECTORS, name));
    process.stdout.write(`Vecteurs du masquage écrits : ${String(cases.length)} cas, ${String(spanCases.length)} cas d’étendues\n`);
    return 0;
  } finally {
    upstream.dispose();
  }
}

if (process.argv[1] !== undefined && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (error: unknown) => {
      process.stderr.write(`Vecteurs refusés : ${error instanceof Error ? error.message : 'erreur inattendue'}\n`);
      process.exitCode = 1;
    },
  );
}
