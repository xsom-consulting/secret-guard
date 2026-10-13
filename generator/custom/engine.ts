/**
 * Ce que le générateur utilise du moteur d'origine transpilé pour les règles du client, typé et lu sans lui faire
 * confiance (toute forme inattendue arrête le générateur).
 */
import { loadModule, UpstreamError } from './upstream.ts';

/** Motif validé : sa source ECMAScript, ses drapeaux, sa borne statique de travail et son interpréteur. */
export interface SafePatternLike {
  readonly source: string;
  readonly flags: string;
  readonly attemptBound: number;
  matchAt(text: string, start: number, meter: WorkMeterLike): number;
  nativeMatches(text: string): { start: number; end: number }[];
}

export interface WorkMeterLike {
  readonly used: number;
}

export type PatternValidation = { readonly ok: true; readonly pattern: SafePatternLike } | { readonly ok: false; readonly error: string };

export interface CompiledPackLike {
  readonly payload: { readonly detectors: readonly unknown[] };
  readonly detectors: readonly { readonly spec: unknown }[];
  detect(text: string, meter: WorkMeterLike, only?: ReadonlySet<number>, maxMatches?: number): { start: number; end: number }[][];
}

export type PackCompilation = { readonly ok: true; readonly pack: CompiledPackLike } | { readonly ok: false; readonly error: string };

/** Finding d'origine, réduit aux champs des vecteurs (positions UTF-16). */
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

export interface CustomEngine {
  validatePattern(source: string, hasContext: boolean, caseInsensitive: boolean): PatternValidation;
  compileRulesPack(payload: unknown): PackCompilation;
  compileDetector(spec: unknown): unknown;
  newPack(payload: unknown, detectors: readonly unknown[]): CompiledPackLike;
  scan(content: string, rules: CompiledPackLike | undefined, meter?: WorkMeterLike): EngineResult;
  normalizeTerm(term: string): string;
  normalizeWord(word: string): string;
  termDigest(salt: Uint8Array, normalized: string): string;
  decodeSalt(salt: string): Uint8Array;
  newMeter(limit: number): WorkMeterLike;
  isBudgetError(error: unknown): boolean;
  readonly customWorkBudget: number;
  readonly selfTestWorkBudget: number;
}

function field<T>(module: Readonly<Record<string, unknown>>, key: string, kind: string): T {
  const value = module[key];
  if (typeof value !== kind) throw new UpstreamError(`export absent du moteur : ${key}`);
  return value as T;
}

type Fn = (...args: unknown[]) => unknown;
type Ctor = new (...args: unknown[]) => unknown;

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === 'object' && value !== null;
}

/** Lit un `ScanResult` d'origine. */
export function readScanResult(value: unknown): EngineResult {
  if (!isRecord(value) || typeof value['complete'] !== 'boolean' || !Array.isArray(value['findings'])) {
    throw new UpstreamError('résultat du moteur hors forme');
  }
  const findings = (value['findings'] as readonly unknown[]).map((item): EngineFinding => {
    if (!isRecord(item) || !isRecord(item['span'])) throw new UpstreamError('constat du moteur hors forme');
    const span = item['span'];
    const start = isRecord(span['start']) ? span['start']['offset'] : undefined;
    const end = isRecord(span['end']) ? span['end']['offset'] : undefined;
    const text = (key: string): string => {
      const v = item[key];
      if (typeof v !== 'string') throw new UpstreamError(`constat hors forme : ${key}`);
      return v;
    };
    const score = item['score'];
    if (typeof start !== 'number' || typeof end !== 'number' || typeof score !== 'number') {
      throw new UpstreamError('constat hors forme');
    }
    return {
      ruleId: text('ruleId'),
      secretType: text('secretType'),
      encoding: text('encoding'),
      score,
      level: text('level'),
      start,
      end,
    };
  });
  return { complete: value['complete'], findings };
}

/** Moteur typé à partir de la copie transpilée. */
export async function loadCustomEngine(directory: string): Promise<CustomEngine> {
  const index = await loadModule(directory, 'packages/core/src/index.js');
  const pack = await loadModule(directory, 'packages/core/src/custom/pack.js');
  const terms = await loadModule(directory, 'packages/core/src/custom/terms.js');
  const work = await loadModule(directory, 'packages/core/src/custom/work.js');
  const validatePattern = field<Fn>(index, 'validatePattern', 'function');
  const compileRulesPack = field<Fn>(index, 'compileRulesPack', 'function');
  const scan = field<Fn>(index, 'scan', 'function');
  const normalizeTerm = field<Fn>(index, 'normalizeTerm', 'function');
  const termDigest = field<Fn>(index, 'termDigest', 'function');
  const compileDetector = field<Fn>(pack, 'compileDetector', 'function');
  const CompiledRulesPack = field<Ctor>(pack, 'CompiledRulesPack', 'function');
  const decodeBase64 = field<Fn>(terms, 'decodeBase64', 'function');
  const normalizeWord = field<Fn>(terms, 'normalizeWord', 'function');
  const WorkMeter = field<Ctor>(work, 'WorkMeter', 'function');
  const WorkBudgetExceeded = field<Ctor>(work, 'WorkBudgetExceeded', 'function');
  const customWorkBudget = field<number>(index, 'CUSTOM_RULES_WORK_BUDGET', 'number');
  const selfTestWorkBudget = field<number>(index, 'SELF_TEST_WORK_BUDGET', 'number');
  return {
    validatePattern: (source, hasContext, caseInsensitive) =>
      validatePattern(source, hasContext, caseInsensitive) as PatternValidation,
    compileRulesPack: (payload) => compileRulesPack(payload) as PackCompilation,
    compileDetector: (spec) => compileDetector(spec),
    newPack: (payload, detectors) => new CompiledRulesPack(payload, detectors) as CompiledPackLike,
    scan: (content, rules, meter) =>
      readScanResult(
        scan(rules === undefined ? { content } : meter === undefined ? { content, rules } : { content, rules, workMeter: meter }),
      ),
    normalizeTerm: (term) => {
      const out = normalizeTerm(term);
      if (typeof out !== 'string') throw new UpstreamError('normalizeTerm hors forme');
      return out;
    },
    normalizeWord: (word) => {
      const out = normalizeWord(word);
      if (typeof out !== 'string') throw new UpstreamError('normalizeWord hors forme');
      return out;
    },
    termDigest: (salt, normalized) => {
      const out = termDigest(salt, normalized);
      if (typeof out !== 'string') throw new UpstreamError('termDigest hors forme');
      return out;
    },
    decodeSalt: (salt) => {
      const out = decodeBase64(salt);
      if (!(out instanceof Uint8Array)) throw new UpstreamError('decodeBase64 hors forme');
      return out;
    },
    newMeter: (limit) => new WorkMeter(limit) as WorkMeterLike,
    isBudgetError: (error) => error instanceof WorkBudgetExceeded,
    customWorkBudget,
    selfTestWorkBudget,
  };
}
