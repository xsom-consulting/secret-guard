/**
 * Vecteurs de parité du Pack de règles du client (`vectors/custom/`) : forme des cas, résultat attendu calculé par
 * le moteur d'origine (positions UTF-16 → octets), écriture déterministe (un cas par ligne). Lus tels quels par les
 * tests Go `TestCustomPackParity`, `TestCustomPatternParity`, `TestCustomTermsParity`, `TestCustomUnicodeParity`
 * (paquet custom) et `TestCustomScanParity` (paquet detect).
 */
import { byteOffsetOf, decodeInput, utf8Bytes } from '../corpus/bytes.ts';
import { jsonString } from '../corpus/json.ts';
import { compareFindings, levelForScore, type CorpusFinding } from '../corpus/model.ts';
import { describeText } from '../redact/vectors.ts';
import type { RedactedText } from '../redact/model.ts';
import { readScanResult, type CompiledPackLike, type CustomEngine, type EngineResult } from './engine.ts';

export class VectorError extends Error {
  override readonly name = 'VectorError';
}

/** Version du format des vecteurs, inscrite dans `manifest.json`. */
export const CUSTOM_FORMAT_VERSION = 1;

/** Fichiers de cas, dans l'ordre du manifeste. */
export const CUSTOM_FILES = [
  'detection.json',
  'packs.json',
  'pattern-matching.json',
  'pattern-validation.json',
  'redact.json',
  'scan.json',
  'terms.json',
  'unicode.json',
] as const;
export type CustomFile = (typeof CUSTOM_FILES)[number];

/** Issues d'une analyse avec un Pack de règles du client. */
export const CUSTOM_SCAN_FAILURES = ['none', 'scan_limit', 'scan_error', 'custom_budget', 'custom_too_many'] as const;
export type CustomScanFailure = (typeof CUSTOM_SCAN_FAILURES)[number];

/** Constat d'échec de l'origine → issue (`FAILURES` de scanner.ts). */
const FAILURE_OF_RULE: Readonly<Record<string, CustomScanFailure>> = {
  input_too_large: 'scan_limit',
  scanner_failure: 'scan_error',
  custom_rules_incomplete: 'custom_budget',
  custom_rules_too_many_findings: 'custom_too_many',
};

/** Écriture d'une entrée : texte UTF-8 valide, suite de répétitions (`runs`, longue entrée périodique), ou base64. */
export interface EncodedInput {
  readonly input: string | readonly (readonly [string, number])[];
  readonly inputEncoding: 'utf8' | 'base64' | 'runs';
}

/** Taille à partir de laquelle une entrée périodique s'écrit en répétitions. */
const RUNS_THRESHOLD = 65_536;

/**
 * Entrée périodique : préfixe, motif de 1 à 64 unités répété, reste. Rend `undefined` si la partie périodique est
 * trop courte ou si le découpage ne rend pas exactement les octets (paire de substitution coupée).
 */
function periodicRuns(text: string, bytes: Uint8Array): (readonly [string, number])[] | undefined {
  let best: { period: number; start: number } | undefined;
  for (let period = 1; period <= 64 && period < text.length; period += 1) {
    let start = text.length - period;
    while (start > 0 && text.charCodeAt(start - 1) === text.charCodeAt(start - 1 + period)) start -= 1;
    if (best === undefined || start < best.start) best = { period, start };
  }
  if (best === undefined || text.length - best.start < RUNS_THRESHOLD) return undefined;
  const unit = text.slice(best.start, best.start + best.period);
  const count = Math.floor((text.length - best.start) / best.period);
  const runs: (readonly [string, number])[] = [];
  const prefix = text.slice(0, best.start);
  const suffix = text.slice(best.start + count * best.period);
  if (prefix !== '') runs.push([prefix, 1]);
  runs.push([unit, count]);
  if (suffix !== '') runs.push([suffix, 1]);
  const rebuilt = utf8Bytes(runs.map(([part, times]) => part.repeat(times)).join(''));
  return Buffer.from(rebuilt).equals(Buffer.from(bytes)) ? runs : undefined;
}

export function encodeInput(bytes: Uint8Array): EncodedInput {
  const decoded = decodeInput(bytes);
  if (!decoded.validUtf8) return { input: Buffer.from(bytes).toString('base64'), inputEncoding: 'base64' };
  const runs = bytes.length >= RUNS_THRESHOLD ? periodicRuns(decoded.text, bytes) : undefined;
  return runs === undefined ? { input: decoded.text, inputEncoding: 'utf8' } : { input: runs, inputEncoding: 'runs' };
}

/** Valeur JSON écrite avec les chaînes de `jsonString` (caractères invisibles en `\uXXXX`), clés dans l'ordre reçu. */
export function stableJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'string') return jsonString(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new VectorError('nombre non fini');
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .map(([key, entry]) => `${jsonString(key)}:${stableJson(entry)}`)
      .join(',')}}`;
  }
  throw new VectorError(`valeur non JSON : ${typeof value}`);
}

/** Fichier de cas : tableau JSON, un cas par ligne. */
export function serializeCases(cases: readonly unknown[]): string {
  if (cases.length === 0) return '[]\n';
  return `[\n${cases.map(stableJson).join(',\n')}\n]\n`;
}

// --- Résultats attendus -------------------------------------------------------------------------------------------

/** Étendues [début, fin) en octets des positions UTF-16 d'un texte décodé. */
function byteSpans(bytes: Uint8Array, spans: readonly { start: number; end: number }[]): [number, number][] {
  const decoded = decodeInput(bytes);
  return spans.map(({ start, end }) => [byteOffsetOf(decoded, start), byteOffsetOf(decoded, end)]);
}

export interface PatternValidationExpected {
  readonly valid: boolean;
  readonly error: string;
}

export function expectedPatternValidation(
  engine: CustomEngine,
  pattern: string,
  hasContext: boolean,
  caseInsensitive: boolean,
): PatternValidationExpected {
  const result = engine.validatePattern(pattern, hasContext, caseInsensitive);
  return result.ok ? { valid: true, error: '' } : { valid: false, error: result.error };
}

/** Travail admis pour le résultat de référence d'un motif (au-delà : pas de résultat de référence en temps borné). */
const REFERENCE_WORK = 200_000_000;

/**
 * Correspondances d'un motif sur tout le texte (matchAll d'ECMAScript), par l'automate compté de l'origine ; si la
 * borne statique d'un essai est petite, aussi par la RegExp de V8, qui doit donner le même résultat. `undefined` si
 * l'automate dépasse REFERENCE_WORK (motif pathologique : aucun résultat de référence en temps borné).
 */
export function expectedPatternMatches(
  engine: CustomEngine,
  pattern: string,
  caseInsensitive: boolean,
  bytes: Uint8Array,
): [number, number][] | undefined {
  const validation = engine.validatePattern(pattern, true, caseInsensitive);
  if (!validation.ok) throw new VectorError('motif invalide dans un cas de correspondances');
  const text = decodeInput(bytes).text;
  const meter = engine.newMeter(REFERENCE_WORK);
  const matches: { start: number; end: number }[] = [];
  try {
    for (let position = 0; position < text.length; ) {
      const end = validation.pattern.matchAt(text, position, meter);
      if (end < 0) position += 1;
      else {
        matches.push({ start: position, end });
        position = end;
      }
    }
  } catch (error) {
    if (engine.isBudgetError(error)) return undefined;
    throw error;
  }
  if (validation.pattern.attemptBound <= 4_096) {
    const native = validation.pattern.nativeMatches(text);
    if (JSON.stringify(native) !== JSON.stringify(matches)) throw new VectorError(`automate et RegExp en désaccord : ${pattern}`);
  }
  return byteSpans(bytes, matches);
}

export interface PackExpected {
  readonly valid: boolean;
  readonly error: string;
}

/**
 * Validité d'un Pack (octets du document). `undefined` si JSON.parse refuse le texte : l'origine reçoit une valeur
 * déjà lue, ce refus est celui de son appelant.
 */
export function expectedPack(engine: CustomEngine, bytes: Uint8Array): PackExpected | undefined {
  let value: unknown;
  try {
    value = JSON.parse(decodeInput(bytes).text);
  } catch {
    return undefined;
  }
  const result = engine.compileRulesPack(value);
  return result.ok ? { valid: true, error: '' } : { valid: false, error: result.error };
}

/** Détections par détecteur `[index, début, fin]` d'un Pack construit à la main (sans essais), ou `undefined`. */
export function expectedDetection(
  engine: CustomEngine,
  detectorsJson: string,
  bytes: Uint8Array,
): [number, number, number][] | undefined {
  const specs = JSON.parse(detectorsJson) as unknown[];
  const compiled = specs.map((spec) => {
    const detector = engine.compileDetector(spec);
    if (detector === undefined) throw new VectorError('détecteur invalide dans un cas de détection');
    return detector;
  });
  const pack = engine.newPack({ detectors: specs }, compiled);
  const text = decodeInput(bytes).text;
  let results: { start: number; end: number }[][];
  try {
    results = pack.detect(text, engine.newMeter(REFERENCE_WORK));
  } catch (error) {
    if (engine.isBudgetError(error)) return undefined;
    throw error;
  }
  const out: [number, number, number][] = [];
  results.forEach((matches, index) => {
    for (const [start, end] of byteSpans(bytes, matches)) out.push([index, start, end]);
  });
  return out;
}

export interface ScanExpected {
  readonly complete: boolean;
  readonly failure: CustomScanFailure;
  readonly findings: readonly CorpusFinding[];
}

/** Résultat d'une analyse, constats en octets triés par `(byteStart, ruleId, byteEnd)`. */
export function scanExpectedOf(result: EngineResult, bytes: Uint8Array): ScanExpected {
  if (!result.complete) {
    const [failure] = result.findings;
    const kind = failure === undefined ? undefined : FAILURE_OF_RULE[failure.ruleId];
    if (result.findings.length !== 1 || kind === undefined) throw new VectorError('analyse incomplète sans constat d’échec unique');
    return { complete: false, failure: kind, findings: [] };
  }
  const decoded = decodeInput(bytes);
  const findings = result.findings.map((finding): CorpusFinding => {
    if (finding.ruleId in FAILURE_OF_RULE) throw new VectorError('analyse complète avec un constat d’échec');
    if (finding.level !== levelForScore(finding.score)) throw new VectorError(`niveau incohérent : ${finding.ruleId}`);
    return {
      ruleId: finding.ruleId,
      secretType: finding.secretType,
      encoding: finding.encoding as CorpusFinding['encoding'],
      score: finding.score,
      level: levelForScore(finding.score),
      byteStart: byteOffsetOf(decoded, finding.start),
      byteEnd: byteOffsetOf(decoded, finding.end),
    };
  });
  return { complete: true, failure: 'none', findings: findings.sort(compareFindings) };
}

export interface TermExpected {
  readonly normalized: string;
  readonly digest: string;
}

export function expectedTerm(engine: CustomEngine, term: string, salt: string): TermExpected {
  const normalized = engine.normalizeTerm(term);
  return { normalized, digest: salt === '' ? '' : engine.termDigest(engine.decodeSalt(salt), normalized) };
}

/** Issue d'un masquage suivi d'une nouvelle analyse, dans la forme du moteur Go (`detect.SanitizeFailure`). */
export type RedactFailure = 'none' | 'incomplete' | 'residual';

export interface RedactExpectedCustom {
  readonly failure: RedactFailure;
  /** Vrai si le texte rendu (ou jugé) est celui des libellés neutres (`neutralCustomNames`). */
  readonly neutral: boolean;
  readonly redacted: RedactedText | null;
}

function sanitizeFailureOf(result: EngineResult): RedactFailure {
  if (!result.complete) return 'incomplete';
  return result.findings.length > 0 ? 'residual' : 'none';
}

/**
 * Masquage avec un Pack de règles du client, dans la forme du moteur Go (`detect.RedactAndRescan`) : analyse,
 * `redact` d'origine avec les libellés des détecteurs, nouvelle analyse ; si elle échoue et que l'entrée a des constats
 * du Pack, `redact` avec des libellés neutres puis une nouvelle analyse. Tout constat restant fait échouer le masquage
 * (le moteur d'origine rend le texte quand il ne reste que des constats LOW : un tel cas arrête le générateur). Le
 * texte rendu est comparé à celui de `redactAndRescan` d'origine. Entrées UTF-8 valides seulement.
 */
export function expectedRedaction(engine: CustomEngine, bytes: Uint8Array, rules: CompiledPackLike): RedactExpectedCustom {
  const decoded = decodeInput(bytes);
  if (!decoded.validUtf8) throw new VectorError('masquage : entrée hors UTF-8');
  const text = decoded.text;
  const raw = engine.rawScan(text, rules);
  const initial = readScanResult(raw);
  const upstream = engine.redactAndRescan(text, rules);
  if (!initial.complete) {
    if (upstream !== '') throw new VectorError('texte rendu après une analyse incomplète');
    return { failure: 'incomplete', neutral: false, redacted: null };
  }
  if (initial.findings.length === 0) {
    if (upstream !== text) throw new VectorError('texte sans constat non rendu tel quel');
    return { failure: 'none', neutral: false, redacted: describeText(bytes) };
  }
  let neutral = false;
  let out = engine.redact(text, raw, false);
  let failure = sanitizeFailureOf(engine.scan(out, rules));
  const hasCustom = initial.findings.some((finding) => finding.secretType === 'custom_rule');
  if (failure !== 'none' && hasCustom) {
    neutral = true;
    out = engine.redact(text, raw, true);
    failure = sanitizeFailureOf(engine.scan(out, rules));
  }
  if (failure === 'none' ? upstream !== out : upstream !== '') {
    throw new VectorError(`texte rendu par redactAndRescan inattendu pour l’issue ${failure} (constats LOW)`);
  }
  return { failure, neutral, redacted: failure === 'none' ? describeText(utf8Bytes(out)) : null };
}

export { utf8Bytes };
