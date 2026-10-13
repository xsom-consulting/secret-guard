/**
 * Résultats attendus du masquage, à partir du moteur d'origine (fonctions injectées) : `redact` et `redactAndRescan`
 * de Secret Guard travaillent sur une chaîne UTF-16, le moteur Go sur des octets. Le générateur reconstruit chaque
 * texte masqué de Secret Guard à partir des étendues fusionnées (`mergeSpans`, copie de `redact`) et exige l'égalité
 * avec le texte rendu par l'origine ; il écrit alors le texte attendu du moteur Go : les octets d'origine hors des
 * étendues (un octet hors UTF-8 reste tel quel, là où Secret Guard a lu U+FFFD), un libellé à la place de chaque
 * étendue. Tout écart : arrêt, rien n'est écrit.
 */
import { createHash } from 'node:crypto';
import { byteOffsetOf, decodeInput, type DecodedInput } from '../corpus/bytes.ts';
import { expectedFor } from '../corpus/corpus.ts';
import { jsonString } from '../corpus/json.ts';
import type { CorpusExpected, CorpusFinding } from '../corpus/model.ts';
import type { EngineResult, UpstreamEngine } from '../corpus/upstream.ts';
import {
  DECISIONS,
  INLINE_TEXT_MAX_BYTES,
  LEVELS,
  SCORE_RANGE,
  type DecisionVectors,
  type RedactCase,
  type RedactExpected,
  type RedactedText,
  type RedactVectors,
  type SanitizeFailure,
  type SpanCase,
  type SpanFinding,
} from './model.ts';

export class RedactVectorError extends Error {
  override readonly name = 'RedactVectorError';
}

/** Constat passé à `redact` : identité, score et étendue en unités UTF-16. */
export interface Utf16Finding {
  readonly ruleId: string;
  readonly score: number;
  readonly start: number;
  readonly end: number;
}

/** Ce que le générateur utilise du masquage d'origine. */
export interface RedactEngine {
  /** `redact` de Secret Guard sur des constats construits. */
  redact(content: string, findings: readonly Utf16Finding[]): string;
  /**
   * `redactAndRescan` de Secret Guard : texte rendu, analyses initiale et finale, et texte de `redact` sur les
   * constats initiaux tels que le moteur les a rendus (absent si l'analyse initiale est incomplète).
   */
  redactAndRescan(
    content: string,
    languageId: string | undefined,
  ): { readonly content: string; readonly initial: EngineResult; readonly final: EngineResult; readonly redacted?: string };
}

/** Fonctions de `risk.ts` de Secret Guard. */
export interface RiskEngine {
  levelForScore(score: number): string;
  decisionForLevel(level: string): string;
  boundedScore(score: number): number;
}

/** Position UTF-16 d'une position en octets, qui doit tomber au début d'un caractère du texte décodé. */
export function utf16OffsetOf(decoded: DecodedInput, byteOffset: number): number {
  for (let index = 0; index < decoded.byteOffsets.length; index += 1) {
    if (decoded.byteOffsets[index] === byteOffset) return index;
  }
  throw new RangeError(`position en octets hors d’un début de caractère : ${String(byteOffset)}`);
}

/** Nom du libellé d'un constat de règle intégrée (`placeholderName` de Secret Guard, sans `u` : unité UTF-16). */
export function placeholderName(ruleId: string): string {
  return ruleId.replace(/[^A-Za-z0-9_]/g, '_');
}

/** Étendue fusionnée et nom de son libellé. */
export interface MergedSpan {
  readonly start: number;
  readonly end: number;
  readonly name: string;
}

/**
 * Copie de la fusion de `redact` (Secret Guard) : étendues valides et non vides, triées par début, fin, puis score
 * décroissant (tri stable), fusionnées quand elles se chevauchent ou se touchent ; nom de la première.
 */
export function mergeSpans(findings: readonly Utf16Finding[], length: number): MergedSpan[] {
  const valid = findings
    .filter((f) => Number.isInteger(f.start) && Number.isInteger(f.end) && f.start >= 0 && f.end > f.start && f.end <= length)
    .sort((left, right) => left.start - right.start || left.end - right.end || right.score - left.score);
  const merged: { start: number; end: number; name: string }[] = [];
  for (const finding of valid) {
    const previous = merged.at(-1);
    if (previous !== undefined && finding.start <= previous.end) {
      previous.end = Math.max(previous.end, finding.end);
      continue;
    }
    merged.push({ start: finding.start, end: finding.end, name: placeholderName(finding.ruleId) });
  }
  return merged;
}

const label = (name: string): string => `<REDACTED_${name}>`;

/** Texte de Secret Guard reconstruit à partir des étendues fusionnées. */
export function rebuildText(text: string, spans: readonly MergedSpan[]): string {
  let out = '';
  let cursor = 0;
  for (const span of spans) {
    out += text.slice(cursor, span.start) + label(span.name);
    cursor = span.end;
  }
  return out + text.slice(cursor);
}

/** Texte attendu du moteur Go : octets d'origine hors des étendues, libellé à la place de chaque étendue. */
export function rebuildBytes(bytes: Uint8Array, decoded: DecodedInput, spans: readonly MergedSpan[]): Uint8Array {
  const parts: Uint8Array[] = [];
  let cursor = 0;
  for (const span of spans) {
    const start = byteOffsetOf(decoded, span.start);
    const end = byteOffsetOf(decoded, span.end);
    parts.push(bytes.subarray(cursor, start), new TextEncoder().encode(label(span.name)));
    cursor = end;
  }
  parts.push(bytes.subarray(cursor));
  return Uint8Array.from(Buffer.concat(parts));
}

/** Taille, SHA-256 et, s'il est court, texte (UTF-8 valide) ou octets en base64. */
export function describeText(bytes: Uint8Array): RedactedText {
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  if (bytes.length > INLINE_TEXT_MAX_BYTES) return { bytes: bytes.length, sha256 };
  const decoded = decodeInput(bytes);
  return decoded.validUtf8
    ? { bytes: bytes.length, sha256, text: decoded.text, textEncoding: 'utf8' }
    : { bytes: bytes.length, sha256, text: Buffer.from(bytes).toString('base64'), textEncoding: 'base64' };
}

/** Texte masqué par `redact` d'origine, vérifié par reconstruction, dans la forme du moteur Go. */
function redactedBytes(bytes: Uint8Array, decoded: DecodedInput, findings: readonly Utf16Finding[], upstream: string): Uint8Array {
  const spans = mergeSpans(findings, decoded.text.length);
  if (rebuildText(decoded.text, spans) !== upstream) throw new RedactVectorError('texte de redact différent de sa reconstruction');
  const out = rebuildBytes(bytes, decoded, spans);
  if (decodeInput(out).text !== upstream) throw new RedactVectorError('octets masqués différents du texte de redact');
  if (decoded.validUtf8 && !Buffer.from(out).equals(Buffer.from(new TextEncoder().encode(upstream)))) {
    throw new RedactVectorError('octets masqués différents de l’UTF-8 du texte de redact');
  }
  return out;
}

/** Cas de `redact` seul : constats construits en octets, convertis en unités UTF-16 pour l'origine. */
export function spanCaseOf(engine: RedactEngine, id: string, bytes: Uint8Array, findings: readonly SpanFinding[]): SpanCase {
  const decoded = decodeInput(bytes);
  const utf16 = findings.map(
    (f): Utf16Finding => ({ ruleId: f.ruleId, score: f.score, start: utf16OffsetOf(decoded, f.byteStart), end: utf16OffsetOf(decoded, f.byteEnd) }),
  );
  const out = redactedBytes(bytes, decoded, utf16, engine.redact(decoded.text, utf16));
  return {
    id,
    content: decoded.validUtf8 ? decoded.text : Buffer.from(bytes).toString('base64'),
    contentEncoding: decoded.validUtf8 ? 'utf8' : 'base64',
    findings,
    redacted: describeText(out),
  };
}

function sameOutcome(expected: CorpusExpected, upstream: EngineResult): boolean {
  return expected.complete === upstream.complete && (expected.complete ? expected.findings.length === upstream.findings.length : true);
}

/**
 * Résultat attendu de `redactAndRescan` sur des octets : analyse initiale (comme le corpus de parité), texte de
 * `redact`, analyse finale du texte masqué dans la forme du moteur Go, issue. L'issue `residual` vaut pour tout
 * constat final : Secret Guard rend le texte quand la décision finale est ALLOW (constats LOW seulement), ses
 * appelants exigent zéro constat ; le moteur Go aussi (UPSTREAM.md). Le générateur s'arrête sur un tel cas.
 */
export function redactExpectedFor(
  scanEngine: UpstreamEngine,
  engine: RedactEngine,
  bytes: Uint8Array,
  languageId: string | undefined,
): { readonly expected: Required<Pick<RedactExpected, 'initial'>> & RedactExpected; readonly redacted: Uint8Array | null } {
  const decoded = decodeInput(bytes);
  const initial = expectedFor(scanEngine, bytes, languageId);
  const upstream = engine.redactAndRescan(decoded.text, languageId);
  if (!sameOutcome(initial, upstream.initial)) throw new RedactVectorError('analyse initiale de redactAndRescan différente de scan');
  if (!initial.complete) {
    if (upstream.content !== '' || upstream.redacted !== undefined) throw new RedactVectorError('texte rendu après une analyse incomplète');
    return { expected: { failure: 'incomplete', initial, redacted: null, final: null }, redacted: null };
  }
  if (upstream.redacted === undefined) throw new RedactVectorError('texte de redact absent');
  const findings = upstream.initial.findings.map((f): Utf16Finding => ({ ruleId: f.ruleId, score: f.score, start: f.start, end: f.end }));
  const out = redactedBytes(bytes, decoded, findings, upstream.redacted);
  const final = expectedFor(scanEngine, out, languageId);
  if (!sameOutcome(final, upstream.final)) throw new RedactVectorError('analyse finale différente de la nouvelle analyse du texte masqué');
  const failure: SanitizeFailure = !final.complete ? 'incomplete' : final.findings.length > 0 ? 'residual' : 'none';
  if (failure === 'none' ? upstream.content !== upstream.redacted : upstream.content !== '') {
    throw new RedactVectorError(`texte rendu par redactAndRescan inattendu pour l’issue ${failure} (constats LOW : voir UPSTREAM.md)`);
  }
  return { expected: { failure, initial, redacted: describeText(out), final }, redacted: out };
}

/** Vecteurs des niveaux et décisions, depuis `risk.ts` d'origine. */
export function decisionVectors(engine: RiskEngine, upstreamCommit: string): DecisionVectors {
  const scores = [];
  for (let score = SCORE_RANGE.from; score <= SCORE_RANGE.to; score += 1) {
    const level = engine.levelForScore(score);
    const bounded = engine.boundedScore(score);
    if (!(LEVELS as readonly string[]).includes(level) || !Number.isInteger(bounded)) {
      throw new RedactVectorError(`niveau ou score borné hors forme : ${String(score)}`);
    }
    scores.push({ score, bounded, level });
  }
  const levels = LEVELS.map((level) => {
    const decision = engine.decisionForLevel(level);
    if (!(DECISIONS as readonly string[]).includes(decision)) throw new RedactVectorError(`décision hors forme : ${level}`);
    return { level, decision };
  });
  return { formatVersion: 1, upstreamCommit, scores, levels };
}

// Écriture déterministe : une entrée par ligne, champs dans un ordre fixe, fin de ligne `\n`.

function corpusFinding(value: CorpusFinding): string {
  return (
    `{"ruleId":${jsonString(value.ruleId)},"secretType":${jsonString(value.secretType)},` +
    `"encoding":${jsonString(value.encoding)},"score":${String(value.score)},"level":${jsonString(value.level)},` +
    `"byteStart":${String(value.byteStart)},"byteEnd":${String(value.byteEnd)}}`
  );
}

function scanExpected(value: CorpusExpected | null): string {
  if (value === null) return 'null';
  return (
    `{"complete":${String(value.complete)},"failure":${jsonString(value.failure)},` +
    `"findings":[${value.findings.map(corpusFinding).join(',')}]}`
  );
}

function redactedText(value: RedactedText | null): string {
  if (value === null) return 'null';
  const text = value.text === undefined ? '' : `,"text":${jsonString(value.text)},"textEncoding":${jsonString(value.textEncoding ?? 'utf8')}`;
  return `{"bytes":${String(value.bytes)},"sha256":${jsonString(value.sha256)}${text}}`;
}

function spanCase(value: SpanCase): string {
  const findings = value.findings.map(
    (f) =>
      `{"ruleId":${jsonString(f.ruleId)},"score":${String(f.score)},"byteStart":${String(f.byteStart)},"byteEnd":${String(f.byteEnd)}}`,
  );
  return (
    `{"id":${jsonString(value.id)},"content":${jsonString(value.content)},"contentEncoding":${jsonString(value.contentEncoding)},` +
    `"findings":[${findings.join(',')}],"redacted":${redactedText(value.redacted)}}`
  );
}

function redactCase(value: RedactCase): string {
  const source =
    value.corpusFile !== undefined
      ? `"corpusFile":${jsonString(value.corpusFile)},`
      : `"input":${jsonString(value.input ?? '')},"inputEncoding":${jsonString(value.inputEncoding ?? 'utf8')},` +
        (value.repeat === undefined ? '' : `"repeat":{"text":${jsonString(value.repeat.text)},"count":${String(value.repeat.count)}},`) +
        (value.languageId === undefined ? '' : `"languageId":${jsonString(value.languageId)},`);
  const initial = value.expected.initial === undefined ? '' : `"initial":${scanExpected(value.expected.initial)},`;
  return (
    `{"id":${jsonString(value.id)},${source}"expected":{"failure":${jsonString(value.expected.failure)},${initial}` +
    `"redacted":${redactedText(value.expected.redacted)},"final":${scanExpected(value.expected.final)}}}`
  );
}

const lines = (items: readonly string[]): string => (items.length === 0 ? '[]' : `[\n${items.join(',\n')}\n]`);

/** Fichier `vectors/redact.json`. */
export function serializeRedactVectors(vectors: RedactVectors): string {
  return (
    `{"formatVersion":${String(vectors.formatVersion)},"upstreamCommit":${jsonString(vectors.upstreamCommit)},\n` +
    `"spanCases":${lines(vectors.spanCases.map(spanCase))},\n` +
    `"cases":${lines(vectors.cases.map(redactCase))}\n}\n`
  );
}

/** Fichier `vectors/decision.json`. */
export function serializeDecisionVectors(vectors: DecisionVectors): string {
  const scores = vectors.scores.map(
    (s) => `{"score":${String(s.score)},"bounded":${String(s.bounded)},"level":${jsonString(s.level)}}`,
  );
  const levels = vectors.levels.map((l) => `{"level":${jsonString(l.level)},"decision":${jsonString(l.decision)}}`);
  return (
    `{"formatVersion":${String(vectors.formatVersion)},"upstreamCommit":${jsonString(vectors.upstreamCommit)},\n` +
    `"scores":${lines(scores)},\n"levels":${lines(levels)}\n}\n`
  );
}
