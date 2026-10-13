/**
 * Résultats attendus des vecteurs de parité, calculés par les fonctions d'origine (`findHidden`, `stripHidden`,
 * `mentionedPaths`), puis convertis pour le portage Go : positions UTF-16 → octets, sortie lue sans lui faire
 * confiance.
 *
 * Octets : chaque entrée est décodée comme Go la parcourt (`../corpus/bytes.ts` : un octet hors UTF-8 vaut U+FFFD, un
 * par octet). La limite de 1 Mio porte en Go sur les octets reçus, à l'origine sur l'UTF-8 du texte décodé : une
 * entrée que les deux mesures classeraient différemment arrête le générateur.
 */
import { createHash } from 'node:crypto';
import { posix } from 'node:path';
import { byteOffsetOf, decodeInput, utf8Bytes, type DecodedInput } from '../corpus/bytes.ts';
import { UpstreamError, type HiddenUpstream, type RegexLiteral } from './upstream.ts';

/** Sortie `stripped` écrite en texte jusqu'à cette taille, au-delà par son SHA-256. */
export const STRIPPED_TEXT_MAX_BYTES = 65_536;

/** Répertoire de travail passé à `mentionedPaths` (résolution POSIX). */
export const MENTION_CWD = '/work';

export const HIDDEN_KINDS = ['tag_characters', 'bidi_controls', 'invisible_characters', 'variation_selectors'] as const;
export type HiddenKind = (typeof HIDDEN_KINDS)[number];

export interface HiddenFindingExpected {
  readonly kind: HiddenKind;
  readonly line: number;
  readonly column: number;
  readonly count: number;
  readonly byteStart: number;
  readonly byteEnd: number;
}

export interface HiddenExpected {
  readonly complete: boolean;
  readonly hidden: number;
  readonly findings: readonly HiddenFindingExpected[];
  /** Sortie de Strip en texte (UTF-8 valide), ou son SHA-256 au-delà de `STRIPPED_TEXT_MAX_BYTES`. */
  readonly stripped?: string;
  readonly strippedSha256?: string;
}

export interface MentionExpected {
  readonly path: string;
  readonly lines?: string;
  readonly byteStart: number;
  readonly byteEnd: number;
}

export interface MentionsExpected {
  readonly mentions: readonly MentionExpected[];
  /** Sortie de `mentionedPaths(prompt, MENTION_CWD)` : chemins résolus, sans doublon. */
  readonly upstream: readonly string[];
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === 'object' && value !== null;
}

function integer(value: unknown, what: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) throw new UpstreamError(`résultat d’origine hors forme : ${what}`);
  return value;
}

/** Point de code k → position UTF-16, et (ligne, colonne) → point de code, comme les compte `findHidden`. */
interface CodePointMap {
  readonly utf16: number[];
  readonly at: Map<string, number>;
}

function codePointMap(text: string): CodePointMap {
  const utf16: number[] = [];
  const at = new Map<string, number>();
  let offset = 0;
  let line = 1;
  let column = 1;
  for (const character of text) {
    at.set(`${String(line)}:${String(column)}`, utf16.length);
    utf16.push(offset);
    offset += character.length;
    if (character === '\n') {
      line += 1;
      column = 1;
    } else column += 1;
  }
  utf16.push(offset);
  return { utf16, at };
}

/** UTF-8 du texte décodé, tel que `findHidden` le mesure (un U+FFFD de remplacement compte trois octets). */
function decodedUtf8Length(decoded: DecodedInput): number {
  return utf8Bytes(decoded.text).length;
}

/** Résultat attendu de Find et Strip pour des octets. */
export function hiddenExpected(upstream: HiddenUpstream, bytes: Uint8Array, maxInputBytes: number): HiddenExpected {
  const decoded = decodeInput(bytes);
  if (decodedUtf8Length(decoded) > maxInputBytes !== bytes.length > maxInputBytes) {
    throw new UpstreamError('entrée que la limite de 1 Mio classe autrement en octets reçus et en texte décodé');
  }
  const report = upstream.findHidden(decoded.text);
  const stripped = upstream.stripHidden(decoded.text);
  if (!isRecord(report) || typeof report['complete'] !== 'boolean' || !Array.isArray(report['findings'])) {
    throw new UpstreamError('rapport d’origine hors forme');
  }
  if (!isRecord(stripped) || typeof stripped['complete'] !== 'boolean' || typeof stripped['text'] !== 'string') {
    throw new UpstreamError('texte nettoyé d’origine hors forme');
  }
  const complete = report['complete'];
  const hidden = integer(report['hidden'], 'hidden');
  const map = codePointMap(decoded.text);
  const findings = (report['findings'] as readonly unknown[]).map((item): HiddenFindingExpected => {
    if (!isRecord(item)) throw new UpstreamError('constat d’origine hors forme');
    const keys = Object.keys(item).join(',');
    if (keys !== 'kind,line,column,count') throw new UpstreamError(`constat d’origine hors forme : ${keys}`);
    const kind = item['kind'];
    if (typeof kind !== 'string' || !(HIDDEN_KINDS as readonly string[]).includes(kind)) throw new UpstreamError('sorte inconnue');
    const line = integer(item['line'], 'line');
    const column = integer(item['column'], 'column');
    const count = integer(item['count'], 'count');
    const start = map.at.get(`${String(line)}:${String(column)}`);
    const startUnit = start === undefined ? undefined : map.utf16[start];
    const endUnit = start === undefined ? undefined : map.utf16[start + count];
    if (startUnit === undefined || endUnit === undefined || count < 1) throw new UpstreamError('position d’origine hors du texte');
    return {
      kind: kind as HiddenKind,
      line,
      column,
      count,
      byteStart: byteOffsetOf(decoded, startUnit),
      byteEnd: byteOffsetOf(decoded, endUnit),
    };
  });
  if (stripped['complete'] !== complete) throw new UpstreamError('findHidden et stripHidden en désaccord sur la limite');
  if (complete && integer(stripped['removed'], 'removed') !== hidden) throw new UpstreamError('caractères retirés ≠ caractères signalés');
  if (!complete && (hidden !== 0 || findings.length !== 0 || stripped['text'] !== decoded.text)) {
    throw new UpstreamError('rapport incomplet non vide');
  }
  if (!complete && !decoded.validUtf8) throw new UpstreamError('entrée incomplète hors UTF-8 : Strip la rend inchangée en octets');
  const strippedBytes = utf8Bytes(stripped['text']);
  const out =
    strippedBytes.length <= STRIPPED_TEXT_MAX_BYTES
      ? { stripped: stripped['text'] }
      : { strippedSha256: createHash('sha256').update(strippedBytes).digest('hex') };
  return { complete, hidden, findings, ...out };
}

/** Expressions de `mentionedPaths` attendues (motif des mentions, suffixe de lignes, ponctuation finale). */
export const MENTION_REGEXES: readonly RegexLiteral[] = [
  { source: String.raw`(?:^|\s)@(?:"([^"]+)"|(\S+))`, flags: 'gu' },
  { source: String.raw`#L\d+(?:-\d+)?$`, flags: 'u' },
  { source: String.raw`[,;:!?)]+$`, flags: 'u' },
];

interface ReferenceMention {
  readonly path: string;
  readonly lines: string;
  readonly start: number;
  readonly end: number;
}

/**
 * Référence du portage : les expressions mêmes de `mentionedPaths` (lues dans le source vérifié), avec les positions
 * de chaque correspondance (drapeau `d`). Chaque chemin est recalculé par les remplacements d'origine et comparé.
 */
function referenceMentions(text: string, regexes: readonly RegexLiteral[]): ReferenceMention[] {
  const [mention, suffix, punctuation] = regexes;
  if (mention === undefined || suffix === undefined || punctuation === undefined || regexes.length !== 3) {
    throw new UpstreamError('expressions de mentionedPaths inattendues');
  }
  const out: ReferenceMention[] = [];
  for (const match of text.matchAll(new RegExp(mention.source, `${mention.flags}d`))) {
    const quoted = match[1] !== undefined;
    const token = (quoted ? match[1] : match[2]) ?? '';
    const span = match.indices?.[quoted ? 1 : 2];
    if (span === undefined) throw new UpstreamError('correspondance sans position');
    const at = span[0] - (quoted ? 2 : 1);
    if (text[at] !== '@') throw new UpstreamError('mention sans @');
    let path = token;
    let lines = '';
    const found = new RegExp(suffix.source, suffix.flags).exec(path);
    if (found !== null) {
      lines = found[0].slice('#L'.length);
      path = path.slice(0, found.index);
    }
    const tail = new RegExp(punctuation.source, punctuation.flags).exec(path);
    if (tail !== null) path = path.slice(0, tail.index);
    const replaced = token.replace(new RegExp(suffix.source, suffix.flags), '').replace(new RegExp(punctuation.source, punctuation.flags), '');
    if (replaced !== path) throw new UpstreamError('référence différente des remplacements d’origine');
    if (path === '') continue;
    out.push({ path, lines, start: at, end: match.index + match[0].length });
  }
  return out;
}

/** Résultat attendu de Parse pour des octets. */
export function mentionsExpected(upstream: HiddenUpstream, bytes: Uint8Array): MentionsExpected {
  const decoded = decodeInput(bytes);
  const result = upstream.mentionedPaths(decoded.text, MENTION_CWD);
  if (!Array.isArray(result) || !result.every((path): path is string => typeof path === 'string')) {
    throw new UpstreamError('mentionedPaths hors forme');
  }
  const all = referenceMentions(decoded.text, upstream.mentionRegexes);
  const resolved = [...new Set(all.map((entry) => posix.resolve(MENTION_CWD, entry.path)))];
  if (JSON.stringify(resolved) !== JSON.stringify(result)) throw new UpstreamError('référence différente de mentionedPaths');
  const mentions: { path: string; lines: string; start: number; end: number }[] = [];
  const seen = new Map<string, number>();
  for (const entry of all) {
    const index = seen.get(entry.path);
    if (index !== undefined) {
      const kept = mentions[index];
      if (kept !== undefined && kept.lines !== entry.lines) kept.lines = '';
      continue;
    }
    seen.set(entry.path, mentions.length);
    mentions.push({ ...entry });
  }
  return {
    mentions: mentions.map((entry) => ({
      path: entry.path,
      ...(entry.lines === '' ? {} : { lines: entry.lines }),
      byteStart: byteOffsetOf(decoded, entry.start),
      byteEnd: byteOffsetOf(decoded, entry.end),
    })),
    upstream: result,
  };
}
