// SPDX-License-Identifier: Apache-2.0
/**
 * Matrice d'encodages (v0.10.0) : `vectors/detection/views-encodings.json`.
 *
 * Vingt et un cas : le même jeton GitHub synthétique, en clair puis sous chaque écriture qu'un texte collé ou un
 * fichier peut lui donner. Le tableau publié dans `docs/encodages.md` (« ce que le moteur voit ») est la lecture de ce
 * fichier : il compte aussi ce que le moteur ne voit pas encore (aucun constat, ou le seul avertissement d'entropie).
 *
 * Résultat attendu. Seize cas sont jugés par le moteur d'origine, que le moteur Go suit sur ces textes. Cinq cas
 * éprouvent un écart du moteur Go (`UPSTREAM.md`, « Décodage à plusieurs couches et vue UTF-16 ») et sont jugés par
 * une seconde écriture, sans rien reprendre du moteur Go :
 * - fichier UTF-16 : le texte est décodé ici, le moteur d'origine juge le texte ; chaque constat garde sa règle et son
 *   score, prend l'encodage `normalized` et l'étendue des octets UTF-16 (deux par caractère, après la marque d'ordre) ;
 * - base64 à plusieurs couches, base64 d'UTF-16 : le candidat est décodé ici couche après couche, le moteur d'origine
 *   juge le texte clair ; le constat attendu garde la règle, prend l'encodage `base64`, l'étendue du candidat et
 *   5 points de moins par couche de base64.
 * Toute autre forme arrête le générateur (le cas doit être redessiné).
 */
import { crc32, deflateRawSync } from 'node:zlib';
import { utf8Bytes } from './bytes.ts';
import { CorpusError, expectedFor, type CaseSource } from './corpus.ts';
import { compareFindings, levelForScore, type CorpusExpected, type CorpusFinding } from './model.ts';
import { synth } from './synthetic.ts';
import type { UpstreamEngine } from './upstream.ts';

export const ENCODINGS_FILE = 'views-encodings.json';

/** `layerPenalty` de `detect/encoding.go`. */
const LAYER_PENALTY = 5;

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Lecture qui donne le résultat attendu d'un cas. */
type Reading =
  | { readonly kind: 'origin' }
  | { readonly kind: 'utf16'; readonly markBytes: number; readonly text: string }
  | { readonly kind: 'layers'; readonly candidate: string; readonly layers: number; readonly wide: boolean };

export interface EncodingSource extends CaseSource {
  readonly reading: Reading;
}

function base64(bytes: Uint8Array | string): string {
  return Buffer.from(bytes).toString('base64');
}

function utf16(text: string, bigEndian: boolean): Uint8Array {
  const bytes = Buffer.from(text, 'utf16le');
  return bigEndian ? bytes.swap16() : bytes;
}

/** Base32 de la RFC 4648, avec remplissage. */
function base32(bytes: Uint8Array): string {
  let bits = '';
  for (const byte of bytes) bits += byte.toString(2).padStart(8, '0');
  let out = '';
  for (let at = 0; at < bits.length; at += 5) out += BASE32[Number.parseInt(bits.slice(at, at + 5).padEnd(5, '0'), 2)] ?? '';
  return out.padEnd(Math.ceil(out.length / 8) * 8, '=');
}

/** Archive gzip à en-tête fixe (ni date, ni système) : mêmes octets sur tout poste. */
function gzip(bytes: Uint8Array): Uint8Array {
  const trailer = Buffer.alloc(8);
  trailer.writeUInt32LE(crc32(bytes), 0);
  trailer.writeUInt32LE(bytes.length, 4);
  return Buffer.concat([Buffer.from([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff]), deflateRawSync(bytes, { level: 9 }), trailer]);
}

function escaped(text: string, write: (code: number) => string): string {
  return [...text].map((character) => write(character.codePointAt(0) ?? 0)).join('');
}

function hex(code: number, width: number): string {
  return code.toString(16).padStart(width, '0');
}

/** Les vingt et un cas, dans l'ordre du tableau de `docs/encodages.md`. */
export function encodingCases(): EncodingSource[] {
  const token = `${['gh', 'p'].join('')}_${synth('encodings/github', ALNUM, 36)}`;
  const name = ['GITHUB', ['TOK', 'EN'].join('')].join('_');
  const line = `export ${name}=${token}\n`;
  const command = `$env:${name} = '${token}'; git push`;
  const twice = base64(base64(line));
  const wideCommand = base64(utf16(command, false));
  const origin: Reading = { kind: 'origin' };
  const cases: (readonly [string, Uint8Array | string, Reading])[] = [
    ['01-clair', line, origin],
    ['02-base64', `data: ${base64(line)}\n`, origin],
    ['03-base64-deux-couches', `data: ${twice}\n`, { kind: 'layers', candidate: twice, layers: 2, wide: false }],
    ['04-utf16-petit-boutien-marque', Buffer.concat([Buffer.from([0xff, 0xfe]), utf16(line, false)]), { kind: 'utf16', markBytes: 2, text: line }],
    ['05-utf16-petit-boutien-sans-marque', utf16(line, false), { kind: 'utf16', markBytes: 0, text: line }],
    ['06-utf16-gros-boutien-marque', Buffer.concat([Buffer.from([0xfe, 0xff]), utf16(line, true)]), { kind: 'utf16', markBytes: 2, text: line }],
    ['07-commande-powershell-encodee', `powershell -NoProfile -EncodedCommand ${wideCommand}\n`, { kind: 'layers', candidate: wideCommand, layers: 1, wide: true }],
    ['08-hexadecimal', `payload=${Buffer.from(line).toString('hex')}\n`, origin],
    ['09-echappements-deux-chiffres', `s = "${escaped(token, (code) => `\\x${hex(code, 2)}`)}"\n`, origin],
    ['10-echappements-quatre-chiffres', `{"valeur": "${escaped(token, (code) => `\\u${hex(code, 4)}`)}"}\n`, origin],
    ['11-echappements-accolades', `s = "${escaped(token, (code) => `\\u{${hex(code, 1)}}`)}"\n`, origin],
    ['12-entites-html-hexadecimales', `<input value="${escaped(token, (code) => `&#x${hex(code, 1)};`)}">\n`, origin],
    ['13-entites-html-decimales', `<input value="${escaped(token, (code) => `&#${String(code)};`)}">\n`, origin],
    ['14-pourcentage', `https://exemple.test/?t=${escaped(token, (code) => `%${hex(code, 2).toUpperCase()}`)}\n`, origin],
    ['15-coupe-par-un-retour-a-la-ligne', `valeur: ${token.slice(0, 20)}\n${token.slice(20)}\n`, origin],
    ['16-base32', `data: ${base32(utf8Bytes(line))}\n`, origin],
    ['17-concatenation', `t = "${token.slice(0, 10)}" + "${token.slice(10)}"\n`, origin],
    ['18-largeur-nulle', `valeur: ${token.slice(0, 8)}​${token.slice(8)}\n`, origin],
    ['19-inverse', `x: ${[...token].reverse().join('')}\n`, origin],
    ['20-gzip-puis-base64', `blob: ${base64(gzip(utf8Bytes(line)))}\n`, origin],
    ['21-dans-une-phrase', `voici la valeur ${token} à utiliser\n`, origin],
  ];
  return cases.map(([id, input, reading]) => ({
    file: ENCODINGS_FILE,
    id: `encodings/${id}`,
    bytes: typeof input === 'string' ? utf8Bytes(input) : input,
    reading,
  }));
}

function indexOfBytes(haystack: Uint8Array, needle: string, id: string): number {
  const at = Buffer.from(haystack).indexOf(needle, 0, 'latin1');
  if (at < 0) throw new CorpusError(`${id} : candidat absent de l’entrée`);
  return at;
}

/** Résultat attendu d'un cas de la matrice (voir l'en-tête). */
export function encodingExpected(engine: UpstreamEngine, source: EncodingSource): CorpusExpected {
  const { reading } = source;
  if (reading.kind === 'origin') return expectedFor(engine, source.bytes, undefined);
  if (reading.kind === 'utf16') {
    if (!/^[\u0000-\u007f]*$/.test(reading.text)) throw new CorpusError(`${source.id} : texte hors ASCII`);
    const inner = expectedFor(engine, utf8Bytes(reading.text), undefined);
    if (!inner.complete || inner.findings.some((finding) => finding.encoding !== 'plain')) {
      throw new CorpusError(`${source.id} : le texte décodé n’est pas jugé en clair par l’origine`);
    }
    const findings = inner.findings.map(
      (finding): CorpusFinding => ({
        ...finding,
        encoding: 'normalized',
        byteStart: reading.markBytes + 2 * finding.byteStart,
        byteEnd: reading.markBytes + 2 * finding.byteEnd,
      }),
    );
    return { complete: true, failure: 'none', findings: findings.sort(compareFindings) };
  }
  let clear = reading.candidate;
  for (let layer = 1; layer <= reading.layers; layer += 1) {
    const decoded = Buffer.from(clear, 'base64');
    clear = layer === reading.layers && reading.wide ? decoded.toString('utf16le') : new TextDecoder('utf-8', { fatal: true }).decode(decoded);
  }
  const inner = expectedFor(engine, utf8Bytes(clear), undefined);
  const [found] = inner.findings;
  if (!inner.complete || inner.findings.length !== 1 || found === undefined || found.encoding !== 'plain') {
    throw new CorpusError(`${source.id} : le texte clair ne porte pas un seul constat en clair`);
  }
  const byteStart = indexOfBytes(source.bytes, reading.candidate, source.id);
  const score = found.score - LAYER_PENALTY * reading.layers;
  const { ruleId, secretType } = found;
  const finding: CorpusFinding = { ruleId, secretType, encoding: 'base64', score, level: levelForScore(score), byteStart, byteEnd: byteStart + reading.candidate.length };
  return { complete: true, failure: 'none', findings: [finding] };
}
