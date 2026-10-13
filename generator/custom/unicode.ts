/**
 * Pont Unicode des termes confidentiels : ce que calcule Node 26 (ICU 78, Unicode 17.0.0), figé par blocs de 4 096
 * points de code dans `vectors/custom/unicode.json`, recalculé par le test Go `TestCustomUnicodeParity` :
 *
 * - pour chaque point de code de \p{L}, \p{N} ou \p{M} (caractère de mot) : `normalizeWord` de l'origine
 *   (NFKD, marques retirées, `toLowerCase`) ;
 * - pour chaque point de code hors substituts : `toLowerCase` de « A », U+03A3, c et de « A », c, U+03A3, qui
 *   éprouvent la correspondance simple de c et la règle du sigma final (c ignorable de la casse, à casse, ou ni l'un
 *   ni l'autre).
 *
 * Chaque bloc est le SHA-256 de ses lignes : `<point de code>:<UTF-8 hexadécimal>` pour un caractère de mot,
 * `<point de code>~<UTF-8 hexadécimal>~<UTF-8 hexadécimal>` pour les minuscules, dans l'ordre des points de code.
 */
import { createHash } from 'node:crypto';

export const UNICODE_BLOCK = 0x1000;
const LAST_CODE_POINT = 0x10ffff;
const WORD = /^[\p{L}\p{N}\p{M}]$/u;
const SIGMA = '\u03a3';

/** normalizeWord de l'origine (terms.ts). */
export type NormalizeWord = (word: string) => string;

function hex(text: string): string {
  return Buffer.from(text, 'utf8').toString('hex');
}

/** Lignes d'un bloc. */
export function unicodeBlockLines(from: number, normalizeWord: NormalizeWord): string {
  let lines = '';
  for (let cp = from; cp < from + UNICODE_BLOCK && cp <= LAST_CODE_POINT; cp += 1) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    const character = String.fromCodePoint(cp);
    if (WORD.test(character)) lines += `${String(cp)}:${hex(normalizeWord(character))}\n`;
    lines += `${String(cp)}~${hex(`A${SIGMA}${character}`.toLowerCase())}~${hex(`A${character}${SIGMA}`.toLowerCase())}\n`;
  }
  return lines;
}

export interface UnicodeBlock {
  readonly id: string;
  readonly from: number;
  readonly to: number;
  readonly sha256: string;
}

/** Blocs du pont Unicode. */
export function unicodeBlocks(normalizeWord: NormalizeWord): UnicodeBlock[] {
  const blocks: UnicodeBlock[] = [];
  for (let from = 0; from <= LAST_CODE_POINT; from += UNICODE_BLOCK) {
    const to = Math.min(from + UNICODE_BLOCK - 1, LAST_CODE_POINT);
    const sha256 = createHash('sha256').update(unicodeBlockLines(from, normalizeWord)).digest('hex');
    blocks.push({ id: `unicode/${from.toString(16).padStart(6, '0')}`, from, to, sha256 });
  }
  return blocks;
}
