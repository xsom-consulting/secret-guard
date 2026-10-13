/**
 * Octets ↔ texte du corpus de parité. Le moteur Go analyse des octets, Secret Guard une chaîne UTF-16 :
 * le générateur décode chaque entrée comme Go la parcourt, puis convertit les positions UTF-16 du moteur
 * TypeScript en positions d'octets.
 *
 * Décodage : séquence UTF-8 valide → son point de code ; tout autre octet → U+FFFD, un par octet, comme
 * `utf8.DecodeRune` de Go (surrogats, formes trop longues, au-delà de U+10FFFF et séquences tronquées compris).
 * NUL est un caractère ordinaire.
 */

/** Marque d'une position UTF-16 au milieu d'une paire de substitution (aucun octet ne lui correspond). */
const INSIDE_PAIR = 0xffff_ffff;

export interface DecodedInput {
  /** Texte vu par Secret Guard. */
  readonly text: string;
  /** Vrai si les octets sont de l'UTF-8 valide (aucun U+FFFD de remplacement). */
  readonly validUtf8: boolean;
  /** Position en octets de chaque position UTF-16 de `text` (longueur `text.length + 1`). */
  readonly byteOffsets: Uint32Array;
}

/** Longueur et point de code de la séquence UTF-8 valide qui commence à `index`, ou `undefined`. */
function validSequence(bytes: Uint8Array, index: number): { length: number; codePoint: number } | undefined {
  const first = bytes[index] ?? 0;
  const at = (offset: number): number => bytes[index + offset] ?? -1;
  const continuation = (value: number): boolean => value >= 0x80 && value <= 0xbf;
  if (first < 0x80) return { length: 1, codePoint: first };
  if (first >= 0xc2 && first <= 0xdf) {
    const second = at(1);
    return continuation(second) ? { length: 2, codePoint: ((first & 0x1f) << 6) | (second & 0x3f) } : undefined;
  }
  if (first >= 0xe0 && first <= 0xef) {
    const second = at(1);
    const third = at(2);
    // E0 : pas de forme trop longue ; ED : pas de surrogat.
    const low = first === 0xe0 ? 0xa0 : 0x80;
    const high = first === 0xed ? 0x9f : 0xbf;
    if (second < low || second > high || !continuation(third)) return undefined;
    return { length: 3, codePoint: ((first & 0x0f) << 12) | ((second & 0x3f) << 6) | (third & 0x3f) };
  }
  if (first >= 0xf0 && first <= 0xf4) {
    const second = at(1);
    // F0 : pas de forme trop longue ; F4 : pas au-delà de U+10FFFF.
    const low = first === 0xf0 ? 0x90 : 0x80;
    const high = first === 0xf4 ? 0x8f : 0xbf;
    if (second < low || second > high || !continuation(at(2)) || !continuation(at(3))) return undefined;
    return {
      length: 4,
      codePoint: ((first & 0x07) << 18) | ((second & 0x3f) << 12) | ((at(2) & 0x3f) << 6) | (at(3) & 0x3f),
    };
  }
  return undefined;
}

/** Décode des octets comme Go les parcourt (`for range` sur une chaîne). */
export function decodeInput(bytes: Uint8Array): DecodedInput {
  const parts: string[] = [];
  const offsets: number[] = [];
  let validUtf8 = true;
  let index = 0;
  while (index < bytes.length) {
    const sequence = validSequence(bytes, index);
    if (sequence === undefined) {
      validUtf8 = false;
      parts.push('\ufffd');
      offsets.push(index);
      index += 1;
      continue;
    }
    parts.push(String.fromCodePoint(sequence.codePoint));
    offsets.push(index);
    if (sequence.codePoint > 0xffff) offsets.push(INSIDE_PAIR);
    index += sequence.length;
  }
  offsets.push(bytes.length);
  return { text: parts.join(''), validUtf8, byteOffsets: Uint32Array.from(offsets) };
}

/** Position en octets d'une position UTF-16 ; refuse une position au milieu d'une paire ou hors du texte. */
export function byteOffsetOf(decoded: DecodedInput, utf16Offset: number): number {
  if (!Number.isInteger(utf16Offset) || utf16Offset < 0 || utf16Offset >= decoded.byteOffsets.length) {
    throw new RangeError(`position UTF-16 hors du texte : ${String(utf16Offset)}`);
  }
  const offset = decoded.byteOffsets[utf16Offset] ?? INSIDE_PAIR;
  if (offset === INSIDE_PAIR) throw new RangeError(`position UTF-16 au milieu d'une paire : ${String(utf16Offset)}`);
  return offset;
}

/** Octets UTF-8 d'un texte ; un demi-code de substitution isolé devient U+FFFD (`TextEncoder`). */
export function utf8Bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}
