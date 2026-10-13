/**
 * Pont Unicode entre le moteur d'origine (Node) et le moteur Go.
 *
 * Secret Guard retire `\p{Default_Ignorable_Code_Point}` et normalise en NFKC point de code par point de code
 * (`mapping.ts`) avec les tables Unicode de Node ; le moteur Go utilise une table générée
 * (`detect/unicode_tables.go`) et `golang.org/x/text/unicode/norm`. `vectors/unicode-parity.json` fige ce que Node
 * calcule : version Unicode, plages de la propriété et empreinte SHA-256 de la normalisation NFKC de chaque point de
 * code qu'elle change. Le test Vitest `test/unicode-parity.test.ts` le recalcule avec le Node de la CI, le test Go
 * `TestUnicodeParity` avec les tables du moteur : un écart d'un côté ou de l'autre échoue.
 *
 * `npm run vectors:unicode` (dans `generator/`) : réécrit le fichier (seulement après une montée de version Unicode
 * voulue des deux côtés).
 */
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export interface UnicodeParity {
  readonly unicodeVersion: string;
  readonly defaultIgnorableCodePoint: readonly (readonly [number, number])[];
  readonly nfkcChangedCodePoints: number;
  readonly nfkcSha256: string;
}

const DEFAULT_IGNORABLE = /^\p{Default_Ignorable_Code_Point}$/u;

/** Calcule le pont avec les tables Unicode du Node qui exécute ce code. */
export function unicodeParity(): UnicodeParity {
  const ranges: [number, number][] = [];
  const hash = createHash('sha256');
  let changed = 0;
  let open = -1;
  for (let codePoint = 0; codePoint <= 0x10ffff; codePoint += 1) {
    // Les substituts ne sont pas des points de code scalaires : ni ignorables, ni changés par la normalisation.
    const scalar = codePoint < 0xd800 || codePoint > 0xdfff;
    const character = scalar ? String.fromCodePoint(codePoint) : '';
    const ignorable = scalar && DEFAULT_IGNORABLE.test(character);
    if (ignorable && open < 0) open = codePoint;
    if (!ignorable && open >= 0) {
      ranges.push([open, codePoint - 1]);
      open = -1;
    }
    if (!scalar) continue;
    const normalized = character.normalize('NFKC');
    if (normalized !== character) {
      changed += 1;
      // Même écriture que le test Go : « <point de code en hexadécimal>:<octets UTF-8 en hexadécimal>; ».
      hash.update(`${codePoint.toString(16)}:${Buffer.from(normalized, 'utf8').toString('hex')};`);
    }
  }
  if (open >= 0) ranges.push([open, 0x10ffff]);
  const version = process.versions['unicode'] ?? '';
  return {
    unicodeVersion: /^\d+\.\d+$/.test(version) ? `${version}.0` : version,
    defaultIgnorableCodePoint: ranges,
    nfkcChangedCodePoints: changed,
    nfkcSha256: hash.digest('hex'),
  };
}

/** Écriture du fichier : une plage par ligne, fin de ligne finale. */
export function serializeUnicodeParity(parity: UnicodeParity): string {
  const ranges = parity.defaultIgnorableCodePoint.map(([lo, hi]) => `    [${String(lo)}, ${String(hi)}]`).join(',\n');
  return [
    '{',
    `  "unicodeVersion": ${JSON.stringify(parity.unicodeVersion)},`,
    `  "defaultIgnorableCodePoint": [\n${ranges}\n  ],`,
    `  "nfkcChangedCodePoints": ${String(parity.nfkcChangedCodePoints)},`,
    `  "nfkcSha256": ${JSON.stringify(parity.nfkcSha256)}`,
    '}',
    '',
  ].join('\n');
}

export const UNICODE_PARITY_FILE = new URL('../vectors/unicode-parity.json', import.meta.url);

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  writeFileSync(UNICODE_PARITY_FILE, serializeUnicodeParity(unicodeParity()));
  process.stdout.write(`Pont Unicode écrit : ${UNICODE_PARITY_FILE.pathname}\n`);
}
