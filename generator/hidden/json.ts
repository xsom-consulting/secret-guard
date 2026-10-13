/**
 * Écriture déterministe de `vectors/hidden.json` et `vectors/mentions.json` : en-tête, puis un cas par ligne, champs
 * dans un ordre fixe, fin de ligne `\n`. Les chaînes passent par `jsonString` du corpus : aucun caractère invisible
 * n'entre dans le fichier (ils s'écrivent `\uXXXX`).
 */
import { jsonString } from '../corpus/json.ts';
import type { HiddenExpected, HiddenFindingExpected, MentionExpected, MentionsExpected } from './expected.ts';

/** Version du format des deux fichiers. */
export const VECTORS_FORMAT_VERSION = 1;

/** Entrée d'un cas : texte quand les octets sont de l'UTF-8 valide, sinon base64 standard avec remplissage. */
export interface VectorInput {
  readonly id: string;
  readonly input: string;
  readonly inputEncoding: 'utf8' | 'base64';
}

export function vectorInput(id: string, bytes: Uint8Array): VectorInput {
  const text = new TextDecoder('utf-8', { fatal: false, ignoreBOM: true }).decode(bytes);
  const valid = Buffer.from(new TextEncoder().encode(text)).equals(Buffer.from(bytes));
  return valid ? { id, input: text, inputEncoding: 'utf8' } : { id, input: Buffer.from(bytes).toString('base64'), inputEncoding: 'base64' };
}

function head(value: VectorInput): string {
  return `{"id":${jsonString(value.id)},"input":${jsonString(value.input)},"inputEncoding":${jsonString(value.inputEncoding)},`;
}

function hiddenFinding(value: HiddenFindingExpected): string {
  return (
    `{"kind":${jsonString(value.kind)},"line":${String(value.line)},"column":${String(value.column)},` +
    `"count":${String(value.count)},"byteStart":${String(value.byteStart)},"byteEnd":${String(value.byteEnd)}}`
  );
}

export function serializeHiddenCase(input: VectorInput, expected: HiddenExpected): string {
  const stripped =
    expected.stripped !== undefined ? `"stripped":${jsonString(expected.stripped)}` : `"strippedSha256":${jsonString(expected.strippedSha256 ?? '')}`;
  return (
    `${head(input)}"expected":{"complete":${String(expected.complete)},"hidden":${String(expected.hidden)},` +
    `"findings":[${expected.findings.map(hiddenFinding).join(',')}],${stripped}}}`
  );
}

function mention(value: MentionExpected): string {
  const lines = value.lines === undefined ? '' : `"lines":${jsonString(value.lines)},`;
  return `{"path":${jsonString(value.path)},${lines}"byteStart":${String(value.byteStart)},"byteEnd":${String(value.byteEnd)}}`;
}

export function serializeMentionCase(input: VectorInput, expected: MentionsExpected): string {
  return (
    `${head(input)}"expected":{"mentions":[${expected.mentions.map(mention).join(',')}],` +
    `"upstream":[${expected.upstream.map(jsonString).join(',')}]}}`
  );
}

/** Fichier : en-tête (paires clé → valeur JSON déjà écrites), puis les cas, un par ligne. */
export function serializeVectorFile(header: readonly (readonly [string, string])[], cases: readonly string[]): string {
  const fields = header.map(([key, value]) => `  ${JSON.stringify(key)}: ${value},`).join('\n');
  const body = cases.length === 0 ? '[]' : `[\n${cases.join(',\n')}\n  ]`;
  return `{\n${fields}\n  "cases": ${body}\n}\n`;
}
