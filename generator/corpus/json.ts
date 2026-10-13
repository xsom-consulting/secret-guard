/**
 * Écriture déterministe des fichiers du corpus : un cas par ligne, champs dans un ordre fixe, fin de
 * ligne `\n`. Les chaînes gardent les caractères visibles tels quels ; les caractères de contrôle, de format
 * (U+200B, U+FEFF…), les séparateurs (U+00A0, U+2028, U+3000…), les codes privés et non attribués s'écrivent
 * `\uXXXX`, pour qu'aucun caractère invisible n'entre dans le fichier.
 */
import type { CorpusCase, CorpusExpected, CorpusFinding, CorpusManifest } from './model.ts';

/**
 * Caractère écrit tel quel : ASCII imprimable, ou lettre, marque, chiffre, ponctuation ou symbole hors ASCII qui
 * n'est pas ignorable par défaut (U+034F, U+FE0F, U+3164… restent échappés).
 */
const VISIBLE = /^(?:[\x20-\x7e]|(?!\p{Default_Ignorable_Code_Point})[\p{L}\p{M}\p{N}\p{P}\p{S}])$/u;

function hex4(unit: number): string {
  return `\\u${unit.toString(16).padStart(4, '0')}`;
}

/** Chaîne JSON : `"`, `\`, `\n`, `\r`, `\t` échappés, autres caractères non visibles en `\uXXXX` (paires comprises). */
export function jsonString(value: string): string {
  let out = '"';
  for (const character of value) {
    if (character === '"') out += '\\"';
    else if (character === '\\') out += '\\\\';
    else if (character === '\n') out += '\\n';
    else if (character === '\r') out += '\\r';
    else if (character === '\t') out += '\\t';
    else if (VISIBLE.test(character)) out += character;
    else for (let index = 0; index < character.length; index += 1) out += hex4(character.charCodeAt(index));
  }
  return `${out}"`;
}

function finding(value: CorpusFinding): string {
  return (
    `{"ruleId":${jsonString(value.ruleId)},"secretType":${jsonString(value.secretType)},` +
    `"encoding":${jsonString(value.encoding)},"score":${String(value.score)},"level":${jsonString(value.level)},` +
    `"byteStart":${String(value.byteStart)},"byteEnd":${String(value.byteEnd)}}`
  );
}

function expected(value: CorpusExpected): string {
  return (
    `{"complete":${String(value.complete)},"failure":${jsonString(value.failure)},` +
    `"findings":[${value.findings.map(finding).join(',')}]}`
  );
}

/** Une ligne par cas. */
export function serializeCase(value: CorpusCase): string {
  const language = value.languageId === undefined ? '' : `"languageId":${jsonString(value.languageId)},`;
  return (
    `{"id":${jsonString(value.id)},"input":${jsonString(value.input)},` +
    `"inputEncoding":${jsonString(value.inputEncoding)},${language}"expected":${expected(value.expected)}}`
  );
}

/** Fichier de cas : tableau JSON, un cas par ligne. */
export function serializeCaseFile(cases: readonly CorpusCase[]): string {
  if (cases.length === 0) return '[]\n';
  return `[\n${cases.map(serializeCase).join(',\n')}\n]\n`;
}

/** Manifeste : fichiers triés par nom. */
export function serializeManifest(manifest: CorpusManifest): string {
  const files = manifest.files.map((entry) => `    {"file":${jsonString(entry.file)},"cases":${String(entry.cases)}}`);
  return (
    `{\n  "formatVersion": ${String(manifest.formatVersion)},\n` +
    `  "upstreamCommit": ${jsonString(manifest.upstreamCommit)},\n` +
    `  "files": [\n${files.join(',\n')}\n  ]\n}\n`
  );
}
