// SPDX-License-Identifier: Apache-2.0
/**
 * Décodage à plusieurs couches (v0.10.0) : cas tirés des tests d'origine dont le résultat attendu change.
 *
 * Le moteur d'origine décode une couche de base64 ; le moteur Go en décode jusqu'à trois (`detect/scan.go`,
 * `decodedText`). Deux tests d'origine éprouvent justement l'arrêt à une couche : leur entrée reste dans le corpus,
 * leur résultat attendu vient de la seconde écriture ci-dessous, pas du moteur d'origine (écart décrit dans
 * `UPSTREAM.md`, « Décodage à plusieurs couches et vue UTF-16 »).
 *
 * Seconde écriture, sans rien reprendre du moteur Go : l'entrée entière est un candidat base64 ; elle est décodée
 * ici, couche après couche, et le moteur d'origine juge chaque texte décodé (il y lit lui-même une couche). Le
 * premier texte où il trouve un constat « base64 » donne le constat attendu : même règle, étendue de l'entrée
 * entière, encodage de la couche extérieure, 5 points de moins par couche décodée ici. Toute autre forme arrête le
 * générateur (le cas doit être redessiné).
 */
import { decodeInput, utf8Bytes } from './bytes.ts';
import { CorpusError, expectedFor, type CaseSource } from './corpus.ts';
import { levelForScore, type CorpusExpected } from './model.ts';
import type { UpstreamEngine } from './upstream.ts';

/** Cas d'origine rejugés (identifiants du corpus). */
export const LAYERED_UPSTREAM_CASES: ReadonlySet<string> = new Set([
  'upstream/scan.test.ts > normalization and bounded transformations > detects exactly one Base64 layer #2',
  'upstream/security.test.ts > adversarial bounded behavior > does not recursively decode nested Base64 #1',
]);

/** `maxDecodeLayers` et `layerPenalty` de `detect/encoding.go`. */
const MAX_LAYERS = 3;
const LAYER_PENALTY = 5;
/** L'entrée entière est une correspondance de `BASE64_CANDIDATE`. */
const WHOLE_CANDIDATE = /^[A-Za-z0-9+/_-]{20,16384}={0,2}$/;

function peel(id: string, text: string): string {
  if (!WHOLE_CANDIDATE.test(text)) throw new CorpusError(`${id} : le texte n’est pas un candidat base64 entier`);
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(text, 'base64'));
  } catch {
    throw new CorpusError(`${id} : le texte décodé n’est pas de l’UTF-8`);
  }
}

/** Résultat attendu d'un cas de `LAYERED_UPSTREAM_CASES`. */
export function layeredExpected(engine: UpstreamEngine, source: CaseSource): CorpusExpected {
  const origin = expectedFor(engine, source.bytes, source.languageId);
  const outer = decodeInput(source.bytes);
  const whole = (start: number, end: number, length: number): boolean => start === 0 && end === length;
  if (!origin.complete || !outer.validUtf8) throw new CorpusError(`${source.id} : analyse d’origine incomplète ou entrée hors UTF-8`);
  // L'origine n'y voit rien, ou le seul avertissement d'entropie sur l'entrée entière, que le constat de règle remplace.
  if (origin.findings.some((finding) => finding.ruleId !== 'high_entropy' || !whole(finding.byteStart, finding.byteEnd, source.bytes.length))) {
    throw new CorpusError(`${source.id} : l’origine trouve autre chose qu’un avertissement d’entropie sur l’entrée entière`);
  }
  let text = outer.text;
  for (let peeled = 1; peeled < MAX_LAYERS; peeled += 1) {
    text = peel(source.id, text);
    const inner = expectedFor(engine, utf8Bytes(text), undefined);
    const [found] = inner.findings;
    if (found === undefined) continue;
    if (inner.findings.length !== 1 || found.encoding !== 'base64' || !whole(found.byteStart, found.byteEnd, utf8Bytes(text).length)) {
      throw new CorpusError(`${source.id} : le texte décodé ne porte pas un seul constat base64 entier`);
    }
    const score = found.score - LAYER_PENALTY * peeled;
    const { ruleId, secretType } = found;
    const finding = { ruleId, secretType, encoding: 'base64' as const, score, level: levelForScore(score), byteStart: 0, byteEnd: source.bytes.length };
    return { complete: true, failure: 'none', findings: [finding] };
  }
  throw new CorpusError(`${source.id} : aucune couche ne porte de constat, le cas n’a pas à être rejugé`);
}
