/**
 * Vecteurs du masquage et des décisions : contrôles des fichiers commités, sans le checkout de Secret Guard (le
 * résultat attendu vient du moteur d'origine ; la régénération et sa comparaison octet pour octet se font par
 * `npm run vectors:redact -- --upstream <checkout> [--check]`).
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parse as parseToml } from 'smol-toml';
import { describe, expect, it } from 'vitest';
import { decodeInput } from '../corpus/bytes.ts';
import { levelForScore, MANIFEST_FILE, type CorpusCase, type CorpusExpected } from '../corpus/model.ts';
import { UPSTREAM_COMMIT, type EngineResult, type UpstreamEngine } from '../corpus/upstream.ts';
import { filledPrefix, intentProblem, redactSources, sourceBytes, spanSources } from '../redact/cases.ts';
import { corpusCaseSelected } from '../redact/main.ts';
import {
  DECISIONS,
  INLINE_TEXT_MAX_BYTES,
  LEVELS,
  REDACT_FORMAT_VERSION,
  SANITIZE_FAILURES,
  SCORE_RANGE,
  type DecisionVectors,
  type RedactedText,
  type RedactVectors,
} from '../redact/model.ts';
import {
  decisionVectors,
  describeText,
  mergeSpans,
  placeholderName,
  rebuildBytes,
  rebuildText,
  redactExpectedFor,
  RedactVectorError,
  serializeDecisionVectors,
  serializeRedactVectors,
  utf16OffsetOf,
  type RedactEngine,
} from '../redact/vectors.ts';

const VECTORS = new URL('../../vectors/', import.meta.url);
const read = (name: string): string => readFileSync(new URL(name, VECTORS), 'utf8');
const redactText = read('redact.json');
const decisionText = read('decision.json');
const redact = JSON.parse(redactText) as RedactVectors;
const decision = JSON.parse(decisionText) as DecisionVectors;

const manifest = JSON.parse(read(`detection/${MANIFEST_FILE}`)) as { files: { file: string }[] };
const corpus = new Map(
  manifest.files.map(({ file }) => [file, new Map((JSON.parse(read(`detection/${file}`)) as CorpusCase[]).map((c) => [c.id, c]))]),
);

const textBytes = (text: string, encoding: string | undefined): Uint8Array =>
  encoding === 'base64' ? Uint8Array.from(Buffer.from(text, 'base64')) : new TextEncoder().encode(text);

function checkRedactedText(value: RedactedText, id: string): void {
  expect(Object.keys(value).sort(), id).toEqual(value.text === undefined ? ['bytes', 'sha256'] : ['bytes', 'sha256', 'text', 'textEncoding']);
  expect(/^[0-9a-f]{64}$/.test(value.sha256), id).toBe(true);
  expect(value.text === undefined, id).toBe(value.bytes > INLINE_TEXT_MAX_BYTES);
  if (value.text !== undefined) {
    const bytes = textBytes(value.text, value.textEncoding);
    expect(bytes.length, id).toBe(value.bytes);
    expect(createHash('sha256').update(bytes).digest('hex'), id).toBe(value.sha256);
    expect(value.textEncoding, id).toBe(decodeInput(bytes).validUtf8 ? 'utf8' : 'base64');
  }
}

describe('vecteurs du masquage commités', () => {
  it('chaque cas a la forme du contrat, une issue cohérente avec ses analyses et un identifiant unique', () => {
    expect(redact.formatVersion).toBe(REDACT_FORMAT_VERSION);
    expect(redact.upstreamCommit).toBe(UPSTREAM_COMMIT);
    const ids = new Set<string>();
    for (const c of redact.cases) {
      expect(ids.has(c.id), c.id).toBe(false);
      ids.add(c.id);
      expect(SANITIZE_FAILURES).toContain(c.expected.failure);
      const initial: CorpusExpected | undefined = c.corpusFile === undefined ? c.expected.initial : corpus.get(c.corpusFile)?.get(c.id)?.expected;
      expect(initial, c.id).toBeDefined();
      if (initial === undefined) continue;
      if (!initial.complete) {
        expect(c.expected, c.id).toMatchObject({ failure: 'incomplete', redacted: null, final: null });
        continue;
      }
      expect(c.expected.redacted, c.id).not.toBeNull();
      expect(c.expected.final, c.id).not.toBeNull();
      if (c.expected.redacted !== null) checkRedactedText(c.expected.redacted, c.id);
      const final = c.expected.final;
      if (final === null) continue;
      const failure = !final.complete ? 'incomplete' : final.findings.length > 0 ? 'residual' : 'none';
      expect(c.expected.failure, c.id).toBe(failure);
    }
    for (const c of redact.spanCases) checkRedactedText(c.redacted, c.id);
  });

  it('chaque cas du corpus de parité qui a un constat ou une analyse incomplète est repris une fois, par renvoi', () => {
    const referenced = redact.cases.filter((c) => c.corpusFile !== undefined);
    for (const c of referenced) {
      expect(c.input, c.id).toBeUndefined();
      expect(c.expected.initial, c.id).toBeUndefined();
    }
    const selected = [...corpus].flatMap(([file, cases]) =>
      [...cases.values()].filter(corpusCaseSelected).map((c) => `${file}\u0000${c.id}`),
    );
    expect(referenced.map((c) => `${c.corpusFile ?? ''}\u0000${c.id}`).sort()).toEqual(selected.sort());
    expect(selected.length).toBeGreaterThan(500);
  });

  it('les entrées synthétiques et les cas d’étendues sont exactement ceux du générateur (valeurs générées, aucune copiée)', () => {
    const synthetic = redact.cases.filter((c) => c.corpusFile === undefined);
    const sources = redactSources();
    expect(synthetic.map((c) => c.id)).toEqual(sources.map((s) => s.id));
    synthetic.forEach((c, index) => {
      const source = sources[index];
      if (source === undefined) throw new Error('source absente');
      expect(Buffer.from(textBytes(c.input ?? '', c.inputEncoding)).equals(Buffer.from(source.rest)), c.id).toBe(true);
      expect(Buffer.from(sourceBytes(c.repeat, source.rest)).equals(Buffer.from(source.bytes)), c.id).toBe(true);
      expect(c.repeat, c.id).toEqual(source.repeat);
      expect(c.languageId, c.id).toEqual(source.languageId);
      const redacted = c.expected.redacted;
      const bytes = redacted?.text === undefined ? null : textBytes(redacted.text, redacted.textEncoding);
      // L'intention se relit sur le fichier (nombre de libellés : quand le texte masqué y est écrit).
      if (bytes !== null || source.intent.minLabels === undefined) expect(intentProblem(source, c.expected, bytes), c.id).toBeUndefined();
    });
    const spans = spanSources();
    expect(redact.spanCases.map((c) => c.id)).toEqual(spans.map((s) => s.id));
    redact.spanCases.forEach((c, index) => {
      const source = spans[index];
      expect(Buffer.from(textBytes(c.content, c.contentEncoding)).equals(Buffer.from(source?.bytes ?? [])), c.id).toBe(true);
      expect(c.findings, c.id).toEqual(source?.findings);
    });
  });

  it('les cas synthétiques couvrent chaque issue, chaque étape d’analyse incomplète, et le test d’origine des étendues', () => {
    const failures = new Set(redact.cases.map((c) => c.expected.failure));
    expect([...failures].sort()).toEqual([...SANITIZE_FAILURES].sort());
    const synthetic = redactSources();
    expect(synthetic.some((s) => s.intent.incompleteAt === 'initial')).toBe(true);
    expect(synthetic.some((s) => s.intent.incompleteAt === 'final')).toBe(true);
    expect(synthetic.some((s) => s.intent.adjacent === true)).toBe(true);
    const upstreamTest = redact.spanCases.find((c) => c.id === 'spans/overlap-and-adjacent');
    expect(upstreamTest?.redacted.text).toBe('01<REDACTED_left>9');
  });

  it('les fichiers sont dans l’écriture canonique du générateur (la régénération octet pour octet se vérifie par --check)', () => {
    expect(serializeRedactVectors(redact)).toBe(redactText);
    expect(serializeDecisionVectors(decision)).toBe(decisionText);
  });
});

describe('vecteurs des niveaux et décisions commités', () => {
  it('chaque score entier de -5 à 105 a son niveau et son score borné, chaque niveau sa décision', () => {
    expect(decision.formatVersion).toBe(1);
    expect(decision.upstreamCommit).toBe(UPSTREAM_COMMIT);
    expect(decision.scores.map((s) => s.score)).toEqual(
      Array.from({ length: SCORE_RANGE.to - SCORE_RANGE.from + 1 }, (_, i) => SCORE_RANGE.from + i),
    );
    for (const s of decision.scores) {
      expect(s.level, String(s.score)).toBe(levelForScore(s.score));
      expect(s.bounded, String(s.score)).toBe(Math.max(0, Math.min(100, s.score)));
    }
    expect(decision.levels).toEqual([
      { level: 'LOW', decision: 'ALLOW' },
      { level: 'MEDIUM', decision: 'WARN' },
      { level: 'HIGH', decision: 'BLOCK' },
      { level: 'CRITICAL', decision: 'BLOCK' },
    ]);
    expect(LEVELS).toHaveLength(4);
    expect(DECISIONS).toHaveLength(3);
  });

  it('decisionVectors refuse un niveau ou une décision hors liste', () => {
    const engine = { levelForScore, decisionForLevel: () => 'ALLOW', boundedScore: (score: number) => score };
    expect(decisionVectors(engine, 'x').scores).toHaveLength(111);
    expect(() => decisionVectors({ ...engine, levelForScore: () => 'NONE' }, 'x')).toThrow(RedactVectorError);
    expect(() => decisionVectors({ ...engine, decisionForLevel: () => 'MAYBE' }, 'x')).toThrow(RedactVectorError);
    expect(() => decisionVectors({ ...engine, boundedScore: () => 0.5 }, 'x')).toThrow(RedactVectorError);
  });
});

describe('recherche de secrets des vecteurs du masquage', () => {
  it('vectors/redact.json est exempté par un chemin exact ; vectors/decision.json reste analysé', () => {
    const config = parseToml(readFileSync(new URL('../../.gitleaks.toml', import.meta.url), 'utf8')) as Record<string, unknown>;
    const patterns = ((config['allowlists'] ?? []) as Record<string, unknown>[])
      .flatMap((allowlist) => allowlist['paths'] as string[])
      .map((source) => new RegExp(source));
    const exempted = (path: string): boolean => patterns.some((pattern) => pattern.test(path));
    expect(exempted('vectors/redact.json')).toBe(true);
    for (const path of ['vectors/decision.json', 'vectors/redact.json.bak', 'vectors/redact-x.json', 'generator/redact/cases.ts']) {
      expect(exempted(path), path).toBe(false);
    }
  });
});

describe('outils des vecteurs du masquage', () => {
  it('fusion et nommage : copie de redact (étendues triées, contiguës fusionnées, nom du premier, unité UTF-16)', () => {
    const f = (ruleId: string, start: number, end: number, score = 70) => ({ ruleId, score, start, end });
    const spans = mergeSpans([f('adjacent', 8, 9), f('overlap', 4, 8), f('left', 2, 6), f('empty', 3, 3), f('out', 9, 12)], 10);
    expect(spans).toEqual([{ start: 2, end: 9, name: 'left' }]);
    expect(rebuildText('0123456789', spans)).toBe('01<REDACTED_left>9');
    expect(mergeSpans([f('low', 2, 6, 10), f('high', 2, 6, 90)], 10)[0]?.name).toBe('high');
    expect(placeholderName('a-b.c\u{1f600}é z')).toBe('a_b_c____z');
  });

  it('positions en octets ↔ UTF-16 ; octets hors UTF-8 gardés hors des étendues', () => {
    const bytes = Uint8Array.from([0xff, 0x61, 0xc3, 0xa9, 0xf0, 0x9f, 0x98, 0x80, 0x62]);
    const decoded = decodeInput(bytes);
    expect(utf16OffsetOf(decoded, 2)).toBe(2);
    expect(utf16OffsetOf(decoded, 4)).toBe(3);
    expect(utf16OffsetOf(decoded, 8)).toBe(5);
    expect(() => utf16OffsetOf(decoded, 3)).toThrow(RangeError);
    expect(() => utf16OffsetOf(decoded, 5)).toThrow(RangeError);
    const out = rebuildBytes(bytes, decoded, [{ start: 3, end: 5, name: 'x' }]);
    expect([...out]).toEqual([0xff, 0x61, 0xc3, 0xa9, ...new TextEncoder().encode('<REDACTED_x>'), 0x62]);
  });

  it('describeText écrit le texte court (UTF-8 ou base64), seulement la taille et le SHA-256 au-delà', () => {
    expect(describeText(new TextEncoder().encode('é'))).toMatchObject({ bytes: 2, text: 'é', textEncoding: 'utf8' });
    expect(describeText(Uint8Array.from([0xff]))).toMatchObject({ bytes: 1, text: '/w==', textEncoding: 'base64' });
    expect(describeText(new Uint8Array(INLINE_TEXT_MAX_BYTES + 1)).text).toBeUndefined();
  });

  it('filledPrefix construit une entrée d’exactement la taille demandée', () => {
    const { repeat, rest } = filledPrefix(1_000, '\ntail\n');
    expect(sourceBytes(repeat, new TextEncoder().encode(rest)).length).toBe(1_000);
  });

  it('redactExpectedFor : issues, reconstruction vérifiée, texte rendu contrôlé', () => {
    const finding = { ruleId: 'r', secretType: 'generic_secret', encoding: 'plain', score: 70, level: 'HIGH' };
    const scanResults = new Map<string, EngineResult>([
      ['ab SECRET cd', { complete: true, findings: [{ ...finding, start: 3, end: 9 }] }],
      ['ab <REDACTED_r> cd', { complete: true, findings: [] }],
      ['big', { complete: false, findings: [{ ...finding, ruleId: 'scan_limit', secretType: 'scan_limit', start: 0, end: 0, score: 100, level: 'CRITICAL' }] }],
    ]);
    const scanEngine = {
      scan: (content: string) => scanResults.get(content) ?? { complete: true, findings: [] },
    } as unknown as UpstreamEngine;
    const engine = (content: string, redacted: string | undefined): RedactEngine => ({
      redact: () => '',
      redactAndRescan: (text) => ({
        content,
        initial: scanEngine.scan(text, undefined),
        final: redacted === undefined ? scanEngine.scan(text, undefined) : scanEngine.scan(redacted, undefined),
        ...(redacted === undefined ? {} : { redacted }),
      }),
    });
    const input = new TextEncoder().encode('ab SECRET cd');
    const ok = redactExpectedFor(scanEngine, engine('ab <REDACTED_r> cd', 'ab <REDACTED_r> cd'), input, undefined);
    expect(ok.expected).toMatchObject({ failure: 'none', final: { complete: true, findings: [] } });
    expect(Buffer.from(ok.redacted ?? []).toString()).toBe('ab <REDACTED_r> cd');
    const incomplete = redactExpectedFor(scanEngine, engine('', undefined), new TextEncoder().encode('big'), undefined);
    expect(incomplete.expected).toMatchObject({ failure: 'incomplete', redacted: null, final: null });
    // Texte de redact différent de sa reconstruction.
    expect(() => redactExpectedFor(scanEngine, engine('', 'ab <REDACTED_x> cd'), input, undefined)).toThrow(RedactVectorError);
    // Texte rendu alors que l'issue n'est pas none (constats LOW de l'origine : écart documenté).
    scanResults.set('ab <REDACTED_r> cd', { complete: true, findings: [{ ...finding, score: 10, level: 'LOW', start: 0, end: 2 }] });
    expect(() => redactExpectedFor(scanEngine, engine('ab <REDACTED_r> cd', 'ab <REDACTED_r> cd'), input, undefined)).toThrow(
      /constats LOW/,
    );
    const residual = redactExpectedFor(scanEngine, engine('', 'ab <REDACTED_r> cd'), input, undefined);
    expect(residual.expected.failure).toBe('residual');
  });
});
