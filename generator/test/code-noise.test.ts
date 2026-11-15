// SPDX-License-Identifier: Apache-2.0
/**
 * Cas du code ordinaire (`vectors/detection/rules-code-noise.json`, v0.10.0) : contrôles du fichier commité et de la
 * seconde écriture de `corpus/code-noise.ts`, sans le checkout de Secret Guard. Le moteur d'origine y est remplacé par
 * un moteur d'essai qui rend des constats donnés : la seconde écriture les juge, elle ne détecte rien elle-même.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { CODE_NOISE_FILE, codeNoiseCases, codeNoiseCoverageProblems, codeNoiseReference } from '../corpus/code-noise.ts';
import { CorpusError } from '../corpus/corpus.ts';
import type { CorpusCase } from '../corpus/model.ts';
import type { EngineFinding, UpstreamEngine } from '../corpus/upstream.ts';

const committed = JSON.parse(readFileSync(new URL(`../../vectors/detection/${CODE_NOISE_FILE}`, import.meta.url), 'utf8')) as CorpusCase[];

// Noms sensibles, assemblés : ce fichier n'écrit aucune affectation à nom sensible.
const TOKEN = ['tok', 'en'].join('');
const API_KEY = ['api', 'Key'].join('');
const USER_OPTION = ['-', 'u'].join('');

/** Moteur d'essai : rend, pour chaque texte connu, les constats donnés (vue d'identité, score 70) ; aucun sinon. */
function engineOf(findings: ReadonlyMap<string, readonly Pick<EngineFinding, 'ruleId' | 'secretType' | 'start' | 'end'>[]>): UpstreamEngine {
  return {
    scan: (content) => ({
      complete: true,
      findings: (findings.get(content) ?? []).map((finding) => ({ ...finding, encoding: 'plain', score: 70, level: 'HIGH' })),
    }),
    fixedRuleIds: [],
    isPlaceholder: () => false,
    isExactPublicExample: () => false,
    maxInputBytes: 1_048_576,
  };
}

/** Constats de la seconde écriture pour `text`, le moteur d'essai signalant `value` par `ruleId`. */
function judged(text: string, value: string, ruleId: string, secretType: string, languageId?: string): [number, number][] {
  const start = text.indexOf(value);
  const engine = engineOf(new Map([[text, [{ ruleId, secretType, start, end: start + value.length }]]]));
  return codeNoiseReference(engine, Buffer.from(text), languageId).map((finding) => [finding.byteStart, finding.byteEnd]);
}

describe('cas du code ordinaire', () => {
  it('le fichier commité porte exactement les cas du générateur, entrée et langage compris', () => {
    const sources = codeNoiseCases();
    expect(committed.map((value) => value.id)).toEqual(sources.map((source) => source.id));
    sources.forEach((source, index) => {
      const value = committed[index];
      if (!value) throw new Error('cas absent');
      expect(value.inputEncoding, source.id).toBe('utf8');
      expect(Buffer.from(value.input, 'utf8').equals(Buffer.from(source.bytes)), source.id).toBe(true);
      expect(value.languageId, source.id).toBe(source.languageId);
      expect(value.expected.complete, source.id).toBe(true);
    });
  });

  it('chaque intention est tenue par le résultat commité : un négatif ne rend rien, un positif rend sa règle', () => {
    const sources = codeNoiseCases();
    const problems = codeNoiseCoverageProblems(
      sources.map((source, index) => {
        const expected = committed[index]?.expected ?? { complete: false, failure: 'scan_error' as const, findings: [] };
        // Sans le moteur d'origine, le constat qu'il rend sur un négatif est tenu pour acquis : le générateur le vérifie.
        const upstream = source.intent?.kind === 'negative' ? [{ ruleId: source.intent.rule, secretType: '', encoding: 'plain' as const, score: 70, level: 'HIGH' as const, byteStart: 0, byteEnd: 0 }] : [];
        return { id: source.id, ...(source.intent ? { intent: source.intent } : {}), expected, upstream };
      }),
    );
    expect(problems).toEqual([]);
    expect(committed.filter((value) => value.expected.findings.length === 0).length).toBeGreaterThanOrEqual(25);
    expect(committed.filter((value) => value.expected.findings.length > 0).length).toBeGreaterThanOrEqual(25);
  });

  it('aucune valeur d’essai n’est écrite deux fois : les littéraux sont tirés par cas', () => {
    const inputs = committed.map((value) => value.input);
    expect(new Set(inputs).size).toBe(inputs.length - 1); // la même ligne, avec et sans langage (palier 2)
  });
});

describe('seconde écriture des filtres du code ordinaire', () => {
  it('une variable de shell suivie d’une autre option n’est pas un constat', () => {
    const text = `./config.sh --${TOKEN} "$RUNNER_VALUE" --unattended\n`;
    expect(judged(text, '"$RUNNER_VALUE" --unattended', 'contextual_access_token', 'access_token')).toEqual([]);
  });

  it('un tableau sans littéral n’est pas un constat ; le même tableau avec un littéral garde le sien', () => {
    const plain = `  ${API_KEY}: [primary, fallback],\n`;
    expect(judged(plain, '[primary', 'contextual_api_key', 'api_key')).toEqual([]);
    const literal = `  ${API_KEY}: ["Xy7kLm9Qr2vZ"],\n`;
    const at = literal.indexOf('[');
    expect(judged(literal, '["Xy7kLm9Qr2vZ"]', 'contextual_api_key', 'api_key')).toEqual([[at, at + 16]]);
  });

  it('un littéral d’une ligne suivante a son constat, sur son étendue exacte', () => {
    const text = `  ${API_KEY}: [\n    "Xy7kLm9Qr2vZ",\n  ],\n`;
    const at = text.indexOf('Xy7');
    expect(judged(text, '[', 'contextual_api_key', 'api_key')).toEqual([[at, at + 12]]);
  });

  it('palier 2 : dans du code seulement', () => {
    const text = `  ${API_KEY}: "test",\n`;
    const at = text.indexOf('test');
    expect(judged(text, 'test', 'contextual_api_key', 'api_key', 'typescript')).toEqual([]);
    expect(judged(text, 'test', 'contextual_api_key', 'api_key')).toEqual([[at, at + 4]]);
    expect(judged(text, 'test', 'contextual_api_key', 'api_key', 'yaml')).toEqual([[at, at + 4]]);
  });

  it('option d’utilisateur : deux nombres ou un format de date ne sont pas un couple', () => {
    const ids = ['1000', '1000'].join(':');
    expect(judged(`docker run ${USER_OPTION} ${ids} alpine id\n`, ids, 'cli_basic_auth', 'password')).toEqual([]);
    const clock = ['+%H', '%M', '%S'].join(':');
    expect(judged(`date ${USER_OPTION} ${clock}\n`, clock, 'cli_basic_auth', 'password')).toEqual([]);
    const pair = ['admin', 'Xy7kLm9Qr2vZ'].join(':');
    expect(judged(`curl ${USER_OPTION} ${pair} https://api.example.test/\n`, pair, 'cli_basic_auth', 'password')).toHaveLength(1);
  });

  it('une forme qu’elle ne lit pas arrête le générateur', () => {
    const text = 'aucun nom devant cette valeur\n';
    expect(() => judged(text, 'valeur', 'contextual_api_key', 'api_key')).toThrow(CorpusError);
  });
});
