import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { buildInitialPack } from '../rule-pack/catalog.ts';
import { AUXILIARY_PATTERNS, buildEnginePatternsGo, isEngineRule } from '../rule-pack/engine-patterns.ts';
import { translateJsPattern } from '../rule-pack/js-to-re2.ts';

const upstream = readFileSync(new URL('../../pack/initial/upstream/rules.ts.txt', import.meta.url), 'utf8');
const committed = readFileSync(new URL('../../detect/engine_patterns.go', import.meta.url), 'utf8');

describe('motifs du moteur de détection Go', () => {
  it('les motifs du moteur Go sont ceux du générateur (npm run pack:initial)', () => {
    expect(committed).toBe(buildEnginePatternsGo(upstream));
  });

  it('chaque motif auxiliaire est un littéral de rules.ts, traduit par la traduction du Pack', () => {
    for (const pattern of AUXILIARY_PATTERNS) {
      expect(upstream.includes(pattern.literal), pattern.name).toBe(true);
      const close = pattern.literal.lastIndexOf('/');
      const translated = translateJsPattern(pattern.literal.slice(1, close), pattern.literal.slice(close + 1)).pattern;
      expect(committed.includes(`const ${pattern.name} = ${JSON.stringify(pattern.lineSeparators === true ? translated.replace('(?m)(?:^|', '(?m)(?:^|[\\x{2028}\\x{2029}]|') : translated)}`)).toBe(true);
    }
    expect(new Set(AUXILIARY_PATTERNS.map((pattern) => pattern.name)).size).toBe(AUXILIARY_PATTERNS.length);
  });

  it('le moteur porte la logique des familles autres que « motif seul » et de jwt, chacune une fois', () => {
    const engine = buildInitialPack(upstream).rules.filter(isEngineRule);
    expect(engine.map((rule) => rule.ruleId)).toContain('jwt');
    expect(engine.filter((rule) => rule.family === 'fixed_pattern').map((rule) => rule.ruleId)).toEqual(['jwt']);
    for (const rule of engine) {
      expect(committed).toContain(`{ruleID: ${JSON.stringify(rule.ruleId)}, family: ${JSON.stringify(rule.family)},`);
    }
  });

  it('un motif auxiliaire absent de rules.ts arrête le générateur', () => {
    expect(() => buildEnginePatternsGo(upstream.replace('/^(?:example|placeholder|redacted)$/i', '/^(?:example)$/i'))).toThrow(/absent de rules\.ts/);
  });
});
