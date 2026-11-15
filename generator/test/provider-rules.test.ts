// SPDX-License-Identifier: Apache-2.0
/**
 * Règles de fournisseurs (v0.10.0) : vraisemblance d'un jeton, cas de bruit, banc de comparaison Betterleaks.
 * Contrôles sans le clone de Betterleaks ni le checkout de Secret Guard : la régénération du banc et sa comparaison
 * octet pour octet se font par `node corpus/betterleaks.ts --clone <clone> [--check]`.
 */
import { readFileSync } from 'node:fs';
import { parse as parseToml } from 'smol-toml';
import { describe, expect, it } from 'vitest';
import {
  BETTERLEAKS_COMMIT,
  BETTERLEAKS_LICENSE,
  BETTERLEAKS_REPOSITORY,
  BETTERLEAKS_RULES_DIGEST,
  casesOfSource,
  COMPARISON_FORMAT_VERSION,
  parseGoString,
  parseLiteralArguments,
  rulesDigest,
  serializeComparison,
  type ComparisonCase,
} from '../corpus/betterleaks.ts';
import { serializeProviderNoise } from '../corpus/provider-noise.ts';
import { PROVIDER_NOISE_ASSIGNMENT_FORM, providerNoiseCases, providerNoiseText } from '../corpus/provider-rules.ts';
import {
  plausibleToken,
  PROVIDER_ENTROPY_FLOOR,
  PROVIDER_MIN_DISTINCT,
  PROVIDER_RULE_SOURCES,
  PROVIDER_RULES,
  providerEntropyFloor,
  providerPatternMatches,
  providerReferenceFindings,
  tokenDiversity,
  type SamplePart,
} from '../rule-pack/provider-rules.ts';
import { RULE_VALIDATORS } from '../src/rule-pack.ts';

const REPOSITORY = new URL('../../', import.meta.url);
const read = (path: string): string => readFileSync(new URL(path, REPOSITORY), 'utf8');

/** Générateur pseudo-aléatoire déterministe (mulberry32) : les tirages de ce fichier ne changent jamais. */
function generator(seed: number): () => number {
  let state = seed;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Alphabet d'une clé réelle : un alphabet hexadécimal des deux casses (motif qui replie la casse) est tiré dans une
 * seule casse, comme l'écrit un fournisseur ; c'est le cas le moins divers.
 */
function realisticAlphabet(alphabet: string): string {
  return /^[0-9a-fA-F]+$/.test(alphabet) && /[a-f]/.test(alphabet) && /[A-F]/.test(alphabet) ? [...new Set(alphabet.toLowerCase())].join('') : alphabet;
}

function draw(parts: readonly SamplePart[], random: () => number): string {
  let value = '';
  for (const part of parts) {
    if ('lit' in part) value += part.lit;
    else {
      const alphabet = realisticAlphabet(part.alphabet);
      for (let index = 0; index < part.length; index += 1) value += alphabet[Math.floor(random() * alphabet.length)] ?? '';
    }
  }
  return value;
}

describe('vraisemblance des règles de fournisseurs', () => {
  it('une valeur de moins de 6 caractères distincts ou d’entropie inférieure au seuil n’est pas un jeton', () => {
    expect(PROVIDER_MIN_DISTINCT).toBe(6);
    expect(PROVIDER_ENTROPY_FLOOR).toBe(30);
    const eight = 'abcdefgh'.repeat(4);
    const sixteen = '0123456789abcdef'.repeat(2);
    expect(tokenDiversity(eight)).toEqual({ distinct: 8, entropy: 3 });
    expect(tokenDiversity(sixteen)).toEqual({ distinct: 16, entropy: 4 });
    const cases: [string, number, boolean][] = [
      ['a'.repeat(40), 30, false],
      ['0'.repeat(32), 30, false],
      ['abcde'.repeat(8), 25, false],
      ['abcdef'.repeat(6), 30, false],
      ['abcdef'.repeat(6), 25, true],
      [eight, 30, true],
      [eight, 31, false],
      [sixteen, 40, true],
      [sixteen, 41, false],
      [`${'a'.repeat(33)}bcdefgh`, 30, false],
    ];
    for (const [value, floor, expected] of cases) expect(plausibleToken(value, floor), `${String(value.length)} caractères, seuil ${String(floor)}`).toBe(expected);
    expect(() => tokenDiversity('clé')).toThrow();
  });

  it('chaque règle à proximité porte un validateur de vraisemblance de la liste fermée ; une règle à préfixe fixe garde le seuil d’office', () => {
    const closed = RULE_VALIDATORS as readonly string[];
    const named = closed.filter((name) => name.startsWith('token_entropy_'));
    expect(named).toEqual(Array.from({ length: 21 }, (_, index) => `token_entropy_${String(25 + index)}`));
    for (const rule of PROVIDER_RULE_SOURCES) {
      if (rule.score === 80) {
        expect(rule.validator, rule.ruleId).toMatch(/^token_entropy_[0-9]{2}$/);
        expect(closed, rule.ruleId).toContain(rule.validator);
      } else {
        expect(rule.score, rule.ruleId).toBe(95);
        expect(rule.validator, rule.ruleId).toBeUndefined();
        expect(providerEntropyFloor(rule), rule.ruleId).toBe(PROVIDER_ENTROPY_FLOOR);
      }
    }
    expect(PROVIDER_RULES.map((rule) => rule.validator)).toEqual(PROVIDER_RULE_SOURCES.map((rule) => rule.validator ?? ''));
    expect(() => providerEntropyFloor({ ruleId: 'demo', validator: 'jwt_structure' })).toThrow();
  });

  // Garde de rappel : un seuil trop haut pour la forme d'une clé (20 chiffres hexadécimaux sous un seuil de 3,5, par
  // exemple) écarterait de vraies clés. 4 000 valeurs tirées de la forme de chaque règle : 99,5 % au moins passent.
  it('le seuil de chaque règle laisse passer une valeur tirée au hasard de la forme de son motif', () => {
    const random = generator(0x5eed);
    const draws = 4_000;
    const losses: string[] = [];
    for (const rule of PROVIDER_RULE_SOURCES) {
      const floor = providerEntropyFloor(rule);
      let rejected = 0;
      for (let index = 0; index < draws; index += 1) {
        if (!plausibleToken(draw(rule.sample.value, random), floor)) rejected += 1;
      }
      if (rejected > draws * 0.005) losses.push(`${rule.ruleId} : ${String(rejected)} valeurs sur ${String(draws)} écartées au seuil ${String(floor)}`);
    }
    expect(losses).toEqual([]);
  });
});

describe('bruit des règles de fournisseurs', () => {
  const committed = read('vectors/noise-providers.json');

  it('le fichier commité est exactement celui du générateur, au format du corpus de bruit', () => {
    expect(committed).toBe(serializeProviderNoise());
    const parsed = JSON.parse(committed) as { formatVersion: number; about: string; cases: { id: string; input: string }[] };
    expect(parsed.formatVersion).toBe(1);
    expect(parsed.cases.map((entry) => Object.keys(entry))).toEqual(parsed.cases.map(() => ['id', 'input']));
    expect(new Set(parsed.cases.map((entry) => entry.id)).size).toBe(parsed.cases.length);
  });

  it('chaque cas a la forme du motif de sa règle (qui le reconnaît) et la lecture de référence n’y trouve rien', () => {
    const { cases, unmatched, plausible } = providerNoiseCases();
    const byId = new Map(PROVIDER_RULE_SOURCES.map((rule) => [rule.ruleId, rule]));
    for (const entry of cases) {
      const rule = byId.get(entry.id.split('/')[1] ?? '');
      if (rule === undefined) throw new Error(`règle inconnue : ${entry.id}`);
      expect(entry.input, entry.id).toBe(providerNoiseText(rule));
      expect(providerPatternMatches(entry.input).some((found) => found.rule.ruleId === rule.ruleId), entry.id).toBe(true);
      expect(providerReferenceFindings(entry.input), entry.id).toEqual([]);
    }
    for (const id of PROVIDER_NOISE_ASSIGNMENT_FORM) expect(byId.has(id), id).toBe(true);
    // Chaque règle a son cas, sauf exemption motivée ; aucun motif ne refuse une valeur à caractère répété.
    expect(unmatched).toEqual([]);
    expect(cases.length + plausible.length + PROVIDER_NOISE_ASSIGNMENT_FORM.length).toBe(PROVIDER_RULE_SOURCES.length);
    // Adresses de webhook : les littéraux de l'adresse portent la diversité, la règle se déclenche encore.
    expect(plausible).toEqual(['slack_workflow_webhook', 'slack_trigger_url']);
  });
});

describe('banc de comparaison Betterleaks', () => {
  const text = (bytes: readonly number[]): string => Buffer.from(bytes).toString('utf8');

  it('lit un littéral de chaîne Go, brut ou interprété, et rien d’autre', () => {
    expect(text(parseGoString('`a\\n"b`', 0)?.bytes ?? [])).toBe('a\\n"b');
    expect(text(parseGoString('`a\r\nb`', 0)?.bytes ?? [])).toBe('a\nb');
    expect(text(parseGoString('"a\\tb\\"c\\\\d\\x41\\u00e9\\101"', 0)?.bytes ?? [])).toBe('a\tb"c\\dAéA');
    expect(parseGoString('"ab" + x', 0)?.next).toBe(4);
    expect(parseGoString('name', 0)).toBeUndefined();
    expect(() => parseGoString('"ouverte', 0)).toThrow();
    expect(() => parseGoString('"\\q"', 0)).toThrow();
  });

  it('lit les arguments littéraux d’un appel, joints par +, et refuse tout autre argument', () => {
    expect(parseLiteralArguments('"a", "b" + `c`,\n\t// note\n\t"d")', 0)).toEqual(['a', 'bc', 'd']);
    expect(parseLiteralArguments('"a", "b",)', 0)).toEqual(['a', 'b']);
    expect(parseLiteralArguments('"a", value)', 0)).toBeUndefined();
    expect(parseLiteralArguments('"a", fmt.Sprintf("b"))', 0)).toBeUndefined();
    expect(parseLiteralArguments(')', 0)).toBeUndefined();
  });

  it('rattache chaque cas à la règle qui le précède et compte les appels non lus', () => {
    const source = [
      'var _ = rulebuilder.Add(config.Rule{',
      '\tID: "demo-one",',
      '\tTests: []config.RuleTest{',
      '\t\trulebuilder.Match("positif", "x=" + "abc", "abc"),',
      '\t\trulebuilder.NoMatch("négatif", `x=`),',
      '\t\trulebuilder.Match("non lu", value, "abc"),',
      '\t},',
      '})',
      'var _ = rulebuilder.Add(config.Rule{',
      '\tID: "demo-two",',
      '\tTests: []config.RuleTest{',
      '\t\trulebuilder.MatchComponent("composant", "id abc", "abc"),',
      '\t\trulebuilder.NoMatchComponent("composant négatif", "id"),',
      '\t},',
      '})',
    ].join('\n');
    const read = casesOfSource('rules/demo.go', source);
    expect(read.unread).toBe(1);
    expect(read.cases).toEqual([
      { rule: 'demo-one', file: 'rules/demo.go', kind: 'match', name: 'positif', input: 'x=abc', secret: 'abc' },
      { rule: 'demo-one', file: 'rules/demo.go', kind: 'no_match', name: 'négatif', input: 'x=', secret: '' },
      { rule: 'demo-two', file: 'rules/demo.go', kind: 'match_component', name: 'composant', input: 'id abc', secret: 'abc' },
      { rule: 'demo-two', file: 'rules/demo.go', kind: 'no_match_component', name: 'composant négatif', input: 'id', secret: '' },
    ]);
  });

  it('l’empreinte des règles dépend du chemin et du contenu de chaque fichier', () => {
    const a = rulesDigest([['rules/a.go', Buffer.from('x')]]);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(rulesDigest([['rules/b.go', Buffer.from('x')]])).not.toBe(a);
    expect(rulesDigest([['rules/a.go', Buffer.from('y')]])).not.toBe(a);
  });

  it('le fichier commité vient du commit épinglé : 1 880 cas, écrits dans la forme du générateur', () => {
    const committed = read('vectors/comparison/betterleaks.json');
    const parsed = JSON.parse(committed) as {
      formatVersion: number;
      source: { repository: string; commit: string; license: string; rulesDigest: string; unreadCalls: number };
      cases: ComparisonCase[];
    };
    expect(parsed.formatVersion).toBe(COMPARISON_FORMAT_VERSION);
    expect(parsed.source).toEqual({
      repository: BETTERLEAKS_REPOSITORY,
      commit: BETTERLEAKS_COMMIT,
      license: BETTERLEAKS_LICENSE,
      rulesDigest: BETTERLEAKS_RULES_DIGEST,
      unreadCalls: 17,
    });
    expect(BETTERLEAKS_COMMIT).toMatch(/^b4b1c44[0-9a-f]{33}$/);
    expect(parsed.cases).toHaveLength(1_880);
    const count = (kind: string): number => parsed.cases.filter((entry) => entry.kind === kind).length;
    expect([count('match'), count('no_match'), count('match_component'), count('no_match_component')]).toEqual([867, 858, 82, 73]);
    expect(new Set(parsed.cases.map((entry) => entry.id)).size).toBe(1_880);
    expect(new Set(parsed.cases.map((entry) => entry.rule)).size).toBe(464);
    for (const entry of parsed.cases) {
      const positive = entry.kind === 'match' || entry.kind === 'match_component';
      expect(positive ? entry.secret !== '' && entry.input.includes(entry.secret) : entry.secret === '', entry.id).toBe(true);
      expect(entry.file, entry.id).toMatch(/^rules\/(?:generic\/)?[a-z0-9_]+\.go$/);
    }
    // Réécriture à l'identique : le fichier n'a pas été retouché à la main.
    expect(serializeComparison({ cases: parsed.cases, unread: parsed.source.unreadCalls, digest: parsed.source.rulesDigest })).toBe(committed);
  });

  it('le banc et le bruit des règles de fournisseurs sont exemptés de la recherche de secrets par leur chemin exact', () => {
    const config = parseToml(read('.gitleaks.toml')) as { allowlists?: { paths?: string[] }[] };
    const paths = (config.allowlists ?? []).flatMap((allowlist) => allowlist.paths ?? []);
    expect(paths).toContain('^vectors/comparison/betterleaks\\.json$');
    expect(paths).toContain('^vectors/noise-providers\\.json$');
  });
});
