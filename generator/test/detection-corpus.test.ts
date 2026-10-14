/**
 * Corpus de parité de détection : contrôles du corpus commité, sans le checkout de Secret Guard (le résultat attendu
 * vient du moteur d'origine ; la régénération et sa comparaison octet pour octet se font par
 * `npm run vectors:detection -- --upstream <checkout> [--check]`).
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parse as parseToml } from 'smol-toml';
import { describe, expect, it } from 'vitest';
import { UPSTREAM_COMMIT as PACK_UPSTREAM_COMMIT } from '../rule-pack/catalog.ts';
import { RulePack } from '../src/rule-pack.ts';
import { byteOffsetOf, decodeInput } from '../corpus/bytes.ts';
import { CorpusError, coverageProblems, expectedFor, type CoverageInput, type EvaluatedCase } from '../corpus/corpus.ts';
import { jsonString, serializeCaseFile } from '../corpus/json.ts';
import type { RecordedTest } from '../corpus/harness.ts';
import { TESTS_WITHOUT_INPUT, upstreamSources } from '../corpus/main.ts';
import {
  CASE_FILE_PATTERN,
  compareFindings,
  CORPUS_FORMAT_VERSION,
  FINDING_ENCODINGS,
  INPUT_ENCODINGS,
  levelForScore,
  MANIFEST_FILE,
  MAX_INPUT_BYTES,
  SCAN_FAILURES,
  type CorpusCase,
  type CorpusFinding,
} from '../corpus/model.ts';
import {
  DEFAULT_IGNORABLES,
  FIXED_RULE_ORDER,
  JS_ONLY_SPACES,
  PLACEHOLDER_NOT_APPLICABLE,
  PUBLIC_EXAMPLE_NOT_APPLICABLE,
  PUBLIC_EXAMPLES,
  syntheticCases,
} from '../corpus/synthetic.ts';
import {
  importSpecifiers,
  moduleImports,
  readPinnedFiles,
  rewriteImports,
  UPSTREAM_COMMIT,
  UPSTREAM_FILES,
  UPSTREAM_TEST_FILES,
  UpstreamError,
  type EngineFinding,
  type UpstreamEngine,
} from '../corpus/upstream.ts';

const CORPUS = new URL('../../vectors/detection/', import.meta.url);
const REPOSITORY = new URL('../../', import.meta.url);
const read = (url: URL): string => readFileSync(url, 'utf8');

const manifestText = read(new URL(MANIFEST_FILE, CORPUS));
const manifest = JSON.parse(manifestText) as {
  formatVersion: unknown;
  upstreamCommit: unknown;
  files: { file: string; cases: number }[];
};
const fileTexts = new Map(manifest.files.map((entry) => [entry.file, read(new URL(entry.file, CORPUS))]));
const corpus = new Map([...fileTexts].map(([file, text]) => [file, JSON.parse(text) as CorpusCase[]]));
const allCases = [...corpus.values()].flat();
const packRuleIds = RulePack.parse(JSON.parse(read(new URL('../../pack/initial/pack.json', import.meta.url)))).rules.map(
  (rule) => rule.ruleId,
);

function inputBytes(value: CorpusCase): Uint8Array {
  return value.inputEncoding === 'utf8' ? new TextEncoder().encode(value.input) : Buffer.from(value.input, 'base64');
}

const CASE_KEYS = ['id', 'input', 'inputEncoding', 'languageId', 'expected'];
const FINDING_KEYS = ['ruleId', 'secretType', 'encoding', 'score', 'level', 'byteStart', 'byteEnd'];

describe('corpus de parité commité', () => {
  it('le manifeste donne le nombre de cas de chaque fichier du dossier', () => {
    expect(manifest.formatVersion).toBe(CORPUS_FORMAT_VERSION);
    expect(manifest.upstreamCommit).toBe(UPSTREAM_COMMIT);
    const onDisk = readdirSync(CORPUS, { withFileTypes: true })
      .filter((entry) => entry.isFile())
      .map((entry) => entry.name)
      .filter((name) => name !== MANIFEST_FILE)
      .sort();
    expect(manifest.files.map((entry) => entry.file)).toEqual(onDisk);
    for (const entry of manifest.files) {
      expect(entry.file).toMatch(CASE_FILE_PATTERN);
      expect(corpus.get(entry.file)?.length, entry.file).toBe(entry.cases);
    }
  });

  it('chaque cas a la forme du contrat, un identifiant unique et ses constats triés en octets', () => {
    const ids = new Set<string>();
    const pack = new Set(packRuleIds);
    for (const value of allCases) {
      expect(ids.has(value.id), value.id).toBe(false);
      ids.add(value.id);
      expect(Object.keys(value).every((key) => CASE_KEYS.includes(key)), value.id).toBe(true);
      expect(INPUT_ENCODINGS).toContain(value.inputEncoding);
      if (value.inputEncoding === 'base64') {
        expect(Buffer.from(value.input, 'base64').toString('base64'), value.id).toBe(value.input);
        expect(decodeInput(inputBytes(value)).validUtf8, value.id).toBe(false);
      } else {
        expect(value.input.isWellFormed(), value.id).toBe(true);
      }
      const { expected } = value;
      expect(Object.keys(expected).sort()).toEqual(['complete', 'failure', 'findings']);
      expect(SCAN_FAILURES).toContain(expected.failure);
      expect(expected.complete, value.id).toBe(expected.failure === 'none');
      if (!expected.complete) expect(expected.findings, value.id).toEqual([]);
      const bytes = inputBytes(value);
      // Entrée hors UTF-8 : frontières des caractères du texte décodé (un U+FFFD par octet invalide).
      const boundaries = value.inputEncoding === 'base64' ? new Set(decodeInput(bytes).byteOffsets) : undefined;
      const sorted = [...expected.findings].sort(compareFindings);
      expect(expected.findings, value.id).toEqual(sorted);
      for (const finding of expected.findings) {
        expect(Object.keys(finding)).toEqual(FINDING_KEYS);
        expect(pack.has(finding.ruleId), `${value.id} : ${finding.ruleId}`).toBe(true);
        expect(FINDING_ENCODINGS).toContain(finding.encoding);
        expect(Number.isInteger(finding.score) && finding.score >= 0 && finding.score <= 100).toBe(true);
        expect(finding.level).toBe(levelForScore(finding.score));
        expect(0 <= finding.byteStart && finding.byteStart <= finding.byteEnd && finding.byteEnd <= bytes.length).toBe(true);
        // Une étendue commence et finit à une frontière de caractère (jamais au milieu d'une séquence UTF-8).
        for (const offset of [finding.byteStart, finding.byteEnd]) {
          if (value.inputEncoding === 'utf8') {
            if (offset < bytes.length) expect((bytes[offset] ?? 0) & 0xc0).not.toBe(0x80);
          } else {
            expect(boundaries?.has(offset), value.id).toBe(true);
          }
        }
      }
    }
  });

  it('les fichiers du corpus sont dans l’écriture canonique du générateur (la régénération octet pour octet se vérifie par --check)', () => {
    for (const [file, cases] of corpus) expect(serializeCaseFile(cases), file).toBe(fileTexts.get(file));
  });

  it('les entrées synthétiques du corpus sont exactement celles du générateur (valeurs générées, aucune copiée)', () => {
    const synthetic = syntheticCases();
    const byId = new Map(allCases.map((value) => [value.id, value]));
    for (const source of synthetic) {
      const committed = byId.get(source.id);
      expect(committed, source.id).toBeDefined();
      if (committed === undefined) continue;
      expect(corpus.get(source.file)?.includes(committed), source.id).toBe(true);
      expect(Buffer.from(inputBytes(committed)).equals(Buffer.from(source.bytes)), source.id).toBe(true);
      expect(committed.languageId, source.id).toBe(source.languageId);
    }
    const others = allCases.filter((value) => !value.id.startsWith('upstream/'));
    expect(others.length).toBe(synthetic.length);
  });

  it('chaque règle du Pack initial a un cas positif, négatif, de valeur fictive et d’exemple public, et chaque vue un cas positif', () => {
    const byId = new Map(allCases.map((value) => [value.id, value]));
    const evaluated: EvaluatedCase[] = syntheticCases().map((source) => ({
      id: source.id,
      ...(source.intent === undefined ? {} : { intent: source.intent }),
      expected: byId.get(source.id)?.expected ?? { complete: false, failure: 'scan_error', findings: [] },
    }));
    const publicExamples: readonly string[] = Object.values(PUBLIC_EXAMPLES);
    const problems = coverageProblems({
      cases: evaluated,
      packRuleIds,
      placeholderNotApplicable: PLACEHOLDER_NOT_APPLICABLE,
      publicExampleNotApplicable: PUBLIC_EXAMPLE_NOT_APPLICABLE,
      engine: {
        fixedRuleIds: FIXED_RULE_ORDER,
        // Vérifiés par le moteur d'origine à la génération ; ici, la valeur fictive est celle de l'intention.
        isPlaceholder: () => true,
        isExactPublicExample: (value) => publicExamples.includes(value),
      },
    });
    expect(problems).toEqual([]);
    for (const view of FINDING_ENCODINGS) {
      expect(
        allCases.some((value) => value.expected.findings.some((finding) => finding.encoding === view)),
        view,
      ).toBe(true);
    }
  });

  it('le corpus contient les cas limites du portage en RE2', () => {
    const sizes = new Map(allCases.map((value) => [value.id, inputBytes(value).length]));
    const exact = allCases.filter((value) => sizes.get(value.id) === MAX_INPUT_BYTES);
    const over = allCases.filter((value) => sizes.get(value.id) === MAX_INPUT_BYTES + 1);
    expect(exact.some((value) => value.expected.complete && value.expected.findings.length > 0)).toBe(true);
    expect(over.length).toBeGreaterThan(0);
    for (const value of over) expect(value.expected).toEqual({ complete: false, failure: 'scan_limit', findings: [] });
    const texts = allCases.map((value) => decodeInput(inputBytes(value)).text);
    expect(texts.some((text) => /[\u{10000}-\u{10ffff}]/u.test(text))).toBe(true);
    for (const character of [...Object.values(JS_ONLY_SPACES), ...Object.values(DEFAULT_IGNORABLES)]) {
      const code = `U+${(character.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}`;
      expect(texts.some((text) => text.includes(character)), code).toBe(true);
    }
    expect(Object.keys(JS_ONLY_SPACES).sort()).toEqual(['u00a0', 'u2028', 'u3000', 'ufeff']);
    expect(Object.keys(DEFAULT_IGNORABLES).sort()).toEqual(['u200b', 'u2060']);
    const longJwt = allCases.some((value) =>
      value.expected.findings.some((finding) => finding.ruleId === 'jwt' && finding.byteEnd - finding.byteStart > 3_000),
    );
    expect(longJwt).toBe(true);
    const quoteForms = ['double-quotes', 'single-quotes', 'no-quotes', 'mismatched-double-single', 'mismatched-single-double'];
    for (const form of quoteForms) expect(allCases.some((value) => value.id === `cli-basic-auth-quotes/${form}`), form).toBe(true);
  });

  it('chaque test repris de Secret Guard figure dans le corpus avec un identifiant qui renvoie au test d’origine', () => {
    const upstream = allCases.filter((value) => value.id.startsWith('upstream/'));
    for (const testFile of UPSTREAM_TEST_FILES) {
      const file = `upstream-${testFile.replace(/\.test\.ts$/, '')}.json`;
      const cases = corpus.get(file) ?? [];
      expect(cases.length, file).toBeGreaterThan(0);
      for (const value of cases) expect(value.id.startsWith(`upstream/${testFile} > `), value.id).toBe(true);
    }
    expect(upstream.length).toBe(UPSTREAM_TEST_FILES.reduce((sum, testFile) => sum + (corpus.get(`upstream-${testFile.replace(/\.test\.ts$/, '')}.json`)?.length ?? 0), 0));
    for (const label of Object.keys(TESTS_WITHOUT_INPUT)) {
      expect(UPSTREAM_TEST_FILES.some((testFile) => label.startsWith(`${testFile} > `)), label).toBe(true);
    }
  });
});

/** Vecteurs du masquage, exemptés de la recherche de secrets par leur chemin exact. */
const REDACT_VECTORS = 'vectors/redact.json';

describe('recherche de secrets', () => {
  const config = parseToml(read(new URL('.gitleaks.toml', REPOSITORY))) as Record<string, unknown>;
  const allowlists = (config['allowlists'] ?? []) as Record<string, unknown>[];
  const fileAllowlists = allowlists.filter((allowlist) => allowlist['targetRules'] === undefined);

  it('les exceptions de fichiers ne couvrent que les cas du corpus et les vecteurs du masquage (le Pack initial et sa copie d’origine restent analysés)', () => {
    expect(Object.keys(config).sort()).toEqual(['allowlists', 'extend']);
    expect(config['extend']).toEqual({ useDefault: true });
    // Ni règle générale (regexes, stopwords, commits, targetRules), ni exception hors de ses chemins.
    expect(fileAllowlists).toHaveLength(2);
    for (const allowlist of fileAllowlists) expect(Object.keys(allowlist).sort()).toEqual(['description', 'paths']);
    const patterns = fileAllowlists.flatMap((allowlist) => allowlist['paths'] as string[]).map((source) => new RegExp(source));
    const tracked = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], {
      cwd: REPOSITORY,
      encoding: 'utf8',
    })
      .split('\0')
      .filter((path) => path !== '');
    const exempted = tracked.filter((path) => patterns.some((pattern) => pattern.test(path)));
    // Vecteurs du masquage : seul autre fichier exempté (test : redact-vectors.test.ts).
    const outside = exempted.filter(
      (path) =>
        path !== REDACT_VECTORS &&
        !(path.startsWith('vectors/detection/') && CASE_FILE_PATTERN.test(path.slice('vectors/detection/'.length))),
    );
    expect(outside).toEqual([]);
    for (const file of corpus.keys()) expect(exempted, file).toContain(`vectors/detection/${file}`);
    expect(exempted).not.toContain(`vectors/detection/${MANIFEST_FILE}`);
    // Le générateur, le moteur, ses tests et le Pack restent analysés.
    expect(exempted.some((path) => !path.startsWith('vectors/detection/') && path !== REDACT_VECTORS)).toBe(false);
  });

  it('la seule exception BMad reconnaît exactement le SHA-256 du modèle, dans son manifeste et pour une seule règle', () => {
    const scoped = allowlists.filter((allowlist) => allowlist['targetRules'] !== undefined);
    expect(scoped).toHaveLength(1);
    const { description, ...criteria } = scoped[0]!;
    expect(typeof description).toBe('string');
    const checksum = createHash('sha256')
      .update(readFileSync(new URL('.agents/skills/bmad-ux/assets/key-screens.md', REPOSITORY)))
      .digest('hex');
    expect(criteria).toEqual({
      targetRules: ['generic-api-key'],
      condition: 'AND',
      paths: ['^_bmad/_config/files-manifest\\.csv$'],
      regexTarget: 'match',
      regexes: [`^key-screens\\.md","${checksum}"$`],
    });
    const manifest = read(new URL('_bmad/_config/files-manifest.csv', REPOSITORY));
    expect(manifest).toContain(`bmad-ux/assets/key-screens.md","${checksum}"`);
  });

  it('aucun fichier .gitleaksignore : pas d’empreinte ignorée hors des exceptions de chemin', () => {
    expect(() => read(new URL('.gitleaksignore', REPOSITORY))).toThrow();
  });
});

describe('outils du générateur', () => {
  it('les octets hors UTF-8 deviennent U+FFFD un par octet, comme Go, et les positions passent en octets', () => {
    const decoded = decodeInput(Uint8Array.from([0x61, 0xe2, 0x82, 0x62, 0xed, 0xa0, 0x80, 0xf0, 0x9f, 0x98, 0x80, 0xc0, 0xaf]));
    expect(decoded.text).toBe('a\ufffd\ufffdb\ufffd\ufffd\ufffd\u{1f600}\ufffd\ufffd');
    expect(decoded.validUtf8).toBe(false);
    expect(byteOffsetOf(decoded, 7)).toBe(7);
    expect(byteOffsetOf(decoded, 9)).toBe(11);
    expect(() => byteOffsetOf(decoded, 8)).toThrow(RangeError);
    expect(() => byteOffsetOf(decoded, 12)).toThrow(RangeError);
    const valid = decodeInput(new TextEncoder().encode('é\u{1f600}\u0000'));
    expect(valid.validUtf8).toBe(true);
    expect([0, 1, 3].map((offset) => byteOffsetOf(valid, offset))).toEqual([0, 2, 6]);
    expect(decodeInput(Uint8Array.from([0xf4, 0x90, 0x80, 0x80])).text).toBe('\ufffd'.repeat(4));
  });

  it('aucun caractère invisible n’est écrit tel quel dans un fichier du corpus', () => {
    expect(jsonString('a"\\\n\r\t\u00a0\u200b\u2028\ufeff\u034f\u0000é\u{1f600}')).toBe(
      '"a\\"\\\\\\n\\r\\t\\u00a0\\u200b\\u2028\\ufeff\\u034f\\u0000é\u{1f600}"',
    );
    for (const [file, text] of fileTexts) {
      expect(/[\p{Cc}\p{Cf}\p{Z}\p{Co}\p{Cn}\p{Default_Ignorable_Code_Point}]/u.test(text.replaceAll('\n', '').replaceAll(' ', '')), file).toBe(false);
    }
  });

  it('le générateur refuse un checkout d’un autre commit et un import dynamique', () => {
    expect(UPSTREAM_COMMIT).toBe(PACK_UPSTREAM_COMMIT);
    const rules = createHash('sha256').update(readFileSync(new URL('../../pack/initial/upstream/rules.ts.txt', import.meta.url))).digest('hex');
    expect(UPSTREAM_FILES['secret-guard/packages/core/src/rules.ts']).toBe(rules);
    const empty = mkdtempSync(join(tmpdir(), 'secret-guard-corpus-test-'));
    try {
      expect(() => readPinnedFiles(empty)).toThrow(UpstreamError);
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
    expect(() => importSpecifiers('const m = await import("x");', 'f.js')).toThrow(UpstreamError);
    expect(importSpecifiers('import { a } from "./a.js";\nexport * from "../b.js";\n', 'f.js')).toEqual(['./a.js', '../b.js']);
  });

  it('le générateur échoue si une règle n’a aucun cas positif', () => {
    const finding: CorpusFinding = {
      ruleId: 'github_token',
      secretType: 'provider_token',
      encoding: 'plain',
      score: 95,
      level: 'CRITICAL',
      byteStart: 0,
      byteEnd: 40,
    };
    const problems = coverageProblems({
      cases: [
        { id: 'p', intent: { kind: 'positive', rule: 'github_token' }, expected: { complete: true, failure: 'none', findings: [finding] } },
        { id: 'n', intent: { kind: 'negative', rule: 'github_token' }, expected: { complete: true, failure: 'none', findings: [] } },
        { id: 'm', intent: { kind: 'negative', rule: 'jwt' }, expected: { complete: true, failure: 'none', findings: [] } },
      ],
      packRuleIds: ['github_token', 'jwt'],
      placeholderNotApplicable: { github_token: 'x', jwt: 'x' },
      publicExampleNotApplicable: { github_token: 'x', jwt: 'x' },
      engine: { fixedRuleIds: ['github_token', 'jwt'], isPlaceholder: () => false, isExactPublicExample: () => false },
    });
    expect(problems).toContain('règle sans cas positif : jwt');
    expect(problems).not.toContain('règle sans cas positif : github_token');
  });

  it('expectedFor convertit les positions UTF-16 en octets, trie les constats et rend l’échec sans constat', () => {
    const found = (ruleId: string, start: number, end: number, secretType = 'password'): EngineFinding => ({
      ruleId,
      secretType,
      encoding: 'plain',
      score: 70,
      level: 'HIGH',
      start,
      end,
    });
    const engine = (complete: boolean, findings: EngineFinding[]): UpstreamEngine => ({
      scan: () => ({ complete, findings }),
      fixedRuleIds: [],
      isPlaceholder: () => false,
      isExactPublicExample: () => false,
      maxInputBytes: MAX_INPUT_BYTES,
    });
    // « é😀 ab » : é (2 octets), 😀 (2 unités, 4 octets), espace, a, b.
    const bytes = new TextEncoder().encode('é\u{1f600} ab');
    const expected = expectedFor(engine(true, [found('zeta', 4, 6), found('alpha', 4, 5), found('beta', 0, 3)]), bytes, undefined);
    expect(expected).toEqual({
      complete: true,
      failure: 'none',
      findings: [
        { ruleId: 'beta', secretType: 'password', encoding: 'plain', score: 70, level: 'HIGH', byteStart: 0, byteEnd: 6 },
        { ruleId: 'alpha', secretType: 'password', encoding: 'plain', score: 70, level: 'HIGH', byteStart: 7, byteEnd: 8 },
        { ruleId: 'zeta', secretType: 'password', encoding: 'plain', score: 70, level: 'HIGH', byteStart: 7, byteEnd: 9 },
      ],
    });
    const limit = expectedFor(engine(false, [{ ...found('input_too_large', 0, 0, 'scan_limit'), score: 100, level: 'CRITICAL' }]), bytes, undefined);
    expect(limit).toEqual({ complete: false, failure: 'scan_limit', findings: [] });
    expect(() => expectedFor(engine(true, [{ ...found('scanner_failure', 0, 0, 'scan_error'), score: 100, level: 'CRITICAL' }]), bytes, undefined)).toThrow(CorpusError);
    expect(() => expectedFor(engine(false, []), bytes, undefined)).toThrow(CorpusError);
    expect(() => expectedFor(engine(true, [found('mid', 2, 3)]), bytes, undefined)).toThrow(RangeError);
    expect(() => expectedFor(engine(true, [{ ...found('x', 0, 1), level: 'LOW' }]), bytes, undefined)).toThrow(CorpusError);
    // Hors UTF-8 : 1 048 476 octets valides et 100 octets 0x80 tiennent dans la limite en octets, pas en texte décodé.
    const inflated = Uint8Array.from([...new Uint8Array(MAX_INPUT_BYTES - 100).fill(0x61), ...new Uint8Array(100).fill(0x80)]);
    expect(() => expectedFor(engine(true, []), inflated, undefined)).toThrow(CorpusError);
  });

  it('le générateur échoue sur chaque manque de couverture', () => {
    const none = { complete: true, failure: 'none', findings: [] } as const;
    const finding = (ruleId: string, encoding: CorpusFinding['encoding'] = 'plain'): CorpusFinding => ({
      ruleId,
      secretType: 'password',
      encoding,
      score: 95,
      level: 'CRITICAL',
      byteStart: 0,
      byteEnd: 4,
    });
    const fired = (ruleId: string) => ({ complete: true, failure: 'none', findings: [finding(ruleId)] }) as const;
    const base = (cases: EvaluatedCase[], overrides: Partial<CoverageInput> = {}): string[] =>
      coverageProblems({
        cases,
        packRuleIds: ['r'],
        placeholderNotApplicable: {},
        publicExampleNotApplicable: {},
        engine: { fixedRuleIds: ['r'], isPlaceholder: (value) => value === 'xxxx', isExactPublicExample: (value) => value === 'pub' },
        ...overrides,
      });
    const complete: EvaluatedCase[] = [
      { id: 'p', intent: { kind: 'positive', rule: 'r' }, expected: fired('r') },
      { id: 'n', intent: { kind: 'negative', rule: 'r' }, expected: none },
      { id: 'f', intent: { kind: 'placeholder', rule: 'r', value: 'xxxx' }, expected: none },
      { id: 'e', intent: { kind: 'public_example', rule: 'r', value: 'pub' }, expected: none },
      ...FINDING_ENCODINGS.map((view): EvaluatedCase => ({
        id: `v-${view}`,
        intent: { kind: 'view', rule: 'r', view },
        expected: { complete: true, failure: 'none', findings: [finding('r', view)] },
      })),
    ];
    expect(base(complete)).toEqual([]);
    const without = (id: string): EvaluatedCase[] => complete.filter((value) => value.id !== id);
    expect(base(without('n'))).toContain('règle sans cas négatif : r');
    expect(base(without('f'))).toContain('règle sans cas de valeur fictive : r');
    expect(base(without('f'), { placeholderNotApplicable: { r: 'raison' } })).toEqual([]);
    expect(base(without('e'))).toContain('règle sans cas d’exemple public : r');
    expect(base(without('v-percent'))).toEqual(['vue sans cas positif : percent', 'vue sans cas de référence : percent']);
    const swap = (id: string, value: EvaluatedCase): EvaluatedCase[] => complete.map((entry) => (entry.id === id ? value : entry));
    expect(base(swap('n', { id: 'n', intent: { kind: 'negative', rule: 'r' }, expected: fired('r') }))).toContain('n : la règle r se déclenche');
    expect(base(swap('p', { id: 'p', intent: { kind: 'positive', rule: 'r' }, expected: none }))).toContain('p : la règle r ne se déclenche pas');
    expect(base(swap('f', { id: 'f', intent: { kind: 'placeholder', rule: 'r', value: 'real' }, expected: none }))).toContain(
      'f : valeur non fictive pour isPlaceholder',
    );
    expect(base(swap('f', { id: 'f', intent: { kind: 'placeholder', rule: 'r', value: 'xxxx' }, expected: fired('r') }))).toContain(
      'f : la règle r se déclenche sur une valeur fictive',
    );
    expect(base(swap('e', { id: 'e', intent: { kind: 'public_example', rule: 'r', value: 'other' }, expected: none }))).toContain(
      'e : valeur hors des exemples publics',
    );
    expect(base([...complete, { id: 'x', expected: fired('unknown') }])).toContain('x : constat d’une règle hors du Pack (unknown)');
    expect(base(complete, { placeholderNotApplicable: { ghost: 'raison' } })).toContain(
      'exemption « valeur fictive » d’une règle hors du Pack : ghost',
    );
    expect(base(complete, { engine: { fixedRuleIds: ['r', 'ghost'], isPlaceholder: () => true, isExactPublicExample: () => true } })).toContain(
      'règle de FIXED_RULE_IDS absente du Pack : ghost',
    );
  });

  it('le générateur échoue si un test repris ne passe aucune entrée, ou si une exemption ne sert plus', () => {
    const test = (title: string, inputs: RecordedTest['inputs'], row?: number): RecordedTest => ({
      file: 'scan.test.ts',
      suite: ['suite'],
      title,
      row,
      inputs,
      unrepresentable: 0,
    });
    const exemptions = { 'scan.test.ts > suite > exempt %s': 'raison' };
    const ok = upstreamSources(
      [
        test('text', [
          { kind: 'text', content: 'a', languageId: 'json' },
          { kind: 'text', content: 'b', languageId: undefined },
        ]),
        test('bytes', [{ kind: 'bytes', bytes: Uint8Array.of(0x80) }], 2),
        test('exempt %s', [], 0),
        test('exempt %s', [], 1),
      ],
      exemptions,
    );
    expect(ok.problems).toEqual([]);
    expect(ok.sources.map((source) => [source.file, source.id, source.languageId])).toEqual([
      ['upstream-scan.json', 'upstream/scan.test.ts > suite > text #1', 'json'],
      ['upstream-scan.json', 'upstream/scan.test.ts > suite > text #2', undefined],
      ['upstream-scan.json', 'upstream/scan.test.ts > suite > bytes [2] #1', undefined],
    ]);
    expect(upstreamSources([test('silent', [])], {}).problems).toEqual(['test d’origine sans entrée relevée : scan.test.ts > suite > silent']);
    expect(upstreamSources([], exemptions).problems).toEqual([
      'exemption sans test d’origine sans entrée : scan.test.ts > suite > exempt %s',
    ]);
    expect(upstreamSources([test('exempt %s', [{ kind: 'text', content: 'a', languageId: undefined }])], exemptions).problems).toContain(
      'test exempté qui passe une entrée : scan.test.ts > suite > exempt %s',
    );
  });

  it('les imports du moteur et des tests repris sont lus dans l’arbre syntaxique et réécrits à leur place seulement', () => {
    expect(importSpecifiers('import "node:fs";\nimport { a } from "./a.js";\n', 'f.js')).toEqual(['node:fs', './a.js']);
    for (const code of ['import/**/("x");', 'require("x");', 'eval("1");', 'new Function("return 1");']) {
      expect(() => moduleImports(code, 'f.js'), code).toThrow(UpstreamError);
    }
    const code = 'import { it } from "vitest";\nconst label = "vitest";\n';
    expect(rewriteImports(code, moduleImports(code, 'f.js'), () => '../h.js')).toBe(
      'import { it } from "../h.js";\nconst label = "vitest";\n',
    );
  });
});
