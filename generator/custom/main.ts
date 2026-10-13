/**
 * `npm run vectors:custom -- --upstream <checkout>` (dans `generator/`) : écrit les vecteurs de parité du Pack de
 * règles du client (`vectors/custom/*.json` et `manifest.json`) avec le moteur TypeScript de Secret Guard : vecteurs
 * du contrat, entrées des trois tests d'origine des règles du client, cas synthétiques, pont Unicode. `--check`
 * régénère en mémoire et compare octet pour octet, sans rien écrire. Le checkout doit être au commit de
 * `UPSTREAM.md` (SHA-256 de chaque fichier lu vérifié). Tout contrôle en échec : sortie 1, rien n'est écrit.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { decodeInput, utf8Bytes } from '../corpus/bytes.ts';
import { jsonString } from '../corpus/json.ts';
import { describeText } from '../redact/vectors.ts';
import { loadCustomEngine, type CompiledPackLike, type CustomEngine } from './engine.ts';
import { recordCustomTests, testLabel, type RecordedTest } from './harness.ts';
import { distinctWords, emptySources, hashingPack, syntheticSources, type PackSource, type ScanContext, type ScanSource, type Sources } from './synthetic.ts';
import { unicodeBlocks } from './unicode.ts';
import { loadModule, transpileCustomUpstream, UPSTREAM_COMMIT } from './upstream.ts';
import {
  CUSTOM_FILES,
  CUSTOM_FORMAT_VERSION,
  encodeInput,
  expectedDetection,
  expectedPack,
  expectedPatternMatches,
  expectedPatternValidation,
  expectedRedaction,
  expectedTerm,
  scanExpectedOf,
  serializeCases,
  VectorError,
  type CustomFile,
} from './vectors.ts';

const VECTORS_DIRECTORY = fileURLToPath(new URL('../../vectors/custom/', import.meta.url));
const MANIFEST_FILE = 'manifest.json';
const FIXTURE = 'secret-guard/contracts/fixtures/rules-pack-vectors.json';

/** Tests repris qui ne passent aucune entrée au moteur. Tout autre test sans entrée fait échouer le générateur. */
export const TESTS_WITHOUT_INPUT: Readonly<Record<string, string>> = {
  'rules-pack-contract.test.ts > rules pack contract vectors > has the frozen number of vectors':
    'compte les vecteurs du contrat, sans appel du moteur',
  'rules-scan.test.ts > scan with an xSOM rules pack > keeps a label free of control, bidi and line characters':
    'éprouve displayLabel (libellé affiché), que le moteur Go ne rend pas',
};

/**
 * Entrée d'un test repris sans résultat de référence en temps borné : l'automate d'origine épuise tout budget sur ce
 * motif (même entrée, en analyse : `synthetic/scan/budget/pathological-pattern`, écart déclaré).
 */
const PATHOLOGICAL_TEST = 'rules-pattern.test.ts > safe pattern compiler > stops a pathological but valid pattern at the work budget';

/**
 * Écarts déclarés sur des entrées de tests repris (libellé du test, rang de l'entrée) : raison de la liste de
 * UPSTREAM.md et résultat Go. Même motif pathologique que PATHOLOGICAL_TEST, en analyse : l'automate de l'origine
 * épuise le budget, RE2 finit en temps linéaire et constate l'absence de correspondance.
 */
const UPSTREAM_DIVERGENCES: Readonly<Record<string, ScanSource['divergence']>> = {
  'rules-scan.test.ts > scan with an xSOM rules pack > blocks as an incomplete analysis when the work budget runs out #2': {
    reason: 'backtracking_budget',
    go: { complete: true, failure: 'none', findings: [] },
  },
};

type Fixture = {
  grammar: { pattern: string; hasContext: boolean }[];
  detection: { name: string; detector: unknown; text: string }[];
  terms: { salt: string; cases: { term: string }[] };
  packs: { name: string; pack: unknown }[];
};

/** Vecteurs du contrat (sans la section de signature, hors du moteur). */
function fixtureSources(fixture: Fixture): Sources {
  const sources = emptySources();
  fixture.grammar.forEach((vector, index) => {
    sources.patternValidation.push({ id: `fixture/grammar/${String(index)}`, pattern: vector.pattern, hasContext: vector.hasContext, caseInsensitive: false });
  });
  for (const vector of fixture.detection) {
    sources.detection.push({ id: `fixture/detection/${vector.name}`, detectors: JSON.stringify([vector.detector]), bytes: utf8Bytes(vector.text) });
  }
  fixture.terms.cases.forEach((entry, index) => {
    sources.terms.push({ id: `fixture/terms/${String(index)}`, kind: 'term', input: entry.term, salt: fixture.terms.salt });
  });
  for (const vector of fixture.packs) sources.packs.push({ id: `fixture/packs/${vector.name}`, bytes: utf8Bytes(JSON.stringify(vector.pack)) });
  return sources;
}

/**
 * Entrées des tests repris : identifiant `upstream/<n> #<rang>`, où n est le numéro du test dans la table `tests` du
 * manifeste (libellé complet).
 */
function recordedSources(tests: readonly RecordedTest[]): { sources: Sources; labels: string[]; problems: string[] } {
  const sources = emptySources();
  const problems: string[] = [];
  const labels: string[] = [];
  const used = new Set<string>();
  const declared = new Set<string>();
  for (const test of tests) {
    const label = testLabel(test);
    const exemption = testLabel({ ...test, row: undefined });
    if (test.inputs.length === 0) {
      if (TESTS_WITHOUT_INPUT[exemption] === undefined) problems.push(`test d’origine sans entrée relevée : ${label}`);
      else used.add(exemption);
      continue;
    }
    if (TESTS_WITHOUT_INPUT[exemption] !== undefined) problems.push(`test exempté qui passe une entrée : ${label}`);
    const number = labels.length;
    labels.push(label);
    test.inputs.forEach((input, index) => {
      const id = `upstream/${String(number)} #${String(index + 1)}`;
      switch (input.kind) {
        case 'pattern':
          sources.patternValidation.push({ id, pattern: input.pattern, hasContext: input.hasContext, caseInsensitive: input.caseInsensitive });
          break;
        case 'match':
          if (exemption === PATHOLOGICAL_TEST) break;
          sources.patternMatching.push({ id, pattern: input.pattern, caseInsensitive: input.caseInsensitive, bytes: utf8Bytes(input.text) });
          break;
        case 'pack':
          sources.packs.push({ id, bytes: utf8Bytes(input.json) });
          break;
        case 'scan':
          // Un budget partagé entre analyses n'est pas repris : l'analyse est rejouée avec le budget d'une analyse.
          {
            const divergence = UPSTREAM_DIVERGENCES[`${label} #${String(index + 1)}`];
            if (divergence !== undefined) declared.add(`${label} #${String(index + 1)}`);
            sources.scans.push({
              id,
              pack: input.pack === undefined ? undefined : utf8Bytes(input.pack),
              bytes: utf8Bytes(input.content),
              ...(divergence === undefined ? {} : { divergence }),
            });
          }
          break;
        case 'detect':
          sources.detection.push({ id, detectors: input.detectors, bytes: utf8Bytes(input.text) });
          break;
        case 'term':
          sources.terms.push({ id, kind: 'term', input: input.term, salt: '' });
          break;
        case 'digest':
          sources.terms.push({ id, kind: 'digest', input: input.normalized, salt: input.salt });
          break;
      }
    });
  }
  for (const exemption of Object.keys(TESTS_WITHOUT_INPUT)) {
    if (!used.has(exemption)) problems.push(`exemption sans test d’origine sans entrée : ${exemption}`);
  }
  for (const key of Object.keys(UPSTREAM_DIVERGENCES)) {
    if (!declared.has(key)) problems.push(`écart déclaré sans entrée relevée : ${key}`);
  }
  return { sources, labels, problems };
}

/** Plus grand nombre de mots `distinctWords` que `hashingPack` analyse dans le budget (travail mesuré par l'origine). */
function hashingThreshold(engine: CustomEngine): number {
  const compiled = engine.compileRulesPack(hashingPack(engine));
  if (!compiled.ok) throw new VectorError('Pack de hachage refusé');
  const used = (count: number): number => {
    const meter = engine.newMeter(1e15);
    compiled.pack.detect(distinctWords(count), meter);
    return meter.used;
  };
  let low = 1;
  let high = 174_000; // 6 octets par mot : moins de 1 Mio
  if (used(high) <= engine.customWorkBudget) throw new VectorError('seuil de hachage hors de la limite de taille');
  while (high - low > 1) {
    const middle = Math.floor((low + high) / 2);
    if (used(middle) <= engine.customWorkBudget) low = middle;
    else high = middle;
  }
  return low;
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

/** Regroupe des cas consécutifs de même clé (identifiant du premier), en gardant l'ordre. */
function groupBy<T, G>(items: readonly T[], key: (item: T) => string, open: (item: T) => G, add: (group: G, item: T) => void): G[] {
  const groups: G[] = [];
  const index = new Map<string, G>();
  for (const item of items) {
    const k = key(item);
    let group = index.get(k);
    if (group === undefined) {
      group = open(item);
      index.set(k, group);
      groups.push(group);
    }
    add(group, item);
  }
  return groups;
}

interface Built {
  readonly files: Map<string, string>;
  readonly counts: Map<CustomFile, number>;
}

/** Évalue toutes les sources et écrit les fichiers (en mémoire). */
function build(engine: CustomEngine, all: Sources, labels: readonly string[], problems: string[]): Built {
  const ids = new Set<string>();
  const claim = (id: string): void => {
    if (ids.has(id)) problems.push(`identifiant en double : ${id}`);
    ids.add(id);
  };
  const firstOf = <T extends { id: string }>(items: readonly T[], key: (item: T) => string): T[] => {
    const seen = new Set<string>();
    return items.filter((item) => {
      const k = key(item);
      if (seen.has(k)) return false;
      seen.add(k);
      claim(item.id);
      return true;
    });
  };

  // Motifs : validité.
  const validation = firstOf(all.patternValidation, (s) => JSON.stringify([s.pattern, s.hasContext, s.caseInsensitive])).map((s) => ({
    id: s.id,
    pattern: s.pattern,
    hasContext: s.hasContext,
    caseInsensitive: s.caseInsensitive,
    expected: expectedPatternValidation(engine, s.pattern, s.hasContext, s.caseInsensitive),
  }));

  // Motifs : correspondances, regroupées par motif.
  type MatchingGroup = { id: string; pattern: string; caseInsensitive: boolean; inputs: unknown[] };
  const matching = groupBy(
    firstOf(all.patternMatching, (s) => JSON.stringify([s.pattern, s.caseInsensitive, hex(s.bytes)])),
    (s) => JSON.stringify([s.pattern, s.caseInsensitive]),
    (s): MatchingGroup => ({ id: s.id, pattern: s.pattern, caseInsensitive: s.caseInsensitive, inputs: [] }),
    (group, s) => {
      const expected = expectedPatternMatches(engine, s.pattern, s.caseInsensitive, s.bytes);
      if (expected === undefined) problems.push(`motif sans résultat de référence : ${s.id}`);
      else group.inputs.push({ ...encodeInput(s.bytes), expected });
    },
  );

  // Packs : validité, puis Packs des analyses (identifiant tiré de leurs octets).
  const packs: unknown[] = [];
  const packIds = new Map<string, string>();
  const packCase = (source: PackSource): void => {
    const key = hex(source.bytes);
    if (packIds.has(key)) return;
    claim(source.id);
    packIds.set(key, source.id);
    const expected = expectedPack(engine, source.bytes);
    const decoded = encodeInput(source.bytes);
    const entry: Record<string, unknown> = { id: source.id, pack: decoded.input, packEncoding: decoded.inputEncoding };
    if (expected === undefined) {
      entry['upstream'] = 'json_parse_error';
      entry['expected'] = { valid: false, error: 'schema' };
    } else entry['expected'] = expected;
    if (source.divergence !== undefined) {
      if (expected === undefined || (expected.valid === source.divergence.go.valid && expected.error === source.divergence.go.error)) {
        problems.push(`écart déclaré sans écart : ${source.id}`);
      }
      entry['divergence'] = source.divergence;
    }
    packs.push(entry);
  };
  for (const source of all.packs) packCase(source);
  const packRef = (bytes: Uint8Array): string => {
    const known = packIds.get(hex(bytes));
    if (known !== undefined) return known;
    const id = `pack/${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;
    packCase({ id, bytes });
    return id;
  };

  // Détections par détecteur, regroupées par jeu de détecteurs.
  type DetectionGroup = { id: string; detectors: unknown; inputs: unknown[] };
  const detection = groupBy(
    firstOf(all.detection, (s) => JSON.stringify([s.detectors, hex(s.bytes)])),
    (s) => s.detectors,
    (s): DetectionGroup => ({ id: s.id, detectors: JSON.parse(s.detectors) as unknown, inputs: [] }),
    (group, s) => {
      const expected = expectedDetection(engine, s.detectors, s.bytes);
      if (expected === undefined) problems.push(`détection sans résultat de référence : ${s.id}`);
      else group.inputs.push({ ...encodeInput(s.bytes), expected });
    },
  );

  // Analyses.
  const compiledPacks = new Map<string, CompiledPackLike>();
  const scans: unknown[] = [];
  const scanSources = firstOf(all.scans, (s) => JSON.stringify([s.pack === undefined ? null : hex(s.pack), hex(s.bytes)]));
  for (const s of scanSources) {
    let rules: CompiledPackLike | undefined;
    if (s.pack !== undefined) {
      const key = hex(s.pack);
      rules = compiledPacks.get(key);
      if (rules === undefined) {
        const compiled = engine.compileRulesPack(JSON.parse(decodeInput(s.pack).text));
        if (!compiled.ok) {
          problems.push(`Pack d’analyse refusé (${compiled.error}) : ${s.id}`);
          continue;
        }
        rules = compiled.pack;
        compiledPacks.set(key, rules);
      }
    }
    // Texte décodé comme Go parcourt les octets (U+FFFD par octet invalide, marque d'ordre gardée), pas par TextDecoder.
    const expected = scanExpectedOf(engine.scan(decodeInput(s.bytes).text, rules), s.bytes);
    const entry: Record<string, unknown> = { id: s.id, pack: s.pack === undefined ? null : packRef(s.pack), ...encodeInput(s.bytes), expected };
    if (s.divergence !== undefined) {
      if (expected.complete === s.divergence.go.complete && expected.failure === s.divergence.go.failure) {
        problems.push(`écart déclaré sans écart : ${s.id}`);
      }
      entry['divergence'] = s.divergence;
    }
    scans.push(entry);
  }

  // Masquages avec un Pack de règles du client (entrées UTF-8 valides).
  const redactions: unknown[] = [];
  for (const s of scanSources) {
    if (s.pack === undefined || !decodeInput(s.bytes).validUtf8) continue;
    const rules = compiledPacks.get(hex(s.pack));
    if (rules === undefined) continue;
    const entry: Record<string, unknown> = { id: s.id, pack: packRef(s.pack), ...encodeInput(s.bytes), expected: expectedRedaction(engine, s.bytes, rules) };
    if (s.divergence !== undefined) {
      // Écart déclaré de l'analyse : le masquage du moteur Go suit son analyse (complète et sans constat ici).
      if (!s.divergence.go.complete || s.divergence.go.findings.length > 0) problems.push(`écart de masquage non pris en charge : ${s.id}`);
      entry['divergence'] = { reason: s.divergence.reason, go: { failure: 'none', neutral: false, redacted: describeText(s.bytes) } };
    }
    redactions.push(entry);
  }

  // Termes.
  const terms = firstOf(all.terms, (s) => JSON.stringify([s.kind, s.input, s.salt])).map((s) => ({
    id: s.id,
    kind: s.kind,
    input: s.input,
    salt: s.salt,
    expected:
      s.kind === 'term'
        ? expectedTerm(engine, s.input, s.salt)
        : { normalized: s.input, digest: engine.termDigest(engine.decodeSalt(s.salt), s.input) },
  }));

  const contents: Record<CustomFile, readonly unknown[]> = {
    'detection.json': detection,
    'packs.json': packs,
    'pattern-matching.json': matching,
    'pattern-validation.json': validation,
    'redact.json': redactions,
    'scan.json': scans,
    'terms.json': terms,
    'unicode.json': unicodeBlocks((word) => engine.normalizeWord(word)),
  };
  const files = new Map<string, string>();
  const counts = new Map<CustomFile, number>();
  for (const name of CUSTOM_FILES) {
    files.set(name, serializeCases(contents[name]));
    counts.set(name, contents[name].length);
  }
  files.set(
    MANIFEST_FILE,
    `{\n  "formatVersion": ${String(CUSTOM_FORMAT_VERSION)},\n  "upstreamCommit": ${jsonString(UPSTREAM_COMMIT)},\n` +
      `  "files": [\n${CUSTOM_FILES.map((name) => `    {"file":${jsonString(name)},"cases":${String(counts.get(name) ?? 0)}}`).join(',\n')}\n  ],\n` +
      `  "tests": [\n${labels.map((label) => `    ${jsonString(label)}`).join(',\n')}\n  ]\n}\n`,
  );
  return { files, counts };
}

function merge(...parts: Sources[]): Sources {
  const out = emptySources();
  for (const part of parts) {
    out.patternValidation.push(...part.patternValidation);
    out.patternMatching.push(...part.patternMatching);
    out.packs.push(...part.packs);
    out.detection.push(...part.detection);
    out.scans.push(...part.scans);
    out.terms.push(...part.terms);
  }
  return out;
}

async function main(): Promise<number> {
  const { values } = parseArgs({
    options: { upstream: { type: 'string' }, check: { type: 'boolean', default: false } },
    strict: true,
    allowPositionals: false,
  });
  if (values.upstream === undefined) {
    process.stderr.write('Usage : vectors:custom --upstream <checkout de poc-AI_guard> [--check]\n');
    return 1;
  }
  const upstream = transpileCustomUpstream(values.upstream);
  try {
    const engine = await loadCustomEngine(upstream.directory);
    const fixture = JSON.parse(upstream.file(FIXTURE)) as Fixture;
    const recorded = await recordCustomTests(upstream.directory);
    const { sources: fromTests, labels, problems } = recordedSources(recorded);
    const reference = fixture.packs[0]?.pack;
    if (typeof reference !== 'object' || reference === null) throw new VectorError('Pack de référence du contrat absent');
    const context: ScanContext = { reference: reference as Record<string, unknown>, hashingWords: hashingThreshold(engine) };
    const all = merge(fixtureSources(fixture), fromTests, syntheticSources(engine, context));
    const built = build(engine, all, labels, problems);
    if (problems.length > 0) {
      process.stderr.write(`Vecteurs refusés, rien n’est écrit :\n${problems.map((problem) => `- ${problem}`).join('\n')}\n`);
      return 1;
    }
    // Le script du plus grand Pack est lu par les tests repris (Pack et analyses relevés) : contrôle de sa présence.
    await loadModule(upstream.directory, 'harness/largest-rules-pack.js');
    mkdirSync(VECTORS_DIRECTORY, { recursive: true });
    const stale = readdirSync(VECTORS_DIRECTORY).filter((name) => name.endsWith('.json') && !built.files.has(name));
    const summary = [...built.counts].map(([name, count]) => `${name} ${String(count)}`).join(', ');
    if (values.check) {
      const differing = [...built.files].filter(([name, content]) => {
        try {
          return readFileSync(join(VECTORS_DIRECTORY, name), 'utf8') !== content;
        } catch {
          return true;
        }
      });
      if (differing.length > 0 || stale.length > 0) {
        process.stderr.write(`Vecteurs différents : ${[...differing.map(([name]) => name), ...stale].join(', ')}\n`);
        return 1;
      }
      process.stdout.write(`Vecteurs identiques : ${summary}\n`);
      return 0;
    }
    const temporary = (name: string): string => join(VECTORS_DIRECTORY, `.${name}.tmp-generate`);
    try {
      for (const [name, content] of built.files) writeFileSync(temporary(name), content);
    } catch (error) {
      for (const name of built.files.keys()) rmSync(temporary(name), { force: true });
      throw error;
    }
    for (const name of built.files.keys()) renameSync(temporary(name), join(VECTORS_DIRECTORY, name));
    for (const name of stale) rmSync(join(VECTORS_DIRECTORY, name));
    process.stdout.write(`Vecteurs écrits : ${summary}\n`);
    return 0;
  } finally {
    upstream.dispose();
  }
}

if (process.argv[1] !== undefined && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (error: unknown) => {
      process.stderr.write(`Vecteurs refusés : ${error instanceof Error ? `${error.name}: ${error.message}` : 'erreur inattendue'}\n`);
      process.exitCode = 1;
    },
  );
}
