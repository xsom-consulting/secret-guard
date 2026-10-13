/**
 * `npm run vectors:detection -- --upstream <checkout>` (dans `generator/`) : écrit le corpus de parité de détection
 * (`vectors/detection/*.json` et `manifest.json`) avec le moteur TypeScript de Secret Guard. `--check` régénère en
 * mémoire et compare octet pour octet aux fichiers présents, sans rien écrire. Le checkout doit être au commit de
 * `UPSTREAM.md` (SHA-256 de chaque fichier vérifié).
 * Tout contrôle en échec : sortie 1, rien n'est écrit ; l'écriture passe par des fichiers temporaires renommés.
 */
import { readdirSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { RulePack } from '../src/rule-pack.ts';
import { utf8Bytes } from './bytes.ts';
import { corpusCaseOf, coverageProblems, expectedFor, type CaseSource, type EvaluatedCase } from './corpus.ts';
import { recordUpstreamTests, testImport, testLabel, type RecordedTest } from './harness.ts';
import { serializeCaseFile, serializeManifest } from './json.ts';
import { CASE_FILE_PATTERN, CORPUS_FORMAT_VERSION, MANIFEST_FILE, MAX_INPUT_BYTES, type CorpusCase } from './model.ts';
import { PLACEHOLDER_NOT_APPLICABLE, PUBLIC_EXAMPLE_NOT_APPLICABLE, syntheticCases } from './synthetic.ts';
import { transpileUpstream, UPSTREAM_COMMIT } from './upstream.ts';

const CORPUS_DIRECTORY = fileURLToPath(new URL('../../vectors/detection/', import.meta.url));
const PACK = new URL('../../pack/initial/pack.json', import.meta.url);

/**
 * Tests repris qui ne passent aucune entrée de texte ou d'octets au moteur : ils ne peuvent pas figurer comme cas
 * (libellé sans rang de ligne → raison). Tout autre test sans entrée fait échouer le générateur.
 */
export const TESTS_WITHOUT_INPUT: Readonly<Record<string, string>> = {
  'scan.test.ts > source locations and risk contract > maps score %i to %s':
    'éprouve levelForScore et decisionForLevel sur des scores, sans analyse',
  'scan.test.ts > redaction > unions overlapping and adjacent spans so no covered tail survives':
    'éprouve redact sur des constats construits à la main, sans analyse',
  'scan.test.ts > fail-closed limits > fails closed for an invalid runtime argument instead of throwing':
    'appelle scan avec des arguments hors forme (null, nombre…), sans entrée d’octets possible',
  'security.test.ts > non-disclosure > returns no candidate content when the runtime input is invalid':
    'appelle redactAndRescan avec des arguments hors forme, sans entrée d’octets possible',
};

/** Cas tirés des tests d'origine : un fichier par fichier de test, `upstream-<nom>.json`. */
export function upstreamSources(
  tests: readonly RecordedTest[],
  withoutInput: Readonly<Record<string, string>> = TESTS_WITHOUT_INPUT,
): { sources: CaseSource[]; problems: string[] } {
  const sources: CaseSource[] = [];
  const problems: string[] = [];
  const ids = new Set<string>();
  const exemptionsUsed = new Set<string>();
  for (const test of tests) {
    const label = testLabel(test);
    const exemption = testLabel({ ...test, row: undefined });
    if (test.inputs.length === 0) {
      if (withoutInput[exemption] === undefined) problems.push(`test d’origine sans entrée relevée : ${label}`);
      else exemptionsUsed.add(exemption);
      continue;
    }
    if (withoutInput[exemption] !== undefined) problems.push(`test exempté qui passe une entrée : ${label}`);
    const file = `upstream-${test.file.replace(/\.test\.ts$/, '')}.json`;
    test.inputs.forEach((input, index) => {
      const id = `upstream/${label} #${String(index + 1)}`;
      if (ids.has(id)) problems.push(`identifiant de cas en double : ${id}`);
      ids.add(id);
      if (input.kind === 'bytes') sources.push({ file, id, bytes: input.bytes });
      else {
        sources.push({
          file,
          id,
          bytes: utf8Bytes(input.content),
          ...(input.languageId === undefined ? {} : { languageId: input.languageId }),
        });
      }
    });
  }
  for (const exemption of Object.keys(withoutInput)) {
    if (!exemptionsUsed.has(exemption)) problems.push(`exemption sans test d’origine sans entrée : ${exemption}`);
  }
  return { sources, problems };
}

/** Fichiers du corpus (nom → contenu), manifeste compris. */
export function corpusFiles(cases: readonly (readonly [string, CorpusCase])[]): Map<string, string> {
  const byFile = new Map<string, CorpusCase[]>();
  for (const [file, value] of cases) {
    if (!CASE_FILE_PATTERN.test(file) || file === MANIFEST_FILE) throw new Error(`nom de fichier de cas refusé : ${file}`);
    const list = byFile.get(file) ?? [];
    list.push(value);
    byFile.set(file, list);
  }
  const names = [...byFile.keys()].sort();
  const files = new Map<string, string>();
  for (const name of names) files.set(name, serializeCaseFile(byFile.get(name) ?? []));
  files.set(
    MANIFEST_FILE,
    serializeManifest({
      formatVersion: CORPUS_FORMAT_VERSION,
      upstreamCommit: UPSTREAM_COMMIT,
      files: names.map((file) => ({ file, cases: byFile.get(file)?.length ?? 0 })),
    }),
  );
  return files;
}

function existingCorpusFiles(): string[] {
  return readdirSync(CORPUS_DIRECTORY, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.json'))
    .map((entry) => entry.name)
    .sort();
}

async function main(): Promise<number> {
  const { values } = parseArgs({
    options: { upstream: { type: 'string' }, check: { type: 'boolean', default: false } },
    strict: true,
    allowPositionals: false,
  });
  if (values.upstream === undefined) {
    process.stderr.write('Usage : vectors:detection --upstream <checkout de poc-AI_guard> [--check]\n');
    return 1;
  }
  const packRuleIds = RulePack.parse(JSON.parse(readFileSync(PACK, 'utf8'))).rules.map((rule) => rule.ruleId);
  const upstream = await transpileUpstream(values.upstream, testImport);
  try {
    const { engine } = upstream;
    if (engine.maxInputBytes !== MAX_INPUT_BYTES) throw new Error('MAX_INPUT_BYTES du moteur différent du corpus');
    const recorded = await recordUpstreamTests(upstream.directory);
    const { sources: upstreamCases, problems } = upstreamSources(recorded);
    const sources: CaseSource[] = [...syntheticCases(), ...upstreamCases];

    const evaluated: EvaluatedCase[] = [];
    const written: [string, CorpusCase][] = [];
    for (const source of sources) {
      const expected = expectedFor(engine, source.bytes, source.languageId);
      evaluated.push({ id: source.id, ...(source.intent === undefined ? {} : { intent: source.intent }), expected });
      written.push([source.file, corpusCaseOf(source, expected)]);
    }
    problems.push(
      ...coverageProblems({
        cases: evaluated,
        packRuleIds,
        placeholderNotApplicable: PLACEHOLDER_NOT_APPLICABLE,
        publicExampleNotApplicable: PUBLIC_EXAMPLE_NOT_APPLICABLE,
        engine,
      }),
    );
    if (problems.length > 0) {
      process.stderr.write(`Corpus refusé, rien n’est écrit :\n${problems.map((problem) => `- ${problem}`).join('\n')}\n`);
      return 1;
    }

    const files = corpusFiles(written);
    const stale = existingCorpusFiles().filter((name) => !files.has(name));
    if (values.check) {
      const differing = [...files].filter(([name, content]) => {
        try {
          return readFileSync(join(CORPUS_DIRECTORY, name), 'utf8') !== content;
        } catch {
          return true;
        }
      });
      if (differing.length > 0 || stale.length > 0) {
        process.stderr.write(`Corpus différent : ${[...differing.map(([name]) => name), ...stale].join(', ')}\n`);
        return 1;
      }
      process.stdout.write(`Corpus identique : ${String(sources.length)} cas, ${String(files.size - 1)} fichiers\n`);
      return 0;
    }
    // Fichiers temporaires d'abord (un échec d'écriture laisse le corpus en place), puis renommages, puis retraits.
    const temporary = (name: string): string => join(CORPUS_DIRECTORY, `.${name}.tmp-generate`);
    try {
      for (const [name, content] of files) writeFileSync(temporary(name), content);
    } catch (error) {
      for (const name of files.keys()) rmSync(temporary(name), { force: true });
      throw error;
    }
    for (const name of files.keys()) renameSync(temporary(name), join(CORPUS_DIRECTORY, name));
    for (const name of stale) rmSync(join(CORPUS_DIRECTORY, name));
    process.stdout.write(`Corpus de parité écrit : ${String(sources.length)} cas, ${String(files.size - 1)} fichiers\n`);
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
      process.stderr.write(`Corpus refusé : ${error instanceof Error ? error.message : 'erreur inattendue'}\n`);
      process.exitCode = 1;
    },
  );
}
