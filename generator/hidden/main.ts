/**
 * `npm run vectors:hidden -- --upstream <checkout>` (dans `generator/`) : écrit `vectors/hidden.json` et
 * `vectors/mentions.json`, vecteurs de parité des paquets Go `hidden` et `mentions`, avec `hidden.ts` et
 * `mentionedPaths` d'origine. `--check` régénère en mémoire et compare octet pour octet, sans rien écrire. Le checkout
 * doit porter les fichiers épinglés (`upstream.ts`, SHA-256 vérifiés).
 *
 * Contrôles avant toute écriture : expressions de `hidden.ts` égales à celles des tables Go (`unicode-tables.ts`),
 * expressions de `mentionedPaths` égales à celles du portage, constantes d'origine égales à celles du portage, chaque
 * sorte de porteur présente, identifiants uniques. Tout écart : sortie 1, rien n'est écrit.
 */
import { readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { utf8Bytes } from '../corpus/bytes.ts';
import { HIDDEN_KINDS, hiddenExpected, MENTION_CWD, MENTION_REGEXES, mentionsExpected } from './expected.ts';
import { serializeHiddenCase, serializeMentionCase, serializeVectorFile, vectorInput, VECTORS_FORMAT_VERSION } from './json.ts';
import { hiddenSyntheticCases, MAX_INPUT_BYTES, mentionSyntheticCases, type SyntheticCase } from './synthetic.ts';
import { HIDDEN_UNICODE_CLASSES } from './unicode-tables.ts';
import { loadHiddenUpstream, UPSTREAM_COMMIT, type HiddenUpstream, type RecordedTest } from './upstream.ts';

export const HIDDEN_VECTORS_FILE = fileURLToPath(new URL('../../vectors/hidden.json', import.meta.url));
export const MENTION_VECTORS_FILE = fileURLToPath(new URL('../../vectors/mentions.json', import.meta.url));

/** Constantes du portage Go (`hidden.MaxFindings`, `hidden.ScatteredInvisibleThreshold`). */
export const PORT_MAX_FINDINGS = 50;
export const PORT_SCATTERED_INVISIBLE_THRESHOLD = 4;

/** Cas tirés du test d'origine, par sorte d'entrée : `upstream/file-guard.test.ts > <suites> > <titre> #n`. */
export function upstreamCases(tests: readonly RecordedTest[]): { hidden: SyntheticCase[]; mentions: SyntheticCase[] } {
  const hidden: SyntheticCase[] = [];
  const mentions: SyntheticCase[] = [];
  for (const test of tests) {
    const label = `upstream/file-guard.test.ts > ${[...test.suite, test.title].join(' > ')}`;
    let hiddenRank = 0;
    let mentionRank = 0;
    for (const input of test.inputs) {
      if (input.kind === 'hidden') {
        hiddenRank += 1;
        hidden.push({ id: `${label} #${String(hiddenRank)}`, bytes: utf8Bytes(input.text) });
      } else {
        mentionRank += 1;
        mentions.push({ id: `${label} #${String(mentionRank)}`, bytes: utf8Bytes(input.prompt) });
      }
    }
  }
  return { hidden, mentions };
}

function sameRegexes(left: readonly { source: string; flags: string }[], right: readonly { source: string; flags: string }[]): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

/** Contrôles de l'origine avant tout calcul ; rend la liste des écarts. */
export function upstreamProblems(upstream: HiddenUpstream): string[] {
  const problems: string[] = [];
  const expected = HIDDEN_UNICODE_CLASSES.map((entry) => ({ source: entry.source, flags: 'u' }));
  if (!sameRegexes(upstream.hiddenRegexes, expected)) problems.push('expressions de hidden.ts différentes des tables Unicode du portage');
  if (!sameRegexes(upstream.mentionRegexes, MENTION_REGEXES)) problems.push('expressions de mentionedPaths différentes de celles du portage');
  if (upstream.maxInputBytes !== MAX_INPUT_BYTES) problems.push('MAX_INPUT_BYTES différent');
  if (upstream.maxHiddenFindings !== PORT_MAX_FINDINGS) problems.push('MAX_HIDDEN_FINDINGS différent');
  if (upstream.scatteredInvisibleThreshold !== PORT_SCATTERED_INVISIBLE_THRESHOLD) problems.push('SCATTERED_INVISIBLE_THRESHOLD différent');
  if (!upstream.tests.some((test) => test.inputs.some((input) => input.kind === 'mentions'))) problems.push('aucun prompt relevé dans le test d’origine');
  return problems;
}

/** Contenu des deux fichiers. */
export function buildVectorFiles(upstream: HiddenUpstream): { hidden: string; mentions: string; problems: string[] } {
  const problems = upstreamProblems(upstream);
  const fromTests = upstreamCases(upstream.tests);
  const ids = new Set<string>();
  const unique = (id: string): void => {
    if (ids.has(id)) problems.push(`identifiant de cas en double : ${id}`);
    ids.add(id);
  };

  const kinds = new Set<string>();
  const hiddenLines: string[] = [];
  for (const source of [...hiddenSyntheticCases(), ...fromTests.hidden]) {
    unique(`hidden/${source.id}`);
    const expected = hiddenExpected(upstream, source.bytes, MAX_INPUT_BYTES);
    for (const finding of expected.findings) kinds.add(finding.kind);
    hiddenLines.push(serializeHiddenCase(vectorInput(source.id, source.bytes), expected));
  }
  for (const kind of HIDDEN_KINDS) if (!kinds.has(kind)) problems.push(`sorte sans cas positif : ${kind}`);

  const mentionLines: string[] = [];
  for (const source of [...mentionSyntheticCases(), ...fromTests.mentions]) {
    unique(`mentions/${source.id}`);
    mentionLines.push(serializeMentionCase(vectorInput(source.id, source.bytes), mentionsExpected(upstream, source.bytes)));
  }

  const common: [string, string][] = [
    ['formatVersion', String(VECTORS_FORMAT_VERSION)],
    ['upstreamCommit', JSON.stringify(UPSTREAM_COMMIT)],
  ];
  const hidden = serializeVectorFile(
    [
      ...common,
      ['maxInputBytes', String(MAX_INPUT_BYTES)],
      ['maxFindings', String(PORT_MAX_FINDINGS)],
      ['scatteredInvisibleThreshold', String(PORT_SCATTERED_INVISIBLE_THRESHOLD)],
    ],
    hiddenLines,
  );
  const mentions = serializeVectorFile(
    [...common, ['cwd', JSON.stringify(MENTION_CWD)], ['patterns', JSON.stringify(MENTION_REGEXES.map((regex) => `/${regex.source}/${regex.flags}`))]],
    mentionLines,
  );
  return { hidden, mentions, problems };
}

async function main(): Promise<number> {
  const { values } = parseArgs({
    options: { upstream: { type: 'string' }, check: { type: 'boolean', default: false } },
    strict: true,
    allowPositionals: false,
  });
  if (values.upstream === undefined) {
    process.stderr.write('Usage : vectors:hidden --upstream <checkout de poc-AI_guard> [--check]\n');
    return 1;
  }
  const upstream = await loadHiddenUpstream(values.upstream);
  const { hidden, mentions, problems } = buildVectorFiles(upstream);
  if (problems.length > 0) {
    process.stderr.write(`Vecteurs refusés, rien n’est écrit :\n${problems.map((problem) => `- ${problem}`).join('\n')}\n`);
    return 1;
  }
  const files: [string, string][] = [
    [HIDDEN_VECTORS_FILE, hidden],
    [MENTION_VECTORS_FILE, mentions],
  ];
  const count = (content: string): number => content.split('\n').filter((line) => line.startsWith('{"id":')).length;
  if (values.check) {
    const differing = files.filter(([path, content]) => {
      try {
        return readFileSync(path, 'utf8') !== content;
      } catch {
        return true;
      }
    });
    if (differing.length > 0) {
      process.stderr.write(`Vecteurs différents : ${differing.map(([path]) => path.slice(path.lastIndexOf('/') + 1)).join(', ')}\n`);
      return 1;
    }
    process.stdout.write(`Vecteurs identiques : hidden.json ${String(count(hidden))} cas, mentions.json ${String(count(mentions))} cas\n`);
    return 0;
  }
  const temporary = (path: string): string => `${path}.tmp-generate`;
  try {
    for (const [path, content] of files) writeFileSync(temporary(path), content);
  } catch (error) {
    for (const [path] of files) rmSync(temporary(path), { force: true });
    throw error;
  }
  for (const [path] of files) renameSync(temporary(path), path);
  process.stdout.write(`Vecteurs écrits : hidden.json ${String(count(hidden))} cas, mentions.json ${String(count(mentions))} cas\n`);
  return 0;
}

if (process.argv[1] !== undefined && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (error: unknown) => {
      process.stderr.write(`Vecteurs refusés : ${error instanceof Error ? error.message : 'erreur inattendue'}\n`);
      process.exitCode = 1;
    },
  );
}
