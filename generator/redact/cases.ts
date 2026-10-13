/**
 * Cas synthétiques des vecteurs du masquage. Fonction pure et déterministe : chaque valeur de secret est tirée de
 * SHA-256 sur une étiquette fixe (`synth` du corpus, étiquettes `redact/…`), jamais copiée d'un vrai secret ; aucun
 * en-tête de clé privée ni jeton n'est écrit d'un seul tenant dans ce fichier. Le résultat attendu vient du moteur
 * d'origine (`main.ts`) ; l'intention de chaque cas (issue, étape de l'échec, nombre de libellés, constats contigus)
 * est contrôlée par le générateur (`intentProblem`), pour qu'un cas éprouve bien ce qu'il annonce.
 */
import { MAX_INPUT_BYTES } from '../corpus/model.ts';
import { synth } from '../corpus/synthetic.ts';
import type { RedactExpected, RepeatedPrefix, SanitizeFailure, SpanFinding } from './model.ts';

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';
const ALNUM = UPPER + LOWER + DIGITS;

/** Intention d'un cas, contrôlée sur le résultat du moteur d'origine ; jamais écrite. */
export interface RedactIntent {
  readonly failure: SanitizeFailure;
  /** Étape de l'analyse incomplète. */
  readonly incompleteAt?: 'initial' | 'final';
  /** Nombre de libellés au moins dans le texte masqué. */
  readonly minLabels?: number;
  /** Au moins deux constats initiaux contigus (fin de l'un = début de l'autre). */
  readonly adjacent?: boolean;
}

/** Entrée synthétique de `redactAndRescan`. */
export interface RedactSource {
  readonly id: string;
  /** Entrée entière : préfixe répété, puis `rest`. */
  readonly bytes: Uint8Array;
  /** Entrée après le préfixe répété (écrite dans le fichier). */
  readonly rest: Uint8Array;
  readonly repeat?: RepeatedPrefix;
  readonly languageId?: string;
  readonly intent: RedactIntent;
}

/** Cas de `redact` seul : contenu et constats construits. */
export interface SpanSource {
  readonly id: string;
  readonly bytes: Uint8Array;
  readonly findings: readonly SpanFinding[];
}

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

function github(label: string): string {
  return `gh${'p_'}${synth(`redact/${label}`, ALNUM, 36)}`;
}

function gitlab(label: string): string {
  return `gl${'pat-'}${synth(`redact/${label}`, ALNUM, 20)}`;
}

function password(label: string): string {
  return `${synth(`redact/${label}/a`, ALNUM, 10)}!${synth(`redact/${label}/b`, ALNUM, 6)}`;
}

/** Ligne d'en-tête PEM, assemblée en morceaux. */
function pemLine(marker: 'BEGIN' | 'END', kind: string): string {
  return `${'-'.repeat(5)}${marker} ${kind}${'-'.repeat(5)}`;
}

/** Préfixe de remplissage d'une entrée de `total` octets terminée par `tail` (lignes neutres, puis points). */
export function filledPrefix(total: number, tail: string): { repeat: RepeatedPrefix; rest: string } {
  const line = 'lorem ipsum dolor sit amet consectetur\n';
  const fill = total - utf8(tail).length;
  return { repeat: { text: line, count: Math.floor(fill / line.length) }, rest: `${'.'.repeat(fill % line.length)}${tail}` };
}

/** Octets d'une entrée synthétique : préfixe répété, puis le reste. */
export function sourceBytes(repeat: RepeatedPrefix | undefined, rest: Uint8Array): Uint8Array {
  if (repeat === undefined) return rest;
  return Uint8Array.from(Buffer.concat([Buffer.from(utf8(repeat.text.repeat(repeat.count))), Buffer.from(rest)]));
}

/** Entrées synthétiques de `redactAndRescan`, dans l'ordre d'écriture. */
export function redactSources(): RedactSource[] {
  const sources: RedactSource[] = [];
  const add = (id: string, text: string, intent: RedactIntent, options: { languageId?: string; repeat?: RepeatedPrefix } = {}): void => {
    sources.push({
      id: `redact/${id}`,
      bytes: sourceBytes(options.repeat, utf8(text)),
      rest: utf8(text),
      ...(options.repeat === undefined ? {} : { repeat: options.repeat }),
      ...(options.languageId === undefined ? {} : { languageId: options.languageId }),
      intent,
    });
  };
  const addBytes = (id: string, bytes: readonly number[], intent: RedactIntent): void => {
    sources.push({ id: `redact/${id}`, bytes: Uint8Array.from(bytes), rest: Uint8Array.from(bytes), intent });
  };
  const encoded = (text: string): number[] => [...utf8(text)];
  const token = github('token');
  const second = gitlab('second');
  const pw = password('pw');

  add('clean/prose', 'Explain this pure function.\n', { failure: 'none' });
  add('clean/empty', '', { failure: 'none' });
  add('clean/already-redacted', 'TOKEN=<REDACTED_github_token>\n', { failure: 'none' });
  add('multiple/two-providers-two-lines', `first ${token}\nsecond ${second}\n`, { failure: 'none', minLabels: 2 });
  add('multiple/token-password-url', `${token}\nDB_PASSWORD=${pw}\npostgres://app:${pw}@db.redact.test/app\n`, {
    failure: 'none',
    minLabels: 3,
  });
  add('glued/two-tokens-read-as-one-value', `${token}${github('glued')}\n`, { failure: 'none', minLabels: 1 });
  // Valeur longue : plusieurs constats high_entropy contigus, fusionnés en un seul libellé.
  add('adjacent/entropy-run', `${synth('redact/entropy', `${ALNUM}_-`, 700)}\n`, { failure: 'none', minLabels: 1, adjacent: true });
  add('non-ascii/accents-cjk-emoji', `Clé d’accès « ${token} » — 密码 😀\npassword = "${pw}" ✓\n`, { failure: 'none', minLabels: 2 });
  add('non-ascii/emoji-inside-value', `DB_PASSWORD=😀${pw}🔒\nnext ${token}\n`, { failure: 'none', minLabels: 2 });
  addBytes(
    'invalid-utf8/around-two-secrets',
    [0xff, ...encoded(` token ${token} `), 0xc3, ...encoded(`\nDB_PASSWORD=${pw}\n`), 0xe2, 0x82],
    { failure: 'none', minLabels: 2 },
  );
  addBytes('invalid-utf8/inside-token', [...encoded(`token ${token.slice(0, 20)}`), 0xff, ...encoded(`${token.slice(20)} end\n`)], {
    failure: 'none',
  });
  add('views/base64-of-assignment', `payload ${Buffer.from(`TOKEN=${token}`).toString('base64')}\n`, { failure: 'none', minLabels: 1 });
  add('views/percent-in-query', `https://api.redact.test/?access_token=ghp%5F${token.slice(4)}&page=2\n`, { failure: 'none', minLabels: 1 });
  add('views/json-escaped', `{"token":"ghp\\u005f${token.slice(4)}","n":1}\n`, { failure: 'none', minLabels: 1 });
  add('views/line-wrapped', `token ${token.slice(0, 12)}\n    ${token.slice(12)}\nafter\n`, { failure: 'none', minLabels: 1 });
  add('views/normalized-fullwidth', `token ${token.slice(0, 2)}ｐ${token.slice(3)}\n`, { failure: 'none', minLabels: 1 });
  add('views/plain-and-base64', `${second}\npayload ${Buffer.from(`token ${token}`).toString('base64')}\n`, { failure: 'none', minLabels: 2 });
  add('language/dotenv-punctuation', `API_SECRET=${pw}#;tail\nOTHER=1\n`, { failure: 'none', minLabels: 1 }, { languageId: 'dotenv' });
  add('language/typescript-assignment', `const apiKey = "${password('ts')}";\nexport default apiKey;\n`, { failure: 'none', minLabels: 1 }, {
    languageId: 'typescript',
  });
  const body = synth('redact/pem', `${ALNUM}+/`, 64);
  add('private-key/block', `${pemLine('BEGIN', 'RSA PRIVATE KEY')}\n${body}\n${body}\n${pemLine('END', 'RSA PRIVATE KEY')}\nafter\n`, {
    failure: 'none',
    minLabels: 1,
  });
  // La valeur de l'affectation déborde sur la ligne suivante : après masquage, « <libellé>=another » est relu comme
  // une nouvelle valeur (comportement d'origine, gardé tel quel).
  add('residual/assignment-swallows-next-line', `API_KEY=${token}\nNEXT=another`, { failure: 'residual' });
  add('residual/yaml-block', `app_secret: |\n  ${synth('redact/yaml/a', ALNUM, 24)}\n  ${synth('redact/yaml/b', ALNUM, 24)}\nnext: 1\n`, {
    failure: 'residual',
  }, { languageId: 'yaml' });
  // Entrée de 1 Mio dont le libellé est plus long que la valeur : le texte masqué dépasse 1 Mio.
  const growing = filledPrefix(MAX_INPUT_BYTES, `\npassword = "${password('limit')}"\n`);
  add('limit/redacted-text-over-1mib', growing.rest, { failure: 'incomplete', incompleteAt: 'final' }, { repeat: growing.repeat });
  // Entrée de 1 Mio dont le libellé est plus court que la valeur : le texte masqué reste sous la limite.
  const shrinking = filledPrefix(MAX_INPUT_BYTES, `\ntoken ${github('limit')}\n`);
  add('limit/redacted-text-under-1mib', shrinking.rest, { failure: 'none', minLabels: 1 }, { repeat: shrinking.repeat });
  // Plus de 2 048 constats : analyse initiale incomplète (scan_error).
  add('incomplete/too-many-findings', '\n', { failure: 'incomplete', incompleteAt: 'initial' }, { repeat: { text: `${token} `, count: 2_100 } });
  const over = filledPrefix(MAX_INPUT_BYTES + 1, `\ntoken ${token}\n`);
  add('incomplete/input-over-1mib', over.rest, { failure: 'incomplete', incompleteAt: 'initial' }, { repeat: over.repeat });
  return sources;
}

/** Problème d'un cas dont le résultat ne tient pas son intention ; `undefined` s'il la tient. */
export function intentProblem(source: RedactSource, expected: RedactExpected, redacted: Uint8Array | null): string | undefined {
  const { intent } = source;
  if (expected.failure !== intent.failure) return `${source.id} : issue ${expected.failure}, attendu ${intent.failure}`;
  if (intent.incompleteAt === 'initial' && expected.initial?.complete !== false) return `${source.id} : analyse initiale complète`;
  if (intent.incompleteAt === 'final' && (expected.initial?.complete !== true || expected.final?.complete !== false)) {
    return `${source.id} : analyse finale complète`;
  }
  if (intent.minLabels !== undefined) {
    const labels = Buffer.from(redacted ?? new Uint8Array(0)).toString('latin1').split('<REDACTED_').length - 1;
    if (labels < intent.minLabels) return `${source.id} : ${String(labels)} libellé(s), au moins ${String(intent.minLabels)} attendu(s)`;
  }
  if (intent.adjacent === true) {
    const findings = expected.initial?.findings ?? [];
    if (!findings.some((f, i) => findings.slice(i + 1).some((g) => g.byteStart === f.byteEnd))) {
      return `${source.id} : aucun constat contigu`;
    }
  }
  return undefined;
}

/** Cas de `redact` seul, sur des constats construits (fusion, ordre, nommage, contenu non ASCII). */
export function spanSources(): SpanSource[] {
  const f = (ruleId: string, byteStart: number, byteEnd: number, score = 70): SpanFinding => ({ ruleId, score, byteStart, byteEnd });
  const digits = utf8('0123456789');
  const nonAscii = utf8('é😀密码abc😀z');
  return [
    // Test d'origine « unions overlapping and adjacent spans so no covered tail survives ».
    { id: 'spans/overlap-and-adjacent', bytes: digits, findings: [f('left', 2, 6), f('overlap', 4, 8), f('adjacent', 8, 9)] },
    { id: 'spans/same-span-higher-score-names', bytes: digits, findings: [f('low', 2, 6, 40), f('high', 2, 6, 90)] },
    { id: 'spans/same-span-equal-scores-first-kept', bytes: digits, findings: [f('first', 2, 6), f('second', 2, 6)] },
    { id: 'spans/same-start-shorter-names', bytes: digits, findings: [f('long', 2, 8, 90), f('short', 2, 4, 10)] },
    { id: 'spans/unsorted-disjoint', bytes: digits, findings: [f('c', 7, 9), f('b', 4, 5), f('a', 0, 2)] },
    { id: 'spans/gap-of-one-byte', bytes: digits, findings: [f('a', 1, 3), f('b', 4, 6)] },
    { id: 'spans/nested', bytes: digits, findings: [f('inner', 3, 5, 99), f('outer', 1, 9, 10)] },
    { id: 'spans/chain', bytes: digits, findings: [f('c', 4, 7), f('a', 0, 3), f('b', 2, 5)] },
    { id: 'spans/empty-spans-ignored', bytes: digits, findings: [f('e1', 3, 3), f('real', 5, 7), f('e2', 10, 10), f('e0', 0, 0)] },
    { id: 'spans/whole-content', bytes: digits, findings: [f('all', 0, 10)] },
    { id: 'spans/rule-id-sanitized', bytes: digits, findings: [f('a-b.c😀é z', 1, 3), f('', 5, 6)] },
    { id: 'spans/no-findings', bytes: digits, findings: [] },
    { id: 'spans/empty-content', bytes: new Uint8Array(0), findings: [] },
    // é (2 octets), 😀 (4), 密 码 (3 chacun), « abc », 😀, « z » : positions en octets ≠ positions UTF-16.
    { id: 'spans/non-ascii-content', bytes: nonAscii, findings: [f('emoji', 2, 6), f('cjk', 9, 12), f('tail', 15, 19)] },
    {
      id: 'spans/invalid-utf8-content',
      bytes: Uint8Array.from([0xff, 0x61, 0xc3, 0x62, 0xe2, 0x82, 0x63, 0xed, 0xa0, 0x80, 0x64]),
      findings: [f('inner', 2, 3), f('tail', 7, 10)],
    },
  ];
}
