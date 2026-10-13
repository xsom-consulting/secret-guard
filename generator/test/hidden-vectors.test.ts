import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { MENTION_CWD, MENTION_REGEXES, HIDDEN_KINDS, type HiddenExpected, type MentionsExpected } from '../hidden/expected.ts';
import { serializeHiddenCase, serializeMentionCase, vectorInput, type VectorInput } from '../hidden/json.ts';
import { HIDDEN_VECTORS_FILE, MENTION_VECTORS_FILE, PORT_MAX_FINDINGS, PORT_SCATTERED_INVISIBLE_THRESHOLD } from '../hidden/main.ts';
import { hiddenSyntheticCases, JS_WHITESPACE, MAX_INPUT_BYTES, mentionSyntheticCases } from '../hidden/synthetic.ts';
import {
  buildHiddenUnicodeTablesGo,
  classRanges,
  HIDDEN_UNICODE_CLASSES,
  HIDDEN_UNICODE_TABLES_FILE,
  nodeUnicodeVersion,
  rangeTableGo,
} from '../hidden/unicode-tables.ts';
import { regexLiterals, UPSTREAM_COMMIT } from '../hidden/upstream.ts';

interface VectorFile<T> {
  readonly formatVersion: number;
  readonly upstreamCommit: string;
  readonly cases: readonly (VectorInput & { readonly expected: T })[];
  readonly [key: string]: unknown;
}

function load<T>(path: string): { text: string; file: VectorFile<T> } {
  const text = readFileSync(path, 'utf8');
  return { text, file: JSON.parse(text) as VectorFile<T> };
}

const hidden = load<HiddenExpected>(HIDDEN_VECTORS_FILE);
const mentions = load<MentionsExpected>(MENTION_VECTORS_FILE);

function caseLines(text: string): string[] {
  return text.split('\n').filter((line) => line.startsWith('{"id":')).map((line) => line.replace(/,$/, ''));
}

describe('tables Unicode des instructions cachées', () => {
  it('hidden/unicode_tables.go est celui du générateur (npm run hidden:tables), calculé par Node avec Unicode 17.0.0', () => {
    expect(nodeUnicodeVersion()).toBe('17.0.0');
    expect(readFileSync(HIDDEN_UNICODE_TABLES_FILE, 'utf8')).toBe(buildHiddenUnicodeTablesGo());
  });

  it('une plage à cheval sur U+FFFF est coupée entre R16 et R32 ; LatinOffset compte les plages Latin-1', () => {
    const table = rangeTableGo('t', 'x', [
      [0x41, 0x5a],
      [0x100, 0x200],
      [0xfff0, 0x10010],
    ]);
    expect(table).toContain('{Lo: 0xFFF0, Hi: 0xFFFF, Stride: 1},');
    expect(table).toContain('{Lo: 0x10000, Hi: 0x10010, Stride: 1},');
    expect(table).toContain('LatinOffset: 1,');
  });

  it('les classes ne contiennent aucun substitut et se ferment à U+10FFFF', () => {
    expect(classRanges(String.raw`^[\u{d7ff}-\u{e000}]$`)).toEqual([
      [0xd7ff, 0xd7ff],
      [0xe000, 0xe000],
    ]);
    expect(classRanges(String.raw`^\u{10ffff}$`)).toEqual([[0x10ffff, 0x10ffff]]);
    expect(HIDDEN_UNICODE_CLASSES.map((entry) => entry.name)).toEqual(['defaultIgnorable', 'emoji', 'letterOrMark', 'joiningScript', 'mongolian']);
  });
});

describe('vecteurs de parité des instructions cachées (vectors/hidden.json)', () => {
  it('en-tête : format, commit d’origine, constantes du portage', () => {
    expect(hidden.file.formatVersion).toBe(1);
    expect(hidden.file.upstreamCommit).toBe(UPSTREAM_COMMIT);
    expect(hidden.file['maxInputBytes']).toBe(MAX_INPUT_BYTES);
    expect(hidden.file['maxFindings']).toBe(PORT_MAX_FINDINGS);
    expect(hidden.file['scatteredInvisibleThreshold']).toBe(PORT_SCATTERED_INVISIBLE_THRESHOLD);
  });

  it('écriture canonique : chaque ligne est réécrite à l’identique, identifiants uniques', () => {
    const lines = caseLines(hidden.text);
    expect(lines).toHaveLength(hidden.file.cases.length);
    hidden.file.cases.forEach((value, index) => {
      expect(serializeHiddenCase(value, value.expected)).toBe(lines[index]);
    });
    expect(new Set(hidden.file.cases.map((value) => value.id)).size).toBe(hidden.file.cases.length);
  });

  it('les cas synthétiques sont ceux du générateur, dans l’ordre ; chaque sorte a un cas positif', () => {
    const synthetic = hiddenSyntheticCases().map((value) => vectorInput(value.id, value.bytes));
    expect(hidden.file.cases.slice(0, synthetic.length).map(({ id, input, inputEncoding }) => ({ id, input, inputEncoding }))).toEqual(synthetic);
    expect(hidden.file.cases.slice(synthetic.length).every((value) => value.id.startsWith('upstream/file-guard.test.ts > '))).toBe(true);
    const kinds = new Set(hidden.file.cases.flatMap((value) => value.expected.findings.map((finding) => finding.kind)));
    expect([...kinds].sort()).toEqual([...HIDDEN_KINDS].sort());
  });

  it('les bornes de 1 Mio sont couvertes des deux côtés', () => {
    const limits = hidden.file.cases.filter((value) => value.id.startsWith('synthetic/limit/'));
    expect(limits.map((value) => [value.id, value.expected.complete])).toEqual([
      ['synthetic/limit/exactly-1mib-ascii', true],
      ['synthetic/limit/1mib-plus-one-ascii', false],
      ['synthetic/limit/exactly-1mib-hidden-at-end', true],
      ['synthetic/limit/1mib-plus-one-hidden-at-end', false],
    ]);
  });

  it('aucun caractère invisible n’est écrit tel quel dans le fichier', () => {
    expect(/[\p{Default_Ignorable_Code_Point}\p{Cc}]/u.test(hidden.text.replaceAll('\n', ''))).toBe(false);
  });
});

describe('vecteurs de parité des mentions (vectors/mentions.json)', () => {
  it('en-tête : format, commit d’origine, répertoire de travail, expressions de mentionedPaths', () => {
    expect(mentions.file.formatVersion).toBe(1);
    expect(mentions.file.upstreamCommit).toBe(UPSTREAM_COMMIT);
    expect(mentions.file['cwd']).toBe(MENTION_CWD);
    expect(mentions.file['patterns']).toEqual(MENTION_REGEXES.map((regex) => `/${regex.source}/${regex.flags}`));
  });

  it('écriture canonique et cas synthétiques du générateur', () => {
    const lines = caseLines(mentions.text);
    mentions.file.cases.forEach((value, index) => {
      expect(serializeMentionCase(value, value.expected)).toBe(lines[index]);
    });
    const synthetic = mentionSyntheticCases().map((value) => vectorInput(value.id, value.bytes));
    expect(mentions.file.cases.slice(0, synthetic.length).map(({ id, input, inputEncoding }) => ({ id, input, inputEncoding }))).toEqual(synthetic);
    expect(mentions.file.cases.some((value) => value.id.startsWith('upstream/file-guard.test.ts > local file reading'))).toBe(true);
  });

  it('aucun caractère invisible n’est écrit tel quel dans le fichier', () => {
    expect(/[\p{Default_Ignorable_Code_Point}\p{Cc}]/u.test(mentions.text.replaceAll('\n', ''))).toBe(false);
  });

  it('chaque espacement de JavaScript précède une mention ; chaque cas « not-whitespace » n’en a aucune', () => {
    for (const [name] of JS_WHITESPACE) {
      const found = mentions.file.cases.find((value) => value.id === `synthetic/whitespace/${name}`);
      expect(found?.expected.mentions, name).toHaveLength(1);
    }
    expect(JS_WHITESPACE.every(([, point]) => /^\s$/u.test(String.fromCodePoint(point)))).toBe(true);
    for (const value of mentions.file.cases.filter((entry) => entry.id.startsWith('synthetic/not-whitespace/'))) {
      expect(value.expected.mentions, value.id).toEqual([]);
    }
  });
});

describe('outils du générateur', () => {
  it('vectorInput : UTF-8 valide (BOM compris) en texte, sinon base64', () => {
    expect(vectorInput('a', new TextEncoder().encode('\u{feff}x'))).toEqual({ id: 'a', input: '\u{feff}x', inputEncoding: 'utf8' });
    expect(vectorInput('b', Uint8Array.of(0x40, 0xff))).toEqual({ id: 'b', input: 'QP8=', inputEncoding: 'base64' });
  });

  it('regexLiterals relève les expressions d’un source ou d’une seule fonction', () => {
    const source = 'const A = /a/u;\nexport function f(x: string) { return x.replace(/b+$/u, "").match(/c/gu); }\nconst B = /d/;';
    expect(regexLiterals(source, 'x.ts')).toEqual([
      { source: 'a', flags: 'u' },
      { source: 'b+$', flags: 'u' },
      { source: 'c', flags: 'gu' },
      { source: 'd', flags: '' },
    ]);
    expect(regexLiterals(source, 'x.ts', 'f')).toEqual([
      { source: 'b+$', flags: 'u' },
      { source: 'c', flags: 'gu' },
    ]);
    expect(() => regexLiterals(source, 'x.ts', 'g')).toThrow(/introuvable/);
  });
});
