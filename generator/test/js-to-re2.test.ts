import { describe, expect, it } from 'vitest';
import {
  JS_WHITESPACE_CLASS_BODY,
  UnsupportedPatternError,
  bodyCanMatchQuote,
  rewriteQuoteBackreference,
  translateJsPattern,
} from '../rule-pack/js-to-re2.ts';

const WS = `[${JS_WHITESPACE_CLASS_BODY}]`;

describe('traduction JavaScript → RE2', () => {
  it('\\s et \\S deviennent la classe explicite des espaces de JavaScript', () => {
    expect(translateJsPattern(String.raw`a\sb`, 'g').pattern).toBe(`a${WS}b`);
    expect(translateJsPattern(String.raw`[^\s"']`, '').pattern).toBe(`[^${JS_WHITESPACE_CLASS_BODY}"']`);
    expect(translateJsPattern(String.raw`\S+`, '').pattern).toBe(`[^${JS_WHITESPACE_CLASS_BODY}]+`);
    // La classe explicite reconnaît exactement les unités que `\s` de JavaScript reconnaît (BMP entier).
    const explicit = new RegExp(`[${JS_WHITESPACE_CLASS_BODY.replace(/\\x\{([0-9A-F]{4})\}/g, '\\u$1')}]`);
    for (let code = 0; code <= 0xffff; code += 1) {
      const unit = String.fromCharCode(code);
      expect(explicit.test(unit), code.toString(16)).toBe(/\s/.test(unit));
    }
    expect(JS_WHITESPACE_CLASS_BODY).toContain('\\x{3000}');
  });

  it('une borne supérieure de plus de 1 000 devient une répétition ouverte', () => {
    expect(translateJsPattern('a{4,2048}b{0,5000}c{1,1001}d{2,1000}', '')).toEqual({
      pattern: 'a{4,}b*c+d{2,1000}',
      openedRepetitions: [
        { min: 4, max: 2048 },
        { min: 0, max: 5000 },
        { min: 1, max: 1001 },
      ],
      backreferenceRewritten: false,
    });
    expect(() => translateJsPattern('a{1001}', '')).toThrow(UnsupportedPatternError);
    expect(() => translateJsPattern('a{1001,}', '')).toThrow(UnsupportedPatternError);
    expect(translateJsPattern('[{]{2}', '').pattern).toBe('[{]{2}');
  });

  it('drapeaux i (classes ASCII explicites), m, y (ancré à la position) et g', () => {
    expect(translateJsPattern('(?:auth|Sk)', 'gim').pattern).toBe('(?m)(?:[aA][uU][tT][hH]|[sS][kK])');
    // Sous i, un échappement qui ne code pas une lettre reste tel quel.
    expect(translateJsPattern(['\\x30', '\\u', '0021', '\\d'].join(''), 'i').pattern).toBe(String.raw`\x30\x{0021}\d`);
    expect(translateJsPattern('ab', 'y').pattern).toBe(String.raw`\A(?:ab)`);
    expect(translateJsPattern('a.b', '').pattern).toBe(String.raw`a[^\n\r\x{2028}\x{2029}]b`);
    expect(translateJsPattern(String.raw`\bx\b`, 'g').pattern).toBe(String.raw`\bx\b`);
    expect(translateJsPattern('[a-z]', 'i').pattern).toBe('[A-Za-z]');
    expect(() => translateJsPattern('a', 'u')).toThrow(UnsupportedPatternError);
    expect(() => translateJsPattern('a', 's')).toThrow(UnsupportedPatternError);
  });

  it('la rétro-référence (["\']?)X\\1 est réécrite par alternative', () => {
    expect(rewriteQuoteBackreference(String.raw`-u(["']?)([^:"']+):([^"']+)\1`)).toEqual({
      source: String.raw`-u(?:"([^:"']+):([^"']+)"|'([^:"']+):([^"']+)'|([^:"']+):([^"']+))`,
      rewritten: true,
    });
    expect(rewriteQuoteBackreference('abc')).toEqual({ source: 'abc', rewritten: false });
    const translated = translateJsPattern(String.raw`(["']?)(\w+)\1`, '');
    expect(translated.backreferenceRewritten).toBe(true);
    const re = new RegExp(translated.pattern);
    for (const [input, expected] of [
      ['"ab"', '"ab"'],
      ["'ab'", "'ab'"],
      ['ab', 'ab'],
    ] as const) {
      expect(re.exec(input)?.[0]).toBe(expected);
    }
  });

  it.each([
    ['autre rétro-référence', String.raw`(a)(b)\2`],
    ['rétro-référence sans groupe de guillemets', String.raw`(a)\1`],
    ['groupe capturant avant les guillemets', String.raw`(x)(["']?)a\1`],
    ['regard avant', 'a(?=b)'],
    ['regard arrière', '(?<=a)b'],
    ['groupe nommé', '(?<n>a)'],
    ['\\S dans une classe', String.raw`[\S]`],
    ['\\b dans une classe', String.raw`[\b]`],
    ['propriété Unicode', String.raw`\p{L}`],
    ['classe non fermée', '[ab'],
    ['classe vide', '[]'],
    ['\\x incomplet', String.raw`\xZ`],
    ['\\u incomplet', String.raw`\u12`],
    ['barre finale', 'a\\'],
  ])('refuse ce que RE2 ne connaît pas : %s', (_name, source) => {
    expect(() => translateJsPattern(source, '')).toThrow(UnsupportedPatternError);
  });

  it.each([
    ['\\x qui code une lettre ASCII', String.raw`\x41`],
    ['\\u qui code une lettre ASCII', ['\\u', '0061'].join('')],
    ['\\u qui code une lettre non ASCII', ['\\u', '00E9'].join('')],
    ['\\x qui code une lettre non ASCII', String.raw`\xE9`],
    ['lettre non ASCII littérale', 'é'],
    ['lettre non ASCII dans une classe', '[é]'],
    ['\\x d’une lettre dans une classe', String.raw`[\x41]`],
    ['plage qui couvre des lettres non ASCII', String.raw`[\x20-\xFF]`],
  ])('refuse sous le drapeau i : %s', (_name, source) => {
    expect(() => translateJsPattern(source, 'i')).toThrow(UnsupportedPatternError);
  });

  it('sous le drapeau i, une plage déjà repliée est admise', () => {
    expect(translateJsPattern('[!-~]', 'i').pattern).toBe('[!-~]');
    expect(translateJsPattern(String.raw`[\x20-\x7E]`, 'i').pattern).toBe(String.raw`[\x20-\x7E]`);
    expect(translateJsPattern('[0-9_-]', 'i').pattern).toBe('[0-9_-]');
  });

  it('sous le drapeau i, une lettre ASCII ou une plage de lettres ASCII d’une classe reçoit l’autre casse', () => {
    expect(translateJsPattern('[A-Z_]', 'i').pattern).toBe('[a-zA-Z_]');
    expect(translateJsPattern('[a-f0-9]', 'i').pattern).toBe('[A-Fa-f0-9]');
    expect(translateJsPattern('[0-Z]', 'i').pattern).toBe('[a-z0-Z]');
    expect(translateJsPattern(String.raw`[\x30-\x5A]`, 'i').pattern).toBe(String.raw`[a-z\x30-\x5A]`);
    expect(translateJsPattern('[x*]', 'i').pattern).toBe('[Xx*]');
    expect(translateJsPattern('[A-Za-z]', 'i').pattern).toBe('[A-Za-z]');
    expect(translateJsPattern('[-a]', 'i').pattern).toBe(String.raw`[A\-a]`);
    expect(translateJsPattern('[^a-]', 'i').pattern).toBe('[^Aa-]');
    expect(translateJsPattern('[A-Fx]', 'i').pattern).toBe('[Xa-fA-Fx]');
    expect(translateJsPattern('[_.-]', 'i').pattern).toBe('[_.-]');
    const re = new RegExp(translateJsPattern('^[A-Z_][a-f]$', 'i').pattern);
    for (const [input, expected] of [
      ['Za', true],
      ['zF', true],
      ['_c', true],
      ['ſa', false],
      ['\u212Aa', false],
      ['Ag', false],
      ['.a', false],
    ] as const) {
      expect(re.test(input)).toBe(expected);
      expect(/^[A-Z_][a-f]$/i.test(input)).toBe(expected);
    }
  });

  it.each(['a', 'z', 'A', 'Q', 'E', 'e', 'c', 'k', 'p', 'P', 'g', 'h', 'i', 'j', 'l', 'm', 'o', 'q', 'y', 'Z', 'X', 'U', 'N'])(
    'refuse l’échappement d’identité de la lettre %s (hors liste fermée)',
    (letter) => {
      expect(() => translateJsPattern(`a\\${letter}`, '')).toThrow(UnsupportedPatternError);
      expect(() => translateJsPattern(`[\\${letter}]`, '')).toThrow(UnsupportedPatternError);
    },
  );

  it('admet les échappements de la liste fermée', () => {
    expect(translateJsPattern(String.raw`\d\D\w\W\b\B\t\n\r\f\v\x2C\u002C\0`, '').pattern).toBe(
      String.raw`\d\D\w\W\b\B\t\n\r\f\v\x2C\x{002C}\x00`,
    );
    expect(() => translateJsPattern(String.raw`\01`, '')).toThrow(UnsupportedPatternError);
    expect(() => translateJsPattern('a\\ b', '')).toThrow(UnsupportedPatternError);
  });

  it.each([
    ['\\s en début de plage', String.raw`[\s-z]`],
    ['\\s en fin de plage', String.raw`[!-\s]`],
    ['\\d en extrémité de plage', String.raw`[\d-z]`],
    ['\\w en extrémité de plage', String.raw`[a-\w]`],
  ])('refuse une classe d’échappement en extrémité de plage : %s', (_name, source) => {
    expect(() => translateJsPattern(source, '')).toThrow(UnsupportedPatternError);
  });

  it('seule une rétro-référence non échappée et hors classe compte', () => {
    // `\\1` : barre oblique échappée suivie de 1, pas une rétro-référence.
    expect(rewriteQuoteBackreference(String.raw`(["']?)a\\1`)).toEqual({ source: String.raw`(["']?)a\\1`, rewritten: false });
    expect(translateJsPattern(String.raw`(["']?)a\\1`, '').backreferenceRewritten).toBe(false);
    // `[\1]` : octal dans une classe, pas une rétro-référence ; la traduction le refuse.
    expect(rewriteQuoteBackreference(String.raw`(["']?)[\1]`).rewritten).toBe(false);
    expect(() => translateJsPattern(String.raw`(["']?)[\1]`, '')).toThrow(UnsupportedPatternError);
  });

  it.each([
    ['classe qui admet les guillemets', String.raw`(["']?)([^:\s]+)\1`],
    ['point', String.raw`(["']?)(.+)\1`],
    ['guillemet littéral', String.raw`(["']?)a"b\1`],
    ['\\x22', String.raw`(["']?)a\x22\1`],
    ['\\S', String.raw`(["']?)\S+\1`],
    ['\\W', String.raw`(["']?)\W\1`],
    ['classe positive avec plage couvrant les guillemets', String.raw`(["']?)[!-~]+\1`],
  ])('refuse la rétro-référence quand le corps peut reconnaître un guillemet : %s', (_name, source) => {
    expect(() => rewriteQuoteBackreference(source)).toThrow(UnsupportedPatternError);
  });

  it('bodyCanMatchQuote vérifie chaque élément avec le moteur JavaScript', () => {
    expect(bodyCanMatchQuote(String.raw`([^:\s"']{1,256}):([^\s"']{1,1024})`, true)).toBe(false);
    expect(bodyCanMatchQuote(String.raw`(?:\w+|\d)\b`, false)).toBe(false);
    expect(bodyCanMatchQuote(String.raw`[^a]`, false)).toBe(true);
    expect(bodyCanMatchQuote("'", false)).toBe(true);
  });

  it('\\0 et les échappements communs restent équivalents', () => {
    expect(translateJsPattern(String.raw`\0\t\/\.`, '').pattern).toBe(String.raw`\x00\t\/\.`);
  });
});
