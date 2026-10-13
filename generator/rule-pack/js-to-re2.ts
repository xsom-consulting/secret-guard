/**
 * Traduction d'un motif JavaScript du catalogue Secret Guard en syntaxe RE2 (`regexp` de Go).
 * Fonctions pures ; règles détaillées dans `docs/rule-pack.md` :
 *   - `\s` (et `\s` dans une classe) → classe explicite des espaces de JavaScript ; `\S` → sa négation ;
 *   - `.` → tout caractère sauf les fins de ligne de JavaScript (`\n`, `\r`, U+2028, U+2029) ;
 *   - drapeau `i` → classes explicites des lettres ASCII (`[aA]`) : `(?i)` de RE2 replierait aussi `ſ` et `K` (U+212A),
 *     ce que JavaScript sans `u` ne fait pas ;
 *   - drapeau `m` → `(?m)` ; drapeau `y` (collant) → motif ancré à la position (`\A(?:…)`, appliqué par le moteur
 *     au texte qui commence à cette position) ; drapeau `g` ignoré ;
 *   - répétition dont la borne supérieure dépasse 1 000 (limite de RE2) → répétition ouverte, bornes rendues à
 *     l'appelant (`minLength`/`maxLength` du Pack) ;
 *   - `\b` inchangé : en JavaScript sans `u` comme en RE2, il ne connaît que les caractères de mot ASCII ;
 *   - rétro-référence `(["']?)X\1` → alternative `(?:"X"|'X'|X)` (seule forme admise).
 * Toute autre construction absente de RE2 ou de sens différent (regard avant ou arrière, autre rétro-référence, groupe
 * nommé, drapeaux `u`, `s`, `d`, `v`, échappement d'une lettre hors de la liste fermée `ESCAPED_LETTERS`, octal
 * hérité, lettre que le drapeau `i` replierait sans classe ASCII explicite, classe d'échappement en extrémité de
 * plage) lève une erreur : rien n'est traduit à moitié.
 */

/** Limite de RE2 pour une borne de répétition. */
export const RE2_REPEAT_MAX = 1_000;

/** Corps de la classe des espaces de `\s` en JavaScript (WhiteSpace et LineTerminator d'ECMAScript), en RE2. */
export const JS_WHITESPACE_CLASS_BODY =
  '\\t\\n\\x0B\\f\\r \\x{00A0}\\x{1680}\\x{2000}-\\x{200A}\\x{2028}\\x{2029}\\x{202F}\\x{205F}\\x{3000}\\x{FEFF}';

/** `.` de JavaScript : tout caractère sauf ses fins de ligne. */
const JS_DOT = '[^\\n\\r\\x{2028}\\x{2029}]';

export interface OpenedRepetition {
  readonly min: number;
  readonly max: number;
}

export interface Translation {
  readonly pattern: string;
  /** Répétitions rendues ouvertes (borne supérieure > 1 000), dans l'ordre du motif. */
  readonly openedRepetitions: readonly OpenedRepetition[];
  /** Vrai si la rétro-référence `(["']?)X\1` a été réécrite par alternative. */
  readonly backreferenceRewritten: boolean;
}

export class UnsupportedPatternError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsupportedPatternError';
  }
}

const QUOTE_GROUP = `(["']?)`;

/**
 * Lettres admises après `\` : classes (`\d \D \w \W \s \S`), limites de mot (`\b \B`), caractères de commande
 * (`\t \n \r \f \v`) et codes (`\x \u`), plus `\0` (sans chiffre à la suite). Toute autre lettre échappée est refusée :
 * en JavaScript sans `u` elle vaut la lettre elle-même, en RE2 elle a un autre sens (`\a`, `\z`, `\A`, `\Q`…) ou
 * n'existe pas (`\e`). Les chiffres de rétro-référence sont traités par `rewriteQuoteBackreference`.
 */
export const ESCAPED_LETTERS = 'dDwWsSbBtnrfvxu';

/** Codes des caractères de commande échappés. */
const CONTROL_ESCAPES: Readonly<Record<string, number>> = { t: 0x09, n: 0x0a, r: 0x0d, f: 0x0c, v: 0x0b };

const ASCII_PUNCTUATION = /^[!-/:-@[-`{-~]$/;

/** Indique si la parenthèse ouvrante en `index` ouvre un groupe capturant (hors classe, non échappée). */
function capturingGroupOpenings(source: string): number[] {
  const openings: number[] = [];
  let inClass = false;
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    if (character === '\\') {
      index += 1;
    } else if (inClass) {
      if (character === ']') {
        inClass = false;
      }
    } else if (character === '[') {
      inClass = true;
    } else if (character === '(' && source[index + 1] !== '?') {
      openings.push(index);
    }
  }
  return openings;
}

/** Rétro-références `\N` (N de 1 à 9, chiffres suivants compris) non échappées et hors classe : position et texte. */
function backreferences(source: string): { readonly index: number; readonly text: string }[] {
  const found: { index: number; text: string }[] = [];
  let inClass = false;
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    if (character === '\\') {
      if (!inClass) {
        const digits = /^[1-9][0-9]*/.exec(source.slice(index + 1));
        if (digits !== null) {
          found.push({ index, text: `\\${digits[0]}` });
        }
      }
      index += 1;
    } else if (inClass) {
      if (character === ']') {
        inClass = false;
      }
    } else if (character === '[') {
      inClass = true;
    }
  }
  return found;
}

/**
 * Vrai si le motif JavaScript `body` peut reconnaître `"` ou `'` : chaque élément qui consomme un caractère (lettre,
 * échappement, classe, `.`) est soumis au moteur JavaScript lui-même avec `"` puis `'`. Un élément que l'analyse ne
 * sait pas isoler compte comme pouvant les reconnaître.
 */
export function bodyCanMatchQuote(body: string, ignoreCase: boolean): boolean {
  const flags = ignoreCase ? 'i' : '';
  const matchesQuote = (atom: string): boolean => {
    try {
      const re = new RegExp(`^(?:${atom})$`, flags);
      return re.test('"') || re.test("'");
    } catch {
      return true;
    }
  };
  for (let index = 0; index < body.length; ) {
    const character = body.charAt(index);
    if (character === '\\') {
      const next = body[index + 1];
      const length = next === 'x' ? 4 : next === 'u' ? 6 : 2;
      const atom = body.slice(index, index + length);
      // `\b` et `\B` ne consomment rien ; tout autre échappement est soumis au moteur.
      if (next !== 'b' && next !== 'B' && matchesQuote(atom)) {
        return true;
      }
      index += length;
      continue;
    }
    if (character === '[') {
      let end = index + 1;
      if (body[end] === '^') {
        end += 1;
      }
      if (body[end] === ']') {
        end += 1;
      }
      while (end < body.length && body[end] !== ']') {
        end += body[end] === '\\' ? 2 : 1;
      }
      if (end >= body.length || matchesQuote(body.slice(index, end + 1))) {
        return true;
      }
      index = end + 1;
      continue;
    }
    if (character === '(') {
      const group = /^\((?:\?(?::|=|!|<=|<!|<[A-Za-z_$][\w$]*>))?/.exec(body.slice(index));
      index += group?.[0].length ?? 1;
      continue;
    }
    if (character === '{') {
      const quantifier = /^\{\d+(?:,\d*)?\}/.exec(body.slice(index));
      if (quantifier !== null) {
        index += quantifier[0].length;
        continue;
      }
    }
    if (')|*+?^$'.includes(character)) {
      index += 1;
      continue;
    }
    if (character === '.' || matchesQuote(character.replace(/[{}]/, '\\$&'))) {
      return true;
    }
    index += 1;
  }
  return false;
}

/**
 * Réécrit l'unique forme de rétro-référence admise : `(["']?)` premier groupe capturant, puis `X`, puis `\1`
 * (une seule fois, en fin de `X`) → `(?:"X"|'X'|X)`. Seul un `\N` non échappé et hors classe compte comme
 * rétro-référence (dans une classe, `\N` est refusé par la traduction). `X` ne doit reconnaître ni `"` ni `'`
 * (`bodyCanMatchQuote`) : sinon la forme sans guillemets reconnaîtrait des guillemets dépareillés. Rend le motif
 * inchangé sans rétro-référence.
 */
export function rewriteQuoteBackreference(source: string, flags = ''): { readonly source: string; readonly rewritten: boolean } {
  const references = backreferences(source);
  if (references.length === 0) {
    return { source, rewritten: false };
  }
  const groupStart = source.indexOf(QUOTE_GROUP);
  const [firstCapture] = capturingGroupOpenings(source);
  const reference = references[0];
  if (references.length !== 1 || reference?.text !== '\\1' || groupStart < 0 || firstCapture !== groupStart) {
    throw new UnsupportedPatternError('rétro-référence non admise : seule la forme (["\']?)X\\1 se réécrit');
  }
  const body = source.slice(groupStart + QUOTE_GROUP.length, reference.index);
  if (body.length === 0 || body.includes(QUOTE_GROUP)) {
    throw new UnsupportedPatternError('rétro-référence non admise : groupe de guillemets vide ou répété');
  }
  if (bodyCanMatchQuote(body, flags.includes('i'))) {
    throw new UnsupportedPatternError('rétro-référence non admise : le corps entre les guillemets peut reconnaître " ou \'');
  }
  const rewritten = `(?:"${body}"|'${body}'|${body})`;
  return {
    source: source.slice(0, groupStart) + rewritten + source.slice(reference.index + reference.text.length),
    rewritten: true,
  };
}

const ASCII_LETTER = /^[A-Za-z]$/;

function caseClass(letter: string): string {
  return `[${letter.toLowerCase()}${letter.toUpperCase()}]`;
}

/** Vrai si le drapeau `i` de JavaScript peut replier ce caractère sur un autre (lettre ou caractère à casse). */
function isCaseSensitive(code: number): boolean {
  const character = String.fromCharCode(code);
  return /\p{L}/u.test(character) || character.toLowerCase() !== character.toUpperCase();
}

function isSurrogate(code: number): boolean {
  return code >= 0xd800 && code <= 0xdfff;
}

/** Élément traduit : un caractère (avec son code), une classe (`\d`, `\s`…) ou une assertion (`\b`, `\B`). */
type Atom =
  | { readonly kind: 'char'; readonly text: string; readonly code: number; readonly length: number }
  | { readonly kind: 'set' | 'assertion'; readonly text: string; readonly length: number };

/** Traduit une séquence d'échappement ; rend le texte RE2, sa nature et la longueur consommée. */
function translateEscape(source: string, index: number, inClass: boolean): Atom {
  const next = source[index + 1];
  if (next === undefined) {
    throw new UnsupportedPatternError('motif terminé par \\');
  }
  if (next === 's') {
    return { kind: 'set', text: inClass ? JS_WHITESPACE_CLASS_BODY : `[${JS_WHITESPACE_CLASS_BODY}]`, length: 2 };
  }
  if (next === 'S') {
    if (inClass) {
      throw new UnsupportedPatternError('\\S dans une classe : non traduit');
    }
    return { kind: 'set', text: `[^${JS_WHITESPACE_CLASS_BODY}]`, length: 2 };
  }
  if ('dDwW'.includes(next)) {
    return { kind: 'set', text: `\\${next}`, length: 2 };
  }
  if (next === 'b' || next === 'B') {
    if (inClass) {
      throw new UnsupportedPatternError(`\\${next} dans une classe : non traduit`);
    }
    return { kind: 'assertion', text: `\\${next}`, length: 2 };
  }
  const control = CONTROL_ESCAPES[next];
  if (control !== undefined) {
    return { kind: 'char', text: `\\${next}`, code: control, length: 2 };
  }
  if (next === 'u' || next === 'x') {
    const digits = next === 'u' ? 4 : 2;
    const hex = new RegExp(`^[0-9A-Fa-f]{${String(digits)}}`).exec(source.slice(index + 2));
    if (hex === null) {
      throw new UnsupportedPatternError(`\\${next} sans ${digits === 4 ? 'quatre' : 'deux'} chiffres hexadécimaux`);
    }
    const code = Number.parseInt(hex[0], 16);
    if (isSurrogate(code)) {
      throw new UnsupportedPatternError('demi-code de substitution UTF-16 : non traduit');
    }
    return { kind: 'char', text: next === 'u' ? `\\x{${hex[0].toUpperCase()}}` : `\\x${hex[0]}`, code, length: digits + 2 };
  }
  if (next === '0') {
    if (/[0-9]/.test(source[index + 2] ?? '')) {
      throw new UnsupportedPatternError('échappement octal hérité : non traduit');
    }
    return { kind: 'char', text: '\\x00', code: 0, length: 2 };
  }
  if (/[1-9]/.test(next)) {
    throw new UnsupportedPatternError(inClass ? 'échappement octal dans une classe : non traduit' : 'rétro-référence restante');
  }
  if (ASCII_PUNCTUATION.test(next)) {
    return { kind: 'char', text: `\\${next}`, code: next.charCodeAt(0), length: 2 };
  }
  // Lettre hors de ESCAPED_LETTERS (\a \z \A \Q \E \e \c \k \p…), espace, caractère non ASCII.
  throw new UnsupportedPatternError(`échappement \\${next} : non traduit`);
}

/** Élément d'une classe : échappement ou caractère littéral. */
function classAtom(source: string, index: number): Atom {
  const character = source.charAt(index);
  if (character === '\\') {
    return translateEscape(source, index, true);
  }
  if (character === '[' && source[index + 1] === ':') {
    throw new UnsupportedPatternError('[: dans une classe : classe POSIX en RE2, non traduit');
  }
  const code = character.charCodeAt(0);
  if (isSurrogate(code)) {
    throw new UnsupportedPatternError('demi-code de substitution UTF-16 : non traduit');
  }
  return { kind: 'char', text: character, code, length: 1 };
}

/** Sous le drapeau `i`, refuse une plage qui couvre un caractère non ASCII à casse. */
function checkAsciiCaseRange(low: number, high: number): void {
  for (let code = low; code <= high; code += 1) {
    if (isCaseSensitive(code) && !ASCII_LETTER.test(String.fromCharCode(code))) {
      throw new UnsupportedPatternError('plage couvrant un caractère non ASCII à casse sous le drapeau i : non traduit');
    }
  }
}

/**
 * Sous le drapeau `i`, une lettre ASCII d'une classe reconnaît aussi son autre casse (JavaScript sans `u` ne replie
 * jamais un caractère non ASCII sur une lettre ASCII) : plages des lettres de l'autre casse que la classe ne couvre
 * pas encore (`covered` : caractères ASCII couverts par ses caractères et ses plages).
 */
function foldedLetters(covered: readonly boolean[]): string {
  const missing: number[] = [];
  for (let code = 0x41; code <= 0x7a; code += 1) {
    const other = code <= 0x5a ? code + 0x20 : code - 0x20;
    if (ASCII_LETTER.test(String.fromCharCode(code)) && covered[code] !== true && covered[other] === true) {
      missing.push(code);
    }
  }
  let out = '';
  for (let index = 0; index < missing.length; ) {
    let end = index;
    while (end + 1 < missing.length && missing[end + 1] === (missing[end] ?? 0) + 1) {
      end += 1;
    }
    const first = String.fromCharCode(missing[index] ?? 0);
    const last = String.fromCharCode(missing[end] ?? 0);
    out += end === index ? first : `${first}-${last}`;
    index = end + 1;
  }
  return out;
}

/** Traduit une classe à partir de `[` ; rend son texte RE2 et sa longueur. */
function translateClass(source: string, start: number, ignoreCase: boolean): { readonly text: string; readonly length: number } {
  let index = start + 1;
  let head = '[';
  let out = '';
  const covered: boolean[] = [];
  if (source[index] === '^') {
    head += '^';
    index += 1;
  }
  if (source[index] === ']') {
    throw new UnsupportedPatternError('classe vide ou commençant par ] : non traduit');
  }
  while (index < source.length && source[index] !== ']') {
    const low = classAtom(source, index);
    index += low.length;
    if (source[index] === '-' && index + 1 < source.length && source[index + 1] !== ']') {
      const high = classAtom(source, index + 1);
      index += 1 + high.length;
      if (low.kind !== 'char' || high.kind !== 'char') {
        throw new UnsupportedPatternError('classe d’échappement (\\s, \\d, \\w…) en extrémité de plage : non traduit');
      }
      if (low.code > high.code) {
        throw new UnsupportedPatternError('plage inversée');
      }
      if (ignoreCase) {
        checkAsciiCaseRange(low.code, high.code);
      }
      for (let code = low.code; code <= Math.min(high.code, 0x7f); code += 1) {
        covered[code] = true;
      }
      out += `${low.text}-${high.text}`;
      continue;
    }
    if (ignoreCase && low.kind === 'char' && isCaseSensitive(low.code)) {
      if (low.length !== 1 || !ASCII_LETTER.test(low.text)) {
        throw new UnsupportedPatternError('lettre échappée ou non ASCII dans une classe sous le drapeau i : non traduit');
      }
    }
    if (low.kind === 'char' && low.code <= 0x7f) {
      covered[low.code] = true;
    }
    out += low.text;
  }
  if (index >= source.length) {
    throw new UnsupportedPatternError('classe non fermée');
  }
  // Les plages de l'autre casse précèdent les éléments d'origine : ajoutées à la fin, elles formeraient une plage avec
  // un « - » final littéral ; un « - » initial devenu intérieur est échappé.
  const folded = ignoreCase ? foldedLetters(covered) : '';
  const items = folded !== '' && out.startsWith('-') ? `\\${out}` : out;
  return { text: `${head}${folded}${items}]`, length: index + 1 - start };
}

/**
 * Traduit le motif JavaScript `source` (texte entre les barres d'un littéral) et ses drapeaux en RE2.
 * Lève `UnsupportedPatternError` pour toute construction non traduite.
 */
export function translateJsPattern(source: string, flags: string): Translation {
  for (const flag of flags) {
    if (!'gimy'.includes(flag)) {
      throw new UnsupportedPatternError(`drapeau ${flag} : non traduit`);
    }
  }
  const ignoreCase = flags.includes('i');
  const { source: rewrittenSource, rewritten } = rewriteQuoteBackreference(source, flags);
  const opened: OpenedRepetition[] = [];
  let out = '';
  for (let index = 0; index < rewrittenSource.length; ) {
    const character = rewrittenSource.charAt(index);
    if (character === '\\') {
      const escape = translateEscape(rewrittenSource, index, false);
      if (ignoreCase && escape.kind === 'char' && isCaseSensitive(escape.code)) {
        throw new UnsupportedPatternError('échappement d’une lettre sous le drapeau i : non traduit');
      }
      out += escape.text;
      index += escape.length;
      continue;
    }
    if (character === '[') {
      const translated = translateClass(rewrittenSource, index, ignoreCase);
      out += translated.text;
      index += translated.length;
      continue;
    }
    if (character === '(' && rewrittenSource[index + 1] === '?' && rewrittenSource[index + 2] !== ':') {
      throw new UnsupportedPatternError('regard avant ou arrière, ou groupe nommé : absent de RE2');
    }
    if (character === '{') {
      const quantifier = /^\{(\d+)(?:(,)(\d*))?\}/.exec(rewrittenSource.slice(index));
      if (quantifier !== null) {
        const min = Number(quantifier[1]);
        const max = quantifier[2] === undefined ? min : quantifier[3] === '' ? undefined : Number(quantifier[3]);
        if (min > RE2_REPEAT_MAX) {
          throw new UnsupportedPatternError(`borne inférieure ${String(min)} > ${String(RE2_REPEAT_MAX)} : non traduit`);
        }
        if (max !== undefined && max > RE2_REPEAT_MAX) {
          if (quantifier[2] === undefined) {
            throw new UnsupportedPatternError(`répétition exacte ${String(max)} > ${String(RE2_REPEAT_MAX)} : non traduit`);
          }
          opened.push({ min, max });
          out += min === 0 ? '*' : min === 1 ? '+' : `{${String(min)},}`;
        } else {
          out += quantifier[0];
        }
        index += quantifier[0].length;
        continue;
      }
    }
    const code = character.charCodeAt(0);
    if (isSurrogate(code)) {
      throw new UnsupportedPatternError('demi-code de substitution UTF-16 : non traduit');
    }
    if (character === '.') {
      out += JS_DOT;
    } else if (ignoreCase && ASCII_LETTER.test(character)) {
      out += caseClass(character);
    } else if (ignoreCase && isCaseSensitive(code)) {
      throw new UnsupportedPatternError('lettre non ASCII sous le drapeau i : non traduit');
    } else {
      out += character;
    }
    index += 1;
  }
  let pattern = flags.includes('y') ? `\\A(?:${out})` : out;
  if (flags.includes('m')) {
    pattern = `(?m)${pattern}`;
  }
  return { pattern, openedRepetitions: opened, backreferenceRewritten: rewritten };
}
