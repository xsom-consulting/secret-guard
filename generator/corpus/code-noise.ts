// SPDX-License-Identifier: Apache-2.0
/**
 * Cas du corpus de parité pour le code ordinaire (v0.10.0) : `vectors/detection/rules-code-noise.json`.
 *
 * Le moteur Go n'émet plus de constat d'affectation quand la valeur lue après un nom sensible n'est pas un littéral
 * (`detect/codenoise.go`, `detect/publicvalues.go`). Le moteur TypeScript d'origine, lui, la signale : le résultat
 * attendu d'un cas vient donc d'une seconde écriture de ces filtres, faite ici, qui part des constats du moteur
 * d'origine et décide pour chacun s'il reste, s'il tombe, ou s'il laisse la place aux littéraux que porte la
 * structure. Elle est écrite avec le moteur d'expressions de JavaScript, sans RE2 ni le moteur Go, et ne lit que les
 * formes que ces cas éprouvent : toute autre forme arrête le générateur (« cas à redessiner »), elle n'est jamais
 * devinée.
 *
 * Les cas vont par voisins : la forme écartée (négatif) et la même forme qui porte un littéral (positif, le vrai
 * positif gardé). Aucune valeur relevée : littéraux tirés de SHA-256 (`synth`), noms sensibles assemblés par morceaux.
 */
import { byteOffsetOf, decodeInput, utf8Bytes, type DecodedInput } from './bytes.ts';
import { CorpusError, type CaseSource } from './corpus.ts';
import { compareFindings, levelForScore, type CorpusExpected, type CorpusFinding } from './model.ts';
import { synth, type CaseIntent } from './synthetic.ts';
import type { EngineFinding, UpstreamEngine } from './upstream.ts';

/** Fichier du corpus qui porte ces cas (famille `rules`, couverte par l'exception de `.gitleaks.toml`). */
export const CODE_NOISE_FILE = 'rules-code-noise.json';

// Noms sensibles, assemblés : ce fichier n'écrit aucune affectation à nom sensible.
const PASSWORD = ['pass', 'word'].join('');
const TOKEN = ['tok', 'en'].join('');
const API_KEY = ['api', 'Key'].join('');
const SECRET = ['sec', 'ret'].join('');
const AUTH = ['Authori', 'zation'].join('');
const USER_OPTION = ['-', 'u'].join('');

const LOWER = 'abcdefghijkmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
const DIGITS = '23456789';
const ALNUM = `${LOWER}${UPPER}${DIGITS}`;

const at = (label: string, alphabet: string, length: number): string => synth(`code-noise/${label}`, alphabet, length);
/** Littéral de forme stricte : majuscule, minuscules, chiffres, signe (quatre classes, 12 caractères). */
const strong = (label: string): string => `${at(`${label}/u`, UPPER, 2)}${at(`${label}/d`, DIGITS, 2)}#${at(`${label}/l`, LOWER, 4)}${at(`${label}/x`, DIGITS, 1)}${at(`${label}/y`, UPPER, 2)}`;
/** Littéral de lettres et de chiffres, sans signe (16 caractères). */
const plain = (label: string): string => `${at(`${label}/a`, LOWER, 5)}${at(`${label}/b`, DIGITS, 3)}${at(`${label}/c`, UPPER, 5)}${at(`${label}/d`, DIGITS, 3)}`;
/** Mot de passe fait de mots, sans chiffre. */
const WORDS = ['not', 'a', 'real', PASSWORD].join('-');

// ---------------------------------------------------------------------------------------------------------------
// Seconde écriture des filtres.
// ---------------------------------------------------------------------------------------------------------------

const CODE_LANGUAGES = new Set(['c', 'cpp', 'cs', 'csharp', 'go', 'java', 'javascript', 'javascriptreact', 'js', 'jsx', 'kotlin', 'php', 'py', 'python', 'rb', 'ruby', 'rs', 'rust', 'swift', 'ts', 'tsx', 'typescript', 'typescriptreact']);
const STRUCTURED_LANGUAGES = new Set(['hcl', 'json', 'jsonc', 'properties', 'terraform', 'toml', 'yaml', 'yml']);
const DOTENV_LANGUAGES = new Set(['dotenv', 'env', 'shell-env']);
const SHAPE_JUDGED = new Set(['api_key', 'access_token', `generic_${SECRET}`]);

/** Entropie de Shannon par unité UTF-16, comme `shannonEntropy` de l'origine. */
function entropy(value: string): number {
  const counts = new Map<string, number>();
  for (const character of value) counts.set(character, (counts.get(character) ?? 0) + 1);
  let bits = 0;
  for (const count of counts.values()) bits -= (count / value.length) * Math.log2(count / value.length);
  return bits;
}

function strongEntropy(value: string): boolean {
  return value.length >= 16 && entropy(value) >= (/^[0-9a-fA-F]+$/.test(value) ? 3 : 4.3);
}

function classes(value: string): { count: number; digits: number; letters: boolean } {
  const lower = /[a-z]/.test(value);
  const upper = /[A-Z]/.test(value);
  const digits = (value.match(/[0-9]/g) ?? []).length;
  const other = /[^A-Za-z0-9]/.test(value);
  return { count: Number(lower) + Number(upper) + Number(digits > 0) + Number(other), digits, letters: lower || upper };
}

/** Mot de nom (lecture simplifiée de `nameTokenLetters`) : minuscules, majuscule initiale, majuscules, casse de chameau, quatre chiffres au plus à la fin ; ou huit chiffres au plus. */
const NAME_WORD = /^(?:[0-9]{1,8}|(?:[a-z]+|[A-Z][a-z]{2,}|[A-Z]+|[A-Z]?[a-z]+(?:[A-Z][a-z]+)+)[0-9]{0,4})$/;

/** Forme d'un secret (palier 2). */
function secretShaped(value: string): boolean {
  if (value.length < 8 || /\s/.test(value)) return false;
  const c = classes(value);
  if (c.count >= 3 || (c.letters && c.digits >= 2 && value.length >= 10) || strongEntropy(value)) return true;
  return (value.match(/[A-Za-z0-9]+/g) ?? []).some((run) => run.length >= 12 && (!NAME_WORD.test(run) || (run.length > 15 && /^(?:[a-z]+|[A-Z]+)$/.test(run))));
}

/** Forme stricte : littéral porté par une structure. */
function strictShaped(value: string): boolean {
  if (value.length < 8 || /\s/.test(value)) return false;
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^@?]*$/.test(value) || /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(value) || /^\d{4}-\d{2}-\d{2}(?:T[0-9:.Z+-]{5,})?$/.test(value)) return false;
  const c = classes(value);
  return strongEntropy(value) || (c.digits > 0 && c.count >= 3);
}

function hasSecretWord(text: string): boolean {
  return text.split(/[ \t\r\n]+/).some((word) => secretShaped(word.replace(/^["'`([{<]+/, '').replace(/["'`)\]}>,;.:]+$/, '')));
}

/** Chaînes entre guillemets d'une ligne ou d'une région : position de l'ouverture, contenu, rôle. */
interface Quoted {
  readonly open: number;
  readonly close: number;
  readonly content: string;
  /** Nom d'un champ : suivi de « : », précédé de « { », « , » ou d'un début de ligne. */
  readonly field: boolean;
  /** Dans une donnée (crochets, accolades) et non dans une liste d'arguments. */
  readonly data: boolean;
  /** Valeur d'un champ au nom sensible. */
  readonly underSensitive: boolean;
}

const SENSITIVE_NAME = new RegExp(`(?:${PASSWORD}|passwd|${TOKEN}|${SECRET}|apikey|api_key|${AUTH})$`, 'i');

function quotedStrings(text: string, from: number, to: number, data: boolean): Quoted[] {
  const out: Quoted[] = [];
  const stack: boolean[] = [];
  for (let i = from; i < to; i += 1) {
    const c = text[i] ?? '';
    if ('([{'.includes(c)) stack.push(c !== '(');
    else if (')]}'.includes(c)) stack.pop();
    else if (c === '"' || c === "'" || c === '`') {
      let close = i + 1;
      while (close < to && text[close] !== c && text[close] !== '\n') close += text[close] === '\\' ? 2 : 1;
      if (close >= to || text[close] !== c) continue;
      const before = text.slice(from, i).replace(/[ \t]+$/, '');
      const after = text.slice(close + 1).replace(/^[ \t]+/, '');
      const field = /^:(?!:)/.test(after) && (before === '' || /[{,\n\r]$/.test(before));
      const lead = /([A-Za-z0-9_.-]+)["']?[ \t]*:?[:=]$/.exec(before);
      out.push({ open: i, close, content: text.slice(i + 1, close), field, data: stack.at(-1) ?? data, underSensitive: lead !== null && SENSITIVE_NAME.test((lead[1] ?? '').replace(/[^A-Za-z0-9]/g, '')) });
      i = close;
    }
  }
  return out;
}

function credible(q: Quoted, secretType: string): boolean {
  if (q.field) return false;
  if (strictShaped(q.content)) return true;
  return q.data && secretType === PASSWORD && q.content.length >= 8 && !/\s/.test(q.content) && !/^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^@?]*$/.test(q.content);
}

function hasCredible(text: string, from: number, to: number, secretType: string, data: boolean, words: boolean): boolean {
  if (quotedStrings(text, from, to, data).some((q) => credible(q, secretType))) return true;
  if (!words) return false;
  const bare = text.slice(from, to).replace(/(["'`])(?:\\.|(?!\1)[^\\\n])*\1/g, ' ');
  return bare.split(/[\s()[\]{},;:=]+/).some((word) => strictShaped(word));
}

/** Position qui suit la fermeture de l'ouverture `text[open]`, sur la même ligne ; -1 sinon. */
function balancedEnd(text: string, open: number, limit: number): number {
  let depth = 0;
  for (let i = open; i < Math.min(limit, open + 513); i += 1) {
    const c = text[i] ?? '';
    if (c === '\n' || c === '\r') return -1;
    if (c === '"' || c === "'" || c === '`') {
      let close = i + 1;
      while (close < limit && text[close] !== c && text[close] !== '\n') close += text[close] === '\\' ? 2 : 1;
      if (close < limit && text[close] === c) i = close;
    } else if ('([{'.includes(c)) depth += 1;
    else if (')]}'.includes(c)) {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

/** Fin de la référence qui commence en `i` (avant `limit`), ou -1 ; `inner` : où la relecture reprend. */
function referenceAt(text: string, i: number, limit: number, secretType: string): { end: number; inner: number } | undefined {
  const rest = text.slice(i, limit);
  const template = (open: number, closing: string): { end: number; inner: number } | undefined => {
    const found = text.slice(i + open, limit).indexOf(closing);
    const body = found < 0 ? '' : text.slice(i + open, i + open + found);
    if (found <= 0 || /[\r\n]/.test(body) || body.trim() === '' || hasCredible(text, i + open, i + open + found, secretType, false, false)) return undefined;
    return { end: i + open + found + closing.length, inner: i + open };
  };
  if (rest.startsWith('${{')) return template(3, '}}');
  if (rest.startsWith('{{')) return template(2, '}}');
  if (rest.startsWith('#{') || rest.startsWith('%{')) return template(2, '}');
  if (rest.startsWith('$(')) {
    const end = balancedEnd(text, i + 1, limit);
    return end < 0 || hasCredible(text, i + 2, end - 1, secretType, false, true) ? undefined : { end, inner: i + 2 };
  }
  if (rest.startsWith('${')) {
    const end = balancedEnd(text, i + 1, limit);
    if (end < 0) return undefined;
    const body = text.slice(i + 2, end - 1);
    const shell = /^[#!]?[A-Za-z_$][A-Za-z0-9_$.]*(.*)$/s.exec(body);
    const expression = (): { end: number; inner: number } | undefined => (body.trim() === '' || hasCredible(text, i + 2, end - 1, secretType, false, false) ? undefined : { end, inner: i + 2 });
    if (shell === null) return expression();
    const tail = shell[1] ?? '';
    if (tail === '') return { end, inner: end };
    const operator = /^:?[-=+?]/.exec(tail);
    if (operator === null) return /^[[%#/^,@]/.test(tail) ? { end, inner: end } : expression();
    const operand = tail.slice(operator[0].length);
    if (operator[0].includes('?') || operand === '') return { end, inner: end };
    const nested = referenceAt(text, end - 1 - operand.length, end - 1, secretType);
    return nested !== undefined && nested.end === end - 1 ? { end, inner: end } : undefined;
  }
  const variable = /^\$(?:[0-9@*#?!]|[A-Za-z_][A-Za-z0-9_]*)/.exec(rest);
  if (variable !== null) return { end: i + variable[0].length, inner: i + variable[0].length };
  if (/^%[svdq](?![A-Za-z0-9])/.test(rest)) return { end: i + 2, inner: i + 2 };
  return undefined;
}

/** Ce qui suit `cursor` prolonge la valeur : caractère collé, ou opérateur de concaténation ou de repli. */
function concatTail(text: string, cursor: number): boolean {
  const c = text[cursor];
  if (c === undefined) return false;
  if (c !== ' ' && c !== '\t') return ',;#})]\r\n"\'`\\|&><'.includes(c) ? text.startsWith('||', cursor) : true;
  return /^[ \t]+(?:\+|\|\||\?\?|\.\.)/.test(text.slice(cursor));
}

/** Contenu d'une chaîne fait de références : rend où reprendre, ou -1. */
function interpolation(text: string, start: number, end: number, secretType: string, fields: boolean): number {
  const literalOk = (from: number, to: number): boolean => (secretType === PASSWORD ? !/[A-Za-z0-9\u0080-￿]/.test(text.slice(from, to)) : !hasSecretWord(text.slice(from, to)));
  let references = 0;
  let inner = end;
  let literalStart = start;
  for (let i = start; i < end; ) {
    const c = text[i] ?? '';
    let reference: { end: number; inner: number } | undefined;
    if (fields && c === '{' && text[i + 1] !== '{') {
      const closing = balancedEnd(text, i, end);
      if (closing > i + 2 && !hasCredible(text, i + 1, closing - 1, secretType, false, false)) reference = { end: closing, inner: i + 1 };
    } else if ('$`{#%'.includes(c)) {
      reference = c === '`' ? undefined : referenceAt(text, i, end, secretType);
      if (reference !== undefined && (c === '$' || c === '%') && reference.inner === reference.end && text[i + 1] !== '{' && i > start && /[A-Za-z0-9]/.test(text[i - 1] ?? '')) reference = undefined;
    }
    if (reference === undefined) {
      i += 1;
      continue;
    }
    if (!literalOk(literalStart, i)) return -1;
    if (references === 0) inner = reference.inner;
    references += 1;
    i = reference.end;
    literalStart = i;
  }
  return references > 0 && literalOk(literalStart, end) ? inner : -1;
}

/** Valeur chiffrée. */
function encryptedEnvelope(value: string, quoted: boolean): boolean {
  const headers = ['$ANSIBLE_VAULT;', '!vault', '-----BEGIN AGE ENCRYPTED FILE-----', '-----BEGIN PGP MESSAGE-----', 'age-encryption.org/v'];
  const trimmed = value.trim();
  if (headers.some((header) => trimmed.startsWith(header))) return true;
  const firstLine = trimmed.indexOf('\n');
  if (firstLine >= 0) return firstLine < 64 && headers.some((header) => trimmed.slice(firstLine + 1).trim().startsWith(header));
  const word = quoted ? trimmed : (trimmed.split(/[ \t]/)[0] ?? '');
  return /^ENC\[[A-Z0-9_]+,data:.*\]$/.test(word) || /^\{cipher\}[A-Za-z0-9+/=]{16,}$/i.test(word) || /^vault:v[0-9]+:[A-Za-z0-9+/=_-]{8,}$/.test(word);
}

/** Formes de valeurs publiques que ces cas éprouvent (la liste entière est dans `detect/publicvalues.go`). */
const PUBLIC_FORMS: readonly { readonly pattern: RegExp; readonly keywords: readonly string[] }[] = [
  { pattern: /^phc_[A-Za-z0-9_-]{43,44}$/, keywords: [] },
  { pattern: /^sb_publishable_[A-Za-z0-9_-]{31}$/, keywords: [] },
  { pattern: /^pk_live_[A-Za-z0-9]{24}(?:[A-Za-z0-9]{10})?(?:[A-Za-z0-9]{65})?$/, keywords: ['stripe', 'woo', 'wcm'] },
  { pattern: /^[A-Za-z0-9]{32}$/, keywords: ['bugsnag'] },
];

function publicValue(text: string, start: number, end: number): boolean {
  const before = text.slice(text.lastIndexOf('\n', start - 1) + 1, start).toLowerCase();
  return PUBLIC_FORMS.some((form) => form.pattern.test(text.slice(start, end)) && (form.keywords.length === 0 || form.keywords.some((keyword) => before.includes(keyword))));
}

/** Verdict de la seconde écriture sur un constat d'origine. */
interface Verdict {
  readonly keep: boolean;
  /** Position où le moteur Go reprend sa lecture quand le constat tombe. */
  readonly resume?: number;
  /** Littéraux crédibles d'une structure, après sa première ligne. */
  readonly literals?: readonly (readonly [number, number])[];
}

const KEEP: Verdict = { keep: true };

interface Context {
  readonly text: string;
  readonly languageId: string | undefined;
}

/** Juge un constat d'affectation du moteur d'origine. */
function judgeAssignment(context: Context, finding: EngineFinding): Verdict {
  const { text, languageId } = context;
  const language = languageId?.toLowerCase();
  const span = text.slice(finding.start, finding.end);
  // Forme de la valeur, d'après l'étendue du constat d'origine.
  const quote = text[finding.start - 1] ?? '';
  const quotedBare = '"\'`'.includes(quote) && quote !== '' && text[finding.end] === quote;
  const quotedTail = !quotedBare && '"\'`'.includes(text[finding.start] ?? ' ');
  const syntaxStart = quotedBare ? finding.start - 1 : finding.start;
  // Préfixe de chaîne (« f"…" », « $"…" ») : hors de la valeur.
  const prefixed = /[fFrRbB$@]{1,2}$/.exec(text.slice(0, syntaxStart));
  const before = text.slice(0, syntaxStart - (quotedBare && prefixed !== null && /(?:^|[^A-Za-z0-9_])[fFrRbB$@]{1,2}$/.test(text.slice(0, syntaxStart)) ? prefixed[0].length : 0));
  const assignment = /(?:^|[\s,{;?&])((?:(?:export|set)\s+)?["']?[A-Za-z_][A-Za-z0-9_.-]{0,80}["']?\s*(?::=|[:=])\s*)$/.exec(before);
  const argument = /(?:^|\s)(--[A-Za-z][A-Za-z_-]*(?:=|\s+))$/.exec(before);
  const lead = assignment?.[1] ?? argument?.[1];
  if (lead === undefined) throw new CorpusError('affectation non reconnue par la lecture de référence : cas à redessiner');
  const leadStart = before.length - lead.length;
  const lineStart = text.lastIndexOf('\n', leadStart - 1) + 1;
  const linePrefix = text.slice(lineStart, before.length);
  const lineEnd = ((): number => {
    const found = text.indexOf('\n', finding.start);
    return found < 0 ? text.length : found;
  })();
  const secretType = finding.secretType;

  // Valeur de plusieurs lignes (bloc YAML, heredoc) : seul l'en-tête d'une enveloppe chiffrée est lu.
  if (span.includes('\n')) return encryptedEnvelope(span, false) ? { keep: false } : KEEP;

  // Étendue de la valeur lue.
  let valueStart = finding.start;
  let valueEnd = finding.end;
  if (quotedTail) {
    valueStart = finding.start + 1;
    valueEnd = valueStart;
    while (valueEnd < text.length && text[valueEnd] !== text[finding.start]) valueEnd += text[valueEnd] === '\\' ? 2 : 1;
  }
  const quoted = quotedBare || quotedTail;
  const unquotedEnd = quoted ? valueEnd : finding.start + (/^[^,;#}\r\n]*/.exec(text.slice(finding.start, lineEnd))?.[0] ?? '').replace(/[ \t]+$/, '').length;
  const placeholder = !quoted && /^(?:\$\{\{|\$\{|\{\{)/.test(span);

  if (encryptedEnvelope(quoted ? text.slice(valueStart, valueEnd) : text.slice(finding.start, lineEnd), quoted)) return { keep: false };

  // Valeur sans guillemets lue à la ligne suivante ; sous un mot de passe, seule une ligne qui est elle-même un champ.
  const mappingEntry = /^["']?[A-Za-z0-9_.-]+["']?[ \t]*:(?:[ \t]|$)/.test(text.slice(finding.start, lineEnd));
  if (!quoted && !placeholder && /[\r\n][ \t]*$/.test(before) && !hasSecretWord(text.slice(finding.start, lineEnd)) && (secretType !== PASSWORD || mappingEntry)) {
    return { keep: false, resume: text.lastIndexOf('\n', finding.start - 1) + 1 };
  }
  // Valeur publique connue.
  if ((secretType === 'api_key' || secretType === 'access_token') && publicValue(text, valueStart, quoted ? valueEnd : unquotedEnd)) return { keep: false };

  // Références.
  if (quoted) {
    const closing = valueEnd + 1;
    if (text.startsWith('$(', valueStart)) {
      const reference = referenceAt(text, valueStart, lineEnd, secretType);
      if (reference !== undefined && reference.end > valueEnd) {
        const after = reference.end + (text[reference.end] === text[valueStart - 1] ? 1 : 0);
        return concatTail(text, after) ? KEEP : { keep: false, resume: reference.inner };
      }
    }
    const scheme = /^(?:bearer|basic|token)[ \t]+(?=\S)/i.exec(text.slice(valueStart, valueEnd));
    const fields = /(?:^|[^A-Za-z0-9_$])[rRbB@]?[fF$][rRbB@]?$/.test(text.slice(0, valueStart - 1));
    const inner = interpolation(text, valueStart + (scheme?.[0].length ?? 0), valueEnd, secretType, fields);
    if (inner >= 0 && !concatTail(text, closing)) return { keep: false, resume: Math.max(inner, valueStart) };
  } else {
    const scheme = /^(?:bearer|basic|token)[ \t]+(?=\S)/i.exec(text.slice(finding.start, unquotedEnd));
    const first = finding.start + (scheme?.[0].length ?? 0);
    const reference = referenceAt(text, first, lineEnd, secretType);
    if (reference !== undefined && !concatTail(text, reference.end) && (!placeholder || reference.end === finding.start + (/^(?:\$\{\{.*?\}\}|\$\{[^}]*\}|\{\{.*?\}\})/.exec(span)?.[0].length ?? -1))) {
      return { keep: false, resume: Math.max(reference.inner, first + 1) };
    }
  }

  // Affectation nue d'environnement : rien d'autre.
  const plainAssignment = assignment !== undefined && assignment !== null && lead.trimEnd().endsWith('=') && !lead.trimEnd().endsWith(':=');
  const bare = (language !== undefined && DOTENV_LANGUAGES.has(language)) || (plainAssignment && /^\s*(?:(?:export|set)\s+)?[A-Z_][A-Z0-9_]*\s*=\s*$/.test(linePrefix));
  if (bare) return KEEP;

  const eligible =
    language !== undefined
      ? CODE_LANGUAGES.has(language) || STRUCTURED_LANGUAGES.has(language)
      : lead.includes(':') || /^\s*[a-z_][A-Za-z0-9_.-]*\s*:?=\s*$/.test(linePrefix) || /\b(?:const|final|let|mut|readonly|return|static|type|interface|enum|var)\b/.test(linePrefix);

  // Structures.
  if (!quoted && !placeholder) {
    const skipped = /^[!*&.]*(?:(?:await|new|return|yield|typeof|void|not|throw|delete)[ \t]+)?/.exec(text.slice(finding.start, unquotedEnd))?.[0].length ?? 0;
    const i = finding.start + skipped;
    const walked = (open: number): Verdict => {
      const closing = balancedEnd(text, open, lineEnd);
      if (closing >= 0 && closing < text.length && !/[\s,;)\]}.?:]/.test(text[closing] ?? ' ')) return KEEP;
      const bracketed = /^[([{][ \t]*([^\s"'`()[\]{},;:=]+)[ \t]*[)\]}]/.exec(text.slice(open, lineEnd));
      const word = bracketed?.[1] ?? '';
      if (hasCredible(text, open, lineEnd, secretType, true, false) || (bracketed !== null && (strictShaped(word) || (secretType === PASSWORD && word.length >= 8)))) return KEEP;
      // Lignes suivantes, jusqu'à la fermeture de la structure.
      let depth = 0;
      let end = -1;
      for (let k = open; k < Math.min(text.length, open + 4096); k += 1) {
        const c = text[k] ?? '';
        if (c === '"' || c === "'" || c === '`') {
          let close = k + 1;
          while (close < text.length && text[close] !== c && text[close] !== '\n') close += text[close] === '\\' ? 2 : 1;
          if (text[close] === c) k = close;
        } else if ('([{'.includes(c)) depth += 1;
        else if (')]}'.includes(c)) {
          depth -= 1;
          if (depth === 0) {
            end = k;
            break;
          }
        }
      }
      if (end < 0) {
        if (text.length > open + 4096) return KEEP;
        end = text.length;
      }
      const literals = quotedStrings(text, open, end, true)
        .filter((q) => q.open > lineEnd && !q.underSensitive && credible(q, secretType))
        .map((q) => [q.open + 1, q.close] as const);
      return { keep: false, resume: open + 1, literals };
    };
    const c = text[i] ?? '';
    if (c === '[' || (c === '{' && text[i + 1] !== '{')) return walked(i);
    if (eligible) {
      if (c === '(') return walked(i);
      const keyword = /^(?:function|async|lambda|func|fn)(?![A-Za-z0-9_$])/.exec(text.slice(i, unquotedEnd));
      if (keyword !== null) return { keep: false, resume: i + keyword[0].length };
      const path = /^[A-Za-z_$][A-Za-z0-9_$]*(?:(?:\?\.|\.|::|->)[A-Za-z_$][A-Za-z0-9_$]*)*/.exec(text.slice(i))?.[0] ?? '';
      const pathEnd = i + path.length;
      const next = text[pathEnd] ?? '';
      if (path !== '') {
        if (next === '(') return walked(pathEnd);
        if (next === '[' && path.includes('.')) return walked(pathEnd);
        if (next === '<' && /[A-Za-z_${]/.test(text[pathEnd + 1] ?? '')) return { keep: false, resume: pathEnd + 1 };
        // Type d'un paramètre : flèche ou accolade après la parenthèse, ou « ): » sur une ligne qui finit en signature.
        if (next === ')' && /^[ \t]*(?:=>|->|\{|:(?!:).*(?:\{|=>|;)[ \t]*$)/.test(text.slice(pathEnd + 1, lineEnd))) return { keep: false, resume: pathEnd };
      }
    }
  }

  // Palier 2 : du code seulement.
  const code = language !== undefined ? CODE_LANGUAGES.has(language) : /\b(?:const|let|var|return|readonly|public|private|protected|type|interface|enum)\b/.test(linePrefix);
  if (!SHAPE_JUDGED.has(secretType) || !code || hasSecretWord(text.slice(valueStart, Math.max(quoted ? valueEnd : unquotedEnd, quotedTail ? valueEnd : finding.end)))) return KEEP;
  if (quoted && concatTail(text, valueEnd + 1)) return KEEP;
  return { keep: false, resume: valueStart };
}

/** Juge un constat de l'option d'utilisateur : deux nombres, ou un format de date. */
function judgeBasicAuth(context: Context, finding: EngineFinding): Verdict {
  const [user = '', secret = ''] = context.text.slice(finding.start, finding.end).split(/:(.*)/s);
  return { keep: !(user.startsWith('+%') || (/^[0-9]+$/.test(user) && /^[0-9]+$/.test(secret))) };
}

const ASSIGNMENT_RULE = /^contextual_/;

/**
 * Constats attendus d'un texte : ceux du moteur d'origine, jugés un à un. Un constat qui tombe laisse au moteur Go la
 * suite de son étendue à relire : elle est relue par le moteur d'origine sur un texte dont le début de la ligne est
 * effacé (remplacé par des espaces, positions inchangées), et ses constats sont jugés à leur tour.
 */
function referenceFindings(engine: UpstreamEngine, context: Context, depth = 0): EngineFinding[] {
  const result = engine.scan(context.text, context.languageId);
  if (!result.complete) throw new CorpusError('analyse d’origine incomplète : cas à redessiner');
  const out: EngineFinding[] = [];
  for (const finding of result.findings) {
    if (finding.encoding !== 'plain') throw new CorpusError(`constat hors de la vue d’identité (${finding.ruleId}) : cas à redessiner`);
    let verdict = KEEP;
    if (finding.ruleId === 'cli_basic_auth') verdict = judgeBasicAuth(context, finding);
    else if (finding.ruleId === 'high_entropy') verdict = { keep: !publicValue(context.text, finding.start, finding.end) };
    else if (ASSIGNMENT_RULE.test(finding.ruleId)) verdict = judgeAssignment(context, finding);
    if (verdict.keep) {
      out.push(finding);
      continue;
    }
    for (const [start, end] of verdict.literals ?? []) {
      const value = context.text.slice(start, end);
      const score = finding.score - (strongEntropy(context.text.slice(finding.start, finding.end)) ? 5 : 0) + (strongEntropy(value) ? 5 : 0);
      out.push({ ...finding, score, level: levelForScore(score), start, end });
    }
    if (verdict.resume === undefined || verdict.resume >= finding.end) continue;
    if (depth >= 4) throw new CorpusError('relecture trop profonde : cas à redessiner');
    // Relecture de la suite de l'étendue : la ligne du nom sensible, jusqu'à la reprise, est effacée (fins de ligne
    // gardées).
    const lineStart = context.text.lastIndexOf('\n', Math.min(finding.start, verdict.resume) - 1) + 1;
    const nameLine = context.text.lastIndexOf('\n', lineStart - 2) + 1;
    const from = /[\r\n][ \t]*$/.test(context.text.slice(0, finding.start)) ? nameLine : lineStart;
    const masked = `${context.text.slice(0, from)}${context.text.slice(from, verdict.resume).replace(/[^\r\n]/g, ' ')}${context.text.slice(verdict.resume)}`;
    for (const again of referenceFindings(engine, { text: masked, languageId: context.languageId }, depth + 1)) {
      const known = result.findings.some((other) => other.start === again.start && other.end === again.end && other.ruleId === again.ruleId);
      if (!known && again.start >= verdict.resume && again.start < finding.end) out.push(again);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// Cas.
// ---------------------------------------------------------------------------------------------------------------

interface Draft {
  readonly id: string;
  readonly text: string;
  readonly languageId?: string;
  readonly intent: CaseIntent;
}

const RULE = { password: `contextual_${PASSWORD}`, token: 'contextual_access_token', apiKey: 'contextual_api_key', secret: `contextual_generic_${SECRET}`, cli: 'cli_basic_auth', entropy: 'high_entropy' } as const;

/** Forme écartée : le moteur d'origine signale ce texte, le moteur Go non. */
function noise(name: string, rule: string, text: string, languageId?: string): Draft {
  return { id: `code_noise/negative/${name}`, text: `${text}\n`, ...(languageId === undefined ? {} : { languageId }), intent: { kind: 'negative', rule } };
}

/** Vrai positif voisin : le constat reste. */
function kept(name: string, rule: string, text: string, languageId?: string): Draft {
  return { id: `code_noise/positive/${name}`, text: `${text}\n`, ...(languageId === undefined ? {} : { languageId }), intent: { kind: 'positive', rule } };
}

function drafts(): Draft[] {
  const option = `--${TOKEN}`;
  const upperToken = TOKEN.toUpperCase();
  const upperPassword = PASSWORD.toUpperCase();
  const posthog = `phc_${at('posthog', ALNUM, 43)}`;
  const supabase = `sb_publishable_${at('supabase', ALNUM, 31)}`;
  const bugsnag = at('bugsnag', ALNUM, 32);
  const stripe = `pk_live_${at('stripe', ALNUM, 24)}`;
  const cipherHex = at('cipher', '0123456789abcdef', 32);
  const pair = (user: string, secret: string): string => [user, secret].join(':');
  return [
    // Références de shell et de CI.
    noise('reference/variable-puis-option', RULE.token, `./config.sh --url "$REPO_URL" ${option} "$RUNNER_VALUE" --unattended --replace`, 'shellscript'),
    noise('reference/variable-sans-guillemets', RULE.token, `./config.sh ${option} $RUNNER_VALUE --unattended`),
    noise('reference/variable-apres-egal', RULE.token, `./config.sh ${option}="$RUNNER_VALUE" --unattended`, 'shellscript'),
    noise('reference/parametre-positionnel', RULE.token, `register ${option} "$1" --name "$2"`, 'shellscript'),
    noise('reference/expansion-a-message', RULE.token, `RUNNER_${upperToken}="\${RUNNER_VALUE:?variable requise}"`, 'shellscript'),
    noise('reference/expansion-defaut-variable', RULE.token, `${upperToken}="\${RUNNER_VALUE:-$OTHER_VALUE}"`, 'shellscript'),
    kept('reference/expansion-defaut-litteral', RULE.password, `      POSTGRES_${upperPassword}: \${POSTGRES_VALUE:-${plain('defaut')}}`, 'yaml'),
    noise('reference/substitution-de-commande', RULE.token, `./config.sh ${option} "$(gh api -X POST repos/o/r/runners --jq .value)" --unattended`),
    noise('reference/substitution-guillemets-imbriques', RULE.token, `export GH_${upperToken}="$(cat "$HOME/.config/value")"`, 'shellscript'),
    kept('reference/substitution-avec-litteral', RULE.token, `${upperToken}="$(fetch --key '${strong('substitution')}')"`, 'shellscript'),
    noise('reference/en-tete-a-schema', RULE.token, `curl -sS -H "${AUTH}: Bearer $RUNNER_VALUE" https://api.example.test/v1/runners`, 'shellscript'),
    noise('reference/option-de-mot-de-passe', RULE.password, `psql --host "$HOST" --${PASSWORD} "$PGPASS" --dbname app`, 'shellscript'),
    kept('reference/option-suivante-a-litteral', RULE.password, `./run.sh ${option} "$RUNNER_VALUE" --${PASSWORD} "${strong('option')}"`, 'shellscript'),
    noise('reference/expression-de-ci', RULE.token, `          GITHUB_${upperToken}: \${{ github.${TOKEN} }}`, 'yaml'),
    noise('reference/expression-de-ci-sortie', RULE.token, `          ${TOKEN}: \${{ steps.app.outputs.value }}`, 'yaml'),
    noise('reference/gabarit-helm', RULE.password, `  ${PASSWORD}: {{ .Values.database.value }}`, 'yaml'),
    noise('reference/gabarit-jinja-a-appel', RULE.password, `  ${PASSWORD}: "{{ lookup('env', 'DB_VALUE') }}"`, 'yaml'),
    kept('reference/gabarit-defaut-litteral', RULE.token, `  ${TOKEN}: {{ .Values.value | default "${strong('gabarit')}" }}`, 'yaml'),
    noise('reference/gabarit-javascript', RULE.apiKey, `  ${API_KEY}: \`\${prefix}-\${suffix}\`,`, 'typescript'),
    kept('reference/gabarit-javascript-litteral', RULE.apiKey, `  ${API_KEY}: \`${strong('gabarit-js')}\${suffix}\`,`, 'typescript'),
    noise('reference/chaine-a-champs', RULE.token, `    headers = {"${AUTH}": f"Bearer {access_value}"}`, 'python'),
    kept('reference/mot-de-passe-a-dollar', RULE.password, `${PASSWORD}: "Pa$${at('dollar', LOWER, 4)}${at('dollar/d', DIGITS, 2)}!x"`, 'yaml'),
    kept('reference/variable-concatenee', RULE.token, `const ${TOKEN} = "$PREFIX" + stored;`, 'typescript'),
    // Structures.
    noise('structure/tableau', RULE.apiKey, `  ${API_KEY}: ["cle-a", "cle-b"],`, 'typescript'),
    kept('structure/tableau-a-litteral', RULE.apiKey, `  ${API_KEY}: ["${strong('tableau')}"],`, 'typescript'),
    noise('structure/tableau-sur-plusieurs-lignes', RULE.apiKey, `const config = {\n  ${API_KEY}: [\n    primary,\n    fallback,\n  ],\n};`, 'typescript'),
    kept('structure/tableau-sur-plusieurs-lignes-a-litteral', RULE.apiKey, `const config = {\n  ${API_KEY}: [\n    "${strong('lignes')}",\n    fallback,\n  ],\n};`, 'typescript'),
    noise('structure/objet', RULE.secret, `  ${SECRET}: { ref: "vault://kv/app", version: 2 },`, 'typescript'),
    kept('structure/objet-a-litteral', RULE.secret, `  ${SECRET}: { value: "${strong('objet')}", version: 2 },`, 'typescript'),
    kept('structure/objet-json-a-mot-de-passe', RULE.password, `{"${PASSWORD}":{"value":"${WORDS}"}}`, 'json'),
    noise('structure/table-de-libelles', RULE.password, `  ${PASSWORD}: { label: "Mot de passe", hint: "8 caractères au moins" },`, 'typescript'),
    noise('structure/schema-json', RULE.password, `  "${PASSWORD}": { "type": "string", "minLength": 8 },`),
    kept('structure/objet-champ-ordinaire', RULE.secret, `${SECRET} = {\n  value = "${strong('champ')}"\n  version = 2\n}`),
    kept('structure/objet-champ-sensible', RULE.password, `const settings = {\n  ${SECRET}: {\n    ${PASSWORD}: "${strong('sensible')}",\n    label: "Base",\n  },\n};`, 'typescript'),
    noise('structure/appel', RULE.apiKey, `  ${API_KEY}: readSetting("provider.key"),`, 'typescript'),
    kept('structure/appel-a-litteral', RULE.token, `  ${TOKEN}: sign(payload, "${strong('appel')}"),`, 'typescript'),
    kept('structure/appel-sur-plusieurs-lignes-a-litteral', RULE.token, `  const ${TOKEN} = issue(\n    subject,\n    "${strong('appel-lignes')}",\n  );`),
    noise('structure/appel-go', RULE.token, `\t${TOKEN} := r.Header.Get("X-Request-Id")`, 'go'),
    noise('structure/type-generique', RULE.token, `  ${TOKEN}: Map<string, Session>;`, 'typescript'),
    noise('structure/fonction-flechee', RULE.token, `  ${TOKEN}: (request) => request.headers.get("x-request-id"),`),
    noise('structure/type-de-parametre', RULE.secret, `export function check(kind: Kind, ${SECRET}: string): boolean {`, 'typescript'),
    kept('structure/liste-en-ligne-a-mot-de-passe', RULE.password, `${PASSWORD}: [sesameouvretoi]`, 'yaml'),
    kept('structure/tableau-dotenv', RULE.token, `${upperToken}=[${WORDS}]`, 'dotenv'),
    kept('structure/objet-environnement', RULE.token, `export ${upperToken}={"a":"b"}`),
    kept('structure/accolades-et-texte-colle', RULE.password, `spring.datasource.${PASSWORD}={label}${strong('colle')}`, 'properties'),
    // Valeur lue à la ligne suivante.
    noise('ligne-suivante/cle-de-section', RULE.token, `    secrets:\n      NPM_${upperToken}:\n        required: true`, 'yaml'),
    noise('ligne-suivante/case-puis-instruction', RULE.token, `\tcase n == "${AUTH.toLowerCase()}":\n\t\treturn kind, true`, 'go'),
    kept('ligne-suivante/valeur-a-forme-de-secret', RULE.token, `${upperToken}:\n  ${plain('ligne')}`, 'yaml'),
    noise('ligne-suivante/champ-sous-un-mot-de-passe', RULE.password, `properties:\n  ${PASSWORD}:\n    type: string\n    minLength: 8`, 'yaml'),
    kept('ligne-suivante/mot-de-passe-d-un-mot', RULE.password, `${PASSWORD}:\n  sesameouvretoi`, 'yaml'),
    // Palier 2 : du code seulement.
    noise('code/valeur-d-essai', RULE.apiKey, `  ${API_KEY}: "test",`, 'typescript'),
    kept('code/valeur-d-essai-sans-langage', RULE.apiKey, `  ${API_KEY}: "test",`),
    noise('code/declaration-a-valeur-d-essai', RULE.apiKey, `const ${API_KEY} = "test-key";`),
    noise('code/litteral-de-type', RULE.token, `  ${TOKEN}: "bearer" as const,`, 'typescript'),
    noise('code/constante', RULE.secret, `    intake = await start({ port: 0, ${SECRET}: SHARED, sink: queue });`, 'typescript'),
    kept('code/mot-de-passe', RULE.password, `  ${PASSWORD}: "test",`, 'typescript'),
    kept('code/valeur-a-forme-de-secret', RULE.apiKey, `  ${API_KEY}: "${strong('code')}",`, 'typescript'),
    kept('code/lettres-sans-chiffre', RULE.apiKey, `  ${API_KEY}: "${at('lettres', LOWER + UPPER, 20)}",`, 'typescript'),
    kept('code/affectation-d-environnement', RULE.apiKey, `API_${'KEY'} = "test-key"`, 'python'),
    kept('code/yaml', RULE.token, `${TOKEN}: fixture`, 'yaml'),
    // Option d'utilisateur.
    noise('option/date', RULE.cli, `date ${USER_OPTION} ${['+%H', '%M', '%S'].join(':')}`),
    noise('option/docker-run', RULE.cli, `docker run --rm ${USER_OPTION} ${pair('1000', '1000')} alpine id`),
    kept('option/curl', RULE.cli, `curl ${USER_OPTION} ${pair('admin', strong('curl'))} https://api.example.test/`),
    kept('option/utilisateur-numerique', RULE.cli, `curl ${USER_OPTION} ${pair('1000', strong('numerique'))} https://api.example.test/`),
    // Valeurs chiffrées.
    noise('chiffre/sops', RULE.password, `    ${PASSWORD}: ENC[AES256_GCM,data:Zm9vYmFy,iv:YmFyYmF6,tag:cXV4cXV4,type:str]`, 'yaml'),
    noise('chiffre/spring', RULE.password, `spring.datasource.${PASSWORD}={cipher}${cipherHex}`, 'properties'),
    noise('chiffre/transit-de-vault', RULE.password, `  db_${PASSWORD}: vault:v1:${at('transit', ALNUM, 16)}`, 'yaml'),
    noise('chiffre/message-pgp', RULE.password, `${PASSWORD}: |\n  -----BEGIN PGP MESSAGE-----\n  hQEMA5vJ\n  -----END PGP MESSAGE-----`, 'yaml'),
    kept('chiffre/marque-sans-donnees', RULE.password, `${PASSWORD}: ENC[${strong('marque')}]`, 'yaml'),
    kept('chiffre/spring-suivi-d-un-litteral', RULE.password, `  ${PASSWORD}: '{cipher}${strong('spring')}'`, 'yaml'),
    // Valeurs publiques connues.
    noise('public/cle-de-projet', RULE.apiKey, `posthog.init({ ${API_KEY}: "${posthog}" })`),
    noise('public/cle-publiable', RULE.apiKey, `const ${API_KEY} = "${supabase}";`),
    noise('public/mot-cle-sur-la-ligne', RULE.apiKey, `Bugsnag.start({ ${API_KEY}: '${bugsnag}' })`),
    kept('public/sans-le-mot-cle', RULE.apiKey, `client.start({ ${API_KEY}: '${bugsnag}' })`),
    noise('public/variable-d-environnement', RULE.token, `STRIPE_PUBLIC_${upperToken}=${stripe}`),
    kept('public/mot-de-passe', RULE.password, `${PASSWORD}: "${posthog}"`),
    noise('public/entropie', RULE.entropy, `posthog.init('${posthog}')`),
  ];
}

/** Cas du code ordinaire, dans l'ordre de `drafts`. */
export function codeNoiseCases(): CaseSource[] {
  return drafts().map((draft) => ({
    file: CODE_NOISE_FILE,
    id: draft.id,
    bytes: utf8Bytes(draft.text),
    ...(draft.languageId === undefined ? {} : { languageId: draft.languageId }),
    intent: draft.intent,
  }));
}

function corpusFinding(decoded: DecodedInput, finding: EngineFinding): CorpusFinding {
  return {
    ruleId: finding.ruleId,
    secretType: finding.secretType,
    encoding: 'plain',
    score: finding.score,
    level: levelForScore(finding.score),
    byteStart: byteOffsetOf(decoded, finding.start),
    byteEnd: byteOffsetOf(decoded, finding.end),
  };
}

/** Constats attendus d'une entrée par la seconde écriture. */
export function codeNoiseReference(engine: UpstreamEngine, bytes: Uint8Array, languageId: string | undefined): CorpusFinding[] {
  const decoded = decodeInput(bytes);
  if (!decoded.validUtf8) throw new CorpusError('entrée hors UTF-8 : cas à redessiner');
  return referenceFindings(engine, { text: decoded.text, languageId })
    .map((finding) => corpusFinding(decoded, finding))
    .sort(compareFindings);
}

/** Constats du moteur d'origine sur la même entrée (ce que la seconde écriture juge). */
export function codeNoiseUpstream(engine: UpstreamEngine, bytes: Uint8Array, languageId: string | undefined): CorpusFinding[] {
  const decoded = decodeInput(bytes);
  const result = engine.scan(decoded.text, languageId);
  return result.findings.map((finding) => corpusFinding(decoded, finding)).sort(compareFindings);
}

/** Résultat attendu d'un cas. */
export function codeNoiseExpected(engine: UpstreamEngine, source: CaseSource): CorpusExpected {
  try {
    return { complete: true, failure: 'none', findings: codeNoiseReference(engine, source.bytes, source.languageId) };
  } catch (error) {
    if (error instanceof CorpusError) throw new CorpusError(`${source.id} : ${error.message}`);
    throw error;
  }
}

/**
 * Problèmes de couverture : intentions tenues ; un cas négatif est un texte que le moteur d'origine signale par la
 * règle visée (sinon il n'éprouve aucun filtre) ; au moins 25 négatifs et 25 positifs.
 */
export function codeNoiseCoverageProblems(
  cases: readonly { readonly id: string; readonly intent?: CaseIntent; readonly expected: CorpusExpected; readonly upstream: readonly CorpusFinding[] }[],
): string[] {
  const problems: string[] = [];
  const counts = { positive: 0, negative: 0 };
  for (const { id, intent, expected, upstream } of cases) {
    if (intent?.kind !== 'positive' && intent?.kind !== 'negative') {
      problems.push(`${id} : intention absente ou hors positif/négatif`);
      continue;
    }
    const fires = expected.findings.some((finding) => finding.ruleId === intent.rule);
    if (intent.kind === 'positive' && !fires) problems.push(`${id} : la règle ${intent.rule} ne se déclenche pas`);
    if (intent.kind === 'negative' && expected.findings.length > 0) problems.push(`${id} : un constat reste (${expected.findings.map((finding) => finding.ruleId).join(', ')})`);
    if (intent.kind === 'negative' && !upstream.some((finding) => finding.ruleId === intent.rule)) problems.push(`${id} : le moteur d’origine ne signale pas ce texte par ${intent.rule}`);
    counts[intent.kind] += 1;
  }
  if (counts.positive < 25) problems.push('code ordinaire : moins de 25 cas positifs');
  if (counts.negative < 25) problems.push('code ordinaire : moins de 25 cas négatifs');
  return problems;
}
