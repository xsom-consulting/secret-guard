// SPDX-License-Identifier: Apache-2.0
/**
 * Mot de passe annoncé dans une phrase (v0.8.1) : seconde écriture, indépendante du moteur Go
 * (`detect/passwordphrase.go`), de la lecture « indice, liaison facultative, un mot qui a la forme d'un mot de passe ».
 * Extension propre à ce dépôt, sans origine dans Secret Guard : aucune règle nouvelle, le constat est celui de la règle
 * `contextual_password` du Pack initial. Cette écriture sert d'oracle au corpus (`corpus/password-phrase.ts`) : le
 * résultat attendu ne vient donc ni du moteur d'origine (qui ne lit pas ces annonces) ni du moteur Go qu'il éprouve.
 *
 * Elle ne reprend que la forme de l'annonce et de la valeur (indices, liaisons, guillemets, ponctuation finale,
 * longueur, trois classes de caractères, « ${ », « $( », « {{ », « %…% », « :// », référence pointée ou appel) ; les
 * filtres de l'origine que le moteur Go réemploie (valeurs fictives, Substituts) sont éprouvés par les tests Go, et
 * les cas du corpus n'en dépendent pas.
 */

/** Règle dont le moteur porte la logique et qui signe ces constats (score du Pack initial). */
export const PASSWORD_PHRASE_RULE = { ruleId: 'contextual_password', secretType: 'password', score: 70 } as const;

/** Indices, sans la casse ; aucune lettre, chiffre, « _ - . / \ $ @ » juste avant. */
const HINT = /(?<![\p{L}\p{N}_\-./\\$@])(mot[ \t-]+de[ \t-]+passe|code[ \t]+d['’]acc[eè]s|mdp|passphrase|password|passwd|pwd|pass)/giu;

/** Indices que l'affectation ordinaire de l'origine connaît comme noms de variables. */
const ENGLISH = new Set(['password', 'passwd', 'pwd', 'passphrase']);

/** Espace d'une même ligne : `\s` de JavaScript sans fin de ligne. */
const SPACE = /[^\S\n\r\u2028\u2029]/u;
const SPACES = /^[^\S\n\r\u2028\u2029]*/u;

const LINK = /^(?:est|is|c['’]est)(?=[^\S\n\r\u2028\u2029])/iu;

const QUOTES: Readonly<Record<string, string>> = { '"': '"', "'": "'", '`': '`', '«': '»', '“': '”', '‘': '’' };

/** Référence pointée ou appel (« process.env.X », « getPassword(…) »), forme simple. */
const REFERENCE = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\([^"'`]*\))+$/u;

/** Forme d'un mot de passe annoncé. */
export function passwordPhraseShape(value: string): boolean {
  const points = [...value];
  if (points.length < 8 || points.length > 256) return false;
  if (/[\s\p{Cc}]/u.test(value)) return false;
  const classes = new Set<string>();
  for (const point of points) {
    if (/\p{Ll}/u.test(point)) classes.add('lower');
    else if (/[\p{Lu}\p{Lt}]/u.test(point)) classes.add('upper');
    else if (/[0-9]/u.test(point)) classes.add('digit');
    else classes.add('other');
  }
  if (classes.size < 3) return false;
  if (/^(?:\$\{|\$\(|\{\{)/u.test(value) || value.includes('://') || /^%.+%$/su.test(value)) return false;
  return !REFERENCE.test(value);
}

/** Constat de référence : étendue de la valeur, en unités UTF-16 du texte. */
export interface PasswordPhraseFinding {
  readonly start: number;
  readonly end: number;
}

/** Valeur annoncée après un indice qui finit en `from`, ou rien. */
function valueAfter(text: string, hint: string, from: number): PasswordPhraseFinding | undefined {
  const lowered = hint.toLowerCase();
  const english = ENGLISH.has(lowered);
  const next = text[from];
  if (next === undefined) return undefined;
  if (!SPACE.test(next) && (english || (next !== ':' && next !== '='))) return undefined;
  let at = from + (SPACES.exec(text.slice(from))?.[0].length ?? 0);
  let linked = false;
  const link = LINK.exec(text.slice(at));
  if (link !== null) {
    at += link[0].length;
    at += SPACES.exec(text.slice(at))?.[0].length ?? 0;
    linked = true;
  }
  if (text[at] === ':' || text[at] === '=') {
    if (english) return undefined;
    at += 1;
    at += SPACES.exec(text.slice(at))?.[0].length ?? 0;
    linked = true;
  }
  if (lowered === 'pass' && !linked) return undefined;
  let start = at;
  const opening = text[at];
  const closing = opening === undefined ? undefined : QUOTES[opening];
  if (closing !== undefined) {
    start += 1;
    if (opening === '«') start += SPACES.exec(text.slice(start))?.[0].length ?? 0;
  }
  const word = /^\S*/u.exec(text.slice(start))?.[0] ?? '';
  let value = word;
  while (value.length > 0) {
    const last = value.at(-1) ?? '';
    if ('.,;:?'.includes(last) || (last === ')' && !value.includes('('))) value = value.slice(0, -1);
    else break;
  }
  if (closing !== undefined && value.endsWith(closing)) value = value.slice(0, -closing.length);
  if (!passwordPhraseShape(value)) return undefined;
  return { start, end: start + value.length };
}

/** Lecture de référence d'un texte (vue d'identité seulement). */
export function passwordPhraseFindings(text: string): PasswordPhraseFinding[] {
  const found: PasswordPhraseFinding[] = [];
  for (const match of text.matchAll(HINT)) {
    const hint = match[1] ?? '';
    const finding = valueAfter(text, hint, match.index + match[0].length);
    if (finding !== undefined) found.push(finding);
  }
  return found;
}
