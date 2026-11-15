// SPDX-License-Identifier: Apache-2.0
/**
 * Règles de données personnelles du Pack initial (v0.7.0) : IBAN, numéro de sécurité sociale français (NIR), SIRET,
 * SIREN, numéro de carte bancaire. Extension propre à ce dépôt, sans origine dans Secret Guard : ces règles viennent
 * après les 35 règles du catalogue d'origine (`catalog.ts`), leur motif est écrit ici directement en RE2 (aucune
 * traduction JavaScript), et leur contrôle est un validateur nommé que le moteur Go porte dans `detect/personaldata.go`.
 *
 * Ce fichier tient aussi une seconde écriture, indépendante de celle du moteur, des contrôles (BigInt, tables
 * différentes) et des constructeurs de numéros valides : elles servent d'oracle au corpus (`corpus/personal-data.ts`),
 * dont le résultat attendu ne vient donc pas du moteur Go qu'il éprouve, et à des tests croisés. Aucun numéro réel :
 * tout numéro est calculé.
 */
import type { RulePackRule } from '../src/rule-pack.ts';

/**
 * Longueur de l'IBAN par pays : les 76 pays que reconnaît Presidio (`iban_patterns.py`, MIT), longueurs du registre
 * de l'ISO 13616 tenu par SWIFT (52 pays jusqu'à la v0.9.0, 24 ajoutés en v0.10.0 ; UPSTREAM.md). Copie dans
 * `detect/personaldata.go` (`ibanLengths`), comparée par `test/personal-data.test.ts`.
 */
export const IBAN_LENGTHS: Readonly<Record<string, number>> = {
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22, BR: 29, BY: 28, CH: 21, CR: 22,
  CY: 28, CZ: 24, DE: 22, DK: 18, DO: 28, EE: 20, EG: 29, ES: 24, FI: 18, FO: 18, FR: 27, GB: 22, GE: 22,
  GI: 23, GL: 18, GR: 27, GT: 28, HR: 21, HU: 28, IE: 22, IL: 23, IQ: 23, IS: 26, IT: 27, JO: 30, KW: 30,
  KZ: 20, LB: 28, LC: 32, LI: 21, LT: 20, LU: 20, LV: 21, LY: 25, MC: 27, MD: 24, ME: 22, MK: 19, MR: 27,
  MT: 31, MU: 30, NL: 18, NO: 15, PK: 24, PL: 28, PS: 29, PT: 25, QA: 29, RO: 24, RS: 22, SA: 24, SC: 31,
  SE: 24, SI: 19, SK: 24, SM: 27, TL: 23, TN: 24, TR: 26, UA: 29, VA: 22, VG: 24, XK: 20,
};

/**
 * Motif de l'IBAN : deux lettres, deux chiffres, puis 2 à 7 groupes de quatre caractères (espace facultative devant
 * chacun) et un reste de 1 à 3 caractères. Il est volontairement générique (et rapide) : il peut absorber un mot de
 * quatre caractères qui suit l'IBAN (« … 1332 pour »). Le moteur Go retient donc, parmi les fins de groupe de la
 * correspondance, la plus longue dont le contrôle réussit (`ibanPrefixLength` de `detect/personaldata.go`) ; la longueur
 * du pays, quand elle est connue, y est contrôlée.
 */
export const IBAN_PATTERN = String.raw`\b[A-Za-z]{2}[0-9]{2}(?: ?[A-Za-z0-9]{4}){2,7}(?: ?[A-Za-z0-9]{1,3})?\b`;

/** NIR : sexe (1 à 4, 7, 8), année, mois (01 à 12, 20 à 99), département ou 2A/2B, commune, ordre, clé ; espaces facultatifs. */
const NIR_PATTERN = String.raw`\b[1-478] ?[0-9]{2} ?(?:0[1-9]|1[0-2]|[2-9][0-9]) ?(?:[0-9]{2}|2[ABab]) ?[0-9]{3} ?[0-9]{3} ?[0-9]{2}\b`;

/** SIRET : 14 chiffres, groupés ou non (3-3-3-5, 9-5…). */
const SIRET_PATTERN = String.raw`\b[0-9]{3} ?[0-9]{3} ?[0-9]{3} ?[0-9]{5}\b`;

/**
 * SIREN : seulement après le mot « SIREN » (guillemet, deux séparateurs et guillemet facultatifs, « n° » ou « no » admis) ; la valeur détectée
 * est le premier groupe capturant, les 9 chiffres. Le mot n'est pas dans l'étendue du constat.
 */
const SIREN_PATTERN = String.raw`\b[Ss][Ii][Rr][Ee][Nn]["']?[ \t]*(?:[:=#]|[nN][°o]\.?)?[ \t]*[:=]?[ \t]*["']?([0-9]{3} ?[0-9]{3} ?[0-9]{3})\b`;

/**
 * Carte bancaire : 13 à 19 chiffres d'un bloc, ou 4-4-4-4 (espace ou tiret), ou 4-6-4/5 (Amex, Diners). Les numéros de
 * 19 chiffres ne se lisent groupés : un groupe de plus absorberait le cryptogramme ou la date qui suit.
 */
const CARD_PATTERN = String.raw`\b(?:[0-9]{13,19}|[0-9]{4}(?:[ -][0-9]{4}){3}|[0-9]{4}[ -][0-9]{6}[ -][0-9]{4,5})\b`;

/**
 * Règles de données personnelles, dans l'ordre du Pack (après les 35 règles du catalogue). Scores (niveau, sans
 * pénalité d'encodage) : carte bancaire 70 (HIGH), NIR 60 (HIGH), IBAN 45 (MEDIUM), SIRET et SIREN 35 (MEDIUM, données
 * d'entreprise publiques). Bornes de longueur en unités UTF-16, séparateurs compris.
 */
export const PERSONAL_DATA_RULES: readonly RulePackRule[] = [
  {
    ruleId: 'iban',
    family: 'fixed_pattern',
    secretType: 'iban',
    score: 45,
    validator: 'iban_mod97',
    pattern: IBAN_PATTERN,
    minLength: 15,
    maxLength: 42,
  },
  {
    ruleId: 'fr_nir',
    family: 'fixed_pattern',
    secretType: 'fr_social_security_number',
    score: 60,
    validator: 'fr_nir_key',
    pattern: NIR_PATTERN,
    minLength: 15,
    maxLength: 21,
  },
  {
    ruleId: 'fr_siret',
    family: 'fixed_pattern',
    secretType: 'fr_siret',
    score: 35,
    validator: 'fr_siret_luhn',
    pattern: SIRET_PATTERN,
    minLength: 14,
    maxLength: 17,
  },
  {
    ruleId: 'fr_siren',
    family: 'fixed_pattern',
    secretType: 'fr_siren',
    score: 35,
    validator: 'fr_siren_luhn',
    pattern: SIREN_PATTERN,
    minLength: 9,
    maxLength: 11,
  },
  {
    ruleId: 'payment_card',
    family: 'fixed_pattern',
    secretType: 'payment_card_number',
    score: 70,
    validator: 'payment_card_luhn',
    pattern: CARD_PATTERN,
    minLength: 13,
    maxLength: 19,
  },
];

// ---------------------------------------------------------------------------------------------------------------
// Seconde écriture des contrôles (oracle du corpus, indépendante de detect/personaldata.go).
// ---------------------------------------------------------------------------------------------------------------

/** Contrôle de Luhn d'une suite de chiffres. */
export function luhnValid(digits: string): boolean {
  if (!/^[0-9]+$/.test(digits)) return false;
  let sum = 0;
  [...digits].reverse().forEach((character, index) => {
    const value = Number(character);
    const doubled = index % 2 === 1 ? value * 2 : value;
    sum += doubled > 9 ? doubled - 9 : doubled;
  });
  return sum % 10 === 0;
}

/** Chiffre de contrôle de Luhn à ajouter à `prefix`. */
export function luhnCheckDigit(prefix: string): string {
  for (let candidate = 0; candidate < 10; candidate += 1) {
    if (luhnValid(`${prefix}${String(candidate)}`)) return String(candidate);
  }
  throw new Error('chiffre de Luhn introuvable');
}

/** IBAN valide : contrôle modulo 97 (ISO 13616), longueur du pays, chiffres de contrôle 02 à 98. */
export function ibanValid(raw: string): boolean {
  const compact = raw.replaceAll(' ', '').toUpperCase();
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/.test(compact)) return false;
  const check = Number(compact.slice(2, 4));
  if (check < 2 || check > 98) return false;
  const expected = IBAN_LENGTHS[compact.slice(0, 2)];
  if (expected !== undefined && expected !== compact.length) return false;
  const numeric = [...(compact.slice(4) + compact.slice(0, 4))]
    .map((character) => (/[0-9]/.test(character) ? character : String(character.charCodeAt(0) - 55)))
    .join('');
  return BigInt(numeric) % 97n === 1n;
}

/**
 * Longueur retenue d'une correspondance du motif IBAN : la plus longue fin de groupe (fin d'un mot, ou multiple de quatre
 * caractères alphanumériques) dont le préfixe est un IBAN valide ; 0 s'il n'y en a aucune.
 */
export function ibanPrefixLength(value: string): number {
  const ends: number[] = [];
  let alphanumeric = 0;
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === ' ') continue;
    alphanumeric += 1;
    const next = value[index + 1];
    if (next === undefined || next === ' ' || alphanumeric % 4 === 0) ends.push(index + 1);
  }
  return [...ends].reverse().find((end) => ibanValid(value.slice(0, end))) ?? 0;
}

/** IBAN compact calculé : les deux chiffres de contrôle sont ceux qui rendent le reste égal à 1. */
export function makeIban(country: string, bban: string): string {
  const numeric = [...`${bban}${country}00`]
    .map((character) => (/[0-9]/.test(character) ? character : String(character.charCodeAt(0) - 55)))
    .join('');
  const check = 98n - (BigInt(numeric) % 97n);
  return `${country}${check.toString().padStart(2, '0')}${bban}`;
}

/** Groupes de quatre séparés par une espace (écriture imprimée d'un IBAN). */
export function groupBy4(compact: string): string {
  return compact.match(/.{1,4}/g)?.join(' ') ?? compact;
}

/** NIR valide : clé = 97 − (nombre à 13 chiffres mod 97), 2A → 19 et 2B → 18, éléments jamais nuls. */
export function nirValid(raw: string): boolean {
  const compact = raw.replaceAll(' ', '');
  if (!/^[0-9]{5}(?:[0-9]{2}|2[ABab])[0-9]{8}$/.test(compact)) return false;
  const department = compact.slice(5, 7).toUpperCase();
  if (department === '00' || compact.slice(7, 10) === '000' || compact.slice(10, 13) === '000') return false;
  const corsica: Readonly<Record<string, string>> = { '2A': '19', '2B': '18' };
  const body = compact.slice(0, 5) + (corsica[department] ?? department) + compact.slice(7, 13);
  return 97n - (BigInt(body) % 97n) === BigInt(compact.slice(13));
}

/** NIR calculé : `body` = 13 caractères (sexe, année, mois, département ou 2A/2B, commune, ordre). */
export function makeNir(body: string): string {
  const department = body.slice(5, 7).toUpperCase();
  const corsica: Readonly<Record<string, string>> = { '2A': '19', '2B': '18' };
  const number = body.slice(0, 5) + (corsica[department] ?? department) + body.slice(7);
  return `${body}${(97n - (BigInt(number) % 97n)).toString().padStart(2, '0')}`;
}

/** Quatorze chiffres qui se lisent AAAAMMJJHHMMSS (années 1900 à 2099). */
export function timestampLike(digits: string): boolean {
  const match = /^(19|20)[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])([01][0-9]|2[0-3])[0-5][0-9][0-5][0-9]$/.exec(digits);
  return match !== null;
}

/** SIRET valide : Luhn, ou somme des chiffres multiple de 5 pour La Poste (SIREN 356000000) ; ni date-heure, ni chiffre répété. */
export function siretValid(raw: string): boolean {
  const digits = raw.replaceAll(' ', '');
  if (!/^[0-9]{14}$/.test(digits) || /^(.)\1+$/.test(digits) || timestampLike(digits)) return false;
  if (digits.startsWith('356000000')) return [...digits].reduce((sum, digit) => sum + Number(digit), 0) % 5 === 0;
  return luhnValid(digits);
}

/** SIREN valide : 9 chiffres, Luhn, pas de chiffre répété. */
export function sirenValid(raw: string): boolean {
  const digits = raw.replaceAll(' ', '');
  return /^[0-9]{9}$/.test(digits) && !/^(.)\1+$/.test(digits) && luhnValid(digits);
}

/** Réseaux de cartes : préfixe `[from, to]` sur `digits` chiffres, longueurs admises. */
const range = (from: number, to: number): number[] => Array.from({ length: to - from + 1 }, (_, index) => from + index);
const CARD_NETWORKS: readonly { readonly digits: number; readonly from: number; readonly to: number; readonly lengths: readonly number[] }[] = [
  { digits: 1, from: 4, to: 4, lengths: [16, 19] }, // Visa
  { digits: 2, from: 51, to: 55, lengths: [16] }, // Mastercard
  { digits: 4, from: 2221, to: 2720, lengths: [16] }, // Mastercard, série 2
  { digits: 2, from: 34, to: 34, lengths: [15] }, // American Express
  { digits: 2, from: 37, to: 37, lengths: [15] },
  { digits: 4, from: 6011, to: 6011, lengths: range(16, 19) }, // Discover
  { digits: 3, from: 644, to: 649, lengths: range(16, 19) },
  { digits: 2, from: 65, to: 65, lengths: range(16, 19) },
  { digits: 3, from: 300, to: 305, lengths: range(14, 19) }, // Diners Club
  { digits: 4, from: 3095, to: 3095, lengths: range(14, 19) },
  { digits: 2, from: 36, to: 36, lengths: range(14, 19) },
  { digits: 2, from: 38, to: 39, lengths: range(14, 19) },
  { digits: 4, from: 3528, to: 3589, lengths: range(16, 19) }, // JCB
  { digits: 2, from: 62, to: 62, lengths: range(16, 19) }, // UnionPay
  ...[5018, 5020, 5038, 5893, 6304, 6759, 6761, 6762, 6763].map((prefix) => ({ digits: 4, from: prefix, to: prefix, lengths: range(13, 19) })), // Maestro
];

/** Carte bancaire valide : séparateur unique, 13 à 19 chiffres, Luhn, préfixe et longueur d'un réseau, pas de chiffre répété. */
export function cardValid(raw: string): boolean {
  const separators = new Set(raw.replaceAll(/[0-9]/g, ''));
  if (separators.size > 1 || [...separators].some((separator) => separator !== ' ' && separator !== '-')) return false;
  const digits = raw.replaceAll(/[ -]/g, '');
  if (!/^[0-9]{13,19}$/.test(digits) || /^(.)\1+$/.test(digits) || !luhnValid(digits)) return false;
  return CARD_NETWORKS.some(
    (network) => {
      const prefix = Number(digits.slice(0, network.digits));
      return prefix >= network.from && prefix <= network.to && network.lengths.includes(digits.length);
    },
  );
}

// ---------------------------------------------------------------------------------------------------------------
// Identifiants européens et français (v0.10.0) : seconde écriture des contrôles, indépendante de
// detect/personaldata.go. Les règles sont dans `context-data.ts` (mot-clé de contexte obligatoire) ; les contrôles
// européens suivent ceux de Presidio (MIT, avis dans NOTICE, détail dans UPSTREAM.md), les contrôles français les
// formules publiées (UPSTREAM.md).
// ---------------------------------------------------------------------------------------------------------------

/** Lettres en majuscules et chiffres d'une valeur, espaces et tirets retirés. */
const squeeze = (raw: string): string => raw.replaceAll(/[ -]/g, '').toUpperCase();

/** Vrai si la suite n'est faite que d'un même caractère. */
const repeated = (digits: string): boolean => /^(.)\1+$/.test(digits);

/** Lettre de contrôle du NIF et du NIE espagnols : rang = nombre modulo 23. */
const ES_CONTROL = ['TRWAGM', 'YFPDXB', 'NJZSQV', 'HLCKE'].join('');

/** NIF (DNI) espagnol : 7 ou 8 chiffres et la lettre du nombre modulo 23. */
export function esNifValid(raw: string): boolean {
  const [, digits = '', letter = ''] = /^([0-9]{7,8})([A-Z])$/.exec(squeeze(raw)) ?? [];
  return digits !== '' && !repeated(digits) && ES_CONTROL.charAt(Number(BigInt(digits) % 23n)) === letter;
}

/** NIE espagnol : X, Y ou Z (lus 0, 1, 2), 7 chiffres et la lettre du nombre modulo 23. */
export function esNieValid(raw: string): boolean {
  const [, head = '', digits = '', letter = ''] = /^([XYZ])([0-9]{7})([A-Z])$/.exec(squeeze(raw)) ?? [];
  return head !== '' && ES_CONTROL.charAt(Number(BigInt(`${String('XYZ'.indexOf(head))}${digits}`) % 23n)) === letter;
}

/** Valeur d'un caractère de rang impair du code fiscal italien, par rang (chiffre 0 à 9, ou lettre A à Z). */
const IT_ODD: readonly number[] = [1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23];

/** Code fiscal italien : 16 caractères, le dernier est la lettre de la somme (rangs impairs par table, pairs par rang) modulo 26. */
export function itFiscalCodeValid(raw: string): boolean {
  const code = raw.toUpperCase();
  if (!/^[A-Z0-9]{15}[A-Z]$/.test(code)) return false;
  const rank = (character: string): number => (/[0-9]/.test(character) ? Number(character) : character.charCodeAt(0) - 65);
  const sum = [...code.slice(0, 15)].reduce((total, character, index) => total + (index % 2 === 0 ? (IT_ODD[rank(character)] ?? 0) : rank(character)), 0);
  return String.fromCharCode(65 + (sum % 26)) === code.charAt(15);
}

/** Numéro de TVA italien (partita IVA) : 11 chiffres, Luhn. */
export function itVatValid(raw: string): boolean {
  return /^[0-9]{11}$/.test(raw) && !repeated(raw) && luhnValid(raw);
}

/** Chiffre de contrôle ISO 7064 MOD 11,10 d'une suite de chiffres. */
export function iso7064CheckDigit(body: string): string {
  let product = 10;
  for (const digit of body) {
    const sum = (Number(digit) + product) % 10 || 10;
    product = (sum * 2) % 11;
  }
  return String((11 - product) % 10);
}

/** Identifiant fiscal allemand (Steuer-ID) : 11 chiffres sans zéro initial, aucun chiffre plus de trois fois parmi les dix premiers, ISO 7064. */
export function deTaxIdValid(raw: string): boolean {
  const digits = raw.replaceAll(' ', '');
  if (!/^[1-9][0-9]{10}$/.test(digits)) return false;
  const body = digits.slice(0, 10);
  if ([...'0123456789'].some((digit) => body.split(digit).length - 1 > 3)) return false;
  return iso7064CheckDigit(body) === digits.charAt(10);
}

/** Numéro de TVA allemand (USt-IdNr.) : « DE » et 9 chiffres, le dernier est le contrôle ISO 7064 des huit premiers. */
export function deVatValid(raw: string): boolean {
  const [, digits = ''] = /^DE([0-9]{9})$/.exec(raw.replaceAll(' ', '').toUpperCase()) ?? [];
  return digits !== '' && !repeated(digits) && iso7064CheckDigit(digits.slice(0, 8)) === digits.charAt(8);
}

/** PESEL polonais : 11 chiffres, mois (01 à 12, plus 20 par siècle) et jour possibles, somme pondérée 1-3-7-9. */
export function plPeselValid(raw: string): boolean {
  if (!/^[0-9]{11}$/.test(raw) || repeated(raw)) return false;
  const month = Number(raw.slice(2, 4)) % 20;
  const day = Number(raw.slice(4, 6));
  if (month < 1 || month > 12 || day < 1 || day > 31) return false;
  const sum = [...raw.slice(0, 10)].reduce((total, digit, index) => total + Number(digit) * Number('1379137913'.charAt(index)), 0);
  return String((10 - (sum % 10)) % 10) === raw.charAt(10);
}

/** Numéro NHS britannique : 10 chiffres, somme pondérée de 10 à 1 multiple de 11. */
export function ukNhsValid(raw: string): boolean {
  const digits = raw.replaceAll(/[ -]/g, '');
  if (!/^[0-9]{10}$/.test(digits) || repeated(digits)) return false;
  return [...digits].reduce((total, digit, index) => total + Number(digit) * (10 - index), 0) % 11 === 0;
}

/** Personnummer (ou samordningsnummer) suédois : 10 ou 12 chiffres, mois et jour possibles (jour plus 60 admis), Luhn des dix derniers. */
export function sePersonnummerValid(raw: string): boolean {
  const digits = raw.replaceAll(/[-+]/g, '');
  if (!/^(?:[0-9]{2})?[0-9]{10}$/.test(digits)) return false;
  const last = digits.slice(-10);
  const month = Number(last.slice(2, 4));
  const day = Number(last.slice(4, 6)) > 60 ? Number(last.slice(4, 6)) - 60 : Number(last.slice(4, 6));
  return month >= 1 && month <= 12 && day >= 1 && day <= 31 && luhnValid(last);
}

/** Caractères de contrôle de l'identifiant personnel finlandais : rang = nombre modulo 31. */
const FI_CONTROL = ['0123456789', 'ABCDEF', 'HJKLMN', 'PRSTUVWXY'].join('');

/** Identifiant personnel finlandais (henkilötunnus) : date réelle selon le siècle du séparateur, puis caractère du nombre modulo 31. */
export function fiHetuValid(raw: string): boolean {
  const [, day = '', month = '', year = '', separator = '', individual = '', control = ''] =
    /^([0-9]{2})([0-9]{2})([0-9]{2})([-+A-FU-Y])([0-9]{3})([0-9A-Y])$/.exec(raw.toUpperCase()) ?? [];
  if (day === '') return false;
  const century = separator === '+' ? 1800 : /[A-F]/.test(separator) ? 2000 : 1900;
  const date = new Date(Date.UTC(century + Number(year), Number(month) - 1, Number(day)));
  if (date.getUTCMonth() !== Number(month) - 1 || date.getUTCDate() !== Number(day)) return false;
  return FI_CONTROL.charAt(Number(`${day}${month}${year}${individual}`) % 31) === control;
}

/** Numéro de TVA intracommunautaire français : « FR », clé de deux chiffres égale à (12 + 3 × (SIREN mod 97)) mod 97, SIREN valide. */
export function frVatValid(raw: string): boolean {
  const [, key = '', siren = ''] = /^FR([0-9]{2})([0-9]{9})$/.exec(raw.replaceAll(' ', '')) ?? [];
  return siren !== '' && sirenValid(siren) && (12n + 3n * (BigInt(siren) % 97n)) % 97n === BigInt(key);
}

/** Chiffre d'une lettre d'un numéro de compte (RIB), par rang de A à Z. */
const RIB_LETTER_DIGITS = '12345678912345678923456789';

/** RIB : banque (5 chiffres), guichet (5), compte (11 lettres ou chiffres), clé = 97 − (les 21 chiffres suivis de « 00 », modulo 97). */
export function frRibValid(raw: string): boolean {
  const [, bank = '', branch = '', account = '', key = ''] = /^([0-9]{5})([0-9]{5})([0-9A-Z]{11})([0-9]{2})$/.exec(squeeze(raw)) ?? [];
  if (bank === '') return false;
  const digits = `${bank}${branch}${account.replaceAll(/[A-Z]/g, (letter) => RIB_LETTER_DIGITS.charAt(letter.charCodeAt(0) - 65))}`;
  return !repeated(digits) && 97n - ((BigInt(digits) * 100n) % 97n) === BigInt(key);
}

/**
 * Complète `prefix` par le premier de `candidates` qui rend la valeur valide (`suffix` ajouté après) : la clé de
 * contrôle d'une valeur d'essai est retrouvée par essais, avec le contrôle de référence. Erreur s'il n'y en a aucun.
 */
export function withCheck(prefix: string, candidates: readonly string[], valid: (value: string) => boolean, suffix = ''): string {
  const found = candidates.find((candidate) => valid(`${prefix}${candidate}${suffix}`));
  if (found === undefined) throw new Error('clé de contrôle introuvable');
  return `${prefix}${found}${suffix}`;
}

/** Candidats de `withCheck` : un chiffre, une lettre, un chiffre ou une lettre, une clé de deux chiffres. */
export const CHECK_DIGITS: readonly string[] = [...'0123456789'];
export const CHECK_LETTERS: readonly string[] = [...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'];
export const CHECK_ALNUM: readonly string[] = [...CHECK_DIGITS, ...CHECK_LETTERS];
export const CHECK_PAIRS: readonly string[] = Array.from({ length: 98 }, (_, index) => String(index).padStart(2, '0'));

/** Validateur de référence par nom. */
export const REFERENCE_VALIDATORS: Readonly<Record<string, (value: string) => boolean>> = {
  iban_mod97: ibanValid,
  fr_nir_key: nirValid,
  fr_siret_luhn: siretValid,
  fr_siren_luhn: sirenValid,
  payment_card_luhn: cardValid,
  es_nif_mod23: esNifValid,
  es_nie_mod23: esNieValid,
  it_fiscal_code_check: itFiscalCodeValid,
  it_vat_luhn: itVatValid,
  de_tax_id_iso7064: deTaxIdValid,
  de_vat_iso7064: deVatValid,
  pl_pesel_check: plPeselValid,
  uk_nhs_mod11: ukNhsValid,
  se_personnummer_luhn: sePersonnummerValid,
  fi_hetu_mod31: fiHetuValid,
  fr_vat_key: frVatValid,
  fr_rib_key: frRibValid,
};

/** Constat de référence : règle, étendue en unités UTF-16 du texte. */
export interface ReferenceFinding {
  readonly rule: RulePackRule;
  readonly start: number;
  readonly end: number;
}

/**
 * Lecture de référence d'un texte (vue d'identité seulement) : chaque correspondance du motif (`matchAll`, comme le
 * moteur), valeur = premier groupe capturant s'il a participé, sinon la correspondance entière ; bornes de longueur
 * puis validateur. Même sémantique « première alternative » que RE2 pour ces motifs.
 */
export function referenceFindings(text: string): ReferenceFinding[] {
  const found: ReferenceFinding[] = [];
  for (const rule of PERSONAL_DATA_RULES) {
    const check = REFERENCE_VALIDATORS[rule.validator];
    if (check === undefined) throw new Error(`validateur de référence absent : ${rule.validator}`);
    for (const match of text.matchAll(new RegExp(rule.pattern, 'gd'))) {
      const group = match[1];
      const whole = match.indices?.[0];
      const captured = match.indices?.[1];
      if (whole === undefined) continue;
      let [start, end] = group !== undefined && captured !== undefined ? captured : whole;
      if (rule.validator === 'iban_mod97') {
        const kept = ibanPrefixLength(text.slice(start, end));
        if (kept === 0) continue;
        end = start + kept;
      }
      const value = text.slice(start, end);
      if (value.length < rule.minLength || value.length > rule.maxLength || !check(value)) continue;
      found.push({ rule, start, end });
    }
  }
  return found.sort((left, right) => left.start - right.start || left.rule.ruleId.localeCompare(right.rule.ruleId));
}
