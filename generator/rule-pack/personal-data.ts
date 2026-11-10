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
 * Longueur de l'IBAN par pays (registre ISO 13616, pays d'Europe et du pourtour). Copie dans `detect/personaldata.go`
 * (`ibanLengths`), comparée par `test/personal-data.test.ts`.
 */
export const IBAN_LENGTHS: Readonly<Record<string, number>> = {
  AD: 24, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BY: 28, CH: 21, CY: 28, CZ: 24,
  DE: 22, DK: 18, EE: 20, ES: 24, FI: 18, FO: 18, FR: 27, GB: 22, GE: 22, GI: 23, GL: 18,
  GR: 27, HR: 21, HU: 28, IE: 22, IL: 23, IS: 26, IT: 27, LI: 21, LT: 20, LU: 20, LV: 21,
  MC: 27, MD: 24, ME: 22, MK: 19, MT: 31, NL: 18, NO: 15, PL: 28, PT: 25, RO: 24, RS: 22,
  SE: 24, SI: 19, SK: 24, SM: 27, TR: 26, UA: 29, VA: 22, XK: 20,
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

/** Validateur de référence par nom. */
export const REFERENCE_VALIDATORS: Readonly<Record<string, (value: string) => boolean>> = {
  iban_mod97: ibanValid,
  fr_nir_key: nirValid,
  fr_siret_luhn: siretValid,
  fr_siren_luhn: sirenValid,
  payment_card_luhn: cardValid,
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
