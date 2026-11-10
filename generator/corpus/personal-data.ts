// SPDX-License-Identifier: Apache-2.0
/**
 * Cas du corpus de parité pour les règles de données personnelles (v0.7.0) : `vectors/detection/rules-personal-data.json`.
 *
 * Ces règles n'existent pas dans le moteur TypeScript d'origine : le résultat attendu d'un cas ne vient donc pas de
 * lui. Il vient de la seconde écriture indépendante des contrôles (`rule-pack/personal-data.ts` : BigInt, tables
 * différentes, aucun code partagé avec `detect/personaldata.go`) appliquée aux positions du motif ; et le générateur
 * exige en plus que le moteur d'origine ne trouve rien dans le même texte (aucun constat à fusionner : la déduplication
 * des chevauchements n'est pas rejouée ici). Les chevauchements entre règles sont éprouvés par des tests Go.
 *
 * Aucun numéro réel : chaque numéro est calculé (clé de contrôle recalculée) sur des chiffres tirés de SHA-256 ; seul
 * l'IBAN d'exemple public de la documentation bancaire française est écrit tel quel.
 */
import { byteOffsetOf, decodeInput, utf8Bytes } from './bytes.ts';
import { CorpusError, expectedFor, type CaseSource } from './corpus.ts';
import { compareFindings, levelForScore, type CorpusExpected, type CorpusFinding } from './model.ts';
import { synth, type CaseIntent } from './synthetic.ts';
import {
  groupBy4,
  luhnCheckDigit,
  luhnValid,
  makeIban,
  makeNir,
  PERSONAL_DATA_RULES,
  referenceFindings,
  timestampLike,
} from '../rule-pack/personal-data.ts';
import type { UpstreamEngine } from './upstream.ts';

/** Fichier du corpus qui porte ces cas (famille `rules`, couverte par l'exception de `.gitleaks.toml`). */
export const PERSONAL_DATA_FILE = 'rules-personal-data.json';

/** IBAN d'exemple public de la documentation bancaire française (RIB d'exemple). */
const PUBLIC_EXAMPLE_IBAN = 'FR76 3000 6000 0112 3456 7890 189';

const DIGITS = '0123456789';
const ALNUM_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

const digits = (label: string, length: number): string => synth(`personal-data/${label}`, DIGITS, length);

/** Chiffres sans zéro initial (un numéro ne commence pas par 0 dans ces essais). */
const digitsNoZero = (label: string, length: number): string => `${String(1 + (Number(digits(`${label}/first`, 1)) % 9))}${digits(label, length - 1)}`;

/** Nombre de `length` chiffres dont le dernier est la clé de Luhn. */
function luhnNumber(prefix: string, length: number, label: string): string {
  const body = `${prefix}${digits(label, length - 1 - prefix.length)}`;
  return `${body}${luhnCheckDigit(body)}`;
}

/** Même nombre avec le dernier chiffre changé (jamais valide pour Luhn, modulo 97 ou la clé du NIR). */
function breakLastDigit(value: string): string {
  const last = value.at(-1) ?? '0';
  return `${value.slice(0, -1)}${String((Number(last) + 1) % 10)}`;
}

/** Commune et numéro d'ordre non nuls. */
function communeAndOrder(label: string): string {
  return `${String(100 + (Number(digits(`${label}/c`, 3)) % 890))}${String(100 + (Number(digits(`${label}/o`, 3)) % 890))}`;
}

/** NIR en groupes officiels : sexe, année, mois, département, commune, ordre, clé. */
function nirGroups(nir: string): string {
  return `${nir.slice(0, 1)} ${nir.slice(1, 3)} ${nir.slice(3, 5)} ${nir.slice(5, 7)} ${nir.slice(7, 10)} ${nir.slice(10, 13)} ${nir.slice(13)}`;
}

/** SIRET calculé : SIREN de Luhn, quatre chiffres d'établissement, clé de Luhn du total. */
function siret(label: string): string {
  const siren8 = digitsNoZero(`${label}/siren`, 8);
  const siren = `${siren8}${luhnCheckDigit(siren8)}`;
  const body = `${siren}${digits(`${label}/nic`, 4)}`;
  return `${body}${luhnCheckDigit(body)}`;
}

function siren(label: string): string {
  const body = digitsNoZero(label, 8);
  return `${body}${luhnCheckDigit(body)}`;
}

function groupSiret(value: string): string {
  return `${value.slice(0, 3)} ${value.slice(3, 6)} ${value.slice(6, 9)} ${value.slice(9)}`;
}

function groupSiren(value: string): string {
  return `${value.slice(0, 3)} ${value.slice(3, 6)} ${value.slice(6)}`;
}

/** Quatorze chiffres qui se lisent AAAAMMJJHHMMSS et passent Luhn (le contrôle de forme est ce qui les écarte). */
function timestampThatPassesLuhn(): string {
  for (let second = 0; second < 60; second += 1) {
    const candidate = `2026111010${String(second).padStart(2, '0')}30`;
    if (timestampLike(candidate) && luhnValid(candidate)) return candidate;
  }
  throw new Error('horodatage qui passe Luhn introuvable');
}

/** Numéro de carte calculé : préfixe du réseau, longueur, clé de Luhn. */
const card = (prefix: string, length: number, label: string): string => luhnNumber(prefix, length, `card/${label}`);

const group4 = (value: string, separator: string): string => value.match(/.{1,4}/g)?.join(separator) ?? value;

function amexGroups(value: string): string {
  return `${value.slice(0, 4)} ${value.slice(4, 10)} ${value.slice(10)}`;
}

/** BBAN alphanumérique de `length` caractères (majuscules et chiffres) pour un pays sans modèle propre. */
const bban = (label: string, length: number): string => synth(`personal-data/bban/${label}`, ALNUM_UPPER, length);

interface Draft {
  readonly id: string;
  readonly text: string;
  readonly intent: CaseIntent;
}

function positive(rule: string, name: string, text: string): Draft {
  return { id: `${rule}/positive/${name}`, text, intent: { kind: 'positive', rule } };
}

function negative(rule: string, name: string, text: string): Draft {
  return { id: `${rule}/negative/${name}`, text, intent: { kind: 'negative', rule } };
}

function ibanDrafts(): Draft[] {
  const fr = makeIban('FR', digits('iban/fr', 23));
  const be = makeIban('BE', digits('iban/be', 12));
  const no = makeIban('NO', digits('iban/no', 11));
  const es = makeIban('ES', digits('iban/es', 20));
  const de = makeIban('DE', digits('iban/de', 18));
  const gb = makeIban('GB', `${'NWBK'}${digits('iban/gb', 14)}`);
  const nl = makeIban('NL', `ABNA${digits('iban/nl', 10)}`);
  const br = makeIban('BR', bban('br', 25));
  const frBadLength = makeIban('FR', digits('iban/fr-short', 22));
  const frBadCheck = groupBy4(breakLastDigit(fr));
  return [
    positive('iban', 'public-example', PUBLIC_EXAMPLE_IBAN),
    positive('iban', 'in-sentence', `Merci de virer les fonds sur l'IBAN ${groupBy4(fr)} avant vendredi.\n`),
    positive('iban', 'compact-be', `IBAN:${be}\n`),
    positive('iban', 'compact-no', `compte ${no} fin\n`),
    positive('iban', 'followed-by-four-letter-word', `Mon IBAN est ${groupBy4(es)} pour le loyer.\n`),
    positive('iban', 'followed-by-four-digit-group', `Virement ${groupBy4(es)} 2026 en cours.\n`),
    positive('iban', 'spaced-de', `${groupBy4(de)}\n`),
    positive('iban', 'lowercase-gb', `iban ${groupBy4(gb).toLowerCase()} ok\n`),
    positive('iban', 'nl-compact-in-quotes', `payer = "${nl}";\n`),
    positive('iban', 'country-not-in-table', `IBAN ${groupBy4(br)} (Brésil)\n`),
    positive('iban', 'json-field', `{"iban":"${groupBy4(fr)}","amount":12}\n`),
    positive('iban', 'two-in-one-line', `de ${groupBy4(fr)} vers ${groupBy4(de)}\n`),
    negative('iban', 'wrong-check-digits', `IBAN ${frBadCheck}\n`),
    negative('iban', 'wrong-length-for-country', `IBAN ${groupBy4(frBadLength)}\n`),
    negative('iban', 'product-reference', 'Réf. RT50 1234 5678 9012 3456\n'),
    negative('iban', 'too-short', 'FR76 3000 6000\n'),
    negative('iban', 'phone-and-order-numbers', 'tél 01 23 45 67 89, commande FR123456, dossier 2026-0042\n'),
    negative('iban', 'words-and-version', 'se12 jour peut etre bien, version v12 4567 abcd efgh ijkl mnop\n'),
    negative('iban', 'known-country-all-letters-after-head', 'DE89 ABCD EFGH IJKL MNOP QR\n'),
  ];
}

function nirDrafts(): Draft[] {
  const normal = makeNir(`1${digits('nir/normal/yy', 2)}12${digits('nir/normal/dept', 2).replace(/^00$/, '17')}${communeAndOrder('nir/normal')}`);
  const compact = makeNir(`2${digits('nir/compact/yy', 2)}07${'38'}${communeAndOrder('nir/compact')}`);
  const corsicaA = makeNir(`1${digits('nir/2a/yy', 2)}052A${communeAndOrder('nir/2a')}`);
  const corsicaB = makeNir(`2${digits('nir/2b/yy', 2)}112B${communeAndOrder('nir/2b')}`);
  const provisional = makeNir(`7${digits('nir/prov/yy', 2)}0275${communeAndOrder('nir/prov')}`);
  const abroad = makeNir(`1${digits('nir/abroad/yy', 2)}0299${communeAndOrder('nir/abroad')}`);
  const overseas = makeNir(`2${digits('nir/overseas/yy', 2)}0997${communeAndOrder('nir/overseas')}`);
  const wrongKey = breakLastDigit(normal);
  const month13 = makeNir(`1${digits('nir/m13/yy', 2)}1344${communeAndOrder('nir/m13')}`);
  const firstDigit5 = makeNir(`5${digits('nir/s5/yy', 2)}0344${communeAndOrder('nir/s5')}`);
  const zeroCommune = makeNir(`1${digits('nir/c0/yy', 2)}0344000${digits('nir/c0/o', 3).replace(/^000$/, '123')}`);
  const zeroOrder = makeNir(`2${digits('nir/o0/yy', 2)}0344${digits('nir/o0/c', 3).replace(/^000$/, '123')}000`);
  return [
    positive('fr_nir', 'official-groups', `${nirGroups(normal)}\n`),
    positive('fr_nir', 'compact', `NIR ${compact}\n`),
    positive('fr_nir', 'corsica-2a', `${nirGroups(corsicaA)}\n`),
    positive('fr_nir', 'corsica-2b-compact', `sécu: ${corsicaB}\n`),
    positive('fr_nir', 'provisional-number', `numéro provisoire ${nirGroups(provisional)}\n`),
    positive('fr_nir', 'born-abroad', `${nirGroups(abroad)}\n`),
    positive('fr_nir', 'overseas-department', `${overseas}\n`),
    positive('fr_nir', 'in-sentence', `Mon numéro de sécurité sociale est ${nirGroups(normal)}, merci de le noter.\n`),
    negative('fr_nir', 'wrong-key', `${nirGroups(wrongKey)}\n`),
    negative('fr_nir', 'fourteen-digits', `${normal.slice(0, 14)}\n`),
    negative('fr_nir', 'month-13', `${nirGroups(month13)}\n`),
    negative('fr_nir', 'first-digit-5', `${nirGroups(firstDigit5)}\n`),
    negative('fr_nir', 'zero-commune', `${zeroCommune}\n`),
    negative('fr_nir', 'zero-order-number', `${zeroOrder}\n`),
    negative('fr_nir', 'phone-numbers', 'tél 06 12 34 56 78 ou +33 6 12 34 56 78\n'),
    negative('fr_nir', 'longer-number', `réf ${normal}${digits('nir/long', 3)}\n`),
  ];
}

function siretDrafts(): Draft[] {
  const value = siret('siret/a');
  const other = siret('siret/b');
  const post = `356000000${digits('siret/post', 4)}`;
  // Établissement de La Poste : somme des chiffres multiple de 5.
  const postSiret = (() => {
    for (let last = 0; last < 10; last += 1) {
      const candidate = `${post}${String(last)}`;
      if ([...candidate].reduce((sum, digit) => sum + Number(digit), 0) % 5 === 0 && !luhnValid(candidate)) return candidate;
    }
    throw new Error('SIRET de La Poste introuvable');
  })();
  return [
    positive('fr_siret', 'spaced', `${groupSiret(value)}\n`),
    positive('fr_siret', 'compact-in-sentence', `SIRET : ${value}, établissement principal.\n`),
    positive('fr_siret', 'nine-and-five', `${value.slice(0, 9)} ${value.slice(9)}\n`),
    positive('fr_siret', 'la-poste-sum-rule', `${postSiret}\n`),
    positive('fr_siret', 'two-in-one-line', `${value} et ${groupSiret(other)}\n`),
    positive('fr_siret', 'csv-cell', `ACME;${value};Paris\n`),
    negative('fr_siret', 'wrong-luhn', `${breakLastDigit(value)}\n`),
    negative('fr_siret', 'thirteen-digits', `${value.slice(0, 13)}\n`),
    negative('fr_siret', 'timestamp-that-passes-luhn', `${timestampThatPassesLuhn()}\n`),
    negative('fr_siret', 'repeated-digit', '00000000000000\n'),
    negative('fr_siret', 'phone-number', 'tél 01 23 45 67 89\n'),
    negative('fr_siret', 'longer-number', `${value}${digits('siret/long', 2)}\n`),
  ];
}

function sirenDrafts(): Draft[] {
  const value = siren('siren/a');
  return [
    positive('fr_siren', 'colon-spaced', `SIREN : ${groupSiren(value)}\n`),
    positive('fr_siren', 'equals-lowercase', `siren=${value}\n`),
    positive('fr_siren', 'numero-sign', `SIREN n° ${value}\n`),
    positive('fr_siren', 'in-parentheses-sentence', `La société ACME (SIREN ${groupSiren(value)}) est immatriculée à Paris.\n`),
    positive('fr_siren', 'json-field', `{"siren": "${value}"}\n`),
    negative('fr_siren', 'no-context', `${value}\n`),
    negative('fr_siren', 'wrong-luhn', `SIREN : ${breakLastDigit(value)}\n`),
    negative('fr_siren', 'eight-digits', `SIREN : ${value.slice(0, 8)}\n`),
    negative('fr_siren', 'ten-digits', `SIREN : ${value}${digits('siren/long', 1)}\n`),
    negative('fr_siren', 'other-word', `SIRENE ${value}\n`),
    negative('fr_siren', 'repeated-digit', 'SIREN : 000000000\n'),
  ];
}

function cardDrafts(): Draft[] {
  const visa = card('4', 16, 'visa');
  const visaDashed = card('4', 16, 'visa-dashed');
  const master = card('52', 16, 'master');
  const masterSeries2 = card('2223', 16, 'master2');
  const amex = card('37', 15, 'amex');
  const diners = card('36', 14, 'diners');
  const visa19 = card('4', 19, 'visa19');
  const jcb = card('3530', 16, 'jcb');
  const discover = card('6011', 16, 'discover');
  const unionPay = card('62', 16, 'unionpay');
  const maestro = card('5018', 16, 'maestro');
  const unknownPrefix = card('9', 16, 'unknown');
  const visa13 = card('4', 13, 'visa13');
  const amexWrongLength = card('34', 16, 'amex16');
  const mixed = `${visa.slice(0, 4)} ${visa.slice(4, 8)}-${visa.slice(8, 12)} ${visa.slice(12)}`;
  return [
    positive('payment_card', 'visa-compact', `Carte : ${visa}\n`),
    positive('payment_card', 'visa-spaced-with-expiry', `${group4(visa, ' ')} exp 12/29 cvv 123\n`),
    positive('payment_card', 'visa-dashed', `${group4(visaDashed, '-')}\n`),
    positive('payment_card', 'mastercard-51-55', `${master}\n`),
    positive('payment_card', 'mastercard-series-2', `${group4(masterSeries2, ' ')}\n`),
    positive('payment_card', 'amex-compact', `${amex}\n`),
    positive('payment_card', 'amex-4-6-5', `${amexGroups(amex)}\n`),
    positive('payment_card', 'diners-14-spaced', `${diners.slice(0, 4)} ${diners.slice(4, 10)} ${diners.slice(10)}\n`),
    positive('payment_card', 'visa-19-compact', `${visa19}\n`),
    positive('payment_card', 'jcb', `${jcb}\n`),
    positive('payment_card', 'discover', `${group4(discover, ' ')}\n`),
    positive('payment_card', 'unionpay', `${unionPay}\n`),
    positive('payment_card', 'maestro', `${maestro}\n`),
    positive('payment_card', 'json-field', `{"pan":"${visa}","exp":"12/29"}\n`),
    negative('payment_card', 'wrong-luhn', `${breakLastDigit(visa)}\n`),
    negative('payment_card', 'unknown-network-prefix', `${unknownPrefix}\n`),
    negative('payment_card', 'mixed-separators', `${mixed}\n`),
    negative('payment_card', 'thirteen-digit-visa-form', `${visa13}\n`),
    negative('payment_card', 'amex-prefix-wrong-length', `${amexWrongLength}\n`),
    negative('payment_card', 'repeated-digit', '0000000000000000\n'),
    negative('payment_card', 'phone-numbers', 'tél 06 12 34 56 78 et 01 23 45 67 89\n'),
    negative('payment_card', 'nanosecond-timestamp', `${luhnNumber('1699', 19, 'card/ns')}\n`),
  ];
}

/** Cas de données personnelles, dans l'ordre des règles. */
export function personalDataCases(): CaseSource[] {
  return [...ibanDrafts(), ...nirDrafts(), ...siretDrafts(), ...sirenDrafts(), ...cardDrafts()].map((draft) => ({
    file: PERSONAL_DATA_FILE,
    id: draft.id,
    bytes: utf8Bytes(draft.text),
    intent: draft.intent,
  }));
}

/**
 * Résultat attendu d'un cas : constats de la lecture de référence (vue d'identité), à condition que le moteur d'origine
 * ne trouve rien dans le texte. Erreur sinon (le cas doit être redessiné) : la fusion des chevauchements n'est pas
 * simulée ici.
 */
export function personalDataExpected(engine: UpstreamEngine, source: CaseSource): CorpusExpected {
  const upstream = expectedFor(engine, source.bytes, source.languageId);
  if (!upstream.complete || upstream.findings.length > 0) {
    throw new CorpusError(`${source.id} : le moteur d’origine trouve ou échoue sur ce texte, le cas doit être redessiné`);
  }
  const decoded = decodeInput(source.bytes);
  const findings = referenceFindings(decoded.text).map((found): CorpusFinding => {
    const score = found.rule.score;
    return {
      ruleId: found.rule.ruleId,
      secretType: found.rule.secretType,
      encoding: 'plain',
      score,
      level: levelForScore(score),
      byteStart: byteOffsetOf(decoded, found.start),
      byteEnd: byteOffsetOf(decoded, found.end),
    };
  });
  findings.sort(compareFindings);
  for (const [index, finding] of findings.entries()) {
    const previous = findings[index - 1];
    if (previous !== undefined && finding.byteStart < previous.byteEnd) {
      throw new CorpusError(`${source.id} : deux règles de données personnelles se chevauchent, le cas doit être redessiné`);
    }
  }
  return { complete: true, failure: 'none', findings };
}

/** Problèmes de couverture des cas de données personnelles : intentions tenues, au moins 2 positifs et 3 négatifs par règle. */
export function personalDataCoverageProblems(cases: readonly { readonly id: string; readonly intent?: CaseIntent; readonly expected: CorpusExpected }[]): string[] {
  const problems: string[] = [];
  const counts = new Map<string, { positive: number; negative: number }>();
  for (const { id, intent, expected } of cases) {
    if (intent === undefined || (intent.kind !== 'positive' && intent.kind !== 'negative')) {
      problems.push(`${id} : intention absente ou hors positif/négatif`);
      continue;
    }
    const fires = expected.findings.some((finding) => finding.ruleId === intent.rule);
    if (intent.kind === 'positive' && !fires) problems.push(`${id} : la règle ${intent.rule} ne se déclenche pas`);
    if (intent.kind === 'negative' && fires) problems.push(`${id} : la règle ${intent.rule} se déclenche`);
    const entry = counts.get(intent.rule) ?? { positive: 0, negative: 0 };
    entry[intent.kind] += 1;
    counts.set(intent.rule, entry);
  }
  for (const rule of PERSONAL_DATA_RULES) {
    const entry = counts.get(rule.ruleId) ?? { positive: 0, negative: 0 };
    if (entry.positive < 2) problems.push(`règle de données personnelles sans deux cas positifs : ${rule.ruleId}`);
    if (entry.negative < 3) problems.push(`règle de données personnelles sans trois cas négatifs : ${rule.ruleId}`);
  }
  return problems;
}
