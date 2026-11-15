// SPDX-License-Identifier: Apache-2.0
/**
 * Cas du corpus de parité pour les règles de données à contexte (v0.9.0) : `vectors/detection/rules-context-data.json`.
 *
 * Ces règles n'existent pas dans le moteur TypeScript d'origine. Le résultat attendu d'un cas réunit donc deux
 * lectures : celle du moteur d'origine (entropie d'une clé, affectations…) et la lecture de référence des règles de
 * données à contexte (`rule-pack/context-data.ts` : chaque motif exécuté par le moteur d'expressions de JavaScript,
 * sans RE2 ni le moteur Go), fusionnées comme pour les règles de fournisseurs (`mergeProviderFindings`).
 *
 * Aucune donnée réelle. Adresses électroniques : domaines réservés aux essais (`.example`, `.test`, `example.com` ;
 * RFC 2606 et 6761), assemblées par morceaux. Téléphones : tranches réservées à la fiction (Arcep : 01 99 00, 06 39 98 ;
 * Amérique du Nord : 555-01xx ; Ofcom : 020 7946 0xxx). Passeports, cryptogrammes, codes, comptes AWS, identifiants
 * d'instance et clés : chiffres et lettres tirés de SHA-256 (`synth`). Adresses IP : plages privées de la RFC 1918.
 *
 * Depuis la v0.10.0 : identifiants européens et français à somme de contrôle (valeur calculée, clé retrouvée par le
 * contrôle de référence de `rule-pack/personal-data.ts`, seconde écriture indépendante du moteur Go) et règle
 * composée AWS (lecture de référence `awsPairSpans`).
 */
import { byteOffsetOf, decodeInput, utf8Bytes } from './bytes.ts';
import { CorpusError, expectedFor, type CaseSource } from './corpus.ts';
import { levelForScore, type CorpusExpected, type CorpusFinding } from './model.ts';
import { mergeProviderFindings } from './provider-rules.ts';
import { synth, type CaseIntent } from './synthetic.ts';
import { CONTEXT_DATA_RULES, contextReferenceFindings } from '../rule-pack/context-data.ts';
import {
  CHECK_ALNUM,
  CHECK_DIGITS,
  CHECK_LETTERS,
  CHECK_PAIRS,
  deTaxIdValid,
  deVatValid,
  esNieValid,
  esNifValid,
  fiHetuValid,
  frRibValid,
  frVatValid,
  itFiscalCodeValid,
  itVatValid,
  luhnCheckDigit,
  plPeselValid,
  sePersonnummerValid,
  ukNhsValid,
  withCheck,
} from '../rule-pack/personal-data.ts';
import type { UpstreamEngine } from './upstream.ts';

/** Fichier du corpus qui porte ces cas (famille `rules`, couverte par l'exception de `.gitleaks.toml`). */
export const CONTEXT_DATA_FILE = 'rules-context-data.json';

const DIGITS = '0123456789';
const UPPER = 'ABCDEFGHJKLMN' + 'PRSTUVWXYZ';
const LOWER = 'abcdefghijklm' + 'nopqrstuvwxyz';
const LOWER_ALNUM = LOWER + DIGITS;
const B64 = `${LOWER.toUpperCase()}${LOWER}${DIGITS}+/`;

const digits = (label: string, length: number): string => synth(`context-data/${label}`, DIGITS, length);
const letters = (label: string, length: number): string => synth(`context-data/${label}`, UPPER, length);
/** Chiffres sans zéro initial. */
const number = (label: string, length: number): string => `${String(1 + (Number(digits(`${label}/first`, 1)) % 9))}${digits(label, length - 1)}`;

/** Adresse électronique d'essai, assemblée : partie locale, domaine réservé. */
const address = (local: string, domain: string): string => [local, domain].join('@');

interface Draft {
  readonly id: string;
  readonly text: string;
  readonly intent: CaseIntent;
  /** Cas positif : étendue construite de la valeur, en unités UTF-16 du texte. */
  readonly span?: readonly [number, number];
}

/** Cas positif : `value`, entre `before` et `after`, est la valeur que la règle doit trouver, à cette étendue. */
function positive(rule: string, name: string, before: string, value: string, after = ''): Draft {
  return {
    id: `${rule}/positive/${name}`,
    text: `${before}${value}${after}\n`,
    intent: { kind: 'positive', rule },
    span: [before.length, before.length + value.length],
  };
}

function negative(rule: string, name: string, text: string): Draft {
  return { id: `${rule}/negative/${name}`, text: `${text}\n`, intent: { kind: 'negative', rule } };
}

function emailDrafts(): Draft[] {
  const rule = 'email_address';
  const person = address('camille.martin', 'societe.example');
  return [
    positive(rule, 'phrase', 'mon email est ', person),
    positive(rule, 'json', '{"email": "', address('c.martin', 'exemple.test'), '"}'),
    positive(rule, 'courriel', 'Courriel : ', address('accueil', 'mairie.example'), ' (du lundi au vendredi)'),
    positive(rule, 'git-config', 'git config user.email ', address('dev', 'equipe.example')),
    positive(rule, 'adresse-electronique', 'adresse électronique de contact : ', address('cabinet', 'conseil.example.com')),
    positive(rule, 'variable-majuscules', 'CONTACT_EMAIL=', address('Support', 'Service.Example')),
    positive(rule, 'e-mail-sous-domaine', 'e-mail: ', address('a.b+suivi', 'sous.domaine.example'), ', merci'),
    positive(rule, 'mon-mail', 'voici mon mail ', address('camille_m', 'boite.test')),
    negative(rule, 'sans-mot-cle', `écris à ${person} dès demain`),
    negative(rule, 'ligne-precedente', `email\n${person}`),
    negative(rule, 'mot-cle-trop-loin', `email du service après-vente de la région : ${address('sav', 'societe.example')}`),
    negative(rule, 'sans-domaine-de-tete', `email: ${address('root', 'localhost')}`),
    negative(rule, 'domaine-qui-porte-mail', `${address('a', 'mail.example')}, ${address('b', 'autre.example')}`),
    negative(rule, 'sans-adresse', 'email: à compléter'),
    negative(rule, 'point-entre-les-deux', `e-mail de M. Martin, ${address('camille', 'societe.example')}`),
  ];
}

function phoneDrafts(): Draft[] {
  const rule = 'phone_number';
  return [
    positive(rule, 'tel-fixe', 'Tél : ', '01 99 00 12 34'),
    positive(rule, 'telephone-portable-international', 'Téléphone portable : ', '+33 6 39 98 12 34'),
    positive(rule, 'json-amerique-du-nord', '{"phone": "', '+1 202-555-0143', '"}'),
    positive(rule, 'mobile-points', 'mobile ', '06.39.98.12.34', ' après 18 h'),
    positive(rule, 'fax-d-un-bloc', 'fax ', '0199001234'),
    positive(rule, 'tel-majuscules-00', 'TEL: ', '0033 1 99 00 12 34'),
    positive(rule, 'uri-tel-royaume-uni', 'tel:', '+44 20 7946 0123'),
    positive(rule, 'variable-zero-entre-parentheses', 'phone_number=', '+33(0)639981234'),
    positive(rule, 'tirets', 'Portable : ', '06-39-98-56-78'),
    negative(rule, 'sans-mot-cle', 'appelle le 06 39 98 12 34 demain'),
    negative(rule, 'date', 'tél 01.02.2024 10:30'),
    negative(rule, 'mot-cle-trop-loin', 'téléphone du secrétariat de direction : 01 99 00 12 34'),
    negative(rule, 'trop-court', 'tel 01 99 00 12'),
    negative(rule, 'trop-long', 'tel 019900123456'),
    negative(rule, 'separateurs-melanges', 'tel 01 99.00-12 34'),
    negative(rule, 'date-iso', 'mobile 2024-01-15'),
    negative(rule, 'ligne-precedente', 'téléphone\n01 99 00 12 34'),
    negative(rule, 'sans-numero', "téléphone : voir l'annuaire, bureau 142"),
  ];
}

function passportDrafts(): Draft[] {
  const rule = 'passport_number';
  const french = (label: string): string => `${digits(`passport/${label}/a`, 2)}${letters(`passport/${label}/b`, 2)}${digits(`passport/${label}/c`, 5)}`;
  return [
    positive(rule, 'francais', 'passeport n° ', french('fr')),
    positive(rule, 'number-lettre-et-chiffres', 'Passport number: ', `${letters('passport/en/a', 1)}${digits('passport/en/b', 7)}`),
    positive(rule, 'json-neuf-chiffres', '{"passport_no": "', number('passport/nine', 9), '"}'),
    positive(rule, 'numero-de-passeport', 'numéro de passeport : ', french('fr2'), ', délivré à Lyon'),
    positive(rule, 'id-majuscules', 'PASSPORT ID ', `${letters('passport/id/a', 2)}${digits('passport/id/b', 7)}`),
    positive(rule, 'est-le', 'mon passeport est le ', french('fr3')),
    negative(rule, 'paquet-et-version', 'passport@0.6.0 installé'),
    negative(rule, 'sans-numero', 'passeport valable 10 ans'),
    negative(rule, 'trop-court', `passport number: ${digits('passport/short', 5)}`),
    negative(rule, 'mots-entre-les-deux', `passeport de Mme Martin, n° ${french('fr')}`),
    negative(rule, 'sans-mot-cle', `référence ${french('fr')}`),
    negative(rule, 'ligne-precedente', `passeport\n${french('fr')}`),
  ];
}

function cardCodeDrafts(): Draft[] {
  const rule = 'payment_card_security_code';
  const code = (label: string, length: number): string => digits(`card-code/${label}`, length);
  return [
    positive(rule, 'cvv', 'cvv: ', code('cvv', 3)),
    positive(rule, 'cvc-quatre-chiffres', 'CVC ', code('cvc', 4)),
    positive(rule, 'json-cvv2', '{"cvv2": "', code('cvv2', 3), '"}'),
    positive(rule, 'cryptogramme-visuel', 'le cryptogramme visuel est ', code('visuel', 3), '.'),
    positive(rule, 'security-code', 'security code: ', code('security', 4)),
    positive(rule, 'code-de-securite', 'code de sécurité : ', code('securite', 3)),
    positive(rule, 'variable', 'card_cvc=', code('variable', 3)),
    negative(rule, 'champ-de-formulaire', '<input name="cvv" maxlength="4">'),
    negative(rule, 'trop-court', `cvv: ${code('court', 2)}`),
    negative(rule, 'trop-long', `cvv: ${code('long', 5)}`),
    negative(rule, 'controle', 'cvc_check: ok'),
    negative(rule, 'sans-code', 'le cryptogramme est au dos de la carte'),
    negative(rule, 'sans-mot-cle', `code ${code('nu', 3)}`),
  ];
}

function oneTimeCodeDrafts(): Draft[] {
  const rule = 'one_time_code';
  const code = (label: string, length: number): string => number(`otp/${label}`, length);
  const oneTime = ['one-time', ['pass', 'word'].join('')].join(' ');
  return [
    positive(rule, 'code-otp-est', 'votre code OTP est ', code('fr', 6)),
    positive(rule, 'verification-code-deux-groupes', 'Your verification code is ', `${code('en/a', 3)} ${code('en/b', 3)}`),
    positive(rule, 'code-de-verification', 'code de vérification : ', code('verif', 6), ' (valable 10 minutes)'),
    positive(rule, 'affectation-quatre-chiffres', 'otp=', code('court', 4)),
    positive(rule, 'one-time', `${oneTime}: `, code('long', 8)),
    positive(rule, 'usage-unique-tiret', 'code à usage unique ', `${code('unique/a', 3)}-${code('unique/b', 3)}`),
    positive(rule, 'deux-facteurs', '2FA code: ', code('2fa', 6)),
    positive(rule, 'json-otp-code', '{"otp_code": "', code('json', 6), '"}'),
    positive(rule, 'authentification', "code d'authentification reçu : ", code('auth', 6)),
    negative(rule, 'longueur', 'otp_length = 6'),
    negative(rule, 'trop-court', `OTP: ${code('trop-court', 3)}`),
    negative(rule, 'trop-long', `otp ${code('trop-long', 9)}`),
    negative(rule, 'duree', 'le code de vérification expire dans 10 minutes'),
    negative(rule, 'sans-code', 'verification code sent to your phone'),
    negative(rule, 'sans-mot-cle', `code ${code('nu', 6)}`),
    negative(rule, 'ligne-precedente', `OTP\n${code('ligne', 6)}`),
  ];
}

function azureDrafts(): Draft[] {
  const rule = 'azure_shared_access_key';
  const key = (label: string, length: number): string => `${synth(`context-data/azure/${label}`, B64, length)}=`;
  const field = ['Shared', 'Access', 'Key'].join('');
  const name = `${field}Name=RootManage${field}`;
  const serviceBus = 'Endpoint=sb://demo-ns.servicebus.windows.net/';
  return [
    positive(rule, 'service-bus', `${serviceBus};${name};${field}=`, key('service-bus', 43)),
    positive(rule, 'iot-hub', `HostName=demo-hub.azure-devices.net;DeviceId=capteur-1;${field}=`, key('iot-hub', 43), ';GatewayHostName=passerelle'),
    positive(rule, 'event-hubs-entre-guillemets', `EVENTHUB_CONNECTION="Endpoint=sb://demo-eh.servicebus.windows.net/;${name};${field}=`, key('event-hubs', 43), ';EntityPath=mesures"'),
    negative(rule, 'trop-courte', `${serviceBus};${field}=${key('courte', 30)}`),
    negative(rule, 'nom-seul', `${serviceBus};${name}`),
    negative(rule, 'valeur-fictive', `${serviceBus};${field}=<votre clé>`),
  ];
}

function internalIpDrafts(): Draft[] {
  const rule = 'internal_ip_address';
  return [
    positive(rule, 'serveur-interne', 'serveur interne : ', '10.12.3.4'),
    positive(rule, 'internal-ip-address', 'internal IP address is ', '192.168.4.12', ' (staging)'),
    positive(rule, 'ip-privee', 'IP privée ', '172.20.1.9'),
    positive(rule, 'vpn', 'VPN gateway ', '10.8.0.1'),
    positive(rule, 'bastion', 'bastion = ', '172.16.5.4'),
    positive(rule, 'sous-reseau-prive', 'private subnet ', '192.168.10.0', '/24'),
    negative(rule, 'sans-mot-cle', 'adresse 10.12.3.4'),
    negative(rule, 'adresse-publique', 'internal DNS 8.8.8.8'),
    negative(rule, 'hors-plage', 'private 172.32.0.1'),
    negative(rule, 'ligne-precedente', 'interne\n10.12.3.4'),
    negative(rule, 'octet-trop-grand', 'internal build 10.300.2.1'),
    negative(rule, 'version', 'version interne 1.10.2.3'),
    negative(rule, 'mot-cle-apres', "10.12.3.4 est l'adresse interne"),
  ];
}

function awsDrafts(): Draft[] {
  const account = (label: string): string => number(`aws/account/${label}`, 12);
  const instance = (label: string): string => synth(`context-data/aws/rds/${label}`, LOWER_ALNUM, 12);
  const bucket = 'demo-bucket-fictif';
  return [
    positive('aws_arn', 'role-iam', '', `arn:aws:iam::${account('iam')}:role/demo-admin`),
    positive('aws_arn', 'bucket-sans-compte', 'Resource: ', `arn:aws:s3:::${bucket}/exports`, '/*'),
    positive('aws_arn', 'table-dynamodb', '{"Resource": "', `arn:aws:dynamodb:eu-west-3:${account('dynamodb')}:table/Commandes`, '"}'),
    positive('aws_arn', 'partition-gov', 'fonction ', `arn:aws-us-gov:lambda:us-gov-west-1:${account('lambda')}:function:traitement`, '.'),
    negative('aws_arn', 'politique-geree', 'arn:aws:iam::aws:policy/ReadOnlyAccess'),
    negative('aws_arn', 'variable', 'arn:aws:s3:::${BucketName}/*'),
    negative('aws_arn', 'joker', 'arn:aws:s3:::*'),
    negative('aws_arn', 'compte-trop-court', `arn:aws:iam::${number('aws/account/court', 5)}:role/demo`),
    negative('aws_arn', 'forme-generale', 'arn:partition:service:region:account-id:resource'),

    positive('aws_s3_bucket', 'schema-s3', 'aws s3 cp export.csv ', `s3://${bucket}`, '/exports/'),
    positive('aws_s3_bucket', 'hote-virtuel', 'https://', `${bucket}.s3.eu-west-3.amazonaws.com`, '/a.csv'),
    positive('aws_s3_bucket', 'chemin', 'https://', `s3.eu-west-3.amazonaws.com/${bucket}`, '/a.csv'),
    positive('aws_s3_bucket', 'site-statique', 'CNAME ', 'demo-site-fictif.s3-website-eu-west-1.amazonaws.com'),
    negative('aws_s3_bucket', 'schema-seul', 'préfixe s3:// attendu'),
    negative('aws_s3_bucket', 'nom-trop-court', 's3://ab'),
    negative('aws_s3_bucket', 'sans-bucket', 'https://s3.eu-west-3.amazonaws.com/'),
    negative('aws_s3_bucket', 'majuscules', 'S3://Demo_Bucket'),
    negative('aws_s3_bucket', 'prose', "le service s3 d'amazonaws.com"),

    positive('aws_rds_endpoint', 'instance', 'host: ', `demo-db.${instance('instance')}.eu-west-3.rds.amazonaws.com`, ':5432'),
    positive('aws_rds_endpoint', 'grappe', 'PGHOST=', `demo-cluster.cluster-${instance('grappe')}.us-east-1.rds.amazonaws.com`),
    negative('aws_rds_endpoint', 'service-seul', 'rds.amazonaws.com'),
    negative('aws_rds_endpoint', 'point-d-acces-du-service', 'https://rds.eu-west-3.amazonaws.com'),
    negative('aws_rds_endpoint', 'sans-identifiant', 'demo-db.eu-west-3.rds.amazonaws.com'),

    positive('aws_dynamodb_endpoint', 'region', 'https://', 'dynamodb.eu-west-3.amazonaws.com'),
    positive('aws_dynamodb_endpoint', 'region-gov', 'endpoint_url=https://', 'dynamodb.us-gov-west-1.amazonaws.com', '/'),
    negative('aws_dynamodb_endpoint', 'sans-region', 'dynamodb.amazonaws.com'),
    negative('aws_dynamodb_endpoint', 'local', 'http://dynamodb.local:8000'),
    negative('aws_dynamodb_endpoint', 'autre-domaine', 'https://dynamodb.eu-west-3.example.com'),
  ];
}

// ---------------------------------------------------------------------------------------------------------------
// Identifiants européens et français à somme de contrôle, règle composée AWS (v0.10.0). Chaque valeur est calculée :
// chiffres et lettres tirés de SHA-256, clé de contrôle retrouvée par essais avec le contrôle de référence
// (`withCheck`). Aucun identifiant d'une personne ou d'une entreprise réelle ; codes postaux en 99, hors de France.
// ---------------------------------------------------------------------------------------------------------------

/** Premier essai réussi de `build` sur `label/0`, `label/1`… : une suite tirée au sort peut ne pas avoir de clé valide. */
function firstValid(label: string, build: (label: string) => string): string {
  for (let attempt = 0; attempt < 64; attempt += 1) {
    try {
      return build(`${label}/${String(attempt)}`);
    } catch {
      // Essai suivant.
    }
  }
  throw new CorpusError(`valeur d’essai introuvable : ${label}`);
}

/** Nombre de 01 à `max`, sur deux chiffres. */
const two = (label: string, max: number): string => String(1 + (Number(digits(label, 4)) % max)).padStart(2, '0');

/** Même valeur, dernier caractère changé (chiffre ou lettre suivants) : la clé de contrôle ne tient plus. */
function breakLast(value: string): string {
  const last = value.at(-1) ?? '0';
  const next = /[0-9]/.test(last) ? String((Number(last) + 1) % 10) : String.fromCharCode(last === 'Z' ? 65 : last.charCodeAt(0) + 1);
  return `${value.slice(0, -1)}${next}`;
}

/** Cas d'un identifiant annoncé : positifs, puis clé fausse, valeur sans mot-clé et mot-clé sur la ligne précédente. */
function announcedDrafts(
  rule: string,
  keyword: string,
  positives: readonly (readonly [name: string, before: string, value: string, after?: string])[],
): Draft[] {
  const sample = positives[0]?.[2] ?? '';
  return [
    ...positives.map(([name, before, value, after]) => positive(rule, name, before, value, after)),
    negative(rule, 'cle-fausse', `${keyword} ${breakLast(sample)}`),
    negative(rule, 'sans-mot-cle', `dossier ${sample} transmis`),
    negative(rule, 'ligne-precedente', `${keyword}\n${sample}`),
  ];
}

function spanishDrafts(): Draft[] {
  const nif = (label: string): string => withCheck(digits(`es/nif/${label}`, 8), CHECK_LETTERS, esNifValid);
  const nie = (label: string, head: string): string => withCheck(`${head}${digits(`es/nie/${label}`, 7)}`, CHECK_LETTERS, esNieValid);
  const dashed = nif('b');
  const foreign = nie('c', 'Z');
  return [
    ...announcedDrafts('es_nif', 'NIF', [
      ['phrase', 'mon NIF est ', nif('a')],
      ['json-dni-tiret', '{"dni": "', `${dashed.slice(0, 8)}-${dashed.slice(8)}`, '"}'],
      ['carte-espagnole', 'carte d’identité espagnole n° ', nif('c'), ', délivrée à Séville'],
      ['spanish-id-card', 'Spanish ID card number: ', nif('d').toLowerCase()],
    ]),
    ...announcedDrafts('es_nie', 'NIE', [
      ['phrase', 'NIE : ', nie('a', 'X')],
      ['foreigner-identity-number', 'foreigner identity number ', nie('b', 'Y')],
      ['numero-d-etranger-tirets', 'numéro d’identité d’étranger : ', `${foreign.slice(0, 1)}-${foreign.slice(1, 8)}-${foreign.slice(8)}`],
    ]),
  ];
}

function italianDrafts(): Draft[] {
  const fiscalCode = (label: string): string =>
    withCheck(
      `${letters(`it/cf/${label}/name`, 6)}${digits(`it/cf/${label}/year`, 2)}${synth(`context-data/it/cf/${label}/month`, 'ABCDEHLMPRST', 1)}` +
        `${two(`it/cf/${label}/day`, 28)}${letters(`it/cf/${label}/town`, 1)}${digits(`it/cf/${label}/code`, 3)}`,
      CHECK_LETTERS,
      itFiscalCodeValid,
    );
  const vat = (label: string): string => withCheck(digits(`it/vat/${label}`, 10), CHECK_DIGITS, itVatValid);
  return [
    ...announcedDrafts('it_fiscal_code', 'codice fiscale', [
      ['codice-fiscale', 'Codice fiscale: ', fiscalCode('a')],
      ['code-fiscal-italien-minuscules', 'code fiscal italien : ', fiscalCode('b').toLowerCase(), ' (né à Turin)'],
      ['italian-tax-code', 'Italian tax code ', fiscalCode('c')],
    ]),
    ...announcedDrafts('it_vat', 'partita IVA', [
      ['partita-iva', 'Partita IVA: ', vat('a')],
      ['p-iva-prefixe-it', 'P. IVA IT', vat('b')],
      ['tva-italienne', 'TVA italienne : ', vat('c'), ', siège à Milan'],
      ['italian-vat-number', 'Italian VAT number: ', vat('d')],
    ]),
  ];
}

function germanDrafts(): Draft[] {
  const taxId = (label: string): string => firstValid(`de/tax/${label}`, (attempt) => withCheck(number(attempt, 10), CHECK_DIGITS, deTaxIdValid));
  const vat = (label: string): string => withCheck(`DE${number(`de/vat/${label}`, 8)}`, CHECK_DIGITS, deVatValid);
  const spaced = taxId('b');
  const second = vat('c');
  return [
    ...announcedDrafts('de_tax_id', 'Steuer-ID', [
      ['steuer-id', 'Steuer-ID: ', taxId('a')],
      ['idnr-espaces', 'IdNr. ', `${spaced.slice(0, 2)} ${spaced.slice(2, 5)} ${spaced.slice(5, 8)} ${spaced.slice(8)}`],
      ['identifiant-fiscal-allemand', 'identifiant fiscal allemand : ', taxId('c'), ' (Berlin)'],
      ['german-tax-id-number', 'German tax ID number: ', taxId('d')],
    ]),
    ...announcedDrafts('de_vat', 'USt-IdNr.', [
      ['ust-idnr', 'USt-IdNr.: ', vat('a')],
      ['tva-allemande', 'TVA allemande : ', vat('b')],
      ['german-vat-number-espace', 'German VAT number ', `${second.slice(0, 2)} ${second.slice(2)}`],
    ]),
  ];
}

function northernDrafts(): Draft[] {
  const pesel = (label: string): string =>
    withCheck(`${digits(`pl/${label}/year`, 2)}${two(`pl/${label}/month`, 12)}${two(`pl/${label}/day`, 28)}${digits(`pl/${label}/order`, 4)}`, CHECK_DIGITS, plPeselValid);
  const nhs = (label: string): string => firstValid(`uk/nhs/${label}`, (attempt) => withCheck(number(attempt, 9), CHECK_DIGITS, ukNhsValid));
  const personnummer = (label: string): string =>
    withCheck(`${digits(`se/${label}/year`, 2)}${two(`se/${label}/month`, 12)}${two(`se/${label}/day`, 28)}${digits(`se/${label}/order`, 3)}`, CHECK_DIGITS, sePersonnummerValid);
  const hetu = (label: string, separator: string): string =>
    withCheck(`${two(`fi/${label}/day`, 28)}${two(`fi/${label}/month`, 12)}${digits(`fi/${label}/year`, 2)}${separator}${digits(`fi/${label}/order`, 3)}`, CHECK_ALNUM, fiHetuValid);
  const grouped = nhs('a');
  const hyphenated = nhs('c');
  const dashed = personnummer('a');
  return [
    ...announcedDrafts('pl_pesel', 'PESEL', [
      ['phrase', 'mon numéro PESEL est ', pesel('a')],
      ['json', '{"pesel": "', pesel('b'), '"}'],
      ['pesel-number', 'PESEL number: ', pesel('c')],
    ]),
    ...announcedDrafts('uk_nhs', 'NHS number', [
      ['nhs-number-groupes', 'NHS number: ', `${grouped.slice(0, 3)} ${grouped.slice(3, 6)} ${grouped.slice(6)}`],
      ['numero-nhs', 'numéro NHS : ', nhs('b'), ' (patient)'],
      ['national-health-service-tirets', 'National Health Service no. ', `${hyphenated.slice(0, 3)}-${hyphenated.slice(3, 6)}-${hyphenated.slice(6)}`],
    ]),
    ...announcedDrafts('se_personnummer', 'personnummer', [
      ['personnummer-tiret', 'Personnummer: ', `${dashed.slice(0, 6)}-${dashed.slice(6)}`],
      ['personal-identity-number-douze-chiffres', 'personal identity number ', `19${personnummer('b')}`],
      ['numero-personnel-suedois', 'numéro personnel suédois : ', personnummer('c')],
    ]),
    ...announcedDrafts('fi_personal_identity_code', 'HETU', [
      ['hetu', 'HETU: ', hetu('a', '-')],
      ['henkilotunnus-annees-2000', 'henkilötunnus ', hetu('b', 'A')],
      ['identifiant-personnel-finlandais', 'identifiant personnel finlandais : ', hetu('c', '-').toLowerCase(), ' (Helsinki)'],
      ['finnish-personal-identity-code', 'Finnish personal identity code: ', hetu('d', '+')],
    ]),
  ];
}

function frenchDrafts(): Draft[] {
  const siren = (label: string): string => {
    const body = number(`fr/siren/${label}`, 8);
    return `${body}${luhnCheckDigit(body)}`;
  };
  const vat = (label: string): string => withCheck('FR', CHECK_PAIRS, frVatValid, siren(label));
  const rib = (label: string, account: string): string =>
    withCheck(`${digits(`fr/rib/${label}/bank`, 5)}${digits(`fr/rib/${label}/branch`, 5)}${account}`, CHECK_PAIRS, frRibValid);
  const account = (label: string): string => digits(`fr/rib/${label}/account`, 11);
  const plain = rib('a', account('a'));
  const lettered = rib('c', `${digits('fr/rib/c/head', 4)}${letters('fr/rib/c/letters', 3)}${digits('fr/rib/c/tail', 4)}`);
  const plateLetters = (label: string): string => synth(`context-data/fr/plate/${label}`, 'ABCDEFGHJKLMNPQRSTVWXYZ', 2);
  const plate = (label: string, separator: string): string =>
    [plateLetters(`${label}/a`), digits(`fr/plate/${label}`, 3), plateLetters(`${label}/b`)].join(separator);
  const spacedVat = vat('b');
  const street = '12 rue des Essais, 99000 Villefictive';
  return [
    positive('fr_vat', 'tva-intracommunautaire', 'TVA intracommunautaire : ', vat('a')),
    positive('fr_vat', 'espaces', 'N° TVA ', `${spacedVat.slice(0, 4)} ${spacedVat.slice(4, 7)} ${spacedVat.slice(7, 10)} ${spacedVat.slice(10)}`, ' (siège)'),
    positive('fr_vat', 'sans-mot-cle', 'facture émise par ', vat('c'), ', payée'),
    negative('fr_vat', 'cle-fausse', `TVA ${breakLast(vat('a').slice(0, 4))}${vat('a').slice(4)}`),
    negative('fr_vat', 'siren-faux', `TVA ${breakLast(vat('a'))}`),
    negative('fr_vat', 'minuscules', `tva ${vat('a').toLowerCase()}`),
    negative('fr_vat', 'un-chiffre-de-trop', `TVA ${vat('a')}7`),

    ...announcedDrafts('fr_rib', 'RIB', [
      ['rib-groupes', 'RIB : ', `${plain.slice(0, 5)} ${plain.slice(5, 10)} ${plain.slice(10, 21)} ${plain.slice(21)}`],
      ['releve-d-identite-bancaire', 'relevé d’identité bancaire : ', rib('b', account('b')), ', merci'],
      ['compte-a-lettres-tirets', 'RIB ', `${lettered.slice(0, 5)}-${lettered.slice(5, 10)}-${lettered.slice(10, 21).toLowerCase()}-${lettered.slice(21)}`],
      ['bank-account-details', 'bank account details: ', rib('d', account('d'))],
    ]),

    positive('fr_license_plate', 'plaque-d-immatriculation', 'plaque d’immatriculation : ', plate('a', '-')),
    positive('fr_license_plate', 'vehicule-immatricule-espaces', 'véhicule immatriculé ', plate('b', ' '), ', gris'),
    positive('fr_license_plate', 'license-plate-d-un-bloc', 'license plate ', plate('c', '')),
    positive('fr_license_plate', 'registration-number', 'Registration number: ', plate('d', '-')),
    negative('fr_license_plate', 'sans-mot-cle', `référence ${plate('a', '-')} en stock`),
    negative('fr_license_plate', 'minuscules', `plaque ${plate('a', '-').toLowerCase()}`),
    negative('fr_license_plate', 'lettres-exclues', 'plaque AI-123-OU'),
    negative('fr_license_plate', 'mot-cle-trop-loin', `immatriculation du véhicule de la direction régionale : ${plate('a', '-')}`),
    negative('fr_license_plate', 'ligne-precedente', `plaque\n${plate('a', '-')}`),
    negative('fr_license_plate', 'mot-qui-porte-plate', `template ${plate('a', '-')}`),

    positive('fr_postal_address', 'rue', 'Adresse : ', street),
    positive('fr_postal_address', 'avenue-deux-lignes', 'Livraison :\n', '5 bis avenue du Corpus\n99100 Saint-Exemple'),
    positive('fr_postal_address', 'boulevard-a-date', '', '128 Boulevard du 11 Novembre 1918, 99200 Bourg-la-Demo', ' (siège)'),
    negative('fr_postal_address', 'sans-code-postal', '12 rue des Essais, Villefictive'),
    negative('fr_postal_address', 'sans-numero', 'rue des Essais, 99000 Villefictive'),
    negative('fr_postal_address', 'type-de-voie-inconnu', '12 venelle des Essais, 99000 Villefictive'),
    negative('fr_postal_address', 'commune-sans-majuscule', '12 rue des Essais, 99000 villefictive'),
    negative('fr_postal_address', 'code-postal-de-quatre-chiffres', '12 rue des Essais, 9900 Villefictive'),
  ];
}

function awsPairDrafts(): Draft[] {
  const rule = 'aws_access_key_pair';
  const base32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const id = (label: string, prefix: readonly [string, string]): string => `${prefix.join('')}${synth(`context-data/aws/pair/id/${label}`, base32, 16)}`;
  const shaped = (value: string): string => {
    if (!/[a-z]/.test(value) || !/[A-Z]/.test(value) || !/[0-9]/.test(value)) throw new CorpusError('valeur sans minuscule, majuscule ou chiffre');
    return value;
  };
  const secret = (label: string): string => firstValid(`aws/pair/secret/${label}`, (attempt) => shaped(synth(`context-data/${attempt}`, B64, 40)));
  const durable = id('a', ['AK', 'IA']);
  const temporary = id('b', ['AS', 'IA']);
  return [
    positive(rule, 'deux-colonnes', 'identifiant,valeur\n', `${durable},${secret('a')}`),
    positive(rule, 'cote-a-cote', '', `${id('c', ['AK', 'IA'])} ${secret('b')}`, ' (console)'),
    positive(rule, 'valeur-avant-l-identifiant', 'export : ', `${secret('c')}\t${temporary}`),
    positive(rule, 'deux-lignes', 'copie du fichier :\n', `${id('d', ['AK', 'IA'])}\n${secret('d')}`, '\n# fin'),
    negative(rule, 'identifiant-seul', `compte ${durable}`),
    negative(rule, 'empreinte-hexadecimale', `${durable} ${synth('context-data/aws/pair/hex', '0123456789abcdef', 40)}`),
    negative(rule, 'valeur-hors-de-la-fenetre', `${durable} ${'mot '.repeat(60)}${secret('a')}`),
    negative(rule, 'valeur-de-39-caracteres', `${durable},${secret('a').slice(1)}`),
    negative(rule, 'valeur-de-41-caracteres', `${durable},${secret('a')}A`),
    negative(rule, 'valeur-sans-chiffre', `${durable},${synth('context-data/aws/pair/letters', LOWER + UPPER, 40)}`),
  ];
}

function drafts(): Draft[] {
  return [
    ...emailDrafts(),
    ...phoneDrafts(),
    ...passportDrafts(),
    ...cardCodeDrafts(),
    ...oneTimeCodeDrafts(),
    ...azureDrafts(),
    ...internalIpDrafts(),
    ...awsDrafts(),
    ...spanishDrafts(),
    ...italianDrafts(),
    ...germanDrafts(),
    ...northernDrafts(),
    ...frenchDrafts(),
    ...awsPairDrafts(),
  ];
}

/** Cas des règles de données à contexte, dans l'ordre des règles. */
export function contextDataCases(): CaseSource[] {
  return drafts().map((draft) => ({ file: CONTEXT_DATA_FILE, id: draft.id, bytes: utf8Bytes(draft.text), intent: draft.intent }));
}

/** Constats des règles de données à contexte par la lecture de référence. */
export function contextReference(bytes: Uint8Array): CorpusFinding[] {
  const decoded = decodeInput(bytes);
  if (!decoded.validUtf8 || /[\u212a\u017f\r\u2028\u2029]/.test(decoded.text)) throw new CorpusError('cas hors du domaine de la lecture de référence des données à contexte');
  return contextReferenceFindings(decoded.text).map((found) => ({
    ruleId: found.rule.ruleId,
    secretType: found.rule.secretType,
    encoding: 'plain',
    score: found.rule.score,
    level: levelForScore(found.rule.score),
    byteStart: byteOffsetOf(decoded, found.start),
    byteEnd: byteOffsetOf(decoded, found.end),
  }));
}

/**
 * Constats attendus d'un texte que d'autres lectures ont déjà jugé (`findings`) : la lecture de référence des règles
 * de données à contexte s'y ajoute, fusionnée comme `dedupeOverlaps` du moteur d'origine. Sert aussi aux cas des règles
 * de données personnelles de la v0.7.0 dont le texte annonce un téléphone ou un cryptogramme.
 */
export function withContextFindings(id: string, findings: readonly CorpusFinding[], bytes: Uint8Array): CorpusFinding[] {
  return mergeProviderFindings(id, findings, contextReference(bytes));
}

/** Résultat attendu d'un cas : constats du moteur d'origine et de la lecture de référence, fusionnés. */
export function contextDataExpected(engine: UpstreamEngine, source: CaseSource): CorpusExpected {
  const upstream = expectedFor(engine, source.bytes, source.languageId);
  if (!upstream.complete) throw new CorpusError(`${source.id} : le moteur d’origine échoue sur ce texte, le cas doit être redessiné`);
  return { complete: true, failure: 'none', findings: withContextFindings(source.id, upstream.findings, source.bytes) };
}

/** Étendue construite, en octets, de la valeur de chaque cas positif (par identifiant de cas). */
export function contextDataSpans(): Map<string, readonly [number, number]> {
  const spans = new Map<string, readonly [number, number]>();
  for (const draft of drafts()) {
    if (draft.span === undefined) continue;
    const decoded = decodeInput(utf8Bytes(draft.text));
    spans.set(draft.id, [byteOffsetOf(decoded, draft.span[0]), byteOffsetOf(decoded, draft.span[1])]);
  }
  return spans;
}

/**
 * Problèmes de couverture : chaque cas positif trouve une fois la valeur construite, à son étendue exacte et au score
 * de sa règle ; aucun cas négatif ne déclenche sa règle ; au moins 2 positifs et 3 négatifs par règle.
 */
export function contextDataCoverageProblems(
  cases: readonly { readonly id: string; readonly intent?: CaseIntent; readonly expected: CorpusExpected }[],
): string[] {
  const problems: string[] = [];
  const spans = contextDataSpans();
  const counts = new Map<string, { positive: number; negative: number }>();
  for (const { id, intent, expected } of cases) {
    if (intent === undefined || (intent.kind !== 'positive' && intent.kind !== 'negative')) {
      problems.push(`${id} : intention absente ou hors positif/négatif`);
      continue;
    }
    const rule = CONTEXT_DATA_RULES.find((candidate) => candidate.ruleId === intent.rule);
    const found = expected.findings.filter((finding) => finding.ruleId === intent.rule);
    if (intent.kind === 'positive') {
      const span = spans.get(id);
      const [only] = found;
      if (found.length !== 1 || only === undefined || span === undefined || only.byteStart !== span[0] || only.byteEnd !== span[1] || only.score !== rule?.score) {
        problems.push(`${id} : la valeur construite n’est pas trouvée une fois, à son étendue et à son score`);
      }
    } else if (found.length > 0) {
      problems.push(`${id} : la règle ${intent.rule} se déclenche`);
    }
    const entry = counts.get(intent.rule) ?? { positive: 0, negative: 0 };
    entry[intent.kind] += 1;
    counts.set(intent.rule, entry);
  }
  for (const rule of CONTEXT_DATA_RULES) {
    const entry = counts.get(rule.ruleId) ?? { positive: 0, negative: 0 };
    if (entry.positive < 2) problems.push(`règle de données à contexte sans deux cas positifs : ${rule.ruleId}`);
    if (entry.negative < 3) problems.push(`règle de données à contexte sans trois cas négatifs : ${rule.ruleId}`);
  }
  return problems;
}
