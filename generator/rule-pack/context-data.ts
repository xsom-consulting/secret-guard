// SPDX-License-Identifier: Apache-2.0
/**
 * Règles de données à contexte du Pack initial (v0.9.0) : données personnelles annoncées par un mot-clé (adresse
 * électronique, téléphone, passeport, cryptogramme de carte, code à usage unique) et identifiants d'infrastructure
 * (clé d'accès partagé d'une chaîne de connexion Azure, adresse IP privée annoncée comme interne, adresses de
 * ressources AWS : ARN, bucket S3, point d'accès RDS, point d'accès DynamoDB). Extension propre à ce dépôt, sans
 * origine dans Secret Guard : ces règles viennent après les règles de fournisseurs.
 *
 * Chaque règle est une règle « motif seul » (`fixed_pattern`) : le moteur l'exécute telle que le Pack la décrit, la
 * valeur détectée est son unique groupe capturant (la correspondance entière s'il n'en a pas). Les règles de la
 * v0.9.0 n'ont pas de validateur ; les identifiants à somme de contrôle de la v0.10.0 en ont un.
 *
 * Technique : une forme générique (une adresse, dix chiffres, trois chiffres…) n'est un constat que si un mot-clé de
 * contexte la précède de près, sur la même ligne. C'est la technique des motifs de données personnelles d'Akto
 * (akto-api-security/akto, `PiiPatterns.java`, MIT : avis dans NOTICE, détail dans UPSTREAM.md). Les motifs sont écrits
 * ici, en RE2, sans reprise de texte : mots-clés français et anglais, liaison bornée (« : », « = », « est », « is »)
 * au lieu d'un intervalle libre pour les valeurs numériques, formes des valeurs propres à ce dépôt. Pour les adresses
 * de ressources AWS et la clé Azure, le contexte est le littéral fixe du fournisseur (`arn:aws`, `s3://`,
 * `amazonaws.com`, `SharedAccessKey=`).
 *
 * Portes littérales (`detect/prefilter.go`) : un motif qui replie la casse (`(?i:…)`) n'a de porte que si ses littéraux
 * sont en ASCII ; une lettre accentuée d'un mot-clé y est donc écrite « . » (un caractère quelconque), et la règle du
 * téléphone, dont le mot-clé « tél » est trop court pour cela, écrit ses casses une à une sans replier.
 *
 * Ce fichier tient aussi la lecture de référence du corpus (`corpus/context-data.ts`) : chaque motif exécuté par le
 * moteur d'expressions de JavaScript, sans RE2 ni le moteur Go.
 *
 * Depuis la v0.10.0, il porte aussi les identifiants européens et français à somme de contrôle (motif, mot-clé de
 * contexte obligatoire, validateur nommé du moteur) et la règle composée AWS, décrits plus bas.
 */
import type { RulePackRule, RuleSecretType, RuleValidator } from '../src/rule-pack.ts';
import { REFERENCE_VALIDATORS } from './personal-data.ts';

/** Dépôt, commit et fichier d'Akto dont la technique du mot-clé de contexte est reprise (MIT). */
export const CONTEXT_UPSTREAM_REPOSITORY = 'akto-api-security/akto';
export const CONTEXT_UPSTREAM_COMMIT = '6b7de940c28037d726776bc5f201fd9e572133a3';
export const CONTEXT_UPSTREAM_PATH = 'apps/dashboard/src/main/java/com/akto/service/insights/PiiPatterns.java';

/**
 * Dépôt, commit et dossier de Presidio (MIT, « Copyright (c) Presidio Contributors ») dont les reconnaissances
 * européennes sont portées : forme de la valeur et somme de contrôle (v0.10.0).
 */
export const PRESIDIO_UPSTREAM_REPOSITORY = 'data-privacy-stack/presidio';
export const PRESIDIO_UPSTREAM_COMMIT = 'fd78e974fbf9e15dad1f90de4fc125db39ef4200';
export const PRESIDIO_UPSTREAM_PATH = 'presidio-analyzer/presidio_analyzer/predefined_recognizers';

/** Espaces d'une ligne : espace, tabulation, espace insécable, espace fine insécable (typographie française). */
const SP = '[ \\t\u00a0\u202f]';

/**
 * Liaison entre un mot-clé et une valeur numérique : guillemet fermant du nom, puis « : », « = », « est » ou « is »,
 * puis « le » (« est le 123456 »), puis guillemet ouvrant de la valeur ; tout est facultatif, rien d'autre n'est admis.
 */
const LINK = `["']?${SP}*(?:(?:[:=]|is|est)${SP}*)?(?:le${SP}+)?["']?`;

/** Octet d'adresse IPv4 (0 à 255). */
const OCTET = '(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})';

/** Région AWS (`eu-west-3`, `us-gov-west-1`, `ap-southeast-2`). */
const AWS_REGION = '[a-z]{2}(?:-[a-z]+){1,2}-[0-9]';

/** Nom de bucket S3 : 3 à 63 minuscules, chiffres, points et tirets, bornés par une lettre ou un chiffre. */
const S3_BUCKET = '[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]';

/**
 * Adresse électronique : après « email », « e-mail », « courriel », « mail » ou « adresse électronique », à 24
 * caractères au plus sur la même ligne, sans « @ » ni point entre les deux (une adresse dont le domaine porte « mail »
 * n'annonce pas la suivante).
 */
const EMAIL_BODY = String.raw`(?:e-?mail|courriel|\bmail\b|adresse .lectronique)[^\n@.]{0,24}?\b([a-z0-9][a-z0-9._%+-]{0,63}@(?:[a-z0-9][a-z0-9-]{0,62}\.){1,8}[a-z]{2,24})`;

/**
 * Téléphone : après « tél », « tel », « phone » (« téléphone », « telephone »), « mobile », « portable » ou « fax »,
 * à 20 caractères au plus sans chiffre ni « + ». Numéro international (« + » ou « 00 », indicatif, 8 à 15 chiffres,
 * séparés d'une espace, d'un point ou d'un tiret, « (0) » admis) ou numéro français de dix chiffres (d'un bloc, ou par
 * paires séparées toutes de la même façon : une date « 01.02.2024 10 » n'en est pas un). Casses écrites une à une,
 * sans classe « [Tt] » (que l'analyseur de RE2 lit comme un littéral replié) : seize littéraux, le plus que porte une
 * porte.
 */
const PHONE_PATTERN =
  String.raw`(?:\b(?:Tel|tel|TEL|Tél|tél|TÉL)|Phone|phone|PHONE|Mobile|mobile|MOBILE|Portable|portable|Fax|fax)[^\n0-9+]{0,20}?` +
  String.raw`((?:\+|00)[1-9](?:[ .-]?\(?[0-9]\)?){7,14}|0[1-9](?:[0-9]{8}|(?: [0-9]{2}){4}|(?:\.[0-9]{2}){4}|(?:-[0-9]{2}){4}))\b`;

/**
 * Passeport : après « passport » ou « passeport » (puis « number », « numéro », « no », « n° », « # », « id »
 * facultatifs) et la liaison. Numéro français (2 chiffres, 2 lettres, 5 chiffres), 1 ou 2 lettres et 6 à 8 chiffres,
 * ou 9 chiffres.
 */
const PASSPORT_BODY =
  `pass(?:e)?ports?(?:[ \\t_-]*(?:number|num.ro|num|no|n°|#|id))?\\.?${LINK}` +
  String.raw`([0-9]{2}[a-z]{2}[0-9]{5}|[a-z]{1,2}[0-9]{6,8}|[0-9]{9})`;

/**
 * Cryptogramme de carte : après « cvv », « cvc » (« cvv2 », « cvc2 »), « cryptogramme (visuel) », « security code »
 * ou « code de sécurité » (puis « code » ou « number » facultatifs) et la liaison ; 3 ou 4 chiffres.
 */
const CARD_CODE_BODY =
  `(?:cvv2?|cvc2?|cryptogramme(?: visuel)?|security code|code de s.curit.)(?:[ _-]?(?:code|number))?${LINK}` +
  String.raw`([0-9]{3,4})`;

/**
 * Code à usage unique : après « otp » (« totp », « hotp »), « one-time password/passcode/code/pin », « verification code »,
 * « confirmation code », « validation code », « authentication code », « 2fa code », « code de vérification »,
 * « code de confirmation », « code de validation », « code d'authentification » ou « code à usage unique » (puis
 * « code », « sms », « reçu », « received » facultatifs) et la liaison ; 4 à 8 chiffres, ou deux groupes de trois.
 * « otp » n'est pas écrit à côté de « one.time » : l'analyseur de RE2 mettrait leur « o » en facteur, et la branche
 * « tp » restante, trop courte, retirerait la porte littérale.
 */
const ONE_TIME_CODE_BODY =
  String.raw`(?:one.time (?:password|passcode|code|pin)|(?:verification|confirmation|validation|authentication|2fa) code|otp|` +
  String.raw`code (?:de |d.)?(?:v.rification|confirmation|validation|authentification)|code . usage unique)` +
  `(?:[ _-]?(?:code|sms|re.u|received))?${LINK}` +
  String.raw`([0-9]{3}[ -][0-9]{3}|[0-9]{4,8})`;

/** Clé d'accès partagé d'une chaîne de connexion Azure (Service Bus, Event Hubs, IoT Hub) : 32 octets en base64. */
const AZURE_SHARED_ACCESS_KEY_PATTERN = String.raw`\bSharedAccessKey=([A-Za-z0-9+/]{43}=)`;

/**
 * Adresse IP privée (RFC 1918 : 10/8, 172.16/12, 192.168/16) annoncée comme interne : après « internal », « interne »,
 * « intranet », « private », « privé(e) », « vpn » ou « bastion », à 24 caractères au plus sans chiffre.
 */
const INTERNAL_IP_BODY =
  String.raw`(?:\b(?:internal|interne|intranet|private|vpn|bastion)s?\b|\bpriv.e?s?)[^\n0-9]{0,24}?` +
  String.raw`\b(10(?:\.${OCTET}){3}|172\.(?:1[6-9]|2[0-9]|3[01])(?:\.${OCTET}){2}|192\.168(?:\.${OCTET}){2})`;

/**
 * ARN d'une ressource AWS : partition, service, région, compte de 12 chiffres (ou vide : S3), ressource. Un ARN de
 * politique gérée par AWS (compte « aws ») ou dont la ressource est une variable n'en est pas un.
 */
const AWS_ARN_PATTERN = String.raw`\barn:aws(?:-cn|-us-gov)?:[a-z0-9-]{2,32}:[a-z0-9-]{0,24}:(?:[0-9]{12})?:[A-Za-z0-9](?:[A-Za-z0-9_+=,.@/:-]{0,126}[A-Za-z0-9_])?`;

/** Bucket S3 : `s3://nom`, `nom.s3.région.amazonaws.com` (ou `s3-website-…`), `s3.région.amazonaws.com/nom`. */
const AWS_S3_PATTERN =
  String.raw`\bs3://${S3_BUCKET}\b|\b${S3_BUCKET}\.s3[.-](?:[a-z0-9-]{1,24}\.)?amazonaws\.com\b|` +
  String.raw`\bs3[.-][a-z0-9-]{1,24}\.amazonaws\.com/${S3_BUCKET}\b`;

/** Point d'accès RDS : `instance.identifiant.région.rds.amazonaws.com` (grappe et proxy compris). */
const AWS_RDS_PATTERN = String.raw`\b[a-z0-9][a-z0-9-]{0,62}\.[a-z0-9-]{6,40}\.${AWS_REGION}\.rds\.amazonaws\.com(?:\.cn)?\b`;

/** Point d'accès DynamoDB d'une région : `dynamodb.région.amazonaws.com`. */
const AWS_DYNAMODB_PATTERN = String.raw`\b(?:streams\.)?dynamodb\.${AWS_REGION}\.amazonaws\.com(?:\.cn)?\b`;

// ---------------------------------------------------------------------------------------------------------------
// Identifiants européens et français à somme de contrôle (v0.10.0), règle composée AWS.
//
// Les identifiants européens reprennent les reconnaissances par pays de Presidio (MIT : avis dans NOTICE, détail dans
// UPSTREAM.md) : forme de la valeur et contrôle. Les motifs sont réécrits ici en RE2 (ceux de Presidio à anticipation
// ne se copient pas), et deux choses changent : le mot-clé de contexte, qui n'ajoute chez Presidio qu'un bonus de
// score, est ici obligatoire, en français, en anglais et dans la langue du pays ; le contrôle est un validateur nommé
// du moteur (`detect/personaldata.go`), sans lequel il n'y a pas de constat. Les identifiants français (TVA
// intracommunautaire, RIB, plaque d'immatriculation, adresse postale) n'existent pas chez Presidio.
// ---------------------------------------------------------------------------------------------------------------

/** Nom facultatif après le mot-clé : « number », « numéro », « Nummer », « no », « nr », « n° », « # », « id », « code ». */
const NUM = String.raw`(?:[ \t_-]*(?:number|num.ro|nummer|numero|num|no|nr|n°|#|id|code))?\.?`;

/** Mot-clé, nom facultatif, liaison, valeur : corps d'une règle d'identifiant annoncé (`folded`). */
const announced = (keywords: string, value: string): string => `(?:${keywords})${NUM}${LINK}${value}`;

/**
 * NIF (DNI) espagnol : 7 ou 8 chiffres et une lettre, tiret admis. Un mot-clé court est écrit entre deux « \b » : sans
 * eux, l'analyseur de RE2 mettrait sa première lettre en facteur avec la branche voisine et retirerait la porte.
 */
const ES_NIF_BODY = announced(
  String.raw`\bdni\b|\bnif\b|documento nacional de identidad|carte d.identit. espagnole|spanish (?:id|identity) card`,
  String.raw`([0-9]{7,8}-?[a-z])`,
);

/** NIE espagnol (étranger) : X, Y ou Z, 7 chiffres, une lettre. */
const ES_NIE_BODY = announced(
  String.raw`\bnie\b|n.mero de identidad de extranjero|num.ro d.identit. d..tranger|foreigner (?:identity|identification|id) number`,
  String.raw`([xyz]-?[0-9]{7}-?[a-z])`,
);

/**
 * Code fiscal italien : 6 lettres (nom, prénom), année, lettre du mois, jour, lettre et 3 chiffres de la commune,
 * lettre de contrôle ; les chiffres peuvent être remplacés par les lettres L à V (homonymes).
 */
const IT_FISCAL_CODE_BODY = announced(
  String.raw`codice fiscale|code fiscal italien|italian (?:fiscal|tax) code`,
  String.raw`([a-z]{6}[0-9lmnp-v]{2}[a-ehlmpr-t][0-9lmnp-v]{2}[a-z][0-9lmnp-v]{3}[a-z])`,
);

/** Numéro de TVA italien (partita IVA) : 11 chiffres, « IT » admis devant. */
const IT_VAT_BODY = announced(String.raw`partita iva|\bp\.? ?iva|tva italienne|italian vat`, String.raw`(?:it)?([0-9]{11})`);

/** Identifiant fiscal allemand (Steuer-ID, IdNr) : 11 chiffres, écrits d'un bloc ou « 12 345 678 901 ». */
const DE_TAX_ID_BODY = announced(
  String.raw`steuer-?id(?:nr)?|steueridentifikationsnummer|steuerliche identifikationsnummer|\bidnr|identifiant fiscal allemand|german tax id(?:entification)?`,
  String.raw`([1-9][0-9](?: ?[0-9]{3}){3})`,
);

/** Numéro de TVA allemand (USt-IdNr.) : « DE » et 9 chiffres. */
const DE_VAT_BODY = announced(
  String.raw`ust-?id(?:nr)?|umsatzsteuer-?id(?:entifikationsnummer)?|tva allemande|german vat`,
  String.raw`(de ?[0-9]{9})`,
);

/** PESEL polonais : 11 chiffres ; le mot « PESEL » est le même en français et en anglais. */
const PL_PESEL_BODY = announced(String.raw`\bpesel`, String.raw`([0-9]{11})`);

/** Numéro NHS britannique : 10 chiffres, écrits d'un bloc ou 3-3-4. */
const UK_NHS_BODY = announced(String.raw`\bnhs\b|national health service`, String.raw`([0-9]{3}[ -]?[0-9]{3}[ -]?[0-9]{4})`);

/** Personnummer (ou samordningsnummer) suédois : 10 ou 12 chiffres, « - » ou « + » avant les quatre derniers. */
const SE_PERSONNUMMER_BODY = announced(
  String.raw`personnummer|samordningsnummer|personal identity number|num.ro personnel su.dois|swedish personal (?:identity|id) number`,
  String.raw`((?:[0-9]{2})?[0-9]{6}[-+]?[0-9]{4})`,
);

/** Identifiant personnel finlandais (henkilötunnus) : date, séparateur du siècle, 3 chiffres, caractère de contrôle. */
const FI_HETU_BODY = announced(
  String.raw`\bhetu\b|henkil.tunnus|personbeteckning|personal identity code|identifiant personnel finlandais|finnish personal (?:identity|id) code`,
  String.raw`([0-9]{6}[-+a-fu-y][0-9]{3}[0-9a-y])`,
);

/**
 * Numéro de TVA intracommunautaire français : « FR », clé de deux chiffres, SIREN ; espaces admis après la clé et entre
 * les groupes du SIREN. Sans mot-clé : le préfixe et les deux contrôles (clé, Luhn du SIREN) suffisent. Une clé à
 * lettres (numéros récents) ne se calcule pas : elle n'est pas reconnue. Le premier chiffre de la clé est écrit à part :
 * la porte littérale est « FR0 » à « FR9 ».
 */
const FR_VAT_PATTERN = String.raw`\bFR[0-9][0-9] ?[0-9]{3} ?[0-9]{3} ?[0-9]{3}\b`;

/** RIB : après « RIB », « relevé d'identité bancaire », « coordonnées bancaires » ou « bank account details » ; banque, guichet, compte, clé. */
const FR_RIB_BODY =
  String.raw`(?:\brib\b|relev. d.identit. bancaire|coordonn.es bancaires|bank account details)${LINK}` +
  String.raw`([0-9]{5}[ -]?[0-9]{5}[ -]?[0-9a-z]{11}[ -]?[0-9]{2})`;

/**
 * Plaque d'immatriculation française (format de 2009 : deux lettres, trois chiffres, deux lettres, sans I, O ni U),
 * en majuscules, après « immatricul… », « plaque », « plate » ou « registration » à 30 caractères au plus sans
 * chiffre. Aucune clé de contrôle n'existe : le contexte seul la distingue d'une référence. Casses écrites une à une
 * (le motif ne replie pas la casse : « de 100 km » n'est pas une plaque).
 */
const FR_LICENSE_PLATE_PATTERN =
  String.raw`\b(?:Immatricul|Plaque|Plate|Registration|immatricul|plaque|plate|registration|IMMATRICUL|PLAQUE|PLATE|REGISTRATION)[^\n0-9]{0,30}?` +
  String.raw`\b([A-HJ-NP-TV-Z]{2}[ -]?[0-9]{3}[ -]?[A-HJ-NP-TV-Z]{2})\b`;

/** Un mot en toute casse, lettre par lettre (« [rR][uU][eE] ») : écriture de la lecture de référence en JavaScript. */
const anyCase = (word: string): string => [...word].map((c) => (/[a-z]/.test(c) ? `[${c}${c.toUpperCase()}]` : c)).join('');

/** Types de voie d'une adresse postale française (liste fermée ; « all.e » : allée). */
const STREET_TYPES = ['rue', 'avenue', 'boulevard', 'chemin', 'impasse', 'all.e', 'place', 'quai', 'route', 'cours', 'square', 'passage', 'faubourg', 'sentier'];

/** Mot d'un nom de commune : majuscule initiale, lettres, apostrophe, tiret (« Choisy-le-Roi », « L'Haÿ-les-Roses »). */
const TOWN_WORD = String.raw`[A-ZÀ-Ý][A-Za-zà-ÿ'’-]+`;

/**
 * Adresse postale française : numéro (« bis », « ter » admis), type de voie en liste fermée, nom de la voie, puis code
 * postal à cinq chiffres et commune, sur la même ligne ou la suivante. Règle « à activer ». Seuls « bis », « ter » et
 * le type de voie replient la casse (la commune garde sa majuscule) : `(?i:…)` pour RE2, dont la porte littérale est
 * alors la liste des types de voie ; lettre par lettre pour JavaScript (`anyCase`), où une classe « [sS] » ne retirerait
 * rien, mais que RE2 ne lit pas comme un littéral replié (« s » se replie aussi sur U+017F).
 */
const postalAddress = (fold: (words: readonly string[]) => string): string =>
  String.raw`\b([0-9]{1,4}(?: ?${fold(['bis', 'ter'])})?,? ${fold(STREET_TYPES)} [^\n]{1,60}?,?[ \n]` +
  String.raw`[0-9]{5} ${TOWN_WORD}(?:[ -]${TOWN_WORD}){0,3})`;
const FR_POSTAL_ADDRESS: ContextPattern = {
  pattern: postalAddress((words) => `(?i:${words.join('|')})`),
  reference: { source: postalAddress((words) => `(?:${words.map(anyCase).join('|')})`), flags: 'dg' },
};

/** Fenêtre, en octets, entre un identifiant de clé d'accès AWS et la valeur de 40 caractères qui l'accompagne. */
export const AWS_PAIR_WINDOW_BYTES = 200;

/**
 * Règle composée AWS : un identifiant de clé d'accès (AKIA, ASIA) et, dans la fenêtre, une valeur de 40 caractères de
 * base64. Le motif du Pack décrit la forme « identifiant, puis valeur » ; le moteur Go exécute à sa place une famille
 * qui lui est propre (`detect/awspair.go`) : les deux ordres, valeur bornée, ni empreinte hexadécimale ni valeur sans
 * minuscule, majuscule et chiffre. Idée du secret en plusieurs parties de TruffleHog (AGPL-3.0) : aucune ligne
 * reprise, détail dans UPSTREAM.md.
 */
const AWS_PAIR_PATTERN = String.raw`\b((?:AKIA|ASIA)[A-Z2-7]{16}\b(?:.|\n){0,199}?[^A-Za-z0-9+/][A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|$)`;

/**
 * Lecture de référence de la règle composée AWS (seconde écriture, indépendante de `detect/awspair.go`) : étendues
 * [début, fin) en unités UTF-16, de l'identifiant à la valeur. Pour chaque identifiant, la valeur la plus proche qui
 * le suit dans la fenêtre, sinon la plus proche qui le précède.
 */
export function awsPairSpans(text: string): [number, number][] {
  const distance = (from: number, to: number): number => Buffer.byteLength(text.slice(from, to), 'utf8');
  const secrets = [...text.matchAll(/[A-Za-z0-9+/]+/g)]
    .filter(([run]) => run.length === 40 && !/^[0-9A-Fa-f]+$/.test(run) && /[a-z]/.test(run) && /[A-Z]/.test(run) && /[0-9]/.test(run))
    .map((match): [number, number] => [match.index, match.index + 40]);
  const spans: [number, number][] = [];
  for (const id of text.matchAll(/\b(?:AKIA|ASIA)[A-Z2-7]{16}\b/g)) {
    const [start, end] = [id.index, id.index + id[0].length];
    const after = secrets.find((secret) => secret[0] >= end && distance(end, secret[0]) <= AWS_PAIR_WINDOW_BYTES);
    const before = secrets.findLast((secret) => secret[1] <= start && distance(secret[1], start) <= AWS_PAIR_WINDOW_BYTES);
    if (after !== undefined) spans.push([start, after[1]]);
    else if (before !== undefined) spans.push([before[0], end]);
  }
  return spans;
}

/** Règle de données à contexte : règle du Pack, libellé de Substitut (français, anglais), activation. */
export interface ContextRule {
  readonly rule: RulePackRule;
  readonly labelFr: string;
  readonly labelEn: string;
  /**
   * Vrai : règle « à activer ». Le moteur ne l'exécute que si l'appelant la nomme (`detect.LoadRulesWithOptIn`), parce
   * qu'elle se déclenche sur des textes ordinaires du corpus de bruit (`vectors/noise.json`).
   */
  readonly optIn: boolean;
  /** Le même motif pour le moteur d'expressions de JavaScript (lecture de référence) : source et drapeaux. */
  readonly reference: { readonly source: string; readonly flags: string };
  /**
   * Lecture de référence écrite à la main, à la place de l'exécution du motif : règle dont le moteur Go porte la
   * logique (règle composée AWS). Étendues [début, fin) en unités UTF-16.
   */
  readonly scan?: (text: string) => readonly (readonly [number, number])[];
}

/** Motif d'une règle et son écriture pour la lecture de référence. */
interface ContextPattern {
  readonly pattern: string;
  readonly reference: { readonly source: string; readonly flags: string };
}

/** Motif sensible à la casse : le même texte pour RE2 et pour JavaScript. */
const exact = (pattern: string): ContextPattern => ({ pattern, reference: { source: pattern, flags: 'dg' } });

/**
 * Motif qui replie la casse, fini par une limite de mot : `(?i:corps)\b` pour RE2, le corps sous le drapeau `i` pour
 * JavaScript (Node 26.0 n'applique pas un repli écrit `(?i:…)` à toutes les branches d'une alternance capturée).
 */
const folded = (body: string): ContextPattern => ({ pattern: `(?i:${body})\\b`, reference: { source: `${body}\\b`, flags: 'dgi' } });

function contextRule(
  ruleId: string,
  secretType: RuleSecretType,
  score: number,
  pattern: ContextPattern,
  labelFr: string,
  labelEn: string,
  optIn = false,
  validator: RuleValidator = '',
  scan?: ContextRule['scan'],
): ContextRule {
  return {
    rule: { ruleId, family: 'fixed_pattern', secretType, score, validator, pattern: pattern.pattern, minLength: 0, maxLength: 0 },
    labelFr,
    labelEn,
    optIn,
    reference: pattern.reference,
    ...(scan === undefined ? {} : { scan }),
  };
}

/** Règle d'identifiant à somme de contrôle : règle de données à contexte dont la valeur passe un validateur nommé. */
function checkedRule(
  ruleId: string,
  secretType: RuleSecretType,
  score: number,
  pattern: ContextPattern,
  validator: RuleValidator,
  labelFr: string,
  labelEn: string,
): ContextRule {
  return contextRule(ruleId, secretType, score, pattern, labelFr, labelEn, false, validator);
}

/**
 * Règles de données à contexte, dans l'ordre du Pack (après les règles de fournisseurs). Scores (niveau) : cryptogramme
 * 70 et passeport 60 (HIGH, comme la carte et le NIR), code à usage unique 45, adresse électronique, téléphone, adresse
 * IP interne, ARN, bucket S3 et point d'accès RDS 30, point d'accès DynamoDB 25 (MEDIUM : une adresse de région,
 * publique) ; clé d'accès partagé Azure 95 (CRITICAL, comme `azure_storage_key`).
 *
 * `email_address` est « à activer » : une adresse annoncée par son champ (`email: …`) est courante dans les jeux
 * d'essai et la configuration d'un dépôt (78 constats sur 58 Mo de quatre dépôts réels le 14 novembre 2026, aucun pour
 * les autres règles personnelles hors des cas d'essai de ce dépôt).
 */
export const CONTEXT_RULE_SOURCES: readonly ContextRule[] = [
  contextRule('email_address', 'email_address', 30, folded(EMAIL_BODY), 'adresse électronique', 'email address', true),
  contextRule('phone_number', 'phone_number', 30, exact(PHONE_PATTERN), 'numéro de téléphone', 'phone number'),
  contextRule('passport_number', 'passport_number', 60, folded(PASSPORT_BODY), 'numéro de passeport', 'passport number'),
  contextRule('payment_card_security_code', 'payment_card_security_code', 70, folded(CARD_CODE_BODY), 'cryptogramme de carte bancaire', 'payment card security code'),
  contextRule('one_time_code', 'one_time_code', 45, folded(ONE_TIME_CODE_BODY), 'code à usage unique', 'one-time code'),
  contextRule('azure_shared_access_key', 'cloud_credential', 95, exact(AZURE_SHARED_ACCESS_KEY_PATTERN), 'clé d’accès partagé Azure', 'Azure shared access key'),
  contextRule('internal_ip_address', 'internal_ip_address', 30, folded(INTERNAL_IP_BODY), 'adresse IP interne', 'internal IP address'),
  contextRule('aws_arn', 'cloud_resource_address', 30, exact(AWS_ARN_PATTERN), 'ARN AWS', 'AWS ARN'),
  contextRule('aws_s3_bucket', 'cloud_resource_address', 30, exact(AWS_S3_PATTERN), 'adresse de bucket S3', 'S3 bucket address'),
  contextRule('aws_rds_endpoint', 'cloud_resource_address', 30, exact(AWS_RDS_PATTERN), 'adresse de base RDS', 'RDS endpoint'),
  contextRule('aws_dynamodb_endpoint', 'cloud_resource_address', 25, exact(AWS_DYNAMODB_PATTERN), 'adresse DynamoDB', 'DynamoDB endpoint'),
  // Identifiants européens à somme de contrôle (v0.10.0), portés de Presidio : identifiant d'une personne 60 (HIGH,
  // comme le NIR), numéro de TVA d'une entreprise 35 (MEDIUM, donnée publique, comme le SIRET).
  checkedRule('es_nif', 'national_identifier', 60, folded(ES_NIF_BODY), 'es_nif_mod23', 'numéro d’identité espagnol', 'Spanish identity number'),
  checkedRule('es_nie', 'national_identifier', 60, folded(ES_NIE_BODY), 'es_nie_mod23', 'numéro d’étranger espagnol', 'Spanish foreigner identity number'),
  checkedRule('it_fiscal_code', 'national_identifier', 60, folded(IT_FISCAL_CODE_BODY), 'it_fiscal_code_check', 'code fiscal italien', 'Italian fiscal code'),
  checkedRule('it_vat', 'vat_number', 35, folded(IT_VAT_BODY), 'it_vat_luhn', 'numéro de TVA italien', 'Italian VAT number'),
  checkedRule('de_tax_id', 'national_identifier', 60, folded(DE_TAX_ID_BODY), 'de_tax_id_iso7064', 'identifiant fiscal allemand', 'German tax identification number'),
  checkedRule('de_vat', 'vat_number', 35, folded(DE_VAT_BODY), 'de_vat_iso7064', 'numéro de TVA allemand', 'German VAT number'),
  checkedRule('pl_pesel', 'national_identifier', 60, folded(PL_PESEL_BODY), 'pl_pesel_check', 'numéro PESEL', 'PESEL number'),
  checkedRule('uk_nhs', 'national_identifier', 60, folded(UK_NHS_BODY), 'uk_nhs_mod11', 'numéro NHS', 'NHS number'),
  checkedRule('se_personnummer', 'national_identifier', 60, folded(SE_PERSONNUMMER_BODY), 'se_personnummer_luhn', 'numéro personnel suédois', 'Swedish personal identity number'),
  checkedRule('fi_personal_identity_code', 'national_identifier', 60, folded(FI_HETU_BODY), 'fi_hetu_mod31', 'identifiant personnel finlandais', 'Finnish personal identity code'),
  // Identifiants français absents de Presidio (v0.10.0) : TVA 35 (donnée publique), RIB 45 (comme l'IBAN), plaque et
  // adresse postale 30. L'adresse postale est « à activer » : une adresse d'entreprise est courante dans un pied de
  // page, une facture ou un jeu d'essai.
  checkedRule('fr_vat', 'vat_number', 35, exact(FR_VAT_PATTERN), 'fr_vat_key', 'numéro de TVA intracommunautaire', 'French VAT number'),
  checkedRule('fr_rib', 'bank_account_number', 45, folded(FR_RIB_BODY), 'fr_rib_key', 'relevé d’identité bancaire', 'French bank account details'),
  contextRule('fr_license_plate', 'vehicle_registration_plate', 30, exact(FR_LICENSE_PLATE_PATTERN), 'plaque d’immatriculation', 'vehicle registration plate'),
  contextRule('fr_postal_address', 'postal_address', 30, FR_POSTAL_ADDRESS, 'adresse postale', 'postal address', true),
  // Règle composée (v0.10.0) : identifiant de clé AWS et valeur de 40 caractères dans la même fenêtre, 95 (CRITICAL).
  // L'identifiant seul reste à `aws_access_key_id`, 45 (MEDIUM).
  contextRule('aws_access_key_pair', 'cloud_credential', 95, exact(AWS_PAIR_PATTERN), 'paire de clés d’accès AWS', 'AWS access key pair', false, '', awsPairSpans),
];

/** Règles « à activer », dans l'ordre du Pack (`detect.OptInRuleIDs`). */
export const CONTEXT_OPT_IN_RULE_IDS: readonly string[] = CONTEXT_RULE_SOURCES.filter((source) => source.optIn).map((source) => source.rule.ruleId);

/** Règles du Pack, dans l'ordre. */
export const CONTEXT_DATA_RULES: readonly RulePackRule[] = CONTEXT_RULE_SOURCES.map((source) => source.rule);

/** Étendue d'une valeur trouvée par la lecture de référence (indices UTF-16 du texte). */
export interface ContextMatch {
  readonly rule: RulePackRule;
  readonly start: number;
  readonly end: number;
}

/**
 * Lecture de référence : chaque motif exécuté par le moteur d'expressions de JavaScript (seconde exécution,
 * indépendante de RE2 et du moteur Go) ; la valeur est le premier groupe capturant s'il a participé, sinon la
 * correspondance entière. La syntaxe des motifs est commune aux deux moteurs, au repli de casse près (`folded`). À
 * n'utiliser que sur un texte sans U+212A ni U+017F (que RE2 replie sur « k » et « s ») ni fin de ligne autre que
 * « \n » (« . » de JavaScript).
 */
export function contextReferenceFindings(text: string): ContextMatch[] {
  const found: ContextMatch[] = [];
  for (const { rule, reference, scan } of CONTEXT_RULE_SOURCES) {
    if (scan !== undefined) {
      for (const [start, end] of scan(text)) found.push({ rule, start, end });
      continue;
    }
    // Validateur nommé (v0.10.0) : seconde écriture de `personal-data.ts`, appliquée à la valeur.
    const check = rule.validator === '' ? undefined : REFERENCE_VALIDATORS[rule.validator];
    if (rule.validator !== '' && check === undefined) throw new Error(`validateur de référence absent : ${rule.validator}`);
    for (const match of text.matchAll(new RegExp(reference.source, reference.flags))) {
      const [start, end] = match.indices?.[1] ?? match.indices?.[0] ?? [0, 0];
      if (end > start && (check === undefined || check(text.slice(start, end)))) found.push({ rule, start, end });
    }
  }
  return found;
}

function goString(text: string): string {
  return JSON.stringify(text).replace(/[\u007f-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

/**
 * Source Go des règles de données à contexte (`detect/context_rules.go`) : libellés de Substitut et règles « à
 * activer », écrite avec le Pack par `npm run pack:initial`.
 */
export function buildContextRulesGo(): string {
  const lines = CONTEXT_RULE_SOURCES.map((source) => `\t{${goString(source.rule.ruleId)}, ${goString(source.labelFr)}, ${goString(source.labelEn)}},`);
  return [
    '// SPDX-License-Identifier: Apache-2.0',
    '',
    '// Code généré par generator/rule-pack/generate-initial-pack.ts (npm run pack:initial) ; ne pas modifier.',
    '',
    'package detect',
    '',
    '// contextSubstituteLabels : types de secret des règles de données à contexte du Pack initial (v0.9.0, puis',
    "// identifiants européens et français et règle composée AWS de la v0.10.0), dans l'ordre du Pack. Source :",
    '// generator/rule-pack/context-data.ts.',
    'var contextSubstituteLabels = []SubstituteLabel{',
    ...lines,
    '}',
    '',
    "// contextOptInRuleIDs : règles « à activer » (optin.go), dans l'ordre du Pack. Même source.",
    `var contextOptInRuleIDs = []string{${CONTEXT_OPT_IN_RULE_IDS.map(goString).join(', ')}}`,
    '',
  ].join('\n');
}
