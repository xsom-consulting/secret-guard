/**
 * Corpus de parité de détection : forme d'un cas et listes fermées. Le corpus est lu tel
 * quel par le test de parité Go ; tout champ ajouté ici change ce test.
 */

/** Taille maximale d'une entrée analysée, en octets UTF-8 (`MAX_INPUT_BYTES` de Secret Guard). */
export const MAX_INPUT_BYTES = 1_048_576;

/** Vues de texte de Secret Guard, valeur `encoding` d'un constat. */
export const FINDING_ENCODINGS = ['plain', 'normalized', 'percent', 'json-escaped', 'base64', 'whitespace-joined'] as const;
export type FindingEncoding = (typeof FINDING_ENCODINGS)[number];

/** Issue d'une analyse : `none` quand elle est complète. */
export const SCAN_FAILURES = ['none', 'scan_limit', 'scan_error'] as const;
export type ScanFailure = (typeof SCAN_FAILURES)[number];

/** Niveaux de risque de Secret Guard (`levelForScore`). */
export const RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

/** Écriture de l'entrée d'un cas : texte UTF-8 valide, sinon octets en base64 standard avec remplissage. */
export const INPUT_ENCODINGS = ['utf8', 'base64'] as const;
export type InputEncoding = (typeof INPUT_ENCODINGS)[number];

/** Constat attendu : identité de la règle, score et étendue en octets de l'entrée ; jamais la valeur détectée. */
export interface CorpusFinding {
  readonly ruleId: string;
  readonly secretType: string;
  readonly encoding: FindingEncoding;
  readonly score: number;
  readonly level: RiskLevel;
  /** Début inclus, en octets UTF-8 depuis le début de l'entrée. */
  readonly byteStart: number;
  /** Fin exclue, en octets UTF-8. */
  readonly byteEnd: number;
}

export interface CorpusExpected {
  readonly complete: boolean;
  readonly failure: ScanFailure;
  /** Triés par `(byteStart, ruleId)`, puis `byteEnd` ; vide quand l'analyse échoue. */
  readonly findings: readonly CorpusFinding[];
}

/** Cas du corpus, tel qu'écrit dans un fichier `vectors/detection/<nom>.json`. */
export interface CorpusCase {
  readonly id: string;
  readonly input: string;
  readonly inputEncoding: InputEncoding;
  /** Langage déclaré par l'appelant (`languageId` de Secret Guard), absent sinon. */
  readonly languageId?: string;
  readonly expected: CorpusExpected;
}

/** Version du format du corpus, inscrite dans `manifest.json`. */
export const CORPUS_FORMAT_VERSION = 1;

/** Nom du manifeste, à côté des fichiers de cas. */
export const MANIFEST_FILE = 'manifest.json';

/**
 * Nom d'un fichier de cas : famille (`rules`, `views`, `edge`, `limits`, `upstream`), puis minuscules, chiffres et
 * tirets, extension `.json`. Même forme que l'exception de `.gitleaks.toml` (le manifeste n'y entre pas).
 */
export const CASE_FILE_PATTERN = /^(?:rules|views|edge|limits|upstream)(?:-[a-z0-9]+)*\.json$/;

/** Manifeste : nombre de cas par fichier (noms triés), et origine du résultat attendu. */
export interface CorpusManifest {
  readonly formatVersion: number;
  readonly upstreamCommit: string;
  readonly files: readonly { readonly file: string; readonly cases: number }[];
}

/** Niveau d'un score (copie de `levelForScore` de Secret Guard, `risk.ts`). */
export function levelForScore(score: number): RiskLevel {
  if (score >= 75) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 25) return 'MEDIUM';
  return 'LOW';
}

/**
 * Ordre des constats : `byteStart`, puis `ruleId` (comparaison de chaînes JavaScript ; identifiants ASCII), puis
 * `byteEnd`. Ordre total : la déduplication de Secret Guard fusionne tout constat qui en chevauche un autre.
 */
export function compareFindings(left: CorpusFinding, right: CorpusFinding): number {
  if (left.byteStart !== right.byteStart) return left.byteStart - right.byteStart;
  if (left.ruleId !== right.ruleId) return left.ruleId < right.ruleId ? -1 : 1;
  return left.byteEnd - right.byteEnd;
}
