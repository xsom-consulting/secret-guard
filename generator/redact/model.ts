/**
 * Vecteurs du masquage (`vectors/redact.json`) et des niveaux et décisions (`vectors/decision.json`) : forme et
 * listes fermées. Lus tels quels par les tests Go `TestRedactParity` et `TestDecisionParity` (`detect/`) ; tout champ
 * ajouté ici change ces tests.
 */
import type { CorpusExpected, InputEncoding } from '../corpus/model.ts';

/** Version du format des deux fichiers. */
export const REDACT_FORMAT_VERSION = 1;

/** Fichiers écrits, relatifs à `vectors/`. */
export const REDACT_FILE = 'redact.json';
export const DECISION_FILE = 'decision.json';

/**
 * Issue du masquage suivi d'une nouvelle analyse (`redactAndRescan`) : `none` (texte rendu), `incomplete` (analyse
 * initiale ou finale incomplète), `residual` (constat après masquage). Seule `none` rend un texte.
 */
export const SANITIZE_FAILURES = ['none', 'incomplete', 'residual'] as const;
export type SanitizeFailure = (typeof SANITIZE_FAILURES)[number];

/** Texte masqué écrit en clair jusqu'à cette taille, en octets ; au-delà, seuls sa taille et son SHA-256. */
export const INLINE_TEXT_MAX_BYTES = 16_384;

/** Texte masqué : taille et SHA-256 de ses octets, et le texte lui-même s'il est court. */
export interface RedactedText {
  readonly bytes: number;
  readonly sha256: string;
  readonly text?: string;
  readonly textEncoding?: InputEncoding;
}

/** Constat construit à la main pour `redact` : identité, score, étendue en octets du contenu (fin exclue). */
export interface SpanFinding {
  readonly ruleId: string;
  readonly score: number;
  readonly byteStart: number;
  readonly byteEnd: number;
}

/** Cas de `redact` seul, sur des constats construits à la main (fusion, ordre, nommage). */
export interface SpanCase {
  readonly id: string;
  readonly content: string;
  readonly contentEncoding: InputEncoding;
  readonly findings: readonly SpanFinding[];
  readonly redacted: RedactedText;
}

/** Préfixe répété devant `input` : l'entrée est `text` répété `count` fois, puis `input` (entrées de 1 Mio). */
export interface RepeatedPrefix {
  readonly text: string;
  readonly count: number;
}

/**
 * Résultat attendu de `redactAndRescan`. `initial` : analyse de l'entrée (absent pour un cas du corpus de parité :
 * c'est le `expected` du cas, vérifié égal par le générateur). `redacted` : texte de `redact` sur les constats
 * initiaux (null si l'analyse initiale est incomplète), rendu seulement si `failure` vaut `none`. `final` : analyse
 * du texte masqué (null si l'analyse initiale est incomplète).
 */
export interface RedactExpected {
  readonly failure: SanitizeFailure;
  readonly initial?: CorpusExpected;
  readonly redacted: RedactedText | null;
  readonly final: CorpusExpected | null;
}

/**
 * Cas de `redactAndRescan` : renvoi vers un cas du corpus de parité (`corpusFile`, même `id`, entrée et langage du
 * corpus), ou entrée synthétique (`input`, `inputEncoding`, `repeat` facultatif, `languageId` facultatif).
 */
export interface RedactCase {
  readonly id: string;
  readonly corpusFile?: string;
  readonly input?: string;
  readonly inputEncoding?: InputEncoding;
  readonly repeat?: RepeatedPrefix;
  readonly languageId?: string;
  readonly expected: RedactExpected;
}

/** Fichier `vectors/redact.json`. */
export interface RedactVectors {
  readonly formatVersion: number;
  readonly upstreamCommit: string;
  readonly spanCases: readonly SpanCase[];
  readonly cases: readonly RedactCase[];
}

/** Niveau et décision de Secret Guard pour un score entier. */
export interface ScoreVector {
  readonly score: number;
  readonly bounded: number;
  readonly level: string;
}

/** Décision par défaut d'un niveau (`decisionForLevel`). */
export interface LevelVector {
  readonly level: string;
  readonly decision: string;
}

/** Fichier `vectors/decision.json`. */
export interface DecisionVectors {
  readonly formatVersion: number;
  readonly upstreamCommit: string;
  readonly scores: readonly ScoreVector[];
  readonly levels: readonly LevelVector[];
}

/** Scores éprouvés : entiers de -5 à 105 (bornes, seuils et au-delà). */
export const SCORE_RANGE = { from: -5, to: 105 } as const;

/** Niveaux de Secret Guard, dans l'ordre. */
export const LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;

/** Décisions de Secret Guard. */
export const DECISIONS = ['ALLOW', 'WARN', 'BLOCK'] as const;
