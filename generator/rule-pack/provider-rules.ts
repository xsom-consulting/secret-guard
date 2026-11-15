// SPDX-License-Identifier: Apache-2.0
/**
 * Règles de fournisseurs du Pack initial (v0.8.1) : jetons, clés d'API et webhooks de fournisseurs, reconnus par un
 * préfixe fixe (score 95) ou par le nom du fournisseur à proximité de la valeur (score 80). Extension propre à ce
 * dépôt, sans origine dans Secret Guard : ces règles viennent après les règles de données personnelles.
 *
 * Origine des motifs : règles de détection de Titus (praetorian-inc/titus, `pkg/rule/rules/`, Apache-2.0), elles-mêmes
 * dérivées de NoseyParker (Praetorian, identifiants `np.*`) et de Kingfisher (MongoDB, identifiants `kingfisher.*`),
 * toutes deux sous Apache-2.0 (avis dans NOTICE, détail et modifications dans UPSTREAM.md). Chaque règle garde
 * l'identifiant de sa règle d'origine (`upstream`). Les motifs sont écrits en RE2 dans `provider-rules.json`, une
 * règle par ligne : ce fichier est la source, entretenue à la main depuis la reprise. Rien n'y est traduit par
 * `js-to-re2.ts`.
 *
 * Chaque règle est une règle « motif seul » (`fixed_pattern`) : le moteur l'exécute telle que le Pack la décrit, la
 * valeur détectée est son unique groupe capturant. Son libellé de Substitut (français, anglais) est écrit avec le
 * Pack dans `detect/substitute_providers.go`.
 *
 * `sample` décrit une valeur synthétique du motif (littéraux, puis caractères tirés d'un alphabet par `synth`) et ce
 * qui doit l'entourer (`before`, `after`) ; `nearMiss`, la même valeur trop courte d'un caractère (ou réduite à ses
 * littéraux). Ils servent aux cas du corpus (`corpus/provider-rules.ts`) : jamais une valeur relevée.
 */
import type { RulePackRule } from '../src/rule-pack.ts';
import data from './provider-rules.json' with { type: 'json' };

/** Morceau d'une valeur synthétique : littéral, ou `length` caractères tirés de `alphabet`. */
export type SamplePart = { readonly lit: string } | { readonly alphabet: string; readonly length: number };

export interface ProviderSample {
  readonly before: readonly SamplePart[];
  readonly value: readonly SamplePart[];
  readonly after: readonly SamplePart[];
  readonly nearMiss: readonly SamplePart[];
}

export interface ProviderRule {
  readonly ruleId: string;
  /** Identifiant de la règle d'origine dans Titus (`np.*` : NoseyParker ; `kingfisher.*` : Kingfisher ; `titus.*`). */
  readonly upstream: string;
  /** Type de secret écrit dans un Substitut, en français et en anglais. */
  readonly labelFr: string;
  readonly labelEn: string;
  /** 95 : préfixe fixe ; 80 : nom du fournisseur à proximité. */
  readonly score: number;
  /**
   * Validateur de vraisemblance `token_entropy_NN` (entropie minimale de la valeur, en dixièmes de bit par octet) ;
   * absent : le seuil d'office du type (`PROVIDER_ENTROPY_FLOOR`). Porté par les règles à proximité (score 80).
   */
  readonly validator?: string;
  /** Motif RE2 ; la valeur détectée est son unique groupe capturant (la correspondance entière s'il n'en a pas). */
  readonly pattern: string;
  readonly sample: ProviderSample;
}

/** Commit de Titus dont les règles sont reprises (`pkg/rule/rules/`, 318 fichiers). */
export const PROVIDER_UPSTREAM_REPOSITORY = 'praetorian-inc/titus';
export const PROVIDER_UPSTREAM_COMMIT = 'b3964d4352ac2f84af11d1396e864bdc772f2b92';

export const PROVIDER_RULE_SOURCES: readonly ProviderRule[] = data as readonly ProviderRule[];

/** Type de secret des règles de fournisseurs. */
export const PROVIDER_SECRET_TYPE = 'provider_token';

/**
 * Vraisemblance d'un jeton de fournisseur (v0.10.0) : une valeur de moins de `PROVIDER_MIN_DISTINCT` octets distincts,
 * ou d'entropie de Shannon inférieure au seuil de sa règle, n'est pas un constat. Seuil d'office du type :
 * `PROVIDER_ENTROPY_FLOOR` dixièmes de bit par octet ; une règle peut en porter un autre par un validateur nommé
 * `token_entropy_NN`. Seconde écriture du contrôle du moteur Go (`detect/validators.go`, `plausibleToken`).
 */
export const PROVIDER_MIN_DISTINCT = 6;
export const PROVIDER_ENTROPY_FLOOR = 30;
const ENTROPY_VALIDATOR = /^token_entropy_([0-9]{2})$/;

/** Seuil d'entropie d'une règle, en dixièmes de bit par octet. */
export function providerEntropyFloor(rule: Pick<ProviderRule, 'ruleId' | 'validator'>): number {
  if (rule.validator === undefined) return PROVIDER_ENTROPY_FLOOR;
  const named = ENTROPY_VALIDATOR.exec(rule.validator);
  if (named === null) throw new Error(`${rule.ruleId} : validateur de vraisemblance inconnu`);
  return Number(named[1]);
}

/**
 * Diversité d'une valeur ASCII : nombre de caractères distincts et entropie de Shannon, fréquences sommées dans
 * l'ordre des codes de caractère (comme le moteur Go dans l'ordre des octets).
 */
export function tokenDiversity(value: string): { distinct: number; entropy: number } {
  const counts = new Array<number>(256).fill(0);
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code > 0x7f) throw new Error('vraisemblance : valeur hors ASCII');
    counts[code] = (counts[code] ?? 0) + 1;
  }
  let distinct = 0;
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    distinct += 1;
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return { distinct, entropy };
}

/** Vrai si la valeur a la diversité d'un jeton pour ce seuil (dixièmes de bit par octet). */
export function plausibleToken(value: string, floor: number): boolean {
  const { distinct, entropy } = tokenDiversity(value);
  return distinct >= PROVIDER_MIN_DISTINCT && entropy >= floor / 10;
}

/** Règles de fournisseurs, dans l'ordre du Pack (après les règles de données personnelles). */
export const PROVIDER_RULES: readonly RulePackRule[] = PROVIDER_RULE_SOURCES.map((rule) => ({
  ruleId: rule.ruleId,
  family: 'fixed_pattern',
  secretType: PROVIDER_SECRET_TYPE,
  score: rule.score,
  validator: rule.validator ?? '',
  pattern: rule.pattern,
  minLength: 0,
  maxLength: 0,
}));

/** Étendue d'une valeur trouvée par la lecture de référence (indices du texte). */
export interface ProviderMatch {
  readonly rule: ProviderRule;
  readonly start: number;
  readonly end: number;
}

/**
 * Correspondances brutes des motifs, sans le contrôle de vraisemblance : chaque motif exécuté par le moteur
 * d'expressions de JavaScript (seconde exécution, indépendante de RE2 et du moteur Go). La syntaxe des motifs est
 * commune aux deux moteurs (groupes à drapeaux `(?i:…)`, `(?s:…)`, `(?-m:…)` compris) ; la valeur est le premier
 * groupe capturant s'il a participé, sinon la correspondance entière. À n'utiliser que sur un texte ASCII
 * (repliements de casse et classes identiques).
 */
export function providerPatternMatches(text: string): ProviderMatch[] {
  const found: ProviderMatch[] = [];
  for (const rule of PROVIDER_RULE_SOURCES) {
    for (const match of text.matchAll(new RegExp(rule.pattern, 'dg'))) {
      const [start, end] = match.indices?.[1] ?? match.indices?.[0] ?? [0, 0];
      if (end > start) found.push({ rule, start, end });
    }
  }
  return found;
}

/**
 * Lecture de référence : les correspondances brutes dont la valeur a la diversité d'un jeton pour le seuil de sa
 * règle (`plausibleToken`).
 */
export function providerReferenceFindings(text: string): ProviderMatch[] {
  return providerPatternMatches(text).filter((found) => plausibleToken(text.slice(found.start, found.end), providerEntropyFloor(found.rule)));
}

function goString(text: string): string {
  return JSON.stringify(text).replace(/[\u007f-￿]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

/**
 * Source Go des libellés de Substitut des règles de fournisseurs (`detect/substitute_providers.go`), écrite avec le
 * Pack par `npm run pack:initial`.
 */
export function buildProviderLabelsGo(): string {
  const lines = PROVIDER_RULE_SOURCES.map((rule) => `\t{${goString(rule.ruleId)}, ${goString(rule.labelFr)}, ${goString(rule.labelEn)}},`);
  return [
    '// SPDX-License-Identifier: Apache-2.0',
    '',
    '// Code généré par generator/rule-pack/generate-initial-pack.ts (npm run pack:initial) ; ne pas modifier.',
    '',
    'package detect',
    '',
    '// providerSubstituteLabels : types de secret des règles de fournisseurs du Pack initial (v0.8.1), dans l\'ordre du',
    '// Pack. Source : generator/rule-pack/provider-rules.json.',
    'var providerSubstituteLabels = []SubstituteLabel{',
    ...lines,
    '}',
    '',
  ].join('\n');
}
