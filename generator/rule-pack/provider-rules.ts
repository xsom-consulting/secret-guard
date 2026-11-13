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

/** Règles de fournisseurs, dans l'ordre du Pack (après les règles de données personnelles). */
export const PROVIDER_RULES: readonly RulePackRule[] = PROVIDER_RULE_SOURCES.map((rule) => ({
  ruleId: rule.ruleId,
  family: 'fixed_pattern',
  secretType: PROVIDER_SECRET_TYPE,
  score: rule.score,
  validator: '',
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
 * Lecture de référence : chaque motif exécuté par le moteur d'expressions de JavaScript (seconde exécution,
 * indépendante de RE2 et du moteur Go). La syntaxe des motifs est commune aux deux moteurs (groupes à drapeaux
 * `(?i:…)`, `(?s:…)`, `(?-m:…)` compris) ; la valeur est le premier groupe capturant s'il a participé, sinon la
 * correspondance entière. À n'utiliser que sur un texte ASCII (repliements de casse et classes identiques).
 */
export function providerReferenceFindings(text: string): ProviderMatch[] {
  const found: ProviderMatch[] = [];
  for (const rule of PROVIDER_RULE_SOURCES) {
    for (const match of text.matchAll(new RegExp(rule.pattern, 'dg'))) {
      const [start, end] = match.indices?.[1] ?? match.indices?.[0] ?? [0, 0];
      if (end > start) found.push({ rule, start, end });
    }
  }
  return found;
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
