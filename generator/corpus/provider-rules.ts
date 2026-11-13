// SPDX-License-Identifier: Apache-2.0
/**
 * Cas du corpus de parité pour les règles de fournisseurs (v0.8.1) : `vectors/detection/rules-providers.json`.
 *
 * Ces règles n'existent pas dans le moteur TypeScript d'origine. Le résultat attendu d'un cas réunit donc deux
 * lectures : celle du moteur d'origine (entropie, affectations…) et la lecture de référence des règles de
 * fournisseurs (`rule-pack/provider-rules.ts` : chaque motif exécuté par le moteur d'expressions de JavaScript, sans
 * RE2 ni le moteur Go), fusionnées comme `dedupeOverlaps` du moteur d'origine fusionne des constats qui se
 * chevauchent. Le générateur exige que le constat d'une règle de fournisseur soit le mieux classé de son groupe : un
 * cas où une règle d'origine l'emporterait doit être redessiné.
 *
 * Deux cas par règle : une valeur synthétique du motif (`sample.value`, caractères tirés de SHA-256 par `synth`,
 * jamais une valeur relevée), que la règle doit trouver à l'étendue construite ; la même valeur trop courte
 * (`sample.nearMiss`), que la règle ne doit pas trouver. Textes ASCII : octets et unités UTF-16 coïncident.
 */
import { byteOffsetOf, decodeInput, utf8Bytes } from './bytes.ts';
import { CorpusError, expectedFor, type CaseSource } from './corpus.ts';
import { compareFindings, levelForScore, type CorpusExpected, type CorpusFinding } from './model.ts';
import { synth, type CaseIntent } from './synthetic.ts';
import {
  PROVIDER_RULE_SOURCES,
  PROVIDER_SECRET_TYPE,
  providerReferenceFindings,
  type ProviderRule,
  type SamplePart,
} from '../rule-pack/provider-rules.ts';
import type { UpstreamEngine } from './upstream.ts';

/** Fichier du corpus qui porte ces cas (famille `rules`, couverte par l'exception de `.gitleaks.toml`). */
export const PROVIDER_RULES_FILE = 'rules-providers.json';

const BEFORE = 'noted value: ';
const AFTER = ' (end)\n';

/**
 * Cas négatif réduit aux littéraux de la valeur quand elle est une adresse (un littéral porte « / ») : trop courte
 * d'un caractère, elle garde la forme d'un chemin, que l'entropie du moteur Go écarte et pas celle du moteur d'origine
 * (écarts d'analyse des chemins, UPSTREAM.md). Ces textes n'auraient pas de résultat attendu commun.
 */
function literalOnlyNegative(rule: ProviderRule): boolean {
  return rule.sample.value.some((part) => 'lit' in part && part.lit.includes('/'));
}

function render(label: string, parts: readonly SamplePart[]): string {
  return parts.map((part, index) => ('lit' in part ? part.lit : synth(`${label}/${String(index)}`, part.alphabet, part.length))).join('');
}

/** Texte d'un cas et étendue construite de sa valeur. */
export function providerSampleText(rule: ProviderRule, kind: 'value' | 'nearMiss'): { text: string; start: number; end: number } {
  const label = `provider/${rule.ruleId}/${kind}`;
  const head = `${BEFORE}${render(`${label}/before`, rule.sample.before)}`;
  const literalOnly = kind === 'nearMiss' && literalOnlyNegative(rule);
  const value = render(`${label}/value`, literalOnly ? rule.sample.value.filter((part) => 'lit' in part) : rule.sample[kind]);
  return { text: `${head}${value}${render(`${label}/after`, rule.sample.after)}${AFTER}`, start: head.length, end: head.length + value.length };
}

/** Cas des règles de fournisseurs, dans l'ordre du Pack : un positif, puis un négatif par règle. */
export function providerRuleCases(): CaseSource[] {
  const cases: CaseSource[] = [];
  for (const rule of PROVIDER_RULE_SOURCES) {
    const positive: CaseIntent = { kind: 'positive', rule: rule.ruleId };
    const negative: CaseIntent = { kind: 'negative', rule: rule.ruleId };
    cases.push(
      { file: PROVIDER_RULES_FILE, id: `${rule.ruleId}/positive/sample`, bytes: utf8Bytes(providerSampleText(rule, 'value').text), intent: positive },
      { file: PROVIDER_RULES_FILE, id: `${rule.ruleId}/negative/near-miss`, bytes: utf8Bytes(providerSampleText(rule, 'nearMiss').text), intent: negative },
    );
  }
  return cases;
}

/** Constats des règles de fournisseurs par la lecture de référence (texte ASCII exigé). */
export function providerReference(bytes: Uint8Array): CorpusFinding[] {
  const decoded = decodeInput(bytes);
  if (!decoded.validUtf8 || !/^[\x00-\x7f]*$/.test(decoded.text)) throw new CorpusError('cas de fournisseur hors ASCII');
  return providerReferenceFindings(decoded.text).map((found) => ({
    ruleId: found.rule.ruleId,
    secretType: PROVIDER_SECRET_TYPE,
    encoding: 'plain',
    score: found.rule.score,
    level: levelForScore(found.rule.score),
    byteStart: byteOffsetOf(decoded, found.start),
    byteEnd: byteOffsetOf(decoded, found.end),
  }));
}

/** Rang de spécificité de `dedupeOverlaps` : règles ancrées, puis affectations, puis entropie. */
function specificity(finding: CorpusFinding): number {
  if (finding.ruleId === 'high_entropy') return 2;
  return finding.ruleId.startsWith('contextual_') ? 1 : 0;
}

/** Ordre de `String.prototype.localeCompare` sur des identifiants de règle (`_`, puis chiffres, puis lettres). */
function localeOrder(a: string, b: string): number {
  const weight = (c: string): number => (c >= '0' && c <= '9' ? 100 + c.charCodeAt(0) : c >= 'a' && c <= 'z' ? 200 + c.charCodeAt(0) : c.charCodeAt(0));
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) {
    const d = weight(a.charAt(i)) - weight(b.charAt(i));
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

/**
 * Fusion des constats de fournisseurs avec ceux du moteur d'origine : seconde écriture de `dedupeOverlaps`. Les
 * constats sont classés (spécificité, puis score, puis longueur, puis identifiant) ; chacun rejoint le premier constat
 * gardé qu'il chevauche, dont il élargit l'étendue, ou est gardé à son tour. Tous les constats sont de la vue
 * d'identité (erreur sinon : le cas doit être redessiné).
 */
export function mergeProviderFindings(id: string, upstream: readonly CorpusFinding[], providers: readonly CorpusFinding[]): CorpusFinding[] {
  type Mutable = { -readonly [K in keyof CorpusFinding]: CorpusFinding[K] };
  const all = [...upstream, ...providers];
  if (all.some((finding) => finding.encoding !== 'plain')) throw new CorpusError(`${id} : constat d’une autre vue, le cas doit être redessiné`);
  const length = (f: CorpusFinding): number => f.byteEnd - f.byteStart;
  const ranked = all
    .map((finding, index) => ({ finding, index }))
    .sort(
      (a, b) =>
        specificity(a.finding) - specificity(b.finding) ||
        b.finding.score - a.finding.score ||
        length(b.finding) - length(a.finding) ||
        localeOrder(a.finding.ruleId, b.finding.ruleId) ||
        a.index - b.index,
    );
  const kept: Mutable[] = [];
  for (const { finding } of ranked) {
    const host = kept.find((existing) => existing.byteStart < finding.byteEnd && finding.byteStart < existing.byteEnd);
    if (host === undefined) {
      kept.push({ ...finding });
      continue;
    }
    host.byteStart = Math.min(host.byteStart, finding.byteStart);
    host.byteEnd = Math.max(host.byteEnd, finding.byteEnd);
  }
  return kept.sort(compareFindings);
}

/** Résultat attendu d'un cas : constats du moteur d'origine et de la lecture de référence, fusionnés. */
export function providerRuleExpected(engine: UpstreamEngine, source: CaseSource): CorpusExpected {
  const upstream = expectedFor(engine, source.bytes, source.languageId);
  if (!upstream.complete) throw new CorpusError(`${source.id} : le moteur d’origine échoue sur ce texte, le cas doit être redessiné`);
  return { complete: true, failure: 'none', findings: mergeProviderFindings(source.id, upstream.findings, providerReference(source.bytes)) };
}

/**
 * Problèmes de couverture : chaque règle a son cas positif, où la lecture de référence trouve la valeur à l'étendue
 * construite, et son cas négatif, où elle ne la trouve pas.
 */
export function providerRuleCoverageProblems(
  cases: readonly { readonly id: string; readonly intent?: CaseIntent; readonly expected: CorpusExpected }[],
): string[] {
  const problems: string[] = [];
  const byId = new Map(cases.map((evaluated) => [evaluated.id, evaluated]));
  for (const rule of PROVIDER_RULE_SOURCES) {
    const positive = byId.get(`${rule.ruleId}/positive/sample`);
    const negative = byId.get(`${rule.ruleId}/negative/near-miss`);
    if (positive === undefined || negative === undefined) {
      problems.push(`règle de fournisseur sans ses deux cas : ${rule.ruleId}`);
      continue;
    }
    const { start, end } = providerSampleText(rule, 'value');
    const found = positive.expected.findings.filter((finding) => finding.ruleId === rule.ruleId);
    const [only] = found;
    if (found.length !== 1 || only === undefined || only.byteStart > start || only.byteEnd < end || only.score !== rule.score) {
      problems.push(`${rule.ruleId} : la valeur construite n’est pas trouvée une fois, à son étendue et à son score`);
    }
    if (negative.expected.findings.some((finding) => finding.ruleId === rule.ruleId)) {
      problems.push(`${rule.ruleId} : la règle se déclenche sur la valeur trop courte`);
    }
  }
  if (cases.length !== 2 * PROVIDER_RULE_SOURCES.length) problems.push('règles de fournisseurs : nombre de cas inattendu');
  return problems;
}
