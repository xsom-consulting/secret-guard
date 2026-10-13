/**
 * Assemblage du corpus de parité : résultat attendu d'un cas à partir du moteur d'origine (positions
 * UTF-16 → octets, tri), et contrôles de couverture qui font échouer le générateur. Pur, à moteur injecté.
 */
import { byteOffsetOf, decodeInput, utf8Bytes } from './bytes.ts';
import {
  compareFindings,
  FINDING_ENCODINGS,
  levelForScore,
  MAX_INPUT_BYTES,
  type CorpusCase,
  type CorpusExpected,
  type CorpusFinding,
  type FindingEncoding,
  type ScanFailure,
} from './model.ts';
import type { CaseIntent } from './synthetic.ts';
import type { UpstreamEngine } from './upstream.ts';

export class CorpusError extends Error {
  override readonly name = 'CorpusError';
}

/** Source d'un cas : octets d'entrée, langage, intention contrôlée (cas synthétiques). */
export interface CaseSource {
  readonly file: string;
  readonly id: string;
  readonly bytes: Uint8Array;
  readonly languageId?: string;
  readonly intent?: CaseIntent;
}

function isEncoding(value: string): value is FindingEncoding {
  return (FINDING_ENCODINGS as readonly string[]).includes(value);
}

/** Résultat attendu : analyse du texte décodé par le moteur d'origine. */
export function expectedFor(engine: UpstreamEngine, bytes: Uint8Array, languageId: string | undefined): CorpusExpected {
  const decoded = decodeInput(bytes);
  // Secret Guard mesure la limite sur le texte (U+FFFD = 3 octets), Go sur les octets reçus : un cas où les deux
  // mesures tombent de part et d'autre de la limite n'a pas de résultat attendu commun.
  if (!decoded.validUtf8 && utf8Bytes(decoded.text).length > MAX_INPUT_BYTES !== bytes.length > MAX_INPUT_BYTES) {
    throw new CorpusError('limite de taille mesurée différemment sur le texte décodé et sur les octets');
  }
  const result = engine.scan(decoded.text, languageId);
  const failures = result.findings.filter((finding) => finding.secretType === 'scan_limit' || finding.secretType === 'scan_error');
  if (!result.complete) {
    const [failure] = failures;
    if (failures.length !== 1 || result.findings.length !== 1 || failure === undefined) {
      throw new CorpusError('analyse incomplète sans constat d’échec unique');
    }
    return { complete: false, failure: failure.secretType as ScanFailure, findings: [] };
  }
  if (failures.length > 0) throw new CorpusError('analyse complète avec un constat d’échec');
  const findings = result.findings.map((finding): CorpusFinding => {
    if (!isEncoding(finding.encoding)) throw new CorpusError(`vue inconnue : ${finding.encoding}`);
    if (finding.level !== levelForScore(finding.score)) throw new CorpusError(`niveau incohérent : ${finding.ruleId}`);
    const byteStart = byteOffsetOf(decoded, finding.start);
    const byteEnd = byteOffsetOf(decoded, finding.end);
    if (byteEnd < byteStart) throw new CorpusError(`étendue inversée : ${finding.ruleId}`);
    return {
      ruleId: finding.ruleId,
      secretType: finding.secretType,
      encoding: finding.encoding,
      score: finding.score,
      level: levelForScore(finding.score),
      byteStart,
      byteEnd,
    };
  });
  return { complete: true, failure: 'none', findings: findings.sort(compareFindings) };
}

/** Cas écrit : texte quand les octets sont de l'UTF-8 valide, base64 sinon. */
export function corpusCaseOf(source: CaseSource, expected: CorpusExpected): CorpusCase {
  const decoded = decodeInput(source.bytes);
  return {
    id: source.id,
    input: decoded.validUtf8 ? decoded.text : Buffer.from(source.bytes).toString('base64'),
    inputEncoding: decoded.validUtf8 ? 'utf8' : 'base64',
    ...(source.languageId === undefined ? {} : { languageId: source.languageId }),
    expected,
  };
}

/** Cas évalué, pour les contrôles de couverture. */
export interface EvaluatedCase {
  readonly id: string;
  readonly intent?: CaseIntent;
  readonly expected: CorpusExpected;
}

export interface CoverageInput {
  readonly cases: readonly EvaluatedCase[];
  /** Identifiants de règle du Pack initial. */
  readonly packRuleIds: readonly string[];
  readonly placeholderNotApplicable: Readonly<Record<string, string>>;
  readonly publicExampleNotApplicable: Readonly<Record<string, string>>;
  readonly engine: Pick<UpstreamEngine, 'fixedRuleIds' | 'isPlaceholder' | 'isExactPublicExample'>;
}

function fires(expected: CorpusExpected, rule: string, view?: FindingEncoding): boolean {
  return expected.findings.some((finding) => finding.ruleId === rule && (view === undefined || finding.encoding === view));
}

/**
 * Problèmes de couverture ; le générateur échoue s'il y en a un. Chaque règle du Pack a au moins un cas positif et
 * un cas négatif, un cas de valeur fictive et un cas d'exemple public sauf exemption motivée ; chaque vue a un cas
 * positif ; chaque intention est tenue par le moteur ; aucun constat ne nomme une règle hors du Pack.
 */
export function coverageProblems(input: CoverageInput): string[] {
  const problems: string[] = [];
  const pack = new Set(input.packRuleIds);
  for (const id of input.engine.fixedRuleIds) {
    if (!pack.has(id)) problems.push(`règle de FIXED_RULE_IDS absente du Pack : ${id}`);
  }
  for (const [name, exemptions] of [
    ['valeur fictive', input.placeholderNotApplicable],
    ['exemple public', input.publicExampleNotApplicable],
  ] as const) {
    for (const rule of Object.keys(exemptions)) {
      if (!pack.has(rule)) problems.push(`exemption « ${name} » d’une règle hors du Pack : ${rule}`);
    }
  }

  const counts = new Map<string, Record<CaseIntent['kind'], number>>();
  const count = (rule: string, kind: CaseIntent['kind']): void => {
    const entry = counts.get(rule) ?? { positive: 0, negative: 0, placeholder: 0, public_example: 0, view: 0 };
    entry[kind] += 1;
    counts.set(rule, entry);
  };
  const views = new Set<FindingEncoding>();

  for (const evaluated of input.cases) {
    const { expected, intent } = evaluated;
    for (const finding of expected.findings) {
      if (!pack.has(finding.ruleId)) problems.push(`${evaluated.id} : constat d’une règle hors du Pack (${finding.ruleId})`);
      views.add(finding.encoding);
    }
    if (intent === undefined) continue;
    if (!pack.has(intent.rule)) {
      problems.push(`${evaluated.id} : intention sur une règle hors du Pack (${intent.rule})`);
      continue;
    }
    switch (intent.kind) {
      case 'positive':
        if (!fires(expected, intent.rule)) problems.push(`${evaluated.id} : la règle ${intent.rule} ne se déclenche pas`);
        break;
      case 'view':
        if (!fires(expected, intent.rule, intent.view)) {
          problems.push(`${evaluated.id} : la règle ${intent.rule} ne se déclenche pas dans la vue ${intent.view}`);
        }
        break;
      case 'negative':
        if (fires(expected, intent.rule)) problems.push(`${evaluated.id} : la règle ${intent.rule} se déclenche`);
        break;
      case 'placeholder':
        if (!input.engine.isPlaceholder(intent.value)) problems.push(`${evaluated.id} : valeur non fictive pour isPlaceholder`);
        if (fires(expected, intent.rule)) problems.push(`${evaluated.id} : la règle ${intent.rule} se déclenche sur une valeur fictive`);
        break;
      case 'public_example':
        if (!input.engine.isExactPublicExample(intent.value)) problems.push(`${evaluated.id} : valeur hors des exemples publics`);
        if (fires(expected, intent.rule)) problems.push(`${evaluated.id} : la règle ${intent.rule} se déclenche sur un exemple public`);
        break;
    }
    if (expected.complete) count(intent.rule, intent.kind);
  }

  for (const rule of input.packRuleIds) {
    const entry = counts.get(rule);
    if ((entry?.positive ?? 0) === 0) problems.push(`règle sans cas positif : ${rule}`);
    if ((entry?.negative ?? 0) === 0) problems.push(`règle sans cas négatif : ${rule}`);
    if ((entry?.placeholder ?? 0) === 0 && input.placeholderNotApplicable[rule] === undefined) {
      problems.push(`règle sans cas de valeur fictive : ${rule}`);
    }
    if ((entry?.public_example ?? 0) === 0 && input.publicExampleNotApplicable[rule] === undefined) {
      problems.push(`règle sans cas d’exemple public : ${rule}`);
    }
  }
  for (const view of FINDING_ENCODINGS) {
    if (!views.has(view)) problems.push(`vue sans cas positif : ${view}`);
    if (!input.cases.some((evaluated) => evaluated.intent?.kind === 'view' && evaluated.intent.view === view)) {
      problems.push(`vue sans cas de référence : ${view}`);
    }
  }
  return problems;
}
