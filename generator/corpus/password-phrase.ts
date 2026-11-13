// SPDX-License-Identifier: Apache-2.0
/**
 * Cas du corpus de parité pour le mot de passe annoncé dans une phrase (v0.8.1) :
 * `vectors/detection/rules-password-phrase.json`.
 *
 * Le moteur d'origine ne lit pas ces annonces : le résultat attendu d'un cas vient de la seconde écriture de
 * `rule-pack/password-phrase.ts`, et le générateur exige que le moteur d'origine ne trouve rien dans le même texte
 * (aucun constat à fusionner). Valeurs synthétiques tirées de SHA-256 (`synth`), écrites telles quelles dans le
 * corpus : jamais une valeur relevée.
 */
import { byteOffsetOf, decodeInput, utf8Bytes } from './bytes.ts';
import { CorpusError, expectedFor, type CaseSource } from './corpus.ts';
import { compareFindings, levelForScore, type CorpusExpected, type CorpusFinding } from './model.ts';
import { synth, type CaseIntent } from './synthetic.ts';
import { PASSWORD_PHRASE_RULE, passwordPhraseFindings } from '../rule-pack/password-phrase.ts';
import type { UpstreamEngine } from './upstream.ts';

/** Fichier du corpus qui porte ces cas (famille `rules`, couverte par l'exception de `.gitleaks.toml`). */
export const PASSWORD_PHRASE_FILE = 'rules-password-phrase.json';

const UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
const LOWER = 'abcdefghijkmnopqrstuvwxyz';
const DIGITS = '0123456789';
/** Symboles d'un mot de passe (ni espace, ni ponctuation finale retirée, ni guillemet d'ouverture en tête). */
const SYMBOLS = '&"\'$*°#!@+%';
const ACCENTS = 'éèàçùêôîœ';

/** Valeur synthétique : majuscule, minuscules, symboles, chiffres, lettres accentuées (au moins trois classes). */
function value(label: string): string {
  const at = (part: string, alphabet: string, length: number): string => synth(`password-phrase/${label}/${part}`, alphabet, length);
  return `${at('u', UPPER, 1)}${at('l', LOWER, 3)}${at('s', SYMBOLS, 2)}${at('d', DIGITS, 2)}${at('a', ACCENTS, 2)}`;
}

/** Valeur synthétique sans symbole ni accent : majuscule, minuscules, chiffres. */
function plainValue(label: string): string {
  const at = (part: string, alphabet: string, length: number): string => synth(`password-phrase/${label}/${part}`, alphabet, length);
  return `${at('u', UPPER, 1)}${at('l', LOWER, 6)}${at('d', DIGITS, 3)}`;
}

interface Draft {
  readonly id: string;
  readonly text: string;
  readonly intent: CaseIntent;
}

const RULE = PASSWORD_PHRASE_RULE.ruleId;

function positive(name: string, text: string): Draft {
  return { id: `password_phrase/positive/${name}`, text, intent: { kind: 'positive', rule: RULE } };
}

function negative(name: string, text: string): Draft {
  return { id: `password_phrase/negative/${name}`, text, intent: { kind: 'negative', rule: RULE } };
}

function drafts(): Draft[] {
  const word = 'pass' + 'word';
  return [
    positive('mon-mdp', `check mon api avec mon mdp ${value('mon-mdp')}\n`),
    positive('mon-mdp-suivi-d-un-mot', `voici mon mdp ${plainValue('suivi')} pour le serveur\n`),
    positive('mot-de-passe-deux-points', `mot de passe : ${value('deux-points')}\n`),
    positive('le-mot-de-passe-est', `Le mot de passe est ${value('est')}.\n`),
    positive('mot-de-passe-trait-d-union-c-est', `mot-de-passe c'est ${plainValue('c-est')}\n`),
    positive('code-d-acces-typographique', `le code d’accès : ${value('code')}\n`),
    positive('mdp-majuscules-colle', `MDP:${plainValue('colle')}\n`),
    positive('my-password-is', `my ${word} is ${value('is')}\n`),
    positive('passphrase', `the passphrase ${plainValue('phrase')} works\n`),
    positive('pwd-is', `pwd is ${plainValue('pwd')}\n`),
    positive('pass-est', `le pass est ${value('pass')}\n`),
    positive('guillemets', `mon mdp est "${plainValue('guillemets')}"\n`),
    positive('guillemets-francais', `mot de passe « ${value('chevrons')} »\n`),
    positive('deux-annonces', `mdp ${plainValue('un')} puis mot de passe : ${value('deux')}\n`),
    negative('mdp-trop-court', 'mon mdp est trop court\n'),
    negative('mot-de-passe-administrateur', 'le mot de passe Administrateur\n'),
    negative('mot-de-passe-oublie', 'mot de passe oublié\n'),
    negative('reinitialise-capitale', 'Le mot de passe est Réinitialisé.\n'),
    negative('password-reset-link', `${word} reset link https://example.com/Reset?id=42\n`),
    negative('deux-classes', 'mon mdp est azerty123\n'),
    negative('pass-sans-liaison', 'we pass Config-V2 to the parser\n'),
    negative('passe-francais', 'passe Config-V2 à la suite\n'),
    negative('propriete', `user.${word} Hunter2-Xy\n`),
    negative('autre-ligne', 'mdp\nHunter2-Xy\n'),
    negative('variable-shell', 'mon mdp est ${DB_Pass1}\n'),
    negative('reference-de-code', 'mot de passe : process.env.DB_Pass1\n'),
    negative('affectation-anglaise-laissee', `the ${word} = getPassword(Db1)\n`),
  ];
}

/** Cas du mot de passe annoncé, dans l'ordre de `drafts`. */
export function passwordPhraseCases(): CaseSource[] {
  return drafts().map((draft) => ({ file: PASSWORD_PHRASE_FILE, id: draft.id, bytes: utf8Bytes(draft.text), intent: draft.intent }));
}

/**
 * Résultat attendu d'un cas : constats de la lecture de référence (vue d'identité), à condition que le moteur d'origine
 * ne trouve rien dans le texte. Erreur sinon (le cas doit être redessiné).
 */
export function passwordPhraseExpected(engine: UpstreamEngine, source: CaseSource): CorpusExpected {
  const upstream = expectedFor(engine, source.bytes, source.languageId);
  if (!upstream.complete || upstream.findings.length > 0) {
    throw new CorpusError(`${source.id} : le moteur d’origine trouve ou échoue sur ce texte, le cas doit être redessiné`);
  }
  return { complete: true, failure: 'none', findings: passwordPhraseReference(source.bytes) };
}

/** Constats attendus d'une entrée par la lecture de référence. */
export function passwordPhraseReference(bytes: Uint8Array): CorpusFinding[] {
  const decoded = decodeInput(bytes);
  const { ruleId, secretType, score } = PASSWORD_PHRASE_RULE;
  const findings = passwordPhraseFindings(decoded.text).map(
    (found): CorpusFinding => ({
      ruleId,
      secretType,
      encoding: 'plain',
      score,
      level: levelForScore(score),
      byteStart: byteOffsetOf(decoded, found.start),
      byteEnd: byteOffsetOf(decoded, found.end),
    }),
  );
  return findings.sort(compareFindings);
}

/** Problèmes de couverture : intentions tenues, au moins 10 positifs et 10 négatifs. */
export function passwordPhraseCoverageProblems(
  cases: readonly { readonly id: string; readonly intent?: CaseIntent; readonly expected: CorpusExpected }[],
): string[] {
  const problems: string[] = [];
  const counts = { positive: 0, negative: 0 };
  for (const { id, intent, expected } of cases) {
    if (intent?.kind !== 'positive' && intent?.kind !== 'negative') {
      problems.push(`${id} : intention absente ou hors positif/négatif`);
      continue;
    }
    const fires = expected.findings.some((finding) => finding.ruleId === intent.rule);
    if (intent.kind === 'positive' && !fires) problems.push(`${id} : la règle ${intent.rule} ne se déclenche pas`);
    if (intent.kind === 'negative' && fires) problems.push(`${id} : la règle ${intent.rule} se déclenche`);
    counts[intent.kind] += 1;
  }
  if (counts.positive < 10) problems.push('mot de passe annoncé : moins de dix cas positifs');
  if (counts.negative < 10) problems.push('mot de passe annoncé : moins de dix cas négatifs');
  return problems;
}
