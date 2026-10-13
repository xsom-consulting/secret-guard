import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  UPSTREAM_COMMIT,
  UPSTREAM_PATH,
  buildInitialPack,
  extractCatalog,
  serializePack,
  translationOf,
  VALUE_BOUNDS,
} from '../rule-pack/catalog.ts';
import { RULE_FAMILIES, RULE_FAMILIES_WITH_PATTERN, RULE_VALIDATORS, RulePack } from '../src/rule-pack.ts';

const upstreamText = readFileSync(new URL('../../pack/initial/upstream/rules.ts.txt', import.meta.url), 'utf8');
const upstreamBytes = readFileSync(new URL('../../pack/initial/upstream/rules.ts.txt', import.meta.url));
const packText = readFileSync(new URL('../../pack/initial/pack.json', import.meta.url), 'utf8');
const upstreamNotes = readFileSync(new URL('../../UPSTREAM.md', import.meta.url), 'utf8');

const pack = RulePack.parse(JSON.parse(packText));

/**
 * Les 35 règles du catalogue Secret Guard au commit cité, relevées à la main dans `rules.ts` (`FIXED_RULES`,
 * `scanFixedRules`, `scanCredentialUrls`, `typeForSensitiveKey` × `contextual_<type>`, `contextualFinding`,
 * `scanEntropy`), sans passer par le générateur : `[ruleId, family, secretType, score]`, dans l'ordre du Pack.
 */
const CATALOG_BY_HAND: readonly (readonly [string, string, string, number])[] = [
  ['private_key_pem', 'private_key', 'private_key', 100],
  ['private_key_pem_incomplete', 'private_key', 'private_key', 90],
  ['github_fine_grained_pat', 'fixed_pattern', 'provider_token', 95],
  ['github_token', 'fixed_pattern', 'provider_token', 95],
  ['gitlab_pat', 'fixed_pattern', 'provider_token', 95],
  ['openrouter_key', 'fixed_pattern', 'provider_token', 95],
  ['anthropic_key', 'fixed_pattern', 'provider_token', 95],
  ['openai_key', 'fixed_pattern', 'provider_token', 92],
  ['stripe_secret_key', 'fixed_pattern', 'provider_token', 95],
  ['slack_token', 'fixed_pattern', 'provider_token', 95],
  ['slack_webhook', 'fixed_pattern', 'provider_token', 95],
  ['google_api_key', 'fixed_pattern', 'api_key', 90],
  ['google_oauth_token', 'fixed_pattern', 'access_token', 95],
  ['sendgrid_key', 'fixed_pattern', 'provider_token', 95],
  ['npm_token', 'fixed_pattern', 'provider_token', 95],
  ['huggingface_token', 'fixed_pattern', 'provider_token', 95],
  ['databricks_pat', 'fixed_pattern', 'provider_token', 95],
  ['digitalocean_token', 'fixed_pattern', 'provider_token', 95],
  ['shopify_token', 'fixed_pattern', 'provider_token', 95],
  ['azure_storage_key', 'fixed_pattern', 'cloud_credential', 95],
  ['aws_access_key_id', 'fixed_pattern', 'cloud_credential', 45],
  ['jwt', 'fixed_pattern', 'jwt', 60],
  ['database_url_credentials', 'credential_url', 'database_credentials', 95],
  ['basic_auth_url', 'credential_url', 'password', 90],
  ['contextual_password', 'contextual_assignment', 'password', 70],
  ['contextual_private_key', 'contextual_assignment', 'private_key', 70],
  ['contextual_cloud_credential', 'contextual_assignment', 'cloud_credential', 70],
  ['contextual_api_key', 'contextual_assignment', 'api_key', 70],
  ['contextual_access_token', 'contextual_assignment', 'access_token', 70],
  ['contextual_generic_secret', 'contextual_assignment', 'generic_secret', 70],
  ['contextual_database_credentials', 'contextual_assignment', 'database_credentials', 70],
  ['cookie_session_credential', 'contextual_assignment', 'access_token', 70],
  ['cli_basic_auth', 'contextual_assignment', 'password', 70],
  ['docker_auth', 'contextual_assignment', 'password', 70],
  ['high_entropy', 'entropy', 'high_entropy', 35],

];
const catalog = extractCatalog(upstreamText);

describe('Pack initial', () => {
  it('le Pack initial reprend chaque règle du catalogue Secret Guard', () => {
    // Source figée : la copie commitée est celle du commit cité dans UPSTREAM.md, octet pour octet.
    const sha256 = createHash('sha256').update(upstreamBytes).digest('hex');
    expect(upstreamNotes).toContain(UPSTREAM_COMMIT);
    expect(upstreamNotes).toContain('secret-guard/packages/core');
    expect(upstreamNotes).toContain('Apache License, Version 2.0');
    expect(upstreamNotes).toContain(`| \`${UPSTREAM_PATH}\` | \`pack/initial/upstream/rules.ts.txt\` | \`${sha256}\` |`);

    // Une règle du Pack par règle du catalogue, même identifiant, famille, type de secret et score, même ordre :
    // contre la table écrite à la main (indépendante du générateur), puis contre l'extraction.
    expect(CATALOG_BY_HAND).toHaveLength(35);
    expect(pack.rules.map((rule) => [rule.ruleId, rule.family, rule.secretType, rule.score])).toEqual(CATALOG_BY_HAND);
    expect(catalog).toHaveLength(35);
    expect(pack.rules.map((rule) => [rule.ruleId, rule.family, rule.secretType, rule.score])).toEqual(
      catalog.map((rule) => [rule.ruleId, rule.family, rule.secretType, rule.score]),
    );
    // Chaque famille de rules.ts est représentée ; toutes les règles fixes y sont.
    expect([...new Set(pack.rules.map((rule) => rule.family))].sort()).toEqual([...RULE_FAMILIES].sort());
    expect(upstreamText.includes('export const FIXED_RULE_IDS')).toBe(true);
    expect(pack.rules.filter((rule) => rule.family === 'fixed_pattern')).toHaveLength(20);

    // Le fichier commité est exactement la traduction de la source figée (aucune écriture à la main).
    expect(packText).toBe(serializePack(buildInitialPack(upstreamText)));

    // L'unique rétro-référence (`-u user:motdepasse`) est réécrite par alternative des trois formes.
    expect(pack.rules.filter((rule) => /\\[1-9]/.test(rule.pattern))).toEqual([]);
    const rewritten = catalog.filter((rule) => translationOf(rule).backreferenceRewritten).map((rule) => rule.ruleId);
    expect(rewritten).toEqual(['cli_basic_auth']);
    const basicAuth = pack.rules.find((rule) => rule.ruleId === 'cli_basic_auth');
    expect(basicAuth?.pattern).toMatch(/\(\?:"\(.+\)"\|'\(.+\)'\|\(.+\)\)$/);
  });

  it('les motifs traduits ne gardent ni \\s, ni borne de plus de 1 000, ni drapeau i', () => {
    for (const rule of pack.rules) {
      expect(rule.pattern, rule.ruleId).not.toMatch(/\\s|\\S|\(\?i\)/);
      for (const match of rule.pattern.matchAll(/(?<!\\x)\{(\d+)(?:,(\d*))?\}/g)) {
        expect(Number(match[2] === undefined || match[2] === '' ? match[1] : match[2]), rule.ruleId).toBeLessThanOrEqual(1_000);
      }
    }
  });

  it('bornes de longueur reportées pour chaque répétition ouverte, absentes sinon', () => {
    for (const [index, rule] of pack.rules.entries()) {
      const entry = catalog[index];
      expect(entry?.ruleId).toBe(rule.ruleId);
      const opened = entry === undefined ? [] : translationOf(entry).openedRepetitions;
      const bounds = VALUE_BOUNDS[rule.ruleId];
      if (opened.length === 0) {
        expect([rule.minLength, rule.maxLength], rule.ruleId).toEqual([0, 0]);
      } else {
        expect([rule.minLength, rule.maxLength], rule.ruleId).toEqual(bounds);
        expect(rule.minLength).toBeLessThanOrEqual(rule.maxLength);
      }
    }
    expect(Object.keys(VALUE_BOUNDS).sort()).toEqual(['basic_auth_url', 'cli_basic_auth', 'database_url_credentials', 'jwt']);
  });

  it('validateur nommé et valeur portée par le premier groupe des règles fixes', () => {
    expect(pack.rules.filter((rule) => rule.validator !== '').map((rule) => [rule.ruleId, rule.validator])).toEqual([['jwt', 'jwt_structure']]);
    // Validateurs de la liste fermée ; motif présent pour chaque famille qui en exige un.
    expect(pack.rules.every((rule) => (RULE_VALIDATORS as readonly string[]).includes(rule.validator))).toBe(true);
    for (const rule of pack.rules) {
      if ((RULE_FAMILIES_WITH_PATTERN as readonly string[]).includes(rule.family)) {
        expect(rule.pattern, rule.ruleId).not.toBe('');
      }
    }
    for (const rule of catalog.filter((entry) => entry.family === 'fixed_pattern')) {
      const hasCapture = /\((?!\?)/.test(translationOf(rule).pattern);
      expect(hasCapture, rule.ruleId).toBe(rule.capture === 1);
    }
  });

  it('motif vide pour les règles qui combinent plusieurs motifs (logique du moteur)', () => {
    expect(pack.rules.filter((rule) => rule.pattern === '').map((rule) => rule.ruleId)).toEqual([
      'contextual_password',
      'contextual_private_key',
      'contextual_cloud_credential',
      'contextual_api_key',
      'contextual_access_token',
      'contextual_generic_secret',
      'contextual_database_credentials',
      'cookie_session_credential',
    ]);
  });

  it('en-tête du Pack initial', () => {
    expect({ ...pack, rules: undefined }).toEqual({
      schemaVersion: 1,
      minAgentVersion: '0.0.0',
      packVersion: 1,
      issuedAt: '2026-10-09T00:00:00Z',
      rules: undefined,
    });
  });
});

describe('schéma RulePack', () => {
  const valid = JSON.parse(packText) as { rules: Record<string, unknown>[] } & Record<string, unknown>;
  const firstRule = valid.rules[0] ?? {};

  it.each([
    ['champ inconnu à la racine', { ...valid, extra: 'x' }],
    ['champ inconnu dans une règle', { ...valid, rules: [{ ...firstRule, extra: 'x' }] }],
    ['score flottant', { ...valid, rules: [{ ...firstRule, score: 95.5 }] }],
    ['famille inconnue', { ...valid, rules: [{ ...firstRule, family: 'custom' }] }],
    ['type de secret inconnu', { ...valid, rules: [{ ...firstRule, secretType: 'scan_error' }] }],
    ['packVersion texte', { ...valid, packVersion: '1' }],
    ['minAgentVersion non semver', { ...valid, minAgentVersion: '1.0' }],
    ['minAgentVersion en pré-version', { ...valid, minAgentVersion: '1.0.0-dev' }],
    ['issuedAt avec décalage', { ...valid, issuedAt: '2026-10-09T00:00:00+02:00' }],
    ['aucune règle', { ...valid, rules: [] }],
    ['booléen', { ...valid, rules: [{ ...firstRule, minLength: true }] }],
    ['validateur mal formé', { ...valid, rules: [{ ...firstRule, validator: 'Jwt' }] }],
  ])('refuse : %s', (_name, value) => {
    expect(RulePack.safeParse(value).success).toBe(false);
  });
});
