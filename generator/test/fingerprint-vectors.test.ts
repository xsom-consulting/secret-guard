import { readFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';

/*
 * Vecteurs de l'Empreinte locale : vectors/fingerprint.json, lus par le test Go `Empreinte locale HMAC-SHA256 tronquée
 * à 16 octets` (detect). Ce test les recalcule par une implémentation indépendante (node:crypto) : un écart se corrige
 * dans le moteur Go, jamais dans les vecteurs.
 */

/** Forme d'une Empreinte locale : 32 caractères hexadécimaux minuscules. */
const LOCAL_FINGERPRINT_PATTERN = /^[0-9a-f]{32}$/;

interface FingerprintCase {
  name: string;
  keyFrom: number;
  value?: string;
  valueHex?: string;
  fingerprint: string;
}

const vectors = JSON.parse(readFileSync(new URL('../../vectors/fingerprint.json', import.meta.url), 'utf8')) as {
  formatVersion: number;
  description: string;
  cases: FingerprintCase[];
};

const keyOf = (from: number): Buffer => Buffer.from(Array.from({ length: 32 }, (_, i) => (from + i) % 256));

describe('vecteurs de l’Empreinte locale', () => {
  it('chaque vecteur est HMAC-SHA256(clé, valeur) tronqué à 16 octets, en hexadécimal minuscule', () => {
    expect(vectors.formatVersion).toBe(1);
    expect(vectors.cases.length).toBeGreaterThanOrEqual(8);
    const names = new Set<string>();
    for (const c of vectors.cases) {
      expect(names.has(c.name), c.name).toBe(false);
      names.add(c.name);
      expect(Number.isInteger(c.keyFrom) && c.keyFrom >= 0 && c.keyFrom <= 255, c.name).toBe(true);
      expect((c.value === undefined) !== (c.valueHex === undefined), c.name).toBe(true);
      // Écriture hexadécimale stricte : Buffer.from tronque en silence une écriture invalide, Go la refuse.
      if (c.valueHex !== undefined) expect(/^(?:[0-9a-f]{2})*$/.test(c.valueHex), c.name).toBe(true);
      const value = c.valueHex !== undefined ? Buffer.from(c.valueHex, 'hex') : Buffer.from(c.value ?? '', 'utf8');
      const expected = createHmac('sha256', keyOf(c.keyFrom)).update(value).digest().subarray(0, 16).toString('hex');
      expect(c.fingerprint, c.name).toBe(expected);
      // Forme d'une Empreinte locale.
      expect(LOCAL_FINGERPRINT_PATTERN.test(c.fingerprint), c.name).toBe(true);
    }
  });

  it('les vecteurs couvrent deux clés pour une même valeur et des Empreintes locales toutes différentes', () => {
    const byValue = new Map<string, Set<number>>();
    for (const c of vectors.cases) {
      const value = c.value ?? `hex:${c.valueHex ?? ''}`;
      byValue.set(value, (byValue.get(value) ?? new Set()).add(c.keyFrom));
    }
    expect([...byValue.values()].some((keys) => keys.size >= 2)).toBe(true);
    expect(new Set(vectors.cases.map((c) => c.fingerprint)).size).toBe(vectors.cases.length);
  });
});
