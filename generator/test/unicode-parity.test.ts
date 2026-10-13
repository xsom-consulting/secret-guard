/**
 * Pont Unicode Node ↔ Go des vues de texte : le fichier commité est ce que calcule le Node qui a produit le corpus de
 * parité ; le test Go `TestUnicodeParity` le compare aux tables du moteur.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { serializeUnicodeParity, UNICODE_PARITY_FILE, unicodeParity } from '../unicode-parity.ts';

describe('pont Unicode des vues de texte', () => {
  it('les tables Unicode du moteur Go sont celles du moteur d’origine (Default_Ignorable_Code_Point et NFKC de Node)', () => {
    const committed = readFileSync(UNICODE_PARITY_FILE, 'utf8');
    const computed = unicodeParity();
    // Message explicite si le Node qui exécute le test n'a pas la version Unicode du corpus (Node 26 : Unicode 17).
    expect(computed.unicodeVersion, 'version Unicode du Node qui exécute le test (corpus produit sous Unicode 17.0.0)').toBe(
      (JSON.parse(committed) as { unicodeVersion: string }).unicodeVersion,
    );
    expect(committed).toBe(serializeUnicodeParity(computed));
  });
});
