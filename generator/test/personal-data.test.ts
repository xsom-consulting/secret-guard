// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  cardValid,
  groupBy4,
  IBAN_LENGTHS,
  ibanPrefixLength,
  ibanValid,
  luhnCheckDigit,
  luhnValid,
  makeIban,
  makeNir,
  nirValid,
  PERSONAL_DATA_RULES,
  REFERENCE_VALIDATORS,
  referenceFindings,
  sirenValid,
  siretValid,
  timestampLike,
} from '../rule-pack/personal-data.ts';
import { RULE_SECRET_TYPES, RULE_VALIDATORS } from '../src/rule-pack.ts';

const read = (path: string): string => readFileSync(new URL(path, import.meta.url), 'utf8');

describe('règles de données personnelles (v0.7.0)', () => {
  it('chaque règle a un type de secret et un validateur de la liste fermée, un motif RE2 sans \\s ni (?i)', () => {
    expect(PERSONAL_DATA_RULES.map((rule) => rule.ruleId)).toEqual(['iban', 'fr_nir', 'fr_siret', 'fr_siren', 'payment_card']);
    for (const rule of PERSONAL_DATA_RULES) {
      expect(RULE_SECRET_TYPES as readonly string[], rule.ruleId).toContain(rule.secretType);
      expect(RULE_VALIDATORS as readonly string[], rule.ruleId).toContain(rule.validator);
      expect(REFERENCE_VALIDATORS[rule.validator], rule.ruleId).toBeDefined();
      expect(rule.pattern, rule.ruleId).not.toMatch(/\\s|\\S|\(\?i\)/);
      expect(rule.family).toBe('fixed_pattern');
      expect(rule.minLength).toBeGreaterThan(0);
      expect(rule.maxLength).toBeGreaterThanOrEqual(rule.minLength);
      // Niveau : données personnelles au moins MEDIUM (25), carte bancaire HIGH (50) ; encodage décodé : -5.
      expect(rule.score - 5, rule.ruleId).toBeGreaterThanOrEqual(25);
    }
    expect(PERSONAL_DATA_RULES.find((rule) => rule.ruleId === 'payment_card')?.score).toBeGreaterThanOrEqual(55);
    // Le premier groupe capturant porte la valeur (docs/rule-pack.md) : un seul groupe, dans la règle SIREN seulement.
    const captures = PERSONAL_DATA_RULES.map((rule) => [rule.ruleId, (rule.pattern.match(/\((?!\?)/g) ?? []).length]);
    expect(captures).toEqual([
      ['iban', 0],
      ['fr_nir', 0],
      ['fr_siret', 0],
      ['fr_siren', 1],
      ['payment_card', 0],
    ]);
  });

  it('le schéma RulePack.json et le moteur Go listent les mêmes types de secret et validateurs', () => {
    const schema = JSON.parse(read('../../schema/RulePack.json')) as {
      properties: { rules: { items: { properties: { secretType: { enum: string[] } } } } };
    };
    expect(schema.properties.rules.items.properties.secretType.enum).toEqual([...RULE_SECRET_TYPES]);
    const go = read('../../detect/personaldata.go');
    for (const validator of RULE_VALIDATORS.filter((name) => name !== '' && name !== 'jwt_structure')) {
      expect(go, validator).toContain(`"${validator}"`);
    }
  });

  it('la table des longueurs d’IBAN du moteur Go est celle du générateur', () => {
    const go = read('../../detect/personaldata.go');
    const block = /var ibanLengths = map\[string\]int\{([^}]*)\}/s.exec(go)?.[1] ?? '';
    const parsed = Object.fromEntries([...block.matchAll(/"([A-Z]{2})": (\d+)/g)].map((match) => [match[1], Number(match[2])]));
    expect(parsed).toEqual(IBAN_LENGTHS);
  });

  it('contrôles de référence : exemples connus', () => {
    // IBAN d'exemple publics.
    for (const iban of ['FR76 3000 6000 0112 3456 7890 189', 'GB82 WEST 1234 5698 7654 32', 'DE89 3704 0044 0532 0130 00', 'NL91ABNA0417164300']) {
      expect(ibanValid(iban), iban).toBe(true);
    }
    expect(ibanValid('FR76 3000 6000 0112 3456 7890 188')).toBe(false);
    expect(ibanValid('FR76 3000 6000 0112 3456 7890 18')).toBe(false); // longueur du pays
    expect(ibanValid('FR00 3000 6000 0112 3456 7890 189')).toBe(false); // chiffres de contrôle 00
    // Cartes d'essai publiques des réseaux.
    for (const pan of ['4111111111111111', '5555555555554444', '378282246310005', '6011111111111117', '3530111333300000', '4111 1111 1111 1111', '4111-1111-1111-1111']) {
      expect(cardValid(pan), pan).toBe(true);
    }
    expect(cardValid('4111 1111-1111 1111')).toBe(false);
    expect(cardValid('4111111111111112')).toBe(false);
    expect(cardValid('0000000000000000')).toBe(false);
    expect(luhnValid('79927398713')).toBe(true);
    // SIREN de La Poste : Luhn valide.
    expect(sirenValid('356000000')).toBe(true);
  });

  it('SIRET : exception de La Poste, horodatages et chiffres répétés écartés', () => {
    // Somme des chiffres de 35600000000048 = 3+5+6+4+8 = 26 : pas un multiple de 5, et Luhn invalide.
    expect(siretValid('35600000000048')).toBe(false);
    const sumMultipleOfFive = '35600000000001'; // 3+5+6+1 = 15
    expect([...sumMultipleOfFive].reduce((sum, digit) => sum + Number(digit), 0) % 5).toBe(0);
    expect(luhnValid(sumMultipleOfFive)).toBe(false);
    expect(siretValid(sumMultipleOfFive)).toBe(true);
    expect(timestampLike('20261110103000')).toBe(true);
    expect(timestampLike('20261310103000')).toBe(false);
    expect(siretValid('00000000000000')).toBe(false);
  });

  it('NIR : clé = 97 − (nombre mod 97), 2A → 19 et 2B → 18, composants jamais nuls', () => {
    // Clé calculée à la main : 97 − (1841276451089 mod 97) = 46.
    expect(makeNir('1841276451089')).toBe('184127645108946');
    expect(nirValid('1 84 12 76 451 089 46')).toBe(true);
    expect(nirValid('184127645108947')).toBe(false);
    // Corse : même calcul avec 19 / 18 à la place de 2A / 2B.
    const corsicaA = makeNir('15508' + '2A' + '004080');
    expect(nirValid(corsicaA)).toBe(true);
    const asDepartment19 = corsicaA.slice(0, 13).replace('2A', '19');
    expect(97n - (BigInt(asDepartment19) % 97n)).toBe(BigInt(corsicaA.slice(13)));
    const corsicaB = makeNir('25508' + '2B' + '004080');
    expect(nirValid(corsicaB)).toBe(true);
    const asDepartment18 = corsicaB.slice(0, 13).replace('2B', '18');
    expect(97n - (BigInt(asDepartment18) % 97n)).toBe(BigInt(corsicaB.slice(13)));
    expect(nirValid(makeNir('15508' + '00' + '004080'))).toBe(false); // département 00
  });

  it('IBAN calculé pour chaque pays de la table : valide, au bon nombre de caractères', () => {
    for (const [country, length] of Object.entries(IBAN_LENGTHS)) {
      const iban = makeIban(country, '1'.repeat(length - 4));
      expect(iban).toHaveLength(length);
      expect(ibanValid(iban), country).toBe(true);
      expect(ibanValid(groupBy4(iban)), country).toBe(true);
      expect(ibanValid(makeIban(country, '1'.repeat(length - 3))), country).toBe(false);
    }
  });

  it('IBAN suivi d’un mot de quatre caractères : la fin retenue est celle de l’IBAN', () => {
    const es = groupBy4(makeIban('ES', '2'.repeat(20)));
    expect(ibanPrefixLength(`${es} pour`)).toBe(es.length);
    expect(ibanPrefixLength(`${es} 2026`)).toBe(es.length);
    expect(ibanPrefixLength(`${es.replaceAll(' ', '')}pour`)).toBe(es.replaceAll(' ', '').length);
    expect(ibanPrefixLength('AB12 CDEF GHIJ KLMN')).toBe(0);
    const fr = groupBy4(makeIban('FR', '3'.repeat(23)));
    expect(ibanPrefixLength(fr)).toBe(fr.length);
  });

  it('la lecture de référence écarte les numéros de téléphone et de commande', () => {
    const text = 'tél 01 23 45 67 89, commande 20261110103000 et 000000000, réf 1234 5678 9012 3456';
    expect(referenceFindings(text).map((found) => found.rule.ruleId)).toEqual([]);
  });

  it('le chiffre de Luhn calculé complète n’importe quel préfixe', () => {
    for (const prefix of ['1', '4111', '37828224631000', '12345678']) {
      expect(luhnValid(`${prefix}${luhnCheckDigit(prefix)}`), prefix).toBe(true);
    }
  });
});
