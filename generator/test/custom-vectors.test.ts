import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { CUSTOM_UPSTREAM_FILES } from '../custom/upstream.ts';
import { CUSTOM_FILES, encodeInput, serializeCases } from '../custom/vectors.ts';
import { decodeInput, utf8Bytes } from '../corpus/bytes.ts';

const directory = new URL('../../vectors/custom/', import.meta.url);
const read = (name: string): string => readFileSync(new URL(name, directory), 'utf8');

/** Raisons d'écart déclarées, chacune expliquée dans UPSTREAM.md (section « Règles du client »). */
const DECLARED_REASONS = ['json_duplicate_member', 'json_lone_surrogate', 'json_invalid_utf8', 'backtracking_budget'];

interface Case {
  readonly id: string;
  readonly divergence?: { readonly reason: string };
  readonly upstream?: string;
}

describe('vecteurs du Pack de règles du client', () => {
  const manifest = JSON.parse(read('manifest.json')) as { files: { file: string; cases: number }[]; tests: string[]; upstreamCommit: string };

  it('le manifeste compte les cas de chaque fichier, dans l’ordre des fichiers', () => {
    expect(manifest.files.map((entry) => entry.file)).toEqual([...CUSTOM_FILES]);
    for (const entry of manifest.files) {
      const cases = JSON.parse(read(entry.file)) as Case[];
      expect(cases.length, entry.file).toBe(entry.cases);
      expect(new Set(cases.map((c) => c.id)).size, entry.file).toBe(cases.length);
    }
  });

  it('chaque fichier est dans son écriture canonique (un cas par ligne, caractères invisibles échappés)', () => {
    for (const name of CUSTOM_FILES) {
      const text = read(name);
      expect(serializeCases(JSON.parse(text) as unknown[]), name).toBe(text);
    }
  });

  it('chaque écart déclaré a une raison de la liste fermée, expliquée dans UPSTREAM.md avec ses cas', () => {
    const upstream = readFileSync(new URL('../../UPSTREAM.md', import.meta.url), 'utf8');
    for (const name of CUSTOM_FILES) {
      for (const c of JSON.parse(read(name)) as Case[]) {
        if (c.divergence !== undefined) {
          expect(DECLARED_REASONS, c.id).toContain(c.divergence.reason);
          expect(upstream, c.id).toContain(`\`${c.id}\``);
        }
        if (c.upstream !== undefined) {
          expect(c.upstream).toBe('json_parse_error');
          expect(upstream, c.id).toContain(`\`${c.id}\``);
        }
      }
    }
    for (const reason of DECLARED_REASONS) expect(upstream).toContain(`\`${reason}\``);
  });

  it('la copie du schéma est celle de l’origine, titre et description mis à part', () => {
    const copy = readFileSync(new URL('../../schema/CustomPack.json', import.meta.url), 'utf8');
    const original = copy
      .replace('"title": "Secret Guard client rules pack (payload)",', '"title": "xSOM Secret Guard rules pack (payload)",')
      .replace(
        /"description": "Pack de règles du client : [^"]*",/,
        '"description": "Règles sur mesure calibrées et signées par xSOM. Le schéma ne suffit pas : RULES-PACK.md définit la grammaire des motifs, la sémantique de détection et les règles de validité qui s\'ajoutent à lui.",',
      );
    expect(createHash('sha256').update(original).digest('hex')).toBe(CUSTOM_UPSTREAM_FILES['secret-guard/contracts/rules-pack.schema.json']);
  });

  it('une longue entrée périodique s’écrit en répétitions qui redonnent exactement ses octets', () => {
    const text = `en-tête\n${'12345,678901234,55,0\n'.repeat(5000)}1234`;
    const encoded = encodeInput(utf8Bytes(text));
    expect(encoded.inputEncoding).toBe('runs');
    const runs = encoded.input as readonly (readonly [string, number])[];
    expect(runs.map(([part, times]) => part.repeat(times)).join('')).toBe(text);
    expect(encodeInput(utf8Bytes('court')).inputEncoding).toBe('utf8');
    const invalid = Uint8Array.from([0x41, 0xff]);
    expect(encodeInput(invalid)).toEqual({ input: Buffer.from(invalid).toString('base64'), inputEncoding: 'base64' });
    expect(decodeInput(invalid).validUtf8).toBe(false);
  });
});
