// SPDX-License-Identifier: Apache-2.0
/**
 * `node corpus/provider-noise.ts` (dans `generator/`) : écrit `vectors/noise-providers.json`, les cas de bruit des
 * règles de fournisseurs (v0.10.0). `--check` régénère en mémoire et compare octet pour octet, sans rien écrire.
 *
 * Un cas par règle : la forme de sa valeur d'essai, où chaque suite tirée au sort est un seul caractère répété
 * (`providerNoiseCases`). Aucune valeur relevée, aucun secret : ce fichier n'est pas exempté de la recherche de
 * secrets du dépôt. Même format que `vectors/noise.json` (tenu à la main) ; le test Go `TestNoiseProviders` exige une
 * analyse complète sans constat sur chaque cas.
 */
import { readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { jsonString } from './json.ts';
import { providerNoiseCases } from './provider-rules.ts';

const TARGET = fileURLToPath(new URL('../../vectors/noise-providers.json', import.meta.url));

export const PROVIDER_NOISE_FORMAT_VERSION = 1;

const ABOUT =
  'Corpus de bruit des règles de fournisseurs : pour chaque règle, la forme de sa valeur où chaque suite de ' +
  'caractères est un seul caractère répété. La valeur a la forme du motif, pas la diversité d’un jeton : analyse ' +
  'complète, sans constat. Écrit par generator/corpus/provider-noise.ts ; rejoué par TestNoiseProviders à chaque version.';

/** Contenu du fichier : même format que `vectors/noise.json`, un cas par ligne. */
export function serializeProviderNoise(): string {
  const lines = providerNoiseCases().cases.map((entry) => `    {"id":${jsonString(entry.id)},"input":${jsonString(entry.input)}}`);
  return (
    `{\n  "formatVersion": ${String(PROVIDER_NOISE_FORMAT_VERSION)},\n  "about": ${jsonString(ABOUT)},\n` +
    `  "cases": [\n${lines.join(',\n')}\n  ]\n}\n`
  );
}

function main(): number {
  const { values } = parseArgs({ options: { check: { type: 'boolean', default: false } }, strict: true, allowPositionals: false });
  const content = serializeProviderNoise();
  const { cases, unmatched, plausible } = providerNoiseCases();
  const summary = `${String(cases.length)} cas ; ${String(unmatched.length)} règles dont le motif refuse un caractère répété ; ${String(plausible.length)} dont les littéraux suffisent à la diversité`;
  if (values.check) {
    let present = '';
    try {
      present = readFileSync(TARGET, 'utf8');
    } catch {
      present = '';
    }
    if (present !== content) {
      process.stderr.write('Bruit des règles de fournisseurs différent : noise-providers.json\n');
      return 1;
    }
    process.stdout.write(`Bruit des règles de fournisseurs identique : ${summary}\n`);
    return 0;
  }
  const temporary = `${TARGET}.tmp-generate`;
  try {
    writeFileSync(temporary, content);
    renameSync(temporary, TARGET);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
  process.stdout.write(`Bruit des règles de fournisseurs écrit : ${summary}\n`);
  return 0;
}

if (process.argv[1] !== undefined && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])) {
  process.exitCode = main();
}
