// Prépare le paquet npm dans un dossier à part : node wasm/stage.mjs [--out dist/npm] [--version x.y.z]
// Copie les fichiers de « files » (package.json) : chargeurs et types de wasm/, module construit dist/secret-guard.wasm,
// LICENSE et NOTICE de la racine. Avec --version (étiquette de la Release sans « v »), refuse un package.json d'une
// autre version. Aucun réseau.
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const { values } = parseArgs({ options: { out: { type: 'string', default: join(root, 'dist', 'npm') }, version: { type: 'string' } } });

const manifest = JSON.parse(readFileSync(join(here, 'package.json'), 'utf8'));
if (values.version !== undefined && values.version !== manifest.version) {
  console.error(`stage : package.json en version ${manifest.version}, étiquette ${values.version}`);
  process.exit(1);
}
const sources = {
  'secret-guard.wasm': join(root, 'dist', 'secret-guard.wasm'),
  LICENSE: join(root, 'LICENSE'),
  NOTICE: join(root, 'NOTICE'),
};
const out = resolve(values.out);
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
for (const file of ['package.json', ...manifest.files]) {
  const source = sources[file] ?? join(here, file);
  if (!existsSync(source)) {
    console.error(`stage : fichier absent : ${source}`);
    process.exit(1);
  }
  copyFileSync(source, join(out, file));
}
console.log(`Paquet ${manifest.name}@${manifest.version} préparé dans ${out}`);
