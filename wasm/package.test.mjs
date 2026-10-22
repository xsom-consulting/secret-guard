// Paquet npm : node --test wasm/package.test.mjs (module construit requis). Prépare le paquet (stage.mjs) dans un
// dossier temporaire, vérifie son contenu (liste fermée « files », chaque cible de « exports » présente, types de chaque
// point d'entrée), puis charge le module par le point d'entrée Node du paquet préparé.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const dir = mkdtempSync(join(tmpdir(), 'secret-guard-npm-'));
after(() => rmSync(dir, { recursive: true, force: true }));
execFileSync(process.execPath, [fileURLToPath(new URL('./stage.mjs', import.meta.url)), '--out', dir], { stdio: 'ignore' });
const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));

test('paquet : nom, licence, contenu en liste fermée', () => {
  assert.equal(manifest.name, '@xsom-consulting/secret-guard-wasm');
  assert.equal(manifest.license, 'Apache-2.0');
  assert.match(manifest.version, /^\d+\.\d+\.\d+$/);
  assert.equal(manifest.dependencies, undefined, 'aucune dépendance');
  assert.equal(manifest.scripts, undefined, 'aucun script (ni postinstall)');
  assert.deepEqual(readdirSync(dir).sort(), ['package.json', ...manifest.files].sort());
  assert.ok(readFileSync(join(dir, 'LICENSE'), 'utf8').includes('Apache License'));
});

test('chaque cible de « exports » existe, chaque point d’entrée JavaScript a ses types', () => {
  for (const [entry, target] of Object.entries(manifest.exports)) {
    const targets = typeof target === 'string' ? [target] : Object.values(target);
    for (const file of targets) assert.ok(manifest.files.includes(file.slice(2)) || file === './package.json', `${entry} → ${file}`);
    if (typeof target !== 'string') {
      assert.ok(target.types.endsWith('.d.mts') && target.default.endsWith('.mjs'), entry);
      assert.equal(target.types.replace('.d.mts', ''), target.default.replace('.mjs', ''), entry);
    }
  }
});

test('le paquet préparé se charge sous Node et analyse', async () => {
  const { createSecretGuard, wasmUrl } = await import(pathToFileURL(join(dir, 'node.mjs')).href);
  const guard = await createSecretGuard(readFileSync(wasmUrl));
  const token = 'gh' + 'p_' + 'aB3d'.repeat(9);
  assert.equal(guard.scan(new TextEncoder().encode(`TOKEN=${token}`)).findings[0].ruleId, 'github_token');
});

test('npm pack reprend exactement les fichiers préparés', () => {
  const [packed] = JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: dir, encoding: 'utf8' }));
  assert.deepEqual(packed.files.map((f) => f.path).sort(), ['package.json', ...manifest.files].sort());
});
