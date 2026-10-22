// Parité du module WebAssembly avec le moteur Go : node --test wasm/parity.test.mjs (Go et le module construit requis).
// tools/wasmparity exécute en Go natif, sur tout le corpus du module (vectors/detection/, 823 cas ; vectors/expurgate.json ;
// vectors/hidden.json), l'analyse, l'expurgation et les instructions cachées ; chaque chargeur du paquet exécute les
// mêmes cas, sur les mêmes octets, dans le module WebAssembly, et doit rendre les mêmes documents (et le même texte
// expurgé). Un écart n'affiche que l'identifiant du cas, jamais son entrée.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { loaders } from './loaders.test-helpers.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const output = execFileSync('go', ['run', './tools/wasmparity', '-root', root], {
  cwd: root, encoding: 'utf8', maxBuffer: 256 << 20, stdio: ['ignore', 'pipe', 'inherit'],
});
const [summary, ...lines] = output.trimEnd().split('\n').map((line) => JSON.parse(line));
const key = Uint8Array.from({ length: 32 }, (_, i) => i + 1); // FingerprintKey de tools/wasmparity

/** Document natif, octets d'entrée et texte attendu d'une ligne. */
const decode = (base64) => Uint8Array.from(Buffer.from(base64, 'base64'));

test('le décompte natif couvre tout le corpus', () => {
  assert.equal(summary.kind, 'summary');
  assert.equal(summary.scan, 823);
  assert.ok(summary.expurgate > summary.scan);
  assert.ok(summary.hidden > 0);
  const counts = { scan: 0, expurgate: 0, hidden: 0 };
  for (const line of lines) counts[line.kind]++;
  assert.deepEqual(counts, { scan: summary.scan, expurgate: summary.expurgate, hidden: summary.hidden });
});

for (const { name, load } of loaders) {
  test(`parité à 100 % avec le moteur Go (${name})`, async () => {
    const guard = await load();
    assert.equal(guard.setFingerprintKey(key), true);
    const differences = [];
    for (const line of lines) {
      const input = decode(line.input);
      const native = JSON.parse(line.native.split('\n')[0]);
      let got;
      let text;
      switch (line.kind) {
        case 'scan':
          got = guard.scan(input, line.languageId ?? '');
          break;
        case 'expurgate': {
          const { text: expurgated, ...document } = guard.expurgate(input, { languageId: line.languageId ?? '', minOrdinal: line.minOrdinal ?? 0 });
          got = document;
          text = expurgated;
          break;
        }
        case 'hidden':
          got = guard.findHidden(input);
          break;
        default:
          throw new Error(`sorte de cas inconnue : ${line.kind}`);
      }
      try {
        assert.deepStrictEqual(got, native);
        if (line.kind === 'expurgate') {
          if (line.text === undefined) assert.equal(text, null);
          else assert.deepStrictEqual(text, decode(line.text));
        }
      } catch {
        differences.push(`${line.kind} ${line.id}`);
      }
    }
    assert.equal(guard.broken, false);
    assert.deepEqual(differences, [], `${differences.length} cas en écart`);
  });
}
