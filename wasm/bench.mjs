// Mesures du module WebAssembly sous Node : node wasm/bench.mjs [chemin du .wasm]
// Taille (brute, gzip -9, brotli), démarrage (compilation, instanciation et _initialize, qui charge le Pack initial),
// première analyse, puis analyse d'une entrée de 64 Kio : la même que BenchmarkScan64KiB (detect/scan_test.go).
// Sortie : un document JSON. Mesures indicatives, propres à la machine qui les lance.
import { readFileSync } from 'node:fs';
import { arch, cpus, platform } from 'node:os';
import { performance } from 'node:perf_hooks';
import { WASI } from 'node:wasi';
import { brotliCompressSync, constants, gzipSync } from 'node:zlib';
import { SecretGuard } from './secret-guard.mjs';

const path = process.argv[2] ?? new URL('../dist/secret-guard.wasm', import.meta.url);
const wasmBytes = readFileSync(path);

const median = (values) => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
};
const percentile = (values, p) => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)];
};
const ms = (value) => Math.round(value * 100) / 100;

// Entrée de BenchmarkScan64KiB, reconstruite à l'identique (valeurs synthétiques assemblées à l'exécution).
function entropyValue(n) {
  const alphabet = 'aB3dE5fG7hJ9kL1mN2pQrS4tU6vW8xY0z';
  let out = '';
  for (let i = 0; i < n; i++) out += alphabet[(i * 7) % alphabet.length];
  return out;
}
function benchmarkInput() {
  const password = 'pass' + 'word';
  const unit = [
    'import { readFile } from "node:fs/promises";',
    'export async function load(path: string): Promise<Config> {',
    '  const text = await readFile(path, "utf8"); // lecture',
    '  return JSON.parse(text) as Config;',
    '}',
    'const url = "https://api.example.com/v1/items?limit=50&offset=100";',
    '2026-10-11T08:15:42.123Z INFO request completed method=GET status=200 duration=12ms',
    'DATABASE_HOST=db.internal',
    '{"name": "demo", "version": "1.2.3", "dependencies": {"zod": "^4.0.0"}}',
    '    for (let i = 0; i < items.length; i++) { total += items[i].price * items[i].quantity; }',
  ].join('\n') + '\n';
  const encoder = new TextEncoder();
  let content = encoder.encode('');
  const unitBytes = encoder.encode(unit);
  const parts = [];
  let size = 0;
  while (size < 64 << 10) {
    parts.push(unitBytes);
    size += unitBytes.length;
  }
  content = Buffer.concat(parts);
  const secrets = [
    'gh' + 'p_' + 'aB3d'.repeat(9),
    `${password} = "hunter2-${entropyValue(12)}"`,
    Buffer.from(`${password}=${entropyValue(16)}`).toString('base64'),
  ];
  secrets.forEach((secret, i) => {
    let at = Math.floor(((i + 1) * content.length) / (secrets.length + 1));
    at = content.indexOf(0x0a, at) + 1;
    content = Buffer.concat([content.subarray(0, at), Buffer.from(`${secret}\n`), content.subarray(at)]);
  });
  return new Uint8Array(content.subarray(0, 64 << 10));
}

// GOGC du module (variable d'environnement WASI) : BENCH_GOGC=400 node wasm/bench.mjs ; défaut du runtime Go sinon.
const env = process.env.BENCH_GOGC === undefined ? {} : { GOGC: process.env.BENCH_GOGC };

async function start() {
  const wasi = new WASI({ version: 'preview1', args: [], env, returnOnExit: true });
  const t0 = performance.now();
  const module = await WebAssembly.compile(wasmBytes);
  const t1 = performance.now();
  const instance = await WebAssembly.instantiate(module, { wasi_snapshot_preview1: wasi.wasiImport });
  wasi.initialize(instance);
  const t2 = performance.now();
  return { guard: new SecretGuard(instance), compile: t1 - t0, instantiate: t2 - t1, total: t2 - t0 };
}

const startups = [];
for (let i = 0; i < 10; i++) startups.push(await start());

const { guard } = await start();
const tiny = new TextEncoder().encode('const a = 1;\n');
const firstStart = performance.now();
guard.scan(tiny);
const firstScan = performance.now() - firstStart;

const input = benchmarkInput();
const check = guard.scan(input, 'typescript');
if (!check.complete || check.findings.length === 0) throw new Error(`entrée de 64 Kio : ${check.failure}`);
for (let i = 0; i < 3; i++) guard.scan(input, 'typescript');
const scans = [];
for (let i = 0; i < 20; i++) {
  const t0 = performance.now();
  guard.scan(input, 'typescript');
  scans.push(performance.now() - t0);
}

process.stdout.write(`${JSON.stringify({
  measuredAt: new Date().toISOString(),
  machine: { platform: platform(), arch: arch(), cpu: cpus()[0]?.model ?? '', logicalCpu: cpus().length, node: process.version },
  gogc: env.GOGC ?? 'défaut (100)',
  size: {
    rawBytes: wasmBytes.length,
    gzip9Bytes: gzipSync(wasmBytes, { level: 9 }).length,
    brotliBytes: brotliCompressSync(wasmBytes, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } }).length,
  },
  startupMs: {
    runs: startups.length,
    compileMedian: ms(median(startups.map((s) => s.compile))),
    instantiateAndInitializeMedian: ms(median(startups.map((s) => s.instantiate))),
    totalMedian: ms(median(startups.map((s) => s.total))),
    totalMax: ms(Math.max(...startups.map((s) => s.total))),
  },
  firstScanMs: ms(firstScan),
  scan64KiBMs: {
    runs: scans.length,
    findings: check.findings.length,
    median: ms(median(scans)),
    p95: ms(percentile(scans, 95)),
    min: ms(Math.min(...scans)),
  },
}, null, 2)}\n`);
