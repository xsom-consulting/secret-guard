// Usage typé des points d'entrée du paquet : vérifié par tsc (wasm/tsconfig.json), jamais exécuté.
import { createSecretGuard as createBrowser, createMinimalWasi, WASI_FUNCTIONS, type MinimalWasiOptions } from './browser.mjs';
import { createSecretGuard as createNode, wasmUrl } from './node.mjs';
import type { ExpurgateResult, Finding, ScanResult, Substitution } from './secret-guard.mjs';

export async function usage(bytes: Uint8Array): Promise<void> {
  const options: MinimalWasiOptions = { onOutput: (fd, output) => void [fd, output.length] };
  const guard = await createBrowser(bytes, options);
  const result: ScanResult = guard.scan(new TextEncoder().encode('x'), 'typescript');
  const first: Finding | undefined = result.findings[0];
  if (result.complete && first !== undefined) void first.byteEnd;
  guard.setFingerprintKey(new Uint8Array(32));
  const expurgated: ExpurgateResult = guard.expurgate(new Uint8Array(1), { known: [{ localFingerprint: 'a'.repeat(32), ordinal: 1 }], minOrdinal: 2 });
  const substitutions: readonly Substitution[] = expurgated.substitutions;
  void substitutions;
  if (expurgated.text !== null) void expurgated.text.length;
  const other = await createNode(bytes);
  void other.broken;
  void [wasmUrl.href, WASI_FUNCTIONS.length, createMinimalWasi().wasiImport];
}
