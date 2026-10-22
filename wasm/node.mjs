// Point d'entrée pour Node : le module de Secret Guard sous node:wasi, sans argument, sans variable d'environnement et
// sans aucun répertoire ouvert (un arrêt du runtime lève une erreur, jamais process.exit). Ce chargeur ne lit aucun fichier et n'ouvre aucune connexion : l'appelant donne les
// octets du module (par exemple readFile(wasmUrl)).
//
//   import { readFile } from 'node:fs/promises';
//   import { createSecretGuard, wasmUrl } from '@xsom-consulting/secret-guard-wasm/node';
//   const guard = await createSecretGuard(await readFile(wasmUrl));
import { WASI } from 'node:wasi';
import { SecretGuard } from './secret-guard.mjs';

export * from './secret-guard.mjs';

/** Adresse du module livré dans le paquet (à lire par l'appelant). */
export const wasmUrl = new URL('./secret-guard.wasm', import.meta.url);

/** Instancie le module (octets ou WebAssembly.Module) sous node:wasi, sans aucun accès au système de fichiers. */
export async function createSecretGuard(wasm) {
  const wasi = new WASI({ version: 'preview1', args: [], env: {}, preopens: {}, returnOnExit: true });
  return SecretGuard.instantiate(wasm, wasi.wasiImport, (instance) => wasi.initialize(instance));
}
