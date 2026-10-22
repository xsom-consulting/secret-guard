// Point d'entrée pour un navigateur, une extension de navigateur ou un service worker : le module de Secret Guard sous
// la couche WASI minimale (wasi.mjs). Ce chargeur ne télécharge rien et ne lit aucun fichier : l'appelant donne les
// octets du module, qu'il a lui-même lus (fetch d'une ressource de son extension, par exemple) et, de préférence,
// vérifiés contre leur empreinte SHA-256 publiée.
//
//   import { createSecretGuard } from '@xsom-consulting/secret-guard-wasm/browser';
//   const guard = await createSecretGuard(wasmBytes);
//
// Une page d'extension Manifest V3 doit déclarer 'wasm-unsafe-eval' dans sa politique de sécurité du contenu.
import { SecretGuard } from './secret-guard.mjs';
import { createMinimalWasi } from './wasi.mjs';

export * from './secret-guard.mjs';
export { createMinimalWasi, ERRNO, WASI_FUNCTIONS, WasiExit } from './wasi.mjs';

/** Adresse du module livré dans le paquet, relative à ce fichier (pour un empaqueteur qui copie les ressources). */
export const wasmUrl = new URL('./secret-guard.wasm', import.meta.url);

/** Instancie le module (octets ou WebAssembly.Module) sous la couche WASI minimale ; options : celles de createMinimalWasi. */
export async function createSecretGuard(wasm, options = {}) {
  const wasi = createMinimalWasi(options);
  return SecretGuard.instantiate(wasm, wasi.wasiImport, (instance) => wasi.initialize(instance));
}
