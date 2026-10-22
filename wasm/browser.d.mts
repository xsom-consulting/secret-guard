// Types du point d'entrée pour un navigateur ou une extension (browser.mjs).
import type { SecretGuard } from './secret-guard.mjs';
import type { MinimalWasiOptions } from './wasi.mjs';

export * from './secret-guard.mjs';
export { createMinimalWasi, ERRNO, WASI_FUNCTIONS, WasiExit } from './wasi.mjs';
export type { MinimalWasi, MinimalWasiOptions } from './wasi.mjs';
/** Adresse du module livré dans le paquet, relative à ce fichier. */
export declare const wasmUrl: URL;
/** Instancie le module sous la couche WASI minimale. */
export declare function createSecretGuard(wasm: BufferSource | WebAssembly.Module, options?: MinimalWasiOptions): Promise<SecretGuard>;
