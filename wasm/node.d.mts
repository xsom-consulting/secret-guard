// Types du point d'entrée pour Node (node.mjs).
import type { SecretGuard } from './secret-guard.mjs';

export * from './secret-guard.mjs';
/** Adresse du module livré dans le paquet. */
export declare const wasmUrl: URL;
/** Instancie le module sous node:wasi, sans aucun accès au système de fichiers. */
export declare function createSecretGuard(wasm: BufferSource | WebAssembly.Module): Promise<SecretGuard>;
