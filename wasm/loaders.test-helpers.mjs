// Aide des essais : charge le module construit (dist/secret-guard.wasm) par chacun des deux points d'entrée du paquet.
import { readFileSync } from 'node:fs';
import { createSecretGuard as createBrowser } from './browser.mjs';
import { createSecretGuard as createNode } from './node.mjs';

export const wasmBytes = readFileSync(new URL('../dist/secret-guard.wasm', import.meta.url));
export const wasmModule = new WebAssembly.Module(wasmBytes);

/** Les deux chargeurs : node:wasi (node.mjs) et la couche WASI minimale (browser.mjs). */
export const loaders = [
  { name: 'node:wasi', load: () => createNode(wasmBytes) },
  { name: 'couche WASI minimale', load: () => createBrowser(wasmModule) },
];
