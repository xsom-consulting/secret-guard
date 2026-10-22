// Types de la couche WASI preview 1 minimale (wasi.mjs).
import type { WasiImport } from './secret-guard.mjs';

export declare const ERRNO: Readonly<{ SUCCESS: 0; BADF: 8; INVAL: 28; NOSYS: 52 }>;
/** Fonctions fournies au module, et seulement elles. */
export declare const WASI_FUNCTIONS: readonly string[];

/** Levée quand le module appelle proc_exit. */
export declare class WasiExit extends Error {
  readonly code: number;
  constructor(code: number);
}

export interface MinimalWasiOptions {
  /** Reçoit ce que le module écrit sur 1 ou 2 (par défaut : jeté). */
  readonly onOutput?: (fd: 1 | 2, bytes: Uint8Array) => void;
  /** Remplit un tableau d'octets aléatoires (par défaut crypto.getRandomValues). */
  readonly random?: (array: Uint8Array) => void;
  /** Heure en millisecondes depuis l'époque (par défaut Date.now). */
  readonly now?: () => number;
  /** Horloge monotone en millisecondes (par défaut performance.now). */
  readonly monotonic?: () => number;
}

export interface MinimalWasi {
  readonly wasiImport: WasiImport;
  initialize(instance: WebAssembly.Instance): void;
}

export declare function createMinimalWasi(options?: MinimalWasiOptions): MinimalWasi;
