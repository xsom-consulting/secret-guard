// Types du chargeur du module WebAssembly de Secret Guard (secret-guard.mjs).

/** Taille d'entrée la plus grande analysée, en octets ; au-delà, l'analyse rend scan_limit. */
export declare const MAX_INPUT_BYTES: number;
/** Plus grand numéro d'un Substitut. */
export declare const MAX_SUBSTITUTE_ORDINAL: number;
/** Fonctions exportées par le module. */
export declare const MODULE_EXPORTS: readonly string[];
/** Nombre de paramètres de chaque fonction exportée. */
export declare const MODULE_ARITY: Readonly<Record<string, number>>;

export type Level = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ScanFailure = 'none' | 'scan_limit' | 'scan_error' | 'custom_budget' | 'custom_too_many' | (string & {});
export type SanitizeFailure = 'none' | 'incomplete' | 'residual' | 'ordinal_refused' | (string & {});

/** Constat : jamais la valeur détectée. Étendue [byteStart, byteEnd) en octets de l'entrée. */
export interface Finding {
  readonly ruleId: string;
  readonly secretType: string;
  readonly encoding: string;
  readonly score: number;
  readonly level: Level;
  readonly byteStart: number;
  readonly byteEnd: number;
  /** Présente seulement pour scanWithFingerprint : 32 caractères hexadécimaux. */
  readonly localFingerprint?: string;
}

/** Résultat d'une analyse. complete faux : aucun constat, ne jamais lire comme « rien trouvé ». */
export interface ScanResult {
  readonly complete: boolean;
  readonly failure: ScanFailure;
  readonly findings: readonly Finding[];
}

export interface RedactResult {
  readonly failure: SanitizeFailure;
  readonly initial: ScanResult;
  readonly final: ScanResult;
  /** Octets du texte masqué pour failure 'none', sinon null (rien n'est à envoyer). */
  readonly redacted: Uint8Array | null;
}

/** Substitut posé par l'expurgation : positions dans le texte d'origine, jamais la valeur remplacée. */
export interface Substitution {
  readonly ruleId: string;
  readonly secretType: string;
  readonly byteStart: number;
  readonly byteEnd: number;
  readonly utf16Start: number;
  readonly utf16End: number;
  readonly localFingerprint: string;
  readonly ordinal: number;
  readonly replacement: string;
}

/** Substitut déjà posé par l'appelant : Empreinte locale de la valeur et numéro de 1 à 999. */
export interface KnownSubstitute {
  readonly localFingerprint: string;
  readonly ordinal: number;
}

export interface ExpurgateOptions {
  readonly known?: readonly KnownSubstitute[];
  /** Plus petit numéro d'un nouveau Substitut (0 à 999). */
  readonly minOrdinal?: number;
  readonly languageId?: string;
}

export interface ExpurgateResult {
  readonly failure: SanitizeFailure;
  readonly initial: ScanResult;
  readonly final: ScanResult;
  /** Vide sauf pour failure 'none'. */
  readonly substitutions: readonly Substitution[];
  /** Octets du texte expurgé pour failure 'none', sinon null (rien n'est à envoyer). */
  readonly text: Uint8Array | null;
}

export type HiddenKind = 'tag_characters' | 'bidi_controls' | 'invisible_characters' | 'variation_selectors' | (string & {});

export interface HiddenFinding {
  readonly kind: HiddenKind;
  readonly line: number;
  readonly column: number;
  readonly count: number;
  readonly byteStart: number;
  readonly byteEnd: number;
}

export interface HiddenReport {
  readonly complete: boolean;
  readonly hidden: number;
  readonly findings: readonly HiddenFinding[];
}

/** Refus du module (tampon, analyse ou demande refusés) : l'instance reste utilisable. */
export declare class SecretGuardError extends Error {}

/** Fonctions WASI données au module (wasi_snapshot_preview1). */
export type WasiImport = Record<string, (...args: never[]) => unknown>;

export declare class SecretGuard {
  static instantiate(
    wasm: BufferSource | WebAssembly.Module,
    wasiImport: WasiImport,
    initialize: (instance: WebAssembly.Instance) => void,
  ): Promise<SecretGuard>;
  constructor(instance: WebAssembly.Instance);
  /** Vrai après une erreur du module : l'instance ne rend plus aucun résultat. */
  readonly broken: boolean;
  scan(bytes: Uint8Array, languageId?: string): ScanResult;
  scanWithFingerprint(bytes: Uint8Array): ScanResult;
  redact(bytes: Uint8Array, languageId?: string): RedactResult;
  expurgate(bytes: Uint8Array, options?: ExpurgateOptions): ExpurgateResult;
  findHidden(bytes: Uint8Array): HiddenReport;
  loadPack(bytes: Uint8Array): boolean;
  setFingerprintKey(key: Uint8Array): boolean;
  clearFingerprintKey(): void;
}
