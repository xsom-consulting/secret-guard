// Chargeur JavaScript du module WebAssembly de Secret Guard (dist/secret-guard.wasm, WASI preview 1, mode
// bibliothèque). Sans dépendance : l'hôte fournit les fonctions WASI (node:wasi sous Node, une couche WASI dans un
// navigateur ou une extension VS Code pour le web).
//
//   import { WASI } from 'node:wasi';
//   import { SecretGuard } from './secret-guard.mjs';
//   const wasi = new WASI({ version: 'preview1', args: [], env: {}, returnOnExit: true });
//   const guard = await SecretGuard.instantiate(wasmBytes, wasi.wasiImport, (instance) => wasi.initialize(instance));
//   const result = guard.scan(new TextEncoder().encode(text), 'typescript');
//   // result : { complete, failure, findings: [{ ruleId, secretType, encoding, score, level, byteStart, byteEnd }] }
//   const report = guard.findHidden(new TextEncoder().encode(text));
//   // report : { complete, hidden, findings: [{ kind, line, column, count, byteStart, byteEnd }] }
//
// Décider sur result.complete et result.failure : une analyse incomplète (entrée de plus de 1 Mio, budget épuisé)
// n'a aucun constat et ne vaut jamais « rien trouvé ». Aucun constat ne porte la valeur détectée.
//
//   const { failure, redacted } = guard.redact(new TextEncoder().encode(clipboardText));
//   // failure : 'none' (redacted : octets du texte masqué), 'incomplete' ou 'residual' (redacted : null, ne rien coller)

/** Taille d'entrée la plus grande analysée (detect.MaxInputBytes) ; au-delà, l'analyse rend scan_limit. */
export const MAX_INPUT_BYTES = 1 << 20;

const decoder = new TextDecoder('utf-8', { fatal: true });
const encoder = new TextEncoder();

export class SecretGuard {
  #exports;

  /**
   * Compile et instancie le module, puis appelle initialize(instance) (par exemple wasi.initialize), qui exécute
   * _initialize : le Pack initial embarqué est alors chargé.
   */
  static async instantiate(wasmBytes, wasiImport, initialize) {
    const { instance } = await WebAssembly.instantiate(wasmBytes, { wasi_snapshot_preview1: wasiImport });
    initialize(instance);
    return new SecretGuard(instance);
  }

  constructor(instance) {
    this.#exports = instance.exports;
  }

  /** Copie des octets dans un tampon du module ; rend son adresse (le tampon est libéré par #free). */
  #copyIn(bytes) {
    const ptr = this.#exports.sg_alloc(bytes.length);
    if (ptr === 0) throw new RangeError('secret-guard : tampon refusé par le module');
    new Uint8Array(this.#exports.memory.buffer, ptr, bytes.length).set(bytes);
    return ptr;
  }

  /** Lit puis libère le document JSON d'un résultat (i64 : adresse << 32 | longueur). */
  #readResult(packed) {
    if (packed === 0n) throw new Error('secret-guard : analyse refusée par le module');
    const ptr = Number(packed >> 32n);
    const length = Number(packed & 0xffffffffn);
    try {
      return JSON.parse(decoder.decode(new Uint8Array(this.#exports.memory.buffer, ptr, length)));
    } finally {
      this.#exports.sg_free(ptr);
    }
  }

  /**
   * Analyse des octets (Uint8Array). languageId facultatif (« typescript », « dotenv »…). Au-delà de MAX_INPUT_BYTES,
   * seuls MAX_INPUT_BYTES + 1 octets sont copiés : le module rend scan_limit sans rien analyser.
   */
  scan(bytes, languageId = '') {
    const input = bytes.subarray(0, MAX_INPUT_BYTES + 1);
    if (input.length === 0) return { complete: true, failure: 'none', findings: [] };
    const ptr = this.#copyIn(input);
    const language = encoder.encode(languageId);
    const languagePtr = language.length === 0 ? 0 : this.#copyIn(language);
    try {
      return this.#readResult(this.#exports.sg_scan(ptr, input.length, languagePtr, language.length));
    } finally {
      this.#exports.sg_free(ptr); // efface la copie de l'entrée
      if (languagePtr !== 0) this.#exports.sg_free(languagePtr);
    }
  }

  /**
   * Masque des octets (Uint8Array) : chaque secret détecté est remplacé par un libellé <REDACTED_règle>, puis le texte
   * masqué est analysé de nouveau. Rend { failure, initial, final, redacted } : failure 'none' avec redacted, les
   * octets du texte masqué (copie que l'appelant peut effacer) ; 'incomplete' (analyse incomplète, entrée de plus de
   * 1 Mio comprise) ou 'residual' (un secret subsiste après masquage) avec redacted null : rien n'est à envoyer.
   * initial et final sont les analyses de l'entrée et du texte masqué, dans la forme de scan.
   */
  redact(bytes, languageId = '') {
    const input = bytes.subarray(0, MAX_INPUT_BYTES + 1);
    if (input.length === 0) {
      const empty = { complete: true, failure: 'none', findings: [] };
      return { failure: 'none', initial: empty, final: empty, redacted: new Uint8Array(0) };
    }
    const ptr = this.#copyIn(input);
    const language = encoder.encode(languageId);
    const languagePtr = language.length === 0 ? 0 : this.#copyIn(language);
    try {
      const packed = this.#exports.sg_redact(ptr, input.length, languagePtr, language.length);
      if (packed === 0n) throw new Error('secret-guard : masquage refusé par le module');
      const out = Number(packed >> 32n);
      const length = Number(packed & 0xffffffffn);
      try {
        const buffer = new Uint8Array(this.#exports.memory.buffer, out, length);
        const end = buffer.indexOf(0x0a);
        const document = JSON.parse(decoder.decode(buffer.subarray(0, end)));
        const redacted = document.failure === 'none' ? buffer.slice(end + 1) : null;
        return { ...document, redacted };
      } finally {
        this.#exports.sg_free(out); // efface la copie du texte masqué dans le module
      }
    } finally {
      this.#exports.sg_free(ptr);
      if (languagePtr !== 0) this.#exports.sg_free(languagePtr);
    }
  }

  /** Analyse avec l'Empreinte locale de chaque constat ; exige setFingerprintKey. */
  scanWithFingerprint(bytes) {
    const input = bytes.subarray(0, MAX_INPUT_BYTES + 1);
    if (input.length === 0) return { complete: true, failure: 'none', findings: [] };
    const ptr = this.#copyIn(input);
    try {
      return this.#readResult(this.#exports.sg_scan_with_fingerprint(ptr, input.length));
    } finally {
      this.#exports.sg_free(ptr);
    }
  }

  /**
   * Relève les instructions cachées d'un texte (Uint8Array) : caractères d'étiquette Unicode, contrôles
   * bidirectionnels, suites de caractères invisibles, suites de sélecteurs de variante. Rend { complete, hidden,
   * findings: [{ kind, line, column, count, byteStart, byteEnd }] }, jamais ce que les caractères écrivent. Au-delà de
   * MAX_INPUT_BYTES, seuls MAX_INPUT_BYTES + 1 octets sont copiés : le rapport est incomplet (complete: false).
   */
  findHidden(bytes) {
    const input = bytes.subarray(0, MAX_INPUT_BYTES + 1);
    if (input.length === 0) return { complete: true, hidden: 0, findings: [] };
    const ptr = this.#copyIn(input);
    try {
      return this.#readResult(this.#exports.sg_find_hidden(ptr, input.length));
    } finally {
      this.#exports.sg_free(ptr);
    }
  }

  /** Remplace le Pack initial par un autre (octets JSON du schéma RulePack) ; faux si le Pack est refusé. */
  loadPack(bytes) {
    const ptr = this.#copyIn(bytes);
    try {
      return this.#exports.sg_load_pack(ptr, bytes.length) === 0;
    } finally {
      this.#exports.sg_free(ptr);
    }
  }

  /** Garde une clé d'Empreinte locale de 32 octets (copiée puis effacée dans le module) ; faux si refusée. */
  setFingerprintKey(key) {
    const ptr = this.#copyIn(key);
    try {
      return this.#exports.sg_set_fingerprint_key(ptr, key.length) === 0;
    } finally {
      this.#exports.sg_free(ptr);
    }
  }

  /** Efface la clé d'Empreinte locale. */
  clearFingerprintKey() {
    this.#exports.sg_clear_fingerprint_key();
  }
}
