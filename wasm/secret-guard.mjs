// Chargeur JavaScript du module WebAssembly de Secret Guard (dist/secret-guard.wasm, WASI preview 1, mode
// bibliothèque). Sans dépendance, sans réseau ni fichier : l'hôte donne les octets du module et les fonctions WASI
// (node:wasi sous Node, la couche minimale wasi.mjs dans un navigateur ou une extension). Les points d'entrée
// node.mjs et browser.mjs les assemblent.
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
//
//   guard.setFingerprintKey(crypto.getRandomValues(new Uint8Array(32)));
//   const { failure, substitutions, text } = guard.expurgate(new TextEncoder().encode(prompt), { known });
//   // failure 'none' : text, octets du texte où chaque secret est remplacé par un Substitut typé (ghp_XXX…1) ;
//   // substitutions : [{ ruleId, secretType, byteStart, byteEnd, utf16Start, utf16End, localFingerprint, ordinal,
//   // replacement }], jamais la valeur. Sinon text vaut null : rien n'est à envoyer.
//
// Toute erreur du module (piège WebAssembly, arrêt du runtime) rend l'instance inutilisable : chaque appel suivant lève
// une erreur, jamais un résultat « rien trouvé ».

/** Taille d'entrée la plus grande analysée (detect.MaxInputBytes) ; au-delà, l'analyse rend scan_limit. */
export const MAX_INPUT_BYTES = 1 << 20;

const decoder = new TextDecoder('utf-8', { fatal: true });
const encoder = new TextEncoder();

/** Plus grand numéro d'un Substitut (detect.MaxSubstituteOrdinal). */
export const MAX_SUBSTITUTE_ORDINAL = 999;

/** Fonctions exportées par le module, et seulement elles. */
export const MODULE_EXPORTS = Object.freeze([
  '_initialize', 'memory', 'sg_alloc', 'sg_clear_fingerprint_key', 'sg_expurgate', 'sg_find_hidden', 'sg_free',
  'sg_load_pack', 'sg_redact', 'sg_scan', 'sg_scan_with_fingerprint', 'sg_set_fingerprint_key',
]);

/** Refus du module (tampon, analyse ou demande refusés) : l'instance reste utilisable. */
/**
 * Nombre de paramètres de chaque fonction exportée : un module d'une autre version (fonction absente, autre
 * signature) est refusé à la construction, jamais appelé avec des paramètres décalés.
 */
export const MODULE_ARITY = Object.freeze({
  _initialize: 0, sg_alloc: 1, sg_free: 1, sg_load_pack: 2, sg_set_fingerprint_key: 2, sg_clear_fingerprint_key: 0,
  sg_scan: 4, sg_scan_with_fingerprint: 2, sg_redact: 4, sg_find_hidden: 2, sg_expurgate: 6,
});

export class SecretGuardError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SecretGuardError';
  }
}

export class SecretGuard {
  #exports;
  #broken = false;

  /**
   * Compile (octets, ou WebAssembly.Module déjà compilé) et instancie le module, puis appelle initialize(instance)
   * (par exemple wasi.initialize), qui exécute _initialize : le Pack initial embarqué est alors chargé.
   */
  static async instantiate(wasm, wasiImport, initialize) {
    const imports = { wasi_snapshot_preview1: wasiImport };
    const instance = wasm instanceof WebAssembly.Module
      ? await WebAssembly.instantiate(wasm, imports)
      : (await WebAssembly.instantiate(wasm, imports)).instance;
    initialize(instance);
    return new SecretGuard(instance);
  }

  constructor(instance) {
    const { exports } = instance;
    if (!(exports.memory instanceof WebAssembly.Memory)) throw new TypeError('secret-guard : module sans mémoire exportée');
    for (const [name, arity] of Object.entries(MODULE_ARITY)) {
      if (typeof exports[name] !== 'function' || exports[name].length !== arity) {
        throw new TypeError(`secret-guard : module d’une autre version (${name})`);
      }
    }
    this.#exports = exports;
  }

  /** Vrai après une erreur du module : l'instance ne rend plus aucun résultat. */
  get broken() {
    return this.#broken;
  }

  /** Exécute fn sur les exportations ; toute erreur du module rend l'instance inutilisable. */
  #call(fn) {
    if (this.#broken) throw new Error('secret-guard : instance inutilisable après une erreur du module');
    try {
      return fn(this.#exports);
    } catch (error) {
      // Un refus du module laisse l'instance en état ; toute autre erreur (piège, arrêt du runtime, mémoire
      // illisible) la rend inutilisable : jamais un résultat d'un module dans un état inconnu.
      if (!(error instanceof SecretGuardError)) this.#broken = true;
      throw error;
    }
  }

  /** Copie des octets dans un tampon du module ; rend son adresse (le tampon est libéré par #free). */

  /**
   * Copie chaque tableau d'octets non vide dans un tampon du module, appelle fn(exports, [adresse, longueur]…) (adresse
   * 0 pour un tableau vide), puis efface et libère les tampons, erreur comprise.
   */
  #withInputs(inputs, fn) {
    return this.#call((exports) => {
      const pointers = [];
      try {
        for (const bytes of inputs) {
          if (bytes.length === 0) {
            pointers.push([0, 0]);
            continue;
          }
          const ptr = exports.sg_alloc(bytes.length);
          if (ptr === 0) throw new SecretGuardError('secret-guard : tampon refusé par le module');
          new Uint8Array(exports.memory.buffer, ptr, bytes.length).set(bytes);
          pointers.push([ptr, bytes.length]);
        }
        return fn(exports, pointers);
      } finally {
        for (const [ptr] of pointers) if (ptr !== 0) exports.sg_free(ptr);
      }
    });
  }

  /** Copie puis libère (en l'effaçant) un tampon de résultat (i64 : adresse << 32 | longueur) ; null pour un refus. */
  static #take(exports, packed) {
    if (packed === 0n) return null;
    const ptr = Number(packed >> 32n);
    const length = Number(packed & 0xffffffffn);
    try {
      return new Uint8Array(exports.memory.buffer, ptr, length).slice();
    } finally {
      exports.sg_free(ptr);
    }
  }

  /** Coupe un résultat « document JSON, \n, texte » ; le texte n'est gardé que pour l'issue none. */
  static #documentAndText(buffer) {
    const end = buffer.indexOf(0x0a);
    if (end < 0) throw new Error('secret-guard : résultat illisible');
    const document = JSON.parse(decoder.decode(buffer.subarray(0, end)));
    const text = document.failure === 'none' ? buffer.slice(end + 1) : null;
    buffer.fill(0); // efface la copie du texte
    return { document, text };
  }

  /**
   * Analyse des octets (Uint8Array). languageId facultatif (« typescript », « dotenv »…). Au-delà de MAX_INPUT_BYTES,
   * seuls MAX_INPUT_BYTES + 1 octets sont copiés : le module rend scan_limit sans rien analyser.
   */
  scan(bytes, languageId = '') {
    const input = bytes.subarray(0, MAX_INPUT_BYTES + 1);
    if (input.length === 0) return { complete: true, failure: 'none', findings: [] };
    return this.#withInputs([input, encoder.encode(languageId)], (exports, [[ptr, length], [lang, langLength]]) => {
      const out = SecretGuard.#take(exports, exports.sg_scan(ptr, length, lang, langLength));
      if (out === null) throw new SecretGuardError('secret-guard : analyse refusée par le module');
      return JSON.parse(decoder.decode(out));
    });
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
    return this.#withInputs([input, encoder.encode(languageId)], (exports, [[ptr, length], [lang, langLength]]) => {
      const out = SecretGuard.#take(exports, exports.sg_redact(ptr, length, lang, langLength));
      if (out === null) throw new SecretGuardError('secret-guard : masquage refusé par le module');
      const { document, text } = SecretGuard.#documentAndText(out);
      return { ...document, redacted: text };
    });
  }

  /**
   * Expurge des octets (Uint8Array) : la partie secrète de chaque constat est remplacée par un Substitut typé (préfixe
   * public de la règle, des X, un numéro de 1 à 999, à la longueur de la valeur), puis le texte expurgé est analysé de
   * nouveau. Exige setFingerprintKey : le numéro d'un Substitut suit l'Empreinte locale de sa valeur. options.known,
   * les Substituts déjà posés ([{ localFingerprint, ordinal }]) : une même valeur reprend son numéro ; une nouvelle
   * prend le numéro suivant, au-dessus du plus grand connu et d'au moins options.minOrdinal. Rend { failure, initial,
   * final, substitutions, text } : failure 'none' avec text, les octets du texte expurgé ; sinon ('incomplete',
   * 'residual', 'ordinal_refused') text null et aucune Substitution : rien n'est à envoyer.
   */
  expurgate(bytes, options = {}) {
    const input = bytes.subarray(0, MAX_INPUT_BYTES + 1);
    const request = encoder.encode(JSON.stringify({ known: options.known ?? [], minOrdinal: options.minOrdinal ?? 0 }));
    const language = encoder.encode(options.languageId ?? '');
    if (input.length === 0) {
      const empty = { complete: true, failure: 'none', findings: [] };
      return { failure: 'none', initial: empty, final: empty, substitutions: [], text: new Uint8Array(0) };
    }
    return this.#withInputs([input, language, request], (exports, [[ptr, length], [lang, langLength], [req, reqLength]]) => {
      const out = SecretGuard.#take(exports, exports.sg_expurgate(ptr, length, lang, langLength, req, reqLength));
      if (out === null) throw new SecretGuardError('secret-guard : expurgation refusée par le module (clé d’Empreinte locale absente ou demande hors forme)');
      const { document, text } = SecretGuard.#documentAndText(out);
      return { ...document, text };
    });
  }

  /** Analyse avec l'Empreinte locale de chaque constat ; exige setFingerprintKey. */
  scanWithFingerprint(bytes) {
    const input = bytes.subarray(0, MAX_INPUT_BYTES + 1);
    if (input.length === 0) return { complete: true, failure: 'none', findings: [] };
    return this.#withInputs([input], (exports, [[ptr, length]]) => {
      const out = SecretGuard.#take(exports, exports.sg_scan_with_fingerprint(ptr, length));
      if (out === null) throw new SecretGuardError('secret-guard : analyse refusée par le module');
      return JSON.parse(decoder.decode(out));
    });
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
    return this.#withInputs([input], (exports, [[ptr, length]]) => {
      const out = SecretGuard.#take(exports, exports.sg_find_hidden(ptr, length));
      if (out === null) throw new SecretGuardError('secret-guard : analyse refusée par le module');
      return JSON.parse(decoder.decode(out));
    });
  }

  /** Remplace le Pack initial par un autre (octets JSON du schéma RulePack) ; faux si le Pack est refusé. */
  loadPack(bytes) {
    if (bytes.length === 0) return false;
    return this.#withInputs([bytes], (exports, [[ptr, length]]) => exports.sg_load_pack(ptr, length) === 0);
  }

  /** Garde une clé d'Empreinte locale de 32 octets (copiée puis effacée dans le module) ; faux si refusée. */
  setFingerprintKey(key) {
    if (key.length === 0) return false;
    return this.#withInputs([key], (exports, [[ptr, length]]) => exports.sg_set_fingerprint_key(ptr, length) === 0);
  }

  /** Efface la clé d'Empreinte locale. */
  clearFingerprintKey() {
    this.#call((exports) => exports.sg_clear_fingerprint_key());
  }
}
