// Couche WASI preview 1 minimale pour le module de Secret Guard, hors de Node (navigateur, extension de navigateur,
// extension VS Code pour le web). Elle ne donne au module que ce que demande le runtime Go : aucun argument, aucune
// variable d'environnement, aucun répertoire ouvert (fd_prestat_get rend EBADF), aucun fichier, aucun réseau. Les
// seules sources extérieures sont l'horloge et le hasard cryptographique (tables de hachage de Go), lus à la demande.
// Ce que le module écrirait sur les sorties standard (erreur fatale du runtime) est jeté, sauf si l'appelant donne
// onOutput.
//
//   const wasi = createMinimalWasi();
//   const guard = await SecretGuard.instantiate(wasmBytes, wasi.wasiImport, (instance) => wasi.initialize(instance));
//
// Aucune fonction de cette couche n'ouvre de fichier ni de connexion : un import WASI absent de cette liste fait
// échouer l'instanciation (WebAssembly.LinkError), jamais un appel silencieux.

/** Codes d'erreur WASI utilisés (errno). */
export const ERRNO = Object.freeze({ SUCCESS: 0, BADF: 8, INVAL: 28, NOSYS: 52 });

/** Fonctions importées par le module de Secret Guard, et seulement elles : la liste fermée de ce que la couche fournit. */
export const WASI_FUNCTIONS = Object.freeze([
  'args_get', 'args_sizes_get', 'clock_time_get', 'environ_get', 'environ_sizes_get', 'fd_close', 'fd_fdstat_get',
  'fd_fdstat_set_flags', 'fd_prestat_dir_name', 'fd_prestat_get', 'fd_read', 'fd_write', 'poll_oneoff', 'proc_exit',
  'random_get', 'sched_yield',
]);

/** Erreur levée quand le module appelle proc_exit : l'instance n'est plus utilisable. */
export class WasiExit extends Error {
  constructor(code) {
    super(`secret-guard : le module s'est arrêté (code ${code})`);
    this.name = 'WasiExit';
    this.code = code;
  }
}

const STDIO = new Set([0, 1, 2]);
const FILETYPE_CHARACTER_DEVICE = 2;
const EVENTTYPE_CLOCK = 0;
const SUBSCRIPTION_SIZE = 48;
const EVENT_SIZE = 32;
const RANDOM_CHUNK = 65536; // crypto.getRandomValues refuse plus de 65 536 octets par appel.

/**
 * Crée la couche WASI. options.onOutput(fd, octets), facultatif, reçoit ce que le module écrit sur 1 ou 2 ;
 * options.random(tableau) remplit un Uint8Array (par défaut crypto.getRandomValues) ; options.now() rend l'heure en
 * millisecondes depuis l'époque (par défaut Date.now) et options.monotonic() une horloge monotone en millisecondes
 * (par défaut performance.now).
 */
export function createMinimalWasi(options = {}) {
  const random = options.random ?? ((array) => globalThis.crypto.getRandomValues(array));
  const now = options.now ?? (() => Date.now());
  const monotonic = options.monotonic ?? (() => globalThis.performance.now());
  const onOutput = options.onOutput;
  let memory;

  const view = () => new DataView(memory.buffer);
  const bytes = (ptr, length) => new Uint8Array(memory.buffer, ptr, length);
  const nanoseconds = (milliseconds) => BigInt(Math.round(milliseconds * 1e6));

  const wasiImport = {
    args_sizes_get(argcPtr, argvBufSizePtr) {
      view().setUint32(argcPtr, 0, true);
      view().setUint32(argvBufSizePtr, 0, true);
      return ERRNO.SUCCESS;
    },
    args_get() {
      return ERRNO.SUCCESS;
    },
    environ_sizes_get(countPtr, sizePtr) {
      view().setUint32(countPtr, 0, true);
      view().setUint32(sizePtr, 0, true);
      return ERRNO.SUCCESS;
    },
    environ_get() {
      return ERRNO.SUCCESS;
    },
    clock_time_get(id, _precision, timePtr) {
      let time;
      if (id === 0) time = nanoseconds(now());
      else if (id === 1 || id === 2 || id === 3) time = nanoseconds(monotonic());
      else return ERRNO.INVAL;
      view().setBigUint64(timePtr, time, true);
      return ERRNO.SUCCESS;
    },
    random_get(ptr, length) {
      for (let offset = 0; offset < length; offset += RANDOM_CHUNK) {
        random(bytes(ptr + offset, Math.min(RANDOM_CHUNK, length - offset)));
      }
      return ERRNO.SUCCESS;
    },
    fd_write(fd, iovs, iovsLength, writtenPtr) {
      if (fd !== 1 && fd !== 2) return ERRNO.BADF;
      let written = 0;
      for (let i = 0; i < iovsLength; i++) {
        const ptr = view().getUint32(iovs + i * 8, true);
        const length = view().getUint32(iovs + i * 8 + 4, true);
        if (onOutput) onOutput(fd, bytes(ptr, length).slice());
        written += length;
      }
      view().setUint32(writtenPtr, written, true);
      return ERRNO.SUCCESS;
    },
    fd_read(fd, _iovs, _iovsLength, readPtr) {
      if (fd !== 0) return ERRNO.BADF;
      view().setUint32(readPtr, 0, true); // entrée standard vide (fin de fichier)
      return ERRNO.SUCCESS;
    },
    fd_close(fd) {
      return STDIO.has(fd) ? ERRNO.SUCCESS : ERRNO.BADF;
    },
    fd_fdstat_get(fd, ptr) {
      if (!STDIO.has(fd)) return ERRNO.BADF;
      const v = view();
      v.setUint8(ptr, FILETYPE_CHARACTER_DEVICE);
      v.setUint16(ptr + 2, 0, true);
      v.setBigUint64(ptr + 8, 0n, true);
      v.setBigUint64(ptr + 16, 0n, true);
      return ERRNO.SUCCESS;
    },
    fd_fdstat_set_flags(fd) {
      return STDIO.has(fd) ? ERRNO.SUCCESS : ERRNO.BADF;
    },
    fd_prestat_get() {
      return ERRNO.BADF; // aucun répertoire ouvert
    },
    fd_prestat_dir_name() {
      return ERRNO.BADF;
    },
    poll_oneoff(inPtr, outPtr, subscriptions, eventsPtr) {
      // Aucune attente réelle (le fil de la page ne doit pas bloquer) : chaque abonnement à l'horloge est rendu échu,
      // tout autre abonnement en erreur EBADF. Le runtime Go reprend alors son ordonnancement.
      const v = view();
      for (let i = 0; i < subscriptions; i++) {
        const sub = inPtr + i * SUBSCRIPTION_SIZE;
        const event = outPtr + i * EVENT_SIZE;
        const type = v.getUint8(sub + 8);
        v.setBigUint64(event, v.getBigUint64(sub, true), true);
        v.setUint16(event + 8, type === EVENTTYPE_CLOCK ? ERRNO.SUCCESS : ERRNO.BADF, true);
        v.setUint8(event + 10, type);
        v.setBigUint64(event + 16, 0n, true);
        v.setUint16(event + 24, 0, true);
      }
      v.setUint32(eventsPtr, subscriptions, true);
      return ERRNO.SUCCESS;
    },
    sched_yield() {
      return ERRNO.SUCCESS;
    },
    proc_exit(code) {
      throw new WasiExit(code);
    },
  };

  return {
    wasiImport,
    /** Donne la mémoire de l'instance à la couche, puis exécute _initialize (mode bibliothèque). */
    initialize(instance) {
      memory = instance.exports.memory;
      if (!(memory instanceof WebAssembly.Memory)) throw new TypeError('secret-guard : instance sans mémoire exportée');
      if (typeof instance.exports._initialize === 'function') instance.exports._initialize();
    },
  };
}
