# @xsom-consulting/secret-guard-wasm

[English](#english) · [Français](#français)

## English

The [Secret Guard](https://github.com/xsom-consulting/secret-guard) secret detection engine (API keys, tokens, private
keys, passwords, URLs with credentials…) compiled from Go to a WebAssembly module (WASI preview 1, library mode), with
dependency-free loaders for Node and for browsers or browser extensions.

- **Local only.** The module imports a closed list of WASI functions (memory, clock, randomness, standard output for
  fatal errors): no network (`sock_*`), no file opening (`path_*`). The loaders open no file and no connection: you
  give them the module bytes.
- **Never a detected value.** A finding carries rule, secret type, reading, score, level and byte span; never the
  value, an excerpt, a mask or an unsalted hash.
- **Never "nothing found" by default.** An incomplete scan (input over 1 MiB, budget exhausted) returns
  `complete: false` and no finding: decide on `complete` and `failure`, not on the number of findings.
- **Same results as the Go engine.** Every release runs the module and the native Go engine on the whole corpus of the
  repository (823 detection cases, expurgation and hidden-instruction vectors) and requires identical documents.

```js
// Node
import { readFile } from 'node:fs/promises';
import { createSecretGuard, wasmUrl } from '@xsom-consulting/secret-guard-wasm/node';
const guard = await createSecretGuard(await readFile(wasmUrl));

// Browser, extension page or service worker (Manifest V3: declare 'wasm-unsafe-eval' in the extension CSP)
import { createSecretGuard } from '@xsom-consulting/secret-guard-wasm/browser';
const bytes = new Uint8Array(await (await fetch(moduleUrlOfYourOwnBundle)).arrayBuffer());
// Check bytes against the SHA-256 published with the GitHub Release before instantiating.
const guard = await createSecretGuard(bytes);

const result = guard.scan(new TextEncoder().encode(text));
// { complete, failure, findings: [{ ruleId, secretType, encoding, score, level, byteStart, byteEnd }] }

guard.setFingerprintKey(crypto.getRandomValues(new Uint8Array(32)));
const { failure, substitutions, text: expurgated } = guard.expurgate(new TextEncoder().encode(text), { known: [] });
// failure 'none': each secret is replaced by a typed Substitute (ghp_XXX…1) of the same length; same value, same
// number (pass the previous substitutions back as `known`). Otherwise expurgated is null: send nothing.

const hidden = guard.findHidden(new TextEncoder().encode(text)); // hidden instructions (tag characters, bidi…)
```

Other functions: `redact` (`<REDACTED_rule>` labels), `scanWithFingerprint` (local fingerprint of each finding, HMAC
under your 32-byte key), `loadPack` (another rule pack, JSON `RulePack` schema). Any trap of the module makes the
instance unusable (`guard.broken`): every later call throws.

**Integrity.** Each GitHub Release lists the SHA-256 of `secret-guard.wasm` and of the npm tarball (`SHA256SUMS`) and
carries a signed build provenance attestation: `gh attestation verify secret-guard.wasm -R xsom-consulting/secret-guard`.
The npm package is published with npm provenance.

The engine only finds what its rules describe: it lowers the risk, it does not remove it. License: Apache-2.0.

## Français

Le moteur de détection de secrets [Secret Guard](https://github.com/xsom-consulting/secret-guard), compilé de Go en
module WebAssembly (WASI preview 1, mode bibliothèque), avec des chargeurs sans dépendance pour Node et pour un
navigateur ou une extension de navigateur.

- **Local seulement.** Le module n'importe qu'une liste fermée de fonctions WASI (mémoire, horloge, hasard, sortie
  standard des erreurs fatales) : ni réseau (`sock_*`), ni ouverture de fichier (`path_*`). Les chargeurs n'ouvrent ni
  fichier ni connexion : l'appelant leur donne les octets du module.
- **Jamais une valeur détectée.** Un constat porte la règle, le type de secret, la lecture, le score, le niveau et
  l'étendue en octets ; jamais la valeur, un extrait, un masque ni un condensat non salé.
- **Jamais « rien trouvé » par défaut.** Une analyse incomplète (entrée de plus de 1 Mio, budget épuisé) rend
  `complete: false` et aucun constat : décider sur `complete` et `failure`.
- **Mêmes résultats que le moteur Go.** Chaque Release exécute le module et le moteur Go natif sur tout le corpus du
  dépôt (823 cas de détection, vecteurs de l'expurgation et des instructions cachées) et exige des documents identiques.

`expurgate` remplace chaque secret par un Substitut typé (`ghp_XXX…1`) à la longueur de la valeur ; une même valeur
reprend son numéro si l'appelant redonne les Substituts déjà posés (`known`). Exige `setFingerprintKey`.

**Intégrité.** Chaque Release GitHub publie les SHA-256 de `secret-guard.wasm` et de l'archive npm (`SHA256SUMS`) et
porte une attestation de provenance signée : `gh attestation verify secret-guard.wasm -R xsom-consulting/secret-guard`.
Le paquet npm est publié avec la provenance npm.

Le moteur ne trouve que ce que ses règles décrivent : il réduit le risque, il ne le supprime pas. Licence : Apache-2.0.
