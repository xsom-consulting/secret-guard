# Contribuer / Contributing

[Français](#français) · [English](#english)

## Français

Merci de l'intérêt porté à Secret Guard. Le dépôt est maintenu par xSOM Consulting ; les contributions sont relues
par l'équipe de `.github/CODEOWNERS`.

### Avant d'écrire du code

- Une vulnérabilité ne se signale jamais par un ticket ni une demande de fusion : voir [SECURITY.md](SECURITY.md).
- Ouvrir d'abord un ticket qui décrit le besoin (règle manquante, faux positif, faux négatif, défaut), avec une valeur
  **synthétique** de la même forme, jamais un secret réel, ni un nom de client, de poste ou d'outil de sécurité d'une
  entreprise.
- Le comportement du moteur est fixé par son corpus de parité (`vectors/`) : un changement de détection ajoute ses cas
  au corpus et explique chaque résultat qui change.

### Accord de contribution

Le dépôt a deux licences (README, « Licences ») : Apache-2.0 pour le module racine, PolyForm Small Business 1.0.0
pour le module `expurgation/`. Pour pouvoir publier chaque contribution sous la licence de son module, et l'expurgation
aussi sous licence commerciale, xSOM Consulting demande à chaque contributeur d'accepter l'[accord de contribution](docs/CLA.md)
avant la fusion de sa première demande : écrire dans la description de la demande de fusion la phrase
« J'accepte l'accord de contribution de docs/CLA.md (version 1.0) » ou « I agree to the contributor license agreement
in docs/CLA.md (version 1.0) ». Une contribution faite pour un employeur demande l'accord de celui-ci.

L'accord est aujourd'hui un projet de texte : **aucune contribution extérieure n'est fusionnée avant sa version
définitive**. Le contrôle « Accord de contribution » (`.github/workflows/cla.yml`) vérifie la phrase sur chaque
demande de fusion d'une personne extérieure au dépôt ; une demande dont ce contrôle échoue n'est pas fusionnée.

### Règles du code

- Go : `gofmt`, `golangci-lint run` sans remarque dans chaque module (racine, puis `expurgation/`). Le moteur (`detect`,
  `pack`, `custom`, `hidden`, `mentions`, `internal/limits`, `internal/jstext`) et l'expurgation sont purs : ni E/S,
  ni réseau, ni horloge, ni hasard, ni journal (règles `depguard`, prouvées par `go run ./tools/depguardcheck`).
- Un constat, un Substitut, un message, un journal ne portent jamais la valeur détectée, ni un extrait, ni un condensat
  non salé.
- Chaque fichier source (`.go`, `.mjs`, `.mts`, `.ts`) commence par l'identifiant SPDX de son module :
  `// SPDX-License-Identifier: Apache-2.0` hors de `expurgation/`, `// SPDX-License-Identifier: PolyForm-Small-Business-1.0.0`
  dessous (`go run ./tools/spdxcheck`). Le module racine n'importe jamais `expurgation/`.
- Les valeurs à forme de secret des essais sont assemblées par morceaux à l'exécution ; seuls les fichiers de cas du
  corpus en contiennent ([.gitleaks.toml](.gitleaks.toml)).
- Ne jamais éditer à la main les fichiers générés (Pack initial, motifs du moteur, tables Unicode, corpus, vecteurs) :
  README, « Régénérer ».
- Commits petits, messages au format conventionnel (`fix(detect): …`, `feat(expurgation): …`).

### Vérifier avant la demande de fusion

Les commandes de la section « Vérifier » du README, dans les deux modules, plus `go run ./tools/spdxcheck`, et, si le
module WebAssembly change, sa construction et `node --test wasm/secret-guard.test.mjs wasm/parity.test.mjs wasm/package.test.mjs`.

## English

Thank you for your interest in Secret Guard. The repository is maintained by xSOM Consulting; contributions are
reviewed by the team in `.github/CODEOWNERS`.

- Never report a vulnerability in an issue or pull request: see [SECURITY.md](SECURITY.md).
- Open an issue first, with a **synthetic** value of the same shape, never a real secret, customer name, host name or
  security tool of a company. A detection change adds its cases to the parity corpus (`vectors/`).
- **Contributor license agreement**: the repository has two licenses (Apache-2.0 for the root module, PolyForm Small
  Business 1.0.0 for `expurgation/`). Before your first pull request is merged, accept the
  [contributor license agreement](docs/CLA.md) by writing in the pull request description: "I agree to the contributor
  license agreement in docs/CLA.md (version 1.0)". A contribution made for an employer needs the employer's agreement.
  The agreement is still a draft: **no external contribution is merged before its final version**. The "Accord de
  contribution" check (`.github/workflows/cla.yml`) verifies the sentence on every pull request from outside the
  repository; a pull request whose check fails is not merged.
- Code: `gofmt` and `golangci-lint run` clean in both modules; the engine and expurgation stay pure (no I/O, network,
  clock, randomness or logging); no detected value, excerpt or unsalted hash in any output; each source file starts
  with the SPDX identifier of its module (`go run ./tools/spdxcheck`); the root module never imports `expurgation/`;
  test values shaped like secrets are assembled at run time; generated files are never edited by hand.
- Run the "Verify" commands of the README in both modules before opening the pull request.
