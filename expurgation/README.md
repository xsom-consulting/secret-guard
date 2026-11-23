# Secret Guard : expurgation

[Français](#français) · [English](#english)

## Français

Module `github.com/xsom-consulting/secret-guard/expurgation` : remplacement de chaque secret détecté par un Substitut
typé, et module WebAssembly qui l'embarque (`cmd/secret-guard-wasm`). Documentation : README du dépôt, section
« Expurgation ».

**Licence.** Code source disponible, sous **Business Source License 1.1** à partir de la version 0.11.0
([LICENSE](LICENSE), identifiant SPDX `BUSL-1.1`). Ce n'est pas une licence open source : chacun peut copier, modifier,
redistribuer et utiliser le module hors production ; l'usage en production gratuit est défini par l'« Additional Use
Grant » de la licence (seuil de 100 personnes et de 1 000 000 USD de chiffre d'affaires, sociétés affiliées comprises ;
jamais pour un produit ou service concurrent ; règles des prestataires) ; au-delà, une licence écrite de xSOM
Consulting ([COMMERCIAL.md](../COMMERCIAL.md)). Chaque version passe sous Apache-2.0 quatre ans après sa publication.

Les versions v0.6.0 à v0.10.4 restent sous PolyForm Small Business 1.0.0 ; les versions v0.1.0 à v0.5.1 du dépôt,
sous Apache-2.0. Le moteur de détection (module racine) reste sous Apache-2.0.

Contribuer à ce module demande l'accord de contribution ([CONTRIBUTING.md](../CONTRIBUTING.md)).

## English

Module `github.com/xsom-consulting/secret-guard/expurgation`: replaces each detected secret with a typed substitute,
and the WebAssembly module that embeds it (`cmd/secret-guard-wasm`). Documentation: repository README, "Expurgation".

**License.** Source-available under the **Business Source License 1.1** from version 0.11.0 ([LICENSE](LICENSE), SPDX
identifier `BUSL-1.1`). It is not an open source license: anyone may copy, modify, redistribute and make
non-production use of the module; free production use is defined by the license's Additional Use Grant (fewer than
100 people and less than 1,000,000 USD revenue, affiliates included; never for a competing product or service;
service provider rules); beyond that, a written license from xSOM Consulting ([COMMERCIAL.md](../COMMERCIAL.md)). Each
version becomes Apache-2.0 four years after its publication.

Versions v0.6.0 to v0.10.4 remain under PolyForm Small Business 1.0.0; versions v0.1.0 to v0.5.1 of the repository,
Apache-2.0. The detection engine (root module) stays Apache-2.0.

Contributing to this module requires the contributor license agreement ([CONTRIBUTING.md](../CONTRIBUTING.md)).
