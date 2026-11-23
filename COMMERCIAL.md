# Licence commerciale de l'expurgation / Commercial license for expurgation

[Français](#français) · [English](#english)

## Français

Ce dépôt contient deux modules (README, « Licences ») :

- la détection, le masquage, les formats, le corpus et la ligne de commande : module racine
  `github.com/xsom-consulting/secret-guard`, sous Apache-2.0, sans condition d'usage ;
- l'expurgation (remplacement de chaque secret par un Substitut typé) et le module WebAssembly qui l'embarque : module
  `github.com/xsom-consulting/secret-guard/expurgation`, code source disponible, sous Business Source License 1.1
  à partir de la version 0.11.0 ([expurgation/LICENSE](expurgation/LICENSE)). Ce n'est pas une licence open source.

Le texte anglais de la licence fait foi ; ce résumé n'en est pas un substitut.

### Ce que tout le monde peut faire sans autre licence

Copier, modifier, redistribuer l'expurgation et l'utiliser **hors production** (essai, développement, tests), quelle
que soit la taille de l'organisation.

### L'usage en production gratuit (Additional Use Grant)

- **Seuil.** L'organisation pour laquelle on l'utilise compte, sociétés affiliées comprises (contrôle direct ou
  indirect à plus de 50 %), moins de 100 personnes (salariés et indépendants) et moins de 1 000 000 USD de chiffre
  d'affaires annuel sur son dernier exercice clos.
- **Jamais pour un produit concurrent.** Quelle que soit la taille, l'usage gratuit ne couvre jamais la fourniture
  d'un produit ou d'un service, distribué ou hébergé pour des tiers, dont la fonction principale est de détecter ou de
  masquer des secrets ou des données dans ce qui est envoyé à des assistants d'IA. Intégrer l'expurgation dans un
  outil interne n'est pas concurrent.
- **Prestataires.** Un prestataire sous le seuil peut l'utiliser sur ses propres postes pour ses missions, même chez
  un client au-delà du seuil, et chacun de ses consultants sur le poste que le client lui attribue pour sa mission,
  pour son seul usage, un poste par consultant : l'usage relève alors de la licence du prestataire (compte d'usage à
  son nom, avec son adresse e-mail et non celle du client), et l'installation demande l'autorisation du client selon
  ses règles informatiques. Dès que le client installe ou fait installer l'expurgation pour ses salariés ou pour un
  ensemble de prestataires, l'usage relève du client, qui doit être sous le seuil ou titulaire d'une licence de xSOM.

### Qui a besoin d'une licence écrite de xSOM Consulting

Tout usage en production hors de ces conditions : une organisation au-delà du seuil, ou membre d'un groupe qui le
dépasse ; un produit ou un service concurrent ; un déploiement chez un client au-delà du seuil.

Les clients de xSOM Fleet reçoivent cette licence avec leur contrat : l'expurgation qu'exécute l'Agent xSOM est
couverte sans autre démarche.

### Passage sous Apache-2.0

Chaque version passe sous Apache-2.0 quatre ans après sa première publication sous cette licence (Change Date).

### Demander une licence

Écrire à contact@xsom.fr (objet « Secret Guard : licence de l'expurgation ») en indiquant l'entreprise, son groupe,
l'usage prévu (production, redistribution, déploiement chez des clients) et le nombre de postes ou d'utilisateurs.
La licence est un contrat écrit, daté, signé par xSOM Consulting ; rien d'autre (message, ticket, absence de réponse)
ne vaut licence.

### Versions antérieures

Les versions v0.6.0 à v0.10.4 de l'expurgation restent sous PolyForm Small Business 1.0.0 (gratuite pour une
entreprise de moins de 100 personnes et de moins de 1 000 000 USD de chiffre d'affaires, sociétés liées comprises ;
au-delà, y compris pour une évaluation, une licence écrite). Les versions v0.1.0 à v0.5.1 du dépôt restent
entièrement sous Apache-2.0.

## English

The detection engine, redaction, formats, corpus and command line (root module) are Apache-2.0. Expurgation and the
WebAssembly module that embeds it (module `github.com/xsom-consulting/secret-guard/expurgation`) are source-available
under the Business Source License 1.1 from version 0.11.0 ([expurgation/LICENSE](expurgation/LICENSE)), which is not an
open source license. The license text prevails over this summary.

**Anyone** may copy, modify, redistribute and make non-production use of expurgation.

**Free production use** (Additional Use Grant): the organization, affiliates included (more than 50% direct or indirect
control), has fewer than 100 people (employees and individual contractors) and less than 1,000,000 USD annual revenue
in its last completed fiscal year; never to provide a competing product or service (distributed or hosted for third
parties, whose primary function is to detect or mask secrets or data in content sent to AI assistants; an internal
tool is not competing); a service provider under the threshold may use it on its own devices for client work, and
each of its consultants on the one device a client assigns to them for an engagement, for their sole use, under the
provider's rights (user account in the provider's or consultant's name and e-mail, not the client's; installation
with the client's authorization); once the client installs it, or has it installed, for its employees or a group of
contractors, the use is the client's, which must be under the threshold or hold an xSOM license.

**Written license from xSOM Consulting needed** for any other production use. xSOM Fleet customers receive it with
their contract. Each version becomes Apache-2.0 four years after its first publication under this license.

**Request**: e-mail contact@xsom.fr (subject "Secret Guard: expurgation license") with the company, its group, the
intended use and the number of seats or users. A license is a written, dated agreement signed by xSOM Consulting;
nothing else (message, issue, lack of answer) is a license.

Versions v0.6.0 to v0.10.4 of expurgation remain under PolyForm Small Business 1.0.0. Versions v0.1.0 to v0.5.1 remain
entirely Apache-2.0.
