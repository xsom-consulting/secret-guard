# Licence commerciale de l'expurgation / Commercial license for expurgation

[Français](#français) · [English](#english)

## Français

Ce dépôt contient deux modules (README, « Licences ») :

- la détection, le masquage, les formats, le corpus et la ligne de commande : module racine
  `github.com/xsom-consulting/secret-guard`, sous Apache-2.0, sans condition d'usage ;
- l'expurgation (remplacement de chaque secret par un Substitut typé) et le module WebAssembly qui l'embarque : module
  `github.com/xsom-consulting/secret-guard/expurgation`, sous PolyForm Small Business 1.0.0
  ([expurgation/LICENSE](expurgation/LICENSE)), source disponible.

### Qui peut utiliser l'expurgation sans autre licence

Toute utilisation au profit d'une entreprise (personne morale, entreprise individuelle ou autre organisation pour
laquelle on travaille) qui, sur l'exercice précédent, comptait moins de 100 personnes (salariés et indépendants) et
moins de 1 000 000 USD de chiffre d'affaires (valeur de 2019, corrigée de l'inflation), **sociétés qu'elle contrôle, qui la contrôlent ou sous contrôle commun comprises**. Le texte
de la licence fait foi ; ce résumé n'en est pas un substitut.

### Qui a besoin d'une licence écrite de xSOM Consulting

Une entreprise au-delà de ces seuils, ou membre d'un groupe qui les dépasse, quel que soit l'usage, **y compris une
évaluation ou un pilote**. La licence permet de redistribuer l'expurgation (avec son texte et la ligne
`Required Notice`) ; l'usage de chaque destinataire reste soumis aux mêmes seuils.

Les clients de xSOM Fleet reçoivent cette licence avec leur contrat : l'expurgation qu'exécute l'Agent xSOM est
couverte sans autre démarche.

### Demander une licence

Écrire à contact@xsom.fr (objet « Secret Guard : licence de l'expurgation ») en indiquant l'entreprise, son groupe,
l'usage prévu (évaluation, production, redistribution) et le nombre de postes ou d'utilisateurs. La licence est un
contrat écrit, daté, signé par xSOM Consulting ; rien d'autre (message, ticket, absence de réponse) ne vaut licence.

Les versions v0.1.0 à v0.5.1 du dépôt, publiées avant cette séparation, restent entièrement sous Apache-2.0.

## English

The detection engine, redaction, formats, corpus and command line (root module) are Apache-2.0. Expurgation and the
WebAssembly module that embeds it (module `github.com/xsom-consulting/secret-guard/expurgation`) are under PolyForm
Small Business 1.0.0 ([expurgation/LICENSE](expurgation/LICENSE)), source-available.

**Free use**: use for the benefit of a company (legal entity, sole proprietorship or other organization one works
for) that had fewer than 100 people (employees and contractors) and less than 1,000,000 USD (2019, adjusted for inflation) revenue in the prior tax year, **including the
organizations that control it, that it controls or under common control**. The license text prevails over this
summary.

**Written license from xSOM Consulting needed**: a company above these thresholds, or part of a group above them, for
any use **including an evaluation or a pilot**. The license allows redistribution (with its text and the
`Required Notice` line); each recipient's use is subject to the same thresholds. xSOM Fleet customers receive this license with their contract.

**Request**: e-mail contact@xsom.fr (subject "Secret Guard: expurgation license") with the company, its group, the
intended use and the number of seats or users. A license is a written, dated agreement signed by xSOM Consulting;
nothing else (message, issue, lack of answer) is a license.

Versions v0.1.0 to v0.5.1, published before this split, remain entirely Apache-2.0.
