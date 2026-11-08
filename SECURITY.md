# Sécurité / Security

[Français](#français) · [English](#english)

## Français

### Signaler une vulnérabilité

Par un avis de sécurité privé GitHub : onglet « Security » du dépôt, puis « Report a vulnerability »
(<https://github.com/xsom-consulting/secret-guard/security/advisories/new>). À défaut, par courriel à
contact@xsom.fr, objet « Secret Guard : sécurité ». Jamais par un ticket public, une demande de fusion ni une
discussion.

Décrire le problème, la version (étiquette ou commit), le paquet ou le module touché, et un moyen de le reproduire.
N'envoyer aucun secret réel : une valeur synthétique de la même forme suffit, et le dépôt n'en contient que de
synthétiques.

### Périmètre

- Le moteur de détection et le masquage (module racine `github.com/xsom-consulting/secret-guard`, Apache-2.0) ;
- l'expurgation et le module WebAssembly (module `github.com/xsom-consulting/secret-guard/expurgation`, PolyForm
  Small Business 1.0.0) ;
- le paquet npm `@xsom-consulting/secret-guard-wasm` et les fichiers des Releases GitHub.

Entrent dans ce périmètre, par exemple : une valeur détectée qui sort du moteur (constat, journal, message, texte
expurgé), une analyse incomplète rendue comme complète, une entrée qui fait dépasser les budgets de travail ou
arrêter le processus, un Substitut qui révèle une partie de la valeur, un contournement de la vérification d'un Pack.
Un secret que les règles ne décrivent pas est une limite connue de la détection (README) : le signaler par un ticket
ordinaire, sans valeur réelle.

### Traitement

Nous accusons réception, cherchons à reproduire, puis préparons une correction et un avis publié avec la version
corrigée. Le délai dépend de la gravité ; nous informons la personne qui a signalé à chaque étape et la citons dans
l'avis si elle le souhaite. Seule la dernière version publiée reçoit les corrections.

## English

### Reporting a vulnerability

Through a private GitHub security advisory: the repository's "Security" tab, then "Report a vulnerability"
(<https://github.com/xsom-consulting/secret-guard/security/advisories/new>). Otherwise by e-mail to contact@xsom.fr,
subject "Secret Guard: security". Never through a public issue, pull request or discussion.

Describe the problem, the version (tag or commit), the affected package or module, and how to reproduce it. Send no
real secret: a synthetic value of the same shape is enough, and the repository only contains synthetic ones.

### Scope

The detection engine and redaction (root module, Apache-2.0), expurgation and the WebAssembly module (module
`github.com/xsom-consulting/secret-guard/expurgation`, PolyForm Small Business 1.0.0), the npm package
`@xsom-consulting/secret-guard-wasm` and the GitHub Release files. Examples: a detected value leaving the engine, an
incomplete scan reported as complete, an input that exceeds the work budgets or stops the process, a substitute that
reveals part of the value, a bypass of Pack verification. A secret that the rules do not describe is a known limit of
detection: report it as an ordinary issue, without any real value.

### Handling

We acknowledge, reproduce, then prepare a fix and an advisory published with the fixed version. Timing depends on
severity; we keep the reporter informed and credit them in the advisory if they wish. Only the latest published
version receives fixes.
