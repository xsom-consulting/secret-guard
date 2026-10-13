// Package custom exécute un Pack de règles du client : détecteurs propres à un client (identifiants internes,
// noms de code de projets, formats maison…), calibrés et signés par celui qui distribue le Pack, ajoutés aux règles
// intégrées du moteur (docs/custom-pack.md, schéma schema/CustomPack.json).
//
// Portage en Go du dossier secret-guard/packages/core/src/custom du moteur TypeScript de Secret Guard (origine, avis
// et modifications dans UPSTREAM.md). Un Pack n'ajoute que des détections : il ne désactive, n'affaiblit ni ne
// remplace aucune règle intégrée.
//
// Utilisation :
//
//	p, err := custom.Compile(octets) // charge déjà vérifiée (signature) par l'appelant ; refus : *custom.PackError
//	result := detect.Scan(content, rules, detect.Options{Custom: p})
//
// Deux sortes de détecteurs :
//
//   - motif : sous-ensemble sûr d'expressions régulières (§3), validé avec les codes du contrat puis traduit en RE2
//     (temps linéaire) avec la sémantique d'ECMAScript, seule de référence ;
//   - termes confidentiels : le Pack ne porte que des condensats SHA-256 salés de n-grammes normalisés, jamais un
//     terme ; le moteur normalise les mots du texte, hache leurs n-grammes et compare. NormalizeTerm et TermDigest
//     calculent, chez le client, les condensats d'une liste de termes.
//
// Une détection est une étendue d'octets et un détecteur : jamais le texte détecté, un terme ni un condensat. Le
// travail est borné par un budget (ScanWorkBudget) ; un budget épuisé ou trop de détections rendent l'analyse
// incomplète, que l'appelant traite comme un blocage.
//
// Le paquet est pur (règle depguard de .golangci.yml, prouvée par tools/depguardcheck) : ni E/S, ni réseau, ni appel
// système, ni horloge, ni hasard, ni journal.
package custom
