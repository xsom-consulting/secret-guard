// Package detect est le moteur de détection de secrets de Secret Guard, porté en Go depuis le moteur TypeScript
// d'origine (origine, avis et modifications dans UPSTREAM.md) : vues de texte et décodages bornés, règles chargées
// d'un Pack de règles par LoadRules, analyse par Scan ou ScanWithFingerprint, masquage par RedactAndRescan (ou Redact),
// décision par défaut d'un niveau par DecisionForLevel (un préréglage : le produit qui embarque le moteur décide).
//
// Utilisation :
//
//	p, err := pack.Initial() // ou pack.Decode(octets)
//	rules, err := detect.LoadRules(p)
//	result := detect.Scan(content, rules, detect.Options{})
//	if !result.Complete {
//		// Analyse incomplète (entrée trop grande, budget épuisé…) : aucun constat, l'appelant décide (bloquer).
//	}
//
// Décider sur Result.Complete et Result.Failure, jamais sur le seul nombre de constats : une analyse incomplète n'a
// aucun constat. Un constat (Finding) ne porte jamais la valeur détectée, ni un extrait, ni un masque, ni un
// condensat non salé : seulement la règle, le type de secret, la vue, le score, le niveau et l'étendue en octets.
//
// Le paquet est pur (règle depguard de .golangci.yml, prouvée par tools/depguardcheck) : ni E/S, ni réseau, ni appel
// système, ni horloge, ni hasard, ni journal. Ses bornes sont des budgets de travail ; un budget épuisé rend
// l'analyse incomplète. Aucune valeur analysée n'entre dans une erreur ni dans un résultat. Les fonctions sont sûres
// pour des analyses concurrentes avec les mêmes règles.
package detect
