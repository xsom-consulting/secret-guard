// Décision par défaut associée au niveau d'un constat.
//
// Portage en Go de decisionForLevel de secret-guard/packages/core/src/risk.ts (Apache-2.0, origine, avis et
// modifications dans UPSTREAM.md). levelForScore et boundedScore du même fichier sont portés dans scan.go ; les
// vecteurs vectors/decision.json, produits par le moteur d'origine, prouvent l'égalité (TestDecisionParity).

package detect

// Decision est la décision qu'un niveau appelle par défaut (Decision de Secret Guard) : autoriser, avertir ou
// bloquer.
type Decision string

// Décisions par défaut.
const (
	DecisionAllow Decision = "ALLOW"
	DecisionWarn  Decision = "WARN"
	DecisionBlock Decision = "BLOCK"
)

// DecisionForLevel rend la décision que Secret Guard associe par défaut à un niveau : LOW autorise, MEDIUM avertit,
// HIGH et CRITICAL bloquent. Un niveau hors de cette liste fermée bloque.
//
// C'est un préréglage, pas une politique : le produit qui embarque le moteur décide. xSOM Fleet, par exemple,
// associe niveaux et décisions par sa Politique publiée et, sans association publiée, bloque quel que soit le
// niveau. Une analyse incomplète (Result.Complete faux) n'a pas de niveau : elle bloque, toujours.
func DecisionForLevel(level Level) Decision {
	switch level {
	case LevelLow:
		return DecisionAllow
	case LevelMedium:
		return DecisionWarn
	}
	return DecisionBlock
}
