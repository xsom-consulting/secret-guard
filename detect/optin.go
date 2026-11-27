// SPDX-License-Identifier: Apache-2.0

// Règles « à activer » : règles « motif seul » du Pack que le moteur n'exécute que si l'appelant les nomme.
//
// Extension de ce module (v0.9.0), sans origine dans Secret Guard. Une règle qui se déclenche sur des textes
// ordinaires du corpus de bruit (vectors/noise.json) ne peut pas s'exécuter d'office : elle est inscrite dans la liste
// fermée optInRuleIDs (context_rules.go, écrite avec le Pack initial par le générateur), et LoadRules la
// laisse de côté. Le produit qui embarque le moteur l'active par LoadRulesWithOptIn, selon sa politique. Le schéma du Pack
// ne change pas : la liste est du code du moteur, comme celle des validateurs.

package detect

import (
	"errors"

	"github.com/xsom-consulting/secret-guard/pack"
)

// ErrUnknownOptInRule : LoadRulesWithOptIn reçoit une règle absente de OptInRuleIDs. Rien n'est chargé : une règle
// que l'appelant croit activer ne doit pas rester éteinte sans qu'il le sache.
var ErrUnknownOptInRule = errors.New("détection : règle à activer inconnue du moteur")

// optInRules : la liste fermée, par identifiant.
var optInRules = func() map[string]bool {
	set := make(map[string]bool, len(optInRuleIDs))
	for _, id := range optInRuleIDs {
		set[id] = true
	}
	return set
}()

// OptInRuleIDs rend la liste fermée des règles « à activer », dans l'ordre du Pack initial : LoadRules ne les exécute
// pas, LoadRulesWithOptIn exécute celles que l'appelant nomme. Identifiants de règles, jamais une valeur.
func OptInRuleIDs() []string {
	return append([]string(nil), optInRuleIDs...)
}

// LoadRulesWithOptIn charge le Pack comme LoadRules, et exécute en plus les règles « à activer » nommées par optIn,
// parmi OptInRuleIDs. Une règle nommée et absente du Pack est sans effet ; un identifiant absent de OptInRuleIDs fait
// échouer le chargement (ErrUnknownOptInRule). Le Pack est contrôlé en entier dans les deux cas : une règle « à
// activer » inexploitable le fait refuser, activée ou non.
func LoadRulesWithOptIn(p *pack.Pack, optIn []string) (*Rules, error) {
	enabled := make(map[string]bool, len(optIn))
	for _, id := range optIn {
		if !optInRules[id] {
			return nil, ErrUnknownOptInRule
		}
		enabled[id] = true
	}
	return loadRules(p, enabled)
}
