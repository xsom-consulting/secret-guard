// SPDX-License-Identifier: Apache-2.0

// Liens de ressources de claude.ai écartés de l'entropie : faux positif relevé sur un Poste réel (xSOM Fleet,
// 10 novembre 2026), où le lien d'un Artifact (« https://claude.ai/code/artifact/<identifiant> ») était remplacé par un
// Substitut. Ces identifiants désignent une ressource qui ne s'ouvre qu'avec la session de son propriétaire ou d'une
// personne à qui il l'a partagée : ce ne sont pas des secrets. Les liens de partage public (« /share/ ») restent
// détectés, car le lien suffit à ouvrir la conversation. Écart avec Secret Guard (UPSTREAM.md) : moins de constats
// d'entropie, jamais moins de constats d'une règle ancrée.

package detect

import (
	"bytes"
	"regexp"
)

// claudeResourceLink : lien complet, en HTTPS, sans identifiant de connexion ni port, vers une ressource de claude.ai
// qui exige une session (Artifact, conversation, projet, session de Claude Code ouverte à distance), terminé par
// l'identifiant. Le lien d'une session de Claude Code (« https://claude.ai/code/session_<identifiant> », donné par le
// Remote Control et repris dans les messages entre sessions) ne s'ouvre qu'avec le compte de son propriétaire : faux
// positif relevé sur un Poste réel le 19 novembre 2026, où il arrêtait chaque message d'une session Windows.
var claudeResourceLink = regexp.MustCompile(`^https://claude\.ai/(?:(?:code/)?(?:artifact|chat|project)/[A-Za-z0-9_-]{1,64}|code/session_[A-Za-z0-9]{1,64})$`)

// claudeLinkLookBehind borne la recherche du début du lien avant la suite jugée (« https://claude.ai/code/session_ »,
// 31 octets).
const claudeLinkLookBehind = 32

// isKnownResourceLink dit si la suite [start, start+len(value)) de la vue finit un lien de ressource de claude.ai
// (claudeResourceLink) : le lien commence au plus claudeLinkLookBehind octets avant elle et elle en porte l'identifiant.
func isKnownResourceLink(v *view, start int, value []byte) bool {
	text := v.text
	end := start + len(value)
	from := max(0, start-claudeLinkLookBehind)
	at := bytes.LastIndex(text[from:start], []byte("https://"))
	if at < 0 {
		return false
	}
	return claudeResourceLink.Match(text[from+at : end])
}
