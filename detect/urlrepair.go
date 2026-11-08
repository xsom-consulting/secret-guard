// SPDX-License-Identifier: Apache-2.0

// URL à identifiants abîmée : « postgres://admin:< motdepasse@hôte » (chevron, espace ou guillemet collés entre le
// « : » de l'information utilisateur et le mot de passe, en général par un copier-coller ou un gabarit mal rempli).
//
// Écart avec Secret Guard (UPSTREAM.md) : scanCredentialUrls s'arrête au premier caractère qui ne peut pas être dans
// une URL (« [^\s"'<>] ») ; l'URL « postgres://admin: » n'a alors pas d'identifiants et le mot de passe qui suit passe
// en clair. Le moteur recolle les morceaux : un secret de plus détecté, jamais un secret manqué.

package detect

import (
	"bytes"
	"unicode/utf8"
)

const (
	// brokenURLNoiseMax : nombre de caractères parasites admis entre deux morceaux.
	brokenURLNoiseMax = 4
	// brokenURLRounds : nombre de morceaux recollés au plus après « utilisateur: » : le mot de passe, puis « @hôte »
	// s'il en est séparé.
	brokenURLRounds = 2
)

// isBrokenURLNoise dit si c est un caractère parasite d'une URL abîmée : espace, tabulation, chevron ou guillemet,
// jamais une fin de ligne.
func isBrokenURLNoise(c byte) bool {
	switch c {
	case ' ', '\t', '<', '>', '"', '\'':
		return true
	}
	return false
}

// endsWithBareUserinfo dit si candidate est « schéma://utilisateur: » : information utilisateur ouverte par un « : »
// final, sans « @ » ni fin d'autorité après « :// ».
func endsWithBareUserinfo(candidate []byte) bool {
	if len(candidate) == 0 || candidate[len(candidate)-1] != ':' {
		return false
	}
	sep := bytes.Index(candidate, []byte("://"))
	if sep <= 0 {
		return false
	}
	userinfo := candidate[sep+3 : len(candidate)-1]
	if len(userinfo) == 0 {
		return false
	}
	return !bytes.ContainsAny(userinfo, "@/?#\\:")
}

// brokenCredentialURL recolle l'URL abîmée qui commence à start et dont la partie lisible, « schéma://utilisateur: »,
// finit à candEnd. Elle saute au plus brokenURLNoiseMax caractères parasites, lit un morceau de queue d'URL, et
// recommence au plus brokenURLRounds fois, jusqu'à obtenir une URL dont le mot de passe est non vide. Elle rend la fin
// de l'URL dans text (ponctuation finale exclue), l'étendue du mot de passe dans text (parasites exclus) et le mot de
// passe encodé lu par urlPassword.
func brokenCredentialURL(text []byte, start, candEnd int) (end, passwordStart, passwordEnd int, password string, ok bool) {
	if candEnd <= start || candEnd > len(text) || !endsWithBareUserinfo(text[start:candEnd]) {
		return 0, 0, 0, "", false
	}
	repaired := append([]byte(nil), text[start:candEnd]...)
	firstPiece := -1
	cur := candEnd
	for round := 0; round < brokenURLRounds; round++ {
		p := cur
		for noise := 0; p < len(text) && noise < brokenURLNoiseMax && isBrokenURLNoise(text[p]); noise++ {
			p++
		}
		if p == cur || p == len(text) || isBrokenURLNoise(text[p]) {
			return 0, 0, 0, "", false
		}
		if round > 0 && text[p] != '@' {
			// Second morceau : seulement la suite « @hôte » d'un mot de passe entouré (« <motdepasse>@hôte ») ; le mot de
			// passe est toujours un seul morceau, jamais une phrase recollée.
			return 0, 0, 0, "", false
		}
		q := p
		for units := 0; q < len(text); {
			c, width := utf8.DecodeRune(text[q:])
			u := 1
			if c > 0xFFFF {
				u = 2
			}
			if !isCredentialURLTail(c) || units+u > credentialURLTailMax {
				break
			}
			units += u
			q += width
		}
		if q == p {
			return 0, 0, 0, "", false
		}
		if firstPiece < 0 {
			firstPiece = p
		}
		repaired = append(repaired, text[p:q]...)
		stripped := stripTrailingURLPunctuation(repaired)
		if pw, parsed := urlPassword(stripped); parsed && pw != "" {
			end = q - (len(repaired) - len(stripped))
			at := bytes.LastIndexByte(text[firstPiece:end], '@')
			if at < 0 {
				return 0, 0, 0, "", false
			}
			passwordEnd = firstPiece + at
			for passwordEnd > firstPiece && isBrokenURLNoise(text[passwordEnd-1]) {
				passwordEnd--
			}
			if passwordEnd <= firstPiece {
				return 0, 0, 0, "", false
			}
			// Gabarit de documentation (« schéma://utilisateur:<password>@hôte ») : la valeur fictive se juge avec ses
			// chevrons, comme Secret Guard juge « <password> ».
			if text[firstPiece-1] == '<' && passwordEnd < len(text) && text[passwordEnd] == '>' &&
				safeLiteral(text[firstPiece-1:passwordEnd+1]) {
				return 0, 0, 0, "", false
			}
			return end, firstPiece, passwordEnd, pw, true
		}
		cur = q
	}
	return 0, 0, 0, "", false
}

// brokenURLPasswordRange rend l'étendue du mot de passe d'une étendue qui est exactement une URL abîmée trouvée par
// scanCredentialURLs.
func brokenURLPasswordRange(span []byte) (int, int, bool) {
	candEnd := 0
	for candEnd < len(span) && !isBrokenURLNoise(span[candEnd]) {
		candEnd++
	}
	end, start, passwordEnd, _, ok := brokenCredentialURL(span, 0, candEnd)
	if !ok || end != len(span) {
		return 0, 0, false
	}
	return start, passwordEnd, true
}
