// SPDX-License-Identifier: Apache-2.0

// Vue UTF-16 du moteur de détection.
//
// Extension propre à ce module, sans origine dans Secret Guard (avis dans UPSTREAM.md) : Secret Guard reçoit une
// chaîne JavaScript déjà décodée, ce moteur reçoit des octets. Un fichier UTF-16 (sortie redirigée de PowerShell 5.1,
// export Windows) y est une suite « caractère, NUL » où aucune règle ne trouve rien.
//
// La vue est le texte du contenu lu en UTF-16, écrit en UTF-8 : chaque caractère garde l'étendue des deux octets (ou
// des quatre, pour une paire de substitution) dont il vient, caractères accentués compris. Un constat y est donc
// ramené aux octets de la source, comme dans toute autre vue. Elle porte l'encodage « normalized » : le champ encoding
// des constats appartient au contrat des Événements de xSOM Fleet, aucune valeur nouvelle n'y est ajoutée.
//
// Déclenchement : marque d'ordre d'octets (FF FE, FE FF), ou, sans marque, octets nuls nombreux à une parité et
// rares à l'autre (utf16OrderOf). Limite connue : un texte UTF-16 sans marque, fait surtout de caractères hors
// Latin-1, n'est pas reconnu. La vue est débitée du budget de vues : au-delà, l'analyse est incomplète.

package detect

import (
	"bytes"
	"unicode/utf16"
	"unicode/utf8"
)

// utf16Order est l'ordre des octets d'un contenu UTF-16.
type utf16Order int

const (
	utf16None utf16Order = iota
	utf16Little
	utf16Big
)

const (
	// utf16MinNulShare : sans marque d'ordre, une parité doit porter un octet nul dans une paire sur huit au moins…
	utf16MinNulShare = 8
	// utf16NulRatio : … et quatre fois plus d'octets nuls que l'autre parité (un binaire a ses octets nuls en
	// suites, aux deux parités).
	utf16NulRatio = 4
)

// utf16OrderOf rend l'ordre des octets de content s'il est de l'UTF-16, et la longueur de sa marque d'ordre.
// Sans octet nul et sans marque, rien n'est compté : un texte UTF-8 ordinaire ne coûte qu'une recherche d'octet.
func utf16OrderOf(content []byte) (utf16Order, int) {
	if len(content) < 2 {
		return utf16None, 0
	}
	switch {
	case content[0] == 0xFF && content[1] == 0xFE:
		return utf16Little, 2
	case content[0] == 0xFE && content[1] == 0xFF:
		return utf16Big, 2
	}
	if bytes.IndexByte(content, 0) < 0 {
		return utf16None, 0
	}
	even, odd, pairs := 0, 0, len(content)/2
	for i := 0; i+1 < len(content); i += 2 {
		if content[i] == 0 {
			even++
		}
		if content[i+1] == 0 {
			odd++
		}
	}
	switch {
	case odd*utf16MinNulShare >= pairs && odd >= utf16NulRatio*even:
		return utf16Little, 0
	case even*utf16MinNulShare >= pairs && even >= utf16NulRatio*odd:
		return utf16Big, 0
	}
	return utf16None, 0
}

// unit rend l'unité UTF-16 de deux octets dans l'ordre o.
func (o utf16Order) unit(first, second byte) uint16 {
	if o == utf16Big {
		return uint16(first)<<8 | uint16(second)
	}
	return uint16(second)<<8 | uint16(first)
}

// utf16View rend la vue UTF-16 de content, nil s'il n'est pas de l'UTF-16. La marque d'ordre initiale n'entre pas
// dans la vue ; un substitut isolé vaut U+FFFD (builder.pushUnit), un octet final sans pendant aussi.
func utf16View(content []byte, budget *viewBudget) (*view, error) {
	order, skip := utf16OrderOf(content)
	if order == utf16None {
		return nil, nil
	}
	b := newBuilder(len(content)/2, budget)
	i := skip
	for ; i+1 < len(content); i += 2 {
		unit := order.unit(content[i], content[i+1])
		var err error
		if unit < utf8.RuneSelf {
			err = b.pushByte(byte(unit), i, i+2)
		} else {
			err = b.pushUnit(unit, i, i+2)
		}
		if err != nil {
			return nil, err
		}
	}
	if i < len(content) {
		if err := b.push(replacement, i, i+1); err != nil {
			return nil, err
		}
	}
	return b.finish(budget, EncodingNormalized), nil
}

// utf16Text rend en UTF-8 des octets décodés qui sont de l'UTF-16 entier (nombre pair d'octets, aucun substitut
// isolé) : charge d'une commande PowerShell encodée (base64 d'UTF-16 petit-boutien). La marque d'ordre est retirée.
func utf16Text(decoded []byte) ([]byte, bool) {
	order, skip := utf16OrderOf(decoded)
	if order == utf16None || (len(decoded)-skip)%2 != 0 {
		return nil, false
	}
	out := make([]byte, 0, (len(decoded)-skip)/2)
	for i := skip; i < len(decoded); i += 2 {
		r := rune(order.unit(decoded[i], decoded[i+1]))
		if utf16.IsSurrogate(r) {
			if i+3 >= len(decoded) {
				clear(out)
				return nil, false
			}
			r = utf16.DecodeRune(r, rune(order.unit(decoded[i+2], decoded[i+3])))
			if r == utf8.RuneError {
				clear(out)
				return nil, false
			}
			i += 2
		}
		out = utf8.AppendRune(out, r)
	}
	return out, true
}
