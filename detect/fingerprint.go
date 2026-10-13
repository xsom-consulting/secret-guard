// Empreinte locale d'un constat.
//
// L'Empreinte locale est l'hexadécimal minuscule des 16 premiers octets de HMAC-SHA256(clé, valeur
// normalisée), où la valeur normalisée est la suite d'octets de la valeur dans la vue où la règle l'a trouvée (texte
// NFKC pour la vue normalisée, octets décodés pour les vues base64, pourcentage et JSON), sans délimiteurs. Elle est
// calculée dans le processus qui analyse, seul à voir la valeur ; la clé, tirée du hasard par l'appelant et jamais
// transmise, en fait un condensat salé : sans la clé, rien ne relie une Empreinte locale à la valeur. Elle permet de
// reconnaître qu'une même valeur revient, sous une même clé, sans jamais la connaître.

package detect

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

const (
	// FingerprintKeyBytes est la longueur de la clé d'Empreinte locale (32 octets).
	FingerprintKeyBytes = 32
	// fingerprintBytes est la longueur de l'Empreinte locale avant son écriture hexadécimale.
	fingerprintBytes = 16
	// maskedFingerprintKey remplace la clé dans tout texte.
	maskedFingerprintKey = "[clé d'Empreinte locale masquée]"
)

// ErrFingerprintKeyInvalid est le refus d'une clé de longueur différente de FingerprintKeyBytes, ou dont les octets
// sont tous égaux (clé nulle comprise), sans recopier la valeur reçue.
var ErrFingerprintKeyInvalid = errors.New("clé d'Empreinte locale refusée : 32 octets non tous égaux attendus")

// FingerprintKey est la clé HMAC de l'Empreinte locale. Elle ne sort jamais du paquet : aucune méthode ne rend ses
// octets, et String et GoString rendent un texte masqué. Les octets sont derrière deux pointeurs (structure, puis tableau) :
// une FingerprintKey placée dans le champ non exporté d'une autre structure est affichée par fmt par réflexion, sans
// ses méthodes. fmt ne déréférence alors qu'un pointeur de premier niveau vers une structure, un tableau, une
// tranche ou une table (verbe inadapté comme %s compris) : il montre la structure pointée, dont le seul champ est un
// pointeur, affiché par son adresse. Un pointeur direct vers le tableau serait affiché octet par octet.
type FingerprintKey struct {
	secret *fingerprintSecret
}

// fingerprintSecret porte les octets de la clé, derrière un second pointeur.
type fingerprintSecret struct {
	bytes *[FingerprintKeyBytes]byte
}

// NewFingerprintKey copie raw dans une nouvelle clé puis efface raw, dans tous les cas (refus compris).
func NewFingerprintKey(raw []byte) (FingerprintKey, error) {
	defer clear(raw)
	if len(raw) != FingerprintKeyBytes {
		return FingerprintKey{}, ErrFingerprintKeyInvalid
	}
	uniform := true
	for _, b := range raw[1:] {
		uniform = uniform && b == raw[0]
	}
	if uniform {
		return FingerprintKey{}, ErrFingerprintKeyInvalid
	}
	secret := &fingerprintSecret{bytes: new([FingerprintKeyBytes]byte)}
	copy(secret.bytes[:], raw)
	return FingerprintKey{secret: secret}, nil
}

// Wipe efface la clé ; toute analyse avec elle est ensuite incomplète. Sans effet sur la valeur zéro.
func (k FingerprintKey) Wipe() {
	if k.secret != nil {
		clear(k.secret.bytes[:])
	}
}

// usable dit si la clé a été construite par NewFingerprintKey et n'a pas été effacée.
func (k FingerprintKey) usable() bool {
	if k.secret == nil {
		return false
	}
	for _, b := range k.secret.bytes {
		if b != 0 {
			return true
		}
	}
	return false
}

// String masque la clé.
func (FingerprintKey) String() string { return maskedFingerprintKey }

// GoString masque la clé.
func (FingerprintKey) GoString() string { return maskedFingerprintKey }

// localFingerprint calcule l'Empreinte locale de value sous la clé : hexadécimal minuscule des 16 premiers octets de
// HMAC-SHA256(clé, value). Le condensat complet est effacé ; seule la troncature écrite sort. L'état interne de
// crypto/hmac (blocs dérivés de la clé) n'est pas accessible, donc pas effacé : il reste dans le processus qui analyse.
func localFingerprint(key FingerprintKey, value []byte) string {
	mac := hmac.New(sha256.New, key.secret.bytes[:])
	mac.Write(value)
	sum := mac.Sum(make([]byte, 0, sha256.Size))
	defer clear(sum)
	return hex.EncodeToString(sum[:fingerprintBytes])
}

// ScanWithFingerprint analyse content comme Scan (sans identifiant de langage) et donne à chaque constat son
// Empreinte locale, calculée sous key sur la valeur du constat : l'appelant peut ainsi reconnaître qu'une valeur
// revient sans la garder. Une clé absente (valeur zéro) ou effacée rend l'analyse incomplète (FailureScanError, aucun
// constat) : jamais de constat sans Empreinte locale. Les copies de la valeur faites pour le calcul sont effacées
// avant le retour, quelle que soit l'issue.
func ScanWithFingerprint(content []byte, rules *Rules, key FingerprintKey) Result {
	if !key.usable() {
		if len(content) > MaxInputBytes {
			return incomplete(FailureScanLimit)
		}
		return incomplete(FailureScanError)
	}
	return scan(content, rules, Options{}, &key)
}
