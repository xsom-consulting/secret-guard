package pack

import (
	"bytes"
	_ "embed" // Pack initial embarqué.
)

// initialPack est le Pack initial (initial/pack.json) : les 35 règles du catalogue de Secret Guard traduites en RE2
// (docs/rule-pack.md). Ne jamais l'éditer à la main : il est produit par le générateur (generator/).
//
//go:embed initial/pack.json
var initialPack []byte

// InitialJSON rend une copie des octets du Pack initial embarqué.
func InitialJSON() []byte { return bytes.Clone(initialPack) }

// Initial décode le Pack initial embarqué par Decode.
func Initial() (*Pack, error) { return Decode(initialPack) }
