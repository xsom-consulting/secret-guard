// SPDX-License-Identifier: BUSL-1.1

package expurgation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"go/build"
	"os"
	"strings"
	"testing"
)

// Le texte officiel de la Business Source License 1.1 (https://mariadb.com/bsl11, copie SPDX BUSL-1.1 de
// https://github.com/spdx/license-list-data, text/BUSL-1.1.txt, lue le 2026-11-23) est recopié tel quel, en deux
// morceaux : son en-tête (titre, droit d'auteur et marque de MariaDB), puis, après les paramètres de xSOM
// (Parameters, Notice), ses Terms et les Covenants of Licensor jusqu'à la fin. Le texte SPDX entier a pour empreinte
// d90560217049db1d6020ec7cf482da4198bfa372dffd22270ba08fd8088cd93b.
const (
	bslHeader        = "Business Source License 1.1\n\nLicense text copyright © 2017 MariaDB Corporation Ab, All Rights Reserved.\n\"Business Source License\" is a trademark of MariaDB Corporation Ab.\n\n"
	bslTermsSHA256   = "418989f0e58e9be45720f11d0bba6bf7ff7b61da68753918b784754dc22b011b"
	bslTermsMarker   = "\nTerms\n"
	bslChangeLicence = "Change License:       Apache License, Version 2.0\n"
)

// TestLicense : LICENSE est la Business Source License 1.1, en-tête et Terms recopiés octet pour octet, avec les
// paramètres de xSOM entre les deux (Licensor, Licensed Work, Additional Use Grant, Change Date, Change License).
func TestLicense(t *testing.T) {
	data, err := os.ReadFile("LICENSE")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte(bslHeader)) {
		t.Fatal("LICENSE ne commence pas par l'en-tête officiel de la Business Source License 1.1")
	}
	i := bytes.Index(data, []byte(bslTermsMarker))
	if i < 0 {
		t.Fatal("LICENSE sans section Terms")
	}
	sum := sha256.Sum256(data[i+1:])
	if got := hex.EncodeToString(sum[:]); got != bslTermsSHA256 {
		t.Fatalf("Terms de la licence modifiés (SHA-256 %s)", got)
	}
	params := string(data[len(bslHeader) : i+1])
	for _, want := range []string{
		"\nLicensor:             XSOM CONSULTING",
		"\nLicensed Work:        The expurgation module of Secret Guard",
		"\nAdditional Use Grant: ",
		"\nChange Date:          ",
		"\n" + bslChangeLicence,
	} {
		if !strings.Contains(params, want) {
			t.Errorf("paramètre absent de LICENSE : %q", strings.TrimSpace(want))
		}
	}
}

// TestPublicDependencies : le paquet n'importe de ce dépôt que l'API publique de detect et la partie internal/ du
// module racine ; jamais l'inverse (le moteur ne dépend pas de l'expurgation, vérifié dans tools/depguardcheck et par
// la séparation des modules).
func TestPublicDependencies(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range pkg.Imports {
		if !strings.HasPrefix(imp, "github.com/") {
			continue
		}
		switch {
		case imp == "github.com/xsom-consulting/secret-guard/detect":
		case strings.HasPrefix(imp, "github.com/xsom-consulting/secret-guard/internal/"):
		default:
			t.Errorf("import hors de l'API publique de detect et de internal/ : %s", imp)
		}
	}
}
