// SPDX-License-Identifier: PolyForm-Small-Business-1.0.0

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

// polyFormSHA256 est l'empreinte du texte officiel de PolyForm Small Business 1.0.0
// (https://polyformproject.org/licenses/small-business/1.0.0), recopié tel quel.
const polyFormSHA256 = "03eea824bff13316b767424b3e8f49538b46e52d897aecc87d6344343364aa56"

// requiredNotice est l'avis que PolyForm exige de transmettre avec le logiciel (section « Notices »).
const requiredNotice = "\nRequired Notice: Copyright (c) 2026 XSOM CONSULTING (https://xsom.fr)\n"

// TestLicense : LICENSE est le texte officiel de PolyForm Small Business 1.0.0, octet pour octet, suivi de la seule
// ligne Required Notice de xSOM.
func TestLicense(t *testing.T) {
	data, err := os.ReadFile("LICENSE")
	if err != nil {
		t.Fatal(err)
	}
	text, ok := bytes.CutSuffix(data, []byte(requiredNotice))
	if !ok {
		t.Fatal("LICENSE ne finit pas par la ligne Required Notice de xSOM")
	}
	sum := sha256.Sum256(text)
	if got := hex.EncodeToString(sum[:]); got != polyFormSHA256 {
		t.Fatalf("texte de la licence modifié (SHA-256 %s)", got)
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
