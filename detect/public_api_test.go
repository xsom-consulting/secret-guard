package detect_test

// Test externe : l'API publique seule (pack.Decode, detect.LoadRules, detect.Scan, detect.ScanWithFingerprint)
// reproduit le corpus de parité, comme le ferait un programme qui importe le moteur.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/xsom-consulting/secret-guard/detect"
	"github.com/xsom-consulting/secret-guard/pack"
)

// publicFinding est un constat du corpus de parité, dans la forme publique de Scan.
type publicFinding struct {
	RuleID     string          `json:"ruleId"`
	SecretType string          `json:"secretType"`
	Encoding   detect.Encoding `json:"encoding"`
	Score      int             `json:"score"`
	Level      detect.Level    `json:"level"`
	ByteStart  int             `json:"byteStart"`
	ByteEnd    int             `json:"byteEnd"`
}

func TestPublicAPI(t *testing.T) {
	t.Run("les octets du Pack initial, décodés par pack.Decode et chargés par LoadRules, sont exécutés par Scan comme Secret Guard", func(t *testing.T) {
		decoded, err := pack.Decode(pack.InitialJSON())
		if err != nil {
			t.Fatal(err)
		}
		rules, err := detect.LoadRules(decoded)
		if err != nil {
			t.Fatal(err)
		}
		raw := make([]byte, detect.FingerprintKeyBytes)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		key, err := detect.NewFingerprintKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		defer key.Wipe()
		data, err := os.ReadFile("../vectors/detection/rules-fixed.json")
		if err != nil {
			t.Fatal(err)
		}
		var cases []struct {
			ID         string  `json:"id"`
			Input      string  `json:"input"`
			Encoding   string  `json:"inputEncoding"`
			LanguageID *string `json:"languageId"`
			Expected   struct {
				Complete bool            `json:"complete"`
				Failure  string          `json:"failure"`
				Findings []publicFinding `json:"findings"`
			} `json:"expected"`
		}
		if err := json.Unmarshal(data, &cases); err != nil {
			t.Fatalf("corpus illisible : %v", err)
		}
		order := func(f []publicFinding) {
			sort.SliceStable(f, func(i, j int) bool {
				if f[i].ByteStart != f[j].ByteStart {
					return f[i].ByteStart < f[j].ByteStart
				}
				if f[i].RuleID != f[j].RuleID {
					return f[i].RuleID < f[j].RuleID
				}
				return f[i].ByteEnd < f[j].ByteEnd
			})
		}
		checked := 0
		for _, c := range cases {
			content := []byte(c.Input)
			if c.Encoding == "base64" {
				if content, err = base64.StdEncoding.DecodeString(c.Input); err != nil {
					t.Fatalf("%s : entrée illisible", c.ID)
				}
			} else if c.Encoding != "utf8" {
				t.Fatalf("%s : inputEncoding inconnu", c.ID)
			}
			var options detect.Options
			if c.LanguageID != nil {
				options.LanguageID = *c.LanguageID
			}
			checked++
			result := detect.Scan(content, rules, options)
			if result.Complete != c.Expected.Complete || string(result.Failure) != c.Expected.Failure {
				t.Errorf("%s : issue %s", c.ID, result.Failure)
				continue
			}
			got := make([]publicFinding, 0, len(result.Findings))
			for _, f := range result.Findings {
				if f.LocalFingerprint != "" {
					t.Fatalf("%s : Empreinte locale posée par Scan", c.ID)
				}
				got = append(got, publicFinding{
					RuleID: f.RuleID, SecretType: f.SecretType, Encoding: f.Encoding, Score: f.Score, Level: f.Level,
					ByteStart: f.ByteStart, ByteEnd: f.ByteEnd,
				})
			}
			want := append([]publicFinding{}, c.Expected.Findings...)
			order(got)
			order(want)
			if !reflect.DeepEqual(got, want) && (len(got) != 0 || len(want) != 0) {
				t.Errorf("%s : constats %+v, attendu %+v", c.ID, got, want)
			}
			if c.LanguageID == nil {
				// ScanWithFingerprint : mêmes constats, chacun avec son Empreinte locale.
				fingerprinted := detect.ScanWithFingerprint(content, rules, key)
				if fingerprinted.Complete != result.Complete || len(fingerprinted.Findings) != len(result.Findings) {
					t.Errorf("%s : ScanWithFingerprint diffère de Scan", c.ID)
					continue
				}
				for i, f := range fingerprinted.Findings {
					if len(f.LocalFingerprint) != 32 {
						t.Errorf("%s : Empreinte locale absente", c.ID)
					}
					f.LocalFingerprint = ""
					if f != result.Findings[i] {
						t.Errorf("%s : constat %d différent", c.ID, i)
					}
				}
			}
		}
		if checked == 0 {
			t.Fatal("aucun cas")
		}
	})
	t.Run("un Pack inexploitable est refusé par une erreur typée, rattachée à ErrPackUnusable", func(t *testing.T) {
		p, err := pack.Initial()
		if err != nil {
			t.Fatal(err)
		}
		p.Rules[0].Validator = "luhn"
		rules, err := detect.LoadRules(p)
		var refusal *detect.PackError
		if rules != nil || !errors.Is(err, detect.ErrPackUnusable) || !errors.As(err, &refusal) ||
			refusal.Reason != detect.RefusalUnknownValidator {
			t.Fatalf("%v", err)
		}
	})
}
