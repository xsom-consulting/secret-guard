package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoverageThreshold(t *testing.T) {
	cases := []struct {
		name    string
		profile string
		code    int
		want    string
	}{
		{"couverture du moteur — au-dessus du seuil, accepté", "ok.out", 0, "pack\t83.3 %"},
		{"couverture du moteur — pack sous 80 %, refusé", "low-domain.out", 1, "pack\t70.0 %"},
		{"couverture du moteur — detect sous 80 %, refusé", "low-detection.out", 1, "detect\t50.0 %"},
		{"couverture du moteur — sous-paquet non testé compté, refusé", "untested-subpackage.out", 1, "pack\t66.7 %"},
		{"couverture du moteur — blocs en double fusionnés, 80 % accepté", "merged-blocks.out", 0, "pack\t80.0 %"},
		{"couverture du moteur — préfixe voisin ignoré", "sibling-prefix.out", 0, "pack\t100.0 %"},
		{"couverture du moteur — paquets sans instruction acceptés", "vacuous.out", 0, "(0/0 instructions"},
		{"couverture du moteur — profil vide refusé", "empty.out", 1, ""},
		{"couverture du moteur — profil sans mode refusé", "no-mode.out", 1, ""},
		{"couverture du moteur — profil mal formé refusé", "malformed.out", 1, ""},
		{"couverture du moteur — profil absent refusé", "absent.out", 1, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run([]string{filepath.Join("testdata", tc.profile)}, &stdout, &stderr)
			if code != tc.code {
				t.Fatalf("code = %d, attendu %d\nstdout : %s\nstderr : %s", code, tc.code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.want) {
				t.Fatalf("stdout = %q, attendu %q", stdout.String(), tc.want)
			}
			if tc.code != 0 && stdout.Len() == 0 && stderr.Len() == 0 {
				t.Fatal("échec sans explication")
			}
		})
	}
}

func TestSeuilParametrable(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-min", "90", filepath.Join("testdata", "ok.out")}, &stdout, &stderr); code != 1 {
		t.Fatalf("seuil 90 sur 83,3 %% : code = %d, attendu 1", code)
	}
}

func TestUsage(t *testing.T) {
	profile := filepath.Join("testdata", "low-domain.out")
	for _, args := range [][]string{
		{}, {"a.out", "b.out"}, {"-inconnu"},
		{"-min", "NaN", profile}, {"-min", "-1", profile}, {"-min", "100.1", profile}, {"-min", "Inf", profile},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Fatalf("args %q : code = %d, attendu 2", args, code)
		}
	}
}
