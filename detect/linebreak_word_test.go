// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"strings"
	"testing"
)

func TestLooksLikeWrappedTail(t *testing.T) {
	for tail, want := range map[string]bool{
		"": false, "fi": false, "done": false, "EOF": false, "End": false, "x": false, "my-task": false,
		"snake_case": false, "camelCase": false, "iPhone": false, "aBc": false, "internationalization": false,
		"v2": true, "aB3d": true, "xYzW": true, "ab/c": true, "a+b": true, strings.Repeat("abcd", 6): true, "fooBarBaz": true,
	} {
		if got := looksLikeWrappedTail([]byte(tail)); got != want {
			t.Errorf("%q : %v, attendu %v", tail, got, want)
		}
	}
}
