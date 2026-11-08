// SPDX-License-Identifier: Apache-2.0

package jstext

import "testing"

func TestIsWhitespace(t *testing.T) {
	for _, r := range []rune{'\t', '\n', '\v', '\f', '\r', ' ', 0x00A0, 0x1680, 0x2000, 0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF} {
		if !IsWhitespace(r) {
			t.Errorf("U+%04X : espace de JavaScript attendu", r)
		}
	}
	for _, r := range []rune{'a', '0', '_', 0x001F, 0x0085, 0x180E, 0x1FFF, 0x200B, 0x2060, 0xFFFD} {
		if IsWhitespace(r) {
			t.Errorf("U+%04X : pas un espace de JavaScript", r)
		}
	}
}

func TestUTF16Units(t *testing.T) {
	for text, want := range map[string]int{
		"": 0, "abc": 3, "é": 1, "😀": 2, "a😀b": 4, "\xff": 1, "a\xff\xfeb": 4, "\xf0\x9f\x98": 3,
	} {
		if got := UTF16Units([]byte(text)); got != want {
			t.Errorf("%q : %d unités, %d attendues", text, got, want)
		}
	}
}
