package placeholder

import (
	"testing"
	"unicode"
)

func TestCharClassFake_SameLength(t *testing.T) {
	values := []string{
		"abc123XYZ",
		"sk-proj-abc123def456",
		"hello-world_test.value",
		"ALLCAPS123",
		"a",
		"12345",
	}
	for _, v := range values {
		result := charClassFake(v)
		if len(result) != len(v) {
			t.Fatalf("charClassFake(%q): length %d, want %d", v, len(result), len(v))
		}
	}
}

func TestCharClassFake_PrefixPreserved(t *testing.T) {
	restore := setDeterministicRng(30)
	defer restore()

	tests := []struct {
		input  string
		prefix string
	}{
		{"sk-abcdef123456", "sk-"},
		{"ghp_abcdef123456", "ghp_"},
		{"xoxb-123-456-abc", "xoxb-"},
	}
	for _, tt := range tests {
		result := charClassFake(tt.input)
		if result[:len(tt.prefix)] != tt.prefix {
			t.Fatalf("charClassFake(%q): expected prefix %q, got %q", tt.input, tt.prefix, result[:len(tt.prefix)])
		}
	}
}

func TestCharClassFake_SeparatorsPreserved(t *testing.T) {
	restore := setDeterministicRng(40)
	defer restore()

	// The prefix is "abc-", rest is "def.ghi/jkl+mno=pqr"
	input := "abc-def.ghi/jkl+mno=pqr"
	result := charClassFake(input)

	if len(result) != len(input) {
		t.Fatalf("length mismatch: %d vs %d", len(result), len(input))
	}

	// Check separators are preserved in the remainder (after prefix "abc-").
	prefix := "abc-"
	remainder := input[len(prefix):]
	resultRemainder := result[len(prefix):]
	for i, r := range remainder {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			if rune(resultRemainder[i]) != r {
				t.Fatalf("separator %c not preserved at position %d", r, i)
			}
		}
	}
}

func TestCharClassFake_CharacterClasses(t *testing.T) {
	restore := setDeterministicRng(55)
	defer restore()

	input := "aB1cD2eF3"
	result := charClassFake(input)

	if len(result) != len(input) {
		t.Fatalf("length mismatch: %d vs %d", len(result), len(input))
	}

	for i, r := range input {
		rr := rune(result[i])
		switch {
		case unicode.IsDigit(r):
			if !unicode.IsDigit(rr) {
				t.Fatalf("pos %d: expected digit, got %c", i, rr)
			}
		case unicode.IsLower(r):
			if !unicode.IsLower(rr) {
				t.Fatalf("pos %d: expected lowercase, got %c", i, rr)
			}
		case unicode.IsUpper(r):
			if !unicode.IsUpper(rr) {
				t.Fatalf("pos %d: expected uppercase, got %c", i, rr)
			}
		}
	}
}

func TestCharClassFake_EmptyString(t *testing.T) {
	result := charClassFake("")
	if result != "" {
		t.Fatalf("expected empty string, got %q", result)
	}
}

func TestCharClassFake_NoPrefixSeparator(t *testing.T) {
	restore := setDeterministicRng(65)
	defer restore()

	// No separator in input, so no prefix is detected.
	input := "abcDEF123"
	result := charClassFake(input)
	if len(result) != len(input) {
		t.Fatalf("length mismatch: %d vs %d", len(result), len(input))
	}
	// All characters should be replaced (no prefix preserved).
	for i, r := range input {
		rr := rune(result[i])
		switch {
		case unicode.IsDigit(r):
			if !unicode.IsDigit(rr) {
				t.Fatalf("pos %d: expected digit, got %c", i, rr)
			}
		case unicode.IsLower(r):
			if !unicode.IsLower(rr) {
				t.Fatalf("pos %d: expected lowercase, got %c", i, rr)
			}
		case unicode.IsUpper(r):
			if !unicode.IsUpper(rr) {
				t.Fatalf("pos %d: expected uppercase, got %c", i, rr)
			}
		}
	}
}
