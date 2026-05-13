package placeholder

import (
	"strings"
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

func TestCharClassFake_SeparatorsPreserved(t *testing.T) {
	restore := setDeterministicRng(40)
	defer restore()

	input := "abc-def.ghi/jkl+mno=pqr"
	result := charClassFake(input)

	if len(result) != len(input) {
		t.Fatalf("length mismatch: %d vs %d", len(result), len(input))
	}

	// Every non-alphanumeric character must appear at the same byte position
	// in result. This is the structural shape that callers rely on; only the
	// alphanumeric content is randomized.
	for i, r := range input {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			if rune(result[i]) != r {
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

func TestCharClassFake_AllAlphanumericRandomized(t *testing.T) {
	restore := setDeterministicRng(65)
	defer restore()

	// No separators: every position must be replaced with a random char of
	// the same class.
	input := "abcDEF123"
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

// TestCharClassFake_DoesNotLeakInputPrefix is a regression for C1: the prior
// implementation copied the leading alphanumeric run verbatim up to the first
// '-' or '_'. The caller wraps the result with sentinelize(_, 0), which only
// overwrites bytes 0..3, so every alphanumeric byte from position 4 up to
// the first separator survived into the placeholder and leaked the secret.
// The fix randomizes every alphanumeric position; here we assert the
// surviving alphanumeric run from input never appears in the output.
func TestCharClassFake_DoesNotLeakInputPrefix(t *testing.T) {
	restore := setDeterministicRng(75)
	defer restore()

	cases := []struct {
		input string
		// leak is the longest alphanumeric run from input that the buggy
		// code would have preserved verbatim. Long enough that random
		// coincidence in the fixed code is astronomically unlikely.
		leak string
	}{
		{"tenant_abc-prod-key_realsecretvalue", "tenant"},
		{"myDatabase_pwd123", "myDatabase"},
		{"mySuperSecret_token", "mySuperSecret"},
		{"github_pat_secrettail", "github"},
		{"longSecretWithoutSeparators", "longSecretWithoutSeparators"},
	}
	for _, tt := range cases {
		result := charClassFake(tt.input)
		if len(result) != len(tt.input) {
			t.Fatalf("charClassFake(%q): length %d, want %d", tt.input, len(result), len(tt.input))
		}
		if strings.Contains(result, tt.leak) {
			t.Fatalf("charClassFake(%q) leaked %q in result %q", tt.input, tt.leak, result)
		}
	}
}
