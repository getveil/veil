package placeholder

import "testing"

func TestIsSecretLike_ProviderMatch(t *testing.T) {
	if !IsSecretLike("", "sk-proj-abc123def456ghi") {
		t.Fatal("expected true for OpenAI-style key")
	}
}

func TestIsSecretLike_URLWithPassword(t *testing.T) {
	if !IsSecretLike("DATABASE_URL", "postgres://user:secret@host:5432/db") {
		t.Fatal("expected true for URL with password")
	}
}

func TestIsSecretLike_SecretKeyName(t *testing.T) {
	// Short value but secret-like key name.
	if !IsSecretLike("API_KEY", "short") {
		t.Fatal("expected true for secret-like key name")
	}
	if !IsSecretLike("DB_PASSWORD", "abc") {
		t.Fatal("expected true for PASSWORD key name")
	}
	if !IsSecretLike("AUTH_TOKEN", "xyz") {
		t.Fatal("expected true for AUTH key name")
	}
	if !IsSecretLike("MY_SECRET", "val") {
		t.Fatal("expected true for SECRET key name")
	}
	if !IsSecretLike("CREDENTIAL_FILE", "path") {
		t.Fatal("expected true for CREDENTIAL key name")
	}
	if !IsSecretLike("DSN", "val") {
		t.Fatal("expected true for DSN key name")
	}
}

func TestIsSecretLike_HighEntropyLong(t *testing.T) {
	// 40-char high-entropy string.
	value := "aB3$dE7&hI1!kL5@nO9#qR2%tU6^wX0*yZ4(cD8"
	if !IsSecretLike("UNKNOWN", value) {
		t.Fatalf("expected true for high-entropy long string (entropy=%.2f)", shannonEntropy(value))
	}
}

func TestIsSecretLike_LowEntropyShort(t *testing.T) {
	if IsSecretLike("UNKNOWN", "hello") {
		t.Fatal("expected false for short low-entropy string")
	}
}

func TestIsSecretLike_PlainWord(t *testing.T) {
	if IsSecretLike("GREETING", "hello") {
		t.Fatal("expected false for plain word")
	}
}

func TestIsSecretLike_HostnameLongLowEntropy(t *testing.T) {
	// Long but low entropy (repetitive characters).
	value := "aaabbbcccdddeeefffggg"
	e := shannonEntropy(value)
	if e >= 3.0 {
		t.Skipf("test value entropy %.2f is >= 3.0, need a lower entropy value", e)
	}
	if IsSecretLike("HOSTNAME", value) {
		t.Fatalf("expected false for long low-entropy string (entropy=%.2f)", e)
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input   string
		minBits float64
		maxBits float64
	}{
		{"", 0, 0},
		{"aaaa", 0, 0.01},
		{"abcd", 1.9, 2.1}, // 4 distinct chars, uniform = 2.0
		{"aB3$dE7&hI1!", 3.0, 4.0},
	}
	for _, tt := range tests {
		e := shannonEntropy(tt.input)
		if e < tt.minBits || e > tt.maxBits {
			t.Fatalf("shannonEntropy(%q) = %.4f, want [%.2f, %.2f]", tt.input, e, tt.minBits, tt.maxBits)
		}
	}
}

func TestIsSecretLike_LongButRepeating(t *testing.T) {
	// 30 chars but all the same character - entropy = 0
	value := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if IsSecretLike("DATA", value) {
		t.Fatal("expected false for long all-same-char string")
	}
}
