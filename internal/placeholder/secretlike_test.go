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

func TestIsSecretLike_SecretKeyName_GatedByValueShape(t *testing.T) {
	// Name pattern alone is no longer enough — a trivial value must not
	// trigger vaulting. These all match the secret regex but have
	// length-or-distinct values below the gate floor.
	noLonger := []struct{ name, value string }{
		{"API_KEY", "short"},
		{"DB_PASSWORD", "abc"},
		{"AUTH_TOKEN", "xyz"},
		{"MY_SECRET", "val"},
		{"CREDENTIAL_FILE", "path"},
		{"DSN", "val"},
		{"LOG_LEVEL_AUTH", "info"},
		{"AUTH_METHOD", "oauth"},
		{"DB_PASSWORD_PROMPT", "true"},
		{"PWD_THEME", "bracketed"},
	}
	for _, kv := range noLonger {
		if IsSecretLike(kv.name, kv.value) {
			t.Errorf("%s=%q: expected false after value-shape gate", kv.name, kv.value)
		}
	}

	// Name match with a value that clears len>=12 AND distinct>=6 still passes.
	stillSecret := []struct{ name, value string }{
		{"API_KEY", "abcdef123456"},                // len=12, distinct=12
		{"DB_PASSWORD", "ghp_realtoken1234567890"}, // realistic token
		{"AUTH_TOKEN", "xoxb-1234-5678-abcdef"},    // slack-style
	}
	for _, kv := range stillSecret {
		if !IsSecretLike(kv.name, kv.value) {
			t.Errorf("%s=%q: expected true (passes value-shape gate)", kv.name, kv.value)
		}
	}
}

func TestIsSecretLike_NameMatchValueShapeBoundary(t *testing.T) {
	cases := []struct {
		name, value string
		want        bool
		why         string
	}{
		{"API_KEY", "12345678901a", true, "len=12, distinct=11 — passes both floors"},
		{"API_KEY", "12345678901", false, "len=11 — fails length floor"},
		{"API_KEY", "aaaaaaaaaaaa", false, "len=12, distinct=1 — fails distinct floor"},
		{"API_KEY", "aabbccdd1111", false, "len=12, distinct=5 (a,b,c,d,1) — fails distinct floor by one"},
		{"API_KEY", "aabbccdd1122", true, "len=12, distinct=6 (a,b,c,d,1,2) — meets distinct floor exactly"},
		{"API_KEY", "aabbccddeexx", true, "len=12, distinct=6 (a,b,c,d,e,x) — meets distinct floor"},
	}
	for _, tc := range cases {
		got := IsSecretLike(tc.name, tc.value)
		if got != tc.want {
			t.Errorf("%s=%q: got %v want %v (%s)", tc.name, tc.value, got, tc.want, tc.why)
		}
	}
}

func TestIsSecretLike_CIMetadataNotSecret(t *testing.T) {
	// GitHub Actions injects these vars into every job. They are runner
	// metadata, not credentials, and must not trip the secret-like heuristic
	// even though their names contain "GITHUB". Misclassification triggers
	// the deterministic-sentinel collision bug (see TestGenerate_NoDeterministicSentinelCollisionForShortValues).
	for _, kv := range []struct{ name, value string }{
		{"GITHUB_REF_NAME", "main"},
		{"GITHUB_EVENT_NAME", "push"},
		{"GITHUB_JOB", "test"},
		{"GITHUB_REF_TYPE", "branch"},
		{"GITHUB_REPOSITORY_OWNER", "getveil"},
		{"GITHUB_WORKFLOW", "CI"},
	} {
		if IsSecretLike(kv.name, kv.value) {
			t.Errorf("%s=%q should not be classified secret-like (CI metadata)", kv.name, kv.value)
		}
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
	if e >= secretMinEntropy {
		t.Skipf("test value entropy %.2f is >= %.2f, need a lower entropy value", e, secretMinEntropy)
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

// TestIsSecretLike_FilePathNotFlagged asserts that a typical Unix file path
// is not flagged as secret-like. These are a common false-positive source
// because they have moderate entropy (~4.0 bits/char) and exceed 20 chars.
func TestIsSecretLike_FilePathNotFlagged(t *testing.T) {
	cases := []string{
		"/home/user/workspace/veil/internal/placeholder/providers.go",
		"/home/alice/projects/foo/bar/baz/qux.py",
		"/var/log/syslog.1.gz",
		"~/.config/app/settings.json",
	}
	for _, value := range cases {
		t.Run(value, func(t *testing.T) {
			// Key name is deliberately non-secretish so only the
			// length+entropy heuristic can fire.
			if IsSecretLike("SOMEPATH", value) {
				t.Fatalf("expected file path not to be secret-like: %q (entropy=%.2f, distinct=%d)",
					value, shannonEntropy(value), distinctBytes(value))
			}
		})
	}
}

// TestIsSecretLike_EnglishSentenceNotFlagged asserts that a typical English
// sentence is not flagged as secret-like.
func TestIsSecretLike_EnglishSentenceNotFlagged(t *testing.T) {
	cases := []string{
		"the quick brown fox jumps over the lazy dog",
		"this is a sample log line emitted by the service",
		"error: could not connect to the backend server",
	}
	for _, value := range cases {
		t.Run(value, func(t *testing.T) {
			if IsSecretLike("LOG_LINE", value) {
				t.Fatalf("expected English sentence not to be secret-like: %q (entropy=%.2f, distinct=%d)",
					value, shannonEntropy(value), distinctBytes(value))
			}
		})
	}
}

// TestIsSecretLike_HighEntropyLong_StillFlagged preserves the original
// positive signal: a genuinely random, high-entropy string with many
// distinct bytes must still be flagged.
func TestIsSecretLike_HighEntropyLong_StillFlagged(t *testing.T) {
	value := "aB3$dE7&hI1!kL5@nO9#qR2%tU6^wX0*yZ4(cD8"
	if !IsSecretLike("UNKNOWN", value) {
		t.Fatalf("expected true for high-entropy long string (entropy=%.2f, distinct=%d)",
			shannonEntropy(value), distinctBytes(value))
	}
}

// TestDistinctBytes verifies the helper's correctness.
func TestDistinctBytes(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"a", 1},
		{"aa", 1},
		{"ab", 2},
		{"abcabc", 3},
		{"abcdefghij", 10},
	}
	for _, tc := range cases {
		if got := distinctBytes(tc.in); got != tc.want {
			t.Fatalf("distinctBytes(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
