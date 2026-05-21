package placeholder

import (
	"errors"
	"strings"
	"testing"
)

// FuzzPlaceholderReplace fuzzes the full Generate() path (provider →
// charclass fallback) with adversarial names and values. Asserts:
//  1. No panic.
//  2. Non-empty value → non-empty placeholder (or defined error).
//  3. Returned placeholder never equals the input value.
func FuzzPlaceholderReplace(f *testing.F) {
	// Real-world seeds covering every provider we ship.
	seeds := []struct{ name, value string }{
		{"OPENAI_API_KEY", "sk-proj-abcdef123456"},
		{"ANTHROPIC_API_KEY", "sk-ant-api03-abcdef123456"},
		{"GITHUB_TOKEN", "ghp_abcdef1234567890abcdef"},
		{"GITHUB_FINE_PAT", "github_pat_11ABCDEFGHIJKLMNOPQRST_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXa"},
		{"STRIPE_SECRET_KEY", "sk_live_abcdef123456abcdef"},
		{"SLACK_BOT_TOKEN", "xoxb-123-456-abc789def"},
		{"SENDGRID_API_KEY", "SG.abcdefghij0123456789._-abcdefghijklmnopqrstuvwxyz0123456789abcd"},
		{"SUPABASE_SERVICE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def"},
		{"INTERNAL_API_KEY", "abcdef01234567890abcdef0123456789"},
		{"FALLBACK", "just-some-opaque-value-that-hits-charclass"},
		{"", ""},
		{"", "only-value"},
		{"ONLY_NAME", ""},
	}
	for _, s := range seeds {
		f.Add(s.name, s.value)
	}

	f.Fuzz(func(t *testing.T, name, value string) {
		// Add the input value itself to the "existing" collision set. Generate
		// retries up to maxCollisionRetries if the candidate collides; this
		// means a returned placeholder cannot equal the input. For very short
		// values (1-2 chars) where the candidate pool is tiny, Generate will
		// legitimately return ErrCollisionUnresolvable, which we accept.
		existing := Set{}
		if value != "" {
			existing[value] = struct{}{}
		}
		ph, err := Generate(name, value, existing)
		if err != nil {
			if errors.Is(err, ErrCollisionUnresolvable) {
				return
			}
			if strings.Contains(err.Error(), "empty value") {
				return
			}
			t.Fatalf("unexpected error %q for name=%q value=%q", err, name, value)
		}
		if ph == "" {
			t.Fatalf("empty placeholder for name=%q value=%q", name, value)
		}
		if ph == value {
			t.Fatalf("placeholder equals input despite collision set\n name=%q\n value=%q\n ph=%q", name, value, ph)
		}
	})
}
