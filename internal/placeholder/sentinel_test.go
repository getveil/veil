package placeholder

import (
	"strings"
	"testing"
)

// variedSentinelBody mirrors the varied-alphabet helper used in the
// providers_contract_test.go test package; duplicated here because
// providers_contract_test.go is package placeholder_test and this file
// is package placeholder. Kept short and inlined rather than promoted
// to a shared helper.
func variedSentinelBody(n int) string {
	const alphabet = "abcdef0123456789"
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = alphabet[i%len(alphabet)]
	}
	return string(b)
}

// TestGenerateAlwaysContainsSentinel asserts that every placeholder generated
// by the engine contains the detection sentinel. This lets the proxy's
// fail-closed guard detect a leaked placeholder with a single substring scan.
func TestGenerateAlwaysContainsSentinel(t *testing.T) {
	cases := []struct {
		label string
		name  string
		value string
	}{
		{"openai_prefix", "SOME_KEY", "sk-proj-" + variedSentinelBody(40)},
		{"openai_by_name", "OPENAI_API_KEY", variedSentinelBody(40)},
		{"anthropic_prefix", "SOME_KEY", "sk-ant-api03-" + variedSentinelBody(95)},
		{"anthropic_by_name", "ANTHROPIC_API_KEY", variedSentinelBody(40)},
		{"github_ghp", "SOME_KEY", "ghp_" + variedSentinelBody(36)},
		{"github_pat", "SOME_KEY", "github_pat_" + variedSentinelBody(22) + "_" + variedSentinelBody(59)},
		{"github_by_name", "GITHUB_TOKEN", variedSentinelBody(40)},
		{"stripe_live", "SOME_KEY", "sk_live_" + variedSentinelBody(24)},
		{"stripe_test", "SOME_KEY", "sk_test_" + variedSentinelBody(24)},
		{"stripe_by_name", "STRIPE_SECRET_KEY", "sk_live_" + variedSentinelBody(24)},
		{"slack_bot", "SOME_KEY", "xoxb-" + variedSentinelBody(50)},
		{"slack_by_name", "SLACK_TOKEN", variedSentinelBody(40)},
		{"sendgrid_prefix", "SOME_KEY", "SG." + variedSentinelBody(22) + "." + variedSentinelBody(43)},
		{"sendgrid_by_name", "SENDGRID_API_KEY", variedSentinelBody(60)},
		{"supabase_by_name", "SUPABASE_ANON_KEY", variedSentinelBody(40)},
		{"google_prefix", "SOME_KEY", "AIza" + variedSentinelBody(35)},
		{"replicate_prefix", "SOME_KEY", "r8_" + variedSentinelBody(37)},
		{"huggingface_prefix", "SOME_KEY", "hf_" + variedSentinelBody(34)},
		{"vercel_prefix", "SOME_KEY", "vercel_" + variedSentinelBody(16)},
		{"gitlab_prefix", "SOME_KEY", "glpat-" + variedSentinelBody(20)},
		{"resend_prefix", "SOME_KEY", "re_" + variedSentinelBody(20)},
		{"charclass_fallback", "UNKNOWN_KEY", "arbitrarySecret12345_value"},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			ph, err := Generate(tc.name, tc.value, nil)
			if err != nil {
				t.Fatalf("Generate(%q, %q): %v", tc.name, tc.value, err)
			}
			if !strings.Contains(ph, Sentinel) {
				t.Fatalf("placeholder %q does not contain sentinel %q", ph, Sentinel)
			}
		})
	}
}

// TestSentinelConstIsExported asserts the sentinel is available to callers
// (like the proxy's fail-closed guard) as a package-level constant.
func TestSentinelConstIsExported(t *testing.T) {
	if Sentinel == "" {
		t.Fatal("Sentinel is empty")
	}
	if len(Sentinel) < 4 {
		t.Fatalf("Sentinel %q shorter than 4 chars; detection is too weak", Sentinel)
	}
}

// TestContainsSentinel locks in the contract used by the init pipeline to
// refuse re-vaulting its own placeholders.
func TestContainsSentinel(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"plain_secret", "ghp_5KsHJk2lQmN8pR4tWxY7zA1bC3dE5fG7hI9j", false},
		{"sentinel_at_start", Sentinel + "xyz", true},
		{"sentinel_after_prefix", "ghp_" + Sentinel + "abc", true},
		{"generated_placeholder_round_trip", "", true}, // filled in below
	}
	ph, err := Generate("GITHUB_TOKEN", "ghp_"+variedSentinelBody(36), nil)
	if err != nil {
		t.Fatalf("Generate seed: %v", err)
	}
	cases[len(cases)-1].in = ph

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ContainsSentinel(tc.in); got != tc.want {
				t.Fatalf("ContainsSentinel(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
