package scanner

import (
	"testing"
)

func TestScanEnviron_DetectsSecretLike(t *testing.T) {
	environ := []string{
		"HOME=/home/user",
		"PATH=/usr/bin:/bin",
		"OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrst",
		"EDITOR=vim",
	}

	got := ScanEnviron(environ)

	if len(got) != 1 {
		t.Fatalf("ScanEnviron returned %d candidates, want 1: %+v", len(got), got)
	}
	if got[0].Name != "OPENAI_API_KEY" {
		t.Errorf("Name = %q, want OPENAI_API_KEY", got[0].Name)
	}
	if got[0].Value != "sk-proj-abcdefghijklmnopqrst" {
		t.Errorf("Value = %q, want full secret value", got[0].Value)
	}
}

func TestScanEnviron_SkipsDenylistedNames(t *testing.T) {
	// Names on the denylist are skipped even if their values look secret-like.
	environ := []string{
		// High-entropy paths and IDs that would otherwise trip IsSecretLike.
		"PATH=/usr/local/opt/rust/bin:/Users/x/.cargo/bin:/Users/x/.rbenv/shims",
		"HOMEBREW_PREFIX=/opt/homebrew",
		"TERM_PROGRAM_VERSION=444.1.2",
		"XDG_RUNTIME_DIR=/run/user/1000/abc123def456",
	}

	got := ScanEnviron(environ)

	if len(got) != 0 {
		t.Fatalf("ScanEnviron returned %d candidates for denylisted names, want 0: %+v", len(got), got)
	}
}

// TestScanEnviron_SkipsClaudeCodeAndOTelInjectedNames covers the F-2 regression:
// Claude Code and OpenTelemetry inject env vars into child processes that look
// secret-like to the heuristic (high-entropy URLs / baggage strings, or names
// containing the substring "auth") but are not credentials. They must be
// skipped during `veil init` so users aren't prompted to redact them.
func TestScanEnviron_SkipsClaudeCodeAndOTelInjectedNames(t *testing.T) {
	// Values are deliberately long and high-entropy so they would pass
	// IsSecretLike on their own; the test proves the denylist is what skips them.
	environ := []string{
		"ANTHROPIC_BASE_URL=https://api.anthropic.com/v1/x9k2m4p7q1w3e5r6t8y0u2i4o6a8s0d2f4g6h8j0",
		"BAGGAGE=session.id=a1b2c3d4e5f6g7h8i9j0,user.id=u1v2w3x4y5z6a7b8c9d0,trace.id=t1q2r3s4",
		"CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH=true",
		// Prefix denylist coverage with values that would otherwise trip the
		// length+entropy heuristic.
		"CLAUDE_CODE_ENTRYPOINT=cli-x9k2m4p7q1w3e5r6t8y0u2i4o6a8s0d2f4g6h8j0",
		"OTEL_EXPORTER_OTLP_HEADERS=x9k2m4p7q1w3e5r6t8y0u2i4o6a8s0d2f4g6h8j0",
	}

	got := ScanEnviron(environ)

	if len(got) != 0 {
		t.Fatalf("ScanEnviron returned %d candidates for Claude Code / OTel injected names, want 0: %+v", len(got), got)
	}
}

// TestScanEnviron_DetectsAnthropicAPIKey guards against an over-broad denylist
// rule (e.g. an "ANTHROPIC_" prefix) that would silently skip real credentials.
func TestScanEnviron_DetectsAnthropicAPIKey(t *testing.T) {
	environ := []string{
		"ANTHROPIC_BASE_URL=https://api.anthropic.com",
		"ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789",
	}

	got := ScanEnviron(environ)

	if len(got) != 1 || got[0].Name != "ANTHROPIC_API_KEY" {
		t.Fatalf("ScanEnviron = %+v, want only ANTHROPIC_API_KEY", got)
	}
}

func TestScanEnviron_SkipsNonSecretLike(t *testing.T) {
	environ := []string{
		"FOO=bar",
		"COUNT=42",
		"ENABLED=true",
	}

	got := ScanEnviron(environ)

	if len(got) != 0 {
		t.Fatalf("ScanEnviron returned %d candidates for non-secret values, want 0: %+v", len(got), got)
	}
}

func TestScanEnviron_DeduplicatesByName(t *testing.T) {
	// If the same name appears twice (last assignment wins in real shells,
	// but os.Environ() returns the last-set value once; defensively handle dupes).
	environ := []string{
		"API_TOKEN=first-high-entropy-zzzzzzzzzzz",
		"API_TOKEN=second-high-entropy-yyyyyyyyyy",
	}

	got := ScanEnviron(environ)

	if len(got) != 1 {
		t.Fatalf("ScanEnviron returned %d candidates for duplicate name, want 1: %+v", len(got), got)
	}
	if got[0].Value != "second-high-entropy-yyyyyyyyyy" {
		t.Errorf("Value = %q, want last-wins value", got[0].Value)
	}
}

func TestScanEnviron_SkipsMalformedEntries(t *testing.T) {
	environ := []string{
		"NO_EQUALS_SIGN",
		"=VALUE_WITH_EMPTY_NAME",
		"OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrst",
	}

	got := ScanEnviron(environ)

	if len(got) != 1 || got[0].Name != "OPENAI_API_KEY" {
		t.Fatalf("ScanEnviron = %+v, want only OPENAI_API_KEY", got)
	}
}
