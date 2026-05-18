package scanner

import (
	"testing"

	"github.com/getveil/veil/internal/envkeys"
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

// TestScanEnviron_SkipsAllVeilInternalKeys pins the source-of-truth contract:
// every entry in envkeys.VeilInternalKeys MUST be filtered out by
// ScanEnviron, regardless of how secret-like its value is. Previously the
// denylist hardcoded a partial subset (VEIL_TEST_KEYSTORE, VEIL_MCP_CONFIG_PATH)
// and omitted VEIL_PASSPHRASE — so a real high-entropy passphrase tripped the
// value heuristic and was routed into the vault as a credential. The fix
// iterates envkeys.VeilInternalKeys at the call site; this test makes that
// contract a build-time fact (the loop below covers any future addition).
func TestScanEnviron_SkipsAllVeilInternalKeys(t *testing.T) {
	// A long, high-entropy, fully-distinct value — easily passes
	// placeholder.IsSecretLike's name-independent value heuristic
	// (length ≥ 20, entropy ≥ 4.5, distinct bytes ≥ 12).
	const veryLeakyValue = "aB3$dE7&hI1!kL5@nO9#qR2%tU6^wX0*yZ4(cD8"

	for _, name := range envkeys.VeilInternalKeys {
		t.Run(name, func(t *testing.T) {
			if !IsObviouslyNotSecret(name) {
				t.Errorf("IsObviouslyNotSecret(%q) = false; every VeilInternalKey must be skipped", name)
			}
			got := ScanEnviron([]string{name + "=" + veryLeakyValue})
			if len(got) != 0 {
				t.Errorf("ScanEnviron captured %q (value would otherwise pass IsSecretLike); got %+v", name, got)
			}
		})
	}
}

// TestScanEnviron_SkipsVEILPassphraseRegression pins the specific past leak:
// a real master passphrase set via VEIL_PASSPHRASE must never be returned as
// a credential candidate. Without this filter, `veil init` (file keystore
// path on Linux) would auto-vault the very key that decrypts the vault.
func TestScanEnviron_SkipsVEILPassphraseRegression(t *testing.T) {
	// A plausible real passphrase: 32 random hex chars from `openssl rand -hex 16`.
	environ := []string{
		"VEIL_PASSPHRASE=7f3a9c1e4b8d2a6f5e0c9b4d8a3f1e6c",
	}
	got := ScanEnviron(environ)
	if len(got) != 0 {
		t.Fatalf("ScanEnviron captured VEIL_PASSPHRASE — vault master key would be vaulted as a credential. Got: %+v", got)
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

func TestScanEnvironForPairs_KeepsUsernameLikeNames(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin",                       // POSIX — must be filtered
		"DB_USERNAME=alice",                   // non-secret-shaped, must keep
		"DB_PASSWORD=longsecret1234",          // secret-shaped, must keep
		"OTEL_TRACES_SAMPLER=parentbased",     // prefix-denylisted, must filter
	}
	got := ScanEnvironForPairs(environ)
	want := map[string]string{
		"DB_USERNAME": "alice",
		"DB_PASSWORD": "longsecret1234",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates, want %d: %+v", len(got), len(want), got)
	}
	for _, c := range got {
		if w, ok := want[c.Name]; !ok || w != c.Value {
			t.Errorf("unexpected candidate %s=%q", c.Name, c.Value)
		}
	}
}

func TestScanEnvironForPairs_DropsEmptyKeys(t *testing.T) {
	environ := []string{
		"=lonelyvalue",      // no key — drop
		"DB_USER=alice",
	}
	got := ScanEnvironForPairs(environ)
	if len(got) != 1 || got[0].Name != "DB_USER" {
		t.Fatalf("got %+v, want only DB_USER", got)
	}
}
