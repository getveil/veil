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
