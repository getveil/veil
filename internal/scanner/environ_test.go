package scanner

import (
	"testing"

	"github.com/getveil/veil/internal/envkeys"
)

func TestIsObviouslyNotSecret_DenylistedNames(t *testing.T) {
	// POSIX / shell / system names must be classified as obviously-not-secret
	// so the runtime fail-closed scan doesn't fire on PATH, PWD, etc.
	cases := []string{
		"PATH", "HOME", "PWD", "OLDPWD", "TMPDIR", "SHELL",
		"HOMEBREW_PREFIX", "TERM_PROGRAM_VERSION", "XDG_RUNTIME_DIR",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if !IsObviouslyNotSecret(name) {
				t.Errorf("IsObviouslyNotSecret(%q) = false; expected true", name)
			}
		})
	}
}

// TestIsObviouslyNotSecret_PrefixDenylist covers the F-2 regression: Claude
// Code and OpenTelemetry inject env vars into child processes whose names
// trip the secret-name heuristic ("auth" substring, high-entropy values) but
// are not credentials. They must be skipped before IsSecretLike runs.
func TestIsObviouslyNotSecret_PrefixDenylist(t *testing.T) {
	cases := []string{
		"CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH",
		"CLAUDE_CODE_ENTRYPOINT",
		"OTEL_EXPORTER_OTLP_HEADERS",
		"OTEL_RESOURCE_ATTRIBUTES",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if !IsObviouslyNotSecret(name) {
				t.Errorf("IsObviouslyNotSecret(%q) = false; expected true (prefix denylist)", name)
			}
		})
	}
}

// TestIsObviouslyNotSecret_DoesNotMaskRealCredentials guards against an
// over-broad denylist rule (e.g. a bare "ANTHROPIC_" prefix) that would
// silently exempt real credentials.
func TestIsObviouslyNotSecret_DoesNotMaskRealCredentials(t *testing.T) {
	cases := []string{
		"ANTHROPIC_API_KEY",
		"OPENAI_API_KEY",
		"GITHUB_TOKEN",
		"STRIPE_SECRET_KEY",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if IsObviouslyNotSecret(name) {
				t.Errorf("IsObviouslyNotSecret(%q) = true; credential names must NOT be denylisted", name)
			}
		})
	}
}

// TestIsObviouslyNotSecret_SkipsAllVeilInternalKeys pins the source-of-truth
// contract: every entry in envkeys.VeilInternalKeys MUST be classified as
// obviously-not-secret. Previously the denylist hardcoded a partial subset
// and omitted VEIL_PASSPHRASE — so the runtime scan would warn that the very
// passphrase decrypting the vault was "looking like a secret." The fix
// iterates envkeys.VeilInternalKeys at the call site; this test makes that
// contract a build-time fact (the loop below covers any future addition).
func TestIsObviouslyNotSecret_SkipsAllVeilInternalKeys(t *testing.T) {
	for _, name := range envkeys.VeilInternalKeys {
		t.Run(name, func(t *testing.T) {
			if !IsObviouslyNotSecret(name) {
				t.Errorf("IsObviouslyNotSecret(%q) = false; every VeilInternalKey must be skipped", name)
			}
		})
	}
}

// TestIsObviouslyNotSecret_SkipsAllProxyAndCAKeys mirrors the
// VeilInternalKeys contract for proxy and CA-related names. These ride along
// in the user's shell when veil run launches a subprocess, and should never
// be flagged by the runtime fail-closed scan.
func TestIsObviouslyNotSecret_SkipsAllProxyAndCAKeys(t *testing.T) {
	for _, name := range envkeys.ProxyKeys {
		t.Run(name, func(t *testing.T) {
			if !IsObviouslyNotSecret(name) {
				t.Errorf("IsObviouslyNotSecret(%q) = false; every ProxyKey must be skipped", name)
			}
		})
	}
	for _, name := range envkeys.CAKeys {
		t.Run(name, func(t *testing.T) {
			if !IsObviouslyNotSecret(name) {
				t.Errorf("IsObviouslyNotSecret(%q) = false; every CAKey must be skipped", name)
			}
		})
	}
}
