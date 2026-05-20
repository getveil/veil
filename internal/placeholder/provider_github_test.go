package placeholder

import (
	"strings"
	"testing"
)

func TestProviderGitHub(t *testing.T) {
	prov := mustProvider(t, "github")

	for _, prefix := range []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"} {
		t.Run("match_"+prefix, func(t *testing.T) {
			if !prov.Match("", prefix+"abc123") {
				t.Fatalf("should match %s prefix", prefix)
			}
		})
		t.Run("generate_"+prefix, func(t *testing.T) {
			value := prefix + "abcdef123456abcdef123456"
			result := prov.Generate("", value)
			if !strings.HasPrefix(result, prefix) {
				t.Fatalf("prefix not preserved: %s", result)
			}
			if len(result) != len(value) {
				t.Fatalf("length mismatch: %d vs %d", len(result), len(value))
			}
		})
	}
	t.Run("match_name", func(t *testing.T) {
		// Name-only fallback requires a credential-shaped value length so CI
		// metadata like GITHUB_REF_NAME=main isn't misclassified as a secret.
		if !prov.Match("GITHUB_TOKEN", "abcdef0123456789abcdef0123456789abcdef01") {
			t.Fatal("should match GITHUB in name for credential-shaped value")
		}
	})
	t.Run("no_match_short_value_with_github_in_name", func(t *testing.T) {
		// GitHub Actions injects GITHUB_REF_NAME=main and similar metadata.
		// These must not be classified as secrets.
		for _, kv := range []struct{ name, value string }{
			{"GITHUB_REF_NAME", "main"},
			{"GITHUB_EVENT_NAME", "push"},
			{"GITHUB_JOB", "test"},
			{"GITHUB_REF_TYPE", "branch"},
		} {
			if prov.Match(kv.name, kv.value) {
				t.Errorf("should not match CI metadata %s=%q", kv.name, kv.value)
			}
		}
	})
	t.Run("no_match", func(t *testing.T) {
		if prov.Match("OTHER", "value") {
			t.Fatal("should not match unrelated")
		}
	})
}

func TestProviderGitHub_FinegrainedPAT(t *testing.T) {
	prov := mustProvider(t, "github")

	value := "github_pat_11ABCDEFGHIJKLMNOPQRST_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXa"

	t.Run("match_github_pat_prefix", func(t *testing.T) {
		if !prov.Match("", value) {
			t.Fatal("should match github_pat_ prefix")
		}
	})

	t.Run("generate_github_pat_structure", func(t *testing.T) {
		result := prov.Generate("", value)
		if len(result) != len(value) {
			t.Fatalf("length mismatch: %d vs %d", len(result), len(value))
		}
		if result[:11] != "github_pat_" {
			t.Fatalf("expected github_pat_ prefix, got: %s", result[:11])
		}
		// Position 33 (11 + 22) should be an underscore.
		if result[33] != '_' {
			t.Fatalf("expected underscore at position 33, got: %c in %s", result[33], result)
		}
		// Characters 11-32 should be alphanumeric.
		for i := 11; i < 33; i++ {
			c := rune(result[i])
			isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			if !isAlnum {
				t.Fatalf("expected alphanumeric at pos %d, got: %c", i, c)
			}
		}
		// Characters 34-92 should be alphanumeric.
		for i := 34; i < len(result); i++ {
			c := rune(result[i])
			isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			if !isAlnum {
				t.Fatalf("expected alphanumeric at pos %d, got: %c", i, c)
			}
		}
	})
}

func TestProviderGitHub_IsVaultEligible(t *testing.T) {
	r := DefaultRegistry()
	p, ok := r.Get("github")
	if !ok {
		t.Fatal("github provider not registered")
	}
	if !p.VaultEligible {
		t.Fatal("github provider must declare VaultEligible: true")
	}
	if len(p.Hosts) == 0 {
		t.Fatal("github provider must declare a non-empty Hosts set")
	}
}
