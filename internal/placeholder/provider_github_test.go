package placeholder

import (
	"crypto/x509"
	"encoding/pem"
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
			result := prov.Generate(value)
			if !strings.HasPrefix(result, prefix) {
				t.Fatalf("prefix not preserved: %s", result)
			}
			if len(result) != len(value) {
				t.Fatalf("length mismatch: %d vs %d", len(result), len(value))
			}
		})
	}
	t.Run("match_name", func(t *testing.T) {
		if !prov.Match("GITHUB_TOKEN", "anything") {
			t.Fatal("should match GITHUB in name")
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
		result := prov.Generate(value)
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

func TestGenerateGitHubAppPrivateKey_IsValidRSAPEM(t *testing.T) {
	p, err := GenerateGitHubAppPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Errorf("missing PKCS#1 PEM header: %s", p[:80])
	}
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		t.Fatal("pem.Decode returned nil")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if key.N.BitLen() != 2048 {
		t.Errorf("key bit length = %d, want 2048", key.N.BitLen())
	}
}

func TestGenerateGitHubAppPrivateKey_FreshEachCall(t *testing.T) {
	a, _ := GenerateGitHubAppPrivateKey()
	b, _ := GenerateGitHubAppPrivateKey()
	if a == b {
		t.Error("two calls returned the same PEM (keygen deterministic?)")
	}
}
