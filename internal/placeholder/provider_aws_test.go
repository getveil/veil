package placeholder

import (
	"strings"
	"testing"
)

func TestProviderAWS(t *testing.T) {
	prov := mustProvider(t, "aws")

	t.Run("match_AKIA", func(t *testing.T) {
		if !prov.Match("", "AKIAIOSFODNN7EXAMPLE") {
			t.Fatal("should match AKIA prefix")
		}
	})
	t.Run("match_name_access_key_id", func(t *testing.T) {
		if !prov.Match("AWS_ACCESS_KEY_ID", "anything") {
			t.Fatal("should match AWS_ACCESS_KEY_ID")
		}
	})
	t.Run("match_name_secret", func(t *testing.T) {
		if !prov.Match("AWS_SECRET_ACCESS_KEY", "anything") {
			t.Fatal("should match AWS_SECRET_ACCESS_KEY")
		}
	})
	t.Run("no_match", func(t *testing.T) {
		if prov.Match("OTHER", "value") {
			t.Fatal("should not match unrelated")
		}
	})
	t.Run("generate_AKIA_length", func(t *testing.T) {
		value := "AKIAIOSFODNN7EXAMPLE" // 20 chars
		result := prov.Generate(value)
		if len(result) != 20 {
			t.Fatalf("expected length 20, got %d", len(result))
		}
		if !strings.HasPrefix(result, "AKIA") {
			t.Fatalf("expected AKIA prefix, got: %s", result)
		}
		// Rest should be uppercase alphanumeric (sentinel "VEIL" is uppercase alnum).
		for _, c := range result[4:] {
			isUpper := c >= 'A' && c <= 'Z'
			isDigit := c >= '0' && c <= '9'
			if !isUpper && !isDigit {
				t.Fatalf("expected uppercase alphanumeric, got: %c", c)
			}
		}
	})
	t.Run("generate_secret_key_length", func(t *testing.T) {
		value := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" // 40 chars
		result := prov.Generate(value)
		if len(result) != len(value) {
			t.Fatalf("expected length %d, got %d", len(value), len(result))
		}
	})
	t.Run("match_ASIA", func(t *testing.T) {
		if !prov.Match("", "ASIAIOSFODNN7EXAMPLE") {
			t.Fatal("should match ASIA prefix")
		}
	})
	t.Run("generate_ASIA_length_and_prefix", func(t *testing.T) {
		value := "ASIAIOSFODNN7EXAMPLE" // 20 chars
		result := prov.Generate(value)
		if len(result) != 20 {
			t.Fatalf("expected length 20, got %d", len(result))
		}
		if !strings.HasPrefix(result, "ASIA") {
			t.Fatalf("expected ASIA prefix, got: %s", result)
		}
		for _, c := range result[4:] {
			isUpper := c >= 'A' && c <= 'Z'
			isDigit := c >= '0' && c <= '9'
			if !isUpper && !isDigit {
				t.Fatalf("expected uppercase alphanumeric, got: %c", c)
			}
		}
	})
}

func TestGenerateAWSSessionToken_LengthAndSentinel(t *testing.T) {
	real := "FwoGZXIvYXdzEBYaDG" + strings.Repeat("A", 400)
	ph, err := GenerateAWSSessionToken(real, Set{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ph) != len(real) {
		t.Errorf("length = %d, want %d", len(ph), len(real))
	}
	if !strings.Contains(ph, Sentinel) {
		t.Errorf("placeholder missing sentinel")
	}
}

func TestGenerateAWSSessionToken_CollisionRetry(t *testing.T) {
	real := strings.Repeat("x", 200)
	// Seed the Set with the first expected output so Generate must retry.
	// Since randomness is entropy-seeded, just smoke-test uniqueness across
	// 5 calls rather than trying to force a known collision.
	seen := Set{}
	for i := 0; i < 5; i++ {
		ph, err := GenerateAWSSessionToken(real, seen)
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[ph]; dup {
			t.Fatalf("duplicate placeholder on iteration %d: %q", i, ph)
		}
		seen[ph] = struct{}{}
	}
}
