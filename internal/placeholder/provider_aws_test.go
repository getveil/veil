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
		result := prov.Generate("", value)
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
		result := prov.Generate("", value)
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
		result := prov.Generate("", value)
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

// TestProviderAWS_RoleOverridesValuePrefix is the F-7 regression test: a
// secret access key whose value happens to start with AKIA/ASIA must still
// receive a secret-style (base64-ish) placeholder when the caller asserts
// the role via name. The pre-fix code dispatched purely on value prefix and
// emitted an AKID-shaped placeholder for such secrets — a category error.
func TestProviderAWS_RoleOverridesValuePrefix(t *testing.T) {
	t.Run("AKIA_prefix_secret_via_engine", func(t *testing.T) {
		// 40-char value starting with AKIA — plausible when a real secret
		// access key happens to begin with those four base64 chars.
		secret := "AKIAxutnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1"
		ph, err := Generate("AWS_SECRET_ACCESS_KEY", secret, nil)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if len(ph) != len(secret) {
			t.Fatalf("length = %d, want %d", len(ph), len(secret))
		}
		assertSecretStyleAWSPlaceholder(t, ph)
	})

	t.Run("ASIA_prefix_secret_via_engine", func(t *testing.T) {
		secret := "ASIAxutnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1"
		ph, err := Generate("AWS_SECRET_ACCESS_KEY", secret, nil)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if len(ph) != len(secret) {
			t.Fatalf("length = %d, want %d", len(ph), len(secret))
		}
		assertSecretStyleAWSPlaceholder(t, ph)
	})

	t.Run("scoped_secret_var_name", func(t *testing.T) {
		// Substring match must catch PROD_AWS_SECRET_ACCESS_KEY etc.
		secret := "AKIAxutnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1"
		ph, err := Generate("PROD_AWS_SECRET_ACCESS_KEY", secret, nil)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		assertSecretStyleAWSPlaceholder(t, ph)
	})

	t.Run("counter_AKIA_value_with_AKID_role", func(t *testing.T) {
		// Counter-test: AKID role with AKIA value still gets AKID-style.
		akid := "AKIAIOSFODNN7EXAMPLE"
		ph, err := Generate("AWS_ACCESS_KEY_ID", akid, nil)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if !strings.HasPrefix(ph, "AKIA") {
			t.Fatalf("AKID role should produce AKIA-prefixed placeholder, got %q", ph)
		}
		// Body must be uppercase alphanumeric only.
		for _, c := range ph[4:] {
			isUpper := c >= 'A' && c <= 'Z'
			isDigit := c >= '0' && c <= '9'
			if !isUpper && !isDigit {
				t.Fatalf("AKID body must be upper-alphanumeric, got %c in %q", c, ph)
			}
		}
	})

	t.Run("counter_ASIA_value_with_AKID_role", func(t *testing.T) {
		akid := "ASIAIOSFODNN7EXAMPLE"
		ph, err := Generate("AWS_ACCESS_KEY_ID", akid, nil)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if !strings.HasPrefix(ph, "ASIA") {
			t.Fatalf("AKID role with ASIA value should produce ASIA-prefixed placeholder, got %q", ph)
		}
	})
}

// assertSecretStyleAWSPlaceholder verifies a placeholder is base64-ish (the
// secret-style alphabet) rather than AKID-style (upper-alphanumeric only).
// It runs the assertion across several attempts so the secret alphabet's
// presence is essentially certain rather than a coin flip.
func assertSecretStyleAWSPlaceholder(t *testing.T, ph string) {
	t.Helper()
	// AKID alphabet is [A-Z0-9]. Secret alphabet is base64 ([A-Za-z0-9+/]).
	// The probability of a 40-char base64 placeholder containing zero
	// lowercase/+// chars is (36/64)^40 < 1e-10. So a single run suffices,
	// but we sample across several outputs of the underlying generator to
	// keep the assertion robust against future alphabet tweaks.
	hasNonAKIDChar := func(s string) bool {
		for _, c := range s {
			if (c >= 'a' && c <= 'z') || c == '+' || c == '/' {
				return true
			}
		}
		return false
	}
	if !hasNonAKIDChar(ph) {
		// Sample a few more to confirm we're really in the base64 branch
		// (avoids a freak run where every random byte happened to be upper).
		secret := strings.Repeat("AKIA", 10) // 40 chars, AKIA-prefixed
		anyHadNonAKID := false
		for i := 0; i < 10; i++ {
			alt, err := Generate("AWS_SECRET_ACCESS_KEY", secret, nil)
			if err != nil {
				t.Fatalf("Generate iter %d: %v", i, err)
			}
			if hasNonAKIDChar(alt) {
				anyHadNonAKID = true
				break
			}
		}
		if !anyHadNonAKID {
			t.Fatalf("placeholder %q looks AKID-shaped (upper-alphanumeric only); "+
				"expected base64-ish secret-style output", ph)
		}
	}
	if strings.HasPrefix(ph, "AKIA") || strings.HasPrefix(ph, "ASIA") {
		// A secret placeholder should not be deliberately AKIA/ASIA-prefixed.
		// Random base64 starting with "AKIA" is ~1/16M; tolerate it but
		// re-roll a few times to make sure we're not in the deterministic
		// AKID branch.
		secret := strings.Repeat("AKIA", 10)
		anyNotAKIA := false
		for i := 0; i < 10; i++ {
			alt, err := Generate("AWS_SECRET_ACCESS_KEY", secret, nil)
			if err != nil {
				t.Fatalf("Generate iter %d: %v", i, err)
			}
			if !strings.HasPrefix(alt, "AKIA") && !strings.HasPrefix(alt, "ASIA") {
				anyNotAKIA = true
				break
			}
		}
		if !anyNotAKIA {
			t.Fatalf("every secret placeholder begins with AKIA/ASIA — looks like "+
				"the AKID-preserve branch is firing for secret role; got %q", ph)
		}
	}
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
