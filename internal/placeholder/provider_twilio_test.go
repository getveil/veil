package placeholder

import (
	"strings"
	"testing"
)

func TestProviderTwilio(t *testing.T) {
	var prov ProviderPattern
	for _, p := range registry {
		if p.Name == "twilio" {
			prov = p
			break
		}
	}
	if prov.Name == "" {
		t.Fatal("twilio provider not registered")
	}

	t.Run("match_SK_prefix", func(t *testing.T) {
		if !prov.Match("", "SKabcdef1234567890abcdef1234567890") {
			t.Fatal("should match SK prefix")
		}
	})

	t.Run("match_name_auth_token", func(t *testing.T) {
		if !prov.Match("TWILIO_AUTH_TOKEN", "abcdef1234567890abcdef1234567890") {
			t.Fatal("should match TWILIO in name")
		}
	})

	t.Run("match_name_api_key", func(t *testing.T) {
		if !prov.Match("TWILIO_API_KEY", "SKabcdef1234567890abcdef1234567890") {
			t.Fatal("should match TWILIO in name")
		}
	})

	t.Run("no_match", func(t *testing.T) {
		if prov.Match("OTHER_KEY", "some-value") {
			t.Fatal("should not match unrelated key/value")
		}
	})

	t.Run("generate_SK_prefix", func(t *testing.T) {
		value := "SKabcdef1234567890abcdef1234567890"
		result := prov.Generate(value)
		if !strings.HasPrefix(result, "SK") {
			t.Fatalf("expected SK prefix, got: %s", result)
		}
		if len(result) != 34 { // SK + 32 hex
			t.Fatalf("expected length 34, got %d: %s", len(result), result)
		}
		for _, c := range result[2:] {
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
			if !isHex {
				t.Fatalf("expected hex char, got: %c in %s", c, result)
			}
		}
	})

	t.Run("generate_auth_token", func(t *testing.T) {
		// Auth token matched by name, no SK prefix — 32 hex chars.
		value := "abcdef1234567890abcdef1234567890"
		result := prov.Generate(value)
		if len(result) != 32 {
			t.Fatalf("expected length 32, got %d: %s", len(result), result)
		}
		for _, c := range result {
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
			if !isHex {
				t.Fatalf("expected hex char, got: %c in %s", c, result)
			}
		}
	})

	t.Run("hosts", func(t *testing.T) {
		if len(prov.Hosts) != 1 || prov.Hosts[0] != "api.twilio.com" {
			t.Fatalf("unexpected hosts: %v", prov.Hosts)
		}
	})
}
