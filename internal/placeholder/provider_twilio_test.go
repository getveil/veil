package placeholder

import (
	"strings"
	"testing"
)

func TestProviderTwilio(t *testing.T) {
	prov := mustProvider(t, "twilio")

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
		if len(result) != 34 { // SK + 32 body chars
			t.Fatalf("expected length 34, got %d: %s", len(result), result)
		}
		if !strings.Contains(result, Sentinel) {
			t.Fatalf("expected sentinel %q in %s", Sentinel, result)
		}
		// Body chars outside the sentinel positions must still be hex. The
		// sentinel (VEIL) intentionally displaces 4 hex chars to keep every
		// generated placeholder detectable via bytes.Contains.
		body := result[2:]
		sIdx := strings.Index(body, Sentinel)
		if sIdx < 0 {
			t.Fatalf("sentinel not found in body %s", body)
		}
		nonSentinel := body[:sIdx] + body[sIdx+len(Sentinel):]
		for _, c := range nonSentinel {
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
			if !isHex {
				t.Fatalf("expected hex char outside sentinel, got: %c in %s", c, result)
			}
		}
	})

	t.Run("generate_auth_token", func(t *testing.T) {
		// Auth token matched by name, no SK prefix — 32 body chars with
		// sentinel displacing 4 hex positions.
		value := "abcdef1234567890abcdef1234567890"
		result := prov.Generate(value)
		if len(result) != 32 {
			t.Fatalf("expected length 32, got %d: %s", len(result), result)
		}
		if !strings.Contains(result, Sentinel) {
			t.Fatalf("expected sentinel %q in %s", Sentinel, result)
		}
		sIdx := strings.Index(result, Sentinel)
		nonSentinel := result[:sIdx] + result[sIdx+len(Sentinel):]
		for _, c := range nonSentinel {
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
			if !isHex {
				t.Fatalf("expected hex char outside sentinel, got: %c in %s", c, result)
			}
		}
	})

	t.Run("hosts", func(t *testing.T) {
		if len(prov.Hosts) != 1 || prov.Hosts[0] != "api.twilio.com" {
			t.Fatalf("unexpected hosts: %v", prov.Hosts)
		}
	})
}
