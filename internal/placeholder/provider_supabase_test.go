package placeholder

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestProviderSupabase(t *testing.T) {
	prov := mustProvider(t, "supabase")

	// A real-looking Supabase anon key (JWT). iss includes "supabase.co" so the
	// JWT body alone is enough to trigger the provider — the tightened
	// isJWTWithAlg requires either SUPABASE in the key name or iss containing
	// "supabase.co" in the JWT payload.
	anonPayload := `{"iss":"https://abcdefg.supabase.co/auth/v1","ref":"abcdefg","role":"anon","iat":1686000000,"exp":1843680000}`
	anonKey := jwtHeader + "." +
		base64.RawURLEncoding.EncodeToString([]byte(anonPayload)) + "." +
		"abc123def456ghijklmnopqrstuvwxyz01234567890AB"

	t.Run("match_name_anon", func(t *testing.T) {
		// Exercises isJWTWithAlg's name-hint path directly via prov.Match;
		// shape-gate enforcement is covered separately by
		// TestSupabaseNameMatchGatedAtRegistry, so this test uses a
		// credential-shaped varied value rather than a low-distinct
		// Repeat("a", 40).
		if !prov.Match("SUPABASE_ANON_KEY", "abcdef0123456789abcdef0123456789abcdef01") {
			t.Fatal("should match SUPABASE in name for credential-shaped value")
		}
	})

	t.Run("match_name_service_role", func(t *testing.T) {
		if !prov.Match("SUPABASE_SERVICE_ROLE_KEY", "abcdef0123456789abcdef0123456789abcdef01") {
			t.Fatal("should match SUPABASE in name for credential-shaped value")
		}
	})

	t.Run("match_jwt_supabase_iss", func(t *testing.T) {
		if !prov.Match("SOME_OTHER_KEY", anonKey) {
			t.Fatal("should match JWT whose payload iss contains supabase.co")
		}
	})

	t.Run("no_match", func(t *testing.T) {
		if prov.Match("OTHER_KEY", "some-value") {
			t.Fatal("should not match unrelated key/value")
		}
	})

	t.Run("no_match_unrelated_jwt", func(t *testing.T) {
		// JWTs from Auth0/Cognito/Firebase/etc. share the {alg,typ:JWT}
		// header shape with Supabase. Matching on header shape alone
		// caused Supabase placeholders to be injected for unrelated
		// providers; the iss check rules these out.
		auth0Payload := `{"iss":"https://example.auth0.com/","sub":"auth0|abc","aud":"client123"}`
		auth0JWT := jwtHeader + "." +
			base64.RawURLEncoding.EncodeToString([]byte(auth0Payload)) + "." +
			"abc123def456ghijklmnopqrstuvwxyz01234567890AB"
		if prov.Match("AUTH0_TOKEN", auth0JWT) {
			t.Fatal("should not match Auth0 JWT (iss does not contain supabase.co)")
		}
	})

	t.Run("generate_jwt_structure", func(t *testing.T) {
		result := prov.Generate("", anonKey)

		parts := strings.Split(result, ".")
		if len(parts) != 3 {
			t.Fatalf("expected 3 JWT segments, got %d: %s", len(parts), result)
		}

		// Header should decode to valid JSON with alg and typ.
		headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatalf("header not valid base64url: %v", err)
		}
		var header map[string]interface{}
		if err := json.Unmarshal(headerJSON, &header); err != nil {
			t.Fatalf("header not valid JSON: %v", err)
		}
		if header["alg"] != "HS256" {
			t.Fatalf("expected alg HS256, got: %v", header["alg"])
		}
		if header["typ"] != "JWT" {
			t.Fatalf("expected typ JWT, got: %v", header["typ"])
		}

		// Payload should decode to valid JSON with iss, ref, role, iat, exp.
		payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("payload not valid base64url: %v", err)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(payloadJSON, &payload); err != nil {
			t.Fatalf("payload not valid JSON: %v", err)
		}
		if payload["iss"] != "https://placeholder.supabase.co/auth/v1" {
			t.Fatalf("expected iss https://placeholder.supabase.co/auth/v1, got: %v", payload["iss"])
		}
		if _, ok := payload["ref"]; !ok {
			t.Fatal("expected ref field in payload")
		}
		if _, ok := payload["iat"]; !ok {
			t.Fatal("expected iat field in payload")
		}
		if _, ok := payload["exp"]; !ok {
			t.Fatal("expected exp field in payload")
		}

		// Signature segment should be non-empty.
		if len(parts[2]) == 0 {
			t.Fatal("expected non-empty signature segment")
		}
	})

	t.Run("generate_anon_role", func(t *testing.T) {
		result := prov.Generate("", anonKey)
		parts := strings.Split(result, ".")
		payloadJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var payload map[string]interface{}
		_ = json.Unmarshal(payloadJSON, &payload)

		role, ok := payload["role"].(string)
		if !ok {
			t.Fatal("expected role field as string")
		}
		if role != "anon" {
			t.Fatalf("expected role anon, got: %s", role)
		}
	})

	t.Run("generate_different", func(t *testing.T) {
		a := prov.Generate("", anonKey)
		b := prov.Generate("", anonKey)
		if a == b {
			t.Fatal("expected different outputs")
		}
	})

	t.Run("hosts", func(t *testing.T) {
		found := false
		for _, h := range prov.Hosts {
			if h == "*.supabase.co" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected *.supabase.co in hosts, got: %v", prov.Hosts)
		}
	})
}

// TestSupabaseNameMatchGatedAtRegistry ensures the name-only fallback
// in isJWTWithAlg won't flag CI / config metadata vars whose name
// happens to contain "SUPABASE" but whose value is clearly not a
// credential. The check now lives at Registry.Match
// (passesValueShapeGate) rather than inside isJWTWithAlg.
func TestSupabaseNameMatchGatedAtRegistry(t *testing.T) {
	reg := DefaultRegistry()
	cases := []struct{ name, value string }{
		{"SUPABASE_REGION", "us-east-1"},
		{"SUPABASE_PROJECT_REF", "abcd1234"},
	}
	for _, c := range cases {
		if p := reg.Match(c.name, c.value); p != nil {
			t.Errorf("Registry.Match should not match Supabase metadata %s=%q; got %s", c.name, c.value, p.Name)
		}
	}
}

// TestSupabasePlaceholderRoundTripsThroughMatch verifies the placeholder
// generated by the Supabase provider is itself re-recognised by Match when
// stored under an arbitrary key name. Without this property, a user who
// re-runs `veil init --force` on a previously-vaulted .env can lose
// value-based detection for Supabase JWTs stored under non-SUPABASE_* names.
func TestSupabasePlaceholderRoundTripsThroughMatch(t *testing.T) {
	prov := mustProvider(t, "supabase")

	generated := prov.Generate("SB_TOKEN", "")
	if !prov.Match("DIFFERENT_KEY_NAME", generated) {
		t.Fatalf("generated placeholder must round-trip through Match via value-based path; got: %s", generated)
	}
}

func TestProviderSupabase_IsVaultEligible(t *testing.T) {
	p, ok := DefaultRegistry().Get("supabase")
	if !ok {
		t.Fatal("supabase provider not registered")
	}
	if !p.VaultEligible {
		t.Fatal("supabase provider must declare VaultEligible: true")
	}
}
