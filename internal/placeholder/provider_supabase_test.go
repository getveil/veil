package placeholder

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestProviderSupabase(t *testing.T) {
	var prov ProviderPattern
	for _, p := range registry {
		if p.Name == "supabase" {
			prov = p
			break
		}
	}
	if prov.Name == "" {
		t.Fatal("supabase provider not registered")
	}

	// A real-looking Supabase anon key (JWT).
	anonKey := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InByb2plY3RpZCIsInJvbGUiOiJhbm9uIiwiaWF0IjoxNjg2MDAwMDAwLCJleHAiOjE4NDM2ODAwMDB9.abc123def456ghijklmnopqrstuvwxyz01234567890AB"

	t.Run("match_name_anon", func(t *testing.T) {
		if !prov.Match("SUPABASE_ANON_KEY", "anything") {
			t.Fatal("should match SUPABASE in name")
		}
	})

	t.Run("match_name_service_role", func(t *testing.T) {
		if !prov.Match("SUPABASE_SERVICE_ROLE_KEY", "anything") {
			t.Fatal("should match SUPABASE in name")
		}
	})

	t.Run("match_jwt_value", func(t *testing.T) {
		if !prov.Match("SOME_OTHER_KEY", anonKey) {
			t.Fatal("should match JWT value with alg field")
		}
	})

	t.Run("no_match", func(t *testing.T) {
		if prov.Match("OTHER_KEY", "some-value") {
			t.Fatal("should not match unrelated key/value")
		}
	})

	t.Run("generate_jwt_structure", func(t *testing.T) {
		result := prov.Generate(anonKey)

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
		if payload["iss"] != "supabase" {
			t.Fatalf("expected iss supabase, got: %v", payload["iss"])
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
		result := prov.Generate(anonKey)
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
		a := prov.Generate(anonKey)
		b := prov.Generate(anonKey)
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
