package placeholder

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// jwtHeader is the fixed base64url-encoded JWT header for HS256.
// Decodes to: {"alg":"HS256","typ":"JWT"}
const jwtHeader = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

func init() {
	register(ProviderPattern{
		Name:          "supabase",
		VaultEligible: true,
		Hosts:         []string{"*.supabase.co", "*.supabase.com"},
		Match:         isJWTWithAlg,
		Generate: func(_, _ string) string {
			return generateSupabaseJWT("anon")
		},
	})
}

// isJWTWithAlg returns true only when the credential is clearly a Supabase
// JWT — either the key name carries "SUPABASE", or the JWT payload's iss
// field references supabase.co. The earlier shape-only check ("looks like a
// JWT") matched every signed token in the wild (Auth0, Cognito, Firebase,
// custom apps), producing false positives that caused us to inject Supabase
// placeholders for unrelated credentials.
func isJWTWithAlg(name, value string) bool {
	// Name-only fallback: catches custom/unprefixed tokens stored under a
	// SUPABASE_* name. Require a credential-shaped value length so we don't
	// classify config metadata like SUPABASE_REGION=us-east-1 or
	// SUPABASE_PROJECT_REF=abcd1234 as secrets. Mirrors the floor applied in
	// provider_github.go.
	if len(value) >= secretMinLength &&
		strings.Contains(strings.ToUpper(name), "SUPABASE") {
		return true
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return false
	}
	iss, _ := payload["iss"].(string)
	return strings.Contains(iss, "supabase.co")
}

// generateSupabaseJWT creates a structurally valid JWT with Supabase-style
// payload fields.
func generateSupabaseJWT(role string) string {
	ref := randAlphanumeric(20)
	now := time.Now()
	iat := now.Add(-24 * time.Hour).Unix()
	exp := now.Add(365 * 24 * time.Hour).Unix()

	// Use the canonical Supabase JWT iss format so the placeholder is
	// re-detectable by isJWTWithAlg via the iss-containing-"supabase.co"
	// path. Without "supabase.co" in iss, a vaulted JWT stored under a
	// non-SUPABASE_* key name falls through to no-match on a subsequent
	// `veil init` pass.
	payload := fmt.Sprintf(
		`{"iss":"https://placeholder.supabase.co/auth/v1","ref":"%s","role":"%s","iat":%d,"exp":%d}`,
		ref, role, iat, exp,
	)
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))

	const base64urlAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	// Sentinel (uppercase letters) is valid base64url content; embed it at
	// the start of the signature so leaked Supabase JWTs are detectable via
	// a single substring scan.
	signature := sentinelize(randFromAlphabet(43, base64urlAlphabet), 0)

	return jwtHeader + "." + encodedPayload + "." + signature
}
