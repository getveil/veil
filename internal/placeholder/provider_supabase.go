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
		Name:     "supabase",
		Priority: PriorityHandwritten,
		Match: func(name, value string) bool {
			if strings.Contains(strings.ToUpper(name), "SUPABASE") {
				return true
			}
			return isJWTWithAlg(value)
		},
		Generate: func(_, _ string) string {
			return generateSupabaseJWT("anon")
		},
		Hosts: []string{"*.supabase.co", "*.supabase.com"},
	})
}

// isJWTWithAlg checks if a value looks like a JWT by splitting on dots and
// attempting to decode the first segment as JSON with an "alg" field.
func isJWTWithAlg(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return false
	}
	_, hasAlg := header["alg"]
	return hasAlg
}

// generateSupabaseJWT creates a structurally valid JWT with Supabase-style
// payload fields.
func generateSupabaseJWT(role string) string {
	ref := randAlphanumeric(20)
	now := time.Now()
	iat := now.Add(-24 * time.Hour).Unix()
	exp := now.Add(365 * 24 * time.Hour).Unix()

	payload := fmt.Sprintf(
		`{"iss":"supabase","ref":"%s","role":"%s","iat":%d,"exp":%d}`,
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
