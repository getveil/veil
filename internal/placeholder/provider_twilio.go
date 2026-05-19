package placeholder

import "strings"

func init() {
	register(ProviderPattern{
		Name:       "twilio",
		AuthScheme: AuthBasic,
		Priority:   PriorityHandwritten,
		Match: func(name, value string) bool {
			if strings.HasPrefix(value, "SK") && len(value) == 34 {
				return true
			}
			// Name-only fallback: catches custom/unprefixed Twilio tokens
			// stored under a TWILIO_* name. Require a credential-shaped
			// value length so SDK/CI metadata like TWILIO_FROM_NUMBER,
			// TWILIO_REGION, or TWILIO_API_VERSION isn't classified as a
			// secret. Mirrors provider_github.go and provider_supabase.go.
			return len(value) >= secretMinLength &&
				strings.Contains(strings.ToUpper(name), "TWILIO")
		},
		Generate: func(_, value string) string {
			if strings.HasPrefix(value, "SK") {
				// API Key SID: SK + 32 hex chars (sentinel displaces 4 hex chars;
				// the hex shape is intentionally traded for detectability per the
				// Sentinel design in engine.go).
				return sentinelize("SK"+randFromAlphabet(32, "0123456789abcdef"), 2)
			}
			// Auth token: 32 hex chars, no prefix.
			return sentinelize(randFromAlphabet(32, "0123456789abcdef"), 0)
		},
		Hosts: []string{"api.twilio.com"},
	})
}
