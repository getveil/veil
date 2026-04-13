package placeholder

import "strings"

func init() {
	register(ProviderPattern{
		Name: "twilio",
		Match: func(name, value string) bool {
			if strings.HasPrefix(value, "SK") && len(value) == 34 {
				return true
			}
			return strings.Contains(strings.ToUpper(name), "TWILIO")
		},
		Generate: func(value string) string {
			if strings.HasPrefix(value, "SK") {
				// API Key SID: SK + 32 hex chars.
				return "SK" + randFromAlphabet(32, "0123456789abcdef")
			}
			// Auth token: 32 hex chars, no prefix.
			return randFromAlphabet(32, "0123456789abcdef")
		},
		Hosts: []string{"api.twilio.com"},
	})
}
