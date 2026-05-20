package placeholder

import "strings"

func init() {
	register(ProviderPattern{
		Name:          "sendgrid",
		VaultEligible: true,
		Hosts:         []string{"api.sendgrid.com"},
		Match: func(name, value string) bool {
			return strings.HasPrefix(value, "SG.")
		},
		Generate: func(_, _ string) string {
			// SendGrid API keys: SG. + 22 base64 chars + . + 43 base64 chars.
			// Sentinel (uppercase alnum) is valid base64 content; it lands at
			// offset 3 (start of the first base64 block).
			return sentinelize("SG."+randBase64ish(22)+"."+randBase64ish(43), 3)
		},
	})
}
