package placeholder

import "strings"

func init() {
	register(ProviderPattern{
		Name: "sendgrid",
		Match: func(name, value string) bool {
			if strings.HasPrefix(value, "SG.") {
				return true
			}
			return strings.Contains(strings.ToUpper(name), "SENDGRID")
		},
		Generate: func(value string) string {
			// SendGrid API keys: SG. + 22 base64 chars + . + 43 base64 chars.
			// Sentinel (uppercase alnum) is valid base64 content; it lands at
			// offset 3 (start of the first base64 block).
			return sentinelize("SG."+randBase64ish(22)+"."+randBase64ish(43), 3)
		},
		Hosts: []string{"api.sendgrid.com"},
	})
}
