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
			// SendGrid API keys: SG. + 22 base64 chars + . + 43 base64 chars
			return "SG." + randBase64ish(22) + "." + randBase64ish(43)
		},
		Hosts: []string{"api.sendgrid.com"},
	})
}
