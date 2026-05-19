package placeholder

import "strings"

func init() {
	register(ProviderPattern{
		Name:       "sendgrid",
		AuthScheme: AuthBearer,
		Priority:   PriorityHandwritten,
		Match: func(name, value string) bool {
			if strings.HasPrefix(value, "SG.") {
				return true
			}
			// Name-only fallback: catches custom/unprefixed tokens stored
			// under a SENDGRID_* name. Require a credential-shaped value
			// length so we don't classify config metadata like
			// SENDGRID_FROM_EMAIL=foo@bar.com or SENDGRID_REGION=us as
			// secrets. Mirrors the floor applied in provider_github.go.
			return len(value) >= secretMinLength &&
				strings.Contains(strings.ToUpper(name), "SENDGRID")
		},
		Generate: func(_, _ string) string {
			// SendGrid API keys: SG. + 22 base64 chars + . + 43 base64 chars.
			// Sentinel (uppercase alnum) is valid base64 content; it lands at
			// offset 3 (start of the first base64 block).
			return sentinelize("SG."+randBase64ish(22)+"."+randBase64ish(43), 3)
		},
		Hosts: []string{"api.sendgrid.com"},
	})
}
