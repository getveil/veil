package placeholder

import "strings"

func init() {
	register(ProviderPattern{
		Name: "aws",
		Match: func(name, value string) bool {
			if strings.HasPrefix(value, "AKIA") {
				return true
			}
			upper := strings.ToUpper(name)
			return upper == "AWS_SECRET_ACCESS_KEY" || upper == "AWS_ACCESS_KEY_ID"
		},
		Generate: func(value string) string {
			if strings.HasPrefix(value, "AKIA") {
				// Access key ID: preserve AKIA, fill rest with uppercase alphanumeric.
				// Sentinel (uppercase) fits cleanly in the upper-alnum body.
				rest := len(value) - 4
				return sentinelize("AKIA"+randUpperAlphanumeric(rest), 4)
			}
			// Secret access key: base64-ish characters, same length.
			// Sentinel (uppercase letters) is valid base64 content.
			return sentinelize(randBase64ish(len(value)), 0)
		},
		Hosts: []string{"*.amazonaws.com"},
	})
}
