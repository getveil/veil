package placeholder

import "strings"

func init() {
	Register(ProviderPattern{
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
				rest := len(value) - 4
				return "AKIA" + randUpperAlphanumeric(rest)
			}
			// Secret access key: base64-ish characters, same length.
			return randBase64ish(len(value))
		},
	})
}
