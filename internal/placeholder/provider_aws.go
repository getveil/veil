package placeholder

import "strings"

// GenerateAWSSessionToken produces a placeholder for an AWS STS session token.
// Session tokens are long base64-ish strings (~300-800 bytes). Length is
// preserved; Sentinel is embedded near the start.
func GenerateAWSSessionToken(value string, existing Set) (string, error) {
	for attempt := 0; attempt < maxCollisionRetries; attempt++ {
		candidate := sentinelize(randBase64ish(len(value)), 0)
		if _, ok := existing[candidate]; !ok {
			return candidate, nil
		}
	}
	return "", ErrCollisionUnresolvable
}

func init() {
	register(ProviderPattern{
		Name:     "aws",
		Priority: PriorityHandwritten,
		Match: func(name, value string) bool {
			if strings.HasPrefix(value, "AKIA") || strings.HasPrefix(value, "ASIA") {
				return true
			}
			upper := strings.ToUpper(name)
			return upper == "AWS_SECRET_ACCESS_KEY" || upper == "AWS_ACCESS_KEY_ID"
		},
		Generate: func(value string) string {
			if strings.HasPrefix(value, "AKIA") || strings.HasPrefix(value, "ASIA") {
				// Access key ID: preserve the 4-char AKIA/ASIA prefix, fill rest with
				// uppercase alphanumeric. Sentinel (uppercase) fits cleanly in the
				// upper-alnum body.
				prefix := value[:4]
				rest := len(value) - 4
				return sentinelize(prefix+randUpperAlphanumeric(rest), 4)
			}
			// Secret access key: base64-ish characters, same length.
			// Sentinel (uppercase letters) is valid base64 content.
			return sentinelize(randBase64ish(len(value)), 0)
		},
		Hosts: []string{"*.amazonaws.com"},
	})
}
