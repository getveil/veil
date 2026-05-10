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

// nameImpliesAWSSecret reports whether name unambiguously identifies an AWS
// secret access key (rather than an access key ID). Substring match handles
// scoped variants like PROD_AWS_SECRET_ACCESS_KEY.
func nameImpliesAWSSecret(name string) bool {
	return strings.Contains(strings.ToUpper(name), "AWS_SECRET_ACCESS_KEY")
}

// nameImpliesAWSAccessKeyID reports whether name unambiguously identifies an
// AWS access key ID (rather than a secret).
func nameImpliesAWSAccessKeyID(name string) bool {
	return strings.Contains(strings.ToUpper(name), "AWS_ACCESS_KEY_ID")
}

func init() {
	register(ProviderPattern{
		Name:     "aws",
		Priority: PriorityHandwritten,
		Match: func(name, value string) bool {
			if strings.HasPrefix(value, "AKIA") || strings.HasPrefix(value, "ASIA") {
				return true
			}
			return nameImpliesAWSSecret(name) || nameImpliesAWSAccessKeyID(name)
		},
		Generate: func(name, value string) string {
			// Role takes priority over value pattern: a secret value that
			// happens to start with AKIA/ASIA must still get a secret-style
			// placeholder, and an AKID forced through a non-AKID-shaped value
			// (e.g., user typo) must still get an AKID-style placeholder when
			// the env-var name says so.
			if nameImpliesAWSSecret(name) {
				return sentinelize(randBase64ish(len(value)), 0)
			}
			if nameImpliesAWSAccessKeyID(name) {
				return generateAKIDPlaceholder(value)
			}
			// Name doesn't disambiguate — fall back to the value's prefix.
			if strings.HasPrefix(value, "AKIA") || strings.HasPrefix(value, "ASIA") {
				return generateAKIDPlaceholder(value)
			}
			return sentinelize(randBase64ish(len(value)), 0)
		},
		Hosts: []string{"*.amazonaws.com"},
	})
}

// generateAKIDPlaceholder produces an AKID-style placeholder, preserving the
// 4-char AKIA/ASIA prefix when present (added by commit c49af85). For values
// without that prefix (when a caller asserts the role via name), default to
// AKIA + random upper-alphanumeric body.
func generateAKIDPlaceholder(value string) string {
	prefix := "AKIA"
	rest := len(value) - 4
	if strings.HasPrefix(value, "AKIA") || strings.HasPrefix(value, "ASIA") {
		prefix = value[:4]
	} else if len(value) < 4 {
		// Pathologically short value: pad with random body so length matches.
		prefix = ""
		rest = len(value)
	}
	return sentinelize(prefix+randUpperAlphanumeric(rest), len(prefix))
}
