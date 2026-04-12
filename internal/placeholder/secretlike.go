package placeholder

import (
	"math"
	"regexp"
)

// secretNamePattern matches common secret-related key names.
var secretNamePattern = regexp.MustCompile(`(?i)(key|secret|token|password|passwd|pwd|auth|credential|dsn)`)

// IsSecretLike determines whether a name/value pair likely represents a secret.
// It returns true if:
//   - The value matches any registered provider pattern.
//   - The value is a URL with a password in a supported scheme.
//   - The key name matches common secret-related patterns.
//   - The value is long (>= 20 chars) with high Shannon entropy (>= 3.0 bits/char).
func IsSecretLike(name, value string) bool {
	// 1. Check provider patterns.
	for _, p := range registry {
		if p.Match(name, value) {
			return true
		}
	}

	// 2. Check URL with password.
	if isURLWithPassword(value) {
		return true
	}

	// 3. Check key name heuristic.
	if secretNamePattern.MatchString(name) {
		return true
	}

	// 4. Length + entropy check.
	if len(value) >= 20 && shannonEntropy(value) >= 3.0 {
		return true
	}

	return false
}

// shannonEntropy computes Shannon entropy in bits per character over byte
// frequencies in s. Returns 0 for empty strings.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[byte]int)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}

	n := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / n
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}
