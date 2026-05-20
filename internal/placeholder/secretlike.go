package placeholder

import (
	"math"
	"regexp"
	"strings"
)

// secretNamePattern matches common secret-related key names.
var secretNamePattern = regexp.MustCompile(`(?i)(key|secret|token|password|passwd|pwd|auth|credential|dsn)`)

// publicEnvPrefixes are env-var name prefixes (case-insensitive) used by
// front-end build systems to mark values that ship to the client bundle.
// Anything carrying such a prefix is intentionally public and must not be
// vaulted, even if the value looks high-entropy.
var publicEnvPrefixes = []string{
	"NEXT_PUBLIC_",
	"VITE_",
	"REACT_APP_",
	"EXPO_PUBLIC_",
	"PUBLIC_",
}

// hasPublicEnvPrefix reports whether name starts (case-insensitively) with
// any well-known front-end build-system public-bundle prefix. Such names
// are intentionally exposed to the client and must not be classified as
// secrets regardless of value shape.
func hasPublicEnvPrefix(name string) bool {
	upper := strings.ToUpper(name)
	for _, p := range publicEnvPrefixes {
		if strings.HasPrefix(upper, p) {
			return true
		}
	}
	return false
}

// stubValueSubstrings are case-insensitive substrings whose presence in a
// value marks it as a developer placeholder rather than a real secret.
var stubValueSubstrings = []string{
	"your_",
	"_here",
	"replace_me",
	"replaceme",
	"changeme",
	"change_me",
	"fill_in",
	"your-api-key",
	"dummy",
	"fake",
	"example",
	"placeholder",
	"todo",
	"fixme",
}

// stubValueStructural matches values that are entirely a template
// placeholder (angle-bracketed, double-curly-templated, or shell-expanded)
// or that contain four or more consecutive 'x' characters.
var stubValueStructural = regexp.MustCompile(`(?i)(^<.+>$|^\{\{.+\}\}$|^\$\{.+\}$|xxxx+)`)

// isStubValue reports whether value looks like a developer placeholder
// (any case-insensitive substring in stubValueSubstrings, or any structural
// template pattern). Stub values must short-circuit secret detection so
// they are never vaulted as real credentials.
func isStubValue(value string) bool {
	lower := strings.ToLower(value)
	for _, s := range stubValueSubstrings {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return stubValueStructural.MatchString(value)
}

// Calibrated thresholds for the entropy-based secret heuristic. The original
// 3.0 bits/char floor was too low — long file paths and English sentences
// routinely exceed it. Raising to 4.5 and additionally requiring >= 12
// distinct bytes filters most real-world paths / sentences while keeping
// high-entropy tokens like "aB3$dE7&hI1!kL5@nO9#qR2%tU6^wX0*yZ4(cD8" flagged.
// Note: English pangrams reach ~4.39 bits/char, so 4.5 is the minimum floor
// that clears the full negative test suite; the target token scores ~5.29.
const (
	secretMinLength   = 20
	secretMinEntropy  = 4.5
	secretMinDistinct = 12

	// nameMatchMinLength is the minimum value length required for a
	// name-pattern-only match to count as a secret. Values shorter than
	// this floor are treated as non-secrets (e.g., LOG_LEVEL_AUTH=info,
	// DB_PASSWORD_PROMPT=true) even when their name matches the regex.
	nameMatchMinLength = 12

	// nameMatchMinDistinct rules out repetitive values such as
	// "xxxxxxxxxxxx" that would otherwise clear the length floor.
	nameMatchMinDistinct = 6
)

// IsSecretLike determines whether a name/value pair likely represents a
// secret. Returns true when any of:
//   - the value matches a registered provider pattern,
//   - the key name matches a secret-name hint AND the value clears the
//     name-pattern value-shape floor (length + distinct bytes),
//   - the value clears the length + entropy + distinct-byte floor.
//
// Two pre-gates short-circuit detection: a name that carries a front-end
// build-system public-bundle prefix (NEXT_PUBLIC_, VITE_, ...) and a
// value that looks like a developer stub (your_, placeholder, ...).
// Both ALWAYS return false regardless of value shape.
func IsSecretLike(name, value string) bool {
	if hasPublicEnvPrefix(name) {
		return false
	}
	if isStubValue(value) {
		return false
	}
	// 1. Provider patterns.
	for _, p := range DefaultRegistry().All() {
		if p.Match(name, value) {
			return true
		}
	}
	// 2. Key name heuristic, gated by value shape.
	if secretNamePattern.MatchString(name) {
		if len(value) >= nameMatchMinLength && distinctBytes(value) >= nameMatchMinDistinct {
			return true
		}
	}
	// 3. Length + entropy + distinct-byte check.
	if len(value) >= secretMinLength &&
		shannonEntropy(value) >= secretMinEntropy &&
		distinctBytes(value) >= secretMinDistinct {
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

// distinctBytes returns the number of distinct byte values in s. This is
// byte-based (not rune-based) to stay consistent with shannonEntropy, which
// also operates on byte frequencies — so a UTF-8 multi-byte sequence counts
// each underlying byte separately.
func distinctBytes(s string) int {
	var seen [256]bool
	n := 0
	for i := 0; i < len(s); i++ {
		if !seen[s[i]] {
			seen[s[i]] = true
			n++
		}
	}
	return n
}
