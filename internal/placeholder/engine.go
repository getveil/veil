// Package placeholder generates structurally-valid fake values for secrets.
//
// It supports provider-specific patterns (OpenAI, Anthropic, GitHub, Stripe,
// AWS, Slack), URL-aware password replacement, and a character-class fallback
// that preserves the structural shape of any secret value.
package placeholder

import (
	"crypto/rand"
	"errors"
	"io"
)

// rng is the randomness source used by all placeholder generation.
// It defaults to crypto/rand.Reader but can be overridden in tests
// for deterministic output.
var rng io.Reader = rand.Reader

// Set is a set of placeholder strings used for collision detection.
type Set map[string]struct{}

// maxCollisionRetries caps how many candidate placeholders are tried before
// returning ErrCollisionUnresolvable. Providers that produce enough random
// bits (>=64 alphabet^length entropy) should essentially never reach this
// limit; it exists so pathological cases fail loudly instead of looping.
const maxCollisionRetries = 8

// Generate produces a structurally-valid placeholder for the given secret,
// retrying up to maxCollisionRetries times to avoid collisions with the
// supplied `existing` set. Pass nil or an empty Set if collision checks are
// not required. Returns ErrCollisionUnresolvable if no unique candidate is
// found within the retry budget.
func Generate(name, value string, existing Set) (string, error) {
	if value == "" {
		return "", errors.New("empty value")
	}
	for attempt := 0; attempt < maxCollisionRetries; attempt++ {
		ph, err := generateOnce(name, value)
		if err != nil {
			return "", err
		}
		if _, clash := existing[ph]; !clash {
			return ph, nil
		}
	}
	return "", ErrCollisionUnresolvable
}

// generateOnce produces a single candidate placeholder without collision
// checks. Exposed for tests; callers should prefer Generate.
func generateOnce(name, value string) (string, error) {
	if ph, ok := tryURL(value); ok {
		return ph, nil
	}
	for _, p := range registry {
		if p.Match(name, value) {
			return p.Generate(value), nil
		}
	}
	return charClassFake(value), nil
}

// GenerateOnceForTest exposes generateOnce for tests. Production callers
// should use Generate.
var GenerateOnceForTest = generateOnce

// randAlphanumeric generates n random alphanumeric characters.
func randAlphanumeric(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	return randFromAlphabet(n, alphabet)
}

// randUpperAlphanumeric generates n random uppercase alphanumeric characters.
func randUpperAlphanumeric(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	return randFromAlphabet(n, alphabet)
}

// randBase64ish generates n random base64-like characters.
func randBase64ish(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
	return randFromAlphabet(n, alphabet)
}

// randFromAlphabet generates n random characters selected from the given alphabet.
// It uses rejection sampling to avoid modular bias and panics if the RNG fails,
// since crypto/rand failure indicates a catastrophic system state.
func randFromAlphabet(n int, alphabet string) string {
	if n <= 0 {
		return ""
	}
	result := make([]byte, n)
	alen := len(alphabet)
	limit := 256 - (256 % alen) // largest multiple of alen <= 256
	written := 0
	buf := make([]byte, n*2) // read extra to reduce iterations
	for written < n {
		_, err := io.ReadFull(rng, buf)
		if err != nil {
			panic("placeholder: rng failed: " + err.Error())
		}
		for _, b := range buf {
			if written == n {
				break
			}
			if int(b) < limit {
				result[written] = alphabet[int(b)%alen]
				written++
			}
		}
	}
	return string(result)
}
