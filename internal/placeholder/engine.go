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

// Generate produces a structurally-valid placeholder for the given secret.
// It tries, in order: URL-aware replacement, provider-specific generation,
// and character-class fallback.
func Generate(name, value string) (string, error) {
	if value == "" {
		return "", errors.New("empty value")
	}
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
