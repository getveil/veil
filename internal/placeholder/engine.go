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
	"strings"
)

// rng is the randomness source used by all placeholder generation.
// It defaults to crypto/rand.Reader but can be overridden in tests
// for deterministic output.
var rng io.Reader = rand.Reader

// Sentinel is a short, high-entropy-but-rare substring embedded into every
// generated placeholder so the proxy's fail-closed guard can detect a leaked
// placeholder with a single bytes.Contains scan.
//
// Design decisions:
//   - "VEIL" (4 uppercase ASCII letters) is short enough to fit into even the
//     most constrained placeholder body (32 hex chars for Twilio/Datadog) and
//     long enough that a collision with random content of a real secret is
//     vanishingly unlikely (36^-4 ≈ 1 in 1.7M for upper-alnum; lower for hex
//     bodies where VEIL is not a valid character at all — the whole string
//     would have to bear the sentinel, which cannot happen for a hex secret).
//   - Placement: immediately after the provider prefix. Tokens like
//     "sk_live_VEIL_<N random>" remain structurally valid (VEIL is
//     alphanumeric) and preserve total length; the sentinel sits in the
//     random portion where it is easy for the proxy to detect but indistinct
//     to a casual observer.
//   - Charset impact: VEIL is valid for alphanumeric, upper-alphanumeric,
//     and base64-ish charsets, so most providers are undisturbed. For hex
//     bodies (Twilio, Postmark, Datadog) VEIL introduces non-hex characters;
//     this is deliberate — the audit explicitly endorses trading slight
//     shape-conformance for guaranteed detectability, and a leaked
//     sentinel-bearing token is easier to catch than a plausible
//     sentinel-free one.
const Sentinel = "VEIL"

// ContainsSentinel reports whether s carries the placeholder sentinel — i.e.
// whether s plausibly originated from a prior Generate call rather than from
// the user. Callers use this to refuse re-vaulting their own placeholders: the
// init pipeline would otherwise treat a sentinel-bearing value as a fresh
// secret and overwrite the user's backup and keystore with it.
func ContainsSentinel(s string) bool {
	return strings.Contains(s, Sentinel)
}

// sentinelize overwrites len(Sentinel) bytes of s starting at offset with
// Sentinel. If s is too short to host the sentinel at that offset, or if
// overwriting would consume every byte of s (leaving zero randomness and
// defeating collision retry), Sentinel is appended instead. Detectability
// is the strong invariant; exact-length preservation is the weak one.
func sentinelize(s string, offset int) string {
	if offset < 0 {
		offset = 0
	}
	if offset+len(Sentinel) > len(s) || (offset == 0 && len(s) == len(Sentinel)) {
		return s + Sentinel
	}
	b := []byte(s)
	copy(b[offset:], Sentinel)
	return string(b)
}

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
	for range maxCollisionRetries {
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
// checks. The URL and provider branches embed Sentinel at a
// branch-appropriate offset; the charclass fallback has no provider prefix,
// so we sentinelize at offset 0.
func generateOnce(name, value string) (string, error) {
	if ph, ok := tryURL(value); ok {
		return ph, nil
	}
	if p := DefaultRegistry().Match(name, value); p != nil {
		return p.Generate(name, value), nil
	}
	return sentinelize(charClassFake(value), 0), nil
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
