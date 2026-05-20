// provider_formats.go registers the declarative providers — the common
// "prefix + random body" shape. Hand-written providers (Supabase, GitHub,
// SendGrid) live in their own provider_*.go files and supply explicit
// Match/Generate funcs.

package placeholder

import "strings"

func init() {
	register(ProviderPattern{
		Name:          "openai",
		Prefixes:      []string{"sk-proj-"},
		KeyHints:      []string{"OPENAI"},
		Length:        0, // preserve input length
		Charset:       "alphanumeric",
		Hosts:         []string{"api.openai.com"},
		VaultEligible: true,
	})

	register(ProviderPattern{
		Name:          "anthropic",
		Prefixes:      []string{"sk-ant-api", "sk-ant-"}, // sorted by len desc inside register
		KeyHints:      []string{"ANTHROPIC"},
		Length:        0,
		Charset:       "alphanumeric",
		Hosts:         []string{"api.anthropic.com"},
		VaultEligible: true,
	})

	// Stripe is hand-written rather than declarative because the declarative
	// OR-of-(prefix, name-hint) classifier vaults STRIPE_PUBLISHABLE_KEY=pk_live_*
	// — intentionally public keys — on the name-hint alone. The Match below
	// requires the value to start with a secret-key prefix; the STRIPE name
	// hint only narrows which prefix is accepted, it never short-circuits the
	// prefix check.
	stripePrefixes := []string{"sk_live_", "sk_test_", "rk_live_", "rk_test_"}
	register(ProviderPattern{
		Name:          "stripe",
		Prefixes:      stripePrefixes,
		Length:        0,
		Charset:       "alphanumeric",
		Hosts:         []string{"api.stripe.com", "files.stripe.com"},
		VaultEligible: true,
		Match: func(name, value string) bool {
			hasPrefix := false
			for _, p := range stripePrefixes {
				if strings.HasPrefix(value, p) {
					hasPrefix = true
					break
				}
			}
			if hasPrefix {
				return true
			}
			// Name-hint path: only count as a Stripe credential when the value
			// also carries a secret-key prefix. Publishable keys (pk_*) under
			// STRIPE_PUBLISHABLE_KEY must NOT vault.
			if strings.Contains(strings.ToUpper(name), "STRIPE") {
				for _, p := range stripePrefixes {
					if strings.HasPrefix(value, p) {
						return true
					}
				}
			}
			return false
		},
	})

	register(ProviderPattern{
		Name:          "slack",
		Prefixes:      []string{"xoxb-", "xoxp-", "xoxs-", "xoxa-", "xoxr-"},
		KeyHints:      []string{"SLACK"},
		Length:        0,
		Charset:       "alphanumeric",
		Hosts:         []string{"slack.com", "api.slack.com", "files.slack.com"},
		VaultEligible: true,
	})

	register(ProviderPattern{
		Name:          "google",
		Prefixes:      []string{"AIza"},
		KeyHints:      []string{"GOOGLE_API", "FIREBASE_API"},
		Length:        39,
		Charset:       "alphanumeric",
		Hosts:         []string{"generativelanguage.googleapis.com", "firebaseapp.com", "*.googleapis.com"},
		VaultEligible: true,
	})

	register(ProviderPattern{
		Name:          "replicate",
		Prefixes:      []string{"r8_"},
		KeyHints:      []string{"REPLICATE"},
		Length:        40,
		Charset:       "alphanumeric",
		Hosts:         []string{"api.replicate.com"},
		VaultEligible: true,
	})

	register(ProviderPattern{
		Name:          "huggingface",
		Prefixes:      []string{"hf_"},
		KeyHints:      []string{"HUGGING", "HF_"},
		Length:        37,
		Charset:       "alphanumeric",
		Hosts:         []string{"huggingface.co", "api-inference.huggingface.co"},
		VaultEligible: true,
	})

	register(ProviderPattern{
		Name:          "vercel",
		Prefixes:      []string{"vercel_"},
		KeyHints:      []string{"VERCEL"},
		Length:        0,
		Charset:       "alphanumeric",
		Hosts:         []string{"api.vercel.com"},
		VaultEligible: true,
	})

	register(ProviderPattern{
		Name:          "gitlab",
		Prefixes:      []string{"glpat-"},
		KeyHints:      []string{"GITLAB"},
		Length:        26,
		Charset:       "alphanumeric",
		Hosts:         []string{"gitlab.com"},
		VaultEligible: true,
	})

	// Resend is hand-written rather than declarative because the
	// declarative OR-of-(prefix, name-hint) classifier would match any
	// shape-passing value under a RESEND_* name — e.g.
	// RESEND_FROM_EMAIL=team@example.somewhere.com (28 chars, clears the
	// Registry.Match shape gate) would be vaulted as a Resend credential.
	// The hand-written matcher constrains the name-hint path so it only
	// fires when the value also carries the re_ prefix. The Registry-
	// level shape gate handles the length floor; this matcher does not
	// repeat it.
	register(ProviderPattern{
		Name:          "resend",
		Prefixes:      []string{"re_"},
		Length:        0,
		Charset:       "alphanumeric",
		Hosts:         []string{"api.resend.com"},
		VaultEligible: true,
		Match: func(name, value string) bool {
			if strings.HasPrefix(value, "re_") {
				return true
			}
			// Name-hint path: requires the value to also carry the
			// re_ prefix — mirroring the gate applied to Stripe's name
			// hint, which only fires for secret-key-prefixed values.
			if strings.Contains(strings.ToUpper(name), "RESEND") &&
				strings.HasPrefix(value, "re_") {
				return true
			}
			return false
		},
	})
}
