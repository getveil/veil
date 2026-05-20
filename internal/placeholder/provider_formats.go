// provider_formats.go registers the declarative providers — the common
// "prefix + random body" shape. Hand-written providers (Supabase, GitHub,
// SendGrid) live in their own provider_*.go files and supply explicit
// Match/Generate funcs.

package placeholder

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

	register(ProviderPattern{
		Name:          "stripe",
		Prefixes:      []string{"sk_live_", "sk_test_", "pk_live_", "pk_test_", "rk_live_", "rk_test_"},
		KeyHints:      []string{"STRIPE"},
		Length:        0,
		Charset:       "alphanumeric",
		Hosts:         []string{"api.stripe.com", "files.stripe.com"},
		VaultEligible: true,
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

	register(ProviderPattern{
		Name:          "resend",
		Prefixes:      []string{"re_"},
		KeyHints:      []string{"RESEND"},
		Length:        0,
		Charset:       "alphanumeric",
		Hosts:         []string{"api.resend.com"},
		VaultEligible: true,
	})
}
