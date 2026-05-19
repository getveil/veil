// provider_formats.go registers all declarative Format-based providers.
// Resolution order against hand-written providers is governed by Priority
// (see priority.go and providers.go); previously this file was named
// provider_zzz_formats.go to force it to init() last via filename
// alphabetization, which is no longer load-bearing.

package placeholder

func init() {
	registerFormat(Format{
		Name:       "openai",
		Prefixes:   []string{"sk-proj-"},
		KeyHints:   []string{"OPENAI"},
		Length:     0, // preserve input length
		Charset:    "alphanumeric",
		Hosts:      []string{"api.openai.com"},
		AuthScheme: AuthBearer,
	})

	registerFormat(Format{
		Name:       "anthropic",
		Prefixes:   []string{"sk-ant-api", "sk-ant-"}, // sorted by len desc inside registerFormat
		KeyHints:   []string{"ANTHROPIC"},
		Length:     0,
		Charset:    "alphanumeric",
		Hosts:      []string{"api.anthropic.com"},
		AuthScheme: AuthBearer,
	})

	registerFormat(Format{
		Name:       "stripe",
		Prefixes:   []string{"sk_live_", "sk_test_", "pk_live_", "pk_test_", "rk_live_", "rk_test_"},
		KeyHints:   []string{"STRIPE"},
		Length:     0,
		Charset:    "alphanumeric",
		Hosts:      []string{"api.stripe.com", "files.stripe.com"},
		AuthScheme: AuthBearer,
	})

	registerFormat(Format{
		Name:       "slack",
		Prefixes:   []string{"xoxb-", "xoxp-", "xoxs-", "xoxa-", "xoxr-"},
		KeyHints:   []string{"SLACK"},
		Length:     0,
		Charset:    "alphanumeric",
		Hosts:      []string{"slack.com", "api.slack.com", "files.slack.com"},
		AuthScheme: AuthBearer,
	})

	registerFormat(Format{
		Name:       "google",
		Prefixes:   []string{"AIza"},
		KeyHints:   []string{"GOOGLE_API", "FIREBASE_API"},
		Length:     39,
		Charset:    "alphanumeric",
		Hosts:      []string{"generativelanguage.googleapis.com", "firebaseapp.com", "*.googleapis.com"},
		AuthScheme: AuthBearer,
	})

	registerFormat(Format{
		Name:       "replicate",
		Prefixes:   []string{"r8_"},
		KeyHints:   []string{"REPLICATE"},
		Length:     40,
		Charset:    "alphanumeric",
		Hosts:      []string{"api.replicate.com"},
		AuthScheme: AuthBearer,
	})

	registerFormat(Format{
		Name:       "huggingface",
		Prefixes:   []string{"hf_"},
		KeyHints:   []string{"HUGGING", "HF_"},
		Length:     37,
		Charset:    "alphanumeric",
		Hosts:      []string{"huggingface.co", "api-inference.huggingface.co"},
		AuthScheme: AuthBearer,
	})

	registerFormat(Format{
		Name:       "vercel",
		Prefixes:   []string{"vercel_"},
		KeyHints:   []string{"VERCEL"},
		Length:     0,
		Charset:    "alphanumeric",
		Hosts:      []string{"api.vercel.com"},
		AuthScheme: AuthBearer,
	})

	registerFormat(Format{
		Name:       "gitlab",
		Prefixes:   []string{"glpat-"},
		KeyHints:   []string{"GITLAB"},
		Length:     26,
		Charset:    "alphanumeric",
		Hosts:      []string{"gitlab.com"},
		AuthScheme: AuthBearer,
	})

	registerFormat(Format{
		Name:       "resend",
		Prefixes:   []string{"re_"},
		KeyHints:   []string{"RESEND"},
		Length:     0,
		Charset:    "alphanumeric",
		Hosts:      []string{"api.resend.com"},
		AuthScheme: AuthBearer,
	})
}
