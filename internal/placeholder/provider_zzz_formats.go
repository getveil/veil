package placeholder

func init() {
	registerFormat(Format{
		Name:     "google",
		Prefixes: []string{"AIza"},
		KeyHints: []string{"GOOGLE_API", "FIREBASE_API"},
		Length:   39,
		Charset:  "alphanumeric",
		Hosts:    []string{"generativelanguage.googleapis.com", "firebaseapp.com", "*.googleapis.com"},
	})

	registerFormat(Format{
		Name:     "replicate",
		Prefixes: []string{"r8_"},
		KeyHints: []string{"REPLICATE"},
		Length:   40,
		Charset:  "alphanumeric",
		Hosts:    []string{"api.replicate.com"},
	})

	registerFormat(Format{
		Name:     "huggingface",
		Prefixes: []string{"hf_"},
		KeyHints: []string{"HUGGING", "HF_"},
		Length:   37,
		Charset:  "alphanumeric",
		Hosts:    []string{"huggingface.co", "api-inference.huggingface.co"},
	})

	registerFormat(Format{
		Name:     "vercel",
		Prefixes: []string{"vercel_"},
		KeyHints: []string{"VERCEL"},
		Length:   0,
		Charset:  "alphanumeric",
		Hosts:    []string{"api.vercel.com"},
	})

	registerFormat(Format{
		Name:     "gitlab",
		Prefixes: []string{"glpat-"},
		KeyHints: []string{"GITLAB"},
		Length:   26,
		Charset:  "alphanumeric",
		Hosts:    []string{"gitlab.com"},
	})

	registerFormat(Format{
		Name:     "npm",
		Prefixes: []string{"npm_"},
		KeyHints: []string{"NPM_TOKEN"},
		Length:   36,
		Charset:  "alphanumeric",
		Hosts:    []string{"registry.npmjs.org"},
	})

	registerFormat(Format{
		Name:     "resend",
		Prefixes: []string{"re_"},
		KeyHints: []string{"RESEND"},
		Length:   0,
		Charset:  "alphanumeric",
		Hosts:    []string{"api.resend.com"},
	})

	registerFormat(Format{
		Name:     "postmark",
		Prefixes: nil,
		KeyHints: []string{"POSTMARK"},
		Length:   36,
		Charset:  "hex",
		Hosts:    []string{"api.postmarkapp.com"},
	})

	registerFormat(Format{
		Name:     "datadog",
		Prefixes: nil,
		KeyHints: []string{"DATADOG", "DD_API"},
		Length:   32,
		Charset:  "hex",
		Hosts:    []string{"api.datadoghq.com", "*.datadoghq.com"},
	})
}
