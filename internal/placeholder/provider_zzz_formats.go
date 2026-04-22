package placeholder

func init() {
	registerFormat(Format{
		Name:     "openai",
		Prefixes: []string{"sk-proj-"},
		KeyHints: []string{"OPENAI"},
		Length:   0, // preserve input length
		Charset:  "alphanumeric",
		Hosts:    []string{"api.openai.com"},
	})

	registerFormat(Format{
		Name:     "anthropic",
		Prefixes: []string{"sk-ant-api", "sk-ant-"}, // sorted by len desc inside registerFormat
		KeyHints: []string{"ANTHROPIC"},
		Length:   0,
		Charset:  "alphanumeric",
		Hosts:    []string{"api.anthropic.com"},
	})

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

	registerFormat(Format{
		Name:     "pypi",
		Prefixes: []string{"pypi-"},
		KeyHints: []string{"PYPI", "TWINE_PASSWORD"},
		Length:   0,
		Charset:  "alphanumeric",
		Hosts:    []string{"pypi.org", "upload.pypi.org", "test.pypi.org", "upload.test.pypi.org"},
	})

	// Container registries. Token formats vary widely, so most are matched by
	// key-hint only; users who scope credentials via `veil add --host` get
	// correct injection via the AllowedHosts check regardless of format.

	registerFormat(Format{
		Name:     "docker_hub",
		Prefixes: []string{"dckr_pat_"},
		KeyHints: []string{"DOCKER_HUB", "DOCKERHUB", "DOCKER_TOKEN", "DOCKER_PAT"},
		Length:   0,
		Charset:  "alphanumeric",
		Hosts:    []string{"docker.io", "registry-1.docker.io", "index.docker.io", "auth.docker.io"},
	})

	registerFormat(Format{
		Name:     "quay",
		Prefixes: nil,
		KeyHints: []string{"QUAY"},
		Length:   0,
		Charset:  "alphanumeric",
		Hosts:    []string{"quay.io"},
	})

	registerFormat(Format{
		Name:     "gcr",
		Prefixes: nil,
		KeyHints: []string{"GCR_", "GOOGLE_REGISTRY", "ARTIFACT_REGISTRY"},
		Length:   0,
		Charset:  "alphanumeric",
		Hosts:    []string{"gcr.io", "*.gcr.io", "*-docker.pkg.dev"},
	})
}
