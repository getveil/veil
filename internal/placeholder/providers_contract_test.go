package placeholder_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/getveil/veil/internal/placeholder"
)

// sample is a representative input for a provider's Match/Generate.
type sample struct {
	keyName string
	value   string
}

// providerSamples supplies a match-triggering input for each known provider.
// Every entry here must correspond to a registered provider; every registered
// provider must have an entry here. Run TestAllRegisteredProvidersHaveSamples_Dynamic
// to verify completeness — it drives the check off Registry.Names() instead of a
// hardcoded list.
var providerSamples = map[string]sample{
	// Hand-written providers.
	"openai":    {"OPENAI_API_KEY", "sk-proj-" + strings.Repeat("a", 40)},
	"anthropic": {"ANTHROPIC_API_KEY", "sk-ant-api03-" + strings.Repeat("a", 95)},
	"github":    {"GITHUB_TOKEN", "ghp_" + strings.Repeat("a", 36)},
	"stripe":    {"STRIPE_KEY", "sk_live_" + strings.Repeat("a", 24)},
	"aws":       {"AWS_ACCESS_KEY_ID", "AKIA" + strings.Repeat("A", 16)},
	"slack":     {"SLACK_TOKEN", "xoxb-" + strings.Repeat("a", 50)},
	"twilio":    {"TWILIO_AUTH_TOKEN", "SK" + strings.Repeat("a", 32)},
	"supabase":  {"SUPABASE_KEY", "sbp_" + strings.Repeat("a", 36)},
	"sendgrid":  {"SENDGRID_API_KEY", "SG." + strings.Repeat("a", 22) + "." + strings.Repeat("b", 43)},
	// Format providers (declarative — registered in provider_formats.go).
	"google":      {"GOOGLE_API_KEY", "AIza" + strings.Repeat("a", 35)},
	"replicate":   {"REPLICATE_API_TOKEN", "r8_" + strings.Repeat("a", 37)},
	"huggingface": {"HF_TOKEN", "hf_" + strings.Repeat("a", 34)},
	"vercel":      {"VERCEL_TOKEN", "vercel_" + strings.Repeat("a", 20)},
	"gitlab":      {"GITLAB_TOKEN", "glpat-" + strings.Repeat("a", 20)},
	"npm":         {"NPM_TOKEN", "npm_" + strings.Repeat("a", 32)},
	"resend":      {"RESEND_API_KEY", "re_" + strings.Repeat("a", 20)},
	"postmark":    {"POSTMARK_SERVER_TOKEN", strings.Repeat("a", 36)},
	"datadog":     {"DD_API_KEY", strings.Repeat("a", 32)},
	"pypi":        {"TWINE_PASSWORD", "pypi-" + strings.Repeat("a", 40)},
	"docker_hub":  {"DOCKER_HUB_TOKEN", "dckr_pat_" + strings.Repeat("a", 36)},
	"quay":        {"QUAY_TOKEN", strings.Repeat("a", 32)},
	"gcr":         {"GCR_JSON_KEY", strings.Repeat("a", 32)},
}

// providerRegexes validates the structural shape of Generate output. Add
// entries as providers stabilize their output format.
var providerRegexes = map[string]*regexp.Regexp{
	"openai": regexp.MustCompile(`^sk-proj-[A-Za-z0-9]+$`),
	"stripe": regexp.MustCompile(`^sk_live_[A-Za-z0-9]{24}$`),
}

func TestProviderContract(t *testing.T) {
	reg := placeholder.DefaultRegistry()
	for name, s := range providerSamples {
		t.Run(name, func(t *testing.T) {
			p, ok := reg.Get(name)
			if !ok {
				t.Skipf("provider %q not registered", name)
			}
			if !p.Match(s.keyName, s.value) {
				t.Fatalf("provider %q did not match its own sample (name=%q value=%q)",
					name, s.keyName, s.value)
			}
			out := p.Generate(s.keyName, s.value)
			if out == "" {
				t.Fatalf("empty Generate output for %q", name)
			}
			if out == s.value {
				t.Fatalf("Generate returned the input unchanged for %q", name)
			}
			if re := providerRegexes[name]; re != nil && !re.MatchString(out) {
				t.Fatalf("output %q for %q does not match regex %v", out, name, re)
			}
		})
	}
}

// TestAllRegisteredProvidersHaveSamples_Dynamic drives the contract off
// Registry.Names() instead of a hardcoded list. Adding a new provider via
// register()/registerFormat() without also adding a providerSamples entry
// now fails this test loudly instead of being silently ignored.
func TestAllRegisteredProvidersHaveSamples_Dynamic(t *testing.T) {
	reg := placeholder.DefaultRegistry()
	names := reg.Names()
	if len(names) == 0 {
		t.Fatal("Registry.Names() returned empty — expected at least one provider")
	}
	for _, name := range names {
		if _, ok := providerSamples[name]; !ok {
			t.Errorf("provider %q is registered but has no entry in providerSamples (add one at the top of providers_contract_test.go)", name)
		}
	}

	// Reverse direction: every providerSamples entry must correspond to a
	// registered provider. Without this check, removing a provider from the
	// registry while leaving its sample entry behind would silently pass
	// (TestProviderContract skips orphans via t.Skipf).
	registered := make(map[string]struct{}, len(names))
	for _, name := range names {
		registered[name] = struct{}{}
	}
	for name := range providerSamples {
		if _, ok := registered[name]; !ok {
			t.Errorf("providerSamples has entry %q but no such provider is registered (remove stale entry)", name)
		}
	}
}
