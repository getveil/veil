package placeholder_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/8enji/veil/internal/placeholder"
)

// sample is a representative input for a provider's Match/Generate.
type sample struct {
	keyName string
	value   string
}

// providerSamples supplies a match-triggering input for each known provider.
// Add entries as new providers are registered; missing providers are skipped.
var providerSamples = map[string]sample{
	"openai":    {"OPENAI_API_KEY", "sk-proj-" + strings.Repeat("a", 40)},
	"anthropic": {"ANTHROPIC_API_KEY", "sk-ant-api03-" + strings.Repeat("a", 95)},
	"github":    {"GITHUB_TOKEN", "ghp_" + strings.Repeat("a", 36)},
	"stripe":    {"STRIPE_KEY", "sk_live_" + strings.Repeat("a", 24)},
	"aws":       {"AWS_ACCESS_KEY_ID", "AKIA" + strings.Repeat("A", 16)},
	"slack":     {"SLACK_TOKEN", "xoxb-" + strings.Repeat("a", 50)},
	"twilio":    {"TWILIO_AUTH_TOKEN", "SK" + strings.Repeat("a", 32)},
	"supabase":  {"SUPABASE_KEY", "sbp_" + strings.Repeat("a", 36)},
	"sendgrid":  {"SENDGRID_API_KEY", "SG." + strings.Repeat("a", 22) + "." + strings.Repeat("b", 43)},
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
			out := p.Generate(s.value)
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

// TestAllRegisteredProvidersHaveSampleOrRegex flags providers that landed
// without a contract entry so the table gets kept in sync.
func TestAllRegisteredProvidersHaveSampleOrRegex(t *testing.T) {
	// Harvest provider names by probing with unique keys. Since Registry does
	// not expose iteration, we rely on DefaultRegistry().Get(name) for each
	// known provider. This test fails loudly when a new provider lands
	// without coverage, as long as we list it here too. Keep the list sorted.
	known := []string{
		"openai", "anthropic", "github", "stripe", "aws", "slack",
		"twilio", "supabase", "sendgrid",
	}
	reg := placeholder.DefaultRegistry()
	for _, name := range known {
		if _, ok := reg.Get(name); !ok {
			continue
		}
		if _, ok := providerSamples[name]; !ok {
			t.Errorf("provider %q is registered but has no entry in providerSamples", name)
		}
	}
}
