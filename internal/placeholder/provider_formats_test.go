package placeholder

import (
	"strings"
	"testing"
)

func TestFormatProviders(t *testing.T) {
	tests := []struct {
		name       string
		matchKey   string
		matchValue string
		noMatchKey string
		genInput   string
		wantPrefix string
		wantLen    int // 0 = same as input
		charset    string
		wantHosts  []string
	}{
		{
			name:       "openai",
			matchKey:   "OPENAI_API_KEY",
			matchValue: "sk-proj-abcdef0123456789abcdef0123456789",
			noMatchKey: "OTHER_KEY",
			genInput:   "sk-proj-abcdef0123456789abcdef0123456789",
			wantPrefix: "sk-proj-",
			wantLen:    0,
			charset:    "alphanumeric",
			wantHosts:  []string{"api.openai.com"},
		},
		{
			name:       "anthropic",
			matchKey:   "ANTHROPIC_API_KEY",
			matchValue: "sk-ant-api03-" + strings.Repeat("a", 95),
			noMatchKey: "OTHER_KEY",
			genInput:   "sk-ant-api03-" + strings.Repeat("a", 95),
			wantPrefix: "sk-ant-api",
			wantLen:    0,
			charset:    "alphanumeric",
			wantHosts:  []string{"api.anthropic.com"},
		},
		{
			name:       "stripe",
			matchKey:   "STRIPE_SECRET_KEY",
			matchValue: "sk_live_" + strings.Repeat("a", 24),
			noMatchKey: "OTHER_KEY",
			genInput:   "sk_live_" + strings.Repeat("a", 24),
			wantPrefix: "sk_live_",
			wantLen:    0,
			charset:    "alphanumeric",
			wantHosts:  []string{"api.stripe.com", "files.stripe.com"},
		},
		{
			name:       "slack",
			matchKey:   "SLACK_BOT_TOKEN",
			matchValue: "xoxb-" + strings.Repeat("a", 50),
			noMatchKey: "OTHER_KEY",
			genInput:   "xoxb-" + strings.Repeat("a", 50),
			wantPrefix: "xoxb-",
			wantLen:    0,
			charset:    "alphanumeric",
			wantHosts:  []string{"slack.com", "api.slack.com", "files.slack.com"},
		},
		{
			name:       "google",
			matchKey:   "GOOGLE_API_KEY",
			matchValue: "AIzaSyBexamplekey1234567890abcdefghijk",
			noMatchKey: "OTHER_KEY",
			genInput:   "AIzaSyBexamplekey1234567890abcdefghijk",
			wantPrefix: "AIza",
			wantLen:    39,
			charset:    "alphanumeric",
			wantHosts:  []string{"generativelanguage.googleapis.com", "firebaseapp.com", "*.googleapis.com"},
		},
		{
			name:       "replicate",
			matchKey:   "REPLICATE_API_TOKEN",
			matchValue: "r8_abcdefghijklmnopqrstuvwxyz1234567890",
			noMatchKey: "OTHER_KEY",
			genInput:   "r8_abcdefghijklmnopqrstuvwxyz1234567890",
			wantPrefix: "r8_",
			wantLen:    40,
			charset:    "alphanumeric",
			wantHosts:  []string{"api.replicate.com"},
		},
		{
			name:       "huggingface",
			matchKey:   "HF_TOKEN",
			matchValue: "hf_abcdefghijklmnopqrstuvwxyz1234567",
			noMatchKey: "OTHER_KEY",
			genInput:   "hf_abcdefghijklmnopqrstuvwxyz1234567",
			wantPrefix: "hf_",
			wantLen:    37,
			charset:    "alphanumeric",
			wantHosts:  []string{"huggingface.co", "api-inference.huggingface.co"},
		},
		{
			name:       "vercel",
			matchKey:   "VERCEL_TOKEN",
			matchValue: "vercel_abcdefghijklmnopqrst",
			noMatchKey: "OTHER_KEY",
			genInput:   "vercel_abcdefghijklmnopqrst",
			wantPrefix: "vercel_",
			wantLen:    0,
			charset:    "alphanumeric",
			wantHosts:  []string{"api.vercel.com"},
		},
		{
			name:       "gitlab",
			matchKey:   "GITLAB_TOKEN",
			matchValue: "glpat-abcdefghijklmnopqrst",
			noMatchKey: "OTHER_KEY",
			genInput:   "glpat-abcdefghijklmnopqrst",
			wantPrefix: "glpat-",
			wantLen:    26,
			charset:    "alphanumeric",
			wantHosts:  []string{"gitlab.com"},
		},
		{
			name:       "resend",
			matchKey:   "RESEND_API_KEY",
			matchValue: "re_abcdefghijklmnopqrst",
			noMatchKey: "OTHER_KEY",
			genInput:   "re_abcdefghijklmnopqrst",
			wantPrefix: "re_",
			wantLen:    0,
			charset:    "alphanumeric",
			wantHosts:  []string{"api.resend.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prov := mustProvider(t, tt.name)

			t.Run("match_key", func(t *testing.T) {
				if !prov.Match(tt.matchKey, "anything") {
					t.Fatalf("should match key %s", tt.matchKey)
				}
			})

			if tt.wantPrefix != "" {
				t.Run("match_prefix", func(t *testing.T) {
					if !prov.Match("UNKNOWN", tt.matchValue) {
						t.Fatalf("should match value %s", tt.matchValue)
					}
				})
			}

			t.Run("no_match", func(t *testing.T) {
				if prov.Match(tt.noMatchKey, "some-random-value") {
					t.Fatal("should not match unrelated key/value")
				}
			})

			t.Run("generate_prefix", func(t *testing.T) {
				result := prov.Generate("", tt.genInput)
				if tt.wantPrefix != "" && !strings.HasPrefix(result, tt.wantPrefix) {
					t.Fatalf("expected prefix %q, got: %s", tt.wantPrefix, result)
				}
			})

			t.Run("generate_length", func(t *testing.T) {
				result := prov.Generate("", tt.genInput)
				expectedLen := tt.wantLen
				if expectedLen == 0 {
					expectedLen = len(tt.genInput)
				}
				if len(result) != expectedLen {
					t.Fatalf("expected length %d, got %d: %s", expectedLen, len(result), result)
				}
			})

			t.Run("generate_charset", func(t *testing.T) {
				result := prov.Generate("", tt.genInput)
				if !strings.Contains(result, Sentinel) {
					t.Fatalf("expected sentinel %q in %s", Sentinel, result)
				}
				body := result[len(tt.wantPrefix):]
				// Exclude the first occurrence of Sentinel from charset checks;
				// the sentinel intentionally displaces charset-native bytes so
				// every placeholder is detectable via bytes.Contains.
				sIdx := strings.Index(body, Sentinel)
				if sIdx < 0 {
					t.Fatalf("sentinel not found in body %s", body)
				}
				checked := body[:sIdx] + body[sIdx+len(Sentinel):]
				for _, c := range checked {
					valid := false
					switch tt.charset {
					case "hex":
						valid = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
					case "alphanumeric":
						valid = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
					}
					if !valid {
						t.Fatalf("invalid char %c for charset %s in %s", c, tt.charset, result)
					}
				}
			})

			t.Run("hosts", func(t *testing.T) {
				if len(prov.Hosts) != len(tt.wantHosts) {
					t.Fatalf("expected %d hosts, got %d: %v", len(tt.wantHosts), len(prov.Hosts), prov.Hosts)
				}
				for i, h := range tt.wantHosts {
					if prov.Hosts[i] != h {
						t.Fatalf("expected host %q at index %d, got %q", h, i, prov.Hosts[i])
					}
				}
			})
		})
	}
}

func TestProviderFormats_AuthSchemes(t *testing.T) {
	want := map[string]AuthScheme{
		"openai":      AuthBearer,
		"anthropic":   AuthBearer,
		"stripe":      AuthBearer,
		"slack":       AuthBearer,
		"google":      AuthBearer,
		"replicate":   AuthBearer,
		"huggingface": AuthBearer,
		"vercel":      AuthBearer,
		"gitlab":      AuthBearer,
		"resend":      AuthBearer,
	}
	r := DefaultRegistry()
	for name, expected := range want {
		p, ok := r.Get(name)
		if !ok {
			t.Errorf("provider %q not registered", name)
			continue
		}
		if p.AuthScheme != expected {
			t.Errorf("%s AuthScheme = %v, want %v", name, p.AuthScheme, expected)
		}
		if !VaultEligible(&p) {
			t.Errorf("%s must be VaultEligible (Bearer with hosts)", name)
		}
	}
}
