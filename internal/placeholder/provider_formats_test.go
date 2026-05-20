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
		// matchKeyValue is the value paired with matchKey for the
		// "name-hint matches" subtest. Empty string means the legacy
		// behaviour ("anything") — set to a shape-passing value for
		// providers that require the value to also clear a credential
		// shape gate (Stripe, Resend), which intentionally refuse to
		// vault on the name hint alone.
		matchKeyValue string
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
			name:          "stripe",
			matchKey:      "STRIPE_SECRET_KEY",
			matchKeyValue: "sk_live_" + strings.Repeat("a", 24),
			matchValue:    "sk_live_" + strings.Repeat("a", 24),
			noMatchKey:    "OTHER_KEY",
			genInput:      "sk_live_" + strings.Repeat("a", 24),
			wantPrefix:    "sk_live_",
			wantLen:       0,
			charset:       "alphanumeric",
			wantHosts:     []string{"api.stripe.com", "files.stripe.com"},
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
			name:          "resend",
			matchKey:      "RESEND_API_KEY",
			matchKeyValue: "re_abcdefghijklmnopqrst",
			matchValue:    "re_abcdefghijklmnopqrst",
			noMatchKey:    "OTHER_KEY",
			genInput:      "re_abcdefghijklmnopqrst",
			wantPrefix:    "re_",
			wantLen:       0,
			charset:       "alphanumeric",
			wantHosts:     []string{"api.resend.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prov := mustProvider(t, tt.name)

			t.Run("match_key", func(t *testing.T) {
				// Stripe / Resend require the value to also carry a real
				// secret-key prefix; providers without that gate match on
				// the name hint alone (legacy "anything" value).
				valueForKey := tt.matchKeyValue
				if valueForKey == "" {
					valueForKey = "anything"
				}
				if !prov.Match(tt.matchKey, valueForKey) {
					t.Fatalf("should match key %s with value %q", tt.matchKey, valueForKey)
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

func TestProviderFormats_AreVaultEligible(t *testing.T) {
	names := []string{
		"openai", "anthropic", "stripe", "slack", "google",
		"replicate", "huggingface", "vercel", "gitlab", "resend",
	}
	r := DefaultRegistry()
	for _, name := range names {
		p, ok := r.Get(name)
		if !ok {
			t.Errorf("provider %q not registered", name)
			continue
		}
		if !p.VaultEligible {
			t.Errorf("%s must declare VaultEligible: true", name)
		}
		if len(p.Hosts) == 0 {
			t.Errorf("%s must declare a non-empty Hosts set", name)
		}
	}
}

// TestStripe_PublishableKeyNotVaulted is a regression test for the Stripe
// false positive: STRIPE_PUBLISHABLE_KEY=pk_live_<...> matched the legacy
// declarative provider via the STRIPE name hint and got auto-vaulted, even
// though Stripe publishable keys (pk_*) are intentionally public. The new
// hand-written matcher requires the value to start with one of the secret
// prefixes (sk_/rk_) before the STRIPE name hint can fire.
func TestStripe_PublishableKeyNotVaulted(t *testing.T) {
	prov := mustProvider(t, "stripe")

	value := "pk_live_" + strings.Repeat("a", 24)

	if prov.Match("STRIPE_PUBLISHABLE_KEY", value) {
		t.Fatalf("Stripe provider should NOT match publishable key under STRIPE_PUBLISHABLE_KEY=%q", value)
	}
	// Even with the secret-shaped name, a pk_ value must not vault.
	if prov.Match("STRIPE_SECRET_KEY", value) {
		t.Fatalf("Stripe provider should NOT match pk_ value even under STRIPE_SECRET_KEY")
	}
}

// TestResend_ShortPrefixedValueNotVaulted is a regression test for the Resend
// false positive: REDIRECT_URI=re_login_callback_url matched the legacy "re_"
// prefix and got auto-vaulted. The new hand-written matcher requires
// len(value) >= 20 so short re_-prefixed strings (paths, config tokens,
// callback identifiers) cannot match.
func TestResend_ShortPrefixedValueNotVaulted(t *testing.T) {
	prov := mustProvider(t, "resend")

	// Under 20 chars — must not match even though prefix is present.
	short := "re_login_callback"
	if len(short) >= 20 {
		t.Fatalf("test setup: value %q must be < 20 chars to exercise the floor", short)
	}
	if prov.Match("REDIRECT_URI", short) {
		t.Fatalf("Resend provider should NOT match short re_ value REDIRECT_URI=%q", short)
	}
	// Same value under a RESEND-named key must also not match — the name
	// hint never short-circuits the shape gate.
	if prov.Match("RESEND_REDIRECT", short) {
		t.Fatalf("Resend provider should NOT match short re_ value RESEND_REDIRECT=%q", short)
	}
	// Sanity: a realistic-length re_ value still matches.
	long := "re_" + strings.Repeat("a", 36)
	if !prov.Match("REDIRECT_URI", long) {
		t.Fatalf("Resend provider should match real-length value %q", long)
	}
}

// TestResend_NameHintRequiresShape is a tighter sibling to
// TestResend_ShortPrefixedValueNotVaulted: even when the key name contains
// RESEND, a value that doesn't carry the re_ prefix at all must not match.
func TestResend_NameHintRequiresShape(t *testing.T) {
	prov := mustProvider(t, "resend")

	// No re_ prefix at all — name hint alone must not fire.
	if prov.Match("RESEND_FROM_EMAIL", "team@example.com") {
		t.Fatal("Resend provider should NOT match on name hint alone (value lacks re_ prefix)")
	}
}

// TestSupabase_SBPPrefixDetected_UnderGenericName locks in the sbp_ prefix
// path: a Supabase personal access token (sbp_<36 alnum>) stored under an
// arbitrary key name (e.g. MY_DB_TOKEN) must be classified as a Supabase
// credential. Without the prefix path, only SUPABASE_*-named values or
// real Supabase JWTs would be recognised.
func TestSupabase_SBPPrefixDetected_UnderGenericName(t *testing.T) {
	prov := mustProvider(t, "supabase")

	value := "sbp_" + strings.Repeat("a", 36)
	if !prov.Match("MY_DB_TOKEN", value) {
		t.Fatalf("Supabase provider should match sbp_ value under generic key name MY_DB_TOKEN=%q", value)
	}
	// Verify host wiring is intact.
	hasSupabaseHost := false
	for _, h := range prov.Hosts {
		if strings.Contains(h, "supabase") {
			hasSupabaseHost = true
		}
	}
	if !hasSupabaseHost {
		t.Fatalf("supabase provider Hosts missing supabase entry: %v", prov.Hosts)
	}
	// Generate must produce a non-empty placeholder that carries the
	// sentinel and the sbp_ prefix (so the placeholder is re-detectable
	// by Match on a subsequent veil init pass).
	gen := prov.Generate("MY_DB_TOKEN", value)
	if gen == "" {
		t.Fatal("Supabase Generate returned empty placeholder for sbp_ value")
	}
	if !strings.HasPrefix(gen, "sbp_") {
		t.Fatalf("Supabase Generate for sbp_ input must preserve sbp_ prefix; got %q", gen)
	}
	if !strings.Contains(gen, Sentinel) {
		t.Fatalf("Supabase Generate for sbp_ input must contain sentinel %q; got %q", Sentinel, gen)
	}
	// Round-trip: the generated placeholder must itself match Match so a
	// re-run of veil init doesn't re-vault the placeholder as a fresh
	// secret.
	if !prov.Match("ANOTHER_NAME", gen) {
		t.Fatalf("generated sbp_ placeholder %q does not round-trip through Match", gen)
	}
}
