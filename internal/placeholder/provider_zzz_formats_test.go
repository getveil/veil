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
			name:       "npm",
			matchKey:   "NPM_TOKEN",
			matchValue: "npm_abcdefghijklmnopqrstuvwxyz123456",
			noMatchKey: "OTHER_KEY",
			genInput:   "npm_abcdefghijklmnopqrstuvwxyz123456",
			wantPrefix: "npm_",
			wantLen:    36,
			charset:    "alphanumeric",
			wantHosts:  []string{"registry.npmjs.org"},
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
		{
			name:       "postmark",
			matchKey:   "POSTMARK_SERVER_TOKEN",
			matchValue: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
			noMatchKey: "OTHER_KEY",
			genInput:   "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
			wantPrefix: "",
			wantLen:    36,
			charset:    "hex",
			wantHosts:  []string{"api.postmarkapp.com"},
		},
		{
			name:       "datadog",
			matchKey:   "DD_API_KEY",
			matchValue: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
			noMatchKey: "OTHER_KEY",
			genInput:   "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
			wantPrefix: "",
			wantLen:    32,
			charset:    "hex",
			wantHosts:  []string{"api.datadoghq.com", "*.datadoghq.com"},
		},
		{
			name:       "pypi",
			matchKey:   "TWINE_PASSWORD",
			matchValue: "pypi-AgEIcHlwaS5vcmcabcdefghijklmnopqrstuvwxyz",
			noMatchKey: "OTHER_KEY",
			genInput:   "pypi-AgEIcHlwaS5vcmcabcdefghijklmnopqrstuvwxyz",
			wantPrefix: "pypi-",
			wantLen:    0,
			charset:    "alphanumeric",
			wantHosts:  []string{"pypi.org", "upload.pypi.org", "test.pypi.org", "upload.test.pypi.org"},
		},
		{
			name:       "docker_hub",
			matchKey:   "DOCKER_HUB_TOKEN",
			matchValue: "dckr_pat_abcdefghijklmnopqrstuvwxyz12",
			noMatchKey: "OTHER_KEY",
			genInput:   "dckr_pat_abcdefghijklmnopqrstuvwxyz12",
			wantPrefix: "dckr_pat_",
			wantLen:    0,
			charset:    "alphanumeric",
			wantHosts:  []string{"docker.io", "registry-1.docker.io", "index.docker.io", "auth.docker.io"},
		},
		{
			name:       "quay",
			matchKey:   "QUAY_TOKEN",
			matchValue: "somequaytokenvalue1234567890abcdef",
			noMatchKey: "OTHER_KEY",
			genInput:   "somequaytokenvalue1234567890abcdef",
			wantPrefix: "",
			wantLen:    0,
			charset:    "alphanumeric",
			wantHosts:  []string{"quay.io"},
		},
		{
			name:       "gcr",
			matchKey:   "GCR_JSON_KEY",
			matchValue: "some-gcr-credential-value",
			noMatchKey: "OTHER_KEY",
			genInput:   "some-gcr-credential-value",
			wantPrefix: "",
			wantLen:    0,
			charset:    "alphanumeric",
			wantHosts:  []string{"gcr.io", "*.gcr.io", "*-docker.pkg.dev"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var prov ProviderPattern
			for _, p := range registry {
				if p.Name == tt.name {
					prov = p
					break
				}
			}
			if prov.Name == "" {
				t.Fatalf("%s provider not registered", tt.name)
			}

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
				result := prov.Generate(tt.genInput)
				if tt.wantPrefix != "" && !strings.HasPrefix(result, tt.wantPrefix) {
					t.Fatalf("expected prefix %q, got: %s", tt.wantPrefix, result)
				}
			})

			t.Run("generate_length", func(t *testing.T) {
				result := prov.Generate(tt.genInput)
				expectedLen := tt.wantLen
				if expectedLen == 0 {
					expectedLen = len(tt.genInput)
				}
				if len(result) != expectedLen {
					t.Fatalf("expected length %d, got %d: %s", expectedLen, len(result), result)
				}
			})

			t.Run("generate_charset", func(t *testing.T) {
				result := prov.Generate(tt.genInput)
				body := result[len(tt.wantPrefix):]
				for _, c := range body {
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
