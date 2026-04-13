# Format-Aware Placeholder Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand format-aware placeholder generation from 6 to 20 providers so that placeholders pass SDK validation and are indistinguishable from real keys to AI agents.

**Architecture:** Add a `Format` struct and `registerFormat()` function to the existing `placeholder` package. Simple prefix+length+charset providers are registered declaratively via `Format`. Complex providers (SendGrid, Twilio, Supabase JWT) get hand-authored files. The existing `ProviderPattern` registry, `Generate()` entrypoint, and `charClassFake` fallback are unchanged.

**Tech Stack:** Go, `crypto/rand`, `encoding/base64` (for JWT generation), existing test infrastructure (`go test`).

**Spec:** `docs/superpowers/specs/2026-04-12-format-aware-placeholders-design.md`

---

### Task 1: Add `Format` struct and `registerFormat` to `providers.go`

**Files:**
- Modify: `internal/placeholder/providers.go`
- Test: `internal/placeholder/providers_test.go`

- [ ] **Step 1: Write test for `registerFormat`**

Add to `internal/placeholder/providers_test.go`:

```go
func TestRegisterFormat_BasicMatch(t *testing.T) {
	// Snapshot registry length before adding.
	before := len(registry)

	registerFormat(Format{
		Name:     "testprovider",
		Prefixes: []string{"tp_"},
		KeyHints: []string{"TESTPROV"},
		Length:   20,
		Charset:  "alphanumeric",
		Hosts:    []string{"api.testprovider.com"},
	})

	// Clean up: restore registry after test.
	defer func() { registry = registry[:before] }()

	// Find the registered provider.
	var prov ProviderPattern
	for _, p := range registry[before:] {
		if p.Name == "testprovider" {
			prov = p
			break
		}
	}
	if prov.Name == "" {
		t.Fatal("testprovider not registered")
	}

	// Match by prefix.
	if !prov.Match("ANY_KEY", "tp_abc123") {
		t.Fatal("should match tp_ prefix")
	}
	// Match by key hint.
	if !prov.Match("TESTPROV_KEY", "anything") {
		t.Fatal("should match TESTPROV in key name")
	}
	// No match.
	if prov.Match("OTHER", "other") {
		t.Fatal("should not match unrelated")
	}

	// Generate: correct prefix, length, alphanumeric charset.
	result := prov.Generate("tp_originalvalue1234")
	if len(result) != 20 {
		t.Fatalf("expected length 20, got %d: %s", len(result), result)
	}
	if result[:3] != "tp_" {
		t.Fatalf("expected tp_ prefix, got: %s", result)
	}
	for _, c := range result[3:] {
		isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlnum {
			t.Fatalf("expected alphanumeric char, got: %c", c)
		}
	}

	// Hosts.
	if len(prov.Hosts) != 1 || prov.Hosts[0] != "api.testprovider.com" {
		t.Fatalf("unexpected hosts: %v", prov.Hosts)
	}
}

func TestRegisterFormat_HexCharset(t *testing.T) {
	before := len(registry)
	registerFormat(Format{
		Name:     "testhex",
		Prefixes: nil,
		KeyHints: []string{"TESTHEX"},
		Length:   32,
		Charset:  "hex",
		Hosts:    []string{"api.testhex.com"},
	})
	defer func() { registry = registry[:before] }()

	var prov ProviderPattern
	for _, p := range registry[before:] {
		if p.Name == "testhex" {
			prov = p
			break
		}
	}

	result := prov.Generate("anything-at-all-here-for-32chars")
	if len(result) != 32 {
		t.Fatalf("expected length 32, got %d", len(result))
	}
	for _, c := range result {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isHex {
			t.Fatalf("expected hex char, got: %c in %s", c, result)
		}
	}
}

func TestRegisterFormat_ZeroLengthPreservesInput(t *testing.T) {
	before := len(registry)
	registerFormat(Format{
		Name:     "testflex",
		Prefixes: []string{"flex_"},
		KeyHints: nil,
		Length:   0,
		Charset:  "alphanumeric",
		Hosts:    nil,
	})
	defer func() { registry = registry[:before] }()

	var prov ProviderPattern
	for _, p := range registry[before:] {
		if p.Name == "testflex" {
			prov = p
			break
		}
	}

	input := "flex_shortvalue"
	result := prov.Generate(input)
	if len(result) != len(input) {
		t.Fatalf("expected length %d (same as input), got %d", len(input), len(result))
	}
	if result[:5] != "flex_" {
		t.Fatalf("expected flex_ prefix, got: %s", result)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/placeholder/ -run 'TestRegisterFormat' -v`
Expected: compilation error — `Format` and `registerFormat` are undefined.

- [ ] **Step 3: Implement `Format` struct and `registerFormat`**

Add to `internal/placeholder/providers.go`:

```go
// Format describes a secret format that can be matched and replaced using
// declarative fields instead of hand-authored Match/Generate functions.
type Format struct {
	Name     string
	Prefixes []string // value prefixes to match, e.g. ["ghp_", "github_pat_"]
	KeyHints []string // substrings to match in env key name (case-insensitive)
	Length   int      // total output length including prefix (0 = match input length)
	Charset  string   // "alphanumeric", "hex", "base64", "upper-alphanumeric"
	Hosts    []string
}

// registerFormat constructs a ProviderPattern from a Format and appends it
// to the registry.
func registerFormat(f Format) {
	p := ProviderPattern{
		Name:  f.Name,
		Hosts: f.Hosts,
		Match: func(name, value string) bool {
			for _, pfx := range f.Prefixes {
				if strings.HasPrefix(value, pfx) {
					return true
				}
			}
			upper := strings.ToUpper(name)
			for _, hint := range f.KeyHints {
				if strings.Contains(upper, strings.ToUpper(hint)) {
					return true
				}
			}
			return false
		},
		Generate: func(value string) string {
			// Find matched prefix.
			prefix := ""
			for _, pfx := range f.Prefixes {
				if strings.HasPrefix(value, pfx) {
					prefix = pfx
					break
				}
			}
			// Determine total length.
			total := f.Length
			if total == 0 {
				total = len(value)
			}
			rest := total - len(prefix)
			if rest < 0 {
				rest = 0
			}
			// Generate random remainder using the specified charset.
			var body string
			switch f.Charset {
			case "hex":
				body = randFromAlphabet(rest, "0123456789abcdef")
			case "base64":
				body = randBase64ish(rest)
			case "upper-alphanumeric":
				body = randUpperAlphanumeric(rest)
			default: // "alphanumeric"
				body = randAlphanumeric(rest)
			}
			return prefix + body
		},
	}
	register(p)
}
```

Add `"strings"` to the import block in `providers.go` if not already present. Since `providers.go` currently has no imports, add them:

```go
import "strings"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/placeholder/ -run 'TestRegisterFormat' -v`
Expected: all 3 tests PASS.

- [ ] **Step 5: Run full test suite to verify no regressions**

Run: `go test ./internal/placeholder/ -count=1 -v`
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/placeholder/providers.go internal/placeholder/providers_test.go
git commit -m "feat(placeholder): add Format struct and registerFormat for declarative providers"
```

---

### Task 2: Update GitHub provider to handle `github_pat_` tokens

**Files:**
- Modify: `internal/placeholder/provider_github.go`
- Modify: `internal/placeholder/providers_test.go`

- [ ] **Step 1: Write failing test for `github_pat_` match and generate**

Add to `internal/placeholder/providers_test.go` inside `TestProviderGitHub` or as a new test:

```go
func TestProviderGitHub_FinegrainedPAT(t *testing.T) {
	var prov ProviderPattern
	for _, p := range registry {
		if p.Name == "github" {
			prov = p
			break
		}
	}

	// github_pat_ tokens have the structure: github_pat_ + 22 alnum + _ + 59 alnum
	value := "github_pat_11ABCDEFGHIJKLMNOPQRST_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXa"

	t.Run("match_github_pat_prefix", func(t *testing.T) {
		if !prov.Match("", value) {
			t.Fatal("should match github_pat_ prefix")
		}
	})

	t.Run("generate_github_pat_structure", func(t *testing.T) {
		result := prov.Generate(value)
		if len(result) != len(value) {
			t.Fatalf("length mismatch: %d vs %d", len(result), len(value))
		}
		if result[:11] != "github_pat_" {
			t.Fatalf("expected github_pat_ prefix, got: %s", result[:11])
		}
		// Position 33 (11 + 22) should be an underscore.
		if result[33] != '_' {
			t.Fatalf("expected underscore at position 33, got: %c in %s", result[33], result)
		}
		// Characters 11-32 should be alphanumeric.
		for i := 11; i < 33; i++ {
			c := rune(result[i])
			isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			if !isAlnum {
				t.Fatalf("expected alphanumeric at pos %d, got: %c", i, c)
			}
		}
		// Characters 34-92 should be alphanumeric.
		for i := 34; i < len(result); i++ {
			c := rune(result[i])
			isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			if !isAlnum {
				t.Fatalf("expected alphanumeric at pos %d, got: %c", i, c)
			}
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/placeholder/ -run 'TestProviderGitHub_FinegrainedPAT' -v`
Expected: FAIL — `github_pat_` prefix not matched.

- [ ] **Step 3: Update `provider_github.go` to handle `github_pat_`**

Replace the content of `internal/placeholder/provider_github.go`:

```go
package placeholder

import "strings"

var githubPrefixes = []string{"github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_"}

func init() {
	register(ProviderPattern{
		Name: "github",
		Match: func(name, value string) bool {
			for _, p := range githubPrefixes {
				if strings.HasPrefix(value, p) {
					return true
				}
			}
			return strings.Contains(strings.ToUpper(name), "GITHUB")
		},
		Generate: func(value string) string {
			// Fine-grained PATs: github_pat_ + 22 alnum + _ + 59 alnum
			if strings.HasPrefix(value, "github_pat_") {
				return "github_pat_" + randAlphanumeric(22) + "_" + randAlphanumeric(59)
			}
			// Classic tokens: preserve prefix, fill remainder.
			prefix := ""
			for _, p := range githubPrefixes {
				if strings.HasPrefix(value, p) {
					prefix = p
					break
				}
			}
			rest := len(value) - len(prefix)
			return prefix + randAlphanumeric(rest)
		},
		Hosts: []string{"api.github.com", "uploads.github.com", "raw.githubusercontent.com"},
	})
}
```

Note: `github_pat_` must be first in `githubPrefixes` so it matches before the shorter prefixes would skip it.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/placeholder/ -run 'TestProviderGitHub' -v`
Expected: all GitHub tests PASS (both old and new).

- [ ] **Step 5: Run full test suite**

Run: `go test ./internal/placeholder/ -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/placeholder/provider_github.go internal/placeholder/providers_test.go
git commit -m "feat(placeholder): add github_pat_ fine-grained PAT support"
```

---

### Task 3: Add 9 format-based providers

**Files:**
- Create: `internal/placeholder/provider_zzz_formats.go`
- Create: `internal/placeholder/provider_zzz_formats_test.go`

- [ ] **Step 1: Write table-driven test**

Create `internal/placeholder/provider_zzz_formats_test.go`:

```go
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
			wantLen:    0, // match input
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
			wantLen:    0, // match input
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Find provider.
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

			// Match by key name.
			t.Run("match_key", func(t *testing.T) {
				if !prov.Match(tt.matchKey, "anything") {
					t.Fatalf("should match key %s", tt.matchKey)
				}
			})

			// Match by value prefix (if provider has prefixes).
			if tt.wantPrefix != "" {
				t.Run("match_prefix", func(t *testing.T) {
					if !prov.Match("UNKNOWN", tt.matchValue) {
						t.Fatalf("should match value %s", tt.matchValue)
					}
				})
			}

			// No match on unrelated key.
			t.Run("no_match", func(t *testing.T) {
				if prov.Match(tt.noMatchKey, "some-random-value") {
					t.Fatal("should not match unrelated key/value")
				}
			})

			// Generate: check prefix.
			t.Run("generate_prefix", func(t *testing.T) {
				result := prov.Generate(tt.genInput)
				if tt.wantPrefix != "" && !strings.HasPrefix(result, tt.wantPrefix) {
					t.Fatalf("expected prefix %q, got: %s", tt.wantPrefix, result)
				}
			})

			// Generate: check length.
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

			// Generate: check charset.
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

			// Hosts.
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/placeholder/ -run 'TestFormatProviders' -v`
Expected: FAIL — providers not registered.

- [ ] **Step 3: Create `provider_zzz_formats.go`**

Create `internal/placeholder/provider_zzz_formats.go`:

```go
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/placeholder/ -run 'TestFormatProviders' -v`
Expected: all 9 provider subtests PASS.

- [ ] **Step 5: Run full test suite**

Run: `go test ./internal/placeholder/ -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/placeholder/provider_zzz_formats.go internal/placeholder/provider_zzz_formats_test.go
git commit -m "feat(placeholder): add 9 format-based providers (Google, Replicate, HuggingFace, Vercel, GitLab, npm, Resend, Postmark, Datadog)"
```

---

### Task 4: Add SendGrid provider

**Files:**
- Create: `internal/placeholder/provider_sendgrid.go`
- Create: `internal/placeholder/provider_sendgrid_test.go`

- [ ] **Step 1: Write failing test**

Create `internal/placeholder/provider_sendgrid_test.go`:

```go
package placeholder

import (
	"strings"
	"testing"
)

func TestProviderSendGrid(t *testing.T) {
	var prov ProviderPattern
	for _, p := range registry {
		if p.Name == "sendgrid" {
			prov = p
			break
		}
	}
	if prov.Name == "" {
		t.Fatal("sendgrid provider not registered")
	}

	t.Run("match_prefix", func(t *testing.T) {
		if !prov.Match("", "SG.abc123def456ghijklmnopqr.abcdefghijklmnopqrstuvwxyz01234567890ABCDEFG") {
			t.Fatal("should match SG. prefix")
		}
	})

	t.Run("match_name", func(t *testing.T) {
		if !prov.Match("SENDGRID_API_KEY", "anything") {
			t.Fatal("should match SENDGRID in name")
		}
	})

	t.Run("no_match", func(t *testing.T) {
		if prov.Match("OTHER_KEY", "some-value") {
			t.Fatal("should not match unrelated key/value")
		}
	})

	t.Run("generate_structure", func(t *testing.T) {
		value := "SG.abc123def456ghijklmnopqr.abcdefghijklmnopqrstuvwxyz01234567890ABCDEFG"
		result := prov.Generate(value)

		if !strings.HasPrefix(result, "SG.") {
			t.Fatalf("expected SG. prefix, got: %s", result)
		}

		// Should have exactly 3 parts split by '.'
		parts := strings.Split(result, ".")
		if len(parts) != 3 {
			t.Fatalf("expected 3 dot-separated parts, got %d: %s", len(parts), result)
		}

		// First part is "SG" (from "SG." prefix split).
		if parts[0] != "SG" {
			t.Fatalf("expected first part 'SG', got: %s", parts[0])
		}

		// Second part: 22 base64 chars.
		if len(parts[1]) != 22 {
			t.Fatalf("expected second part 22 chars, got %d: %s", len(parts[1]), parts[1])
		}

		// Third part: 43 base64 chars.
		if len(parts[2]) != 43 {
			t.Fatalf("expected third part 43 chars, got %d: %s", len(parts[2]), parts[2])
		}
	})

	t.Run("generate_different", func(t *testing.T) {
		value := "SG.abc123def456ghijklmnopqr.abcdefghijklmnopqrstuvwxyz01234567890ABCDEFG"
		a := prov.Generate(value)
		b := prov.Generate(value)
		if a == b {
			t.Fatal("expected different outputs")
		}
	})

	t.Run("hosts", func(t *testing.T) {
		if len(prov.Hosts) != 1 || prov.Hosts[0] != "api.sendgrid.com" {
			t.Fatalf("unexpected hosts: %v", prov.Hosts)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/placeholder/ -run 'TestProviderSendGrid' -v`
Expected: FAIL — sendgrid provider not registered.

- [ ] **Step 3: Implement `provider_sendgrid.go`**

Create `internal/placeholder/provider_sendgrid.go`:

```go
package placeholder

import "strings"

func init() {
	register(ProviderPattern{
		Name: "sendgrid",
		Match: func(name, value string) bool {
			if strings.HasPrefix(value, "SG.") {
				return true
			}
			return strings.Contains(strings.ToUpper(name), "SENDGRID")
		},
		Generate: func(value string) string {
			// SendGrid API keys: SG. + 22 base64 chars + . + 43 base64 chars
			return "SG." + randBase64ish(22) + "." + randBase64ish(43)
		},
		Hosts: []string{"api.sendgrid.com"},
	})
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/placeholder/ -run 'TestProviderSendGrid' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/placeholder/provider_sendgrid.go internal/placeholder/provider_sendgrid_test.go
git commit -m "feat(placeholder): add SendGrid provider (SG. + two base64 segments)"
```

---

### Task 5: Add Twilio provider

**Files:**
- Create: `internal/placeholder/provider_twilio.go`
- Create: `internal/placeholder/provider_twilio_test.go`

- [ ] **Step 1: Write failing test**

Create `internal/placeholder/provider_twilio_test.go`:

```go
package placeholder

import (
	"strings"
	"testing"
)

func TestProviderTwilio(t *testing.T) {
	var prov ProviderPattern
	for _, p := range registry {
		if p.Name == "twilio" {
			prov = p
			break
		}
	}
	if prov.Name == "" {
		t.Fatal("twilio provider not registered")
	}

	t.Run("match_SK_prefix", func(t *testing.T) {
		if !prov.Match("", "SKabcdef1234567890abcdef1234567890") {
			t.Fatal("should match SK prefix")
		}
	})

	t.Run("match_name_auth_token", func(t *testing.T) {
		if !prov.Match("TWILIO_AUTH_TOKEN", "abcdef1234567890abcdef1234567890") {
			t.Fatal("should match TWILIO in name")
		}
	})

	t.Run("match_name_api_key", func(t *testing.T) {
		if !prov.Match("TWILIO_API_KEY", "SKabcdef1234567890abcdef1234567890") {
			t.Fatal("should match TWILIO in name")
		}
	})

	t.Run("no_match", func(t *testing.T) {
		if prov.Match("OTHER_KEY", "some-value") {
			t.Fatal("should not match unrelated key/value")
		}
	})

	t.Run("generate_SK_prefix", func(t *testing.T) {
		value := "SKabcdef1234567890abcdef1234567890"
		result := prov.Generate(value)
		if !strings.HasPrefix(result, "SK") {
			t.Fatalf("expected SK prefix, got: %s", result)
		}
		if len(result) != 34 { // SK + 32 hex
			t.Fatalf("expected length 34, got %d: %s", len(result), result)
		}
		// Characters after SK should be hex.
		for _, c := range result[2:] {
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
			if !isHex {
				t.Fatalf("expected hex char, got: %c in %s", c, result)
			}
		}
	})

	t.Run("generate_auth_token", func(t *testing.T) {
		// Auth token matched by name, no SK prefix — 32 hex chars.
		value := "abcdef1234567890abcdef1234567890"
		result := prov.Generate(value)
		if len(result) != 32 {
			t.Fatalf("expected length 32, got %d: %s", len(result), result)
		}
		for _, c := range result {
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
			if !isHex {
				t.Fatalf("expected hex char, got: %c in %s", c, result)
			}
		}
	})

	t.Run("hosts", func(t *testing.T) {
		if len(prov.Hosts) != 1 || prov.Hosts[0] != "api.twilio.com" {
			t.Fatalf("unexpected hosts: %v", prov.Hosts)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/placeholder/ -run 'TestProviderTwilio' -v`
Expected: FAIL — twilio provider not registered.

- [ ] **Step 3: Implement `provider_twilio.go`**

Create `internal/placeholder/provider_twilio.go`:

```go
package placeholder

import "strings"

func init() {
	register(ProviderPattern{
		Name: "twilio",
		Match: func(name, value string) bool {
			if strings.HasPrefix(value, "SK") && len(value) == 34 {
				return true
			}
			return strings.Contains(strings.ToUpper(name), "TWILIO")
		},
		Generate: func(value string) string {
			if strings.HasPrefix(value, "SK") {
				// API Key SID: SK + 32 hex chars.
				return "SK" + randFromAlphabet(32, "0123456789abcdef")
			}
			// Auth token: 32 hex chars, no prefix.
			return randFromAlphabet(32, "0123456789abcdef")
		},
		Hosts: []string{"api.twilio.com"},
	})
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/placeholder/ -run 'TestProviderTwilio' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/placeholder/provider_twilio.go internal/placeholder/provider_twilio_test.go
git commit -m "feat(placeholder): add Twilio provider (SK SID + auth token)"
```

---

### Task 6: Add Supabase JWT provider

**Files:**
- Create: `internal/placeholder/provider_supabase.go`
- Create: `internal/placeholder/provider_supabase_test.go`

- [ ] **Step 1: Write failing test**

Create `internal/placeholder/provider_supabase_test.go`:

```go
package placeholder

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestProviderSupabase(t *testing.T) {
	var prov ProviderPattern
	for _, p := range registry {
		if p.Name == "supabase" {
			prov = p
			break
		}
	}
	if prov.Name == "" {
		t.Fatal("supabase provider not registered")
	}

	// A real-looking Supabase anon key (JWT).
	anonKey := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InByb2plY3RpZCIsInJvbGUiOiJhbm9uIiwiaWF0IjoxNjg2MDAwMDAwLCJleHAiOjE4NDM2ODAwMDB9.abc123def456ghijklmnopqrstuvwxyz01234567890AB"

	t.Run("match_name_anon", func(t *testing.T) {
		if !prov.Match("SUPABASE_ANON_KEY", "anything") {
			t.Fatal("should match SUPABASE in name")
		}
	})

	t.Run("match_name_service_role", func(t *testing.T) {
		if !prov.Match("SUPABASE_SERVICE_ROLE_KEY", "anything") {
			t.Fatal("should match SUPABASE in name")
		}
	})

	t.Run("match_jwt_value", func(t *testing.T) {
		if !prov.Match("SOME_OTHER_KEY", anonKey) {
			t.Fatal("should match JWT value with alg field")
		}
	})

	t.Run("no_match", func(t *testing.T) {
		if prov.Match("OTHER_KEY", "some-value") {
			t.Fatal("should not match unrelated key/value")
		}
	})

	t.Run("generate_jwt_structure", func(t *testing.T) {
		result := prov.Generate(anonKey)

		parts := strings.Split(result, ".")
		if len(parts) != 3 {
			t.Fatalf("expected 3 JWT segments, got %d: %s", len(parts), result)
		}

		// Header should decode to valid JSON with alg and typ.
		headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatalf("header not valid base64url: %v", err)
		}
		var header map[string]interface{}
		if err := json.Unmarshal(headerJSON, &header); err != nil {
			t.Fatalf("header not valid JSON: %v", err)
		}
		if header["alg"] != "HS256" {
			t.Fatalf("expected alg HS256, got: %v", header["alg"])
		}
		if header["typ"] != "JWT" {
			t.Fatalf("expected typ JWT, got: %v", header["typ"])
		}

		// Payload should decode to valid JSON with iss, ref, role, iat, exp.
		payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("payload not valid base64url: %v", err)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(payloadJSON, &payload); err != nil {
			t.Fatalf("payload not valid JSON: %v", err)
		}
		if payload["iss"] != "supabase" {
			t.Fatalf("expected iss supabase, got: %v", payload["iss"])
		}
		if _, ok := payload["ref"]; !ok {
			t.Fatal("expected ref field in payload")
		}
		if _, ok := payload["iat"]; !ok {
			t.Fatal("expected iat field in payload")
		}
		if _, ok := payload["exp"]; !ok {
			t.Fatal("expected exp field in payload")
		}

		// Signature segment should be non-empty.
		if len(parts[2]) == 0 {
			t.Fatal("expected non-empty signature segment")
		}
	})

	t.Run("generate_anon_role", func(t *testing.T) {
		result := prov.Generate(anonKey)
		parts := strings.Split(result, ".")
		payloadJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var payload map[string]interface{}
		json.Unmarshal(payloadJSON, &payload)

		// Default role should be "anon" when key name is not available.
		role, ok := payload["role"].(string)
		if !ok {
			t.Fatal("expected role field as string")
		}
		if role != "anon" {
			t.Fatalf("expected role anon, got: %s", role)
		}
	})

	t.Run("generate_different", func(t *testing.T) {
		a := prov.Generate(anonKey)
		b := prov.Generate(anonKey)
		if a == b {
			t.Fatal("expected different outputs")
		}
	})

	t.Run("hosts", func(t *testing.T) {
		found := false
		for _, h := range prov.Hosts {
			if h == "*.supabase.co" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected *.supabase.co in hosts, got: %v", prov.Hosts)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/placeholder/ -run 'TestProviderSupabase' -v`
Expected: FAIL — supabase provider not registered.

- [ ] **Step 3: Implement `provider_supabase.go`**

Create `internal/placeholder/provider_supabase.go`:

```go
package placeholder

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// jwtHeader is the fixed base64url-encoded JWT header for HS256.
// Decodes to: {"alg":"HS256","typ":"JWT"}
const jwtHeader = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

func init() {
	register(ProviderPattern{
		Name: "supabase",
		Match: func(name, value string) bool {
			if strings.Contains(strings.ToUpper(name), "SUPABASE") {
				return true
			}
			return isJWTWithAlg(value)
		},
		Generate: func(value string) string {
			return generateSupabaseJWT("anon")
		},
		Hosts: []string{"*.supabase.co", "*.supabase.com"},
	})
}

// isJWTWithAlg checks if a value looks like a JWT by splitting on dots and
// attempting to decode the first segment as JSON with an "alg" field.
func isJWTWithAlg(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return false
	}
	_, hasAlg := header["alg"]
	return hasAlg
}

// generateSupabaseJWT creates a structurally valid JWT with Supabase-style
// payload fields.
func generateSupabaseJWT(role string) string {
	ref := randAlphanumeric(20)
	now := time.Now()
	iat := now.Add(-24 * time.Hour).Unix()
	exp := now.Add(365 * 24 * time.Hour).Unix()

	payload := fmt.Sprintf(
		`{"iss":"supabase","ref":"%s","role":"%s","iat":%d,"exp":%d}`,
		ref, role, iat, exp,
	)
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))

	const base64urlAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	signature := randFromAlphabet(43, base64urlAlphabet)

	return jwtHeader + "." + encodedPayload + "." + signature
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/placeholder/ -run 'TestProviderSupabase' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/placeholder/provider_supabase.go internal/placeholder/provider_supabase_test.go
git commit -m "feat(placeholder): add Supabase JWT provider with decodable header and payload"
```

---

### Task 7: Integration validation — run full test suite and verify `Generate()` for all 20 providers

**Files:**
- Test: all existing test files in `internal/placeholder/`

- [ ] **Step 1: Run full placeholder test suite**

Run: `go test ./internal/placeholder/ -count=1 -v`
Expected: all tests PASS — no regressions from existing providers.

- [ ] **Step 2: Run project-wide tests**

Run: `go test ./... -count=1`
Expected: all tests PASS — no package-level regressions.

- [ ] **Step 3: Spot-check `Generate()` for a few new providers via a throwaway test**

Run:
```bash
go test ./internal/placeholder/ -run 'TestFormatProviders/google/generate_prefix' -v
go test ./internal/placeholder/ -run 'TestProviderSendGrid/generate_structure' -v
go test ./internal/placeholder/ -run 'TestProviderSupabase/generate_jwt_structure' -v
go test ./internal/placeholder/ -run 'TestProviderGitHub_FinegrainedPAT/generate_github_pat_structure' -v
```
Expected: all PASS.

- [ ] **Step 4: Verify registration count**

The registry should now contain 18 entries (6 original + 3 new hand-authored + 9 format-based). Write and run a quick test:

Add to `internal/placeholder/providers_test.go`:

```go
func TestRegistryCount(t *testing.T) {
	// 6 original hand-authored + 3 new hand-authored + 9 format-based = 18
	// (The 6 original: openai, anthropic, github, stripe, aws, slack)
	// (3 new hand-authored: sendgrid, twilio, supabase)
	// (9 format-based: google, replicate, huggingface, vercel, gitlab, npm, resend, postmark, datadog)
	expected := 18
	if len(registry) != expected {
		names := make([]string, len(registry))
		for i, p := range registry {
			names[i] = p.Name
		}
		t.Fatalf("expected %d providers, got %d: %v", expected, len(registry), names)
	}
}
```

Run: `go test ./internal/placeholder/ -run 'TestRegistryCount' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/placeholder/providers_test.go
git commit -m "test(placeholder): add registry count validation for 18 providers"
```
