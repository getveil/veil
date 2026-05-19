package placeholder_test

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/getveil/veil/internal/placeholder"
)

// readmeDisplayToKey maps the human-readable display names used in the
// README's "Bearer/Basic providers" table to the canonical provider keys
// returned by Registry.Names(). The table is the public-facing list; the
// keys are the implementation. Keep this map narrow and explicit so
// renames in either direction surface as test failures rather than
// silent drift.
var readmeDisplayToKey = map[string]string{
	"github pats":  "github",
	"openai":       "openai",
	"anthropic":    "anthropic",
	"stripe":       "stripe",
	"slack":        "slack",
	"sendgrid":     "sendgrid",
	"resend":       "resend",
	"supabase":     "supabase",
	"vercel":       "vercel",
	"replicate":    "replicate",
	"hugging face": "huggingface",
	"google":       "google",
	"gitlab":       "gitlab",
}

// TestREADMEProviderTableMatchesRegistry parses the "Bearer/Basic
// providers" row of README.md and asserts every display name listed
// there maps to a provider currently registered in DefaultRegistry().
//
// This is a doc-as-code lint: when a provider is removed from the
// registry (e.g. commit 62637c6 dropping Postmark/Datadog/Quay) but
// left in the README table, this test fails loudly instead of letting
// the docs drift silently. It does NOT assert the reverse direction —
// the registry may legitimately contain providers (e.g. aws) that are
// experimental-gated and intentionally omitted from the user-facing
// table.
func TestREADMEProviderTableMatchesRegistry(t *testing.T) {
	readme := readREADME(t)

	names := extractBearerBasicProviders(t, readme)
	if len(names) == 0 {
		t.Fatal("could not extract any provider names from README Bearer/Basic row — table format may have changed")
	}

	reg := placeholder.DefaultRegistry()
	registered := make(map[string]struct{})
	for _, n := range reg.Names() {
		registered[n] = struct{}{}
	}

	for _, display := range names {
		normalized := strings.ToLower(strings.TrimSpace(display))
		key, ok := readmeDisplayToKey[normalized]
		if !ok {
			t.Errorf("README lists provider %q but readmeDisplayToKey has no mapping for it — add the mapping or remove the entry from README.md:136", display)
			continue
		}
		if _, found := registered[key]; !found {
			t.Errorf("README lists provider %q (key=%q) but it is NOT registered in DefaultRegistry() — remove it from README.md:136 or restore the provider", display, key)
		}
	}
}

// readREADME locates and reads the repo-root README.md. It walks up from
// the test file's location to find the file rather than using a fixed
// relative path so it works regardless of where `go test` is invoked.
func readREADME(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	// file is .../internal/placeholder/readme_contract_test.go.
	// Walk up to the repo root (where README.md lives).
	dir := filepath.Dir(file)
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "README.md")
		if _, err := os.Stat(candidate); err == nil {
			b, err := os.ReadFile(candidate)
			if err != nil {
				t.Fatalf("read README.md: %v", err)
			}
			return string(b)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate README.md by walking up from test file")
	return ""
}

// bearerBasicRowRE matches the "Bearer/Basic providers" markdown table
// row. The provider list is the third column (after the leading `|` and
// the bolded label). The row is delimited by the closing `|` at end of
// line. Tolerates surrounding whitespace.
var bearerBasicRowRE = regexp.MustCompile(`(?m)^\|\s*\*\*Bearer/Basic providers\*\*\s*\|\s*(.+?)\s*\|\s*$`)

// extractBearerBasicProviders pulls the provider names out of the
// Bearer/Basic row. Names are separated by `·` (middle dot) in the
// rendered table.
func extractBearerBasicProviders(t *testing.T, readme string) []string {
	t.Helper()
	m := bearerBasicRowRE.FindStringSubmatch(readme)
	if m == nil {
		t.Fatal("Bearer/Basic providers row not found in README — has the table moved or changed format?")
	}
	cell := m[1]
	parts := strings.Split(cell, "·")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		name := strings.TrimSpace(p)
		if name == "" {
			continue
		}
		out = append(out, name)
	}
	return out
}
