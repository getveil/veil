package config

import (
	"strings"
	"testing"
)

func TestGenerate_BasicOutput(t *testing.T) {
	entries := []ScopingEntry{
		{Name: "GITHUB_TOKEN", Hosts: []string{"api.github.com"}},
		{Name: "OPENAI_API_KEY", Hosts: []string{"api.openai.com"}},
	}
	output := Generate(entries)

	if !strings.Contains(output, "scoping:") {
		t.Error("output should contain 'scoping:' key")
	}
	if !strings.Contains(output, "GITHUB_TOKEN:") {
		t.Error("output should contain GITHUB_TOKEN")
	}
	if !strings.Contains(output, "api.github.com") {
		t.Error("output should contain api.github.com")
	}
	if !strings.Contains(output, "OPENAI_API_KEY:") {
		t.Error("output should contain OPENAI_API_KEY")
	}
	if !strings.Contains(output, "# ignore:") {
		t.Error("output should contain commented-out ignore section")
	}
	if !strings.Contains(output, "# skip_hosts:") {
		t.Error("output should contain commented-out skip_hosts section")
	}
}

func TestGenerate_EmptyCredentials(t *testing.T) {
	output := Generate(nil)

	// Should still have the structure with commented scoping.
	if !strings.Contains(output, "# scoping:") {
		t.Error("output should contain commented scoping when no credentials")
	}
}

func TestGenerate_UnscopedCredential(t *testing.T) {
	entries := []ScopingEntry{
		{Name: "CUSTOM_KEY", Hosts: nil},
	}
	output := Generate(entries)

	if !strings.Contains(output, "CUSTOM_KEY:") {
		t.Error("output should contain CUSTOM_KEY")
	}
	// Unscoped credential should have an empty list.
	if !strings.Contains(output, "CUSTOM_KEY: []") {
		t.Error("unscoped credential should show empty list")
	}
}

func TestGenerateFromConfig_DeterministicOrdering(t *testing.T) {
	cfg := &ProjectConfig{
		Scoping: map[string][]string{
			"ZEBRA_KEY":  {"zebra.example.com"},
			"ALPHA_KEY":  {"alpha.example.com"},
			"MIDDLE_KEY": {"middle.example.com"},
		},
	}
	// Run multiple times to detect non-determinism.
	first := GenerateFromConfig(cfg)
	for i := 0; i < 20; i++ {
		got := GenerateFromConfig(cfg)
		if got != first {
			t.Fatalf("GenerateFromConfig produced different output on iteration %d", i)
		}
	}
	// Verify alphabetical order.
	alphaIdx := strings.Index(first, "ALPHA_KEY")
	middleIdx := strings.Index(first, "MIDDLE_KEY")
	zebraIdx := strings.Index(first, "ZEBRA_KEY")
	if alphaIdx > middleIdx || middleIdx > zebraIdx {
		t.Error("scoping entries should be in alphabetical order")
	}
}

func TestGenerateFromConfig_PreservesIgnoreAndSkipHosts(t *testing.T) {
	cfg := &ProjectConfig{
		Scoping: map[string][]string{
			"MY_KEY": {"api.example.com"},
		},
		Ignore:    []string{"test/**", "vendor/**/.env"},
		SkipHosts: []string{"*.internal.com", "staging.local:8080"},
	}
	output := GenerateFromConfig(cfg)

	if !strings.Contains(output, "MY_KEY:") {
		t.Error("output should contain MY_KEY")
	}
	if !strings.Contains(output, "ignore:") {
		t.Error("output should contain populated ignore section")
	}
	if !strings.Contains(output, "test/**") {
		t.Error("output should contain test/** ignore pattern")
	}
	if !strings.Contains(output, "skip_hosts:") {
		t.Error("output should contain populated skip_hosts section")
	}
	if !strings.Contains(output, "*.internal.com") {
		t.Error("output should contain *.internal.com skip host")
	}
}
