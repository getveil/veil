package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_MissingFile(t *testing.T) {
	cfg, err := Load("/nonexistent/path")
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if cfg == nil {
		t.Fatal("missing file should return zero-value config, not nil")
	}
	if len(cfg.Scoping) != 0 || len(cfg.Ignore) != 0 || len(cfg.SkipHosts) != 0 {
		t.Error("missing file config should have empty fields")
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("empty file should not error: %v", err)
	}
	if cfg == nil {
		t.Fatal("empty file should return zero-value config")
	}
}

func TestLoad_CommentsOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("# just a comment\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("comments-only file should not error: %v", err)
	}
	if cfg == nil {
		t.Fatal("comments-only should return zero-value config")
	}
}

func TestLoad_FullConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
scoping:
  GITHUB_TOKEN:
    - api.github.com
  SLACK_TOKEN:
    - slack.com
    - api.slack.com
ignore:
  - "test/fixtures/**"
  - "*.example"
skip_hosts:
  - "*.internal.company.com"
  - "staging.local:8080"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("valid config should not error: %v", err)
	}

	// Scoping.
	if len(cfg.Scoping) != 2 {
		t.Fatalf("expected 2 scoping entries, got %d", len(cfg.Scoping))
	}
	ghHosts := cfg.Scoping["GITHUB_TOKEN"]
	if len(ghHosts) != 1 || ghHosts[0] != "api.github.com" {
		t.Errorf("GITHUB_TOKEN hosts = %v, want [api.github.com]", ghHosts)
	}
	slackHosts := cfg.Scoping["SLACK_TOKEN"]
	if len(slackHosts) != 2 {
		t.Errorf("SLACK_TOKEN hosts = %v, want 2 entries", slackHosts)
	}

	// Ignore.
	if len(cfg.Ignore) != 2 {
		t.Fatalf("expected 2 ignore patterns, got %d", len(cfg.Ignore))
	}

	// SkipHosts.
	if len(cfg.SkipHosts) != 2 {
		t.Fatalf("expected 2 skip_hosts, got %d", len(cfg.SkipHosts))
	}
}

func TestLoad_UnknownKeyErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
scoping:
  GITHUB_TOKEN:
    - api.github.com
scopping:
  TYPO: []
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unknown key 'scopping'")
	}
}

func TestLoad_AbsoluteIgnorePathErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
ignore:
  - "/absolute/path/.env"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for absolute ignore path")
	}
}

func TestLoad_InvalidGlobErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
ignore:
  - "[invalid"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid glob syntax")
	}
}

func TestConfigFile(t *testing.T) {
	got := ConfigFile("/project/root")
	want := filepath.Join("/project/root", ".veil", "config.yaml")
	if got != want {
		t.Errorf("ConfigFile() = %q, want %q", got, want)
	}
}
