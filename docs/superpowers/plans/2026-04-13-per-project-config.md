# Per-Project Config Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `.veil/config.yaml` file that controls credential scoping, scanner ignore patterns, and proxy host skipping — plus a `veil sync` command to reconcile config with vault state.

**Architecture:** New config loading/validation in `internal/config`, a new `doublestar` dependency for glob matching, integration into `scanner.Scan()`, `cli/init.go`, `cli/add.go`, `runner.buildChildEnv()`, and drift detection in `cli/run.go`. New `cli/sync.go` command.

**Tech Stack:** Go, `gopkg.in/yaml.v3`, `github.com/bmatcuk/doublestar/v4`, existing Cobra CLI framework.

---

## File Structure

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `internal/config/config.go` | `ProjectConfig` struct, `Load()`, `Validate()`, `ConfigFile()` path helper |
| Create | `internal/config/config_test.go` | Unit tests for loading, validation, edge cases |
| Create | `internal/config/generate.go` | `Generate()` — writes commented YAML config from vault state |
| Create | `internal/config/generate_test.go` | Tests for config generation |
| Create | `internal/config/sync.go` | `Sync()` — reconciles config scoping with vault, returns diff |
| Create | `internal/config/sync_test.go` | Tests for sync logic |
| Modify | `internal/scanner/scanner.go` | Accept ignore patterns parameter |
| Modify | `internal/scanner/scanner_test.go` | Tests for ignore filtering |
| Modify | `internal/cli/init.go` | Load config, pass ignores to scanner, apply scoping, generate config |
| Modify | `internal/cli/add.go` | Load config, apply scoping defaults |
| Modify | `internal/cli/run.go` | Load config, merge skip_hosts, drift detection |
| Modify | `internal/runner/runner.go` | Accept skip_hosts, merge into NO_PROXY |
| Create | `internal/cli/sync.go` | `veil sync` command wiring |
| Modify | `internal/cli/root.go` | Register sync command |
| Modify | `internal/cli/cli_test.go` | Integration tests for config interactions |

---

### Task 1: Add dependencies

**Files:**
- Modify: `go.mod`

- [ ] **Step 1: Add yaml.v3 and doublestar**

```bash
cd /Users/ben/Workspace/Veil && go get gopkg.in/yaml.v3 github.com/bmatcuk/doublestar/v4
```

- [ ] **Step 2: Tidy**

```bash
cd /Users/ben/Workspace/Veil && go mod tidy
```

- [ ] **Step 3: Verify**

```bash
cd /Users/ben/Workspace/Veil && grep -E "yaml.v3|doublestar" go.mod
```

Expected: both dependencies appear in `require` block.

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: add yaml.v3 and doublestar dependencies"
```

---

### Task 2: Config loading and validation

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/config/config_test.go`:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/ben/Workspace/Veil && go test ./internal/config/ -run "TestLoad|TestConfigFile" -v
```

Expected: compilation failure — `Load` and `ConfigFile` not defined.

- [ ] **Step 3: Implement config.go**

Create `internal/config/config.go`:

```go
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"
)

// ProjectConfig holds the parsed contents of .veil/config.yaml.
type ProjectConfig struct {
	Scoping   map[string][]string `yaml:"scoping"`
	Ignore    []string            `yaml:"ignore"`
	SkipHosts []string            `yaml:"skip_hosts"`
}

// validTopLevelKeys is the set of allowed top-level keys in config.yaml.
var validTopLevelKeys = map[string]bool{
	"scoping":    true,
	"ignore":     true,
	"skip_hosts": true,
}

// ConfigFile returns the path to the project config file.
func ConfigFile(root string) string {
	return filepath.Join(ProjectStateDir(root), "config.yaml")
}

// Load reads and validates .veil/config.yaml at the given path.
// If the file does not exist, it returns a zero-value ProjectConfig (not an error).
// An empty file or comments-only file is valid.
func Load(path string) (*ProjectConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &ProjectConfig{}, nil
		}
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	// Empty or whitespace-only file.
	if len(strings.TrimSpace(string(data))) == 0 {
		return &ProjectConfig{}, nil
	}

	// First pass: check for unknown keys using a raw map.
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	// raw can be nil for comments-only YAML.
	if raw == nil {
		return &ProjectConfig{}, nil
	}
	for key := range raw {
		if !validTopLevelKeys[key] {
			return nil, fmt.Errorf("config: unknown key %q in %s (valid keys: scoping, ignore, skip_hosts)", key, path)
		}
	}

	// Second pass: unmarshal into typed struct.
	var cfg ProjectConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	// Validate ignore patterns.
	for _, pattern := range cfg.Ignore {
		if filepath.IsAbs(pattern) {
			return nil, fmt.Errorf("config: ignore pattern %q is absolute (must be relative to project root)", pattern)
		}
		if !doublestar.ValidatePattern(pattern) {
			return nil, fmt.Errorf("config: ignore pattern %q has invalid glob syntax", pattern)
		}
	}

	// Normalise nil maps/slices to empty.
	if cfg.Scoping == nil {
		cfg.Scoping = map[string][]string{}
	}
	if cfg.Ignore == nil {
		cfg.Ignore = []string{}
	}
	if cfg.SkipHosts == nil {
		cfg.SkipHosts = []string{}
	}

	return &cfg, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/ben/Workspace/Veil && go test ./internal/config/ -run "TestLoad|TestConfigFile" -v
```

Expected: all PASS.

- [ ] **Step 5: Run full test suite to check for regressions**

```bash
cd /Users/ben/Workspace/Veil && go test ./...
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add config loading and validation"
```

---

### Task 3: Scanner ignore filtering

**Files:**
- Modify: `internal/scanner/scanner.go`
- Modify: `internal/scanner/scanner_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `internal/scanner/scanner_test.go`:

```go
func TestScan_IgnorePatterns(t *testing.T) {
	dir := t.TempDir()

	// Create .env and .env.local.
	for _, name := range []string{".env", ".env.local"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("X=1\n"), 0o644); err != nil {
			t.Fatalf("creating %s: %v", name, err)
		}
	}

	// Ignore .env.local.
	got, err := Scan(dir, ".env.local")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(got), got)
	}
	if filepath.Base(got[0]) != ".env" {
		t.Errorf("expected .env, got %s", got[0])
	}
}

func TestScan_IgnoreGlobStar(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("X=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env.production"), []byte("X=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Ignore all .env.* files using glob.
	got, err := Scan(dir, ".env.*")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(got), got)
	}
	if filepath.Base(got[0]) != ".env" {
		t.Errorf("expected .env, got %s", got[0])
	}
}

func TestScan_NoIgnorePatterns(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{".env", ".env.local"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("X=1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// No ignore patterns — same as current behavior.
	got, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 files, got %d: %v", len(got), got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/ben/Workspace/Veil && go test ./internal/scanner/ -run "TestScan_Ignore|TestScan_NoIgnore" -v
```

Expected: compilation failure — `Scan` signature mismatch (extra args).

- [ ] **Step 3: Update Scan to accept variadic ignore patterns**

Modify `internal/scanner/scanner.go`. Change the `Scan` function signature and add ignore matching:

```go
package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// curatedNames is the list of .env file basenames we look for.
var curatedNames = []string{
	".env",
	".env.local",
	".env.development",
	".env.production",
}

// excludeSuffixes lists suffixes that mark a file as an example/sample.
var excludeSuffixes = []string{
	".example",
	".sample",
}

// Scan discovers .env files in root by checking a curated list of names.
// It returns absolute paths sorted alphabetically. Files matching example/sample
// patterns are excluded. Optional ignorePatterns are glob patterns (relative to
// root) that cause matched files to be skipped.
// If no files are found, an empty slice is returned.
func Scan(root string, ignorePatterns ...string) ([]string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	root = abs
	var found []string
	for _, name := range curatedNames {
		if isExcluded(name) {
			continue
		}
		if isIgnored(name, ignorePatterns) {
			continue
		}
		p := filepath.Join(root, name)
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		found = append(found, p)
	}
	sort.Strings(found)
	if found == nil {
		found = []string{}
	}
	return found, nil
}

// isExcluded returns true if the name matches an exclusion pattern.
func isExcluded(name string) bool {
	for _, suffix := range excludeSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// isIgnored returns true if the relative path matches any ignore pattern.
func isIgnored(relPath string, patterns []string) bool {
	for _, pattern := range patterns {
		matched, err := doublestar.Match(pattern, relPath)
		if err != nil {
			continue
		}
		if matched {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run scanner tests**

```bash
cd /Users/ben/Workspace/Veil && go test ./internal/scanner/ -v
```

Expected: all PASS (new tests and existing tests — existing callers pass zero variadic args so behavior is unchanged).

- [ ] **Step 5: Run full test suite to confirm no regressions**

```bash
cd /Users/ben/Workspace/Veil && go test ./...
```

Expected: all PASS. The variadic signature is backward-compatible — all existing call sites pass zero args.

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/scanner.go internal/scanner/scanner_test.go
git commit -m "feat(scanner): add ignore pattern filtering to Scan"
```

---

### Task 4: Config generation

**Files:**
- Create: `internal/config/generate.go`
- Create: `internal/config/generate_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/config/generate_test.go`:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/ben/Workspace/Veil && go test ./internal/config/ -run "TestGenerate" -v
```

Expected: compilation failure — `ScopingEntry` and `Generate` not defined.

- [ ] **Step 3: Implement generate.go**

Create `internal/config/generate.go`:

```go
package config

import (
	"fmt"
	"strings"
)

// ScopingEntry represents a credential's name and allowed hosts for config generation.
type ScopingEntry struct {
	Name  string
	Hosts []string
}

// Generate produces the contents of a .veil/config.yaml file.
// Credentials are listed under the scoping key with their hosts.
// The ignore and skip_hosts sections are included as commented-out examples.
func Generate(entries []ScopingEntry) string {
	var b strings.Builder

	b.WriteString("# Veil project config\n")
	b.WriteString("# Docs: https://getveil.dev/docs/config\n")
	b.WriteString("\n")

	// Scoping section.
	if len(entries) == 0 {
		b.WriteString("# Credential scoping — map credential names to allowed hosts.\n")
		b.WriteString("# These override auto-detected hosts. Remove an entry to use auto-detection.\n")
		b.WriteString("# scoping:\n")
		b.WriteString("#   EXAMPLE_KEY:\n")
		b.WriteString("#     - api.example.com\n")
	} else {
		b.WriteString("# Credential scoping — map credential names to allowed hosts.\n")
		b.WriteString("# These override auto-detected hosts. Remove an entry to use auto-detection.\n")
		b.WriteString("scoping:\n")
		for _, entry := range entries {
			if len(entry.Hosts) == 0 {
				b.WriteString(fmt.Sprintf("  %s: []\n", entry.Name))
			} else {
				b.WriteString(fmt.Sprintf("  %s:\n", entry.Name))
				for _, host := range entry.Hosts {
					b.WriteString(fmt.Sprintf("    - %s\n", host))
				}
			}
		}
	}

	b.WriteString("\n")

	// Ignore section (commented out).
	b.WriteString("# Scanner ignore — glob patterns (relative to project root) to skip during init.\n")
	b.WriteString("# ignore:\n")
	b.WriteString("#   - \"test/fixtures/**\"\n")
	b.WriteString("#   - \"*.example\"\n")

	b.WriteString("\n")

	// SkipHosts section (commented out).
	b.WriteString("# Host skip list — hosts the proxy passes through without interception.\n")
	b.WriteString("# skip_hosts:\n")
	b.WriteString("#   - \"*.internal.company.com\"\n")

	return b.String()
}

// GenerateFromConfig produces config.yaml contents from a full ProjectConfig,
// preserving populated ignore and skip_hosts sections (used by veil sync).
func GenerateFromConfig(cfg *ProjectConfig) string {
	// Build scoping entries from the config map.
	entries := make([]ScopingEntry, 0, len(cfg.Scoping))
	for name, hosts := range cfg.Scoping {
		entries = append(entries, ScopingEntry{Name: name, Hosts: hosts})
	}

	var b strings.Builder

	b.WriteString("# Veil project config\n")
	b.WriteString("# Docs: https://getveil.dev/docs/config\n")
	b.WriteString("\n")

	// Scoping section.
	b.WriteString("# Credential scoping — map credential names to allowed hosts.\n")
	b.WriteString("# These override auto-detected hosts. Remove an entry to use auto-detection.\n")
	if len(entries) == 0 {
		b.WriteString("# scoping:\n")
		b.WriteString("#   EXAMPLE_KEY:\n")
		b.WriteString("#     - api.example.com\n")
	} else {
		b.WriteString("scoping:\n")
		for _, entry := range entries {
			if len(entry.Hosts) == 0 {
				b.WriteString(fmt.Sprintf("  %s: []\n", entry.Name))
			} else {
				b.WriteString(fmt.Sprintf("  %s:\n", entry.Name))
				for _, host := range entry.Hosts {
					b.WriteString(fmt.Sprintf("    - %s\n", host))
				}
			}
		}
	}

	b.WriteString("\n")

	// Ignore section — write populated if non-empty, commented example otherwise.
	b.WriteString("# Scanner ignore — glob patterns (relative to project root) to skip during init.\n")
	if len(cfg.Ignore) > 0 {
		b.WriteString("ignore:\n")
		for _, pattern := range cfg.Ignore {
			b.WriteString(fmt.Sprintf("  - \"%s\"\n", pattern))
		}
	} else {
		b.WriteString("# ignore:\n")
		b.WriteString("#   - \"test/fixtures/**\"\n")
		b.WriteString("#   - \"*.example\"\n")
	}

	b.WriteString("\n")

	// SkipHosts section — write populated if non-empty, commented example otherwise.
	b.WriteString("# Host skip list — hosts the proxy passes through without interception.\n")
	if len(cfg.SkipHosts) > 0 {
		b.WriteString("skip_hosts:\n")
		for _, host := range cfg.SkipHosts {
			b.WriteString(fmt.Sprintf("  - \"%s\"\n", host))
		}
	} else {
		b.WriteString("# skip_hosts:\n")
		b.WriteString("#   - \"*.internal.company.com\"\n")
	}

	return b.String()
}
```

- [ ] **Step 4: Run tests**

```bash
cd /Users/ben/Workspace/Veil && go test ./internal/config/ -run "TestGenerate" -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/generate.go internal/config/generate_test.go
git commit -m "feat(config): add config file generation"
```

---

### Task 5: Integrate config into `veil init`

**Files:**
- Modify: `internal/cli/init.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/cli/cli_test.go`:

```go
func TestInitGeneratesConfig(t *testing.T) {
	root := initProject(t)

	// Config file should exist after init.
	configPath := filepath.Join(root, ".veil", "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("config file should exist after init: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "scoping:") {
		t.Error("config should contain scoping section")
	}
	if !strings.Contains(content, "OPENAI_API_KEY") {
		t.Error("config should contain the vaulted credential name")
	}
	if !strings.Contains(content, "api.openai.com") {
		t.Error("config should contain auto-detected host")
	}
}

func TestInitRespectsIgnorePatterns(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create two .env files.
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("API_KEY=sk-proj-1234567890abcdef\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, ".env.local"), []byte("LOCAL_KEY=sk-proj-abcdef1234567890\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create .veil dir and config that ignores .env.local.
	veilDir := filepath.Join(tmpDir, ".veil")
	if err := os.MkdirAll(veilDir, 0700); err != nil {
		t.Fatal(err)
	}
	configContent := "ignore:\n  - \".env.local\"\n"
	if err := os.WriteFile(filepath.Join(veilDir, "config.yaml"), []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	output := out.String()
	// Should process 1 .env file (not .env.local).
	if !strings.Contains(output, "1 secret") {
		t.Errorf("expected 1 secret vaulted (ignoring .env.local), got: %s", output)
	}
}

func TestInitRespectsScopingConfig(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("CUSTOM_TOKEN=secret1234567890abc\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Pre-create config with scoping.
	veilDir := filepath.Join(tmpDir, ".veil")
	if err := os.MkdirAll(veilDir, 0700); err != nil {
		t.Fatal(err)
	}
	configContent := "scoping:\n  CUSTOM_TOKEN:\n    - api.custom.com\n    - cdn.custom.com\n"
	if err := os.WriteFile(filepath.Join(veilDir, "config.yaml"), []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Verify the credential got the config-specified hosts.
	v, err := openVault(tmpDir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	cred, found := v.Get("CUSTOM_TOKEN")
	if !found {
		t.Fatal("CUSTOM_TOKEN not found in vault")
	}
	if len(cred.AllowedHosts) != 2 {
		t.Fatalf("expected 2 allowed hosts from config, got %d: %v", len(cred.AllowedHosts), cred.AllowedHosts)
	}
	if cred.AllowedHosts[0] != "api.custom.com" {
		t.Errorf("expected first host 'api.custom.com', got %q", cred.AllowedHosts[0])
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/ben/Workspace/Veil && go test ./internal/cli/ -run "TestInitGeneratesConfig|TestInitRespectsIgnore|TestInitRespectsScoping" -v
```

Expected: `TestInitGeneratesConfig` fails (no config file generated), others may fail too.

- [ ] **Step 3: Modify init.go to load config, apply ignore patterns, apply scoping, and generate config**

In `internal/cli/init.go`, add the following changes:

1. After resolving `root` (step 1) and before scanning (step 3), load the config:

```go
	// 2b. Load existing config if present.
	configPath := config.ConfigFile(root)
	cfg, err := config.Load(configPath)
	if err != nil {
		return cliError(fmt.Sprintf("loading config: %v", err), "")
	}
```

2. Pass ignore patterns to `scanner.Scan`:

```go
	envPaths, err := scanner.Scan(root, cfg.Ignore...)
```

3. When building the credential, check config scoping before auto-detection. Replace the `credHosts` line:

```go
	credHosts := placeholder.HostsForCredential(line.Key, line.Value)
```

with:

```go
	var credHosts []string
	if configHosts, ok := cfg.Scoping[line.Key]; ok {
		credHosts = configHosts
	} else {
		credHosts = placeholder.HostsForCredential(line.Key, line.Value)
	}
```

Apply the same change for the MCP config credential hosts in `processMCPConfig`. Pass `cfg` as a parameter to `processMCPConfig`:

```go
	n, s, err := processMCPConfig(cmd, v, mcpConfigPath, cfg, force, dryRun)
```

Update the `processMCPConfig` signature and the credential hosts resolution inside it:

```go
func processMCPConfig(cmd *cobra.Command, v *vault.Vault, configPath string, cfg *config.ProjectConfig, force, dryRun bool) (int, int, error) {
```

And inside the loop:

```go
	var credHosts []string
	if configHosts, ok := cfg.Scoping[credName]; ok {
		credHosts = configHosts
	} else {
		credHosts = placeholder.HostsForCredential(key, value)
	}
```

4. After the vault results section, generate and write the config file. Add before the "Phase: Setting up proxy" section:

```go
	// Phase: Writing config.
	if !dryRun {
		entries := make([]config.ScopingEntry, 0, len(v.List()))
		for _, cred := range v.List() {
			entries = append(entries, config.ScopingEntry{
				Name:  cred.Name,
				Hosts: cred.AllowedHosts,
			})
		}
		configContent := config.Generate(entries)
		configPath := config.ConfigFile(root)
		if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
			return cliError(fmt.Sprintf("writing config: %v", err), "")
		}
	}
```

- [ ] **Step 4: Run the new tests**

```bash
cd /Users/ben/Workspace/Veil && go test ./internal/cli/ -run "TestInitGeneratesConfig|TestInitRespectsIgnore|TestInitRespectsScoping" -v
```

Expected: all PASS.

- [ ] **Step 5: Run full test suite**

```bash
cd /Users/ben/Workspace/Veil && go test ./...
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/init.go internal/cli/cli_test.go
git commit -m "feat(cli): integrate config into veil init"
```

---

### Task 6: Integrate config into `veil add`

**Files:**
- Modify: `internal/cli/add.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/cli/cli_test.go`:

```go
func TestAddRespectsConfigScoping(t *testing.T) {
	root := initProject(t)

	// Write config with scoping for a new credential.
	configPath := filepath.Join(root, ".veil", "config.yaml")
	configContent := "scoping:\n  NEW_TOKEN:\n    - api.newservice.com\n    - cdn.newservice.com\n"
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Add credential without --host flags.
	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"add", "--path", root, "--value", "some-secret-value-123456", "NEW_TOKEN"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	// Check vault has config-specified hosts.
	v, err := openVault(root)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	cred, found := v.Get("NEW_TOKEN")
	if !found {
		t.Fatal("NEW_TOKEN not found in vault")
	}
	if len(cred.AllowedHosts) != 2 || cred.AllowedHosts[0] != "api.newservice.com" {
		t.Errorf("expected config hosts, got %v", cred.AllowedHosts)
	}
}

func TestAddHostFlagOverridesConfig(t *testing.T) {
	root := initProject(t)

	// Write config with scoping.
	configPath := filepath.Join(root, ".veil", "config.yaml")
	configContent := "scoping:\n  NEW_TOKEN:\n    - api.config.com\n"
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Add credential with explicit --host flag — should override config.
	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"add", "--path", root, "--value", "some-secret-value-123456", "--host", "api.override.com", "NEW_TOKEN"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	v, err := openVault(root)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	cred, found := v.Get("NEW_TOKEN")
	if !found {
		t.Fatal("NEW_TOKEN not found")
	}
	if len(cred.AllowedHosts) != 1 || cred.AllowedHosts[0] != "api.override.com" {
		t.Errorf("--host flag should override config, got %v", cred.AllowedHosts)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/ben/Workspace/Veil && go test ./internal/cli/ -run "TestAddRespectsConfig|TestAddHostFlagOverrides" -v
```

Expected: `TestAddRespectsConfigScoping` fails — config scoping not applied.

- [ ] **Step 3: Modify add.go to load config and apply scoping**

In `runAdd`, after resolving `root` and before the "Resolve allowed hosts" section, load the config:

```go
	// Load project config for scoping defaults.
	configPath := config.ConfigFile(root)
	cfg, err := config.Load(configPath)
	if err != nil {
		return cliError(fmt.Sprintf("loading config: %v", err), "")
	}
```

Then modify the "Resolve allowed hosts" section. Replace:

```go
	// Resolve allowed hosts.
	allowedHosts := hosts
	if len(allowedHosts) == 0 {
		allowedHosts = placeholder.HostsForCredential(name, value)
	}
```

With:

```go
	// Resolve allowed hosts: --host flags > config scoping > auto-detection.
	allowedHosts := hosts
	if len(allowedHosts) == 0 {
		if configHosts, ok := cfg.Scoping[name]; ok {
			allowedHosts = configHosts
		} else {
			allowedHosts = placeholder.HostsForCredential(name, value)
		}
	}
```

Add the `config` import to the import block.

- [ ] **Step 4: Run tests**

```bash
cd /Users/ben/Workspace/Veil && go test ./internal/cli/ -run "TestAddRespectsConfig|TestAddHostFlagOverrides" -v
```

Expected: all PASS.

- [ ] **Step 5: Run full test suite**

```bash
cd /Users/ben/Workspace/Veil && go test ./...
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/add.go internal/cli/cli_test.go
git commit -m "feat(cli): apply config scoping in veil add"
```

---

### Task 7: Integrate skip_hosts into `veil run`

**Files:**
- Modify: `internal/runner/runner.go`
- Modify: `internal/cli/run.go`

- [ ] **Step 1: Write the failing tests**

Add to `internal/runner/runner_test.go` (or create if needed — check what exists):

```go
func TestBuildChildEnv_MergesSkipHosts(t *testing.T) {
	env := buildChildEnv([]string{"HOME=/home/user"}, "http://127.0.0.1:8080", "/tmp/bundle.pem", []string{"staging.internal.com", "*.metrics.corp"})

	var noProxy string
	for _, kv := range env {
		if strings.HasPrefix(kv, "NO_PROXY=") {
			noProxy = strings.TrimPrefix(kv, "NO_PROXY=")
			break
		}
	}

	if noProxy == "" {
		t.Fatal("NO_PROXY not found in env")
	}
	if !strings.Contains(noProxy, "localhost") {
		t.Error("NO_PROXY should contain default localhost")
	}
	if !strings.Contains(noProxy, "staging.internal.com") {
		t.Error("NO_PROXY should contain staging.internal.com from skip_hosts")
	}
	if !strings.Contains(noProxy, "*.metrics.corp") {
		t.Error("NO_PROXY should contain *.metrics.corp from skip_hosts")
	}
}

func TestBuildChildEnv_EmptySkipHosts(t *testing.T) {
	env := buildChildEnv([]string{"HOME=/home/user"}, "http://127.0.0.1:8080", "/tmp/bundle.pem", nil)

	var noProxy string
	for _, kv := range env {
		if strings.HasPrefix(kv, "NO_PROXY=") {
			noProxy = strings.TrimPrefix(kv, "NO_PROXY=")
			break
		}
	}
	// Should still have the defaults.
	want := "localhost,127.0.0.1,::1"
	if noProxy != want {
		t.Errorf("NO_PROXY = %q, want %q", noProxy, want)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/ben/Workspace/Veil && go test ./internal/runner/ -run "TestBuildChildEnv" -v
```

Expected: compilation failure — `buildChildEnv` signature mismatch.

- [ ] **Step 3: Add skipHosts parameter to buildChildEnv**

Modify `internal/runner/runner.go`. Update `buildChildEnv` signature:

```go
func buildChildEnv(environ []string, proxyURL, bundlePath string, skipHosts []string) []string {
```

Update the NO_PROXY lines at the end of the function:

```go
	noProxy := "localhost,127.0.0.1,::1"
	if len(skipHosts) > 0 {
		noProxy = noProxy + "," + strings.Join(skipHosts, ",")
	}

	return append(stripped,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
		"NO_PROXY="+noProxy,
		"no_proxy="+noProxy,
		"NODE_EXTRA_CA_CERTS="+bundlePath,
		"SSL_CERT_FILE="+bundlePath,
		"CURL_CA_BUNDLE="+bundlePath,
		"REQUESTS_CA_BUNDLE="+bundlePath,
		"HTTPLIB2_CA_CERTS="+bundlePath,
	)
```

- [ ] **Step 4: Update the call site in Run()**

In `runner.go`, the `Run` function calls `buildChildEnv`. Add `SkipHosts` to `Config`:

```go
type Config struct {
	Root      string
	Command   string
	Args      []string
	Verbose   bool
	SkipHosts []string
	Keystore  vault.Keystore
}
```

Update the call:

```go
	env := buildChildEnv(os.Environ(), proxyURL, bundlePath, cfg.SkipHosts)
```

- [ ] **Step 5: Update cli/run.go to load config and pass skip_hosts**

In `runRun`, load the config and pass skip_hosts to runner:

```go
	// Load project config.
	configPath := config.ConfigFile(root)
	cfg, err := config.Load(configPath)
	if err != nil {
		return cliError(fmt.Sprintf("loading config: %v", err), "")
	}

	result, err := runner.Run(cmd.Context(), runner.Config{
		Root:      root,
		Command:   args[0],
		Args:      args[1:],
		Verbose:   flagVerbose,
		SkipHosts: cfg.SkipHosts,
	})
```

Add the `config` import.

- [ ] **Step 6: Run tests**

```bash
cd /Users/ben/Workspace/Veil && go test ./internal/runner/ -run "TestBuildChildEnv" -v && go test ./internal/cli/ -v
```

Expected: all PASS.

- [ ] **Step 7: Run full test suite**

```bash
cd /Users/ben/Workspace/Veil && go test ./...
```

Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/runner/runner.go internal/runner/runner_test.go internal/cli/run.go
git commit -m "feat(runner): merge config skip_hosts into NO_PROXY"
```

---

### Task 8: Drift detection in `veil run`

**Files:**
- Modify: `internal/cli/run.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/cli/cli_test.go`:

```go
func TestRunWarnsStaleScopingEntry(t *testing.T) {
	root := initProject(t)

	// Write config with an entry for a credential that doesn't exist.
	configPath := filepath.Join(root, ".veil", "config.yaml")
	configContent := "scoping:\n  OPENAI_API_KEY:\n    - api.openai.com\n  NONEXISTENT_KEY:\n    - api.fake.com\n"
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs([]string{"run", "--path", root, "--", "echo", "hi"})

	// Run will likely fail due to proxy setup in test, but we can check stderr
	// for the drift warning. We capture what we can.
	_ = cmd.Execute()

	stderrStr := errOut.String()
	if !strings.Contains(stderrStr, "NONEXISTENT_KEY") {
		t.Errorf("expected stale scoping warning for NONEXISTENT_KEY, stderr: %s", stderrStr)
	}
}
```

Note: This test may need adjustment depending on how far `veil run` gets in test mode (proxy setup may fail). If the test framework doesn't support full `veil run`, we can extract the drift check into a testable function instead.

- [ ] **Step 2: Implement drift detection as a standalone function**

Add to `internal/cli/run.go`, a function that checks for drift and returns warning messages:

```go
// checkConfigDrift compares config scoping entries against vault credentials
// and returns warning messages for any mismatches.
func checkConfigDrift(cfg *config.ProjectConfig, credNames []string) []string {
	if len(credNames) == 0 {
		// Zero credentials loaded — suppress drift warnings.
		return nil
	}

	credSet := make(map[string]bool, len(credNames))
	for _, name := range credNames {
		credSet[name] = true
	}

	var warnings []string

	// Check for stale config entries (config references credential not in vault).
	for name := range cfg.Scoping {
		if !credSet[name] {
			warnings = append(warnings, fmt.Sprintf("config scoping references %q but it is not in the vault (stale entry)", name))
		}
	}

	// Check for uncovered credentials (vault has credential with no config entry).
	for _, name := range credNames {
		if _, ok := cfg.Scoping[name]; !ok {
			warnings = append(warnings, fmt.Sprintf("credential %q has no scoping entry in config", name))
		}
	}

	return warnings
}
```

Then in `runRun`, after loading the config and before calling `runner.Run`, add drift detection that prints warnings to stderr:

```go
	// Drift detection: compare config scoping against vault.
	v, err := openVault(root)
	if err == nil {
		credNames := make([]string, 0, len(v.List()))
		for _, c := range v.List() {
			credNames = append(credNames, c.Name)
		}
		for _, warning := range checkConfigDrift(cfg, credNames) {
			fmt.Fprintf(cmd.ErrOrStderr(), "%s %s\n", ui.WarnPrefix(), warning)
		}
	}
```

Wait — `veil run` already opens the vault inside `runner.Run`. Opening it twice is wasteful. Instead, add the drift check to `runRun` by opening the vault once for the check and letting `runner.Run` open it again internally (the vault is small, this is fine for MVP). Alternatively, extract drift into runner. For simplicity, keep it in `runRun` before `runner.Run` is called.

- [ ] **Step 3: Write a unit test for checkConfigDrift**

Add to `internal/cli/cli_test.go`:

```go
func TestCheckConfigDrift_Stale(t *testing.T) {
	cfg := &config.ProjectConfig{
		Scoping: map[string][]string{
			"EXISTS":     {"api.example.com"},
			"STALE_KEY":  {"api.stale.com"},
		},
	}
	warnings := checkConfigDrift(cfg, []string{"EXISTS"})

	var foundStale, foundUncovered bool
	for _, w := range warnings {
		if strings.Contains(w, "STALE_KEY") && strings.Contains(w, "stale") {
			foundStale = true
		}
	}
	if !foundStale {
		t.Errorf("expected stale warning for STALE_KEY, got: %v", warnings)
	}
	_ = foundUncovered
}

func TestCheckConfigDrift_Uncovered(t *testing.T) {
	cfg := &config.ProjectConfig{
		Scoping: map[string][]string{
			"COVERED": {"api.example.com"},
		},
	}
	warnings := checkConfigDrift(cfg, []string{"COVERED", "UNCOVERED_KEY"})

	var found bool
	for _, w := range warnings {
		if strings.Contains(w, "UNCOVERED_KEY") && strings.Contains(w, "no scoping") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected uncovered warning for UNCOVERED_KEY, got: %v", warnings)
	}
}

func TestCheckConfigDrift_ZeroCredentials(t *testing.T) {
	cfg := &config.ProjectConfig{
		Scoping: map[string][]string{
			"ANYTHING": {"api.example.com"},
		},
	}
	warnings := checkConfigDrift(cfg, nil)
	if len(warnings) != 0 {
		t.Errorf("zero credentials should suppress drift warnings, got: %v", warnings)
	}
}

func TestCheckConfigDrift_NoDrift(t *testing.T) {
	cfg := &config.ProjectConfig{
		Scoping: map[string][]string{
			"KEY_A": {"api.a.com"},
			"KEY_B": {"api.b.com"},
		},
	}
	warnings := checkConfigDrift(cfg, []string{"KEY_A", "KEY_B"})
	if len(warnings) != 0 {
		t.Errorf("expected no drift, got: %v", warnings)
	}
}
```

- [ ] **Step 4: Run tests**

```bash
cd /Users/ben/Workspace/Veil && go test ./internal/cli/ -run "TestCheckConfigDrift" -v
```

Expected: all PASS.

- [ ] **Step 5: Run full test suite**

```bash
cd /Users/ben/Workspace/Veil && go test ./...
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/run.go internal/cli/cli_test.go
git commit -m "feat(cli): add config drift detection to veil run"
```

---

### Task 9: Sync command

**Files:**
- Create: `internal/config/sync.go`
- Create: `internal/config/sync_test.go`
- Create: `internal/cli/sync.go`
- Modify: `internal/cli/root.go`

- [ ] **Step 1: Write the failing tests for sync logic**

Create `internal/config/sync_test.go`:

```go
package config

import (
	"testing"
)

func TestSync_AddsNewCredentials(t *testing.T) {
	existing := &ProjectConfig{
		Scoping: map[string][]string{
			"OLD_KEY": {"api.old.com"},
		},
		Ignore:    []string{},
		SkipHosts: []string{},
	}
	vaultEntries := []ScopingEntry{
		{Name: "OLD_KEY", Hosts: []string{"api.old.com"}},
		{Name: "NEW_KEY", Hosts: []string{"api.new.com"}},
	}

	result := Sync(existing, vaultEntries)

	if len(result.Added) != 1 || result.Added[0] != "NEW_KEY" {
		t.Errorf("expected 1 addition (NEW_KEY), got: %v", result.Added)
	}
	if len(result.Removed) != 0 {
		t.Errorf("expected 0 removals, got: %v", result.Removed)
	}
	if _, ok := result.Config.Scoping["NEW_KEY"]; !ok {
		t.Error("NEW_KEY should be in synced config")
	}
	// OLD_KEY should be preserved.
	if _, ok := result.Config.Scoping["OLD_KEY"]; !ok {
		t.Error("OLD_KEY should be preserved in synced config")
	}
}

func TestSync_RemovesStaleCredentials(t *testing.T) {
	existing := &ProjectConfig{
		Scoping: map[string][]string{
			"ALIVE":   {"api.alive.com"},
			"REMOVED": {"api.removed.com"},
		},
		Ignore:    []string{},
		SkipHosts: []string{},
	}
	vaultEntries := []ScopingEntry{
		{Name: "ALIVE", Hosts: []string{"api.alive.com"}},
	}

	result := Sync(existing, vaultEntries)

	if len(result.Removed) != 1 || result.Removed[0] != "REMOVED" {
		t.Errorf("expected 1 removal (REMOVED), got: %v", result.Removed)
	}
	if _, ok := result.Config.Scoping["REMOVED"]; ok {
		t.Error("REMOVED should not be in synced config")
	}
}

func TestSync_PreservesUserHosts(t *testing.T) {
	existing := &ProjectConfig{
		Scoping: map[string][]string{
			"MY_KEY": {"custom.host.com", "other.host.com"},
		},
		Ignore:    []string{"test/**"},
		SkipHosts: []string{"*.internal.com"},
	}
	vaultEntries := []ScopingEntry{
		{Name: "MY_KEY", Hosts: []string{"auto.detected.com"}},
	}

	result := Sync(existing, vaultEntries)

	// User's custom hosts should be preserved, not replaced with vault's auto-detected hosts.
	hosts := result.Config.Scoping["MY_KEY"]
	if len(hosts) != 2 || hosts[0] != "custom.host.com" {
		t.Errorf("expected preserved user hosts, got %v", hosts)
	}
	// Ignore and skip_hosts should be untouched.
	if len(result.Config.Ignore) != 1 || result.Config.Ignore[0] != "test/**" {
		t.Errorf("ignore should be preserved, got %v", result.Config.Ignore)
	}
	if len(result.Config.SkipHosts) != 1 || result.Config.SkipHosts[0] != "*.internal.com" {
		t.Errorf("skip_hosts should be preserved, got %v", result.Config.SkipHosts)
	}
}

func TestSync_NoDrift(t *testing.T) {
	existing := &ProjectConfig{
		Scoping: map[string][]string{
			"KEY_A": {"api.a.com"},
		},
	}
	vaultEntries := []ScopingEntry{
		{Name: "KEY_A", Hosts: []string{"api.a.com"}},
	}

	result := Sync(existing, vaultEntries)

	if len(result.Added) != 0 || len(result.Removed) != 0 {
		t.Errorf("expected no changes, got added=%v removed=%v", result.Added, result.Removed)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/ben/Workspace/Veil && go test ./internal/config/ -run "TestSync" -v
```

Expected: compilation failure — `Sync` and `SyncResult` not defined.

- [ ] **Step 3: Implement sync.go**

Create `internal/config/sync.go`:

```go
package config

import "sort"

// SyncResult holds the outcome of a config sync operation.
type SyncResult struct {
	Config  *ProjectConfig
	Added   []string
	Removed []string
}

// Sync reconciles a ProjectConfig's scoping section with the current vault state.
// It adds entries for credentials that exist in the vault but not in the config,
// removes entries for credentials that no longer exist in the vault, and preserves
// user-customized host lists for existing entries. Ignore and SkipHosts are left
// untouched.
func Sync(existing *ProjectConfig, vaultEntries []ScopingEntry) SyncResult {
	// Build a set of vault credential names.
	vaultSet := make(map[string][]string, len(vaultEntries))
	for _, entry := range vaultEntries {
		vaultSet[entry.Name] = entry.Hosts
	}

	newScoping := make(map[string][]string, len(vaultEntries))
	var added, removed []string

	// Preserve existing entries that are still in the vault.
	for name, hosts := range existing.Scoping {
		if _, inVault := vaultSet[name]; inVault {
			newScoping[name] = hosts // preserve user's hosts
		} else {
			removed = append(removed, name)
		}
	}

	// Add new entries from vault that aren't in existing config.
	for _, entry := range vaultEntries {
		if _, exists := existing.Scoping[entry.Name]; !exists {
			newScoping[entry.Name] = entry.Hosts
			added = append(added, entry.Name)
		}
	}

	sort.Strings(added)
	sort.Strings(removed)

	return SyncResult{
		Config: &ProjectConfig{
			Scoping:   newScoping,
			Ignore:    existing.Ignore,
			SkipHosts: existing.SkipHosts,
		},
		Added:   added,
		Removed: removed,
	}
}
```

- [ ] **Step 4: Run tests**

```bash
cd /Users/ben/Workspace/Veil && go test ./internal/config/ -run "TestSync" -v
```

Expected: all PASS.

- [ ] **Step 5: Write the CLI sync command**

Create `internal/cli/sync.go`:

```go
package cli

import (
	"fmt"
	"os"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/ui"
	"github.com/spf13/cobra"
)

func syncCmd() *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Reconcile config with vault state",
		Long:  "Adds missing credential scoping entries and removes stale ones from .veil/config.yaml.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSync(cmd, dryRun)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview changes without writing")
	return cmd
}

func runSync(cmd *cobra.Command, dryRun bool) error {
	w := cmd.OutOrStdout()

	root, err := resolveRoot()
	if err != nil {
		return cliError(err.Error(), "")
	}

	// Check .veil/ exists.
	stateDir := config.ProjectStateDir(root)
	if info, statErr := os.Stat(stateDir); statErr != nil || !info.IsDir() {
		return cliError("project not initialized", "Run veil init to get started")
	}

	// Open vault.
	v, err := openVault(root)
	if err != nil {
		return cliError(fmt.Sprintf("opening vault: %v", err), "")
	}

	// Load existing config.
	configPath := config.ConfigFile(root)
	cfg, err := config.Load(configPath)
	if err != nil {
		return cliError(fmt.Sprintf("loading config: %v", err), "")
	}

	// Build vault entries.
	creds := v.List()
	entries := make([]config.ScopingEntry, 0, len(creds))
	for _, cred := range creds {
		entries = append(entries, config.ScopingEntry{
			Name:  cred.Name,
			Hosts: cred.AllowedHosts,
		})
	}

	// Sync.
	result := config.Sync(cfg, entries)

	if len(result.Added) == 0 && len(result.Removed) == 0 {
		fmt.Fprintln(w, "Config is in sync with vault.")
		return nil
	}

	// Report changes.
	for _, name := range result.Added {
		ui.Step(w, fmt.Sprintf("Add %s", name))
	}
	for _, name := range result.Removed {
		ui.Step(w, fmt.Sprintf("Remove %s", name))
	}

	if dryRun {
		fmt.Fprintln(w)
		fmt.Fprintln(w, ui.Muted.Sprint("(dry run — no changes written)"))
		return nil
	}

	// Write updated config. Use GenerateFromConfig to preserve ignore/skip_hosts.
	content := config.GenerateFromConfig(result.Config)
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		return cliError(fmt.Sprintf("writing config: %v", err), "")
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s\n", ui.Success.Sprint("Config synced"))

	return nil
}
```

- [ ] **Step 6: Register the sync command in root.go**

In `internal/cli/root.go`, add inside `NewRoot`:

```go
	root.AddCommand(syncCmd())
```

- [ ] **Step 7: Write integration test for veil sync**

Add to `internal/cli/cli_test.go`:

```go
func TestSyncAddsNewCredential(t *testing.T) {
	root := initProject(t)

	// Add a new credential that won't be in the generated config.
	addCmd := NewRoot("test")
	addCmd.SetOut(new(bytes.Buffer))
	addCmd.SetErr(new(bytes.Buffer))
	addCmd.SetArgs([]string{"add", "--path", root, "--value", "my-new-secret-value-1234", "BRAND_NEW_KEY"})
	if err := addCmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	// Run sync.
	syncCmd := NewRoot("test")
	syncOut := new(bytes.Buffer)
	syncCmd.SetOut(syncOut)
	syncCmd.SetErr(new(bytes.Buffer))
	syncCmd.SetArgs([]string{"sync", "--path", root})
	if err := syncCmd.Execute(); err != nil {
		t.Fatalf("sync failed: %v", err)
	}

	output := syncOut.String()
	if !strings.Contains(output, "BRAND_NEW_KEY") {
		t.Errorf("sync should report adding BRAND_NEW_KEY, got: %s", output)
	}

	// Verify config file contains the new credential.
	configData, err := os.ReadFile(filepath.Join(root, ".veil", "config.yaml"))
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}
	if !strings.Contains(string(configData), "BRAND_NEW_KEY") {
		t.Error("config file should contain BRAND_NEW_KEY after sync")
	}
}

func TestSyncDryRun(t *testing.T) {
	root := initProject(t)

	// Add a credential.
	addCmd := NewRoot("test")
	addCmd.SetOut(new(bytes.Buffer))
	addCmd.SetErr(new(bytes.Buffer))
	addCmd.SetArgs([]string{"add", "--path", root, "--value", "another-secret-value-1234", "DRY_KEY"})
	if err := addCmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	// Read config before sync.
	configBefore, err := os.ReadFile(filepath.Join(root, ".veil", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	// Run sync --dry-run.
	syncCmd := NewRoot("test")
	syncOut := new(bytes.Buffer)
	syncCmd.SetOut(syncOut)
	syncCmd.SetErr(new(bytes.Buffer))
	syncCmd.SetArgs([]string{"sync", "--path", root, "--dry-run"})
	if err := syncCmd.Execute(); err != nil {
		t.Fatalf("sync --dry-run failed: %v", err)
	}

	if !strings.Contains(syncOut.String(), "dry run") {
		t.Error("expected dry run notice in output")
	}

	// Config file should be unchanged.
	configAfter, err := os.ReadFile(filepath.Join(root, ".veil", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(configBefore) != string(configAfter) {
		t.Error("config should not change during dry run")
	}
}

func TestSyncNoChanges(t *testing.T) {
	root := initProject(t)

	// Sync immediately after init — should be in sync already.
	syncCmd := NewRoot("test")
	syncOut := new(bytes.Buffer)
	syncCmd.SetOut(syncOut)
	syncCmd.SetErr(new(bytes.Buffer))
	syncCmd.SetArgs([]string{"sync", "--path", root})
	if err := syncCmd.Execute(); err != nil {
		t.Fatalf("sync failed: %v", err)
	}

	if !strings.Contains(syncOut.String(), "in sync") {
		t.Errorf("expected 'in sync' message, got: %s", syncOut.String())
	}
}
```

- [ ] **Step 8: Run tests**

```bash
cd /Users/ben/Workspace/Veil && go test ./internal/cli/ -run "TestSync" -v && go test ./internal/config/ -run "TestSync" -v
```

Expected: all PASS.

- [ ] **Step 9: Run full test suite**

```bash
cd /Users/ben/Workspace/Veil && go test ./...
```

Expected: all PASS.

- [ ] **Step 10: Commit**

```bash
git add internal/config/sync.go internal/config/sync_test.go internal/cli/sync.go internal/cli/root.go internal/cli/cli_test.go
git commit -m "feat(cli): add veil sync command"
```

---

### Task 10: End-to-end verification

**Files:**
- No new files — manual verification.

- [ ] **Step 1: Run the full test suite**

```bash
cd /Users/ben/Workspace/Veil && go test ./... -count=1
```

Expected: all PASS.

- [ ] **Step 2: Run go vet**

```bash
cd /Users/ben/Workspace/Veil && go vet ./...
```

Expected: no issues.

- [ ] **Step 3: Build the binary**

```bash
cd /Users/ben/Workspace/Veil && go build -o /dev/null ./cmd/veil/
```

Expected: builds successfully.

- [ ] **Step 4: Verify sync command shows up in help**

```bash
cd /Users/ben/Workspace/Veil && go run ./cmd/veil/ --help
```

Expected: `sync` command appears in the command list.

- [ ] **Step 5: Commit (only if any fixups were needed)**

```bash
git add -A && git commit -m "fix: end-to-end verification fixups"
```
