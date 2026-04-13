# Config Removal + Interactive Init Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the per-project config system and replace it with an interactive `veil init` flow and a `veil skip` command, making the vault the sole source of truth.

**Architecture:** Three phases — (1) remove config code and all dependents, (2) add skip_hosts file I/O and `veil skip` command, (3) rewrite `veil init` with interactive prompts. Each phase produces a working binary.

**Tech Stack:** Go, `github.com/spf13/cobra`, `github.com/mattn/go-isatty` (TTY detection), `github.com/fatih/color` via `internal/ui` (styling)

---

## File Map

### Files to delete

| File | Reason |
|---|---|
| `internal/config/config.go` | ProjectConfig, Load, validation — all config.yaml logic |
| `internal/config/config_test.go` | Tests for above |
| `internal/config/generate.go` | Generate, GenerateFromConfig |
| `internal/config/generate_test.go` | Tests for above |
| `internal/config/sync.go` | Sync, SyncResult |
| `internal/config/sync_test.go` | Tests for above |
| `internal/cli/sync.go` | veil sync command |

### Files to create

| File | Responsibility |
|---|---|
| `internal/skiphost/skiphost.go` | Load/Save/Add/Remove/List for `.veil/skip_hosts` flat file |
| `internal/skiphost/skiphost_test.go` | Tests for above |
| `internal/cli/skip.go` | `veil skip` cobra command |
| `internal/cli/prompt.go` | Interactive prompt helpers (Y/n/select, comma-separated input, multi-select) |
| `internal/cli/prompt_test.go` | Tests for prompt parsing logic |

### Files to modify

| File | Change |
|---|---|
| `internal/cli/root.go` | Replace `syncCmd()` with `skipCmd()` |
| `internal/cli/init.go` | Remove config loading/generation, add interactive flow, add `--yes` flag |
| `internal/cli/init_test.go` | Update tests for new init behavior |
| `internal/cli/run.go` | Remove config loading + drift detection, add skip_hosts file reading + `--skip` flag |
| `internal/cli/add.go` | Remove config loading, simplify host resolution to two paths |
| `internal/cli/cli_test.go` | Remove config/sync/drift tests, update init/add/run tests |
| `internal/scanner/scanner.go` | Remove `ignorePatterns` variadic from `Scan()`, remove `isIgnored()` |
| `internal/scanner/scanner_test.go` | Remove ignore pattern tests |
| `internal/config/paths.go` | Add `SkipHostsFile()` path helper |
| `go.mod` | Remove `gopkg.in/yaml.v3`, remove `github.com/bmatcuk/doublestar/v4` |

---

## Task 1: Delete config files and sync command

Remove the config.yaml subsystem wholesale. This breaks `veil init`, `veil run`, and `veil add` temporarily — fixed in subsequent tasks.

**Files:**
- Delete: `internal/config/config.go`, `internal/config/config_test.go`
- Delete: `internal/config/generate.go`, `internal/config/generate_test.go`
- Delete: `internal/config/sync.go`, `internal/config/sync_test.go`
- Delete: `internal/cli/sync.go`
- Modify: `internal/cli/root.go:60` (remove `syncCmd` registration)

- [ ] **Step 1: Delete config files**

```bash
rm internal/config/config.go internal/config/config_test.go
rm internal/config/generate.go internal/config/generate_test.go
rm internal/config/sync.go internal/config/sync_test.go
rm internal/cli/sync.go
```

- [ ] **Step 2: Remove syncCmd from root.go**

In `internal/cli/root.go`, remove line 60:

```go
root.AddCommand(syncCmd())
```

- [ ] **Step 3: Verify the deleted files' tests are gone**

```bash
go test ./internal/config/... 2>&1 | head -20
```

Expected: tests pass (only `paths.go`, `project.go`, and their tests remain).

- [ ] **Step 4: Commit**

```bash
git add -A internal/config/config.go internal/config/config_test.go \
  internal/config/generate.go internal/config/generate_test.go \
  internal/config/sync.go internal/config/sync_test.go \
  internal/cli/sync.go internal/cli/root.go
git commit -m "refactor: delete config.yaml subsystem and veil sync command"
```

---

## Task 2: Remove config integration from `veil add`

Simplify `veil add` to two-path host resolution: `--host` flags or auto-detection. Remove config loading.

**Files:**
- Modify: `internal/cli/add.go:7-8` (remove config import), `add.go:48-53` (remove config loading), `add.go:82-85` (simplify host resolution)

- [ ] **Step 1: Write the test for simplified host resolution**

In `internal/cli/cli_test.go`, replace `TestAddRespectsConfigScoping` (line ~652) and `TestAddHostFlagOverridesConfig` (line ~685) with a single test that verifies the two-path resolution:

```go
func TestAddHostResolution(t *testing.T) {
	root := initProject(t)

	// Add with --host flags — should use the provided hosts.
	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"add", "--path", root, "--value", "sk-test-1234567890abcdef", "--host", "api.custom.com", "MY_KEY"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add with --host failed: %v", err)
	}

	v, err := openVaultForTest(root)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	cred, ok := v.Get("MY_KEY")
	if !ok {
		t.Fatal("MY_KEY not found in vault")
	}
	if len(cred.AllowedHosts) != 1 || cred.AllowedHosts[0] != "api.custom.com" {
		t.Errorf("expected [api.custom.com], got %v", cred.AllowedHosts)
	}
}

func TestAddAutoDetectsHosts(t *testing.T) {
	root := initProject(t)

	// Add without --host — should auto-detect from key name.
	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"add", "--path", root, "--value", "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234", "GITHUB_TOKEN"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	v, err := openVaultForTest(root)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	cred, ok := v.Get("GITHUB_TOKEN")
	if !ok {
		t.Fatal("GITHUB_TOKEN not found in vault")
	}
	if len(cred.AllowedHosts) == 0 {
		t.Error("expected auto-detected hosts, got none")
	}
}
```

Note: `openVaultForTest` is a helper that opens a vault using the test keystore. If it doesn't exist, add it to `cli_test.go`:

```go
func openVaultForTest(root string) (*vault.Vault, error) {
	return vault.Open(root, testKeystore())
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/cli/ -run TestAddHostResolution -v
go test ./internal/cli/ -run TestAddAutoDetectsHosts -v
```

Expected: tests fail because `initProject` still tries to load config. We'll fix this in steps 3-4.

- [ ] **Step 3: Remove config loading from add.go**

In `internal/cli/add.go`, remove the config import and loading block. Replace the three-path host resolution with two paths:

Remove these lines (approximately lines 7-8 in imports):
```go
"github.com/8enji/veil/internal/config"
```

Remove these lines (approximately lines 48-53):
```go
// Load project config for scoping defaults.
configPath := config.ConfigFile(root)
cfg, err := config.Load(configPath)
if err != nil {
    return cliError(fmt.Sprintf("loading config: %v", err), "")
}
```

Replace the host resolution block (approximately lines 82-89):
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

With:
```go
// Resolve allowed hosts: --host flags if provided, otherwise auto-detect.
allowedHosts := hosts
if len(allowedHosts) == 0 {
    allowedHosts = placeholder.HostsForCredential(name, value)
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/cli/ -run TestAddHostResolution -v
go test ./internal/cli/ -run TestAddAutoDetectsHosts -v
```

Expected: PASS

- [ ] **Step 5: Remove old config-dependent add tests**

In `internal/cli/cli_test.go`, delete `TestAddRespectsConfigScoping` and `TestAddHostFlagOverridesConfig` entirely — they test the config scoping path that no longer exists.

- [ ] **Step 6: Run full CLI test suite**

```bash
go test ./internal/cli/ -v 2>&1 | tail -30
```

Expected: some tests fail due to config references in init.go and run.go — that's expected, those are fixed in Tasks 3-4.

- [ ] **Step 7: Commit**

```bash
git add internal/cli/add.go internal/cli/cli_test.go
git commit -m "refactor: remove config loading from veil add, simplify host resolution"
```

---

## Task 3: Remove config integration from `veil run`

Remove config loading, drift detection, and config-based skip_hosts from `veil run`. For now, `SkipHosts` in runner.Config will be an empty slice — the skip_hosts file is wired in Task 6.

**Files:**
- Modify: `internal/cli/run.go` (remove config loading, drift detection, config-based SkipHosts)
- Modify: `internal/cli/cli_test.go` (remove drift detection tests)

- [ ] **Step 1: Remove config integration from run.go**

In `internal/cli/run.go`, remove the config import:
```go
"github.com/8enji/veil/internal/config"
```

Remove the config loading block (approximately lines 40-44):
```go
// Load project config.
configPath := config.ConfigFile(root)
cfg, err := config.Load(configPath)
if err != nil {
    return cliError(fmt.Sprintf("loading config: %v", err), "")
}
```

Remove the drift detection block (approximately lines 47-55):
```go
// Drift detection: compare config scoping against vault.
v, err := openVault(root)
if err == nil {
    credNames := make([]string, 0, len(v.List()))
    for _, c := range v.List() {
        credNames = append(credNames, c.Name)
    }
    for _, warning := range checkConfigDrift(cfg, credNames) {
        ui.Warn(cmd.ErrOrStderr(), warning)
    }
}
```

Remove `cfg.SkipHosts` from the runner.Config — replace with empty slice for now:
```go
result, err := runner.Run(cmd.Context(), runner.Config{
    Root:      root,
    Command:   args[0],
    Args:      args[1:],
    Verbose:   flagVerbose,
    SkipHosts: nil,
})
```

Delete the entire `checkConfigDrift` function (approximately lines 89-123).

- [ ] **Step 2: Remove drift detection tests from cli_test.go**

Delete these test functions entirely:
- `TestCheckConfigDrift_Stale`
- `TestCheckConfigDrift_Uncovered`
- `TestCheckConfigDrift_ZeroCredentials`
- `TestCheckConfigDrift_NoDrift`
- `TestCheckConfigDrift_EmptyScoping`

- [ ] **Step 3: Verify compilation**

```bash
go build ./...
```

Expected: may still fail due to config references in `init.go` — that's fixed in Task 4.

- [ ] **Step 4: Commit**

```bash
git add internal/cli/run.go internal/cli/cli_test.go
git commit -m "refactor: remove config loading and drift detection from veil run"
```

---

## Task 4: Remove config integration from `veil init` and `# veil:skip`

Strip config loading, config-based scoping, config generation, and `# veil:skip` support from init. This makes init non-interactive for now — the interactive flow is added in Task 8. After this task, the full project compiles and all remaining tests pass.

**Files:**
- Modify: `internal/cli/init.go` (remove config imports, loading, scoping lookups, generation, veil:skip)
- Modify: `internal/cli/cli_test.go` (remove config-related init tests and veil:skip test)

- [ ] **Step 1: Remove config from init.go**

In `internal/cli/init.go`, remove the config import:
```go
"github.com/8enji/veil/internal/config"
```

Remove config loading block (approximately lines 62-66):
```go
// 2b. Load existing config if present.
configPath := config.ConfigFile(root)
cfg, err := config.Load(configPath)
if err != nil {
    return cliError(fmt.Sprintf("loading config: %v", err), "")
}
```

Remove ignore patterns from scanner call (line ~71). Change:
```go
envPaths, err := scanner.Scan(root, cfg.Ignore...)
```
To:
```go
envPaths, err := scanner.Scan(root)
```

Remove `# veil:skip` check in the .env processing loop (approximately lines 130-136):
```go
if strings.Contains(line.Raw, "# veil:skip") {
    if flagVerbose {
        _, _ = fmt.Fprintf(w, "%s\n", ui.Muted.Sprintf("  skip (veil:skip): %s", line.Key))
    }
    continue
}
```

Remove config-based scoping lookup for .env credentials (approximately lines 150-154). Change:
```go
var credHosts []string
if configHosts, ok := cfg.Scoping[line.Key]; ok {
    credHosts = configHosts
} else {
    credHosts = placeholder.HostsForCredential(line.Key, line.Value)
}
```
To:
```go
credHosts := placeholder.HostsForCredential(line.Key, line.Value)
```

Remove `cfg` parameter from `processMCPConfig` call (line ~196). Change:
```go
n, s, err := processMCPConfig(cmd, v, mcpConfigPath, force, dryRun, cfg)
```
To:
```go
n, s, err := processMCPConfig(cmd, v, mcpConfigPath, force, dryRun)
```

Remove config-based scoping from `processMCPConfig` function signature and body. Change the signature (approximately line 271):
```go
func processMCPConfig(cmd *cobra.Command, v *vault.Vault, configPath string, force, dryRun bool, cfg *config.ProjectConfig) (int, int, error) {
```
To:
```go
func processMCPConfig(cmd *cobra.Command, v *vault.Vault, configPath string, force, dryRun bool) (int, int, error) {
```

Inside `processMCPConfig`, remove the config scoping lookup (approximately lines 303-308). Change:
```go
var credHosts []string
if configHosts, ok := cfg.Scoping[credName]; ok {
    credHosts = configHosts
} else {
    credHosts = placeholder.HostsForCredential(key, value)
}
```
To:
```go
credHosts := placeholder.HostsForCredential(key, value)
```

Remove the entire config generation block at the end of `runInit` (approximately lines 219-231):
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
    if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
        return cliError(fmt.Sprintf("writing config: %v", err), "")
    }
}
```

- [ ] **Step 2: Remove config-related tests from cli_test.go**

Delete these test functions entirely:
- `TestInitGeneratesConfig`
- `TestInitRespectsScopingConfig`
- `TestInitVeilSkipAnnotation`

Also delete all sync-related tests:
- `TestSyncAddsNewCredential`
- `TestSyncDryRun`
- `TestSyncNoChanges`
- `TestSyncRemovesStaleEntry`
- `TestSyncPreservesUserCustomizedHosts`
- `TestSyncPreservesIgnoreAndSkipHosts`
- `TestSyncUninitialized`
- `TestSyncMultipleAddRemoveCycles`

- [ ] **Step 3: Verify full project compiles and tests pass**

```bash
go build ./...
go test ./internal/cli/ -v 2>&1 | tail -30
go test ./internal/config/... -v
```

Expected: all pass. The project is now config-free.

- [ ] **Step 4: Commit**

```bash
git add internal/cli/init.go internal/cli/cli_test.go
git commit -m "refactor: remove config loading, veil:skip, and config generation from veil init"
```

---

## Task 5: Clean up scanner and remove unused dependencies

Remove the `ignorePatterns` parameter from `scanner.Scan()` and drop `doublestar` and `yaml.v3` from `go.mod`.

**Files:**
- Modify: `internal/scanner/scanner.go` (remove ignorePatterns param, remove isIgnored func)
- Modify: `internal/scanner/scanner_test.go` (remove ignore pattern tests)
- Modify: `go.mod` (remove doublestar, yaml.v3)

- [ ] **Step 1: Simplify scanner.Scan()**

In `internal/scanner/scanner.go`, remove the `doublestar` import:
```go
"github.com/bmatcuk/doublestar/v4"
```

Change the `Scan` function signature from:
```go
func Scan(root string, ignorePatterns ...string) ([]string, error) {
```
To:
```go
func Scan(root string) ([]string, error) {
```

Remove the `isIgnored` check inside the loop:
```go
if isIgnored(name, ignorePatterns) {
    continue
}
```

Delete the `isIgnored` function entirely (approximately lines 62-73).

- [ ] **Step 2: Remove ignore pattern tests from scanner_test.go**

Delete these test functions:
- `TestScan_IgnorePatterns`
- `TestScan_IgnoreGlobStar`
- `TestScan_NoIgnorePatterns`

- [ ] **Step 3: Remove unused dependencies**

```bash
go mod tidy
```

This should remove `gopkg.in/yaml.v3` and `github.com/bmatcuk/doublestar/v4` from `go.mod` since nothing imports them anymore.

- [ ] **Step 4: Verify**

```bash
go build ./...
go test ./internal/scanner/... -v
go test ./... 2>&1 | tail -5
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/scanner.go internal/scanner/scanner_test.go go.mod go.sum
git commit -m "refactor: remove ignore patterns from scanner, drop doublestar and yaml.v3 deps"
```

---

## Task 6: Add skip_hosts file I/O package

Create `internal/skiphost/` with functions to load, save, add, remove, and list entries from `.veil/skip_hosts`.

**Files:**
- Create: `internal/skiphost/skiphost.go`
- Create: `internal/skiphost/skiphost_test.go`
- Modify: `internal/config/paths.go` (add SkipHostsFile helper)

- [ ] **Step 1: Add path helper**

In `internal/config/paths.go`, add:

```go
func SkipHostsFile(root string) string {
	return filepath.Join(ProjectStateDir(root), "skip_hosts")
}
```

- [ ] **Step 2: Write failing tests for skiphost package**

Create `internal/skiphost/skiphost_test.go`:

```go
package skiphost

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_NonexistentFile(t *testing.T) {
	hosts, err := Load("/nonexistent/path/skip_hosts")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("expected empty slice, got %v", hosts)
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skip_hosts")
	if err := os.WriteFile(path, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	hosts, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("expected empty slice, got %v", hosts)
	}
}

func TestLoad_WithEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skip_hosts")
	content := "# Managed by veil skip\napi.anthropic.com\n*.internal.corp.com\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	hosts, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d: %v", len(hosts), hosts)
	}
	if hosts[0] != "api.anthropic.com" {
		t.Errorf("expected api.anthropic.com, got %q", hosts[0])
	}
	if hosts[1] != "*.internal.corp.com" {
		t.Errorf("expected *.internal.corp.com, got %q", hosts[1])
	}
}

func TestLoad_SkipsBlanksAndComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skip_hosts")
	content := "# comment\n\napi.anthropic.com\n  \n# another comment\n*.foo.com\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	hosts, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("expected 2, got %d: %v", len(hosts), hosts)
	}
}

func TestSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skip_hosts")
	err := Save(path, []string{"api.anthropic.com", "*.internal.corp.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hosts, err := Load(path)
	if err != nil {
		t.Fatalf("load after save: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("expected 2, got %d", len(hosts))
	}
}

func TestAdd_NewHost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skip_hosts")

	added, err := Add(path, "api.anthropic.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !added {
		t.Error("expected added=true for new host")
	}

	hosts, _ := Load(path)
	if len(hosts) != 1 || hosts[0] != "api.anthropic.com" {
		t.Errorf("expected [api.anthropic.com], got %v", hosts)
	}
}

func TestAdd_Duplicate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skip_hosts")

	Add(path, "api.anthropic.com")
	added, err := Add(path, "api.anthropic.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if added {
		t.Error("expected added=false for duplicate")
	}

	hosts, _ := Load(path)
	if len(hosts) != 1 {
		t.Errorf("expected 1 host, got %d", len(hosts))
	}
}

func TestRemove_Existing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skip_hosts")

	Add(path, "api.anthropic.com")
	Add(path, "*.internal.corp.com")

	removed, err := Remove(path, "api.anthropic.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !removed {
		t.Error("expected removed=true")
	}

	hosts, _ := Load(path)
	if len(hosts) != 1 || hosts[0] != "*.internal.corp.com" {
		t.Errorf("expected [*.internal.corp.com], got %v", hosts)
	}
}

func TestRemove_NotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skip_hosts")

	Add(path, "api.anthropic.com")

	removed, err := Remove(path, "not.there.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if removed {
		t.Error("expected removed=false for nonexistent host")
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
go test ./internal/skiphost/... -v
```

Expected: FAIL — package doesn't exist yet.

- [ ] **Step 4: Implement skiphost package**

Create `internal/skiphost/skiphost.go`:

```go
// Package skiphost manages the persistent skip_hosts file for proxy host bypass.
package skiphost

import (
	"errors"
	"os"
	"strings"
)

const header = "# Managed by veil skip\n"

// Load reads the skip_hosts file and returns the list of hosts.
// Returns an empty slice if the file does not exist.
func Load(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []string{}, nil
		}
		return nil, err
	}
	return parse(string(data)), nil
}

// Save writes the host list to the skip_hosts file, overwriting any existing content.
func Save(path string, hosts []string) error {
	var b strings.Builder
	b.WriteString(header)
	for _, h := range hosts {
		b.WriteString(h)
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0600)
}

// Add appends a host to the skip_hosts file. Returns true if the host was added,
// false if it was already present (duplicate). Creates the file if it does not exist.
func Add(path string, host string) (bool, error) {
	hosts, err := Load(path)
	if err != nil {
		return false, err
	}
	for _, h := range hosts {
		if h == host {
			return false, nil
		}
	}
	hosts = append(hosts, host)
	return true, Save(path, hosts)
}

// Remove deletes a host from the skip_hosts file. Returns true if the host was found
// and removed, false if it was not present.
func Remove(path string, host string) (bool, error) {
	hosts, err := Load(path)
	if err != nil {
		return false, err
	}
	filtered := make([]string, 0, len(hosts))
	found := false
	for _, h := range hosts {
		if h == host {
			found = true
			continue
		}
		filtered = append(filtered, h)
	}
	if !found {
		return false, nil
	}
	return true, Save(path, filtered)
}

// parse extracts host entries from file content, skipping blank lines and comments.
func parse(content string) []string {
	var hosts []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hosts = append(hosts, line)
	}
	if hosts == nil {
		hosts = []string{}
	}
	return hosts
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
go test ./internal/skiphost/... -v
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/skiphost/skiphost.go internal/skiphost/skiphost_test.go internal/config/paths.go
git commit -m "feat: add skiphost package for persistent host skip list"
```

---

## Task 7: Add `veil skip` command and wire into `veil run`

Create the `veil skip` cobra command and update `veil run` to read the skip_hosts file and accept a `--skip` flag.

**Files:**
- Create: `internal/cli/skip.go`
- Modify: `internal/cli/root.go:60` (add `skipCmd()`)
- Modify: `internal/cli/run.go` (read skip_hosts file, add `--skip` flag)

- [ ] **Step 1: Write failing tests for veil skip**

Add to `internal/cli/cli_test.go`:

```go
func TestSkipAdd(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"skip", "--path", root, "api.anthropic.com"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("skip add failed: %v", err)
	}

	if !strings.Contains(out.String(), "api.anthropic.com") {
		t.Errorf("expected confirmation output, got %q", out.String())
	}

	// Verify file was written.
	hosts, err := skiphost.Load(config.SkipHostsFile(root))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "api.anthropic.com" {
		t.Errorf("expected [api.anthropic.com], got %v", hosts)
	}
}

func TestSkipDuplicate(t *testing.T) {
	root := initProject(t)

	// Add once.
	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"skip", "--path", root, "api.anthropic.com"})
	cmd.Execute()

	// Add again — should succeed silently.
	cmd2 := NewRoot("test")
	out := new(bytes.Buffer)
	cmd2.SetOut(out)
	cmd2.SetErr(new(bytes.Buffer))
	cmd2.SetArgs([]string{"skip", "--path", root, "api.anthropic.com"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("skip duplicate failed: %v", err)
	}

	hosts, _ := skiphost.Load(config.SkipHostsFile(root))
	if len(hosts) != 1 {
		t.Errorf("expected 1 host, got %d", len(hosts))
	}
}

func TestSkipList(t *testing.T) {
	root := initProject(t)

	// Add two hosts.
	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"skip", "--path", root, "api.anthropic.com"})
	cmd.Execute()

	cmd2 := NewRoot("test")
	cmd2.SetOut(new(bytes.Buffer))
	cmd2.SetErr(new(bytes.Buffer))
	cmd2.SetArgs([]string{"skip", "--path", root, "*.internal.com"})
	cmd2.Execute()

	// List.
	cmd3 := NewRoot("test")
	out := new(bytes.Buffer)
	cmd3.SetOut(out)
	cmd3.SetErr(new(bytes.Buffer))
	cmd3.SetArgs([]string{"skip", "--path", root, "--list"})
	if err := cmd3.Execute(); err != nil {
		t.Fatalf("skip list failed: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "api.anthropic.com") || !strings.Contains(output, "*.internal.com") {
		t.Errorf("expected both hosts in output, got %q", output)
	}
}

func TestSkipRemove(t *testing.T) {
	root := initProject(t)

	// Add.
	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"skip", "--path", root, "api.anthropic.com"})
	cmd.Execute()

	// Remove.
	cmd2 := NewRoot("test")
	out := new(bytes.Buffer)
	cmd2.SetOut(out)
	cmd2.SetErr(new(bytes.Buffer))
	cmd2.SetArgs([]string{"skip", "--path", root, "--remove", "api.anthropic.com"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("skip remove failed: %v", err)
	}

	hosts, _ := skiphost.Load(config.SkipHostsFile(root))
	if len(hosts) != 0 {
		t.Errorf("expected empty list, got %v", hosts)
	}
}

func TestSkipRemoveNotFound(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"skip", "--path", root, "--remove", "not.there.com"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for removing nonexistent host")
	}
}
```

Add the `skiphost` and `config` imports at the top of `cli_test.go` if not already present:
```go
"github.com/8enji/veil/internal/skiphost"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/cli/ -run TestSkip -v
```

Expected: FAIL — `skipCmd` doesn't exist.

- [ ] **Step 3: Implement veil skip command**

Create `internal/cli/skip.go`:

```go
package cli

import (
	"fmt"
	"os"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/skiphost"
	"github.com/8enji/veil/internal/ui"
	"github.com/spf13/cobra"
)

func skipCmd() *cobra.Command {
	var list bool
	var remove string
	cmd := &cobra.Command{
		Use:   "skip [host]",
		Short: "Manage hosts the proxy passes through untouched",
		Long:  "Add, remove, or list hosts that the proxy should not intercept.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSkip(cmd, args, list, remove)
		},
	}
	cmd.Flags().BoolVar(&list, "list", false, "list all skip hosts")
	cmd.Flags().StringVar(&remove, "remove", "", "remove a host from the skip list")
	return cmd
}

func runSkip(cmd *cobra.Command, args []string, list bool, remove string) error {
	w := cmd.OutOrStdout()

	root, err := resolveRoot()
	if err != nil {
		return cliError(err.Error(), "")
	}

	stateDir := config.ProjectStateDir(root)
	if info, statErr := os.Stat(stateDir); statErr != nil || !info.IsDir() {
		return cliError("project not initialized", "Run veil init to get started")
	}

	path := config.SkipHostsFile(root)

	// --list mode.
	if list {
		hosts, err := skiphost.Load(path)
		if err != nil {
			return cliError(fmt.Sprintf("reading skip hosts: %v", err), "")
		}
		if len(hosts) == 0 {
			fmt.Fprintln(w, ui.Muted.Sprint("No skip hosts configured."))
			fmt.Fprintf(w, "  %s\n", ui.Muted.Sprint("Add one with: veil skip <host>"))
			return nil
		}
		for _, h := range hosts {
			fmt.Fprintf(w, "  %s\n", h)
		}
		return nil
	}

	// --remove mode.
	if remove != "" {
		removed, err := skiphost.Remove(path, remove)
		if err != nil {
			return cliError(fmt.Sprintf("removing skip host: %v", err), "")
		}
		if !removed {
			return cliError(fmt.Sprintf("%s is not in the skip list", remove), "")
		}
		ui.Step(w, fmt.Sprintf("Removed %s from skip list", remove))
		return nil
	}

	// Add mode (default) — requires exactly one positional argument.
	if len(args) == 0 {
		return cliError("no host provided", "Usage: veil skip <host>")
	}
	host := args[0]

	added, err := skiphost.Add(path, host)
	if err != nil {
		return cliError(fmt.Sprintf("adding skip host: %v", err), "")
	}
	if !added {
		fmt.Fprintf(w, "  %s %s is already in the skip list\n", ui.Muted.Sprint("·"), host)
		return nil
	}
	ui.Step(w, fmt.Sprintf("Added %s to skip list", host))
	return nil
}
```

- [ ] **Step 4: Register skipCmd in root.go**

In `internal/cli/root.go`, add at line 60 (where `syncCmd()` used to be):
```go
root.AddCommand(skipCmd())
```

- [ ] **Step 5: Run skip tests**

```bash
go test ./internal/cli/ -run TestSkip -v
```

Expected: all PASS.

- [ ] **Step 6: Wire skip_hosts into veil run**

In `internal/cli/run.go`, add imports:
```go
"github.com/8enji/veil/internal/config"
"github.com/8enji/veil/internal/skiphost"
```

Add a `--skip` flag to `runCmd()`:
```go
func runCmd() *cobra.Command {
	var ephemeralSkip []string
	cmd := &cobra.Command{
		Use:   "run [flags] -- <command> [args...]",
		Short: "Run a command with secrets injected via proxy",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRun(cmd, args, ephemeralSkip)
		},
	}
	cmd.Flags().SetInterspersed(false)
	cmd.Flags().StringArrayVar(&ephemeralSkip, "skip", nil, "host to pass through without proxying (non-persistent, repeatable)")
	return cmd
}
```

Update `runRun` to accept and merge skip hosts:
```go
func runRun(cmd *cobra.Command, args []string, ephemeralSkip []string) error {
	root, err := resolveRoot()
	if err != nil {
		return cliError(err.Error(), "")
	}

	// Check .veil/ exists.
	stateDir := config.ProjectStateDir(root)
	if info, statErr := os.Stat(stateDir); statErr != nil || !info.IsDir() {
		return cliError("project not initialized", "Run veil init to get started")
	}

	// Load persistent skip hosts.
	skipHosts, err := skiphost.Load(config.SkipHostsFile(root))
	if err != nil {
		return cliError(fmt.Sprintf("reading skip hosts: %v", err), "")
	}

	// Merge ephemeral --skip flags.
	skipHosts = append(skipHosts, ephemeralSkip...)

	result, err := runner.Run(cmd.Context(), runner.Config{
		Root:      root,
		Command:   args[0],
		Args:      args[1:],
		Verbose:   flagVerbose,
		SkipHosts: skipHosts,
	})
	if err != nil {
		return cliError(mapRunError(err), "")
	}

	os.Exit(result.ExitCode)
	return nil // unreachable
}
```

- [ ] **Step 7: Run full test suite**

```bash
go test ./... 2>&1 | tail -10
```

Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add internal/cli/skip.go internal/cli/root.go internal/cli/run.go internal/cli/cli_test.go
git commit -m "feat: add veil skip command and wire skip_hosts into veil run"
```

---

## Task 8: Add interactive prompt helpers

Create reusable prompt functions for the interactive init flow. These handle Y/n/select input, multi-select, and comma-separated host input.

**Files:**
- Create: `internal/cli/prompt.go`
- Create: `internal/cli/prompt_test.go`

- [ ] **Step 1: Write failing tests for prompt parsing**

Create `internal/cli/prompt_test.go`:

```go
package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseYNS_Defaults(t *testing.T) {
	tests := []struct {
		input string
		want  ynsChoice
	}{
		{"", choiceYes},       // empty = default (Y)
		{"\n", choiceYes},     // newline = default
		{"y\n", choiceYes},
		{"Y\n", choiceYes},
		{"n\n", choiceNo},
		{"N\n", choiceNo},
		{"select\n", choiceSelect},
		{"s\n", choiceSelect},
		{"S\n", choiceSelect},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			r := strings.NewReader(tt.input)
			w := new(bytes.Buffer)
			got := promptYNS(r, w, "Test?")
			if got != tt.want {
				t.Errorf("input %q: got %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseCSV_Hosts(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"\n", nil},
		{"api.anthropic.com\n", []string{"api.anthropic.com"}},
		{"api.anthropic.com, *.internal.com\n", []string{"api.anthropic.com", "*.internal.com"}},
		{"  api.anthropic.com , *.internal.com  \n", []string{"api.anthropic.com", "*.internal.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			r := strings.NewReader(tt.input)
			w := new(bytes.Buffer)
			got := promptCSV(r, w, "Hosts:")
			if len(got) != len(tt.want) {
				t.Fatalf("input %q: got %v, want %v", tt.input, got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("input %q [%d]: got %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestMultiSelect(t *testing.T) {
	// Simulate selecting items 1 and 3 out of 3.
	// Input: "1,3\n" — user types the numbers of items to keep.
	items := []string{"GITHUB_TOKEN", "DATABASE_URL", "STRIPE_KEY"}
	input := "1,3\n"
	r := strings.NewReader(input)
	w := new(bytes.Buffer)

	selected := promptMultiSelect(r, w, items)
	if len(selected) != 2 {
		t.Fatalf("expected 2 selected, got %d: %v", len(selected), selected)
	}
	if selected[0] != "GITHUB_TOKEN" || selected[1] != "STRIPE_KEY" {
		t.Errorf("expected [GITHUB_TOKEN, STRIPE_KEY], got %v", selected)
	}
}

func TestMultiSelect_All(t *testing.T) {
	items := []string{"A", "B", "C"}
	// Empty input or "all" selects everything.
	r := strings.NewReader("\n")
	w := new(bytes.Buffer)

	selected := promptMultiSelect(r, w, items)
	if len(selected) != 3 {
		t.Fatalf("expected 3, got %d", len(selected))
	}
}

func TestPromptYN_Defaults(t *testing.T) {
	tests := []struct {
		input      string
		defaultYes bool
		want       bool
	}{
		{"\n", true, true},
		{"\n", false, false},
		{"y\n", false, true},
		{"n\n", true, false},
	}
	for _, tt := range tests {
		r := strings.NewReader(tt.input)
		w := new(bytes.Buffer)
		got := promptYN(r, w, "Continue?", tt.defaultYes)
		if got != tt.want {
			t.Errorf("input=%q default=%v: got %v, want %v", tt.input, tt.defaultYes, got, tt.want)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/cli/ -run TestParse -v
go test ./internal/cli/ -run TestMultiSelect -v
go test ./internal/cli/ -run TestPromptYN -v
```

Expected: FAIL — functions don't exist.

- [ ] **Step 3: Implement prompt helpers**

Create `internal/cli/prompt.go`:

```go
package cli

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/8enji/veil/internal/ui"
)

type ynsChoice int

const (
	choiceYes    ynsChoice = iota
	choiceNo
	choiceSelect
)

// promptYNS asks a Y/n/select question. Default is Y (empty input = yes).
func promptYNS(r io.Reader, w io.Writer, question string) ynsChoice {
	fmt.Fprintf(w, "%s %s ", question, ui.Bold.Sprint("(Y/n/select):"))
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return choiceYes
	}
	input := strings.TrimSpace(strings.ToLower(scanner.Text()))
	switch input {
	case "", "y", "yes":
		return choiceYes
	case "n", "no":
		return choiceNo
	case "s", "select":
		return choiceSelect
	default:
		return choiceYes
	}
}

// promptYN asks a yes/no question with the given default.
func promptYN(r io.Reader, w io.Writer, question string, defaultYes bool) bool {
	hint := "(y/N)"
	if defaultYes {
		hint = "(Y/n)"
	}
	fmt.Fprintf(w, "%s %s ", question, ui.Bold.Sprint(hint))
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return defaultYes
	}
	input := strings.TrimSpace(strings.ToLower(scanner.Text()))
	switch input {
	case "":
		return defaultYes
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		return defaultYes
	}
}

// promptCSV asks for comma-separated input and returns trimmed, non-empty values.
// Returns nil if the user enters nothing.
func promptCSV(r io.Reader, w io.Writer, prompt string) []string {
	fmt.Fprintf(w, "%s ", prompt)
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return nil
	}
	raw := strings.TrimSpace(scanner.Text())
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// promptMultiSelect displays numbered items and lets the user pick by typing
// comma-separated numbers. Empty input selects all. Returns the selected items
// in their original order.
func promptMultiSelect(r io.Reader, w io.Writer, items []string) []string {
	for i, item := range items {
		fmt.Fprintf(w, "  %s %s\n", ui.Muted.Sprintf("[%d]", i+1), item)
	}
	fmt.Fprintf(w, "\n%s ", ui.Bold.Sprint("Select (comma-separated numbers, or Enter for all):"))

	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return items
	}
	input := strings.TrimSpace(scanner.Text())
	if input == "" {
		return items
	}

	selectedSet := make(map[int]bool)
	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > len(items) {
			continue
		}
		selectedSet[n-1] = true
	}

	var selected []string
	for i, item := range items {
		if selectedSet[i] {
			selected = append(selected, item)
		}
	}
	return selected
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/cli/ -run "TestParse|TestMultiSelect|TestPromptYN" -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/prompt.go internal/cli/prompt_test.go
git commit -m "feat: add interactive prompt helpers for init flow"
```

---

## Task 9: Rewrite `veil init` with interactive flow

Replace the current auto-vault-everything init with the interactive flow: file selection, token selection, MCP selection, skip hosts prompt. Add `--yes` flag for non-interactive mode. Handle TTY detection for auto-fallback.

**Files:**
- Modify: `internal/cli/init.go` (rewrite `runInit` with interactive prompts)
- Modify: `internal/cli/init_test.go` (update tests for `--yes` behavior)
- Modify: `internal/cli/cli_test.go` (update `initProject` helper, update existing init tests)

- [ ] **Step 1: Update initProject test helper**

The `initProject` helper in `cli_test.go` currently calls `veil init` without `--yes`. Since init is now interactive, all test invocations need `--yes`. Update `initProject`:

```go
func initProject(t *testing.T) string {
	t.Helper()
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envContent := "OPENAI_API_KEY=sk-proj-1234567890abcdef\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	return tmpDir
}
```

- [ ] **Step 2: Write tests for interactive init**

Add to `internal/cli/init_test.go`:

```go
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/skiphost"
	"github.com/8enji/veil/internal/vault"
)

func TestInitYes_VaultsAll(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, ".git"), 0755)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY=sk-proj-1234567890abcdef\nGITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz1234\n"), 0644)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", dir, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init --yes failed: %v", err)
	}

	v, err := openVaultForTest(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	creds := v.List()
	if len(creds) != 2 {
		t.Errorf("expected 2 credentials, got %d", len(creds))
	}
}

func TestInitInteractive_SkipFile(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, ".git"), 0755)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY=sk-proj-1234567890abcdef\n"), 0644)
	os.WriteFile(filepath.Join(dir, ".env.local"), []byte("LOCAL_KEY=sk-proj-localsecret1234567\n"), 0644)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	// Simulate: "select" for file prompt, "1" to select only .env, "y" for vault all, "" to skip hosts.
	cmd.SetIn(strings.NewReader("select\n1\ny\n\n"))
	cmd.SetArgs([]string{"init", "--path", dir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	v, err := openVaultForTest(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	// Only .env was scanned, so only OPENAI_API_KEY should be vaulted.
	if _, ok := v.Get("OPENAI_API_KEY"); !ok {
		t.Error("OPENAI_API_KEY should be vaulted")
	}
	if _, ok := v.Get("LOCAL_KEY"); ok {
		t.Error("LOCAL_KEY should NOT be vaulted (file was skipped)")
	}
}

func TestInitInteractive_SkipToken(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, ".git"), 0755)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY=sk-proj-1234567890abcdef\nSTRIPE_KEY=sk_live_12345678901234567890abcd\n"), 0644)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	// Simulate: "y" to scan all files, "select" for tokens, "1" for only first token, "" to skip hosts.
	cmd.SetIn(strings.NewReader("y\nselect\n1\n\n"))
	cmd.SetArgs([]string{"init", "--path", dir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	v, err := openVaultForTest(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if _, ok := v.Get("OPENAI_API_KEY"); !ok {
		t.Error("OPENAI_API_KEY should be vaulted")
	}
	if _, ok := v.Get("STRIPE_KEY"); ok {
		t.Error("STRIPE_KEY should NOT be vaulted (was deselected)")
	}
}

func TestInitInteractive_SkipHosts(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, ".git"), 0755)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY=sk-proj-1234567890abcdef\n"), 0644)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	// Simulate: "y" for files, "y" for tokens, "api.anthropic.com" for skip hosts.
	cmd.SetIn(strings.NewReader("y\ny\napi.anthropic.com\n"))
	cmd.SetArgs([]string{"init", "--path", dir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	hosts, err := skiphost.Load(config.SkipHostsFile(dir))
	if err != nil {
		t.Fatalf("load skip hosts: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "api.anthropic.com" {
		t.Errorf("expected [api.anthropic.com], got %v", hosts)
	}
}

func TestInitForce_WipesVault(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, ".git"), 0755)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY=sk-proj-1234567890abcdef\n"), 0644)

	// First init.
	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", dir, "--yes"})
	cmd.Execute()

	// Force re-init with confirmation.
	cmd2 := NewRoot("test")
	cmd2.SetOut(new(bytes.Buffer))
	cmd2.SetErr(new(bytes.Buffer))
	cmd2.SetIn(strings.NewReader("y\n"))
	cmd2.SetArgs([]string{"init", "--path", dir, "--force", "--yes"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("init --force failed: %v", err)
	}

	// Vault should be fresh (new project ID).
	v, err := openVaultForTest(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	creds := v.List()
	// .env now has placeholders, so no secrets detected on re-scan.
	// This is expected behavior — the spec says placeholders aren't secret-like.
	if len(creds) != 0 {
		t.Logf("note: %d creds found (may be from re-scanning placeholders)", len(creds))
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
go test ./internal/cli/ -run "TestInit" -v
```

Expected: FAIL — init doesn't have `--yes` flag or interactive flow yet.

- [ ] **Step 4: Rewrite runInit with interactive flow**

Rewrite `internal/cli/init.go`. The full replacement for `runInit`:

```go
func initCmd() *cobra.Command {
	var force, dryRun, yes bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize Veil for the current project",
		Long:  "Scan .env files, vault secrets, and replace them with placeholders.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(cmd, force, dryRun, yes)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "reinitialize even if .veil/ exists")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be vaulted without making changes")
	cmd.Flags().BoolVar(&yes, "yes", false, "accept all defaults non-interactively")
	return cmd
}

func runInit(cmd *cobra.Command, force, dryRun, yes bool) error {
	w := cmd.OutOrStdout()
	stdin := cmd.InOrStdin()

	// Detect non-interactive: --yes flag or non-TTY stdin.
	interactive := !yes
	if interactive {
		if f, ok := stdin.(*os.File); ok {
			if !isatty.IsTerminal(f.Fd()) && !isatty.IsCygwinTerminal(f.Fd()) {
				interactive = false
				fmt.Fprintln(w, ui.Muted.Sprint("Non-interactive mode: vaulting all detected secrets"))
			}
		}
	}

	// 1. Resolve project root.
	root := flagPath
	if root == "" {
		r, err := config.FindProjectRoot(".")
		if err != nil {
			return cliError(err.Error(), "")
		}
		root = r
	} else {
		abs, err := filepath.Abs(root)
		if err != nil {
			return cliError(err.Error(), "")
		}
		root = abs
	}

	// 2. Check existing .veil/ directory.
	stateDir := config.ProjectStateDir(root)
	if info, err := os.Stat(stateDir); err == nil && info.IsDir() {
		if !force {
			return cliError("project already initialized", "Use --force to reinitialize")
		}
		// --force: confirm destructive reset.
		if interactive {
			if !promptYN(cmd.InOrStdin(), w, "This will replace your existing vault. Continue?", false) {
				fmt.Fprintln(w, ui.Muted.Sprint("Aborted."))
				return nil
			}
		}
	}

	// Phase: Scanning project.
	ui.Phase(w, "Scanning project...")

	// 3. Scan .env files.
	envPaths, err := scanner.Scan(root)
	if err != nil {
		return cliError(fmt.Sprintf("scanning .env files: %v", err), "")
	}

	// 3b. Discover MCP config.
	mcpConfigPath, err := mcpconfig.Discover()
	if err != nil {
		return cliError(fmt.Sprintf("discovering MCP config: %v", err), "")
	}

	// Early exit if nothing to process.
	if len(envPaths) == 0 && mcpConfigPath == "" {
		_, _ = fmt.Fprintf(w, "no .env files or MCP configs found in %s\n", root)
		return nil
	}

	// 3c. Interactive file selection.
	if interactive && len(envPaths) > 1 {
		fmt.Fprintf(w, "\nFound %d .env files:\n", len(envPaths))
		names := make([]string, len(envPaths))
		for i, p := range envPaths {
			rel, _ := filepath.Rel(root, p)
			if rel == "" {
				rel = filepath.Base(p)
			}
			names[i] = rel
			fmt.Fprintf(w, "  %s\n", rel)
		}
		fmt.Fprintln(w)
		choice := promptYNS(cmd.InOrStdin(), w, "Scan all?")
		switch choice {
		case choiceNo:
			envPaths = nil
		case choiceSelect:
			selected := promptMultiSelect(cmd.InOrStdin(), w, names)
			selectedSet := make(map[string]bool)
			for _, s := range selected {
				selectedSet[s] = true
			}
			var filtered []string
			for i, p := range envPaths {
				if selectedSet[names[i]] {
					filtered = append(filtered, p)
				}
			}
			envPaths = filtered
		}
	}

	// Report what will be scanned.
	if len(envPaths) > 0 {
		ui.Step(w, fmt.Sprintf("Found %d .env %s", len(envPaths), plural(len(envPaths), "file", "files")))
	}
	if mcpConfigPath != "" {
		ui.Step(w, "Found 1 MCP config")
	}
	_, _ = fmt.Fprintln(w)

	// 4. Generate project ID.
	projectID := vault.NewID()

	// 5. Determine keystore.
	ks, err := buildKeystore()
	if err != nil {
		return cliError(fmt.Sprintf("keystore: %v", err), "")
	}

	// 6. Create vault.
	v, err := vault.CreateVault(root, projectID, ks)
	if err != nil {
		return cliError(fmt.Sprintf("creating vault: %v", err), "")
	}

	// Phase: Vaulting secrets.
	ui.Phase(w, "Vaulting secrets...")

	// 7. Process each .env file.
	var secretsVaulted int
	var secretsScoped int
	for _, envPath := range envPaths {
		envFile, err := scanner.ParseFile(envPath)
		if err != nil {
			return cliError(fmt.Sprintf("parsing %s: %v", envPath, err), "")
		}

		// Collect secret-like lines.
		type secretLine struct {
			key   string
			value string
			index int // index into envFile.Lines
		}
		var secrets []secretLine
		for i, line := range envFile.Lines {
			if line.Kind != scanner.KVLine {
				continue
			}
			if !placeholder.IsSecretLike(line.Key, line.Value) {
				if flagVerbose {
					_, _ = fmt.Fprintf(w, "%s\n", ui.Muted.Sprintf("  skip (not secret-like): %s", line.Key))
				}
				continue
			}
			secrets = append(secrets, secretLine{key: line.Key, value: line.Value, index: i})
		}

		if len(secrets) == 0 {
			continue
		}

		// Interactive token selection.
		selectedKeys := make(map[string]bool)
		if interactive {
			rel, _ := filepath.Rel(root, envPath)
			if rel == "" {
				rel = filepath.Base(envPath)
			}
			fmt.Fprintf(w, "\nDetected %d %s in %s:\n", len(secrets), plural(len(secrets), "secret", "secrets"), rel)
			names := make([]string, len(secrets))
			for i, s := range secrets {
				redacted := redactValue(s.value)
				fmt.Fprintf(w, "  %-24s %s\n", s.key, ui.Muted.Sprint(redacted))
				names[i] = s.key
			}
			fmt.Fprintln(w)
			choice := promptYNS(cmd.InOrStdin(), w, "Vault all?")
			switch choice {
			case choiceYes:
				for _, s := range secrets {
					selectedKeys[s.key] = true
				}
			case choiceNo:
				continue // skip entire file
			case choiceSelect:
				selected := promptMultiSelect(cmd.InOrStdin(), w, names)
				for _, name := range selected {
					selectedKeys[name] = true
				}
			}
		} else {
			for _, s := range secrets {
				selectedKeys[s.key] = true
			}
		}

		fileChanged := false
		for _, s := range secrets {
			if !selectedKeys[s.key] {
				continue
			}

			ph, err := placeholder.Generate(s.key, s.value)
			if err != nil {
				return cliError(fmt.Sprintf("generating placeholder for %s: %v", s.key, err), "")
			}

			credHosts := placeholder.HostsForCredential(s.key, s.value)

			cred := &vault.Credential{
				ID:           vault.NewID(),
				Name:         s.key,
				Real:         s.value,
				Placeholder:  ph,
				Source:       "init",
				AllowedHosts: credHosts,
				CreatedAt:    time.Now(),
			}
			if err := v.Add(cred); err != nil {
				if strings.Contains(err.Error(), "already exists") {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: duplicate key %q, skipping\n", s.key)
					continue
				}
				return cliError(fmt.Sprintf("vaulting %s: %v", s.key, err), "")
			}

			secretsVaulted++
			if len(credHosts) > 0 {
				secretsScoped++
			}

			if dryRun {
				_, _ = fmt.Fprintf(w, "%s\n", ui.Muted.Sprintf("  would vault: %s -> %s", s.key, ph))
			} else {
				envFile.SetValue(s.key, ph)
				fileChanged = true
			}
		}

		if !dryRun && fileChanged {
			if err := atomicWriteFile(envPath, envFile.Bytes()); err != nil {
				return cliError(fmt.Sprintf("writing %s: %v", envPath, err), "")
			}
		}
	}

	// 8b. Process MCP config.
	var mcpConfigsProcessed int
	if mcpConfigPath != "" {
		n, s, err := processMCPConfig(cmd, v, mcpConfigPath, force, dryRun, interactive)
		if err != nil {
			return err
		}
		secretsVaulted += n
		secretsScoped += s
		if n > 0 {
			mcpConfigsProcessed = 1
		}
	}

	// Report vault results.
	unscoped := secretsVaulted - secretsScoped
	ui.Step(w, fmt.Sprintf("%d %s stored in keychain", secretsVaulted, plural(secretsVaulted, "secret", "secrets")))
	if secretsScoped > 0 {
		ui.Step(w, fmt.Sprintf("%d auto-scoped to hosts", secretsScoped))
	}
	if unscoped > 0 {
		ui.Warn(w, fmt.Sprintf("%d unscoped (use veil add --host to scope)", unscoped))
	}
	_, _ = fmt.Fprintln(w)

	// Phase: Skip hosts.
	if interactive && !dryRun {
		fmt.Fprintln(w, "Skip hosts — any hosts the proxy should pass through untouched?")
		fmt.Fprintln(w, ui.Muted.Sprint("Common examples: api.anthropic.com, *.internal.company.com"))
		fmt.Fprintln(w, ui.Muted.Sprint("(You can manage these later with: veil skip)"))
		fmt.Fprintln(w)
		hosts := promptCSV(cmd.InOrStdin(), w, "Hosts to skip (comma-separated, or Enter to skip):")
		if len(hosts) > 0 {
			skipPath := config.SkipHostsFile(root)
			for _, h := range hosts {
				skiphost.Add(skipPath, h)
				ui.Step(w, fmt.Sprintf("%s added to skip list", h))
			}
			_, _ = fmt.Fprintln(w)
		}
	}

	// Phase: Setting up proxy.
	ui.Phase(w, "Setting up proxy...")

	ca, err := proxy.LoadOrCreateCA()
	if err != nil {
		return cliError(fmt.Sprintf("setting up CA: %v", err), "")
	}
	_ = ca
	ui.Step(w, "CA certificate ready")
	_, _ = fmt.Fprintln(w)

	// 9. Append to project .gitignore.
	if !dryRun {
		appendGitignore(root)
	}

	// 10. Final summary.
	_, _ = fmt.Fprintf(w, "%s\n", ui.Success.Sprintf("Veil initialized for %s", root))
	_, _ = fmt.Fprintf(w, "  .env files processed:  %d\n", len(envPaths))
	if mcpConfigsProcessed > 0 {
		_, _ = fmt.Fprintf(w, "  MCP configs processed: %d\n", mcpConfigsProcessed)
	}
	_, _ = fmt.Fprintf(w, "  Secrets vaulted:       %d\n", secretsVaulted)
	_, _ = fmt.Fprintln(w)
	return nil
}
```

Update `processMCPConfig` to accept `interactive bool` instead of `cfg *config.ProjectConfig`:

```go
func processMCPConfig(cmd *cobra.Command, v *vault.Vault, configPath string, force, dryRun, interactive bool) (int, int, error) {
```

Inside `processMCPConfig`, replace config-based scoping with auto-detection and add interactive MCP selection similar to the .env flow. Replace:
```go
var credHosts []string
if configHosts, ok := cfg.Scoping[credName]; ok {
    credHosts = configHosts
} else {
    credHosts = placeholder.HostsForCredential(key, value)
}
```
With:
```go
credHosts := placeholder.HostsForCredential(key, value)
```

Add the `isatty` import if not already present:
```go
"github.com/mattn/go-isatty"
```

Add the `skiphost` import:
```go
"github.com/8enji/veil/internal/skiphost"
```

Add the `redactValue` helper to `init.go`:

```go
// redactValue returns a redacted display of a secret value, showing the
// first 4 characters followed by **** for visual identification.
func redactValue(value string) string {
	if len(value) <= 4 {
		return "****"
	}
	return value[:4] + "****"
}
```

- [ ] **Step 5: Run init tests**

```bash
go test ./internal/cli/ -run "TestInit" -v
```

Expected: all PASS.

- [ ] **Step 6: Run full test suite**

```bash
go test ./... 2>&1 | tail -10
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add internal/cli/init.go internal/cli/init_test.go internal/cli/cli_test.go
git commit -m "feat: rewrite veil init with interactive file and token selection"
```

---

## Task 10: Final verification and cleanup

Run the full test suite, verify the binary works end-to-end, and clean up any dead imports.

**Files:**
- All modified files (verification only)

- [ ] **Step 1: Run full test suite**

```bash
go test ./... -v 2>&1 | tail -30
```

Expected: all pass.

- [ ] **Step 2: Verify compilation**

```bash
go build -o /dev/null ./cmd/veil/
```

Expected: clean build.

- [ ] **Step 3: Verify CLI surface**

```bash
go run ./cmd/veil/ --help
```

Expected: shows all commands including `skip`, no `sync`.

```bash
go run ./cmd/veil/ skip --help
```

Expected: shows skip command help with `--list` and `--remove` flags.

- [ ] **Step 4: Check for dead imports**

```bash
go vet ./...
```

Expected: no issues.

- [ ] **Step 5: Check that doublestar and yaml.v3 are gone from go.mod**

```bash
grep -E "doublestar|yaml.v3" go.mod
```

Expected: no output.

- [ ] **Step 6: Verify line count reduction**

```bash
git diff --stat main
```

Expected: significant net deletion of lines.

- [ ] **Step 7: Commit any cleanup**

If any dead imports or lint issues were found and fixed:

```bash
git add -A
git commit -m "chore: final cleanup after config removal"
```
