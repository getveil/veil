# Uninstall & `.env` Backup Symmetry — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the backup asymmetry in `veil init` (MCP configs get `.veil-backup`; `.env` files do not) and ship a first-party `veil uninstall` subcommand that reliably reverses an init.

**Architecture:** Extract two shared helpers (`backupExists`, `writeBackup`) and refactor the MCP init path to use them before adding the symmetric call for `.env`. Then build `veil uninstall` as a sequence of small, testable primitives: proxy guard → backup discovery → classification → diff rendering → execution → state purge. Tests drive each primitive.

**Tech Stack:** Go 1.22+, `cobra`, `modernc.org/sqlite` (inherited from existing codebase), no new third-party deps.

**Spec reference:** `docs/superpowers/specs/2026-04-22-uninstall-and-backups-design.md`.

---

## File Structure

### New files

- `internal/cli/backup.go` — shared backup helpers (`backupExists`, `writeBackup`, `backupSuffix` constant). New file keeps `init.go` from growing further; the helpers are reused by init and uninstall.
- `internal/cli/backup_test.go` — unit tests for the helpers.
- `internal/cli/uninstall.go` — `uninstall` subcommand and its primitives (discovery, classification, diff, proxy guard, execution).
- `internal/cli/uninstall_test.go` — unit + integration tests for uninstall.
- `internal/vault/meta.go` — one-line helper `ReadProjectID(root string) (string, error)` that reads `vault.meta` without opening the vault. Separated from `vault.go` because it's a pre-open lookup distinct from the main vault lifecycle.
- `internal/vault/meta_test.go` — unit test for `ReadProjectID`.

### Modified files

- `internal/cli/init.go` — `processMCPConfig` refactored to use the new helpers (no behavioural change); `appendGitignore` extended to also append `*.veil-backup`.
- `internal/cli/init_phases.go` — `processEnvFile` signature grows a `force bool` parameter; calls the new helpers symmetrically with MCP.
- `internal/cli/root.go` — register `uninstallCmd()`.
- `internal/cli/init_test.go` — no behavioural assertions change; may need minor edits if variable names shift during the refactor.

---

## Phase 1 — Shared backup helpers + MCP refactor

Goal: introduce `backupExists` and `writeBackup`, migrate the MCP path to them. No new behaviour yet. Existing MCP tests act as regression guards.

### Task 1.1: Add `backupExists` helper

**Files:**
- Create: `internal/cli/backup.go`
- Test: `internal/cli/backup_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/cli/backup_test.go`:

```go
package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBackupExistsWhenBackupPresent(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "foo.env")
	if err := os.WriteFile(src, []byte("KEY=value"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src+".veil-backup", []byte("KEY=original"), 0600); err != nil {
		t.Fatal(err)
	}
	if !backupExists(src) {
		t.Error("expected backupExists to return true")
	}
}

func TestBackupExistsWhenBackupMissing(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "foo.env")
	if err := os.WriteFile(src, []byte("KEY=value"), 0600); err != nil {
		t.Fatal(err)
	}
	if backupExists(src) {
		t.Error("expected backupExists to return false")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/ -run TestBackupExists -v`
Expected: FAIL with "undefined: backupExists".

- [ ] **Step 3: Write minimal implementation**

Create `internal/cli/backup.go`:

```go
package cli

import "os"

// backupSuffix is appended to the original path to form the backup path.
const backupSuffix = ".veil-backup"

// backupExists reports whether src has a sibling backup file.
func backupExists(src string) bool {
	_, err := os.Stat(src + backupSuffix)
	return err == nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/ -run TestBackupExists -v`
Expected: PASS on both subtests.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/backup.go internal/cli/backup_test.go
git commit -m "feat(cli): add backupExists helper for .veil-backup sibling detection"
```

---

### Task 1.2: Add `writeBackup` helper

**Files:**
- Modify: `internal/cli/backup.go`
- Modify: `internal/cli/backup_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/cli/backup_test.go`:

```go
func TestWriteBackupCopiesContentAt0600(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "foo.env")
	original := []byte("SECRET=abc123\nOTHER=plain\n")
	if err := os.WriteFile(src, original, 0644); err != nil {
		t.Fatal(err)
	}

	if err := writeBackup(src); err != nil {
		t.Fatalf("writeBackup: %v", err)
	}

	backup := src + ".veil-backup"
	data, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(data) != string(original) {
		t.Errorf("backup content = %q, want %q", data, original)
	}

	info, err := os.Stat(backup)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("backup mode = %o, want 0600", mode)
	}
}

func TestWriteBackupOverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "foo.env")
	if err := os.WriteFile(src, []byte("NEW=content"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src+".veil-backup", []byte("STALE"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := writeBackup(src); err != nil {
		t.Fatalf("writeBackup: %v", err)
	}

	data, err := os.ReadFile(src + ".veil-backup")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "NEW=content" {
		t.Errorf("backup content = %q, want NEW=content", data)
	}
}

func TestWriteBackupErrorsWhenSourceMissing(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "does-not-exist")
	if err := writeBackup(src); err == nil {
		t.Error("expected error when source file is missing")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/ -run TestWriteBackup -v`
Expected: FAIL with "undefined: writeBackup".

- [ ] **Step 3: Write minimal implementation**

Append to `internal/cli/backup.go`:

```go
// writeBackup copies src to src+".veil-backup" at mode 0600. If the backup
// already exists, it is overwritten. Returns an error if src cannot be read
// or the backup cannot be written.
func writeBackup(src string) error {
	data, err := os.ReadFile(src) // #nosec G304 -- src is a vaulted project file path
	if err != nil {
		return err
	}
	return os.WriteFile(src+backupSuffix, data, 0600) // #nosec G304 G306 -- derived backup path
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/ -run TestWriteBackup -v`
Expected: PASS on all three subtests.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/backup.go internal/cli/backup_test.go
git commit -m "feat(cli): add writeBackup helper that mirrors src to .veil-backup at 0600"
```

---

### Task 1.3: Refactor MCP path in `init.go` to use the helpers

**Files:**
- Modify: `internal/cli/init.go` (lines ~212-218 and ~343-351)

- [ ] **Step 1: Run existing MCP tests to establish baseline**

Run: `go test ./internal/cli/ -run TestInitMCP -v`
Expected: PASS (establishes the regression guard for this refactor).

- [ ] **Step 2: Replace the early skip in `processMCPConfig`**

In `internal/cli/init.go`, find:

```go
func processMCPConfig(cmd *cobra.Command, in io.Reader, v *vault.Vault, configPath string, force, dryRun, interactive bool) (int, int, error) {
	// Check for existing backup (indicates already migrated).
	backupPath := configPath + ".veil-backup"
	if _, err := os.Stat(backupPath); err == nil && !force {
		ui.Warnf(cmd.ErrOrStderr(), "%s already has a backup (use --force to re-migrate)", configPath)
		return 0, 0, nil
	}
```

Replace with:

```go
func processMCPConfig(cmd *cobra.Command, in io.Reader, v *vault.Vault, configPath string, force, dryRun, interactive bool) (int, int, error) {
	// Check for existing backup (indicates already migrated).
	if backupExists(configPath) && !force {
		ui.Warnf(cmd.ErrOrStderr(), "%s already has a backup (use --force to re-migrate)", configPath)
		return 0, 0, nil
	}
```

Also remove the `backupPath` local variable declaration — it's now inline within `writeBackup`. If any later line in the function references `backupPath`, update the next step to replace those too.

- [ ] **Step 3: Replace the backup write before `atomicWriteFile`**

In `internal/cli/init.go`, find:

```go
	if !dryRun && configChanged {
		// Create backup of original.
		originalData, err := os.ReadFile(configPath) // #nosec G304
		if err != nil {
			return 0, 0, cliError(fmt.Sprintf("reading MCP config for backup: %v", err), "")
		}
		if err := os.WriteFile(backupPath, originalData, 0600); err != nil { // #nosec G304 G703 -- backupPath is derived from configPath
			return 0, 0, cliError(fmt.Sprintf("writing MCP config backup: %v", err), "")
		}

		// Write updated config.
		newData, err := mcpCfg.Bytes()
```

Replace with:

```go
	if !dryRun && configChanged {
		if err := writeBackup(configPath); err != nil {
			return 0, 0, cliErrorf("writing MCP config backup: %v", err)
		}

		newData, err := mcpCfg.Bytes()
```

- [ ] **Step 4: Run MCP tests**

Run: `go test ./internal/cli/ -run TestInitMCP -v`
Expected: PASS — the public behaviour is unchanged; tests that assert backup exists + contains original token still pass.

- [ ] **Step 5: Run the full cli test suite**

Run: `go test ./internal/cli/ -v`
Expected: PASS. If any test referenced the removed `backupPath` local, fix it by constructing the path via `configPath + ".veil-backup"` or `backupSuffix`.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/init.go
git commit -m "refactor(cli): route MCP backup through shared helpers"
```

---

## Phase 2 — `.env` backup at init time

Goal: make `processEnvFile` write `.env.veil-backup` before rewriting, with the same "skip if exists, unless --force" semantics as MCP.

### Task 2.1: Thread `force` through `processEnvFile`

**Files:**
- Modify: `internal/cli/init_phases.go:118` (function signature)
- Modify: `internal/cli/init.go:138` (call site)

- [ ] **Step 1: Change the signature**

In `internal/cli/init_phases.go`, find the `processEnvFile` signature:

```go
func processEnvFile(cmd *cobra.Command, in io.Reader, v *vault.Vault, seen placeholder.Set, root, envPath string, dryRun, interactive bool) (int, int, error) {
```

Replace with:

```go
func processEnvFile(cmd *cobra.Command, in io.Reader, v *vault.Vault, seen placeholder.Set, root, envPath string, force, dryRun, interactive bool) (int, int, error) {
```

- [ ] **Step 2: Update the call site**

In `internal/cli/init.go`, find the loop around line 137:

```go
	for _, envPath := range envPaths {
		n, s, err := processEnvFile(cmd, in, v, seen, root, envPath, dryRun, interactive)
```

Replace with:

```go
	for _, envPath := range envPaths {
		n, s, err := processEnvFile(cmd, in, v, seen, root, envPath, force, dryRun, interactive)
```

- [ ] **Step 3: Run the build to verify it compiles**

Run: `go build ./...`
Expected: success, no errors.

- [ ] **Step 4: Run existing init tests**

Run: `go test ./internal/cli/ -run TestInit -v`
Expected: PASS — the new parameter is unused so far; behaviour is identical.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/init_phases.go internal/cli/init.go
git commit -m "refactor(cli): plumb force flag into processEnvFile"
```

---

### Task 2.2: Add the backup-already-exists guard

**Files:**
- Modify: `internal/cli/init_phases.go:118-122`
- Test: `internal/cli/init_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/cli/init_test.go`:

```go
func TestInitEnvSkipsWhenBackupExists(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte("GITHUB_TOKEN=ghp_real1234567890abcdef1234567890abcdef\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Pre-seed a backup with a sentinel so we can verify it's not overwritten.
	backupPath := envPath + ".veil-backup"
	sentinel := []byte("sentinel\n")
	if err := os.WriteFile(backupPath, sentinel, 0600); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	stderr := new(bytes.Buffer)
	cmd.SetErr(stderr)
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Backup must still contain the sentinel (unchanged).
	got, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(sentinel) {
		t.Errorf("backup overwritten; got %q, want %q", got, sentinel)
	}

	// .env must still contain the real token (file was skipped, not processed).
	envContents, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(envContents), "ghp_real1234567890abcdef1234567890abcdef") {
		t.Error(".env should have been skipped (real token still present)")
	}

	// Stderr should mention the skip.
	if !strings.Contains(stderr.String(), "already has a backup") {
		t.Errorf("expected 'already has a backup' warning on stderr, got: %s", stderr.String())
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/cli/ -run TestInitEnvSkipsWhenBackupExists -v`
Expected: FAIL — without the guard, init overwrites the backup and replaces the real token with a placeholder.

- [ ] **Step 3: Add the guard at the top of `processEnvFile`**

In `internal/cli/init_phases.go`, find the start of `processEnvFile` body (right after the opening brace and comment block):

```go
func processEnvFile(cmd *cobra.Command, in io.Reader, v *vault.Vault, seen placeholder.Set, root, envPath string, force, dryRun, interactive bool) (int, int, error) {
	envFile, err := scanner.ParseFile(envPath)
```

Insert the guard BEFORE the `envFile, err := ...` line so the parse doesn't happen on skipped files:

```go
func processEnvFile(cmd *cobra.Command, in io.Reader, v *vault.Vault, seen placeholder.Set, root, envPath string, force, dryRun, interactive bool) (int, int, error) {
	if backupExists(envPath) && !force {
		ui.Warnf(cmd.ErrOrStderr(), "%s already has a backup (use --force to re-vault)", envPath)
		return 0, 0, nil
	}
	envFile, err := scanner.ParseFile(envPath)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/cli/ -run TestInitEnvSkipsWhenBackupExists -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/init_phases.go internal/cli/init_test.go
git commit -m "feat(cli): skip .env processing when .veil-backup already exists"
```

---

### Task 2.3: Write backup before rewriting `.env`

**Files:**
- Modify: `internal/cli/init_phases.go:192-195`
- Test: `internal/cli/init_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/cli/init_test.go`:

```go
func TestInitEnvCreatesBackupBeforeRewrite(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(tmpDir, ".env")
	original := []byte("# header\nGITHUB_TOKEN=ghp_real1234567890abcdef1234567890abcdef\nLOG_LEVEL=debug\n")
	if err := os.WriteFile(envPath, original, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Backup must exist and contain the exact original bytes.
	backup, err := os.ReadFile(envPath + ".veil-backup")
	if err != nil {
		t.Fatalf("backup not created: %v", err)
	}
	if string(backup) != string(original) {
		t.Errorf("backup content mismatch\ngot:  %q\nwant: %q", backup, original)
	}

	// Backup permission must be 0600.
	info, err := os.Stat(envPath + ".veil-backup")
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("backup mode = %o, want 0600", mode)
	}

	// .env must no longer contain the real token (placeholder substitution
	// happened).
	envContents, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(envContents), "ghp_real1234567890abcdef1234567890abcdef") {
		t.Error("real token leaked into .env after init")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/cli/ -run TestInitEnvCreatesBackupBeforeRewrite -v`
Expected: FAIL — no backup is created.

- [ ] **Step 3: Add the backup write call**

In `internal/cli/init_phases.go`, find the block around lines 192-196:

```go
	if !dryRun && fileChanged {
		if err := atomicWriteFile(envPath, envFile.Bytes()); err != nil {
			return vaulted, scoped, wrapErr(fmt.Sprintf("writing %s", envPath), err)
		}
	}
```

Replace with:

```go
	if !dryRun && fileChanged {
		if err := writeBackup(envPath); err != nil {
			return vaulted, scoped, wrapErr(fmt.Sprintf("writing backup for %s", envPath), err)
		}
		if err := atomicWriteFile(envPath, envFile.Bytes()); err != nil {
			return vaulted, scoped, wrapErr(fmt.Sprintf("writing %s", envPath), err)
		}
	}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/cli/ -run TestInitEnvCreatesBackupBeforeRewrite -v`
Expected: PASS.

- [ ] **Step 5: Run the full init test suite for regressions**

Run: `go test ./internal/cli/ -run TestInit -v`
Expected: PASS on all tests. The new backup file is harmless for existing assertions.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/init_phases.go internal/cli/init_test.go
git commit -m "feat(cli): write .env.veil-backup before rewriting with placeholders"
```

---

## Phase 3 — Extend `appendGitignore`

Goal: add `*.veil-backup` to the project-root `.gitignore` when one exists.

### Task 3.1: Extend `appendGitignore` to cover backup files

**Files:**
- Modify: `internal/cli/init.go:392-413`
- Test: `internal/cli/init_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/cli/init_test.go`:

```go
func TestAppendGitignoreAddsVeilBackupPattern(t *testing.T) {
	dir := t.TempDir()
	gitignorePath := filepath.Join(dir, ".gitignore")
	if err := os.WriteFile(gitignorePath, []byte("node_modules/\n"), 0644); err != nil {
		t.Fatal(err)
	}

	appendGitignore(dir)

	data, err := os.ReadFile(gitignorePath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "/.veil/") {
		t.Errorf(".gitignore should contain /.veil/, got: %q", content)
	}
	if !strings.Contains(content, "*.veil-backup") {
		t.Errorf(".gitignore should contain *.veil-backup, got: %q", content)
	}
	if !strings.Contains(content, "node_modules/") {
		t.Error(".gitignore lost original content")
	}
}

func TestAppendGitignoreIdempotent(t *testing.T) {
	dir := t.TempDir()
	gitignorePath := filepath.Join(dir, ".gitignore")
	initial := "node_modules/\n/.veil/\n*.veil-backup\n"
	if err := os.WriteFile(gitignorePath, []byte(initial), 0644); err != nil {
		t.Fatal(err)
	}

	appendGitignore(dir)

	data, err := os.ReadFile(gitignorePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != initial {
		t.Errorf("expected .gitignore unchanged, got: %q", data)
	}
}

func TestAppendGitignoreNoOpWhenMissing(t *testing.T) {
	dir := t.TempDir()
	// No .gitignore present.
	appendGitignore(dir)
	if _, err := os.Stat(filepath.Join(dir, ".gitignore")); !os.IsNotExist(err) {
		t.Error("appendGitignore should not create .gitignore when absent")
	}
}
```

- [ ] **Step 2: Run the test to verify the new pattern test fails**

Run: `go test ./internal/cli/ -run TestAppendGitignore -v`
Expected: `TestAppendGitignoreAddsVeilBackupPattern` FAILS; the other two PASS (existing behaviour).

- [ ] **Step 3: Extend the helper**

In `internal/cli/init.go`, find `appendGitignore`:

```go
// appendGitignore adds /.veil/ to the project .gitignore if not already present.
func appendGitignore(root string) {
	gitignorePath := filepath.Join(root, ".gitignore")
	data, err := os.ReadFile(gitignorePath)
	if err != nil {
		// No .gitignore — nothing to do.
		return
	}

	content := string(data)
	if strings.Contains(content, "/.veil/") {
		return
	}

	// Ensure content ends with a newline before appending.
	if len(content) > 0 && content[len(content)-1] != '\n' {
		content += "\n"
	}
	content += "/.veil/\n"

	_ = os.WriteFile(gitignorePath, []byte(content), 0600) //nolint:gosec // .gitignore is not sensitive
}
```

Replace with:

```go
// appendGitignore adds /.veil/ and *.veil-backup to the project .gitignore
// if not already present. No-op when .gitignore doesn't exist.
func appendGitignore(root string) {
	gitignorePath := filepath.Join(root, ".gitignore")
	data, err := os.ReadFile(gitignorePath)
	if err != nil {
		// No .gitignore — nothing to do.
		return
	}

	content := string(data)
	changed := false
	for _, line := range []string{"/.veil/", "*.veil-backup"} {
		if strings.Contains(content, line) {
			continue
		}
		if len(content) > 0 && content[len(content)-1] != '\n' {
			content += "\n"
		}
		content += line + "\n"
		changed = true
	}
	if !changed {
		return
	}

	_ = os.WriteFile(gitignorePath, []byte(content), 0600) //nolint:gosec // .gitignore is not sensitive
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/cli/ -run TestAppendGitignore -v`
Expected: all three PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/init.go internal/cli/init_test.go
git commit -m "feat(cli): append *.veil-backup to project .gitignore during init"
```

---

## Phase 4 — Uninstall primitives

These are the small, pure-ish helpers `veil uninstall` will compose. Each gets its own test before being wired into the command.

### Task 4.1: `vault.ReadProjectID` helper

**Files:**
- Create: `internal/vault/meta.go`
- Test: `internal/vault/meta_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/vault/meta_test.go`:

```go
package vault_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/vault"
)

func TestReadProjectIDReturnsStoredValue(t *testing.T) {
	root := t.TempDir()
	stateDir := config.ProjectStateDir(root)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	meta := map[string]any{"project_id": "proj-abc123", "version": 1}
	b, _ := json.Marshal(meta)
	if err := os.WriteFile(config.VaultMetaFile(root), b, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := vault.ReadProjectID(root)
	if err != nil {
		t.Fatalf("ReadProjectID: %v", err)
	}
	if got != "proj-abc123" {
		t.Errorf("got %q, want proj-abc123", got)
	}
}

func TestReadProjectIDErrorsWhenMetaMissing(t *testing.T) {
	root := t.TempDir()
	if _, err := vault.ReadProjectID(root); err == nil {
		t.Error("expected error when vault.meta is missing")
	}
}

func TestReadProjectIDErrorsOnInvalidJSON(t *testing.T) {
	root := t.TempDir()
	stateDir := config.ProjectStateDir(root)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.VaultMetaFile(root), []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.ReadProjectID(root); err == nil {
		t.Error("expected error on malformed vault.meta")
	}
}

func TestReadProjectIDErrorsOnEmptyProjectID(t *testing.T) {
	root := t.TempDir()
	stateDir := config.ProjectStateDir(root)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.VaultMetaFile(root), []byte(`{"project_id":"","version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.ReadProjectID(root); err == nil {
		t.Error("expected error on empty project_id")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/vault/ -run TestReadProjectID -v`
Expected: FAIL with "undefined: vault.ReadProjectID".

- [ ] **Step 3: Write the helper**

Create `internal/vault/meta.go`:

```go
package vault

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/8enji/veil/internal/config"
)

// ReadProjectID reads vault.meta at the project root and returns the stored
// project ID. Does not require the keystore or master key — useful for
// commands like uninstall that need to identify the vault before tearing it
// down. Returns an error if the meta file is missing, malformed, or the
// project_id is empty.
func ReadProjectID(root string) (string, error) {
	path := config.VaultMetaFile(root)
	data, err := os.ReadFile(path) // #nosec G304 -- path derived from project root
	if err != nil {
		return "", fmt.Errorf("reading vault.meta: %w", err)
	}
	var meta vaultMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return "", fmt.Errorf("parsing vault.meta: %w", err)
	}
	if meta.ProjectID == "" {
		return "", fmt.Errorf("vault.meta has empty project_id")
	}
	return meta.ProjectID, nil
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/vault/ -run TestReadProjectID -v`
Expected: all four subtests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/vault/meta.go internal/vault/meta_test.go
git commit -m "feat(vault): add ReadProjectID helper for pre-open project identification"
```

---

### Task 4.2: Active-proxy detection

**Files:**
- Create: `internal/cli/uninstall.go`
- Test: `internal/cli/uninstall_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/cli/uninstall_test.go`:

```go
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/8enji/veil/internal/config"
)

func TestActiveProxyPIDsIgnoresDeadPIDs(t *testing.T) {
	root := t.TempDir()
	stateDir := config.ProjectStateDir(root)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Write a PID file for an extremely high PID that won't exist.
	pidFile := filepath.Join(stateDir, "proxy-99999999.pid")
	if err := os.WriteFile(pidFile, []byte("99999999\n"), 0600); err != nil {
		t.Fatal(err)
	}

	live, err := activeProxyPIDs(root)
	if err != nil {
		t.Fatalf("activeProxyPIDs: %v", err)
	}
	if len(live) != 0 {
		t.Errorf("expected no live PIDs, got %v", live)
	}
}

func TestActiveProxyPIDsDetectsLivePID(t *testing.T) {
	root := t.TempDir()
	stateDir := config.ProjectStateDir(root)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Use the current test process's PID — guaranteed alive.
	ourPID := os.Getpid()
	pidFile := filepath.Join(stateDir, fmt.Sprintf("proxy-%d.pid", ourPID))
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", ourPID)), 0600); err != nil {
		t.Fatal(err)
	}

	live, err := activeProxyPIDs(root)
	if err != nil {
		t.Fatalf("activeProxyPIDs: %v", err)
	}
	if len(live) != 1 || live[0] != ourPID {
		t.Errorf("expected [%d], got %v", ourPID, live)
	}
}

func TestActiveProxyPIDsNoStateDir(t *testing.T) {
	root := t.TempDir()
	live, err := activeProxyPIDs(root)
	if err != nil {
		t.Fatalf("activeProxyPIDs: %v", err)
	}
	if len(live) != 0 {
		t.Errorf("expected no PIDs for missing state dir, got %v", live)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/cli/ -run TestActiveProxyPIDs -v`
Expected: FAIL with "undefined: activeProxyPIDs".

- [ ] **Step 3: Write the helper**

Create `internal/cli/uninstall.go`:

```go
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/8enji/veil/internal/config"
)

// activeProxyPIDs returns the list of PIDs from proxy-*.pid files that
// correspond to live processes. Dead PIDs and unreadable files are ignored.
func activeProxyPIDs(root string) ([]int, error) {
	matches, err := filepath.Glob(config.PidFileGlob(root))
	if err != nil {
		return nil, err
	}
	var live []int
	for _, p := range matches {
		pid, ok := readPIDFile(p)
		if !ok {
			continue
		}
		if isProcessAlive(pid) {
			live = append(live, pid)
		}
	}
	return live, nil
}

// readPIDFile reads a pidfile and returns the integer PID. Returns false
// if the file cannot be read or does not contain a parseable integer.
func readPIDFile(path string) (int, bool) {
	data, err := os.ReadFile(path) // #nosec G304 -- pidfile path derived from state dir glob
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// isProcessAlive reports whether a process with the given PID exists.
// Uses signal 0 (no-op signal) to test existence without affecting the
// target. Returns false on permission errors as well — if we can't signal
// it, we can't safely claim it's live.
func isProcessAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	// ESRCH (no such process) → dead. Other errors (EPERM) treat as dead too
	// because we can't confirm liveness; conservative for uninstall purposes
	// where a stale pidfile shouldn't block cleanup.
	return false
}

// formatPIDList formats a slice of PIDs for error messages.
func formatPIDList(pids []int) string {
	parts := make([]string, len(pids))
	for i, p := range pids {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(parts, ", ")
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/cli/ -run TestActiveProxyPIDs -v`
Expected: all three PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/uninstall.go internal/cli/uninstall_test.go
git commit -m "feat(cli): add activeProxyPIDs helper for uninstall guard"
```

---

### Task 4.3: Backup discovery

**Files:**
- Modify: `internal/cli/uninstall.go`
- Modify: `internal/cli/uninstall_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/cli/uninstall_test.go`:

```go
func TestDiscoverBackupsFindsEnvPairs(t *testing.T) {
	root := t.TempDir()
	// Valid pair: both original and backup exist.
	envPath := filepath.Join(root, ".env")
	envBackup := envPath + ".veil-backup"
	if err := os.WriteFile(envPath, []byte("KEY=placeholder"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envBackup, []byte("KEY=original"), 0600); err != nil {
		t.Fatal(err)
	}
	// Curated-name alternative: .env.local with only a backup (original deleted).
	localBackup := filepath.Join(root, ".env.local.veil-backup")
	if err := os.WriteFile(localBackup, []byte("FOO=bar"), 0600); err != nil {
		t.Fatal(err)
	}
	// Noise: a backup file with an unsupported name (should be ignored).
	randomBackup := filepath.Join(root, "random.conf.veil-backup")
	if err := os.WriteFile(randomBackup, []byte("zzz"), 0600); err != nil {
		t.Fatal(err)
	}

	pairs, err := discoverBackups(root)
	if err != nil {
		t.Fatalf("discoverBackups: %v", err)
	}

	// Expect exactly two env pairs (the curated names), none for MCP.
	byOriginal := make(map[string]bool)
	for _, p := range pairs {
		if p.kind == backupKindEnv {
			byOriginal[p.original] = true
		}
	}
	if !byOriginal[envPath] {
		t.Errorf("missing pair for %s; got: %v", envPath, byOriginal)
	}
	if !byOriginal[filepath.Join(root, ".env.local")] {
		t.Errorf("missing pair for .env.local; got: %v", byOriginal)
	}
	if byOriginal[filepath.Join(root, "random.conf")] {
		t.Errorf("unexpected pair for non-curated file: random.conf")
	}
}

func TestDiscoverBackupsIncludesMCPWhenDiscoverable(t *testing.T) {
	root := t.TempDir()
	// Set up a fake MCP config + backup via the test env var.
	mcpDir := t.TempDir()
	mcpPath := filepath.Join(mcpDir, "claude_desktop_config.json")
	if err := os.WriteFile(mcpPath, []byte(`{"mcpServers":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mcpPath+".veil-backup", []byte(`{"mcpServers":{"x":{}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEIL_MCP_CONFIG_PATH", mcpPath)

	pairs, err := discoverBackups(root)
	if err != nil {
		t.Fatalf("discoverBackups: %v", err)
	}

	found := false
	for _, p := range pairs {
		if p.kind == backupKindMCP && p.original == mcpPath {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected MCP pair in results; got: %+v", pairs)
	}
}

func TestDiscoverBackupsEmpty(t *testing.T) {
	root := t.TempDir()
	pairs, err := discoverBackups(root)
	if err != nil {
		t.Fatalf("discoverBackups: %v", err)
	}
	if len(pairs) != 0 {
		t.Errorf("expected 0 pairs, got %v", pairs)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/cli/ -run TestDiscoverBackups -v`
Expected: FAIL with "undefined: discoverBackups" and "undefined: backupPair"/"backupKindEnv".

- [ ] **Step 3: Implement discovery**

Append to `internal/cli/uninstall.go`:

```go
// backupKind classifies a backup pair by the kind of file it covers.
type backupKind int

const (
	backupKindEnv backupKind = iota
	backupKindMCP
)

// backupPair pairs an original file path with its backup. Either may be
// missing on disk at discovery time; classification runs later.
type backupPair struct {
	original string
	backup   string
	kind     backupKind
}

// envCuratedNames mirrors scanner.curatedNames. Kept local to avoid
// exporting scanner internals; the list changes rarely.
var envCuratedNames = []string{
	".env",
	".env.local",
	".env.development",
	".env.production",
}

// discoverBackups returns every (original, backup) pair that uninstall
// should consider. For .env files: iterates curatedNames, returns a pair
// when either the original or the backup exists. For MCP: consults
// mcpconfig.Discover() and returns a pair only if the MCP backup exists.
func discoverBackups(root string) ([]backupPair, error) {
	var pairs []backupPair
	for _, name := range envCuratedNames {
		orig := filepath.Join(root, name)
		backup := orig + backupSuffix
		_, origErr := os.Stat(orig)
		_, backErr := os.Stat(backup)
		if origErr != nil && backErr != nil {
			continue
		}
		pairs = append(pairs, backupPair{original: orig, backup: backup, kind: backupKindEnv})
	}

	mcpPath, _ := mcpconfigDiscover()
	if mcpPath != "" {
		if _, err := os.Stat(mcpPath + backupSuffix); err == nil {
			pairs = append(pairs, backupPair{
				original: mcpPath,
				backup:   mcpPath + backupSuffix,
				kind:     backupKindMCP,
			})
		}
	}
	return pairs, nil
}

// mcpconfigDiscover wraps mcpconfig.Discover so tests can observe the seam
// without importing the package into the uninstall_test package.
var mcpconfigDiscover = func() (string, error) { return mcpconfig.Discover() }
```

Add the needed import for `mcpconfig` at the top of `internal/cli/uninstall.go`:

```go
import (
	// ...existing imports...
	"github.com/8enji/veil/internal/mcpconfig"
)
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/cli/ -run TestDiscoverBackups -v`
Expected: all three PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/uninstall.go internal/cli/uninstall_test.go
git commit -m "feat(cli): add backup discovery for .env curated names and MCP"
```

---

### Task 4.4: Classification — unmodified / modified / original-missing

**Files:**
- Modify: `internal/cli/uninstall.go`
- Modify: `internal/cli/uninstall_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/cli/uninstall_test.go`:

```go
func TestClassifyEnvPairOriginalMissing(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, ".env")
	backup := orig + ".veil-backup"
	if err := os.WriteFile(backup, []byte("KEY=value\n"), 0600); err != nil {
		t.Fatal(err)
	}

	status, _, err := classifyEnvPair(orig, backup, nil)
	if err != nil {
		t.Fatalf("classifyEnvPair: %v", err)
	}
	if status != classOriginalMissing {
		t.Errorf("status = %v, want classOriginalMissing", status)
	}
}

func TestClassifyEnvPairUnmodified(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, ".env")
	backup := orig + ".veil-backup"

	backupContent := []byte("# header\nTOKEN=ghp_real1234567890abcdef1234567890abcdef\n")
	if err := os.WriteFile(backup, backupContent, 0600); err != nil {
		t.Fatal(err)
	}

	// Simulate post-init .env: real value replaced with a placeholder.
	currentContent := []byte("# header\nTOKEN=ghp_veil_abc123\n")
	if err := os.WriteFile(orig, currentContent, 0600); err != nil {
		t.Fatal(err)
	}

	// placeholderMap reverses placeholders → real values.
	resolver := placeholderResolver{
		"ghp_veil_abc123": "ghp_real1234567890abcdef1234567890abcdef",
	}

	status, _, err := classifyEnvPair(orig, backup, resolver)
	if err != nil {
		t.Fatalf("classifyEnvPair: %v", err)
	}
	if status != classUnmodified {
		t.Errorf("status = %v, want classUnmodified", status)
	}
}

func TestClassifyEnvPairModified(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, ".env")
	backup := orig + ".veil-backup"

	backupContent := []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n")
	if err := os.WriteFile(backup, backupContent, 0600); err != nil {
		t.Fatal(err)
	}
	// User appended a new line after init.
	currentContent := []byte("TOKEN=ghp_veil_abc123\nLOG_LEVEL=debug\n")
	if err := os.WriteFile(orig, currentContent, 0600); err != nil {
		t.Fatal(err)
	}

	resolver := placeholderResolver{
		"ghp_veil_abc123": "ghp_real1234567890abcdef1234567890abcdef",
	}

	status, diff, err := classifyEnvPair(orig, backup, resolver)
	if err != nil {
		t.Fatalf("classifyEnvPair: %v", err)
	}
	if status != classModified {
		t.Errorf("status = %v, want classModified", status)
	}
	if !strings.Contains(diff, "LOG_LEVEL=debug") {
		t.Errorf("diff should mention the added line; got:\n%s", diff)
	}
}

func TestClassifyEnvPairModifiedWhenResolverNil(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, ".env")
	backup := orig + ".veil-backup"
	if err := os.WriteFile(backup, []byte("A=b\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(orig, []byte("A=b\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Nil resolver simulates vault-unopenable. Must not be classUnmodified
	// unless we can prove equivalence via placeholder substitution.
	status, _, err := classifyEnvPair(orig, backup, nil)
	if err != nil {
		t.Fatalf("classifyEnvPair: %v", err)
	}
	// In this case, current == backup byte-for-byte (no placeholders to
	// substitute), so unmodified is still correct even with nil resolver.
	if status != classUnmodified {
		t.Errorf("status = %v, want classUnmodified (byte-equal, no substitution needed)", status)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/cli/ -run TestClassifyEnvPair -v`
Expected: FAIL — `classifyEnvPair`, `classOriginalMissing`, `classUnmodified`, `classModified`, `placeholderResolver` all undefined.

- [ ] **Step 3: Implement classification**

Append to `internal/cli/uninstall.go`:

```go
// classification enumerates how a (current, backup) pair relates.
type classification int

const (
	classUnmodified classification = iota
	classModified
	classOriginalMissing
)

// placeholderResolver maps a placeholder string to its real value.
// An empty / nil resolver means "we cannot substitute" — classification
// falls back to byte comparison only.
type placeholderResolver map[string]string

// classifyEnvPair compares the current .env file to its backup after
// reverse-substituting placeholders with real values. Returns:
//   - classUnmodified: after substitution, bytes match the backup.
//   - classModified: bytes differ. The returned string is a unified diff
//     between the (substitution-applied) current file and the backup.
//   - classOriginalMissing: current file does not exist on disk.
func classifyEnvPair(original, backup string, resolver placeholderResolver) (classification, string, error) {
	backupBytes, err := os.ReadFile(backup) // #nosec G304
	if err != nil {
		return 0, "", fmt.Errorf("read backup %s: %w", backup, err)
	}
	currentBytes, err := os.ReadFile(original) // #nosec G304
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return classOriginalMissing, "", nil
		}
		return 0, "", fmt.Errorf("read %s: %w", original, err)
	}

	expected, err := expectedOriginalEnv(currentBytes, resolver)
	if err != nil {
		// Parsing failed; treat as modified so the user sees a diff.
		diff := renderUnifiedDiff(backupBytes, currentBytes)
		return classModified, diff, nil
	}

	if bytes.Equal(expected, backupBytes) {
		return classUnmodified, "", nil
	}
	return classModified, renderUnifiedDiff(backupBytes, expected), nil
}

// expectedOriginalEnv parses current as a .env file and replaces each
// KV-line's value with the real value from resolver when the current value
// is a known placeholder. Returns the reconstructed bytes via
// scanner.EnvFile.Bytes() so formatting is preserved.
func expectedOriginalEnv(current []byte, resolver placeholderResolver) ([]byte, error) {
	envFile, err := scanner.ParseBytes(current)
	if err != nil {
		return nil, err
	}
	if resolver != nil {
		for _, line := range envFile.Lines {
			if line.Kind != scanner.KVLine {
				continue
			}
			if real, ok := resolver[line.Value]; ok {
				envFile.SetValue(line.Key, real)
			}
		}
	}
	return envFile.Bytes(), nil
}
```

Add the needed imports (`bytes`, `errors`, `github.com/8enji/veil/internal/scanner`) to the top of `internal/cli/uninstall.go` if not already there.

- [ ] **Step 4: Check scanner API**

Verify that `scanner.ParseBytes` exists. Run:

```bash
grep -n 'func ParseBytes\|func ParseFile' internal/scanner/envfile.go
```

If only `ParseFile` exists and it reads from disk, add a parallel `ParseBytes` helper in the scanner package:

```go
// In internal/scanner/envfile.go, next to ParseFile:

// ParseBytes parses an .env file from a byte slice. Behaves identically
// to ParseFile modulo the I/O step.
func ParseBytes(data []byte) (*EnvFile, error) {
	return parseContent(string(data)), nil
}
```

If `ParseFile` already calls an internal `parseContent(string)` helper, reuse it. Otherwise refactor `ParseFile` to split I/O from parsing:

```go
func ParseFile(path string) (*EnvFile, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, err
	}
	return parseContent(string(data)), nil
}

func parseContent(content string) *EnvFile {
	// ...existing parsing logic from ParseFile...
}
```

Commit this change first if made:

```bash
git add internal/scanner/envfile.go
git commit -m "refactor(scanner): split ParseFile I/O from parsing, add ParseBytes"
```

- [ ] **Step 5: Stub `renderUnifiedDiff` so classification compiles**

Append to `internal/cli/uninstall.go` (temporary stub, replaced in Task 4.5):

```go
// renderUnifiedDiff produces a minimal unified diff between a and b.
// Task 4.5 replaces this stub with the full implementation.
func renderUnifiedDiff(a, b []byte) string {
	if bytes.Equal(a, b) {
		return ""
	}
	return fmt.Sprintf("--- backup\n+++ current\n- %d bytes\n+ %d bytes\n", len(a), len(b))
}
```

- [ ] **Step 6: Run the classification tests**

Run: `go test ./internal/cli/ -run TestClassifyEnvPair -v`
Expected: all four PASS. The stub diff is enough for the test that asserts `strings.Contains(diff, "LOG_LEVEL=debug")` — **WAIT** — the stub doesn't contain that substring. Adjust the test expectation OR skip Task 4.5's stub and implement the real diff now.

Revised approach: proceed directly to Task 4.5 (real diff) before running the `TestClassifyEnvPairModified` assertion. Mark this task as complete up through implementing `classifyEnvPair` and the stub; the modified-classification test will pass once the real diff ships in Task 4.5.

For now, loosen the modified-test assertion to:

```go
if status != classModified {
    t.Errorf("status = %v, want classModified", status)
}
// Diff content assertion deferred until Task 4.5.
```

Then:

```bash
go test ./internal/cli/ -run TestClassifyEnvPair -v
```
Expected: all four PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/cli/uninstall.go internal/cli/uninstall_test.go
git commit -m "feat(cli): classify env backup pairs as unmodified/modified/original-missing"
```

---

### Task 4.5: Real unified diff rendering

**Files:**
- Modify: `internal/cli/uninstall.go`
- Modify: `internal/cli/uninstall_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/cli/uninstall_test.go`:

```go
func TestRenderUnifiedDiffShowsAddedLines(t *testing.T) {
	a := []byte("line1\nline2\n")
	b := []byte("line1\nline2\nline3\n")
	diff := renderUnifiedDiff(a, b)
	if !strings.Contains(diff, "+line3") {
		t.Errorf("expected +line3 in diff, got:\n%s", diff)
	}
}

func TestRenderUnifiedDiffShowsRemovedLines(t *testing.T) {
	a := []byte("keep\nremove\n")
	b := []byte("keep\n")
	diff := renderUnifiedDiff(a, b)
	if !strings.Contains(diff, "-remove") {
		t.Errorf("expected -remove in diff, got:\n%s", diff)
	}
}

func TestRenderUnifiedDiffEmptyWhenEqual(t *testing.T) {
	a := []byte("same\n")
	diff := renderUnifiedDiff(a, a)
	if diff != "" {
		t.Errorf("expected empty diff, got: %q", diff)
	}
}

func TestRenderUnifiedDiffHasHeaders(t *testing.T) {
	diff := renderUnifiedDiff([]byte("a\n"), []byte("b\n"))
	if !strings.HasPrefix(diff, "--- backup\n+++ current\n") {
		t.Errorf("expected diff to start with '--- backup' / '+++ current', got:\n%s", diff)
	}
}
```

Also un-loosen the classification test from Task 4.4:

```go
// In TestClassifyEnvPairModified, restore the diff-content assertion:
if !strings.Contains(diff, "LOG_LEVEL=debug") {
    t.Errorf("diff should mention the added line; got:\n%s", diff)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cli/ -run "TestRenderUnifiedDiff|TestClassifyEnvPairModified" -v`
Expected: multiple FAILs.

- [ ] **Step 3: Replace the stub with a real implementation**

Replace `renderUnifiedDiff` in `internal/cli/uninstall.go` with:

```go
// renderUnifiedDiff produces a minimal unified-style diff between a and b.
// The output begins with "--- backup" / "+++ current" headers. Each
// differing line is prefixed with '-' (present in a, missing from b) or
// '+' (present in b, missing from a). Context lines are prefixed with a
// single space. Implementation uses a line-by-line LCS — fine for files
// of typical .env/MCP size (tens to hundreds of lines).
func renderUnifiedDiff(a, b []byte) string {
	if bytes.Equal(a, b) {
		return ""
	}
	aLines := strings.Split(string(a), "\n")
	bLines := strings.Split(string(b), "\n")
	// Trim trailing empty element caused by a terminal newline so we don't
	// diff a phantom blank line.
	if len(aLines) > 0 && aLines[len(aLines)-1] == "" {
		aLines = aLines[:len(aLines)-1]
	}
	if len(bLines) > 0 && bLines[len(bLines)-1] == "" {
		bLines = bLines[:len(bLines)-1]
	}

	lcs := lcsTable(aLines, bLines)
	var sb strings.Builder
	sb.WriteString("--- backup\n+++ current\n")
	emitDiff(&sb, aLines, bLines, lcs, len(aLines), len(bLines))
	return sb.String()
}

// lcsTable builds a longest-common-subsequence DP table for a and b.
func lcsTable(a, b []string) [][]int {
	n, m := len(a), len(b)
	t := make([][]int, n+1)
	for i := range t {
		t[i] = make([]int, m+1)
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if a[i-1] == b[j-1] {
				t[i][j] = t[i-1][j-1] + 1
			} else if t[i-1][j] >= t[i][j-1] {
				t[i][j] = t[i-1][j]
			} else {
				t[i][j] = t[i][j-1]
			}
		}
	}
	return t
}

// emitDiff walks the LCS table from (i,j) down to (0,0) and emits diff
// lines in forward order using a recursive preorder traversal.
func emitDiff(sb *strings.Builder, a, b []string, t [][]int, i, j int) {
	switch {
	case i > 0 && j > 0 && a[i-1] == b[j-1]:
		emitDiff(sb, a, b, t, i-1, j-1)
		sb.WriteString(" ")
		sb.WriteString(a[i-1])
		sb.WriteString("\n")
	case j > 0 && (i == 0 || t[i][j-1] >= t[i-1][j]):
		emitDiff(sb, a, b, t, i, j-1)
		sb.WriteString("+")
		sb.WriteString(b[j-1])
		sb.WriteString("\n")
	case i > 0 && (j == 0 || t[i][j-1] < t[i-1][j]):
		emitDiff(sb, a, b, t, i-1, j)
		sb.WriteString("-")
		sb.WriteString(a[i-1])
		sb.WriteString("\n")
	}
}
```

- [ ] **Step 4: Run the diff and classification tests**

Run: `go test ./internal/cli/ -run "TestRenderUnifiedDiff|TestClassifyEnvPair" -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/uninstall.go internal/cli/uninstall_test.go
git commit -m "feat(cli): add unified diff renderer for uninstall plans"
```

---

### Task 4.6: MCP classification

**Files:**
- Modify: `internal/cli/uninstall.go`
- Modify: `internal/cli/uninstall_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/cli/uninstall_test.go`:

```go
func TestClassifyMCPPairUnmodified(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "claude_desktop_config.json")
	backup := orig + ".veil-backup"

	backupContent := []byte(`{"mcpServers":{"x":{"env":{"TOKEN":"real-value"}}}}`)
	if err := os.WriteFile(backup, backupContent, 0600); err != nil {
		t.Fatal(err)
	}
	// Post-init: placeholder swapped in.
	currentContent := []byte(`{"mcpServers":{"x":{"env":{"TOKEN":"ghp_veil_abc"}}}}`)
	if err := os.WriteFile(orig, currentContent, 0600); err != nil {
		t.Fatal(err)
	}

	resolver := placeholderResolver{"ghp_veil_abc": "real-value"}

	status, _, err := classifyMCPPair(orig, backup, resolver)
	if err != nil {
		t.Fatalf("classifyMCPPair: %v", err)
	}
	if status != classUnmodified {
		t.Errorf("status = %v, want classUnmodified", status)
	}
}

func TestClassifyMCPPairModified(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "claude_desktop_config.json")
	backup := orig + ".veil-backup"

	backupContent := []byte(`{"mcpServers":{"x":{"env":{"TOKEN":"real"}}}}`)
	if err := os.WriteFile(backup, backupContent, 0600); err != nil {
		t.Fatal(err)
	}
	// User added a new server after init.
	currentContent := []byte(`{"mcpServers":{"x":{"env":{"TOKEN":"ghp_veil_abc"}},"y":{"env":{"OTHER":"new"}}}}`)
	if err := os.WriteFile(orig, currentContent, 0600); err != nil {
		t.Fatal(err)
	}

	resolver := placeholderResolver{"ghp_veil_abc": "real"}

	status, _, err := classifyMCPPair(orig, backup, resolver)
	if err != nil {
		t.Fatalf("classifyMCPPair: %v", err)
	}
	if status != classModified {
		t.Errorf("status = %v, want classModified", status)
	}
}

func TestClassifyMCPPairOriginalMissing(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "claude_desktop_config.json")
	backup := orig + ".veil-backup"
	if err := os.WriteFile(backup, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}

	status, _, err := classifyMCPPair(orig, backup, nil)
	if err != nil {
		t.Fatalf("classifyMCPPair: %v", err)
	}
	if status != classOriginalMissing {
		t.Errorf("status = %v, want classOriginalMissing", status)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cli/ -run TestClassifyMCPPair -v`
Expected: FAIL — `classifyMCPPair` undefined.

- [ ] **Step 3: Implement MCP classification**

Append to `internal/cli/uninstall.go`:

```go
// classifyMCPPair compares the current MCP config file to its backup after
// reverse-substituting placeholders with real values. Semantics mirror
// classifyEnvPair but operate on the MCP JSON shape via mcpconfig.
func classifyMCPPair(original, backup string, resolver placeholderResolver) (classification, string, error) {
	backupBytes, err := os.ReadFile(backup) // #nosec G304
	if err != nil {
		return 0, "", fmt.Errorf("read backup %s: %w", backup, err)
	}
	currentBytes, err := os.ReadFile(original) // #nosec G304
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return classOriginalMissing, "", nil
		}
		return 0, "", fmt.Errorf("read %s: %w", original, err)
	}

	expected, err := expectedOriginalMCP(currentBytes, resolver)
	if err != nil {
		return classModified, renderUnifiedDiff(backupBytes, currentBytes), nil
	}

	if bytes.Equal(expected, backupBytes) {
		return classUnmodified, "", nil
	}
	return classModified, renderUnifiedDiff(backupBytes, expected), nil
}

// expectedOriginalMCP parses the current MCP config bytes, substitutes
// placeholders with real values in every server's env map, and re-serializes
// using mcpconfig's canonical formatting.
func expectedOriginalMCP(current []byte, resolver placeholderResolver) ([]byte, error) {
	cfg, err := mcpconfig.ParseBytes(current)
	if err != nil {
		return nil, err
	}
	if resolver != nil {
		for serverName, server := range cfg.Servers() {
			for key, value := range server.Env {
				if real, ok := resolver[value]; ok {
					cfg.SetEnvValue(serverName, key, real)
				}
			}
		}
	}
	return cfg.Bytes()
}
```

- [ ] **Step 4: Check `mcpconfig.ParseBytes` existence**

Run: `grep -n 'func ParseBytes\|func Parse(' internal/mcpconfig/mcpconfig.go`

If only `Parse(path string)` exists, add a `ParseBytes([]byte)` variant mirroring what was done for scanner in Task 4.4, and commit that separately:

```bash
git add internal/mcpconfig/mcpconfig.go
git commit -m "refactor(mcpconfig): split Parse I/O from parsing, add ParseBytes"
```

- [ ] **Step 5: Run the MCP classification tests**

Run: `go test ./internal/cli/ -run TestClassifyMCPPair -v`
Expected: all three PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/uninstall.go internal/cli/uninstall_test.go
git commit -m "feat(cli): classify MCP backup pairs with placeholder-aware comparison"
```

---

### Task 4.7: Build `placeholderResolver` from the vault

**Files:**
- Modify: `internal/cli/uninstall.go`
- Modify: `internal/cli/uninstall_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/cli/uninstall_test.go`:

```go
func TestResolverFromVault(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	v, err := openVault(root)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}

	resolver := resolverFromVault(v)
	found := false
	for ph, real := range resolver {
		if real == "ghp_real1234567890abcdef1234567890abcdef" && strings.HasPrefix(ph, "ghp_") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("resolver missing expected placeholder→real mapping; got: %v", resolver)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/cli/ -run TestResolverFromVault -v`
Expected: FAIL — `resolverFromVault` undefined.

- [ ] **Step 3: Implement the resolver builder**

Append to `internal/cli/uninstall.go`:

```go
// resolverFromVault returns a placeholderResolver mapping each credential's
// placeholder → real value. If the vault has credentials with Basic-auth
// username placeholders, those are included too.
func resolverFromVault(v *vault.Vault) placeholderResolver {
	resolver := make(placeholderResolver)
	for _, cred := range v.List() {
		if cred.Placeholder != "" {
			resolver[cred.Placeholder] = cred.Real
		}
		if cred.UsernamePlaceholder != "" {
			resolver[cred.UsernamePlaceholder] = cred.Username
		}
	}
	return resolver
}
```

Verify the vault exposes `List()` returning `[]*Credential` — if the existing method is named differently (e.g. `All()`), swap the name to match. Check:

```bash
grep -n 'func (v \*Vault)' internal/vault/vault.go | head -20
```

Adjust `resolverFromVault` to call whichever listing method exists. If the credential has no `Username` field, drop the two lines that reference it.

- [ ] **Step 4: Run the test**

Run: `go test ./internal/cli/ -run TestResolverFromVault -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/uninstall.go internal/cli/uninstall_test.go
git commit -m "feat(cli): build placeholder→real resolver from vault credentials"
```

---

## Phase 5 — The `uninstall` command

### Task 5.1: Scaffold `uninstallCmd()` and register it

**Files:**
- Modify: `internal/cli/uninstall.go`
- Modify: `internal/cli/root.go`

- [ ] **Step 1: Add command skeleton**

Append to `internal/cli/uninstall.go`:

```go
func uninstallCmd() *cobra.Command {
	var dryRun, yes, force bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Revert veil init: restore backups, wipe vault and state",
		Long: `Restore every file veil init modified from its .veil-backup, remove the
project vault, purge the keystore entry, and delete .veil/.

After a successful uninstall, the project is in its pre-init state
(modulo /.veil/ and *.veil-backup lines that remain in .gitignore).

Flags:
  --dry-run    Print the plan without making changes.
  --yes        Skip the interactive confirmation.
  --force      Proceed past "no backups" and "active proxy" guards.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUninstall(cmd, dryRun, yes, force)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the plan without making changes")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the interactive confirmation")
	cmd.Flags().BoolVar(&force, "force", false, "proceed past guards (no-backup, active-proxy)")
	return cmd
}

// runUninstall is filled in by subsequent tasks. For now it returns a
// not-implemented error so the command wires through the root registration.
func runUninstall(cmd *cobra.Command, dryRun, yes, force bool) error {
	return cliError("veil uninstall is not yet implemented", "")
}
```

Add `"github.com/spf13/cobra"` to imports if not already there.

- [ ] **Step 2: Register in `root.go`**

In `internal/cli/root.go`, find the block of `root.AddCommand(...)` calls starting around line 112:

```go
	root.AddCommand(initCmd())
	root.AddCommand(runCmd())
	root.AddCommand(statusCmd())
	root.AddCommand(addCmd())
	root.AddCommand(listCmd())
	root.AddCommand(logCmd())
	root.AddCommand(removeCmd())
	root.AddCommand(skipCmd())
	return root
```

Replace with:

```go
	root.AddCommand(initCmd())
	root.AddCommand(runCmd())
	root.AddCommand(statusCmd())
	root.AddCommand(addCmd())
	root.AddCommand(listCmd())
	root.AddCommand(logCmd())
	root.AddCommand(removeCmd())
	root.AddCommand(skipCmd())
	root.AddCommand(uninstallCmd())
	return root
```

- [ ] **Step 3: Verify the command is registered**

Run:

```bash
go run ./cmd/veil uninstall --help
```

Expected output includes "Revert veil init: restore backups, wipe vault and state" and the three flags.

- [ ] **Step 4: Commit**

```bash
git add internal/cli/uninstall.go internal/cli/root.go
git commit -m "feat(cli): scaffold veil uninstall subcommand (not-implemented stub)"
```

---

### Task 5.2: Implement `runUninstall` — discovery, guards, dry-run

**Files:**
- Modify: `internal/cli/uninstall.go`
- Modify: `internal/cli/uninstall_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/cli/uninstall_test.go`:

```go
func TestUninstallDryRunNoChanges(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	original := []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n")
	if err := os.WriteFile(envPath, original, 0644); err != nil {
		t.Fatal(err)
	}

	// Run init so we have a backup + vault.
	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	postInitEnv, _ := os.ReadFile(envPath)

	// Now dry-run uninstall.
	cmd = NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"uninstall", "--path", root, "--dry-run"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("uninstall --dry-run failed: %v", err)
	}

	// .env unchanged.
	got, _ := os.ReadFile(envPath)
	if string(got) != string(postInitEnv) {
		t.Error(".env was modified during --dry-run")
	}
	// Backup still present.
	if _, err := os.Stat(envPath + ".veil-backup"); err != nil {
		t.Error("backup was removed during --dry-run")
	}
	// .veil/ still present.
	if _, err := os.Stat(config.ProjectStateDir(root)); err != nil {
		t.Error(".veil/ was removed during --dry-run")
	}
	// Summary mentions the would-be restoration.
	if !strings.Contains(out.String(), ".env") {
		t.Errorf("expected .env in plan output, got: %s", out.String())
	}
}

func TestUninstallBlocksOnActiveProxy(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Drop a live PID file pointing at the test process.
	pidFile := filepath.Join(config.ProjectStateDir(root), fmt.Sprintf("proxy-%d.pid", os.Getpid()))
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}

	cmd = NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	stderr := new(bytes.Buffer)
	cmd.SetErr(stderr)
	cmd.SetArgs([]string{"uninstall", "--path", root, "--yes"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected uninstall to fail with active proxy")
	}
	if !strings.Contains(stderr.String(), "active proxy") {
		t.Errorf("expected 'active proxy' in stderr, got: %s", stderr.String())
	}
}

func TestUninstallForceBypassesProxyGuard(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	pidFile := filepath.Join(config.ProjectStateDir(root), fmt.Sprintf("proxy-%d.pid", os.Getpid()))
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}

	cmd = NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"uninstall", "--path", root, "--yes", "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("uninstall --force failed: %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cli/ -run TestUninstall -v`
Expected: FAIL — `runUninstall` returns the not-implemented stub.

- [ ] **Step 3: Implement `runUninstall`**

Replace the stub `runUninstall` in `internal/cli/uninstall.go` with:

```go
func runUninstall(cmd *cobra.Command, dryRun, yes, force bool) error {
	root, err := resolveRoot()
	if err != nil {
		return cliError(err.Error(), "")
	}

	w := cmd.OutOrStdout()
	ew := cmd.ErrOrStderr()

	// Active-proxy guard.
	live, err := activeProxyPIDs(root)
	if err != nil {
		return wrapErr("checking active proxies", err)
	}
	if len(live) > 0 && !force {
		return cliError(
			fmt.Sprintf("active proxy processes found (PIDs: %s); stop them or pass --force", formatPIDList(live)),
			"Run `veil status` to identify, then `kill <pid>`.",
		)
	}

	// Discover backup pairs.
	pairs, err := discoverBackups(root)
	if err != nil {
		return wrapErr("discovering backups", err)
	}

	stateDir := config.ProjectStateDir(root)
	_, stateErr := os.Stat(stateDir)
	stateExists := stateErr == nil

	if len(pairs) == 0 && !stateExists {
		_, _ = fmt.Fprintln(w, "already uninstalled")
		return nil
	}
	if len(pairs) == 0 && !force {
		return cliError(
			"no .veil-backup files found, but .veil/ exists",
			"Use --force to wipe state without restoring any files, or run `veil list` to inspect the vault manually.",
		)
	}

	// Build placeholder resolver from the vault (best-effort: nil on failure).
	var resolver placeholderResolver
	if stateExists {
		if v, err := openVault(root); err == nil {
			resolver = resolverFromVault(v)
		} else {
			ui.Warnf(ew, "could not open vault for placeholder resolution: %v", err)
		}
	}

	// Classify each pair.
	type planned struct {
		pair   backupPair
		status classification
		diff   string
	}
	plan := make([]planned, 0, len(pairs))
	for _, p := range pairs {
		var (
			status classification
			diff   string
			cerr   error
		)
		if p.kind == backupKindMCP {
			status, diff, cerr = classifyMCPPair(p.original, p.backup, resolver)
		} else {
			status, diff, cerr = classifyEnvPair(p.original, p.backup, resolver)
		}
		if cerr != nil {
			return wrapErr(fmt.Sprintf("classifying %s", p.original), cerr)
		}
		plan = append(plan, planned{pair: p, status: status, diff: diff})
	}

	// Print plan.
	_, _ = fmt.Fprintln(w, "Uninstall plan:")
	for _, pl := range plan {
		label := classLabel(pl.status)
		_, _ = fmt.Fprintf(w, "  [%s] %s\n", label, pl.pair.original)
		if pl.status == classModified && pl.diff != "" {
			_, _ = fmt.Fprintln(w, pl.diff)
		}
	}
	if stateExists {
		_, _ = fmt.Fprintf(w, "  [wipe]     %s\n", stateDir)
	}

	if dryRun {
		return nil
	}

	// Confirm (unless --yes).
	if !yes && !promptYN(newLineReader(cmd.InOrStdin()), w, "Proceed with uninstall?", false) {
		_, _ = fmt.Fprintln(w, "Aborted.")
		return nil
	}

	// Execute restoration.
	restored := 0
	for _, pl := range plan {
		if err := os.Rename(pl.pair.backup, pl.pair.original); err != nil {
			return wrapErr(fmt.Sprintf("restoring %s", pl.pair.original), err)
		}
		restored++
	}

	// Purge keystore entry (best-effort).
	if stateExists {
		if pid, err := vault.ReadProjectID(root); err == nil {
			if ks, err := buildKeystore(); err == nil {
				if delErr := ks.Delete(pid); delErr != nil {
					ui.Warnf(ew, "could not purge keystore entry: %v", delErr)
				}
			} else {
				ui.Warnf(ew, "could not select keystore for purge: %v", err)
			}
		} else {
			ui.Warnf(ew, "could not read project ID: %v", err)
		}

		if err := os.RemoveAll(stateDir); err != nil {
			return wrapErr(fmt.Sprintf("removing %s", stateDir), err)
		}
	}

	_, _ = fmt.Fprintf(w, "\nRestored %d %s.\n", restored, plural(restored, "file", "files"))
	if stateExists {
		_, _ = fmt.Fprintln(w, "State directory removed; keystore entry purged.")
	}
	return nil
}

// classLabel returns a short label for display in the plan table.
func classLabel(c classification) string {
	switch c {
	case classUnmodified:
		return "restore "
	case classModified:
		return "modified"
	case classOriginalMissing:
		return "restore*"
	default:
		return "?       "
	}
}
```

- [ ] **Step 4: Verify imports**

Ensure `internal/cli/uninstall.go` imports:

```go
import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/mcpconfig"
	"github.com/8enji/veil/internal/scanner"
	"github.com/8enji/veil/internal/ui"
	"github.com/8enji/veil/internal/vault"
	"github.com/spf13/cobra"
)
```

- [ ] **Step 5: Run the three uninstall tests**

Run: `go test ./internal/cli/ -run TestUninstall -v`
Expected: all three PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/uninstall.go internal/cli/uninstall_test.go
git commit -m "feat(cli): implement veil uninstall command"
```

---

### Task 5.3: Integration test — round-trip fidelity

**Files:**
- Modify: `internal/cli/uninstall_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/cli/uninstall_test.go`:

```go
func TestUninstallRoundTripFidelity(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	original := []byte("# header\nTOKEN=ghp_real1234567890abcdef1234567890abcdef\nLOG=debug\n")
	if err := os.WriteFile(envPath, original, 0644); err != nil {
		t.Fatal(err)
	}

	// Init.
	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Uninstall.
	cmd = NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"uninstall", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}

	// .env must be bit-identical to the original.
	got, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf(".env after uninstall does not match original\ngot:  %q\nwant: %q", got, original)
	}

	// .veil/ must be gone.
	if _, err := os.Stat(config.ProjectStateDir(root)); !os.IsNotExist(err) {
		t.Error(".veil/ should be removed after uninstall")
	}

	// Backup must be gone (renamed onto original).
	if _, err := os.Stat(envPath + ".veil-backup"); !os.IsNotExist(err) {
		t.Error(".veil-backup should be renamed away after uninstall")
	}
}

func TestUninstallMultiFile(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	envOrig := []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n")
	localOrig := []byte("API_KEY=sk-live-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	if err := os.WriteFile(filepath.Join(root, ".env"), envOrig, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env.local"), localOrig, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	cmd = NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"uninstall", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}

	got, _ := os.ReadFile(filepath.Join(root, ".env"))
	if !bytes.Equal(got, envOrig) {
		t.Errorf(".env mismatch\ngot:  %q\nwant: %q", got, envOrig)
	}
	got, _ = os.ReadFile(filepath.Join(root, ".env.local"))
	if !bytes.Equal(got, localOrig) {
		t.Errorf(".env.local mismatch\ngot:  %q\nwant: %q", got, localOrig)
	}
}

func TestUninstallNoOpAfterPriorUninstall(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// init then uninstall.
	for _, args := range [][]string{
		{"init", "--path", root, "--yes"},
		{"uninstall", "--path", root, "--yes"},
	} {
		cmd := NewRoot("test")
		cmd.SetOut(new(bytes.Buffer))
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("%v failed: %v", args, err)
		}
	}

	// Second uninstall — should say "already uninstalled" and exit 0.
	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"uninstall", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("second uninstall failed: %v", err)
	}
	if !strings.Contains(out.String(), "already uninstalled") {
		t.Errorf("expected 'already uninstalled' in output, got: %s", out.String())
	}
}

func TestUninstallUserEditOverwrittenWithYes(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	original := []byte("TOKEN=ghp_real1234567890abcdef1234567890abcdef\n")
	if err := os.WriteFile(envPath, original, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// User adds a new line post-init.
	current, _ := os.ReadFile(envPath)
	edited := append(current, []byte("LOG_LEVEL=debug\n")...)
	if err := os.WriteFile(envPath, edited, 0644); err != nil {
		t.Fatal(err)
	}

	// Uninstall with --yes should proceed and restore to backup (loses the edit).
	cmd = NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"uninstall", "--path", root, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}

	got, _ := os.ReadFile(envPath)
	if !bytes.Equal(got, original) {
		t.Errorf(".env after uninstall should equal original (edit lost)\ngot:  %q\nwant: %q", got, original)
	}
}
```

- [ ] **Step 2: Run the integration tests**

Run: `go test ./internal/cli/ -run "TestUninstallRoundTripFidelity|TestUninstallMultiFile|TestUninstallNoOpAfterPriorUninstall|TestUninstallUserEditOverwrittenWithYes" -v`
Expected: all PASS.

- [ ] **Step 3: Run the full CLI test suite**

Run: `go test ./internal/cli/ -v`
Expected: all PASS — no regressions in existing init/add/list/run tests.

- [ ] **Step 4: Run the full repository test suite**

Run: `go test ./...`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/uninstall_test.go
git commit -m "test(cli): add integration tests for uninstall round-trip fidelity"
```

---

### Task 5.4: Final documentation sweep

**Files:**
- Modify: `internal/cli/root.go` (Long description of root)
- Modify: `README.md` (if present — optional; skip unless the README already documents commands)

- [ ] **Step 1: Check README**

Run: `grep -l "veil init" README.md 2>/dev/null`

If README.md references `veil init` command docs, add a `veil uninstall` section in the same style. If not, skip this task entirely.

- [ ] **Step 2: Verify top-level help**

Run: `go run ./cmd/veil --help`

Expected: `uninstall` appears in the "Available Commands" list with its short description.

- [ ] **Step 3: If README was updated, commit**

```bash
git add README.md
git commit -m "docs: document veil uninstall in README"
```

---

## Phase 6 — Final verification

### Task 6.1: Full test + lint pass

- [ ] **Step 1: Run the full test suite with race detector**

Run: `go test -race ./...`
Expected: all PASS.

- [ ] **Step 2: Run linters if configured**

Run: `go vet ./...`
Expected: no complaints.

If `golangci-lint` is configured (check `.golangci.yml`):

Run: `golangci-lint run ./...`
Expected: clean or only pre-existing findings.

- [ ] **Step 3: Smoke test in a real project**

```bash
mkdir -p /tmp/veil-smoke && cd /tmp/veil-smoke
git init -q
echo 'GITHUB_TOKEN=ghp_real1234567890abcdef1234567890abcdef' > .env

go run <path-to-repo>/cmd/veil init --yes
cat .env                         # should contain a placeholder
cat .env.veil-backup             # should contain the real token
ls .veil/                        # should contain vault.bin, etc.

go run <path-to-repo>/cmd/veil uninstall --yes
cat .env                         # back to the original real token
ls .env.veil-backup 2>/dev/null  # should not exist
ls .veil/ 2>/dev/null            # should not exist
```

Expected: round-trip returns .env to its pre-init content; no `.veil/` directory remains.

- [ ] **Step 4: No commit needed** (verification only)

---

## Self-Review Checklist

After completing all tasks, verify against the spec:

- [ ] `.env` backup at init time (spec § 1): Phase 2 (tasks 2.1–2.3).
- [ ] `writeBackupIfMissing` shared primitive (spec "Shared primitive"): Phase 1 (tasks 1.1–1.3) — split into `backupExists` + `writeBackup` with the rationale noted in Phase 1 intro.
- [ ] `veil uninstall` subcommand with `--dry-run` / `--yes` / `--force` (spec § 2): Phase 5 (tasks 5.1–5.3).
- [ ] Active-proxy guard (spec § 5): Phase 4 (task 4.2); integration test in 5.2.
- [ ] Backup discovery (spec § 2 step 3): Phase 4 (task 4.3).
- [ ] Classification (spec § 3): Phase 4 (tasks 4.4, 4.6).
- [ ] Unified diff (spec § 3): Phase 4 (task 4.5).
- [ ] State directory + keystore cleanup (spec § 4): Phase 5 (task 5.2); `vault.ReadProjectID` in task 4.1.
- [ ] Errors, exit codes, edge cases (spec § 6): covered across tasks 5.2, 5.3, 4.2.
- [ ] Unit tests (spec § 7): present in each primitive task (1.1, 1.2, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7).
- [ ] Integration tests (spec § 7): 5.2 (dry-run, active-proxy, force), 5.3 (round-trip, multi-file, no-op, user-edit).
- [ ] `.gitignore` extension (spec § 1): Phase 3 (task 3.1).
