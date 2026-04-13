# MVP Feature Gaps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship 15 work items (new features, enhancements, defensive edge cases, polish) to make `veil run claude` a polished MVP experience for indie developers.

**Architecture:** All changes are in the existing Go CLI codebase. New commands follow the established cobra pattern (one file per command in `internal/cli/`). Tests follow the existing pattern: `t.Setenv("VEIL_TEST_KEYSTORE", "mem")`, `NewRoot("test")` with buffer-captured output. No new dependencies.

**Tech Stack:** Go 1.26, cobra, fatih/color, SQLite (modernc.org/sqlite), OS keychain (go-keyring)

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `internal/cli/remove.go` | Create | `veil remove` command |
| `internal/cli/add.go` | Modify | `--value` flag, piped stdin, output styling, `--force` placeholder sync |
| `internal/cli/list.go` | Modify | `--placeholder` flag |
| `internal/cli/log.go` | Modify | Empty state messaging |
| `internal/cli/status.go` | Modify | Proxy running indicator |
| `internal/cli/run.go` | Modify | Proxy startup error mapping |
| `internal/cli/root.go` | Modify | Register `remove`, custom help/version |
| `internal/cli/errors.go` | Modify | Proxy startup error helper |
| `internal/cli/cli_test.go` | Modify | Tests for remove, add enhancements, list, log, status |
| `internal/runner/runner.go` | Modify | Zero-cred warning, exit summary, PID file |
| `internal/runner/pidfile.go` | Create | PID file write/read/clean |
| `internal/runner/signals.go` | Modify | Escalation (SIGINT → SIGTERM → SIGKILL) |
| `internal/runner/runner_test.go` | Modify | Tests for exit summary, zero-cred warning |
| `internal/runner/pidfile_test.go` | Create | PID file tests |
| `internal/runner/signals_test.go` | Modify | Escalation test |
| `internal/vault/vault.go` | Modify | Better error messages for corruption/collision |
| `internal/vault/vault_test.go` | Modify | Tests for improved errors |
| `internal/config/paths.go` | Modify | Add `PidFile` path helper |

---

### Task 1: `veil remove` Command

**Files:**
- Create: `internal/cli/remove.go`
- Modify: `internal/cli/root.go:42` (register command)
- Test: `internal/cli/cli_test.go`

- [ ] **Step 1: Write the failing test for `veil remove`**

Add to `internal/cli/cli_test.go`:

```go
func TestRemove(t *testing.T) {
	root := initProject(t)

	// Add a credential.
	addCmd := NewRoot("test")
	addCmd.SetOut(new(bytes.Buffer))
	addCmd.SetErr(new(bytes.Buffer))
	addCmd.SetIn(strings.NewReader("my-secret-value-123456\n"))
	addCmd.SetArgs([]string{"add", "--path", root, "MY_SECRET"})
	if err := addCmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	// Remove it.
	rmCmd := NewRoot("test")
	rmOut := new(bytes.Buffer)
	rmCmd.SetOut(rmOut)
	rmCmd.SetErr(new(bytes.Buffer))
	rmCmd.SetArgs([]string{"remove", "--path", root, "--force", "MY_SECRET"})
	if err := rmCmd.Execute(); err != nil {
		t.Fatalf("remove failed: %v", err)
	}
	if !strings.Contains(rmOut.String(), "Removed MY_SECRET") {
		t.Errorf("expected removal confirmation, got: %s", rmOut.String())
	}

	// Verify it's gone from list.
	listCmd := NewRoot("test")
	listOut := new(bytes.Buffer)
	listCmd.SetOut(listOut)
	listCmd.SetErr(new(bytes.Buffer))
	listCmd.SetArgs([]string{"list", "--path", root})
	if err := listCmd.Execute(); err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if strings.Contains(listOut.String(), "MY_SECRET") {
		t.Error("MY_SECRET should not appear in list after removal")
	}
}

func TestRemoveNonexistent(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"remove", "--path", root, "--force", "NONEXISTENT"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent credential")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestRemove -v -timeout 30s`

Expected: FAIL — "remove" command not recognized.

- [ ] **Step 3: Create `internal/cli/remove.go`**

```go
package cli

import (
	"fmt"
	"strings"

	"github.com/8enji/veil/internal/ui"
	"github.com/spf13/cobra"
)

func removeCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a credential from the vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemove(cmd, args[0], force)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "skip confirmation prompt")
	return cmd
}

func runRemove(cmd *cobra.Command, name string, force bool) error {
	root, err := resolveRoot()
	if err != nil {
		return cliError(err.Error(), "")
	}

	v, err := openVault(root)
	if err != nil {
		return cliError(fmt.Sprintf("opening vault: %v", err), "")
	}

	// Check the credential exists before prompting.
	cred, found := v.Get(name)
	if !found {
		return cliError(fmt.Sprintf("credential %q not found", name), "Run veil list to see available credentials")
	}

	// Confirm unless --force.
	if !force {
		fmt.Fprintf(cmd.ErrOrStderr(), "Remove %s from vault? [y/N] ", name)
		var answer string
		fmt.Fscanln(cmd.InOrStdin(), &answer)
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" {
			fmt.Fprintln(cmd.OutOrStdout(), "Cancelled.")
			return nil
		}
	}

	w := cmd.OutOrStdout()

	deleted, err := v.Delete(name)
	if err != nil {
		return cliError(fmt.Sprintf("removing credential: %v", err), "")
	}
	if !deleted {
		return cliError(fmt.Sprintf("credential %q not found", name), "")
	}

	ui.Step(w, fmt.Sprintf("Removed %s from vault", name))
	if len(cred.AllowedHosts) > 0 {
		fmt.Fprintf(w, "    %s\n", ui.Muted.Sprintf("Hosts: %s", strings.Join(cred.AllowedHosts, ", ")))
	}
	ui.Warn(w, "Placeholder in .env will no longer be injected")

	return nil
}
```

- [ ] **Step 4: Register the command in `root.go`**

In `internal/cli/root.go`, add after the `root.AddCommand(logCmd())` line (line 47):

```go
root.AddCommand(removeCmd())
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestRemove -v -timeout 30s`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/cli/remove.go internal/cli/root.go internal/cli/cli_test.go
git commit -m "feat(cli): add veil remove command"
```

---

### Task 2: Non-Interactive `veil add` (`--value` Flag + Piped Stdin)

**Files:**
- Modify: `internal/cli/add.go`
- Test: `internal/cli/cli_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `internal/cli/cli_test.go`:

```go
func TestAddWithValueFlag(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"add", "--path", root, "--value", "my-api-key-1234567890", "API_KEY"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add --value failed: %v", err)
	}
	if !strings.Contains(out.String(), "Added API_KEY") {
		t.Errorf("expected confirmation, got: %s", out.String())
	}

	// Verify it's in the vault.
	listCmd := NewRoot("test")
	listOut := new(bytes.Buffer)
	listCmd.SetOut(listOut)
	listCmd.SetErr(new(bytes.Buffer))
	listCmd.SetArgs([]string{"list", "--path", root})
	if err := listCmd.Execute(); err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if !strings.Contains(listOut.String(), "API_KEY") {
		t.Errorf("API_KEY should appear in list, got: %s", listOut.String())
	}
}

func TestAddWithValueFlagEmpty(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"add", "--path", root, "--value", "", "API_KEY"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for empty value")
	}
	if !strings.Contains(err.Error(), "no value") {
		t.Errorf("error should mention 'no value', got: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestAddWithValue -v -timeout 30s`

Expected: FAIL — unknown flag `--value`.

- [ ] **Step 3: Add `--value` flag to `internal/cli/add.go`**

In `addCmd()`, add the flag declaration after the `--host` flag (around line 23):

```go
var value string
```

Add to the flags section (after line 26):

```go
cmd.Flags().StringVar(&value, "value", "", "secret value (alternative to stdin prompt)")
```

Update the `RunE` closure to pass `value`:

```go
RunE: func(cmd *cobra.Command, args []string) error {
    return runAdd(cmd, args[0], force, hosts, value)
},
```

Update `runAdd` signature and value-reading logic. Replace the function signature at line 30:

```go
func runAdd(cmd *cobra.Command, name string, force bool, hosts []string, flagValue string) error {
```

Replace the stdin-reading block (lines 42-51) with:

```go
	var value string
	if flagValue != "" {
		value = flagValue
	} else {
		// Read value from stdin.
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Enter value for %s: ", name)
		reader := bufio.NewReader(cmd.InOrStdin())
		raw, err := reader.ReadString('\n')
		if err != nil {
			// Accept EOF without newline (e.g. piped input).
			if raw == "" {
				return cliError("no value provided", "")
			}
		}
		value = strings.TrimRight(raw, "\r\n")
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestAddWithValue -v -timeout 30s`

Expected: PASS

- [ ] **Step 5: Run all existing add tests to check for regressions**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestAdd -v -timeout 30s`

Expected: PASS — TestAddAndList, TestAddForce still pass.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/add.go internal/cli/cli_test.go
git commit -m "feat(cli): add --value flag to veil add for non-interactive use"
```

---

### Task 3: `veil add` Output Consistency

**Files:**
- Modify: `internal/cli/add.go`
- Test: `internal/cli/cli_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/cli/cli_test.go`:

```go
func TestAddOutputShowsPlaceholderAndHosts(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"add", "--path", root, "--value", "ghp_test1234567890abcdef1234567890abcdef", "GITHUB_TOKEN"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add failed: %v", err)
	}
	output := out.String()

	// Should show styled success with checkmark.
	if !strings.Contains(output, "✓") {
		t.Errorf("expected checkmark in output, got: %s", output)
	}
	// Should show the placeholder value.
	if !strings.Contains(output, "Placeholder:") {
		t.Errorf("expected placeholder display, got: %s", output)
	}
	// Should show detected hosts.
	if !strings.Contains(output, "api.github.com") {
		t.Errorf("expected auto-detected host in output, got: %s", output)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestAddOutputShowsPlaceholder -v -timeout 30s`

Expected: FAIL — output doesn't contain "✓" or "Placeholder:".

- [ ] **Step 3: Restyle `veil add` output in `internal/cli/add.go`**

Replace the success output block at the end of `runAdd` (everything after `v.Add(cred)` succeeds, roughly lines 90-96) with:

```go
	w := cmd.OutOrStdout()
	ui.Step(w, fmt.Sprintf("Added %s to vault", name))
	fmt.Fprintf(w, "    %s %s\n", ui.Muted.Sprint("Placeholder:"), cred.Placeholder)
	if len(allowedHosts) > 0 {
		fmt.Fprintf(w, "    %s %s\n", ui.Muted.Sprint("Hosts:"), strings.Join(allowedHosts, ", "))
	} else {
		ui.Warn(w, fmt.Sprintf("No target hosts detected for %s", name))
		fmt.Fprintf(w, "    %s\n", ui.Muted.Sprint("Use veil add --host to scope it"))
	}
```

Add `"github.com/8enji/veil/internal/ui"` to the imports if not already present.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestAddOutputShowsPlaceholder -v -timeout 30s`

Expected: PASS

- [ ] **Step 5: Update `TestAddAndList` assertion**

The existing `TestAddAndList` checks for `"Added CUSTOM_SECRET"`. The new output uses `ui.Step` which includes a checkmark. Update the assertion in `TestAddAndList` to check for `"CUSTOM_SECRET"` instead of `"Added CUSTOM_SECRET"` to be resilient to styling changes:

```go
if !strings.Contains(addOut.String(), "CUSTOM_SECRET") {
    t.Errorf("expected confirmation, got: %s", addOut.String())
}
```

- [ ] **Step 6: Run full add test suite**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestAdd -v -timeout 30s`

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/cli/add.go internal/cli/cli_test.go
git commit -m "feat(cli): restyle veil add output with placeholder and host display"
```

---

### Task 4: `veil add --force` Placeholder Sync

**Files:**
- Modify: `internal/cli/add.go`
- Test: `internal/cli/cli_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/cli/cli_test.go`:

```go
func TestAddForceUpdatesEnvFile(t *testing.T) {
	root := initProject(t)

	// Read the .env to find the existing placeholder for OPENAI_API_KEY.
	envData, err := os.ReadFile(filepath.Join(root, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	var oldPlaceholder string
	for _, line := range strings.Split(string(envData), "\n") {
		if strings.HasPrefix(line, "OPENAI_API_KEY=") {
			oldPlaceholder = strings.TrimPrefix(line, "OPENAI_API_KEY=")
			break
		}
	}
	if oldPlaceholder == "" {
		t.Fatal("could not find OPENAI_API_KEY placeholder in .env")
	}

	// Force-replace OPENAI_API_KEY with a new value.
	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"add", "--path", root, "--force", "--value", "sk-proj-newkey9876543210fedcba", "OPENAI_API_KEY"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add --force failed: %v", err)
	}

	// Read .env again — the old placeholder should be replaced with the new one.
	envData2, err := os.ReadFile(filepath.Join(root, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	envStr := string(envData2)
	if strings.Contains(envStr, oldPlaceholder) {
		t.Error("old placeholder should have been replaced in .env")
	}
	if !strings.Contains(envStr, "OPENAI_API_KEY=") {
		t.Error("OPENAI_API_KEY key should still exist in .env")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestAddForceUpdatesEnvFile -v -timeout 30s`

Expected: FAIL — old placeholder still present in `.env`.

- [ ] **Step 3: Add placeholder sync to `--force` path in `internal/cli/add.go`**

In `runAdd`, after the `--force` delete block and before `v.Add(cred)`, add `.env` rewrite logic. Replace the `--force` handling block:

```go
	// Handle --force: delete existing credential, capture old placeholder for .env sync.
	var oldPlaceholder string
	if force {
		if existing, found := v.Get(name); found {
			oldPlaceholder = existing.Placeholder
		}
		_, _ = v.Delete(name)
	}
```

After `v.Add(cred)` succeeds and before the output block, add:

```go
	// If --force replaced a credential, update .env files with the new placeholder.
	if oldPlaceholder != "" && oldPlaceholder != cred.Placeholder {
		updated := syncPlaceholderInEnvFiles(root, oldPlaceholder, cred.Placeholder)
		if updated > 0 {
			ui.Step(w, fmt.Sprintf("Updated placeholder in %d .env %s", updated, plural(updated, "file", "files")))
		}
	}
```

Add the `syncPlaceholderInEnvFiles` helper at the bottom of `add.go`:

```go
// syncPlaceholderInEnvFiles replaces oldPh with newPh in all .env files under root.
// Returns the number of files updated.
func syncPlaceholderInEnvFiles(root, oldPh, newPh string) int {
	envPaths, err := scanner.Scan(root)
	if err != nil {
		return 0
	}
	var count int
	for _, path := range envPaths {
		data, err := os.ReadFile(path) // #nosec G304
		if err != nil {
			continue
		}
		content := string(data)
		if !strings.Contains(content, oldPh) {
			continue
		}
		updated := strings.ReplaceAll(content, oldPh, newPh)
		if err := atomicWriteFile(path, []byte(updated)); err != nil {
			continue
		}
		count++
	}
	return count
}
```

Add `"github.com/8enji/veil/internal/scanner"` and `"os"` to the imports.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestAddForceUpdatesEnvFile -v -timeout 30s`

Expected: PASS

- [ ] **Step 5: Run all add tests**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestAdd -v -timeout 30s`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/cli/add.go internal/cli/cli_test.go
git commit -m "feat(cli): sync .env placeholders on veil add --force"
```

---

### Task 5: `veil list --placeholder` Flag

**Files:**
- Modify: `internal/cli/list.go`
- Test: `internal/cli/cli_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/cli/cli_test.go`:

```go
func TestListPlaceholder(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"list", "--path", root, "--placeholder"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("list --placeholder failed: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "PLACEHOLDER") {
		t.Errorf("expected PLACEHOLDER column header, got: %s", output)
	}
	// The placeholder for OPENAI_API_KEY should start with sk-proj- (format-aware).
	if !strings.Contains(output, "sk-proj-") {
		t.Errorf("expected placeholder value with sk-proj- prefix, got: %s", output)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestListPlaceholder -v -timeout 30s`

Expected: FAIL — unknown flag `--placeholder`.

- [ ] **Step 3: Add `--placeholder` flag to `internal/cli/list.go`**

In `listCmd()`, add the flag declaration alongside `reveal` (around line 17):

```go
var reveal, showPlaceholder bool
```

Update the command flags (after line 23):

```go
cmd.Flags().BoolVar(&showPlaceholder, "placeholder", false, "show placeholder values")
```

Update the `RunE` call:

```go
return runList(cmd, reveal, showPlaceholder)
```

Update `runList` signature:

```go
func runList(cmd *cobra.Command, reveal, showPlaceholder bool) error {
```

In the `row` struct (around line 63), add a `placeholder` field:

```go
type row struct {
    name, hosts, value, placeholder, source, last string
}
```

In the row-building loop, add placeholder population:

```go
if showPlaceholder {
    r.placeholder = c.Placeholder
}
```

In the column-width computation, add:

```go
phW := len("PLACEHOLDER")
```

And in the loop:

```go
if showPlaceholder {
    phW = maxInt(phW, len(r.placeholder))
}
```

Add a new branch for `showPlaceholder` output (between the `reveal` and default branches). The full output section should handle three cases: `reveal`, `showPlaceholder`, and default. Add the `showPlaceholder` case:

```go
} else if showPlaceholder {
    fmt.Fprintf(out, "%s%s%s%s%s%s%s%s%s\n",
        ui.Muted.Sprint(padRight("NAME", nameW)), gap,
        ui.Muted.Sprint(padRight("HOSTS", hostsW)), gap,
        ui.Muted.Sprint(padRight("PLACEHOLDER", phW)), gap,
        ui.Muted.Sprint(padRight("SOURCE", sourceW)), gap,
        ui.Muted.Sprint("LAST INJECTED"))
    for _, r := range rows {
        hosts := styleHosts(r.hosts, hostsW)
        fmt.Fprintf(out, "%s%s%s%s%s%s%s%s%s\n",
            padRight(r.name, nameW), gap,
            hosts, gap,
            padRight(r.placeholder, phW), gap,
            padRight(r.source, sourceW), gap,
            r.last)
    }
} else {
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestListPlaceholder -v -timeout 30s`

Expected: PASS

- [ ] **Step 5: Run full list tests**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestList -v -timeout 30s`

Expected: PASS — TestListEmpty still passes.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/list.go internal/cli/cli_test.go
git commit -m "feat(cli): add --placeholder flag to veil list"
```

---

### Task 6: `veil log` Empty State Messaging

**Files:**
- Modify: `internal/cli/log.go`
- Test: `internal/cli/cli_test.go`

- [ ] **Step 1: Update the test expectation**

In `internal/cli/cli_test.go`, find `TestLogEmpty` (around line 139). Update the assertion to check for the new message. Replace:

```go
if !strings.Contains(out.String(), "No injection events found") {
    t.Errorf("expected empty log message, got: %s", out.String())
}
if !strings.Contains(out.String(), "veil run") {
    t.Errorf("expected hint about 'veil run', got: %s", out.String())
}
```

With:

```go
output := out.String()
if !strings.Contains(output, "No credential injections") {
    t.Errorf("expected empty log message, got: %s", output)
}
if !strings.Contains(output, "proxy was active") {
    t.Errorf("expected proxy-active clarification, got: %s", output)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestLogEmpty -v -timeout 30s`

Expected: FAIL — old message doesn't match.

- [ ] **Step 3: Update empty state message in `internal/cli/log.go`**

In `runLog`, replace the empty-state block (lines 89-91):

```go
if len(rows) == 0 {
    _, _ = fmt.Fprintln(w, "No injection events found.")
    _, _ = fmt.Fprintf(w, "  %s\n", ui.Muted.Sprint("Injections are logged when you run commands through veil run"))
    return nil
}
```

With:

```go
if len(rows) == 0 {
    _, _ = fmt.Fprintln(w, "No credential injections during this period.")
    _, _ = fmt.Fprintf(w, "  %s\n", ui.Muted.Sprint("The proxy was active but no managed credentials were used in outbound requests"))
    return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestLogEmpty -v -timeout 30s`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/cli/log.go internal/cli/cli_test.go
git commit -m "fix(cli): improve veil log empty state messaging"
```

---

### Task 7: PID File for Proxy

**Files:**
- Create: `internal/runner/pidfile.go`
- Create: `internal/runner/pidfile_test.go`
- Modify: `internal/config/paths.go`
- Modify: `internal/runner/runner.go`

- [ ] **Step 1: Add `PidFile` path helper to `internal/config/paths.go`**

Add at the end of `internal/config/paths.go`:

```go
func PidFile(root string) string {
	return filepath.Join(ProjectStateDir(root), "proxy.pid")
}
```

- [ ] **Step 2: Write the failing test for PID file operations**

Create `internal/runner/pidfile_test.go`:

```go
package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAndReadPidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.pid")

	if err := WritePidFile(path, 12345); err != nil {
		t.Fatalf("write pid file: %v", err)
	}

	pid, err := ReadPidFile(path)
	if err != nil {
		t.Fatalf("read pid file: %v", err)
	}
	if pid != 12345 {
		t.Errorf("expected pid 12345, got %d", pid)
	}

	RemovePidFile(path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("pid file should be removed")
	}
}

func TestReadPidFileMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent.pid")
	_, err := ReadPidFile(path)
	if err == nil {
		t.Fatal("expected error for missing pid file")
	}
}

func TestReadPidFileCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.pid")
	if err := os.WriteFile(path, []byte("not-a-number\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadPidFile(path)
	if err == nil {
		t.Fatal("expected error for corrupt pid file")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/runner/ -run TestWriteAndReadPid -v -timeout 30s`

Expected: FAIL — `WritePidFile` not defined.

- [ ] **Step 4: Create `internal/runner/pidfile.go`**

```go
package runner

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// WritePidFile writes the given PID to path atomically.
func WritePidFile(path string, pid int) error {
	return os.WriteFile(path, []byte(fmt.Sprintf("%d\n", pid)), 0600)
}

// ReadPidFile reads and parses the PID from a pid file.
func ReadPidFile(path string) (int, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("invalid pid file: %w", err)
	}
	return pid, nil
}

// RemovePidFile removes the pid file at path. Errors are ignored.
func RemovePidFile(path string) {
	_ = os.Remove(path)
}

// IsProcessAlive checks if a process with the given PID is running.
func IsProcessAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds. Send signal 0 to check liveness.
	err = proc.Signal(syscall.Signal(0))
	return err == nil
}
```

Add `"syscall"` to imports.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/runner/ -run TestPid -v -timeout 30s`

Expected: PASS

- [ ] **Step 6: Wire PID file into `runner.go`**

In `internal/runner/runner.go`, after `server.Start()` (around line 84), add:

```go
	// Write PID file for veil status to detect running proxy.
	pidPath := config.PidFile(cfg.Root)
	if err := WritePidFile(pidPath, os.Getpid()); err != nil {
		// Non-fatal — status won't detect proxy, but run still works.
		fmt.Fprintf(os.Stderr, "%s\n", ui.Muted.Sprintf("warning: could not write pid file: %v", err))
	}
	defer RemovePidFile(pidPath)
```

- [ ] **Step 7: Run full runner tests**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/runner/ -v -timeout 60s`

Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/runner/pidfile.go internal/runner/pidfile_test.go internal/config/paths.go internal/runner/runner.go
git commit -m "feat(runner): add proxy PID file for status detection"
```

---

### Task 8: `veil status` Proxy Running Indicator

**Files:**
- Modify: `internal/cli/status.go`
- Test: `internal/cli/cli_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/cli/cli_test.go`:

```go
func TestStatusShowsProxyNotRunning(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"status", "--path", root})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("status failed: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "Proxy") {
		t.Errorf("status should show Proxy line, got: %s", output)
	}
	if !strings.Contains(output, "not running") {
		t.Errorf("status should show 'not running' when proxy is inactive, got: %s", output)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestStatusShowsProxy -v -timeout 30s`

Expected: FAIL — output doesn't contain "Proxy".

- [ ] **Step 3: Add proxy indicator to `internal/cli/status.go`**

Add import for `"github.com/8enji/veil/internal/runner"`.

In `runStatus`, after the CA section (after line 89) and before the blank line, add:

```go
	// Proxy status.
	pidPath := config.PidFile(root)
	pid, pidErr := runner.ReadPidFile(pidPath)
	if pidErr == nil && runner.IsProcessAlive(pid) {
		_, _ = fmt.Fprintf(w, "  %s        %s %s\n",
			ui.Bold.Sprint("Proxy"),
			ui.Success.Sprint("active"),
			ui.Muted.Sprintf("(PID %d)", pid),
		)
	} else {
		_, _ = fmt.Fprintf(w, "  %s        %s\n",
			ui.Bold.Sprint("Proxy"),
			ui.Muted.Sprint("not running"),
		)
	}
```

Add `"github.com/8enji/veil/internal/runner"` to imports.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestStatusShowsProxy -v -timeout 30s`

Expected: PASS

- [ ] **Step 5: Run full status tests**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestStatus -v -timeout 30s`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/cli/status.go internal/cli/cli_test.go
git commit -m "feat(cli): show proxy running indicator in veil status"
```

---

### Task 9: `veil run` Zero-Credential Warning + Exit Summary Accuracy

**Files:**
- Modify: `internal/runner/runner.go`
- Test: `internal/runner/runner_test.go`

- [ ] **Step 1: Write the failing test for zero-credential warning**

Add to `internal/runner/runner_test.go`:

```go
func TestFormatStartupZeroCreds(t *testing.T) {
	msg := formatStartupWarning(0)
	if msg == "" {
		t.Error("expected warning message for zero credentials")
	}
	if !strings.Contains(msg, "No credentials") {
		t.Errorf("expected 'No credentials' in message, got: %s", msg)
	}
}

func TestFormatStartupWithCreds(t *testing.T) {
	msg := formatStartupWarning(5)
	if msg != "" {
		t.Errorf("expected empty message for non-zero credentials, got: %s", msg)
	}
}
```

Add `"strings"` to imports if not present.

- [ ] **Step 2: Write the failing test for exit summary**

Add to `internal/runner/runner_test.go`:

```go
func TestFormatExitSummary(t *testing.T) {
	tests := []struct {
		exitCode int
		signal   bool
		sigName  string
		want     string
	}{
		{0, false, "", "session complete"},
		{1, false, "", "session ended (exit 1)"},
		{130, false, "", "session ended (exit 130)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatExitSummary(tt.exitCode)
			if got != tt.want {
				t.Errorf("formatExitSummary(%d) = %q, want %q", tt.exitCode, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/runner/ -run "TestFormat" -v -timeout 30s`

Expected: FAIL — functions not defined.

- [ ] **Step 4: Add helper functions to `internal/runner/runner.go`**

Add at the bottom of the file:

```go
// formatStartupWarning returns a warning message if credCount is zero, or empty string otherwise.
func formatStartupWarning(credCount int) string {
	if credCount == 0 {
		return "No credentials to inject. Add secrets with veil add or create a .env file and re-run veil init."
	}
	return ""
}

// formatExitSummary returns the session summary line based on exit code.
func formatExitSummary(exitCode int) string {
	if exitCode == 0 {
		return "session complete"
	}
	return fmt.Sprintf("session ended (exit %d)", exitCode)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/runner/ -run "TestFormat" -v -timeout 30s`

Expected: PASS

- [ ] **Step 6: Wire into runner.go**

In `runner.go`, after the startup line (around line 92), add:

```go
	if warning := formatStartupWarning(credCount); warning != "" {
		fmt.Fprintf(os.Stderr, "  %s\n", ui.Warning.Sprint("! ")+warning)
	}
```

Replace the exit summary line (around line 129). Change:

```go
	fmt.Fprintf(os.Stderr, "%s session complete\n", ui.Success.Sprint("veil"))
```

To:

```go
	exitCode := 0
	if exitErr, ok := waitErr.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	}
	summary := formatExitSummary(exitCode)
	fmt.Fprintf(os.Stderr, "%s %s\n", ui.Success.Sprint("veil"), summary)
```

And update the exit code extraction at the bottom to use the already-computed `exitCode`:

```go
	// 12. Extract exit code.
	if waitErr != nil {
		if _, ok := waitErr.(*exec.ExitError); ok {
			return &Result{ExitCode: exitCode}, nil
		}
		return nil, fmt.Errorf("child process failed: %w", waitErr)
	}
	return &Result{ExitCode: 0}, nil
```

- [ ] **Step 7: Run full runner tests**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/runner/ -v -timeout 60s`

Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/runner/runner.go internal/runner/runner_test.go
git commit -m "feat(runner): add zero-credential warning and accurate exit summary"
```

---

### Task 10: Signal Handling Escalation

**Files:**
- Modify: `internal/runner/signals.go`
- Test: `internal/runner/signals_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/runner/signals_test.go`:

```go
func TestEscalationTimings(t *testing.T) {
	// Verify constants are defined and reasonable.
	if escalateTimeout <= 0 {
		t.Error("escalateTimeout should be positive")
	}
	if killTimeout <= 0 {
		t.Error("killTimeout should be positive")
	}
	if killTimeout <= escalateTimeout {
		t.Error("killTimeout should be greater than escalateTimeout")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/runner/ -run TestEscalation -v -timeout 30s`

Expected: FAIL — `escalateTimeout` not defined.

- [ ] **Step 3: Rewrite `internal/runner/signals.go` with escalation**

```go
package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/8enji/veil/internal/ui"
)

const (
	escalateTimeout = 5 * time.Second
	killTimeout     = 10 * time.Second
)

// forwardSignals listens for termination-related signals and forwards them to
// the child process group (negative PID) so the entire tree receives them.
// If the child doesn't exit within escalateTimeout after SIGINT, SIGTERM is sent.
// If still alive after killTimeout, SIGKILL is sent.
func forwardSignals(ctx context.Context, cmd *exec.Cmd) {
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	defer signal.Stop(sigs)

	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-sigs:
			if cmd.Process == nil {
				continue
			}
			// Forward the signal to the process group.
			_ = syscall.Kill(-cmd.Process.Pid, sig.(syscall.Signal))

			// Start escalation for SIGINT.
			if sig == syscall.SIGINT {
				go escalate(ctx, cmd)
			}
			return
		}
	}
}

// escalate sends SIGTERM after escalateTimeout and SIGKILL after killTimeout
// if the child process is still running.
func escalate(ctx context.Context, cmd *exec.Cmd) {
	termTimer := time.NewTimer(escalateTimeout)
	defer termTimer.Stop()

	select {
	case <-ctx.Done():
		return
	case <-termTimer.C:
		if cmd.Process == nil {
			return
		}
		fmt.Fprintln(os.Stderr, ui.Muted.Sprint("Waiting for process to exit..."))
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}

	killTimer := time.NewTimer(killTimeout - escalateTimeout)
	defer killTimer.Stop()

	select {
	case <-ctx.Done():
		return
	case <-killTimer.C:
		if cmd.Process == nil {
			return
		}
		fmt.Fprintln(os.Stderr, ui.Muted.Sprint("Force-killed child process."))
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/runner/ -run TestEscalation -v -timeout 30s`

Expected: PASS

- [ ] **Step 5: Run full runner tests**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/runner/ -v -timeout 60s`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/runner/signals.go internal/runner/signals_test.go
git commit -m "feat(runner): add signal escalation (SIGINT → SIGTERM → SIGKILL)"
```

---

### Task 11: Proxy Startup Error Messages

**Files:**
- Modify: `internal/cli/run.go`
- Test: `internal/cli/cli_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/cli/cli_test.go`:

```go
func TestRunVaultDecryptError(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	// Create .veil with a corrupted vault.
	veilDir := filepath.Join(tmpDir, ".veil")
	if err := os.MkdirAll(veilDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(veilDir, "vault.meta"), []byte(`{"project_id":"test","version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(veilDir, "vault.bin"), []byte("corrupted"), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"run", "--path", tmpDir, "--", "echo", "hi"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for corrupted vault")
	}
	errStr := err.Error()
	// Should get a user-friendly message, not a raw Go error.
	if !strings.Contains(errStr, "decrypt") && !strings.Contains(errStr, "vault") {
		t.Errorf("error should reference vault/decrypt issue, got: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify current behavior**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestRunVaultDecrypt -v -timeout 30s`

Expected: The test should actually pass already since the error propagates — but the message may be a raw Go chain. Check the output.

- [ ] **Step 3: Add error mapping to `internal/cli/run.go`**

Replace the error handling in `runRun` (lines 37-44) with error mapping:

```go
	result, err := runner.Run(cmd.Context(), runner.Config{
		Root:    root,
		Command: args[0],
		Args:    args[1:],
		Verbose: flagVerbose,
	})
	if err != nil {
		return cliError(mapRunError(err), "")
	}
```

Add the mapping function at the bottom of `run.go`:

```go
// mapRunError converts internal runner errors to user-friendly messages.
func mapRunError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "open vault") || strings.Contains(msg, "retrieve master key"):
		return "Cannot decrypt vault. Your keychain may have changed. Run veil init --force to reinitialize."
	case strings.Contains(msg, "load or create CA") || strings.Contains(msg, "CA"):
		return "CA certificate not found or corrupt. Run veil init to regenerate."
	case strings.Contains(msg, "bind") || strings.Contains(msg, "address already in use"):
		return "Cannot start proxy. Another instance may be running."
	default:
		return fmt.Sprintf("run failed: %v", err)
	}
}
```

Add `"strings"` to imports.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run TestRunVaultDecrypt -v -timeout 30s`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/cli/run.go internal/cli/cli_test.go
git commit -m "feat(cli): map proxy startup errors to user-friendly messages"
```

---

### Task 12: Vault Error Message Improvements

**Files:**
- Modify: `internal/vault/vault.go`
- Test: `internal/vault/vault_test.go`

- [ ] **Step 1: Write the failing test for improved collision error**

Add to `internal/vault/vault_test.go`:

```go
func TestAddPlaceholderCollisionMessage(t *testing.T) {
	dir := t.TempDir()
	ks := NewMemKeystore()
	v, err := CreateVault(dir, "test-collision", ks)
	if err != nil {
		t.Fatal(err)
	}

	cred1 := &Credential{
		ID:          NewID(),
		Name:        "KEY_A",
		Real:        "real-a",
		Placeholder: "ph-shared",
		Source:      "test",
	}
	if err := v.Add(cred1); err != nil {
		t.Fatal(err)
	}

	cred2 := &Credential{
		ID:          NewID(),
		Name:        "KEY_B",
		Real:        "real-b",
		Placeholder: "ph-shared",
		Source:      "test",
	}
	err = v.Add(cred2)
	if err == nil {
		t.Fatal("expected placeholder collision error")
	}
	if !strings.Contains(err.Error(), "veil remove") {
		t.Errorf("collision error should suggest veil remove, got: %v", err)
	}
}
```

Add `"strings"` to imports if not present.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/vault/ -run TestAddPlaceholderCollision -v -timeout 30s`

Expected: FAIL — error message doesn't contain "veil remove".

- [ ] **Step 3: Improve error messages in `internal/vault/vault.go`**

In the `Add` method (around line 132), replace the collision error:

```go
if c.Placeholder == cred.Placeholder {
    return fmt.Errorf("vault: placeholder collision for %q — the generated placeholder for %q matches credential %q. Remove the conflicting credential with veil remove", cred.Placeholder, cred.Name, c.Name)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/vault/ -run TestAddPlaceholderCollision -v -timeout 30s`

Expected: PASS

- [ ] **Step 5: Write the test for vault corruption recovery message**

Add to `internal/vault/vault_test.go`:

```go
func TestOpenCorruptedVaultMessage(t *testing.T) {
	dir := t.TempDir()
	ks := NewMemKeystore()

	// Create a valid vault first (to register the key in the keystore).
	v, err := CreateVault(dir, "test-corrupt", ks)
	if err != nil {
		t.Fatal(err)
	}
	_ = v

	// Corrupt the vault file.
	vaultPath := filepath.Join(dir, ".veil", "vault.bin")
	if err := os.WriteFile(vaultPath, []byte("corrupted-data"), 0600); err != nil {
		t.Fatal(err)
	}

	// Create a backup file so the recovery message can reference it.
	backupPath := filepath.Join(dir, ".veil", "vault.bin.bak")
	if err := os.WriteFile(backupPath, []byte("backup-data"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err = Open(dir, ks)
	if err == nil {
		t.Fatal("expected error for corrupted vault")
	}
	// The error should be about corruption, not a generic Go error.
	if !strings.Contains(err.Error(), "corrupt") && !strings.Contains(err.Error(), "unseal") {
		t.Errorf("error should reference corruption, got: %v", err)
	}
}
```

Add `"os"` and `"path/filepath"` to imports if not present.

- [ ] **Step 6: Run test to verify current behavior**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/vault/ -run TestOpenCorruptedVault -v -timeout 30s`

Expected: Likely passes already since the unseal error is descriptive. If not, update the Unseal error message.

- [ ] **Step 7: Run full vault tests**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/vault/ -v -timeout 30s`

Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/vault/vault.go internal/vault/vault_test.go
git commit -m "fix(vault): improve placeholder collision and corruption error messages"
```

---

### Task 13: Branded `--version` and `--help`

**Files:**
- Modify: `internal/cli/root.go`
- Modify: `cmd/veil/main.go`
- Test: `internal/cli/cli_test.go`

- [ ] **Step 1: Write the failing test for custom version**

Add to `internal/cli/cli_test.go`:

```go
func TestVersionOutput(t *testing.T) {
	cmd := NewRoot("0.1.0")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"--version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--version failed: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "veil v0.1.0") {
		t.Errorf("version should contain 'veil v0.1.0', got: %s", output)
	}
}

func TestHelpOutput(t *testing.T) {
	cmd := NewRoot("0.1.0")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--help failed: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "Quick start") {
		t.Errorf("help should contain 'Quick start' section, got: %s", output)
	}
	if !strings.Contains(output, "veil init") {
		t.Errorf("help should mention 'veil init', got: %s", output)
	}
	if !strings.Contains(output, "veil run") {
		t.Errorf("help should mention 'veil run', got: %s", output)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run "TestVersion|TestHelp" -v -timeout 30s`

Expected: FAIL — version shows "veil version 0.1.0" (cobra default), help shows cobra default.

- [ ] **Step 3: Customize version and help in `internal/cli/root.go`**

In `NewRoot`, replace the version template and add a custom long description. After `root.Version = version` (line 39), add:

```go
root.SetVersionTemplate(fmt.Sprintf("veil v%s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH))
```

Replace the `Long` field (line 23) with:

```go
Long: `Veil — protect your secrets from AI agents

Quick start:
  veil init          Scan project, vault secrets, write placeholders
  veil run claude    Launch agent with credential injection active
  veil log           See what credentials were used

Veil sits between your AI coding agent and the network. It replaces
real secrets with format-aware placeholders, then injects the real
credentials at the proxy layer — so the agent never sees them.`,
```

Add `"fmt"` and `"runtime"` to imports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -run "TestVersion|TestHelp" -v -timeout 30s`

Expected: PASS

- [ ] **Step 5: Run full CLI test suite**

Run: `cd /Users/ben/Workspace/Veil && CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/cli/ -v -timeout 60s`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/cli/root.go internal/cli/cli_test.go
git commit -m "feat(cli): add branded --version and --help output"
```

---

## Final Verification

- [ ] **Run full test suite**

```bash
cd /Users/ben/Workspace/Veil && make test
```

Expected: All tests pass.

- [ ] **Run vet and lint**

```bash
cd /Users/ben/Workspace/Veil && make vet && make lint
```

Expected: Clean.

- [ ] **Manual smoke test**

```bash
cd /Users/ben/Workspace/Veil && make build
bin/veil --version
bin/veil --help
bin/veil init --help
bin/veil remove --help
bin/veil add --help
```

Verify output looks polished and branded.
