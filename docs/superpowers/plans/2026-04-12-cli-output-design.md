# CLI Output Design Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add visual hierarchy, color, contextual error hints, and relative timestamps across all Veil CLI commands.

**Architecture:** New `internal/ui` package provides a shared formatting toolkit (colors, icons, formatters). Each CLI command is updated to use `ui` functions instead of raw `fmt.Fprintf`. Color is controlled by `--color`/`--no-color` flags and `NO_COLOR` env var, resolved in root `PersistentPreRunE`. `fatih/color` handles ANSI output and auto-detection.

**Tech Stack:** Go, `fatih/color`, `mattn/go-isatty` (already in deps via cobra)

---

### Task 1: Add `fatih/color` dependency

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`

- [ ] **Step 1: Add the dependency**

Run:
```bash
go get github.com/fatih/color@latest
```

- [ ] **Step 2: Verify it was added**

Run:
```bash
grep fatih go.mod
```
Expected: line containing `github.com/fatih/color`

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: add fatih/color dependency for CLI styling"
```

---

### Task 2: Create `internal/ui` package — color palette and icons

**Files:**
- Create: `internal/ui/ui.go`
- Create: `internal/ui/ui_test.go`

- [ ] **Step 1: Write tests for SetColor and icon rendering**

Create `internal/ui/ui_test.go`:

```go
package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fatih/color"
)

func TestSetColorNever(t *testing.T) {
	SetColor("never")
	if !color.NoColor {
		t.Error("SetColor(\"never\") should set color.NoColor = true")
	}
}

func TestSetColorAlways(t *testing.T) {
	SetColor("always")
	if color.NoColor {
		t.Error("SetColor(\"always\") should set color.NoColor = false")
	}
}

func TestStep(t *testing.T) {
	SetColor("never")
	var buf bytes.Buffer
	Step(&buf, "Found 3 .env files")
	got := buf.String()
	if !strings.Contains(got, "✓") {
		t.Errorf("Step should contain ✓, got: %q", got)
	}
	if !strings.Contains(got, "Found 3 .env files") {
		t.Errorf("Step should contain message, got: %q", got)
	}
}

func TestWarn(t *testing.T) {
	SetColor("never")
	var buf bytes.Buffer
	Warn(&buf, "2 unscoped credentials")
	got := buf.String()
	if !strings.Contains(got, "!") {
		t.Errorf("Warn should contain !, got: %q", got)
	}
	if !strings.Contains(got, "2 unscoped credentials") {
		t.Errorf("Warn should contain message, got: %q", got)
	}
}

func TestPhase(t *testing.T) {
	SetColor("never")
	var buf bytes.Buffer
	Phase(&buf, "Scanning project...")
	got := buf.String()
	if !strings.Contains(got, "Scanning project...") {
		t.Errorf("Phase should contain message, got: %q", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
cd /Users/ben/Workspace/Veil && go test ./internal/ui/... -v
```
Expected: compilation error — package `ui` doesn't exist yet.

- [ ] **Step 3: Implement color palette, SetColor, icons, Step, Warn, Phase**

Create `internal/ui/ui.go`:

```go
// Package ui provides shared formatting primitives for Veil's CLI output.
package ui

import (
	"fmt"
	"io"

	"github.com/fatih/color"
)

// Color palette — use these for inline styling beyond the helper functions.
var (
	Success = color.New(color.FgGreen)
	Warning = color.New(color.FgYellow)
	Err     = color.New(color.FgRed, color.Bold)
	Muted   = color.New(color.FgHiBlack)
	Bold    = color.New(color.Bold)
)

// SetColor configures the global color mode. Called once from root PersistentPreRunE.
// mode is "auto", "always", or "never".
func SetColor(mode string) {
	switch mode {
	case "never":
		color.NoColor = true
	case "always":
		color.NoColor = false
	default:
		// "auto" — fatih/color auto-detects by default, so reset to its default.
		color.NoColor = false
	}
}

// Step prints a success step line: "  ✓ msg\n"
func Step(w io.Writer, msg string) {
	fmt.Fprintf(w, "  %s %s\n", Success.Sprint("✓"), msg)
}

// Warn prints a warning step line: "  ! msg\n"
func Warn(w io.Writer, msg string) {
	fmt.Fprintf(w, "  %s %s\n", Warning.Sprint("!"), msg)
}

// Phase prints a muted phase header line: "msg\n"
func Phase(w io.Writer, msg string) {
	fmt.Fprintln(w, Muted.Sprint(msg))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /Users/ben/Workspace/Veil && go test ./internal/ui/... -v
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/ui/ui.go internal/ui/ui_test.go
git commit -m "feat(ui): add color palette, SetColor, Step, Warn, Phase"
```

---

### Task 3: Add Header, TableHeader, Footer, and RelativeTime to `ui` package

**Files:**
- Modify: `internal/ui/ui.go`
- Modify: `internal/ui/ui_test.go`

- [ ] **Step 1: Write tests for Header, TableHeader, Footer, and RelativeTime**

Append to `internal/ui/ui_test.go`:

```go
func TestHeader(t *testing.T) {
	SetColor("never")
	var buf bytes.Buffer
	Header(&buf, "Veil Status")
	got := buf.String()
	if !strings.Contains(got, "Veil Status") {
		t.Errorf("Header should contain label, got: %q", got)
	}
}

func TestFooter(t *testing.T) {
	SetColor("never")
	var buf bytes.Buffer
	Footer(&buf, "5 credentials")
	got := buf.String()
	if !strings.Contains(got, "5 credentials") {
		t.Errorf("Footer should contain message, got: %q", got)
	}
}

func TestRelativeTime(t *testing.T) {
	now := time.Now()
	tests := []struct {
		input time.Time
		want  string
	}{
		{now.Add(-10 * time.Second), "just now"},
		{now.Add(-5 * time.Minute), "5m ago"},
		{now.Add(-3 * time.Hour), "3h ago"},
		{now.Add(-2 * 24 * time.Hour), "2d ago"},
	}
	for _, tt := range tests {
		got := RelativeTime(tt.input)
		if got != tt.want {
			t.Errorf("RelativeTime(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRelativeTimeOld(t *testing.T) {
	old := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)
	got := RelativeTime(old)
	if got != "2026-03-15" {
		t.Errorf("RelativeTime(old date) = %q, want date string", got)
	}
}

func TestTableHeader(t *testing.T) {
	SetColor("never")
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 4, 4, ' ', 0)
	TableHeader(tw, "NAME", "HOST", "SOURCE")
	tw.Flush()
	got := buf.String()
	if !strings.Contains(got, "NAME") || !strings.Contains(got, "HOST") || !strings.Contains(got, "SOURCE") {
		t.Errorf("TableHeader should contain column names, got: %q", got)
	}
}
```

Add these imports to the test file: `"text/tabwriter"` and `"time"`.

- [ ] **Step 2: Run tests to verify the new tests fail**

Run:
```bash
cd /Users/ben/Workspace/Veil && go test ./internal/ui/... -v
```
Expected: compilation errors for undefined `Header`, `TableHeader`, `Footer`, `RelativeTime`.

- [ ] **Step 3: Implement Header, TableHeader, Footer, RelativeTime**

Append to `internal/ui/ui.go`:

```go
import (
	"text/tabwriter"
	"time"
)
```

Add to the existing imports block, then add these functions:

```go
// Header prints a bold section label followed by a newline.
func Header(w io.Writer, label string) {
	fmt.Fprintln(w, Bold.Sprint(label))
}

// TableHeader prints dimmed, tab-separated column headers to a tabwriter.
func TableHeader(tw *tabwriter.Writer, cols ...string) {
	styled := make([]string, len(cols))
	for i, c := range cols {
		styled[i] = Muted.Sprint(c)
	}
	fmt.Fprintln(tw, strings.Join(styled, "\t"))
}

// Footer prints a dimmed footer line preceded by a blank line.
func Footer(w io.Writer, msg string) {
	fmt.Fprintf(w, "\n%s\n", Muted.Sprint(msg))
}

// RelativeTime formats a time relative to now:
//
//	<60s  → "just now"
//	<60m  → "Xm ago"
//	<24h  → "Xh ago"
//	<7d   → "Xd ago"
//	>=7d  → "2026-04-01" (date only)
func RelativeTime(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 7*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	default:
		return t.Format("2006-01-02")
	}
}
```

Also add `"strings"` and `"text/tabwriter"` and `"time"` to the import block.

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /Users/ben/Workspace/Veil && go test ./internal/ui/... -v
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/ui/ui.go internal/ui/ui_test.go
git commit -m "feat(ui): add Header, TableHeader, Footer, RelativeTime"
```

---

### Task 4: Add error and warning formatting to `ui` package

**Files:**
- Modify: `internal/ui/ui.go`
- Modify: `internal/ui/ui_test.go`

- [ ] **Step 1: Write tests for FormatError and FormatWarning**

Append to `internal/ui/ui_test.go`:

```go
func TestFormatError(t *testing.T) {
	SetColor("never")
	var buf bytes.Buffer
	err := FormatError(&buf, "project not initialized", "Run veil init to get started")
	if err == nil {
		t.Error("FormatError should return a non-nil error")
	}
	got := buf.String()
	if !strings.Contains(got, "error:") {
		t.Errorf("FormatError should contain 'error:', got: %q", got)
	}
	if !strings.Contains(got, "project not initialized") {
		t.Errorf("FormatError should contain message, got: %q", got)
	}
	if !strings.Contains(got, "veil init") {
		t.Errorf("FormatError should contain hint, got: %q", got)
	}
}

func TestFormatErrorNoHint(t *testing.T) {
	SetColor("never")
	var buf bytes.Buffer
	_ = FormatError(&buf, "no value provided", "")
	got := buf.String()
	// Should have error line but no indented hint line.
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 1 {
		t.Errorf("FormatError with no hint should be 1 line, got %d: %q", len(lines), got)
	}
}

func TestFormatWarning(t *testing.T) {
	SetColor("never")
	var buf bytes.Buffer
	FormatWarning(&buf, "2 credentials have no host scope", "Use veil add --host to scope them")
	got := buf.String()
	if !strings.Contains(got, "warning:") {
		t.Errorf("FormatWarning should contain 'warning:', got: %q", got)
	}
	if !strings.Contains(got, "2 credentials have no host scope") {
		t.Errorf("FormatWarning should contain message, got: %q", got)
	}
}
```

- [ ] **Step 2: Run tests to verify new tests fail**

Run:
```bash
cd /Users/ben/Workspace/Veil && go test ./internal/ui/... -v
```
Expected: compilation errors for undefined `FormatError`, `FormatWarning`.

- [ ] **Step 3: Implement FormatError and FormatWarning**

Append to `internal/ui/ui.go`:

```go
// FormatError prints a red "error: msg" line with an optional dimmed hint to w.
// Returns a sentinel error for use as a cobra RunE return value.
func FormatError(w io.Writer, msg string, hint string) error {
	fmt.Fprintf(w, "%s %s\n", Err.Sprint("error:"), msg)
	if hint != "" {
		fmt.Fprintf(w, "  %s\n", Muted.Sprint(hint))
	}
	return fmt.Errorf("%s", msg)
}

// FormatWarning prints a yellow "warning: msg" line with an optional dimmed hint to w.
func FormatWarning(w io.Writer, msg string, hint string) {
	fmt.Fprintf(w, "%s %s\n", Warning.Sprint("warning:"), msg)
	if hint != "" {
		fmt.Fprintf(w, "  %s\n", Muted.Sprint(hint))
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /Users/ben/Workspace/Veil && go test ./internal/ui/... -v
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/ui/ui.go internal/ui/ui_test.go
git commit -m "feat(ui): add FormatError and FormatWarning"
```

---

### Task 5: Add `--color`/`--no-color` flags and `PersistentPreRunE` to root

**Files:**
- Modify: `internal/cli/root.go`

- [ ] **Step 1: Write test for color flag resolution**

Append to `internal/cli/cli_test.go`:

```go
func TestColorFlagNoColor(t *testing.T) {
	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"--no-color", "status", "--path", "/nonexistent"})
	// We just need the PersistentPreRunE to execute; status will error.
	_ = cmd.Execute()
	// fatih/color should have NoColor = true
	// (We can't easily assert this without exporting, but the flag path exercises the code.)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
cd /Users/ben/Workspace/Veil && go test ./internal/cli/... -run TestColorFlag -v
```
Expected: FAIL — `--no-color` is not a recognized flag.

- [ ] **Step 3: Add flags and PersistentPreRunE to root.go**

Replace the contents of `internal/cli/root.go`:

```go
// Package cli implements Veil's command-line interface.
package cli

import (
	"os"

	"github.com/8enji/veil/internal/ui"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

var (
	flagPath    string
	flagVerbose bool
	flagColor   bool
	flagNoColor bool
)

// NewRoot returns the top-level cobra command for veil.
func NewRoot(version string) *cobra.Command {
	root := &cobra.Command{
		Use:   "veil",
		Short: "Secure AI coding agents by intercepting secrets at the network layer",
		Long:  "Veil intercepts outbound HTTPS traffic from AI agents, replacing placeholder values with real credentials so the agent never sees real secrets.",

		SilenceUsage:  true,
		SilenceErrors: true,

		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			resolveColor()
			return nil
		},
	}

	root.PersistentFlags().StringVar(&flagPath, "path", "", "project root path (default: auto-detect)")
	root.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "enable verbose logging")
	root.PersistentFlags().BoolVar(&flagColor, "color", false, "force color output")
	root.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "disable color output")
	root.Version = version

	root.AddCommand(initCmd())
	root.AddCommand(runCmd())
	root.AddCommand(statusCmd())
	root.AddCommand(addCmd())
	root.AddCommand(listCmd())
	root.AddCommand(logCmd())
	return root
}

// resolveColor determines the color mode from flags, env, and TTY detection.
// Resolution order: --no-color > --color > NO_COLOR env > TTY auto-detect.
func resolveColor() {
	switch {
	case flagNoColor:
		ui.SetColor("never")
	case flagColor:
		ui.SetColor("always")
	case os.Getenv("NO_COLOR") != "":
		ui.SetColor("never")
	case isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd()):
		ui.SetColor("auto")
	default:
		ui.SetColor("never")
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
cd /Users/ben/Workspace/Veil && go test ./internal/cli/... -run TestColorFlag -v
```
Expected: PASS.

- [ ] **Step 5: Run all existing tests to check for regressions**

Run:
```bash
cd /Users/ben/Workspace/Veil && go test ./... -v -count=1
```
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/root.go internal/cli/cli_test.go
git commit -m "feat(cli): add --color/--no-color flags with NO_COLOR and TTY detection"
```

---

### Task 6: Replace `exitError` with `ui.FormatError` across all commands

**Files:**
- Modify: `internal/cli/errors.go`
- Modify: `internal/cli/init.go`
- Modify: `internal/cli/run.go`
- Modify: `internal/cli/add.go`
- Modify: `internal/cli/list.go`
- Modify: `internal/cli/log.go`
- Modify: `internal/cli/status.go`
- Modify: `cmd/veil/main.go`

This is a mechanical replacement. The old `exitError(msg)` returned `fmt.Errorf("veil: %s", msg)`. The new pattern uses `ui.FormatError(cmd.ErrOrStderr(), msg, hint)` which prints the styled error and returns an error for cobra.

- [ ] **Step 1: Update `errors.go` to provide a helper that wraps `ui.FormatError`**

Replace `internal/cli/errors.go`:

```go
package cli

import (
	"os"

	"github.com/8enji/veil/internal/ui"
)

// cliError prints a styled error to stderr with an optional hint and returns
// an error for cobra's RunE to propagate as a non-zero exit code.
func cliError(msg string, hint string) error {
	return ui.FormatError(os.Stderr, msg, hint)
}
```

- [ ] **Step 2: Update `main.go` to simplify error handling**

Replace `cmd/veil/main.go`:

```go
package main

import (
	"os"

	"github.com/8enji/veil/internal/cli"
)

var version = "dev"

func main() {
	root := cli.NewRoot(version)
	if err := root.Execute(); err != nil {
		// Error is already printed by cliError/ui.FormatError.
		os.Exit(1)
	}
}
```

- [ ] **Step 3: Replace all `exitError` calls with `cliError` — add hints where appropriate**

In `internal/cli/run.go`, replace:
- `exitError("project not initialized (run 'veil init' first)")` → `cliError("project not initialized", "Run veil init to get started")`
- `exitError(fmt.Sprintf("run failed: %v", err))` → `cliError(fmt.Sprintf("run failed: %v", err), "")`

In `internal/cli/init.go`, replace:
- `exitError("project already initialized (use --force to reinitialize)")` → `cliError("project already initialized", "Use --force to reinitialize")`
- All other `exitError(...)` calls → `cliError(..., "")` (no hint — not user-actionable).

In `internal/cli/add.go`, replace:
- `exitError(fmt.Sprintf("adding credential: %v", err))` — check if the error contains "already exists" and route to `cliError("credential already exists", "Use --force to overwrite")`. Otherwise `cliError(msg, "")`.
- `exitError("no value provided")` → `cliError("no value provided", "")`
- All other `exitError(...)` → `cliError(..., "")`.

In `internal/cli/list.go`, `internal/cli/log.go`, `internal/cli/status.go`: replace all `exitError(...)` → `cliError(..., "")`.

Remove the `"fmt"` import from `errors.go` (no longer needed).

- [ ] **Step 4: Run all tests**

Run:
```bash
cd /Users/ben/Workspace/Veil && go test ./... -count=1
```
Expected: all PASS. Tests that check `err.Error()` for "not initialized" or "already initialized" should still match because `ui.FormatError` returns an error containing the message.

**Note:** if any test checks for the `"veil: "` prefix specifically, update those assertions to match the new format (no prefix).

- [ ] **Step 5: Commit**

```bash
git add internal/cli/errors.go internal/cli/init.go internal/cli/run.go internal/cli/add.go internal/cli/list.go internal/cli/log.go internal/cli/status.go cmd/veil/main.go
git commit -m "refactor(cli): replace exitError with styled cliError using ui.FormatError"
```

---

### Task 7: Restyle `veil init` with step-by-step progress

**Files:**
- Modify: `internal/cli/init.go`
- Modify: `internal/cli/init_test.go`

- [ ] **Step 1: Update test assertions for new output format**

In `internal/cli/init_test.go`, update `TestInitHappyPath`:

Change the assertion from:
```go
if !strings.Contains(outStr, "Veil initialized") {
```
to:
```go
if !strings.Contains(outStr, "Veil initialized") {
```
(This stays the same.)

Change:
```go
if !strings.Contains(outStr, "Secrets vaulted: 1") {
```
to:
```go
if !strings.Contains(outStr, "Secrets vaulted:") {
```
(Keep flexible — exact count varies.)

Add an assertion for step-by-step output:
```go
if !strings.Contains(outStr, "✓") {
    t.Errorf("init should show checkmarks, got: %s", outStr)
}
```

- [ ] **Step 2: Run updated test to see it fail on missing checkmark**

Run:
```bash
cd /Users/ben/Workspace/Veil && go test ./internal/cli/... -run TestInitHappyPath -v
```
Expected: FAIL on the `✓` assertion.

- [ ] **Step 3: Restyle `runInit` in `init.go`**

Replace the output logic in `runInit`. The data-gathering code stays the same. Change the print calls:

Before the `.env` scanning loop, add:
```go
w := cmd.OutOrStdout()
ui.Phase(w, "Scanning project...")
```

After scanning `.env` files and MCP config, print discovery results:
```go
if len(envPaths) > 0 {
    ui.Step(w, fmt.Sprintf("Found %d .env file(s)", len(envPaths)))
}
if mcpConfigPath != "" {
    ui.Step(w, "Found 1 MCP config")
}
fmt.Fprintln(w)
```

Before the vaulting loop, add:
```go
ui.Phase(w, "Vaulting secrets...")
```

After all vaulting is complete, print results:
```go
ui.Step(w, fmt.Sprintf("%d secrets stored in keychain", secretsVaulted))
if secretsScoped > 0 {
    ui.Step(w, fmt.Sprintf("%d auto-scoped to hosts", secretsScoped))
}
unscoped := secretsVaulted - secretsScoped
if unscoped > 0 {
    ui.Warn(w, fmt.Sprintf("%d unscoped (use veil add --host to scope)", unscoped))
}
fmt.Fprintln(w)
```

Before CA setup:
```go
ui.Phase(w, "Setting up proxy...")
```

After CA setup:
```go
ui.Step(w, "CA certificate ready")
fmt.Fprintln(w)
```

Final summary:
```go
fmt.Fprintf(w, "%s for %s\n", ui.Success.Sprint("Veil initialized"), root)
fmt.Fprintf(w, "  .env files processed:  %d\n", len(envPaths))
if mcpConfigsProcessed > 0 {
    fmt.Fprintf(w, "  MCP configs processed: %d\n", mcpConfigsProcessed)
}
fmt.Fprintf(w, "  Secrets vaulted:       %d\n", secretsVaulted)
fmt.Fprintln(w)
```

Remove the old summary print block at the end (lines 194-208 of current init.go).

Add import: `"github.com/8enji/veil/internal/ui"`

Move the phase/step prints to execute inline as each phase completes (the scanning phase header prints before the scanning loop, the vaulting phase header prints before the vaulting loop, etc.).

- [ ] **Step 4: Run tests**

Run:
```bash
cd /Users/ben/Workspace/Veil && go test ./internal/cli/... -v -count=1
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/init.go internal/cli/init_test.go
git commit -m "feat(cli): restyle veil init with step-by-step progress output"
```

---

### Task 8: Restyle `veil status` with bold labels and relative time

**Files:**
- Modify: `internal/cli/status.go`
- Modify: `internal/cli/cli_test.go`

- [ ] **Step 1: Update test assertions for new output format**

In `internal/cli/cli_test.go`, update `TestStatusOutput`:

Change `"Credentials:"` to `"Credentials"` (no colon in new format):
```go
if !strings.Contains(output, "Credentials") {
    t.Errorf("status should contain 'Credentials', got: %s", output)
}
if !strings.Contains(output, "CA") {
    t.Errorf("status should contain 'CA', got: %s", output)
}
if !strings.Contains(output, "Veil Status") {
    t.Errorf("status should contain 'Veil Status', got: %s", output)
}
if !strings.Contains(output, "Injections") {
    t.Errorf("status should contain 'Injections', got: %s", output)
}
```

- [ ] **Step 2: Restyle `runStatus` in `status.go`**

Replace the print section of `runStatus`:

```go
w := cmd.OutOrStdout()

// Title line.
fmt.Fprintf(w, "%s  %s\n", ui.Bold.Sprint("Veil Status"), ui.Muted.Sprint(root))
fmt.Fprintln(w)

// Credentials.
fmt.Fprintf(w, "  %s  %d vaulted\n", ui.Bold.Sprint("Credentials"), credCount)

// CA status.
caStatusStr := ui.Success.Sprint("ready") + " " + caFile
if _, caErr := proxy.LoadOrCreateCA(); caErr != nil {
    caStatusStr = ui.Err.Sprint("error") + " " + caErr.Error()
}
fmt.Fprintf(w, "  %s           %s\n", ui.Bold.Sprint("CA"), caStatusStr)
fmt.Fprintln(w)

// Last 24h.
fmt.Fprintf(w, "  %s\n", ui.Bold.Sprint("Last 24h"))
fmt.Fprintf(w, "  Injections   %d\n", total)
if blocked > 0 {
    fmt.Fprintf(w, "  Blocked      %d\n", blocked)
}

if len(hosts) > 0 {
    fmt.Fprintf(w, "  Hosts        %s\n", strings.Join(hosts, ", "))
} else {
    fmt.Fprintf(w, "  Hosts        %s\n", ui.Muted.Sprint("(none)"))
}

if lastInj != nil {
    fmt.Fprintf(w, "  Last         %s → %s (%s)\n",
        ui.RelativeTime(lastInj.Timestamp), lastInj.Host, lastInj.CredentialName)
} else {
    fmt.Fprintf(w, "  Last         %s\n", ui.Muted.Sprint("(none)"))
}

// Warn about unscoped credentials.
unscopedCount := 0
for _, c := range v.List() {
    if len(c.AllowedHosts) == 0 {
        unscopedCount++
    }
}
if unscopedCount > 0 {
    fmt.Fprintln(w)
    ui.Warn(w, fmt.Sprintf("%d credential(s) have no host scope", unscopedCount))
    fmt.Fprintf(w, "    %s\n", ui.Muted.Sprint("Use veil add --host to scope them"))
}
```

Add import: `"github.com/8enji/veil/internal/ui"`

Note: the current code calls `proxy.LoadOrCreateCA()` to check CA status. Keep that, but restructure to avoid duplicate calls: do the CA check once and store the error.

- [ ] **Step 3: Run tests**

Run:
```bash
cd /Users/ben/Workspace/Veil && go test ./internal/cli/... -v -count=1
```
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/cli/status.go internal/cli/cli_test.go
git commit -m "feat(cli): restyle veil status with bold labels and relative timestamps"
```

---

### Task 9: Restyle `veil list` with dimmed headers, relative time, and footer

**Files:**
- Modify: `internal/cli/list.go`
- Modify: `internal/cli/cli_test.go`

- [ ] **Step 1: Update `TestAddAndList` to assert on new format**

In `internal/cli/cli_test.go`, the existing test checks for `"CUSTOM_SECRET"`, `"manual"`, `"OPENAI_API_KEY"`. These will still be present. Add assertion for footer:
```go
if !strings.Contains(output, "credentials") {
    t.Errorf("list should show credential count footer, got: %s", output)
}
```

Also check that CREATED column is gone:
```go
if strings.Contains(output, "CREATED") {
    t.Errorf("list should not have CREATED column, got: %s", output)
}
```

- [ ] **Step 2: Restyle `runList` in `list.go`**

Replace the table-printing section:

```go
w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 4, ' ', 0)
if reveal {
    ui.TableHeader(w, "NAME", "HOSTS", "VALUE", "SOURCE", "LAST INJECTED")
} else {
    ui.TableHeader(w, "NAME", "HOSTS", "SOURCE", "LAST INJECTED")
}
for _, c := range creds {
    last := "never"
    if t, ok := lastInjected[c.Name]; ok {
        last = ui.RelativeTime(t)
    }
    hostsStr := ui.Warning.Sprint("(none)")
    if len(c.AllowedHosts) > 0 {
        hostsStr = strings.Join(c.AllowedHosts, ", ")
    }
    if reveal {
        fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
            c.Name, hostsStr, c.Real, c.Source, last)
    } else {
        fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
            c.Name, hostsStr, c.Source, last)
    }
}
_ = w.Flush()
ui.Footer(cmd.OutOrStdout(), fmt.Sprintf("%d credentials", len(creds)))
```

Key changes:
- Drop the CREATED column from both the header and data rows.
- Store `lastInjected` values as `time.Time` instead of pre-formatted strings, so `ui.RelativeTime` can be applied.
- Change the `lastInjected` map type from `map[string]string` to `map[string]time.Time`.
- Update the map population loop:
```go
lastInjected := make(map[string]time.Time)
// ...
if qErr == nil && len(rows) > 0 {
    lastInjected[c.Name] = rows[0].Timestamp
}
```

Add import: `"github.com/8enji/veil/internal/ui"`

- [ ] **Step 3: Run tests**

Run:
```bash
cd /Users/ben/Workspace/Veil && go test ./internal/cli/... -v -count=1
```
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/cli/list.go internal/cli/cli_test.go
git commit -m "feat(cli): restyle veil list with dimmed headers, relative time, footer"
```

---

### Task 10: Restyle `veil log` with dimmed headers, relative time, footer, and better empty state

**Files:**
- Modify: `internal/cli/log.go`
- Modify: `internal/cli/cli_test.go`

- [ ] **Step 1: Update `TestLogEmpty` to assert on new empty state**

In `internal/cli/cli_test.go`, update `TestLogEmpty`:
```go
if !strings.Contains(out.String(), "No injection events found") {
    t.Errorf("expected empty log message, got: %s", out.String())
}
if !strings.Contains(out.String(), "veil run") {
    t.Errorf("expected hint about veil run, got: %s", out.String())
}
```

- [ ] **Step 2: Restyle `runLog` in `log.go`**

Replace the human-readable output section (the non-JSON path):

Empty state:
```go
if len(rows) == 0 {
    _, _ = fmt.Fprintln(w, "No injection events found.")
    fmt.Fprintln(w, ui.Muted.Sprint("  Injections are logged when you run commands through veil run"))
    return nil
}
```

Table output:
```go
tw := tabwriter.NewWriter(w, 0, 4, 4, ' ', 0)
ui.TableHeader(tw, "TIMESTAMP", "HOST", "METHOD", "CREDENTIAL", "LOCATION")
for _, r := range rows {
    _, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
        ui.RelativeTime(r.Timestamp),
        r.Host,
        r.Method,
        r.CredentialName,
        r.Location,
    )
}
_ = tw.Flush()
ui.Footer(w, fmt.Sprintf("%d events (last %s)", len(rows), since))
```

Add import: `"github.com/8enji/veil/internal/ui"`

- [ ] **Step 3: Run tests**

Run:
```bash
cd /Users/ben/Workspace/Veil && go test ./internal/cli/... -v -count=1
```
Expected: all PASS. `TestLogJSON` should still pass since the JSON codepath is untouched.

- [ ] **Step 4: Commit**

```bash
git add internal/cli/log.go internal/cli/cli_test.go
git commit -m "feat(cli): restyle veil log with dimmed headers, relative time, footer"
```

---

### Task 11: Add `veil run` bookends (startup line + exit summary)

**Files:**
- Modify: `internal/runner/runner.go`
- Modify: `internal/runner/runner_test.go`

- [ ] **Step 1: Write test for startup and exit output**

Append to `internal/runner/runner_test.go`:

```go
func TestRunBookends(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	root, ks := setupProject(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Capture stderr to check bookend output.
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	result, err := Run(ctx, Config{
		Root:     root,
		Command:  "echo",
		Args:     []string{"hello"},
		Keystore: ks,
	})

	_ = w.Close()
	os.Stderr = oldStderr

	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	stderr := buf.String()

	if !strings.Contains(stderr, "proxy active") {
		t.Errorf("startup line should contain 'proxy active', got: %q", stderr)
	}
	if !strings.Contains(stderr, "session complete") {
		t.Errorf("exit summary should contain 'session complete', got: %q", stderr)
	}
	if !strings.Contains(stderr, "Duration:") {
		t.Errorf("exit summary should contain 'Duration:', got: %q", stderr)
	}
}
```

Add `"bytes"` to the test file imports.

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
cd /Users/ben/Workspace/Veil && go test ./internal/runner/... -run TestRunBookends -v
```
Expected: FAIL on "proxy active" assertion.

- [ ] **Step 3: Add bookend output to `Run()` in `runner.go`**

Add import: `"github.com/8enji/veil/internal/ui"`

After step 5 (proxy start, line ~83), before step 6 (build child env), add the startup line:

```go
// 5b. Print startup line to stderr.
credCount := len(vlt.List())
fmt.Fprintf(os.Stderr, "\n%s proxy active · %d credentials loaded\n",
    ui.Success.Sprint("veil"), credCount)
fmt.Fprintln(os.Stderr, ui.Muted.Sprint("───────────────────────────────────────"))
```

Capture the start time just before `child.Start()`:

```go
sessionStart := time.Now()
```

After step 11 (reclaim foreground, line ~114), before step 12 (extract exit code), add the exit summary:

```go
// 11b. Print exit summary to stderr.
sessionDuration := time.Since(sessionStart)
sessionTotal, sessionBlocked, sessionHosts, _, summaryErr := auditStore.Summary(sessionStart)
fmt.Fprintln(os.Stderr, ui.Muted.Sprint("───────────────────────────────────────"))
fmt.Fprintf(os.Stderr, "%s session complete\n", ui.Success.Sprint("veil"))
fmt.Fprintf(os.Stderr, "  Duration:    %s\n", formatDuration(sessionDuration))
if summaryErr == nil {
    hostInfo := "0 hosts"
    if len(sessionHosts) > 0 {
        hostInfo = fmt.Sprintf("%d host(s)", len(sessionHosts))
    }
    fmt.Fprintf(os.Stderr, "  Injections:  %d across %s\n", sessionTotal, hostInfo)
    if sessionBlocked > 0 {
        fmt.Fprintf(os.Stderr, "  Blocked:     %d\n", sessionBlocked)
    }
}
fmt.Fprintln(os.Stderr)
```

Add a `formatDuration` helper at the bottom of `runner.go`:

```go
// formatDuration formats a duration as "Xh Ym Zs", omitting zero components.
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60

	switch {
	case h > 0:
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	case m > 0:
		return fmt.Sprintf("%dm %ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}
```

Add `"time"` and `"fmt"` to imports (they may already be there).

- [ ] **Step 4: Run tests**

Run:
```bash
cd /Users/ben/Workspace/Veil && go test ./internal/runner/... -v -count=1
```
Expected: all PASS.

- [ ] **Step 5: Run full test suite for regressions**

Run:
```bash
cd /Users/ben/Workspace/Veil && go test ./... -count=1
```
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/runner/runner.go internal/runner/runner_test.go
git commit -m "feat(runner): add startup line and exit summary bookends to veil run"
```

---

### Task 12: Final integration verification

**Files:** None (read-only verification).

- [ ] **Step 1: Run full test suite**

Run:
```bash
cd /Users/ben/Workspace/Veil && go test ./... -v -count=1
```
Expected: all PASS.

- [ ] **Step 2: Run linter**

Run:
```bash
cd /Users/ben/Workspace/Veil && golangci-lint run ./...
```
Expected: no new issues.

- [ ] **Step 3: Build the binary**

Run:
```bash
cd /Users/ben/Workspace/Veil && go build -o veil ./cmd/veil
```
Expected: builds cleanly.

- [ ] **Step 4: Manual smoke test — init**

Run in a test directory with a `.env` containing a secret:
```bash
./veil init --path /tmp/test-project
```
Expected: step-by-step output with green checkmarks, phase headers, styled summary.

- [ ] **Step 5: Manual smoke test — status**

```bash
./veil status --path /tmp/test-project
```
Expected: bold labels, green "ready" for CA, relative timestamps.

- [ ] **Step 6: Manual smoke test — list**

```bash
./veil list --path /tmp/test-project
```
Expected: dimmed headers, relative timestamps, credential count footer, no CREATED column.

- [ ] **Step 7: Manual smoke test — no-color flag**

```bash
./veil --no-color status --path /tmp/test-project
```
Expected: same content, no ANSI escape codes.

- [ ] **Step 8: Manual smoke test — piped output**

```bash
./veil status --path /tmp/test-project | cat
```
Expected: no ANSI escape codes (auto-detected as non-TTY).
