# Styled Help & Version Output Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Style `veil --help` and `veil --version` output to match the rest of the CLI (bold section headers, muted secondary text, styled version line).

**Architecture:** Register Cobra template functions (`bold`, `muted`, `styledFlags`) that delegate to the existing `ui` package, then apply custom usage and version templates that use them. All changes confined to `internal/cli/root.go`.

**Tech Stack:** Go, `github.com/spf13/cobra` v1.10.2 (template functions via `cobra.AddTemplateFunc`), existing `internal/ui` package (wraps `fatih/color`).

**Spec:** `docs/superpowers/specs/2026-04-13-styled-help-version-design.md`

---

## File Structure

- **Modify:** `internal/cli/root.go` — add template functions, `styledFlags` helper, custom usage/version templates
- **No changes:** `internal/ui/ui.go` (existing primitives are sufficient)
- **No changes:** `internal/cli/cli_test.go` (existing substring-based tests remain valid since ANSI codes interleave around plain text without breaking `strings.Contains` checks)

---

## Testing Strategy

The existing tests in `cli_test.go` verify help/version *content* via `strings.Contains`:

- `TestVersionOutput` checks `"veil v0.1.0"`
- `TestHelpOutput` checks `"Quick start"`, `"veil init"`, `"veil run"`
- `TestSubcommandHelp` checks each subcommand `--help` produces non-empty output
- `TestNoArgsShowsHelp` checks `"Available Commands"` and each subcommand name

ANSI escape codes wrap around plain text (e.g. `"\x1b[1mAvailable Commands:\x1b[0m"`), so `strings.Contains(output, "Available Commands")` still matches. No test changes required.

Because the change is purely cosmetic, TDD here means:
1. Run existing tests *before* to establish baseline (they pass)
2. Make changes
3. Run existing tests *after* to confirm nothing broke
4. Visually verify styled output in a terminal

No new test files are added — writing tests that assert specific ANSI escape sequences would test `fatih/color`'s internals, not Veil's behavior.

---

## Task 1: Add template functions, `styledFlags` helper, and styled version template

**Files:**
- Modify: `internal/cli/root.go`

### Step 1: Run baseline tests to confirm they pass before changes

- [ ] Run: `go test ./internal/cli/ -run 'TestVersionOutput|TestHelpOutput|TestSubcommandHelp|TestNoArgsShowsHelp' -v`

Expected: all four tests PASS. If any fail, stop and investigate before making changes.

### Step 2: Add `strings` import to `internal/cli/root.go`

- [ ] Read `internal/cli/root.go` and confirm current imports are:

```go
import (
	"fmt"
	"os"
	"runtime"

	"github.com/8enji/veil/internal/ui"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)
```

- [ ] Replace the import block with:

```go
import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/8enji/veil/internal/ui"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)
```

### Step 3: Add the `styledFlags` helper function

The `pflag.FlagUsages()` method returns a block like:

```
      --color         force color output
  -h, --help          help for veil
      --path string   project root path (default: auto-detect)
```

`styledFlags` finds the gap between the flag definition and the description (a run of 2+ consecutive spaces after the flag content) and applies `ui.Muted` to the description portion only. Flag names stay in the default color.

- [ ] Append this function to the end of `internal/cli/root.go`:

```go
// styledFlags applies muted styling to the description portion of each line
// produced by pflag.FlagUsages. Flag names are left in the default color;
// descriptions (including "(default: ...)" suffixes) are dimmed.
//
// pflag produces lines of the form:
//
//	"      --flag type   description text"
//
// The boundary between flag and description is the first run of 2+
// consecutive spaces that follows non-space content.
func styledFlags(s string) string {
	var b strings.Builder
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		if strings.TrimSpace(line) == "" {
			b.WriteString(line)
			continue
		}
		idx := flagDescriptionStart(line)
		if idx < 0 {
			b.WriteString(line)
			continue
		}
		// Find where the description text actually starts (skip padding spaces).
		descStart := idx
		for descStart < len(line) && line[descStart] == ' ' {
			descStart++
		}
		if descStart >= len(line) {
			b.WriteString(line)
			continue
		}
		b.WriteString(line[:idx])
		b.WriteString(strings.Repeat(" ", descStart-idx))
		b.WriteString(ui.Muted.Sprint(line[descStart:]))
	}
	return b.String()
}

// flagDescriptionStart returns the index of the first run of 2+ consecutive
// spaces that follows non-space content. Returns -1 if no such boundary exists.
func flagDescriptionStart(line string) int {
	inContent := false
	for i := 0; i < len(line)-1; i++ {
		if line[i] != ' ' {
			inContent = true
			continue
		}
		if inContent && line[i+1] == ' ' {
			return i
		}
	}
	return -1
}
```

### Step 4: Register template functions in `NewRoot`

- [ ] In `internal/cli/root.go`, locate this block inside `NewRoot`:

```go
	root.PersistentFlags().StringVar(&flagPath, "path", "", "project root path (default: auto-detect)")
	root.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "enable verbose logging")
	root.PersistentFlags().BoolVar(&flagColor, "color", false, "force color output")
	root.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "disable color output")
	root.Version = version
	root.SetVersionTemplate(fmt.Sprintf("veil v%s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH))
```

- [ ] Replace it with:

```go
	root.PersistentFlags().StringVar(&flagPath, "path", "", "project root path (default: auto-detect)")
	root.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "enable verbose logging")
	root.PersistentFlags().BoolVar(&flagColor, "color", false, "force color output")
	root.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "disable color output")
	root.Version = version

	// Register template functions used by custom help and version templates.
	// These are package-level in Cobra and are looked up at render time, so the
	// current color state (set by PersistentPreRunE for regular commands, or
	// auto-detected by fatih/color for --help/--version) is respected.
	cobra.AddTemplateFunc("bold", func(s string) string { return ui.Bold.Sprint(s) })
	cobra.AddTemplateFunc("muted", func(s string) string { return ui.Muted.Sprint(s) })
	cobra.AddTemplateFunc("styledFlags", styledFlags)

	// Styled version line: bold "veil vX.Y.Z", muted "(goos/goarch)".
	// Pre-formatted because --version bypasses PersistentPreRunE; fatih/color
	// auto-detects terminal status and NO_COLOR at package init, which covers
	// the common cases.
	root.SetVersionTemplate(fmt.Sprintf("%s %s\n",
		ui.Bold.Sprintf("veil v%s", version),
		ui.Muted.Sprintf("(%s/%s)", runtime.GOOS, runtime.GOARCH)))
```

### Step 5: Build to check for compile errors

- [ ] Run: `go build ./...`

Expected: no output (success). If there are errors, read them, fix, and re-run.

### Step 6: Run existing tests to confirm nothing regressed

- [ ] Run: `go test ./internal/cli/ -run 'TestVersionOutput|TestHelpOutput|TestSubcommandHelp|TestNoArgsShowsHelp' -v`

Expected: all four tests PASS. ANSI escape codes wrap the plain text but don't break substring matching.

### Step 7: Visually verify the version output

- [ ] Run: `go run ./cmd/veil --version`

Expected: in a terminal, `veil vdev` is bold and `(darwin/arm64)` (or your os/arch) is dim. Piped output (e.g. `go run ./cmd/veil --version | cat`) should be plain text because `fatih/color` auto-detects non-TTY.

- [ ] Run: `go run ./cmd/veil --version | cat`

Expected: plain text, no ANSI codes visible.

### Step 8: Commit

- [ ] Run:

```bash
git add internal/cli/root.go
git commit -m "feat(cli): style version output and register template funcs

Adds bold/muted/styledFlags template functions for Cobra and replaces the
plain version template with a styled one. Version line is now bold name
+ muted OS/arch, matching the rest of the CLI."
```

---

## Task 2: Add styled usage template

**Files:**
- Modify: `internal/cli/root.go`

Cobra's help output is produced by *two* templates:
- `HelpTemplate` — renders Long/Short description, then calls `UsageString()`
- `UsageTemplate` — the big template containing `Usage:`, `Available Commands:`, `Flags:`, etc.

All the section headers live in the usage template, so that's what we override. The help template stays at its default (just description + usage).

### Step 1: Add the styled usage template

- [ ] In `internal/cli/root.go`, find the newly-added block:

```go
	// Styled version line: bold "veil vX.Y.Z", muted "(goos/goarch)".
	// Pre-formatted because --version bypasses PersistentPreRunE; fatih/color
	// auto-detects terminal status and NO_COLOR at package init, which covers
	// the common cases.
	root.SetVersionTemplate(fmt.Sprintf("%s %s\n",
		ui.Bold.Sprintf("veil v%s", version),
		ui.Muted.Sprintf("(%s/%s)", runtime.GOOS, runtime.GOARCH)))
```

- [ ] Append this immediately after it (still inside `NewRoot`, before `root.AddCommand(...)`):

```go
	// Styled usage template. Based on Cobra's defaultUsageTemplate (v1.10.2),
	// with `bold` applied to section headers, `muted` applied to command
	// descriptions and the footer hint, and `styledFlags` applied to flag
	// usage blocks. Propagates to all subcommands via Cobra's template
	// inheritance.
	root.SetUsageTemplate(`{{bold "Usage:"}}{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

{{bold "Aliases:"}}
  {{muted .NameAndAliases}}{{end}}{{if .HasExample}}

{{bold "Examples:"}}
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

{{bold "Available Commands:"}}{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{muted .Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{bold .Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{muted .Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

{{bold "Additional Commands:"}}{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{muted .Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

{{bold "Flags:"}}
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces | styledFlags}}{{end}}{{if .HasAvailableInheritedFlags}}

{{bold "Global Flags:"}}
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces | styledFlags}}{{end}}{{if .HasHelpSubCommands}}

{{bold "Additional help topics:"}}{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{muted .Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

{{muted (printf "Use \"%s [command] --help\" for more information about a command." .CommandPath)}}{{end}}
`)
```

### Step 2: Build to check for compile and template parse errors

- [ ] Run: `go build ./...`

Expected: no output. Template parse errors show up only at render time, but we'll catch those in the next step.

### Step 3: Run existing tests

- [ ] Run: `go test ./internal/cli/ -run 'TestVersionOutput|TestHelpOutput|TestSubcommandHelp|TestNoArgsShowsHelp' -v`

Expected: all PASS. If `TestNoArgsShowsHelp` fails with "expected 'Available Commands' in help output", the template has a parse error or an unmatched `{{end}}`. Read the test failure output carefully — Go will show the rendered output, and a missing `Available Commands:` string signals a broken template.

### Step 4: Run the full test suite to catch any broader regressions

- [ ] Run: `go test ./...`

Expected: all PASS.

### Step 5: Visually verify root help

- [ ] Run: `go run ./cmd/veil --help`

Expected in a terminal:
- `Usage:`, `Available Commands:`, `Flags:` — **bold**
- Long description and command names — default color
- Command short descriptions (e.g. `Add a secret to the vault`) — dim/muted
- Flag names (e.g. `--color`) — default color
- Flag descriptions (e.g. `force color output`) — dim/muted
- Footer (`Use "veil [command] --help"...`) — dim/muted

### Step 6: Visually verify subcommand help

- [ ] Run: `go run ./cmd/veil init --help`

Expected: same styling pattern. `Usage:`, `Flags:`, `Global Flags:` bold; flag descriptions muted.

- [ ] Run: `go run ./cmd/veil run --help`

Expected: same styling.

### Step 7: Verify color-off behavior

- [ ] Run: `go run ./cmd/veil --help | cat`

Expected: plain text, no ANSI codes visible (because `fatih/color` auto-detects non-TTY).

- [ ] Run: `NO_COLOR=1 go run ./cmd/veil --help`

Expected: plain text (because `fatih/color` reads `NO_COLOR` at package init).

### Step 8: Commit

- [ ] Run:

```bash
git add internal/cli/root.go
git commit -m "feat(cli): style help output with bold headers and muted descriptions

Applies custom usage template with bold section headers (Usage, Available
Commands, Flags, Global Flags), muted command descriptions, muted footer
hint, and muted flag description text. Inherited by all subcommands via
Cobra's template resolution."
```

---

## Self-Review Complete

Checked:

- **Spec coverage:** All spec sections mapped to tasks. Bold headers → Task 2. Muted command descriptions → Task 2. Muted flag descriptions → Task 1 (`styledFlags`) + Task 2 (template pipeline). Muted footer → Task 2. Bold version name, muted OS/arch → Task 1.
- **Placeholders:** None. Every code block shows exact code.
- **Type consistency:** Template function names (`bold`, `muted`, `styledFlags`) consistent across Task 1 registration and Task 2 template usage. `flagDescriptionStart` and `styledFlags` signatures match their call sites.
- **Completeness:** Test verification steps, visual verification steps, and commit commands included in both tasks.
