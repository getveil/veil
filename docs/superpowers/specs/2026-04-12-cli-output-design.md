# CLI Output Design

**Date:** 2026-04-12
**Status:** Draft
**Scope:** Structured output redesign across all 6 CLI commands

## Overview

A cohesive design pass across the Veil CLI to add visual hierarchy, color, contextual error hints, and relative timestamps. No changes to command structure, flag names, or `--json` output. The goal is to make the CLI feel professional and scannable without adding interactive TUI complexity.

## Decisions

- **Dependency:** `fatih/color` for ANSI styling. Lightweight, handles `NO_COLOR`, pipe detection, and cross-platform edge cases. No TUI framework.
- **Command structure:** Unchanged. `init`, `run`, `status`, `add`, `list`, `log`.
- **`veil run` presence:** Bookends only — startup line and exit summary. Silent during child execution.
- **`veil init` progress:** Step-by-step with checkmarks as each phase completes.
- **Color control:** Auto-detect TTY with `--color` / `--no-color` overrides and `NO_COLOR` env var support.
- **Errors:** Colored prefix with optional contextual hint when the next action is obvious.

## 1. `internal/ui` Package

A small formatting toolkit. Not a framework — no table rendering, no spinners, no interactive prompts.

### Colors

A fixed palette defined once:

| Name | Use | Color |
|---|---|---|
| Success | Checkmarks, "ready", green status | Green |
| Warning | `!` markers, `(none)` hosts, unscoped nudges | Yellow |
| Error | Error prefix | Red |
| Muted | Hints, headers, footers, separators | Gray/dim |
| Bold | Section labels, emphasized commands in hints | White bold |

All go through `fatih/color` so `NO_COLOR`, pipe detection, and flag overrides are handled automatically.

### Icons

Constants pre-wrapped in their color:

- `IconOK` — green `✓`
- `IconWarn` — yellow `!`
- `IconFail` — red `✗`

### Formatters

```go
// SetColor configures global color mode. Called once from root PersistentPreRun.
// mode is "auto", "always", or "never".
func SetColor(mode string)

// Step prints a success step: "  ✓ msg"
func Step(w io.Writer, msg string)

// Warn prints a warning step: "  ! msg"
func Warn(w io.Writer, msg string)

// Phase prints a muted phase header: "Scanning project..."
func Phase(w io.Writer, msg string)

// Header prints a bold section label.
func Header(w io.Writer, label string)

// TableHeader prints dimmed column headers to a tabwriter.
func TableHeader(w *tabwriter.Writer, cols ...string)

// Footer prints a dimmed footer line.
func Footer(w io.Writer, msg string)

// RelativeTime formats a time relative to now:
//   <60s  → "just now"
//   <60m  → "Xm ago"
//   <24h  → "Xh ago"
//   <7d   → "Xd ago"
//   >=7d  → "2026-04-01" (date only)
func RelativeTime(t time.Time) string

// Error prints a red "error: msg" line to stderr with an optional dimmed hint.
// Returns an error suitable for use as a cobra RunE return value (triggers exit code 1).
func Error(msg string, hint string) error

// Warning prints a yellow "warning: msg" line to stderr with an optional dimmed hint.
func Warning(msg string, hint string)
```

### What it does NOT contain

- Table rendering — keep `tabwriter`
- Spinners or progress bars
- Interactive prompts
- Terminal width detection

## 2. `veil init`

### Output Structure

```
Scanning project...
  ✓ Found 3 .env files
  ✓ Found 1 MCP config

Vaulting secrets...
  ✓ 8 secrets stored in keychain
  ✓ 6 auto-scoped to hosts
  ! 2 unscoped (use veil add --host to scope)

Setting up proxy...
  ✓ CA certificate ready

Veil initialized for /Users/ben/myproject
  .env files processed:  3
  MCP configs processed: 1
  Secrets vaulted:       8
```

### Behavior

- Phase headers ("Scanning project...") printed in muted before work starts.
- `ui.Step()` printed as each step within a phase completes.
- `ui.Warn()` for actionable warnings (unscoped credentials).
- Final summary: "Veil initialized" in green bold, stats in plain aligned text.
- `--dry-run`: prints "would vault: X → Y" lines in muted. No checkmarks.
- `--verbose`: prints "skip (not secret-like)" and "skip (veil:skip)" lines in muted.

### Code Changes

`runInit` in `init.go`: replace `fmt.Fprintf` summary calls with `ui.Phase()`, `ui.Step()`, `ui.Warn()` calls emitted as work happens. The function structure stays the same — it already does work in the right order.

## 3. `veil run`

### Output Structure

```
veil proxy active · 5 credentials loaded
───────────────────────────────────────

  ... child process runs here ...

───────────────────────────────────────
veil session complete
  Duration:    47m 12s
  Injections:  12 across 3 hosts
  Blocked:     0
```

### Behavior

- **Startup line:** printed to stderr after `server.Start()` succeeds, before `child.Start()`. "veil" in green, rest in muted. Credential count from `vlt.List()`.
- **Separator:** fixed-width `─` line (39 chars), muted. No terminal width detection.
- **Exit summary:** printed to stderr after `child.Wait()` and `reclaimForeground()`. "veil" in green.
- **Duration:** wall-clock time from just before `child.Start()` to after `child.Wait()`.
- **Injection stats:** query `auditStore.Summary()` with `Since` set to session start time.
- **Non-zero child exit:** summary still prints. It reports what Veil did, not whether the child succeeded.
- All Veil output goes to **stderr** so child stdout is not polluted.

### Code Changes

`runner.go` `Run()` function: add startup print after step 5 (proxy start), capture start time. Add exit summary after step 11 (reclaim foreground), querying audit store for session stats. The `run.go` CLI wrapper is unchanged.

## 4. `veil status`

### Output Structure

```
Veil Status  /Users/ben/myproject

  Credentials  5 vaulted
  CA           ready ~/.veil/ca.crt

  Last 24h
  Injections   12
  Hosts        api.github.com, api.stripe.com
  Last         2m ago → api.github.com (GITHUB_TOKEN)
```

### Changes from Current

- "Veil Status" bold, project path muted on same line.
- Section labels ("Credentials", "CA", "Last 24h") in bold.
- CA status colored: green "ready" or red "error" with message.
- Last injection uses `ui.RelativeTime()` instead of RFC3339. Arrow `→` instead of `->`.
- Blocked count shown only when > 0 (already does this).
- New: if unscoped credentials exist, a warning surfaces at the bottom: `! 2 credentials have no host scope` with hint `Use veil add --host to scope them`.

### Code Changes

`runStatus` in `status.go`: replace `fmt.Fprintf` with `ui.Header()`, `ui.Bold()`, `ui.Muted()`. Add loop through `v.List()` to count and warn about unscoped credentials. Data gathering unchanged.

## 5. `veil list`

### Output Structure

```
NAME                HOSTS                SOURCE    LAST INJECTED
GITHUB_TOKEN        api.github.com       init      2m ago
STRIPE_SECRET_KEY   api.stripe.com       init      1h ago
OPENAI_API_KEY      api.openai.com       init      3d ago
SLACK_BOT_TOKEN     slack.com            manual    never
DATABASE_URL        (none)               init      never

5 credentials
```

### Changes from Current

- Column headers dimmed via `ui.TableHeader()`.
- "CREATED" column dropped — low-value compared to "LAST INJECTED".
- "LAST INJECTED" uses `ui.RelativeTime()`. "never" stays as plain text.
- `(none)` for empty hosts styled yellow.
- Footer: dimmed credential count.
- `--reveal` still works, adds VALUE column.
- `tabwriter` retained for alignment.

### Code Changes

`runList` in `list.go`: wrap header in `ui.TableHeader()`, timestamps in `ui.RelativeTime()`, add `ui.Footer()`. Remove CREATED column.

## 6. `veil log`

### Output Structure

```
TIMESTAMP        HOST               METHOD   CREDENTIAL        LOCATION
2m ago           api.github.com     POST     GITHUB_TOKEN      header
15m ago          api.github.com     GET      GITHUB_TOKEN      header
1h ago           api.stripe.com     POST     STRIPE_SECRET_KEY body

4 events (last 24h)
```

### Changes from Current

- Column headers dimmed via `ui.TableHeader()`.
- Relative timestamps in human mode. `--json` output unchanged (RFC3339).
- Footer: dimmed count + time range (derived from `--since` value).
- Empty state: "No injection events found." followed by dimmed hint "Injections are logged when you run commands through veil run".
- `tabwriter` retained for alignment.

### Code Changes

`runLog` in `log.go`: wrap header in `ui.TableHeader()`, timestamps in `ui.RelativeTime()`, add `ui.Footer()`. Update empty state message with hint. `--json` codepath untouched.

## 7. Error and Warning Formatting

### Error Format

```
error: project not initialized
  Run veil init to get started
```

"error:" in red bold. Message in plain text. Hint indented, dimmed, with actionable command in bold.

### Warning Format

```
! 2 credentials have no host scope
  Use veil add --host to scope them
```

Yellow `!`. Hint indented, dimmed, with command in bold.

### Error Hint Map

| Error | Hint |
|---|---|
| project not initialized | `Run veil init to get started` |
| project already initialized | `Use --force to reinitialize` |
| credential already exists | `Use --force to overwrite` |
| no value provided | (none) |
| vault/audit open failures | (none — not user-actionable) |

### Code Changes

- `exitError()` in `errors.go` replaced by `ui.Error()`.
- Each call site in CLI commands updated to pass appropriate hint string.
- `main.go`: simplified to just `os.Exit(1)` since `ui.Error()` handles printing.

## 8. Color Control

### Flags

Two new persistent flags on root command:

- `--color` — force color on
- `--no-color` — force color off

Mutually exclusive. `--no-color` wins if both passed.

### Resolution Order

1. `--no-color` flag → off
2. `--color` flag → on
3. `NO_COLOR` env var (any non-empty value) → off
4. TTY detection via `go-isatty` → on if TTY, off if piped

### Code Changes

`root.go`: add two persistent flags. Add `PersistentPreRunE` that resolves color mode and calls `ui.SetColor()`. `ui.SetColor()` sets `color.NoColor` from `fatih/color`.

## Files Changed

| File | Change |
|---|---|
| `internal/ui/ui.go` | **New.** Color palette, icons, formatters (~150 lines) |
| `internal/cli/root.go` | Add `--color`/`--no-color` flags, `PersistentPreRunE` |
| `internal/cli/init.go` | Step-by-step output with `ui.Phase()`, `ui.Step()`, `ui.Warn()` |
| `internal/cli/run.go` | No changes (runner handles bookends) |
| `internal/runner/runner.go` | Add startup line, capture timing, add exit summary |
| `internal/cli/status.go` | Styled sections, relative time, unscoped warning |
| `internal/cli/list.go` | Dimmed headers, relative time, drop CREATED, footer |
| `internal/cli/log.go` | Dimmed headers, relative time, footer, better empty state |
| `internal/cli/errors.go` | Replace `exitError()` with `ui.Error()` usage |
| `internal/cli/helpers.go` | No changes |
| `cmd/veil/main.go` | Simplify error printing |
| `go.mod` | Add `github.com/fatih/color` |

## Not in Scope

- `--json` flag on `list` or `status` (good idea, separate task)
- Custom cobra help formatting
- Spinners or animated progress
- Banner or logo on first run
- `veil add` output changes (already minimal and fine)
