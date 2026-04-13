# Styled Help & Version Output

**Date:** 2026-04-13
**Status:** Approved

## Problem

`veil help` and `veil --version` use Cobra's unstyled defaults while every other
command (`status`, `list`, `init`, etc.) uses the `ui` package with bold, colored,
and muted text. The inconsistency makes these two surfaces feel unfinished.

## Approach

Register Cobra template functions (`bold`, `muted`) that delegate to `ui.Bold.Sprint()`
and `ui.Muted.Sprint()`. Apply custom help and version templates using those functions.
This is Cobra's built-in customization mechanism and the standard approach used by
polished CLIs like `gh`.

## Help Template Styling

| Element | Style | Rationale |
|---------|-------|-----------|
| Section headers (`Usage:`, `Available Commands:`, `Flags:`, `Global Flags:`) | `Bold` | Matches `ui.Header` pattern |
| Long/short description | default | Primary content, no dimming |
| Command names in command list | default | Primary content |
| Command/flag descriptions | `Muted` | Secondary info, matches `list` column style |
| Flag names | default | Primary content |
| Footer hint (`Use "veil [command] --help"...`) | `Muted` | Matches `ui.Footer` pattern |
| Aliases line | `Muted` | Secondary info |

## Version Template Styling

```
veil v0.1.0 (darwin/arm64)
```

- `veil v0.1.0` — Bold
- `(darwin/arm64)` — Muted

## Implementation

All changes in `internal/cli/root.go`:

1. Add `text/template` import for `template.FuncMap`.
2. After creating the root command, call `root.AddTemplateFuncs()` with a `FuncMap`
   mapping `"bold"` and `"muted"` to `ui.Bold.Sprint()` and `ui.Muted.Sprint()`.
3. Set `root.SetHelpTemplate()` with a custom template that applies `bold` to section
   headers and `muted` to descriptions and the footer hint.
4. Set `root.SetVersionTemplate()` with a template that bolds the name+version and
   mutes the OS/arch.

No new files. No changes to `ui.go`.

## Color-Off Behavior

The existing `resolveColor()` / `ui.SetColor()` / `fatih/color.NoColor` pipeline
handles `--no-color`, `NO_COLOR` env, and non-TTY detection. When color is off,
`ui.Bold.Sprint()` returns plain text. The templates degrade gracefully — no special
handling needed.

## Subcommand Inheritance

Cobra template functions registered on the root command propagate to all subcommands.
`veil init --help`, `veil run --help`, etc. are styled automatically.

## Testing

Existing CLI tests that capture help output will verify the template renders without
errors. No new test files needed — the templates use the same `ui` primitives already
tested in `ui_test.go`.
