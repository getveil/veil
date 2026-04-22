// Package ui provides shared formatting primitives for Veil's CLI output.
package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

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
	_, _ = fmt.Fprintf(w, "  %s %s\n", Success.Sprint("✓"), msg)
}

// Warn prints a warning step line: "  ! msg\n"
func Warn(w io.Writer, msg string) {
	_, _ = fmt.Fprintf(w, "  %s %s\n", Warning.Sprint("!"), msg)
}

// Warnf prints a warning step line with Printf-style formatting:
// "  ! <formatted message>\n"
func Warnf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, "  %s %s\n", Warning.Sprint("!"), fmt.Sprintf(format, args...))
}

// Dim prints a single muted line followed by a newline. It replaces the
// common `fmt.Fprintln(w, ui.Muted.Sprint(msg))` pattern seen across the
// runner and signals packages.
func Dim(w io.Writer, msg string) {
	_, _ = fmt.Fprintln(w, Muted.Sprint(msg))
}

// Dimf is the Printf analog of Dim.
func Dimf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintln(w, Muted.Sprint(fmt.Sprintf(format, args...)))
}

// Debugf prints a muted debug line with Printf-style formatting. The output
// is identical to Dimf today; the separate verb documents intent ("this is
// diagnostic") and leaves room for future gating behind a --verbose flag.
func Debugf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintln(w, Muted.Sprint(fmt.Sprintf(format, args...)))
}

// Errorf prints a styled "error: <msg>\n" line to w with Printf-style
// formatting. Use this for non-cobra-return error output (e.g. internal
// package warnings that historically used log.Printf). For cobra RunE
// returns that also render an error line, use FormatError, which returns a
// sentinel error suitable for Cobra's error chain.
func Errorf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, "%s %s\n", Err.Sprint("error:"), fmt.Sprintf(format, args...))
}

// Phase prints a muted phase header line: "msg\n"
func Phase(w io.Writer, msg string) {
	_, _ = fmt.Fprintln(w, Muted.Sprint(msg))
}

// Header prints a bold section label followed by a newline.
func Header(w io.Writer, label string) {
	_, _ = fmt.Fprintln(w, Bold.Sprint(label))
}

// TableHeader prints dimmed, tab-separated column headers to a tabwriter.
func TableHeader(tw *tabwriter.Writer, cols ...string) {
	styled := make([]string, len(cols))
	for i, c := range cols {
		styled[i] = Muted.Sprint(c)
	}
	_, _ = fmt.Fprintln(tw, strings.Join(styled, "\t"))
}

// Footer prints a dimmed footer line preceded by a blank line.
func Footer(w io.Writer, msg string) {
	_, _ = fmt.Fprintf(w, "\n%s\n", Muted.Sprint(msg))
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

// RedactPath replaces $HOME prefixes inside s with "~" so user-facing error
// messages don't leak the user's home-directory layout. Non-home paths pass
// through unchanged. An empty or unresolvable $HOME disables redaction.
func RedactPath(s string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return s
	}
	return strings.ReplaceAll(s, home, "~")
}

// FormatError prints a red "error: msg" line with an optional dimmed hint to w.
// Returns a sentinel error for use as a cobra RunE return value. When a cause
// is supplied, the returned error wraps it via %w so callers can errors.Is
// against the original. Only the first cause is honored; additional arguments
// are ignored so callers cannot accidentally over-specify.
func FormatError(w io.Writer, msg string, hint string, cause ...error) error {
	_, _ = fmt.Fprintf(w, "%s %s\n", Err.Sprint("error:"), msg)
	if hint != "" {
		_, _ = fmt.Fprintf(w, "  %s\n", Muted.Sprint(hint))
	}
	if len(cause) > 0 && cause[0] != nil {
		return fmt.Errorf("%s: %w", msg, cause[0])
	}
	return fmt.Errorf("%s", msg)
}

// FormatWarning prints a yellow "warning: msg" line with an optional dimmed hint to w.
func FormatWarning(w io.Writer, msg string, hint string) {
	_, _ = fmt.Fprintf(w, "%s %s\n", Warning.Sprint("warning:"), msg)
	if hint != "" {
		_, _ = fmt.Fprintf(w, "  %s\n", Muted.Sprint(hint))
	}
}
