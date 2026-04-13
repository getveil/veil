// Package ui provides shared formatting primitives for Veil's CLI output.
package ui

import (
	"fmt"
	"io"
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
