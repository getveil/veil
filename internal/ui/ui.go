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
