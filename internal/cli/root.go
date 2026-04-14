// Package cli implements Veil's command-line interface.
package cli

import (
	"fmt"
	"os"
	"runtime"
	"strings"

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
		Long: `Veil — protect your secrets from AI agents

Quick start:
  veil init          Scan project, vault secrets, write placeholders
  veil run claude    Launch agent with credential injection active
  veil log           See what credentials were used

Veil sits between your AI coding agent and the network. It replaces
real secrets with format-aware placeholders, then injects the real
credentials at the proxy layer — so the agent never sees them.`,

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

	root.AddCommand(initCmd())
	root.AddCommand(runCmd())
	root.AddCommand(statusCmd())
	root.AddCommand(addCmd())
	root.AddCommand(listCmd())
	root.AddCommand(logCmd())
	root.AddCommand(removeCmd())
	root.AddCommand(skipCmd())
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
