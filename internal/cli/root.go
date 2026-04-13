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
	root.AddCommand(syncCmd())
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
