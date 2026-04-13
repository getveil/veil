// Package cli implements Veil's command-line interface.
package cli

import "github.com/spf13/cobra"

var (
	flagPath    string
	flagVerbose bool
)

// NewRoot returns the top-level cobra command for veil.
func NewRoot(version string) *cobra.Command {
	root := &cobra.Command{
		Use:   "veil",
		Short: "Secure AI coding agents by intercepting secrets at the network layer",
		Long:  "Veil intercepts outbound HTTPS traffic from AI agents, replacing placeholder values with real credentials so the agent never sees real secrets.",

		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&flagPath, "path", "", "project root path (default: auto-detect)")
	root.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "enable verbose logging")
	root.Version = version

	root.AddCommand(initCmd())
	root.AddCommand(runCmd())
	root.AddCommand(statusCmd())
	root.AddCommand(addCmd())
	root.AddCommand(listCmd())
	root.AddCommand(logCmd())
	return root
}
