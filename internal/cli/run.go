package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/runner"
	"github.com/8enji/veil/internal/skiphost"
	"github.com/spf13/cobra"
)

func runCmd() *cobra.Command {
	var ephemeralSkip []string
	cmd := &cobra.Command{
		Use:   "run [flags] -- <command> [args...]",
		Short: "Run a command with secrets injected via proxy",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRun(cmd, args, ephemeralSkip)
		},
	}
	cmd.Flags().SetInterspersed(false)
	cmd.Flags().StringArrayVar(&ephemeralSkip, "skip", nil, "host to pass through without proxying (non-persistent, repeatable)")
	return cmd
}

func runRun(cmd *cobra.Command, args []string, ephemeralSkip []string) error {
	root, err := resolveRoot()
	if err != nil {
		return cliError(err.Error(), "")
	}

	stateDir := config.ProjectStateDir(root)
	if info, statErr := os.Stat(stateDir); statErr != nil || !info.IsDir() {
		return cliError("project not initialized", "Run veil init to get started")
	}

	// Load persistent skip hosts.
	skipHosts, err := skiphost.Load(config.SkipHostsFile(root))
	if err != nil {
		return cliError(fmt.Sprintf("reading skip hosts: %v", err), "")
	}

	// Merge ephemeral --skip flags.
	skipHosts = append(skipHosts, ephemeralSkip...)

	result, err := runner.Run(cmd.Context(), runner.Config{
		Root:      root,
		Command:   args[0],
		Args:      args[1:],
		Verbose:   flagVerbose,
		SkipHosts: skipHosts,
	})
	if err != nil {
		return cliError(mapRunError(err), "")
	}

	os.Exit(result.ExitCode)
	return nil // unreachable
}

// mapRunError converts internal runner errors to user-friendly messages.
func mapRunError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "open vault") || strings.Contains(msg, "retrieve master key"):
		return "Cannot decrypt vault. Your keychain may have changed. Run veil init --force to reinitialize."
	case strings.Contains(msg, "load or create CA") || strings.Contains(msg, "CA"):
		return "CA certificate not found or corrupt. Run veil init to regenerate."
	case strings.Contains(msg, "bind") || strings.Contains(msg, "address already in use"):
		return "Cannot start proxy. Another instance may be running."
	default:
		return fmt.Sprintf("run failed: %v", err)
	}
}
