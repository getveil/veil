package cli

import (
	"fmt"
	"os"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/runner"
	"github.com/spf13/cobra"
)

func runCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run [flags] -- <command> [args...]",
		Short: "Run a command with secrets injected via proxy",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRun(cmd, args)
		},
	}
	cmd.Flags().SetInterspersed(false)
	return cmd
}

func runRun(cmd *cobra.Command, args []string) error {
	root, err := resolveRoot()
	if err != nil {
		return exitError(err.Error())
	}

	// Check .veil/ exists.
	stateDir := config.ProjectStateDir(root)
	if info, statErr := os.Stat(stateDir); statErr != nil || !info.IsDir() {
		return exitError("project not initialized (run 'veil init' first)")
	}

	result, err := runner.Run(cmd.Context(), runner.Config{
		Root:    root,
		Command: args[0],
		Args:    args[1:],
		Verbose: flagVerbose,
	})
	if err != nil {
		return exitError(fmt.Sprintf("run failed: %v", err))
	}

	os.Exit(result.ExitCode)
	return nil // unreachable
}
