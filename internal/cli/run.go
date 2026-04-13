package cli

import (
	"fmt"
	"os"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/runner"
	"github.com/8enji/veil/internal/ui"
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
		return cliError(err.Error(), "")
	}

	// Check .veil/ exists.
	stateDir := config.ProjectStateDir(root)
	if info, statErr := os.Stat(stateDir); statErr != nil || !info.IsDir() {
		return cliError("project not initialized", "Run veil init to get started")
	}

	// Load project config.
	configPath := config.ConfigFile(root)
	cfg, err := config.Load(configPath)
	if err != nil {
		return cliError(fmt.Sprintf("loading config: %v", err), "")
	}

	// Drift detection: compare config scoping against vault.
	v, err := openVault(root)
	if err == nil {
		credNames := make([]string, 0, len(v.List()))
		for _, c := range v.List() {
			credNames = append(credNames, c.Name)
		}
		for _, warning := range checkConfigDrift(cfg, credNames) {
			ui.Warn(cmd.ErrOrStderr(), warning)
		}
	}

	result, err := runner.Run(cmd.Context(), runner.Config{
		Root:      root,
		Command:   args[0],
		Args:      args[1:],
		Verbose:   flagVerbose,
		SkipHosts: cfg.SkipHosts,
	})
	if err != nil {
		return cliError(fmt.Sprintf("run failed: %v", err), "")
	}

	os.Exit(result.ExitCode)
	return nil // unreachable
}

// checkConfigDrift compares config scoping entries against vault credentials
// and returns warning messages for any mismatches.
func checkConfigDrift(cfg *config.ProjectConfig, credNames []string) []string {
	if len(credNames) == 0 {
		// Zero credentials loaded — suppress drift warnings.
		return nil
	}

	credSet := make(map[string]bool, len(credNames))
	for _, name := range credNames {
		credSet[name] = true
	}

	var warnings []string

	// Check for stale config entries (config references credential not in vault).
	for name := range cfg.Scoping {
		if !credSet[name] {
			warnings = append(warnings, fmt.Sprintf("config scoping references %q but it is not in the vault (stale entry)", name))
		}
	}

	// Check for uncovered credentials (vault has credential with no config entry).
	for _, name := range credNames {
		if _, ok := cfg.Scoping[name]; !ok {
			warnings = append(warnings, fmt.Sprintf("credential %q has no scoping entry in config", name))
		}
	}

	return warnings
}
