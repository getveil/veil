package cli

import (
	"fmt"
	"os"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/ui"
	"github.com/spf13/cobra"
)

func syncCmd() *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Reconcile config with vault state",
		Long:  "Adds missing credential scoping entries and removes stale ones from .veil/config.yaml.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSync(cmd, dryRun)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview changes without writing")
	return cmd
}

func runSync(cmd *cobra.Command, dryRun bool) error {
	w := cmd.OutOrStdout()

	root, err := resolveRoot()
	if err != nil {
		return cliError(err.Error(), "")
	}

	// Check .veil/ exists.
	stateDir := config.ProjectStateDir(root)
	if info, statErr := os.Stat(stateDir); statErr != nil || !info.IsDir() {
		return cliError("project not initialized", "Run veil init to get started")
	}

	// Open vault.
	v, err := openVault(root)
	if err != nil {
		return cliError(fmt.Sprintf("opening vault: %v", err), "")
	}

	// Load existing config.
	configPath := config.ConfigFile(root)
	cfg, err := config.Load(configPath)
	if err != nil {
		return cliError(fmt.Sprintf("loading config: %v", err), "")
	}

	// Build vault entries.
	creds := v.List()
	entries := make([]config.ScopingEntry, 0, len(creds))
	for _, cred := range creds {
		entries = append(entries, config.ScopingEntry{
			Name:  cred.Name,
			Hosts: cred.AllowedHosts,
		})
	}

	// Sync.
	result := config.Sync(cfg, entries)

	if len(result.Added) == 0 && len(result.Removed) == 0 {
		fmt.Fprintln(w, "Config is in sync with vault.")
		return nil
	}

	// Report changes.
	for _, name := range result.Added {
		ui.Step(w, fmt.Sprintf("Add %s", name))
	}
	for _, name := range result.Removed {
		ui.Step(w, fmt.Sprintf("Remove %s", name))
	}

	if dryRun {
		fmt.Fprintln(w)
		fmt.Fprintln(w, ui.Muted.Sprint("(dry run — no changes written)"))
		return nil
	}

	// Write updated config using GenerateFromConfig to preserve ignore/skip_hosts.
	content := config.GenerateFromConfig(result.Config)
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		return cliError(fmt.Sprintf("writing config: %v", err), "")
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s\n", ui.Success.Sprint("Config synced"))

	return nil
}
