package cli

import (
	"fmt"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/proxy"
	"github.com/spf13/cobra"
)

func trustCmd() *cobra.Command {
	var uninstall bool
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Install or uninstall Veil's root CA in the system trust store",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTrust(cmd, uninstall)
		},
	}
	cmd.Flags().BoolVar(&uninstall, "uninstall", false, "remove CA from system trust store")
	return cmd
}

func runTrust(cmd *cobra.Command, uninstall bool) error {
	caFile, err := config.CAFile()
	if err != nil {
		return exitError(fmt.Sprintf("CA file path: %v", err))
	}

	w := cmd.OutOrStdout()

	if uninstall {
		if err := proxy.UninstallCA(caFile); err != nil {
			return exitError(fmt.Sprintf("removing CA: %v", err))
		}
		_, _ = fmt.Fprintln(w, "CA removed from system trust store.")
		return nil
	}

	_, _ = fmt.Fprintln(w, "Installing Veil's root CA into the system trust store.")
	_, _ = fmt.Fprintln(w, "You may be prompted for your password.")

	if err := proxy.InstallCA(caFile); err != nil {
		return exitError(fmt.Sprintf("installing CA: %v", err))
	}

	_, _ = fmt.Fprintln(w, "CA installed successfully.")
	return nil
}
