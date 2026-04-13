package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/8enji/veil/internal/audit"
	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/proxy"
	"github.com/spf13/cobra"
)

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show Veil status for the current project",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(cmd)
		},
	}
}

func runStatus(cmd *cobra.Command) error {
	root, err := resolveRoot()
	if err != nil {
		return cliError(err.Error(), "")
	}

	w := cmd.OutOrStdout()

	// Open vault.
	v, err := openVault(root)
	if err != nil {
		return cliError(fmt.Sprintf("opening vault: %v", err), "")
	}

	credCount := len(v.List())

	// Check CA.
	caFile, err := config.CAFile()
	if err != nil {
		return cliError(fmt.Sprintf("CA file path: %v", err), "")
	}

	caStatus := caFile
	if _, caErr := proxy.LoadOrCreateCA(); caErr != nil {
		caStatus += " (error: " + caErr.Error() + ")"
	}

	// Open audit.
	auditDBPath := config.AuditDBFile(root)
	store, err := audit.Open(auditDBPath)
	if err != nil {
		return cliError(fmt.Sprintf("opening audit db: %v", err), "")
	}
	defer func() { _ = store.Close() }()

	since := time.Now().Add(-24 * time.Hour)
	total, blocked, hosts, lastInj, err := store.Summary(since)
	if err != nil {
		return cliError(fmt.Sprintf("querying audit: %v", err), "")
	}

	// Print status.
	_, _ = fmt.Fprintln(w, "Veil Status")
	_, _ = fmt.Fprintf(w, "  Project:      %s\n", root)
	_, _ = fmt.Fprintf(w, "  Credentials:  %d\n", credCount)
	_, _ = fmt.Fprintf(w, "  CA:           %s\n", caStatus)
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "  Last 24h:")
	_, _ = fmt.Fprintf(w, "    Injections:   %d\n", total)
	if blocked > 0 {
		_, _ = fmt.Fprintf(w, "    Blocked:      %d\n", blocked)
	}

	if len(hosts) > 0 {
		_, _ = fmt.Fprintf(w, "    Hosts:        %s\n", strings.Join(hosts, ", "))
	} else {
		_, _ = fmt.Fprintln(w, "    Hosts:        (none)")
	}

	if lastInj != nil {
		_, _ = fmt.Fprintf(w, "    Last:         %s -> %s (%s)\n",
			lastInj.Timestamp.Format(time.RFC3339), lastInj.Host, lastInj.CredentialName)
	} else {
		_, _ = fmt.Fprintln(w, "    Last:         (none)")
	}

	return nil
}
