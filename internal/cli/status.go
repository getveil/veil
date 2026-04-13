package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/8enji/veil/internal/audit"
	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/proxy"
	"github.com/8enji/veil/internal/runner"
	"github.com/8enji/veil/internal/ui"
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

	creds := v.List()
	credCount := len(creds)

	// Check CA — call once and store result.
	caFile, err := config.CAFile()
	if err != nil {
		return cliError(fmt.Sprintf("CA file path: %v", err), "")
	}

	_, caErr := proxy.LoadOrCreateCA()

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

	// Print header: "Veil Status  /path/to/project"
	_, _ = fmt.Fprintf(w, "%s  %s\n", ui.Bold.Sprint("Veil Status"), ui.Muted.Sprint(root))
	_, _ = fmt.Fprintln(w)

	// Credentials line.
	_, _ = fmt.Fprintf(w, "  %s  %d vaulted\n", ui.Bold.Sprint("Credentials"), credCount)

	// CA line: tilde-abbreviate path if possible.
	caPath := caFile
	if home, herr := os.UserHomeDir(); herr == nil && strings.HasPrefix(caFile, home) {
		caPath = "~" + caFile[len(home):]
	}
	if caErr != nil {
		_, _ = fmt.Fprintf(w, "  %s           %s %s\n",
			ui.Bold.Sprint("CA"),
			ui.Err.Sprint("error"),
			caErr.Error(),
		)
	} else {
		_, _ = fmt.Fprintf(w, "  %s           %s %s\n",
			ui.Bold.Sprint("CA"),
			ui.Success.Sprint("ready"),
			ui.Muted.Sprint(caPath),
		)
	}

	// Proxy status.
	pidPath := config.PidFile(root)
	pid, pidErr := runner.ReadPidFile(pidPath)
	if pidErr == nil && runner.IsProcessAlive(pid) {
		_, _ = fmt.Fprintf(w, "  %s        %s %s\n",
			ui.Bold.Sprint("Proxy"),
			ui.Success.Sprint("active"),
			ui.Muted.Sprintf("(PID %d)", pid),
		)
	} else {
		_, _ = fmt.Fprintf(w, "  %s        %s\n",
			ui.Bold.Sprint("Proxy"),
			ui.Muted.Sprint("not running"),
		)
	}

	_, _ = fmt.Fprintln(w)

	// Last 24h section.
	_, _ = fmt.Fprintf(w, "  %s\n", ui.Bold.Sprint("Last 24h"))
	_, _ = fmt.Fprintf(w, "  Injections   %d\n", total)
	if blocked > 0 {
		_, _ = fmt.Fprintf(w, "  Blocked      %d\n", blocked)
	}

	if len(hosts) > 0 {
		_, _ = fmt.Fprintf(w, "  Hosts        %s\n", strings.Join(hosts, ", "))
	} else {
		_, _ = fmt.Fprintln(w, "  Hosts        (none)")
	}

	if lastInj != nil {
		_, _ = fmt.Fprintf(w, "  Last         %s → %s (%s)\n",
			ui.RelativeTime(lastInj.Timestamp), lastInj.Host, lastInj.CredentialName)
	} else {
		_, _ = fmt.Fprintln(w, "  Last         (none)")
	}

	// Warn about unscoped credentials.
	var unscoped int
	for _, c := range creds {
		if len(c.AllowedHosts) == 0 {
			unscoped++
		}
	}
	if unscoped > 0 {
		_, _ = fmt.Fprintln(w)
		ui.Warn(w, fmt.Sprintf("%d credential(s) have no host scope", unscoped))
		_, _ = fmt.Fprintf(w, "    %s\n", ui.Muted.Sprint("Use veil add --host to scope them"))
	}

	return nil
}
