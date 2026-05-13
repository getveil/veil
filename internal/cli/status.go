package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/getveil/veil/internal/audit"
	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/proxy"
	"github.com/getveil/veil/internal/runner"
	"github.com/getveil/veil/internal/ui"
	"github.com/getveil/veil/internal/vault"
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
	return withVault(cmd, func(root string, v *vault.Vault) error {
		return runStatusInVault(cmd, root, v)
	})
}

func runStatusInVault(cmd *cobra.Command, root string, v *vault.Vault) error {
	w := cmd.OutOrStdout()

	creds := v.List()
	credCount := len(creds)

	// Check CA — call once and store result.
	caFile, err := config.CAFile()
	if err != nil {
		return wrapErr("CA file path", err)
	}

	_, caErr := proxy.LoadOrCreateCA()

	// Open audit.
	auditDBPath := config.AuditDBFile(root)
	store, err := audit.Open(auditDBPath)
	if err != nil {
		return wrapErr("opening audit db", err)
	}
	defer func() { _ = store.Close() }()

	since := time.Now().Add(-24 * time.Hour)
	total, blocked, leaked, hosts, lastInj, err := store.Summary(since)
	if err != nil {
		return wrapErr("querying audit", err)
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

	// Proxy status — enumerate every live session pidfile. Stale files are
	// removed by ListSessions as a side effect.
	sessions, sessErr := runner.ListSessions(config.PidFileGlob(root))
	switch {
	case sessErr != nil:
		_, _ = fmt.Fprintf(w, "  %s        %s %s\n",
			ui.Bold.Sprint("Proxy"),
			ui.Err.Sprint("error"),
			sessErr.Error(),
		)
	case len(sessions) == 0:
		_, _ = fmt.Fprintf(w, "  %s        %s\n",
			ui.Bold.Sprint("Proxy"),
			ui.Muted.Sprint("not running"),
		)
	case len(sessions) == 1:
		_, _ = fmt.Fprintf(w, "  %s        %s %s\n",
			ui.Bold.Sprint("Proxy"),
			ui.Success.Sprint("active"),
			ui.Muted.Sprintf("(PID %d)", sessions[0].PID),
		)
	default:
		pids := make([]string, len(sessions))
		for i, s := range sessions {
			pids[i] = fmt.Sprintf("%d", s.PID)
		}
		_, _ = fmt.Fprintf(w, "  %s        %s %s\n",
			ui.Bold.Sprint("Proxy"),
			ui.Success.Sprintf("%d active sessions", len(sessions)),
			ui.Muted.Sprintf("(PIDs %s)", strings.Join(pids, ", ")),
		)
	}

	_, _ = fmt.Fprintln(w)

	// Last 24h section.
	_, _ = fmt.Fprintf(w, "  %s\n", ui.Bold.Sprint("Last 24h"))
	_, _ = fmt.Fprintf(w, "  Injections   %d\n", total)
	if blocked > 0 {
		_, _ = fmt.Fprintf(w, "  Blocked      %d\n", blocked)
	}
	if leaked > 0 {
		_, _ = fmt.Fprintf(w, "  Leaks        %d\n", leaked)
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

	// Audit health from prior runs — a sidecar persists if a process saw
	// drops or flush errors without a clean Close.
	if health, herr := audit.ReadHealth(auditDBPath); herr == nil && health.Degraded() {
		_, _ = fmt.Fprintln(w)
		ui.Warn(w, "Audit subsystem reported issues in a prior session")
		if health.Dropped > 0 {
			_, _ = fmt.Fprintf(w, "    %s\n",
				ui.Muted.Sprintf("%d event(s) dropped due to full buffer", health.Dropped))
		}
		if !health.LastErrorTime.IsZero() {
			_, _ = fmt.Fprintf(w, "    %s\n",
				ui.Muted.Sprintf("last error %s: %s",
					ui.RelativeTime(health.LastErrorTime), health.LastErrorMsg))
		}
	}

	return nil
}
