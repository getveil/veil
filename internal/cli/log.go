package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/8enji/veil/internal/audit"
	"github.com/8enji/veil/internal/config"
	"github.com/spf13/cobra"
)

func logCmd() *cobra.Command {
	var (
		since      string
		host       string
		credential string
		limit      int
		jsonOutput bool
		blocked    bool
	)

	cmd := &cobra.Command{
		Use:   "log",
		Short: "Show audit log of secret injections",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLog(cmd, since, host, credential, limit, jsonOutput, blocked)
		},
	}
	cmd.Flags().StringVar(&since, "since", "24h", "show entries since duration (e.g. 24h, 7d) or RFC3339 timestamp")
	cmd.Flags().StringVar(&host, "host", "", "filter by host")
	cmd.Flags().StringVar(&credential, "credential", "", "filter by credential name")
	cmd.Flags().IntVar(&limit, "limit", 100, "max rows to return")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON Lines")
	cmd.Flags().BoolVar(&blocked, "blocked", false, "include blocked credential events")
	return cmd
}

func runLog(cmd *cobra.Command, since, host, credential string, limit int, jsonOutput, blocked bool) error {
	root, err := resolveRoot()
	if err != nil {
		return cliError(err.Error(), "")
	}

	sinceTime, err := parseSince(since)
	if err != nil {
		return cliError(fmt.Sprintf("invalid --since value: %v", err), "")
	}

	auditDBPath := config.AuditDBFile(root)
	store, err := audit.Open(auditDBPath)
	if err != nil {
		return cliError(fmt.Sprintf("opening audit db: %v", err), "")
	}
	defer func() { _ = store.Close() }()

	rows, err := store.Query(audit.Filter{
		Since:          sinceTime,
		Host:           host,
		CredentialName: credential,
		Limit:          limit,
		IncludeBlocked: blocked,
	})
	if err != nil {
		return cliError(fmt.Sprintf("querying audit log: %v", err), "")
	}

	w := cmd.OutOrStdout()

	if jsonOutput {
		enc := json.NewEncoder(w)
		for _, r := range rows {
			_ = enc.Encode(logEntry{
				Timestamp:  r.Timestamp.Format(time.RFC3339),
				Host:       r.Host,
				Method:     r.Method,
				Path:       r.URLPath,
				Credential: r.CredentialName,
				Location:   r.Location,
			})
		}
		return nil
	}

	if len(rows) == 0 {
		_, _ = fmt.Fprintln(w, "No injection events found.")
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 4, 4, ' ', 0)
	_, _ = fmt.Fprintln(tw, "TIMESTAMP\tHOST\tMETHOD\tCREDENTIAL\tLOCATION")
	for _, r := range rows {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			r.Timestamp.Format(time.RFC3339),
			r.Host,
			r.Method,
			r.CredentialName,
			r.Location,
		)
	}
	_ = tw.Flush()
	return nil
}

// logEntry is the JSON representation of an audit log row.
type logEntry struct {
	Timestamp  string `json:"timestamp"`
	Host       string `json:"host"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Credential string `json:"credential"`
	Location   string `json:"location"`
}

// parseSince parses a --since value as either a Go duration (with 'd' suffix
// support) or an RFC3339 timestamp, and returns the corresponding time.
func parseSince(s string) (time.Time, error) {
	// Try RFC3339 first.
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}

	// Handle 'd' suffix: convert to hours.
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid day duration %q", s)
		}
		return time.Now().Add(-time.Duration(days) * 24 * time.Hour), nil
	}

	// Standard Go duration.
	d, err := time.ParseDuration(s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid duration %q", s)
	}
	return time.Now().Add(-d), nil
}
