package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/getveil/veil/internal/audit"
	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/ui"
	"github.com/spf13/cobra"
)

// projectHasEverRun reports whether `veil run` has ever been invoked for
// this project. The runner-started marker file is the primary signal; if
// it's missing we fall back to "are there any audit rows at all" so a
// project that ran the proxy before the marker landed still classifies
// correctly.
func projectHasEverRun(root string, store *audit.Store) (bool, error) {
	if _, err := os.Stat(config.RunnerMarkerFile(root)); err == nil {
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return store.HasAnyRows()
}

func logCmd() *cobra.Command {
	var (
		since       string
		host        string
		credential  string
		limit       int
		jsonOutput  bool
		showBlocked bool
	)

	cmd := &cobra.Command{
		Use:   "log",
		Short: "Show audit log of secret injections (blocked and sentinel-leaked events are hidden by default; pass --blocked to include them)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLog(cmd, since, host, credential, limit, jsonOutput, showBlocked)
		},
	}
	cmd.Flags().StringVar(&since, "since", "24h", "show entries since duration (e.g. 24h, 7d) or RFC3339 timestamp")
	cmd.Flags().StringVar(&host, "host", "", "filter by host")
	cmd.Flags().StringVar(&credential, "credential", "", "filter by credential name")
	cmd.Flags().IntVar(&limit, "limit", 100, "max rows to return")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON Lines")
	cmd.Flags().BoolVar(&showBlocked, "blocked", false, "Include host-blocked and sentinel-leaked events in the output.")
	return cmd
}

func runLog(cmd *cobra.Command, since, host, credential string, limit int, jsonOutput, showBlocked bool) error {
	root, err := requireInitializedProject(cmd)
	if err != nil {
		return err
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
		IncludeBlocked: showBlocked,
	})
	if err != nil {
		return cliError(fmt.Sprintf("querying audit log: %v", err), "")
	}

	// Count blocked+leaked rows so the renderer can disclose how many events
	// are hidden by the default filter. Without this, an operator
	// investigating a leak would see a quiet table and never discover that
	// sentinel-leaked rows exist. When showBlocked is true the rows are
	// already in `rows`, so no hidden count applies.
	var hidden int
	if !showBlocked {
		_, blocked, leaked, _, _, summaryErr := store.Summary(sinceTime)
		if summaryErr != nil {
			return cliError(fmt.Sprintf("querying audit log: %v", summaryErr), "")
		}
		hidden = blocked + leaked
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
		// Distinguish "never run" from "active but quiet" using a marker
		// file the runner touches at session start. The marker is the
		// primary signal; an audit-DB row check is the upgrade fallback
		// for projects that ran `veil run` before the marker existed.
		ever, err := projectHasEverRun(root, store)
		if err != nil {
			return cliError(fmt.Sprintf("querying audit log: %v", err), "")
		}
		if !ever {
			_, _ = fmt.Fprintln(w, "No `veil run` has been executed yet — try `veil run <agent>`.")
			return nil
		}
		// Mirror the non-empty footer's `(last %s)` window suffix so the
		// user always knows the scope they're looking at, regardless of
		// whether anything matched.
		_, _ = fmt.Fprintf(w, "No credential injections in the last %s.\n", since)
		_, _ = fmt.Fprintf(w, "  %s\n", ui.Muted.Sprint("The proxy was active but no managed credentials were used in outbound requests"))
		if hidden > 0 {
			// I1: an operator investigating a suspected leak would
			// otherwise see only the quiet "no injections" message even
			// when blocked/leaked rows exist in the window — surface the
			// hidden count and point at the flag that reveals them.
			_, _ = fmt.Fprintf(w, "  %s\n", ui.Muted.Sprintf("%d %s hidden — re-run with --blocked to inspect.", hidden, plural(hidden, "event", "events")))
		}
		return nil
	}

	// All agent-influenced fields are sanitized before they reach stdout so a
	// compromised agent (or malicious upstream host) cannot smuggle ANSI
	// control sequences into the operator's terminal. Timestamps come from
	// a time.Time and are safe.
	type logRow struct {
		timestamp, host, method, credential, location string
	}
	logRows := make([]logRow, len(rows))
	tsW := len("TIMESTAMP")
	hostW := len("HOST")
	methodW := len("METHOD")
	credW := len("CREDENTIAL")
	for i, r := range rows {
		row := logRow{
			timestamp:  ui.RelativeTime(r.Timestamp),
			host:       sanitizeForTerminal(r.Host),
			method:     sanitizeForTerminal(r.Method),
			credential: sanitizeForTerminal(r.CredentialName),
			location:   sanitizeForTerminal(r.Location),
		}
		logRows[i] = row
		tsW = maxInt(tsW, len(row.timestamp))
		hostW = maxInt(hostW, len(row.host))
		methodW = maxInt(methodW, len(row.method))
		credW = maxInt(credW, len(row.credential))
	}

	// Pad plain text first, then apply ANSI styling so escape codes don't
	// break column alignment.
	const gap = "    "
	headers := []string{
		padRight("TIMESTAMP", tsW),
		padRight("HOST", hostW),
		padRight("METHOD", methodW),
		padRight("CREDENTIAL", credW),
		"LOCATION",
	}
	styled := make([]string, len(headers))
	for i, h := range headers {
		styled[i] = ui.Muted.Sprint(h)
	}
	_, _ = fmt.Fprintln(w, strings.Join(styled, gap))

	for _, r := range logRows {
		cells := []string{
			padRight(r.timestamp, tsW),
			padRight(r.host, hostW),
			padRight(r.method, methodW),
			padRight(r.credential, credW),
			r.location,
		}
		_, _ = fmt.Fprintln(w, strings.Join(cells, gap))
	}
	if hidden > 0 {
		// I1: disclose hidden-row count alongside the shown count so the
		// operator can tell a quiet window from an active-but-filtered one.
		// Pointer to --blocked stays in the footer so users don't have to
		// remember the flag name.
		ui.Footer(w, fmt.Sprintf("%d events shown · %d hidden (--blocked to include host-blocked and sentinel-leaked events)", len(rows), hidden))
	} else {
		ui.Footer(w, fmt.Sprintf("%d events (last %s)", len(rows), since))
	}
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

// sanitizeForTerminal replaces C0 (0x00-0x1F), DEL (0x7F), and C1
// (0x80-0x9F) bytes with '?' so a compromised agent or malicious upstream
// host cannot smuggle ANSI control sequences into the operator's terminal
// via audit-log fields like Host, Method, CredentialName, or Location.
// The replacement is byte-for-byte so column widths stay stable. Valid
// UTF-8 round-trips: lead bytes start at 0xC2 and continuation bytes at
// 0x80-0xBF, but no continuation byte at 0x80-0x9F appears without a
// preserved lead byte. JSON output deliberately skips this — machine
// consumers need the raw bytes for forensic analysis.
func sanitizeForTerminal(s string) string {
	idx := -1
	for i := 0; i < len(s); i++ {
		if isUnsafeTerminalByte(s[i]) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return s
	}
	b := []byte(s)
	for i := idx; i < len(b); i++ {
		if isUnsafeTerminalByte(b[i]) {
			b[i] = '?'
		}
	}
	return string(b)
}

func isUnsafeTerminalByte(c byte) bool {
	return c < 0x20 || c == 0x7F || (c >= 0x80 && c <= 0x9F)
}

// parseSince parses a --since value as either a Go duration (with 'd' suffix
// support) or an RFC3339 timestamp, and returns the corresponding time.
func parseSince(s string) (time.Time, error) {
	// Try RFC3339 first.
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}

	if before, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(before)
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
