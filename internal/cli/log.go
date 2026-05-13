package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/getveil/veil/internal/audit"
	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/ui"
	"github.com/spf13/cobra"
)

func logCmd() *cobra.Command {
	var (
		since        string
		host         string
		credential   string
		limit        int
		jsonOutput   bool
		blocked      bool
		suspect      bool
		signerFailed bool
	)

	cmd := &cobra.Command{
		Use:   "log",
		Short: "Show audit log of secret injections",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLog(cmd, since, host, credential, limit, jsonOutput, blocked, suspect, signerFailed)
		},
	}
	cmd.Flags().StringVar(&since, "since", "24h", "show entries since duration (e.g. 24h, 7d) or RFC3339 timestamp")
	cmd.Flags().StringVar(&host, "host", "", "filter by host")
	cmd.Flags().StringVar(&credential, "credential", "", "filter by credential name")
	cmd.Flags().IntVar(&limit, "limit", 100, "max rows to return")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON Lines")
	cmd.Flags().BoolVar(&blocked, "blocked", false, "include blocked credential events")
	cmd.Flags().BoolVar(&suspect, "suspect", false, "show only transform-mismatch suspect rows")
	cmd.Flags().BoolVar(&signerFailed, "signer-failed", false, "show only rows where a signer (AWS SigV4 / GitHub App JWT) failed closed")
	return cmd
}

func runLog(cmd *cobra.Command, since, host, credential string, limit int, jsonOutput, blocked, suspect, signerFailed bool) error {
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
		IncludeSuspect: true,
		SuspectOnly:    suspect,
	})
	if err != nil {
		return cliError(fmt.Sprintf("querying audit log: %v", err), "")
	}

	// --signer-failed is a client-side post-filter: it mirrors the shape of
	// the existing flag-driven include/exclude options without having to
	// teach the audit Filter a fourth orthogonal mode.
	if signerFailed {
		filtered := rows[:0]
		for _, r := range rows {
			if r.Location == "signer_failed" {
				filtered = append(filtered, r)
			}
		}
		rows = filtered
	}

	w := cmd.OutOrStdout()

	if jsonOutput {
		enc := json.NewEncoder(w)
		for _, r := range rows {
			_ = enc.Encode(logEntry{
				Timestamp:   r.Timestamp.Format(time.RFC3339),
				Host:        r.Host,
				Method:      r.Method,
				Path:        r.URLPath,
				Credential:  r.CredentialName,
				Location:    r.Location,
				Suspect:     r.SuspectFlag,
				AuthSignal:  r.AuthSignal,
				SignerError: r.SignerError,
			})
		}
		return nil
	}

	if len(rows) == 0 {
		_, _ = fmt.Fprintln(w, "No credential injections during this period.")
		_, _ = fmt.Fprintf(w, "  %s\n", ui.Muted.Sprint("The proxy was active but no managed credentials were used in outbound requests"))
		return nil
	}

	// Collect plain-text row data for column width calculation. All
	// agent-influenced fields are sanitized before they reach stdout so a
	// compromised agent (or malicious upstream host) cannot smuggle ANSI
	// control sequences into the operator's terminal during post-incident
	// review. The timestamp is formatted from a time.Time and is safe.
	type logRow struct {
		timestamp, host, method, credential, location, signerErr string
		suspect                                                  bool
	}
	logRows := make([]logRow, len(rows))
	// Show the SignerError column whenever any visible row carries one;
	// this keeps the default no-error case visually identical to before.
	var showSignerErr bool
	for i, r := range rows {
		logRows[i] = logRow{
			timestamp:  ui.RelativeTime(r.Timestamp),
			host:       sanitizeForTerminal(r.Host),
			method:     sanitizeForTerminal(r.Method),
			credential: sanitizeForTerminal(r.CredentialName),
			location:   sanitizeForTerminal(r.Location),
			signerErr:  sanitizeForTerminal(r.SignerError),
			suspect:    r.SuspectFlag,
		}
		if r.SignerError != "" {
			showSignerErr = true
		}
	}

	// Compute column widths from data and headers.
	tsW := len("TIMESTAMP")
	hostW := len("HOST")
	methodW := len("METHOD")
	credW := len("CREDENTIAL")
	locW := len("LOCATION")
	sigW := len("SIGNER ERROR")
	for _, r := range logRows {
		tsW = maxInt(tsW, len(r.timestamp))
		hostW = maxInt(hostW, len(r.host))
		methodW = maxInt(methodW, len(r.method))
		credW = maxInt(credW, len(r.credential))
		locW = maxInt(locW, len(r.location))
		sigW = maxInt(sigW, len(r.signerErr))
	}

	// Print header and rows. Pad plain text first, then apply ANSI styling
	// so escape codes don't break column alignment.
	gap := "    "
	if showSignerErr {
		_, _ = fmt.Fprintf(w, "     %s%s%s%s%s%s%s%s%s%s%s\n",
			ui.Muted.Sprint(padRight("TIMESTAMP", tsW)), gap,
			ui.Muted.Sprint(padRight("HOST", hostW)), gap,
			ui.Muted.Sprint(padRight("METHOD", methodW)), gap,
			ui.Muted.Sprint(padRight("CREDENTIAL", credW)), gap,
			ui.Muted.Sprint(padRight("LOCATION", locW)), gap,
			ui.Muted.Sprint("SIGNER ERROR"))
		for _, r := range logRows {
			marker := "   "
			if r.suspect {
				marker = "[!]"
			}
			_, _ = fmt.Fprintf(w, "%s  %s%s%s%s%s%s%s%s%s%s%s\n",
				marker,
				padRight(r.timestamp, tsW), gap,
				padRight(r.host, hostW), gap,
				padRight(r.method, methodW), gap,
				padRight(r.credential, credW), gap,
				padRight(r.location, locW), gap,
				r.signerErr)
		}
	} else {
		_, _ = fmt.Fprintf(w, "     %s%s%s%s%s%s%s%s%s\n",
			ui.Muted.Sprint(padRight("TIMESTAMP", tsW)), gap,
			ui.Muted.Sprint(padRight("HOST", hostW)), gap,
			ui.Muted.Sprint(padRight("METHOD", methodW)), gap,
			ui.Muted.Sprint(padRight("CREDENTIAL", credW)), gap,
			ui.Muted.Sprint("LOCATION"))
		for _, r := range logRows {
			marker := "   "
			if r.suspect {
				marker = "[!]"
			}
			_, _ = fmt.Fprintf(w, "%s  %s%s%s%s%s%s%s%s%s\n",
				marker,
				padRight(r.timestamp, tsW), gap,
				padRight(r.host, hostW), gap,
				padRight(r.method, methodW), gap,
				padRight(r.credential, credW), gap,
				r.location)
		}
	}
	ui.Footer(w, fmt.Sprintf("%d events (last %s)", len(rows), since))
	return nil
}

// logEntry is the JSON representation of an audit log row.
type logEntry struct {
	Timestamp   string `json:"timestamp"`
	Host        string `json:"host"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	Credential  string `json:"credential"`
	Location    string `json:"location"`
	Suspect     bool   `json:"suspect"`
	AuthSignal  string `json:"auth_signal,omitempty"`
	SignerError string `json:"signer_error,omitempty"`
}

// sanitizeForTerminal scrubs bytes that could let a compromised agent or
// malicious upstream host inject control sequences into the operator's
// terminal when `veil log` renders a row. Audit-log fields like Host,
// Method, CredentialName, Location, and SignerError are populated from
// agent-observed HTTP requests and must be treated as untrusted.
//
// The replacement is a 1:1 byte substitution so callers can sanitize
// before computing column widths without rechecking lengths after.
//
//   - C0 controls (0x00-0x1F) -> '?'. Tabs and newlines have no business in
//     a single-cell table column anyway.
//   - DEL (0x7F)              -> '?'
//   - C1 controls (0x80-0x9F) -> '?'. Some terminals treat 0x9B as CSI.
//
// Printable ASCII and the UTF-8 lead/continuation bytes for code points
// at or above U+00A0 pass through untouched. (UTF-8 lead bytes start at
// 0xC2 and continuation bytes at 0x80-0xBF; we deliberately replace the
// raw 0x80-0x9F range because no valid UTF-8 sequence can begin with
// those bytes, and any continuation byte at that value only appears
// after a lead byte we have also kept.) The net effect is that valid
// UTF-8 strings round-trip and only invalid/control bytes are scrubbed.
//
// JSON output is intentionally NOT sanitized: machine consumers need the
// raw bytes to investigate.
func sanitizeForTerminal(s string) string {
	// Fast path: scan first; allocate only if we find something to replace.
	needsScrub := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7F || (c >= 0x80 && c <= 0x9F) {
			needsScrub = true
			break
		}
	}
	if !needsScrub {
		return s
	}
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7F || (c >= 0x80 && c <= 0x9F) {
			b[i] = '?'
			continue
		}
		b[i] = c
	}
	return string(b)
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
