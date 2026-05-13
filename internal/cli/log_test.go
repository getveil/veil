package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/getveil/veil/internal/audit"
	"github.com/getveil/veil/internal/config"
)

// TestLogCmd_SignerFailedFilter verifies that `veil log --signer-failed`
// returns only rows whose Location == "signer_failed" and renders the
// SignerError column alongside.
func TestLogCmd_SignerFailedFilter(t *testing.T) {
	root := initProject(t)

	// Seed the audit DB with one signer_failed and one ordinary row.
	store, err := audit.Open(config.AuditDBFile(root))
	if err != nil {
		t.Fatalf("audit open: %v", err)
	}
	store.Record(audit.Injection{
		Timestamp:      time.Now(),
		RequestID:      "req-ok",
		Host:           "s3.amazonaws.com",
		Method:         "GET",
		Location:       "aws_sigv4_resigned",
		CredentialName: "aws-prod",
	})
	store.Record(audit.Injection{
		Timestamp:   time.Now(),
		RequestID:   "req-fail",
		Host:        "s3.amazonaws.com",
		Method:      "GET",
		Location:    "signer_failed",
		SignerError: "unknown_access_key_id",
	})
	store.DrainForTest()
	_ = store.Close()

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"log", "--path", root, "--signer-failed"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("log --signer-failed: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "signer_failed") {
		t.Errorf("missing 'signer_failed' location in output:\n%s", s)
	}
	if !strings.Contains(s, "unknown_access_key_id") {
		t.Errorf("missing SignerError class in output:\n%s", s)
	}
	if strings.Contains(s, "aws_sigv4_resigned") {
		t.Errorf("--signer-failed should exclude aws_sigv4_resigned, got:\n%s", s)
	}
}

// TestLogCmd_JSON_IncludesSignerError verifies that `veil log --json` emits
// the signer_error field on rows where Location == "signer_failed", so
// downstream tooling can consume the failure class programmatically.
func TestLogCmd_JSON_IncludesSignerError(t *testing.T) {
	root := initProject(t)

	store, err := audit.Open(config.AuditDBFile(root))
	if err != nil {
		t.Fatalf("audit open: %v", err)
	}
	store.Record(audit.Injection{
		Timestamp:   time.Now(),
		RequestID:   "req-fail",
		Host:        "iam.amazonaws.com",
		Method:      "GET",
		URLPath:     "/",
		Location:    "signer_failed",
		SignerError: "unknown_access_key_id",
	})
	store.DrainForTest()
	_ = store.Close()

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"log", "--path", root, "--signer-failed", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("log --signer-failed --json: %v", err)
	}

	// Output is JSON Lines. Parse the first non-empty line.
	var entry map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("invalid JSON line %q: %v", line, err)
		}
		break
	}
	got, ok := entry["signer_error"]
	if !ok {
		t.Fatalf("signer_error field missing from JSON output:\n%s", out.String())
	}
	if got != "unknown_access_key_id" {
		t.Errorf("signer_error = %v, want %q", got, "unknown_access_key_id")
	}
}

// TestLogCmd_SanitizesTerminalEscapes verifies that audit-log fields are
// scrubbed of control bytes before being rendered to the operator's
// terminal, so a compromised agent (or malicious upstream host) cannot
// plant ANSI / OSC escape sequences that get interpreted when an
// operator runs `veil log` during post-incident review. The test also
// confirms that `--json` mode preserves the original bytes verbatim so
// programmatic consumers still see the actual data.
func TestLogCmd_SanitizesTerminalEscapes(t *testing.T) {
	root := initProject(t)

	// Fields with deliberately nasty content:
	//   Host           — CSI clear-screen + cursor-home (classic terminal hijack)
	//   CredentialName — BEL (0x07) (audible)
	//   SignerError    — OSC 8 hyperlink escape (mislead an operator into clicking)
	//   Location       — embedded ESC
	const (
		nastyHost        = "evil\x1b[2J\x1b[H.com"
		nastyCredential  = "cred\x07alert"
		nastySignerError = "\x1b]8;;http://attacker/\x1b\\fake\x1b]8;;\x1b\\"
		nastyLocation    = "loc\x1bmix"
		nastyMethod      = "GE\x1bT"
	)

	store, err := audit.Open(config.AuditDBFile(root))
	if err != nil {
		t.Fatalf("audit open: %v", err)
	}
	store.Record(audit.Injection{
		Timestamp:      time.Now(),
		RequestID:      "req-nasty",
		Host:           nastyHost,
		Method:         nastyMethod,
		URLPath:        "/",
		Location:       nastyLocation,
		CredentialName: nastyCredential,
		SignerError:    nastySignerError,
	})
	store.DrainForTest()
	_ = store.Close()

	// --- Human-readable mode: terminal escapes must be scrubbed. ---
	humanCmd := NewRoot("test")
	humanOut := new(bytes.Buffer)
	humanCmd.SetOut(humanOut)
	humanCmd.SetErr(new(bytes.Buffer))
	humanCmd.SetArgs([]string{"log", "--path", root})
	if err := humanCmd.Execute(); err != nil {
		t.Fatalf("log: %v", err)
	}

	// Strip ANSI styling applied by ui.Muted (the header coloring is
	// constant and trusted; we are only checking that *agent-controlled*
	// bytes can no longer reach the terminal as control sequences).
	// We do this by scanning for any byte that came from the untrusted
	// data: explicit raw escape, BEL, or anything else in the C0/C1/DEL
	// ranges WITHIN the row payload. Rather than try to whitelist the
	// trusted styling escapes (which would be brittle), we assert that
	// the *exact attacker payloads* do not appear in the output.
	humanS := humanOut.String()
	for _, bad := range []string{
		nastyHost,
		nastyCredential,
		nastySignerError,
		nastyLocation,
		nastyMethod,
	} {
		if strings.Contains(humanS, bad) {
			t.Errorf("human output contains unsanitized attacker payload %q", bad)
		}
	}
	// And spot-check that the specific nasty byte sequences are absent.
	for _, bad := range []string{
		"\x1b[2J",  // clear screen
		"\x1b[H",   // cursor home
		"\x1b]8;;", // OSC 8 hyperlink start
		"\x07",     // BEL
	} {
		if strings.Contains(humanS, bad) {
			t.Errorf("human output contains raw control sequence %q", bad)
		}
	}
	// Belt-and-braces: ensure the visible portion of each row (after we
	// drop the trusted ui.Muted styling for the header) contains no
	// stray C0/DEL/C1 bytes from the row payload. The header line uses
	// ANSI styling so we can't blanket-ban 0x1B over the whole output;
	// instead, check each data row by lines that start with the row
	// marker ("   " or "[!]"). That marker prefix never appears in the
	// header.
	for _, line := range strings.Split(humanS, "\n") {
		if !strings.HasPrefix(line, "   ") && !strings.HasPrefix(line, "[!]") {
			continue
		}
		for i := 0; i < len(line); i++ {
			c := line[i]
			if c < 0x20 || c == 0x7F || (c >= 0x80 && c <= 0x9F) {
				// Allow LF only — but we split on \n already, so no LF
				// can appear inside `line`. Anything else is a bug.
				t.Errorf("data row contains control byte 0x%02X: %q", c, line)
				break
			}
		}
	}

	// --- JSON mode: original bytes must round-trip. Machine consumers
	// need to see what actually came over the wire, not a scrubbed
	// version. ---
	jsonCmd := NewRoot("test")
	jsonOut := new(bytes.Buffer)
	jsonCmd.SetOut(jsonOut)
	jsonCmd.SetErr(new(bytes.Buffer))
	jsonCmd.SetArgs([]string{"log", "--path", root, "--json"})
	if err := jsonCmd.Execute(); err != nil {
		t.Fatalf("log --json: %v", err)
	}
	// Parse the first non-empty JSON line.
	var entry map[string]any
	for _, line := range strings.Split(strings.TrimSpace(jsonOut.String()), "\n") {
		if line == "" {
			continue
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("invalid JSON line %q: %v", line, err)
		}
		break
	}
	// After JSON decoding, the field values must equal the original
	// attacker bytes exactly.
	cases := map[string]string{
		"host":         nastyHost,
		"method":       nastyMethod,
		"credential":   nastyCredential,
		"location":     nastyLocation,
		"signer_error": nastySignerError,
	}
	for k, want := range cases {
		got, ok := entry[k]
		if !ok {
			t.Errorf("JSON field %q missing", k)
			continue
		}
		gotStr, ok := got.(string)
		if !ok {
			t.Errorf("JSON field %q not a string: %T %v", k, got, got)
			continue
		}
		if gotStr != want {
			t.Errorf("JSON field %q round-trip mismatch:\n got %q\nwant %q", k, gotStr, want)
		}
	}
}
