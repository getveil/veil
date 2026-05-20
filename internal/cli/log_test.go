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

// TestLogCmd_ZeroState_NeverRun verifies that `veil log` on a freshly
// init'd project that has never been `veil run` prints the "no veil run
// executed yet" hint instead of the misleading "proxy was active" message.
// The audit DB has no injection rows in either case; only the no-rows-ever
// signal distinguishes a project that was running but quiet from one that
// has never started the proxy.
func TestLogCmd_ZeroState_NeverRun(t *testing.T) {
	root := initProject(t)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"log", "--path", root})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("log: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "No `veil run` has been executed yet") {
		t.Errorf("expected 'never-run' hint, got:\n%s", s)
	}
	if !strings.Contains(s, "veil run") {
		t.Errorf("expected suggested command, got:\n%s", s)
	}
	// The misleading "proxy was active" message must NOT appear.
	if strings.Contains(s, "proxy was active") {
		t.Errorf("misleading 'proxy was active' message must not appear when no run has occurred:\n%s", s)
	}
}

// TestLogCmd_ZeroState_AfterRun verifies that `veil log` on a project that
// HAS produced injection rows (just not within the current --since window)
// keeps the existing zero-state message about an active proxy with no
// injections during the period.
func TestLogCmd_ZeroState_AfterRun(t *testing.T) {
	root := initProject(t)

	// Seed a row from outside the default 24h window so the filter returns
	// zero but the DB still has prior activity.
	store, err := audit.Open(config.AuditDBFile(root))
	if err != nil {
		t.Fatalf("audit open: %v", err)
	}
	store.Record(audit.Injection{
		Timestamp:      time.Now().Add(-72 * time.Hour),
		RequestID:      "req-old",
		Host:           "api.example.com",
		Method:         "GET",
		Location:       "header",
		CredentialName: "old-cred",
	})
	store.DrainForTest()
	_ = store.Close()

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"log", "--path", root})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("log: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "No credential injections during this period") {
		t.Errorf("expected period-bounded zero-state, got:\n%s", s)
	}
	if strings.Contains(s, "No `veil run` has been executed yet") {
		t.Errorf("must not show 'never-run' hint when DB has prior rows:\n%s", s)
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
	//   Location       — embedded ESC
	//   Method         — embedded ESC
	const (
		nastyHost       = "evil\x1b[2J\x1b[H.com"
		nastyCredential = "cred\x07alert"
		nastyLocation   = "loc\x1bmix"
		nastyMethod     = "GE\x1bT"
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
		nastyLocation,
		nastyMethod,
	} {
		if strings.Contains(humanS, bad) {
			t.Errorf("human output contains unsanitized attacker payload %q", bad)
		}
	}
	// And spot-check that the specific nasty byte sequences are absent.
	for _, bad := range []string{
		"\x1b[2J", // clear screen
		"\x1b[H",  // cursor home
		"\x07",    // BEL
	} {
		if strings.Contains(humanS, bad) {
			t.Errorf("human output contains raw control sequence %q", bad)
		}
	}
	// Belt-and-braces: ensure data rows contain no stray C0/DEL/C1 bytes
	// from the row payload. Skip the header line (uses ANSI styling, so
	// it legitimately contains 0x1B) and the footer line ("N events ...").
	lines := strings.Split(humanS, "\n")
	for i, line := range lines {
		if i == 0 || line == "" || strings.Contains(line, "events (last") {
			continue
		}
		for j := 0; j < len(line); j++ {
			c := line[j]
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
		"host":       nastyHost,
		"method":     nastyMethod,
		"credential": nastyCredential,
		"location":   nastyLocation,
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

// TestLogCmd_PublicFlagsVisible verifies that --since, --host,
// --credential, and --blocked flags remain visible in --help output.
func TestLogCmd_PublicFlagsVisible(t *testing.T) {
	cmd := logCmd()
	for _, name := range []string{"since", "host", "credential", "blocked"} {
		f := cmd.Flags().Lookup(name)
		if f == nil {
			t.Fatalf("flag --%s missing", name)
		}
		if f.Hidden {
			t.Errorf("flag --%s must remain visible in --help", name)
		}
	}
}

// seedLogFixtures inserts one regular injection, one blocked event, and
// one sentinel-leaked event into the audit DB for the given project root.
// Returns the credential names so callers can assert on row contents
// without coupling to byte-level details.
func seedLogFixtures(t *testing.T, root string) (regularCred, blockedCred, leakedCred string) {
	t.Helper()
	regularCred = "regular-cred"
	blockedCred = "blocked-cred"
	leakedCred = "leaked-cred"

	store, err := audit.Open(config.AuditDBFile(root))
	if err != nil {
		t.Fatalf("audit open: %v", err)
	}
	now := time.Now()

	// Regular injection — should always appear in `veil log`.
	store.Record(audit.Injection{
		Timestamp:      now.Add(-3 * time.Second),
		RequestID:      "req-regular",
		Host:           "api.example.com",
		Method:         "POST",
		URLPath:        "/v1/chat",
		Location:       "header",
		CredentialName: regularCred,
	})

	// Host-blocked event.
	store.Record(audit.Injection{
		Timestamp:      now.Add(-2 * time.Second),
		RequestID:      "req-blocked",
		Host:           "evil.example.com",
		Method:         "POST",
		URLPath:        "/steal",
		Location:       "blocked",
		CredentialName: blockedCred,
	})

	// Sentinel-leaked event — the fail-closed guard refused to forward.
	store.Record(audit.Injection{
		Timestamp:      now.Add(-time.Second),
		RequestID:      "req-leaked",
		Host:           "api.example.com",
		Method:         "POST",
		URLPath:        "/v1/chat",
		Location:       "leaked",
		CredentialName: leakedCred,
	})

	store.DrainForTest()
	_ = store.Close()
	return
}

// TestLog_DefaultExcludesLeakedRows verifies the default `veil log`
// output hides both blocked and leaked rows, mirroring the session
// footer's "N injections" count. Without this exclusion the footer
// would say "0 injections" while the log table renders leaked rows
// with empty bytes/credential fields — a direct contradiction.
func TestLog_DefaultExcludesLeakedRows(t *testing.T) {
	root := initProject(t)
	regularCred, blockedCred, leakedCred := seedLogFixtures(t, root)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"log", "--path", root})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("log: %v", err)
	}
	s := out.String()

	if !strings.Contains(s, regularCred) {
		t.Errorf("default output must include regular injection %q:\n%s", regularCred, s)
	}
	if strings.Contains(s, blockedCred) {
		t.Errorf("default output must hide blocked rows; saw %q:\n%s", blockedCred, s)
	}
	if strings.Contains(s, leakedCred) {
		t.Errorf("default output must hide leaked rows; saw %q:\n%s", leakedCred, s)
	}
	if strings.Contains(s, "blocked") {
		t.Errorf("default output must not show the 'blocked' location label:\n%s", s)
	}
	if strings.Contains(s, "leaked") {
		t.Errorf("default output must not show the 'leaked' location label:\n%s", s)
	}
}

// TestLog_BlockedFlagShowsBlockedAndLeaked verifies that --blocked
// surfaces BOTH host-blocked and sentinel-leaked rows alongside the
// regular injection, so operators can investigate refusal events from
// the same command.
func TestLog_BlockedFlagShowsBlockedAndLeaked(t *testing.T) {
	root := initProject(t)
	regularCred, blockedCred, leakedCred := seedLogFixtures(t, root)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"log", "--path", root, "--blocked"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("log --blocked: %v", err)
	}
	s := out.String()

	for _, want := range []string{regularCred, blockedCred, leakedCred} {
		if !strings.Contains(s, want) {
			t.Errorf("--blocked output missing credential %q:\n%s", want, s)
		}
	}
	if !strings.Contains(s, "blocked") {
		t.Errorf("--blocked output must show 'blocked' location:\n%s", s)
	}
	if !strings.Contains(s, "leaked") {
		t.Errorf("--blocked output must show 'leaked' location:\n%s", s)
	}

	// Footer reports the row count for the displayed window.
	if !strings.Contains(s, "3 events") {
		t.Errorf("--blocked footer must report 3 events; got:\n%s", s)
	}
}

// TestLog_JSONSchemaUnchangedForRegularRows verifies that --json output
// for a regular injection still has exactly the documented field set,
// so existing machine consumers don't break when the --blocked flag is
// added. The blocked-row schema is the same — we only exercise the
// regular row here because that's the path consumers rely on.
func TestLog_JSONSchemaUnchangedForRegularRows(t *testing.T) {
	root := initProject(t)
	regularCred, _, _ := seedLogFixtures(t, root)

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"log", "--path", root, "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("log --json: %v", err)
	}

	// Parse the regular row (default --json mode excludes blocked/leaked).
	var entry map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("invalid JSON line %q: %v", line, err)
		}
		if entry["credential"] == regularCred {
			break
		}
	}
	if entry["credential"] != regularCred {
		t.Fatalf("did not find regular row in JSON output; got %v", entry)
	}

	wantKeys := map[string]bool{
		"timestamp":  true,
		"host":       true,
		"method":     true,
		"path":       true,
		"credential": true,
		"location":   true,
	}
	for k := range entry {
		if !wantKeys[k] {
			t.Errorf("JSON entry contains unexpected key %q (schema drift):\n%v", k, entry)
		}
		delete(wantKeys, k)
	}
	for k := range wantKeys {
		t.Errorf("JSON entry missing expected key %q:\n%v", k, entry)
	}
}
