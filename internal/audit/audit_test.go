package audit

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open(%q): %v", dbPath, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func makeInjection(host, cred string, ts time.Time) Injection {
	return Injection{
		Timestamp:      ts,
		RequestID:      "01TESTULID000000000000000",
		Host:           host,
		Method:         "POST",
		URLPath:        "/v1/chat",
		CredentialID:   "cred-" + cred,
		CredentialName: cred,
		AgentPID:       1234,
		AgentCmd:       "test-agent",
		BytesBefore:    100,
		BytesAfter:     120,
		Location:       "header",
	}
}

func TestOpenAndSchema(t *testing.T) {
	s := openTestStore(t)

	rows, err := s.db.Query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
	if err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	defer func() { _ = rows.Close() }()

	tables := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		tables[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}

	if !tables["injections"] {
		t.Error("expected 'injections' table to exist")
	}
	if !tables["schema_version"] {
		t.Error("expected 'schema_version' table to exist")
	}

	var v int
	if err := s.db.QueryRow("SELECT v FROM schema_version").Scan(&v); err != nil {
		t.Fatalf("query schema_version: %v", err)
	}
	if v != 4 {
		t.Errorf("schema_version = %d, want 4", v)
	}
}

func TestRecordAndQuery(t *testing.T) {
	s := openTestStore(t)

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	injections := []Injection{
		makeInjection("api.openai.com", "openai-key", base),
		makeInjection("api.openai.com", "openai-key", base.Add(1*time.Second)),
		makeInjection("api.anthropic.com", "anthropic-key", base.Add(2*time.Second)),
		makeInjection("api.anthropic.com", "anthropic-key", base.Add(3*time.Second)),
		makeInjection("api.cohere.com", "cohere-key", base.Add(4*time.Second)),
	}
	for _, inj := range injections {
		s.Record(inj)
	}
	s.flushPending()

	// No filter: get all 5.
	rows, err := s.Query(Filter{})
	if err != nil {
		t.Fatalf("Query(no filter): %v", err)
	}
	if len(rows) != 5 {
		t.Errorf("no filter: got %d rows, want 5", len(rows))
	}

	// Host filter.
	rows, err = s.Query(Filter{Host: "api.openai.com"})
	if err != nil {
		t.Fatalf("Query(host): %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("host filter: got %d rows, want 2", len(rows))
	}

	// CredentialName filter.
	rows, err = s.Query(Filter{CredentialName: "anthropic-key"})
	if err != nil {
		t.Fatalf("Query(cred): %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("cred filter: got %d rows, want 2", len(rows))
	}

	// Since filter.
	rows, err = s.Query(Filter{Since: base.Add(2 * time.Second)})
	if err != nil {
		t.Fatalf("Query(since): %v", err)
	}
	if len(rows) != 3 {
		t.Errorf("since filter: got %d rows, want 3", len(rows))
	}

	// Limit.
	rows, err = s.Query(Filter{Limit: 2})
	if err != nil {
		t.Fatalf("Query(limit): %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("limit filter: got %d rows, want 2", len(rows))
	}
}

// TestQuery_HostFilter_TolerantMatching verifies the host filter accepts a
// bare hostname against host:port rows, ignores case, and still matches when
// the caller does pass an explicit port. Stored rows in production carry the
// host:port form (req.URL.Host) so a strict equality match made the
// documented `--host <name>` filter silently empty.
func TestQuery_HostFilter_TolerantMatching(t *testing.T) {
	s := openTestStore(t)

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.Record(makeInjection("api.github.com:443", "gh", base))
	s.Record(makeInjection("api.github.com:443", "gh", base.Add(time.Second)))
	s.Record(makeInjection("api.openai.com:443", "oai", base.Add(2*time.Second)))
	s.flushPending()

	cases := []struct {
		name, host string
		want       int
	}{
		{"bare hostname matches host:port", "api.github.com", 2},
		{"explicit host:port still matches", "api.github.com:443", 2},
		{"uppercase input case-insensitive", "API.GITHUB.COM", 2},
		{"different host filtered out", "api.openai.com", 1},
		{"non-matching host returns none", "api.anthropic.com", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := s.Query(Filter{Host: tc.host})
			if err != nil {
				t.Fatalf("Query(Host=%q): %v", tc.host, err)
			}
			if len(rows) != tc.want {
				t.Errorf("Query(Host=%q): got %d rows, want %d", tc.host, len(rows), tc.want)
			}
		})
	}
}

func TestRecordBatching(t *testing.T) {
	s := openTestStore(t)

	base := time.Now().UTC()
	for i := 0; i < 60; i++ {
		s.Record(makeInjection("batch.example.com", "batch-key", base.Add(time.Duration(i)*time.Millisecond)))
	}

	// Stop the background flusher and synchronously drain. Deterministic —
	// no time.Sleep needed to wait for the ticker.
	s.DrainForTest()

	rows, err := s.Query(Filter{Limit: 100})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 60 {
		t.Errorf("got %d rows, want 60", len(rows))
	}
}

func TestSummary(t *testing.T) {
	s := openTestStore(t)

	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	hosts := []string{"api.openai.com", "api.anthropic.com", "api.cohere.com"}
	for i, h := range hosts {
		s.Record(makeInjection(h, fmt.Sprintf("key-%d", i), base.Add(time.Duration(i)*time.Second)))
	}

	// Add two blocked injections.
	blockedInj := makeInjection("evil.example.com", "stolen-key", base.Add(5*time.Second))
	blockedInj.Location = "blocked"
	blockedInj.BytesBefore = 0
	blockedInj.BytesAfter = 0
	s.Record(blockedInj)

	blockedInj2 := makeInjection("api.openai.com", "openai-key", base.Add(6*time.Second))
	blockedInj2.Location = "blocked"
	blockedInj2.BytesBefore = 0
	blockedInj2.BytesAfter = 0
	s.Record(blockedInj2)

	s.flushPending()

	total, blocked, leaked, hostList, last, err := s.Summary(base)
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}

	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	if blocked != 2 {
		t.Errorf("blocked = %d, want 2", blocked)
	}
	if leaked != 0 {
		t.Errorf("leaked = %d, want 0", leaked)
	}
	if len(hostList) != 3 {
		t.Errorf("hosts = %v, want 3 distinct", hostList)
	}
	if last == nil {
		t.Fatal("lastInjection is nil")
	}
	if last.Host != "api.cohere.com" {
		t.Errorf("last host = %q, want api.cohere.com", last.Host)
	}
}

// TestSummary_LeakedRowsExcludedFromInjections is the regression test for the
// session-end banner conflating placeholder leaks with successful injections.
// A row with Location=="leaked" represents a request the proxy refused to
// forward (sentinel guard tripped, no real secret reached the wire). Counting
// it as an injection would mislead users into believing a deleted credential
// had been successfully swapped.
func TestSummary_LeakedRowsExcludedFromInjections(t *testing.T) {
	s := openTestStore(t)

	base := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	// One real injection that should count.
	s.Record(makeInjection("api.openai.com", "openai-key", base))
	// Two leaked rows on a host that has no successful injection — these
	// must not count as injections nor add a host.
	leakRow1 := makeInjection("httpbin.org:443", "", base.Add(time.Second))
	leakRow1.Location = "leaked"
	leakRow1.CredentialName = ""
	leakRow1.CredentialID = ""
	s.Record(leakRow1)

	leakRow2 := makeInjection("httpbin.org:443", "", base.Add(2*time.Second))
	leakRow2.Location = "leaked"
	leakRow2.CredentialName = ""
	leakRow2.CredentialID = ""
	s.Record(leakRow2)
	s.flushPending()

	total, blocked, leaked, hosts, last, err := s.Summary(base)
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}

	if total != 1 {
		t.Errorf("total = %d, want 1 (leaked rows must be excluded from injections)", total)
	}
	if blocked != 0 {
		t.Errorf("blocked = %d, want 0", blocked)
	}
	if leaked != 2 {
		t.Errorf("leaked = %d, want 2", leaked)
	}
	if len(hosts) != 1 || hosts[0] != "api.openai.com" {
		t.Errorf("hosts = %v, want [api.openai.com] (httpbin host had only leaks)", hosts)
	}
	if last == nil || last.Host != "api.openai.com" {
		t.Errorf("last = %v, want api.openai.com (leaked rows must not be selected as last injection)", last)
	}
}

func TestCloseFlushes(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")

	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	base := time.Now().UTC()
	for i := 0; i < 5; i++ {
		s.Record(makeInjection("close.example.com", "close-key", base.Add(time.Duration(i)*time.Second)))
	}

	// Close immediately — should flush remaining rows before closing.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Re-open and verify.
	s2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer func() { _ = s2.Close() }()

	rows, err := s2.Query(Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 5 {
		t.Errorf("got %d rows after close/reopen, want 5", len(rows))
	}
}

func TestQueryOrder(t *testing.T) {
	s := openTestStore(t)

	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		s.Record(makeInjection("order.example.com", "order-key", base.Add(time.Duration(i)*time.Second)))
	}
	s.flushPending()

	rows, err := s.Query(Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 5 {
		t.Fatalf("got %d rows, want 5", len(rows))
	}

	// Verify descending order.
	for i := 1; i < len(rows); i++ {
		if rows[i].Timestamp.After(rows[i-1].Timestamp) {
			t.Errorf("row %d (%v) is after row %d (%v) — not DESC order",
				i, rows[i].Timestamp, i-1, rows[i-1].Timestamp)
		}
	}
}

func TestConcurrentRecords(t *testing.T) {
	s := openTestStore(t)

	base := time.Now().UTC()
	const goroutines = 10
	const perGoroutine = 20
	done := make(chan struct{}, goroutines)

	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < perGoroutine; i++ {
				s.Record(makeInjection(
					fmt.Sprintf("host-%d.example.com", gid),
					fmt.Sprintf("key-%d-%d", gid, i),
					base.Add(time.Duration(gid*perGoroutine+i)*time.Millisecond),
				))
			}
		}(g)
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}

	// Stop the background flusher and synchronously drain — deterministic
	// replacement for the old time.Sleep(500ms) wait.
	s.DrainForTest()

	rows, err := s.Query(Filter{Limit: 300})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	expected := goroutines * perGoroutine
	if len(rows) != expected {
		t.Errorf("got %d rows, want %d (concurrent writes)", len(rows), expected)
	}
}

func TestQueryBlockedFilter(t *testing.T) {
	s := openTestStore(t)

	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	// Regular injection.
	s.Record(makeInjection("api.example.com", "regular-key", base))

	// Blocked injection.
	blocked := makeInjection("evil.com", "blocked-key", base.Add(time.Second))
	blocked.Location = "blocked"
	s.Record(blocked)

	s.flushPending()

	// Without IncludeBlocked, should only get regular.
	rows, err := s.Query(Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("without IncludeBlocked: got %d rows, want 1", len(rows))
	}

	// With IncludeBlocked, should get both.
	rows, err = s.Query(Filter{IncludeBlocked: true})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("with IncludeBlocked: got %d rows, want 2", len(rows))
	}
}

// TestSchemaMigratesV3ToV4 verifies that opening a database with a v1/v2/v3
// schema (with suspect_flag / auth_signal / signer_error columns) cleanly
// upgrades to v4 by dropping the legacy injections table and recreating it
// with the simplified v4 shape. Audit data is per-session ephemeral state,
// so the migration deliberately discards old rows rather than copy-rebuild.
func TestSchemaMigratesV3ToV4(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")

	dsn := "file:" + dbPath + "?_pragma=journal_mode%3DWAL&_pragma=synchronous%3DNORMAL"
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	// Frozen snapshot of the pre-v4 production schema (v3 — what shipped
	// with the mismatch detector and signer columns). Do not edit to match
	// current schemaDDL — the point of this fixture is to exercise the
	// migration from what shipped before the Phase 6 cut.
	const v3DDL = `
CREATE TABLE injections (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  ts              INTEGER NOT NULL,
  request_id      TEXT NOT NULL,
  host            TEXT NOT NULL,
  method          TEXT NOT NULL,
  url_path        TEXT NOT NULL,
  credential_id   TEXT NOT NULL,
  credential_name TEXT NOT NULL,
  agent_pid       INTEGER NOT NULL,
  agent_cmd       TEXT NOT NULL,
  bytes_before    INTEGER NOT NULL,
  bytes_after     INTEGER NOT NULL,
  location        TEXT NOT NULL,
  suspect_flag    INTEGER NOT NULL DEFAULT 0,
  auth_signal     TEXT NOT NULL DEFAULT '',
  signer_error    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_inj_suspect ON injections(suspect_flag);
CREATE TABLE schema_version (v INTEGER PRIMARY KEY);
INSERT INTO schema_version VALUES (3);
INSERT INTO injections
  (ts, request_id, host, method, url_path, credential_id, credential_name,
   agent_pid, agent_cmd, bytes_before, bytes_after, location, suspect_flag,
   auth_signal, signer_error)
  VALUES (0, 'r', 'old.example.com', 'GET', '/', 'c', 'cred', 0, '', 0, 0,
          'header', 0, '', '');
`
	if _, err := raw.Exec(v3DDL); err != nil {
		t.Fatalf("v3 ddl: %v", err)
	}
	_ = raw.Close()

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open on v3 db: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Schema version must now be 4.
	var v int
	if err := db.db.QueryRow(`SELECT MAX(v) FROM schema_version`).Scan(&v); err != nil {
		t.Fatalf("scan version: %v", err)
	}
	if v != 4 {
		t.Errorf("schema_version = %d, want 4", v)
	}

	// The legacy injections table (and its row) must have been dropped —
	// historical session rows do not survive the migration.
	var count int
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM injections`).Scan(&count); err != nil {
		t.Fatalf("count injections: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 rows after v3->v4 migration (old data dropped), got %d", count)
	}

	// The dropped columns must no longer exist.
	rows, err := db.db.Query(`PRAGMA table_info(injections)`)
	if err != nil {
		t.Fatalf("pragma: %v", err)
	}
	defer func() { _ = rows.Close() }()
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan: %v", err)
		}
		cols[name] = true
	}
	for _, dropped := range []string{"suspect_flag", "auth_signal", "signer_error"} {
		if cols[dropped] {
			t.Errorf("column %q must not exist after v4 migration", dropped)
		}
	}
	// And the idx_inj_suspect index must be gone too.
	var idxCount int
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_inj_suspect'`).Scan(&idxCount); err != nil {
		t.Fatalf("count idx_inj_suspect: %v", err)
	}
	if idxCount != 0 {
		t.Errorf("idx_inj_suspect index must not exist after v4 migration")
	}

	// Fresh inserts into the v4 table must work.
	db.Record(Injection{
		Timestamp: time.Now(), RequestID: "post-mig-1",
		Host: "new.example.com", Method: "GET", URLPath: "/x",
		Location: "header",
	})
	db.DrainForTest()
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM injections`).Scan(&count); err != nil {
		t.Fatalf("re-count: %v", err)
	}
	if count != 1 {
		t.Errorf("post-migration insert: got %d rows, want 1", count)
	}
}

func TestRecordRedactsURLPathQuery(t *testing.T) {
	s := openTestStore(t)

	s.Record(Injection{
		Timestamp:      time.Now(),
		RequestID:      "req-url-1",
		Host:           "api.example.com",
		Method:         "GET",
		URLPath:        "/v1/thing?token=sk_live_ABCDEFGHIJ&lang=en",
		CredentialID:   "c1",
		CredentialName: "k",
		Location:       "header",
	})
	s.flushPending()

	rows, err := s.Query(Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].URLPath != "/v1/thing" {
		t.Errorf("URLPath = %q, want %q — query string must be stripped at record time",
			rows[0].URLPath, "/v1/thing")
	}
}

func TestRecordRedactsURLPathPreservesPathOnly(t *testing.T) {
	s := openTestStore(t)

	s.Record(Injection{
		Timestamp: time.Now(), RequestID: "req-p-1",
		Host: "api.example.com", Method: "GET",
		URLPath: "/v1/thing", Location: "header",
	})
	s.flushPending()

	rows, err := s.Query(Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if rows[0].URLPath != "/v1/thing" {
		t.Errorf("URLPath = %q, want %q", rows[0].URLPath, "/v1/thing")
	}
}

func TestRecordRedactsAgentCmdArgv(t *testing.T) {
	s := openTestStore(t)

	s.Record(Injection{
		Timestamp:      time.Now(),
		RequestID:      "req-argv-1",
		Host:           "api.example.com",
		Method:         "GET",
		URLPath:        "/x",
		CredentialID:   "c1",
		CredentialName: "k",
		AgentCmd:       "curl -H Authorization: Bearer sk_live_SECRETSECRETSECRET",
		Location:       "header",
	})
	s.flushPending()

	rows, err := s.Query(Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].AgentCmd != "curl" {
		t.Errorf("AgentCmd = %q, want %q — argv[1:] must be stripped", rows[0].AgentCmd, "curl")
	}
}

func TestCloseWaitsForFlusher(t *testing.T) {
	// Verify that Close() synchronises with the flusher goroutine and no
	// rows are lost when close-and-flush interleave. Each iteration writes
	// exactly 200 rows past the 50-row flush threshold, closes the store,
	// then re-opens the DB and counts. If the flusher raced db.Close,
	// tx.Commit in the flusher's flushPending would fail and rows would be
	// silently lost (the old code re-queued into a pending buffer that
	// dies with the process).
	const rowsPerIter = 200
	for i := 0; i < 30; i++ {
		dbPath := filepath.Join(t.TempDir(), "audit.db")
		s, err := Open(dbPath)
		if err != nil {
			t.Fatalf("Open iter %d: %v", i, err)
		}
		base := time.Now()
		for j := 0; j < rowsPerIter; j++ {
			s.Record(makeInjection("close.example.com", "close-key", base.Add(time.Duration(j)*time.Millisecond)))
		}
		if err := s.Close(); err != nil {
			t.Fatalf("Close iter %d: %v", i, err)
		}

		// Re-open and count.
		s2, err := Open(dbPath)
		if err != nil {
			t.Fatalf("re-Open iter %d: %v", i, err)
		}
		rows, err := s2.Query(Filter{Limit: rowsPerIter + 10})
		if err != nil {
			t.Fatalf("Query iter %d: %v", i, err)
		}
		if len(rows) != rowsPerIter {
			t.Errorf("iter %d: got %d rows, want %d (flusher raced db.Close and lost rows)",
				i, len(rows), rowsPerIter)
		}
		_ = s2.Close()
	}
}

func TestQueryCombinedFilters(t *testing.T) {
	s := openTestStore(t)

	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	// Mix of hosts, credentials, and times.
	s.Record(makeInjection("api.openai.com", "openai-key", base))
	s.Record(makeInjection("api.openai.com", "other-key", base.Add(time.Second)))
	s.Record(makeInjection("api.github.com", "openai-key", base.Add(2*time.Second)))
	s.Record(makeInjection("api.openai.com", "openai-key", base.Add(3*time.Second)))
	s.flushPending()

	// Filter: host=api.openai.com AND credential=openai-key.
	rows, err := s.Query(Filter{
		Host:           "api.openai.com",
		CredentialName: "openai-key",
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("combined host+cred filter: got %d rows, want 2", len(rows))
	}

	// Add time filter to further narrow.
	rows, err = s.Query(Filter{
		Host:           "api.openai.com",
		CredentialName: "openai-key",
		Since:          base.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("combined host+cred+since filter: got %d rows, want 1", len(rows))
	}
}

// captureWarn captures ui.Warnf output for inspection.
type captureWarn struct{ buf strings.Builder }

func (c *captureWarn) Write(p []byte) (int, error) { return c.buf.Write(p) }

func TestPendingCapBoundsMemory(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	warn := &captureWarn{}
	s.mu.Lock()
	s.warnWriter = warn
	s.mu.Unlock()

	// Stop the flusher BEFORE the insert loop. The assertion is about
	// Record's drop-on-full path (pending stays bounded, overflow counts as
	// dropped). On a fast runner a live flusher would drain pending each
	// tick — pending never reaches pendingCap and dropped stays near 0.
	// Close the DB after stopping the flusher so a stray late flush (if any)
	// cannot succeed; flushPending tolerates a closed DB by re-queueing.
	s.stopFlusher()
	s.wg.Wait()
	_ = s.db.Close()

	base := time.Now()
	const extras = 1_000
	for i := 0; i < pendingCap+extras; i++ {
		s.Record(makeInjection("bp.example.com", "bp-key", base.Add(time.Duration(i)*time.Millisecond)))
	}

	s.mu.Lock()
	pending := len(s.pending)
	dropped := s.dropped
	warnOutput := warn.buf.String()
	s.mu.Unlock()

	if pending > pendingCap {
		t.Errorf("pending = %d, want <= %d", pending, pendingCap)
	}
	if dropped < extras {
		t.Errorf("dropped = %d, want at least %d", dropped, extras)
	}
	if !strings.Contains(warnOutput, "audit buffer full") {
		t.Errorf("expected ui.Warnf for full buffer, got %q", warnOutput)
	}
}

func TestHealthReflectsDrops(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Stop the flusher before inserting (see TestPendingCapBoundsMemory for
	// the race rationale). The assertion is that Record's drop path bumps
	// Health.Dropped and persists it; a live flusher on a fast runner
	// would drain pending and starve the test of drops.
	s.stopFlusher()
	s.wg.Wait()
	_ = s.db.Close()
	s.mu.Lock()
	s.warnWriter = &captureWarn{}
	s.mu.Unlock()

	base := time.Now()
	for i := 0; i < pendingCap+5; i++ {
		s.Record(makeInjection("h.example.com", "k", base.Add(time.Duration(i)*time.Millisecond)))
	}

	h := s.Health()
	if h.Dropped < 5 {
		t.Errorf("Health.Dropped = %d, want >= 5", h.Dropped)
	}
	if !h.Degraded() {
		t.Error("Health.Degraded() = false, want true after drops")
	}

	persisted, err := ReadHealth(dbPath)
	if err != nil {
		t.Fatalf("ReadHealth: %v", err)
	}
	if persisted.Dropped < 5 {
		t.Errorf("persisted.Dropped = %d, want >= 5", persisted.Dropped)
	}
}

func TestCloseClearsHealthSidecarWhenHealthy(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	// Pre-create a stale sidecar that should be cleared on a clean close.
	sidecar := dbPath + ".health"
	if err := os.MkdirAll(filepath.Dir(sidecar), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(sidecar, []byte("dropped=42\n"), 0o600); err != nil {
		t.Fatalf("write stale sidecar: %v", err)
	}

	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.Record(makeInjection("ok.example.com", "k", time.Now()))
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := os.Stat(sidecar); !os.IsNotExist(err) {
		t.Fatalf("health sidecar should have been removed on clean close, stat err=%v", err)
	}
}

