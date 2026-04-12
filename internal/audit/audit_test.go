package audit

import (
	"fmt"
	"path/filepath"
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
	if v != 1 {
		t.Errorf("schema_version = %d, want 1", v)
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

func TestRecordBatching(t *testing.T) {
	s := openTestStore(t)

	base := time.Now().UTC()
	for i := 0; i < 60; i++ {
		s.Record(makeInjection("batch.example.com", "batch-key", base.Add(time.Duration(i)*time.Millisecond)))
	}

	// Wait for the flusher to process (100ms tick + some margin).
	time.Sleep(300 * time.Millisecond)

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
	s.flushPending()

	total, hostList, last, err := s.Summary(base)
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}

	if total != 3 {
		t.Errorf("total = %d, want 3", total)
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
