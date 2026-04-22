# Audit Subsystem Hygiene Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix five audit-subsystem issues from 2026-04-22 codebase audit: shutdown race, summary miscounts, over-logging of URLs/argv, permission window on SQLite sidecars, and unbounded memory on persistent flush failure.

**Architecture:** All five fixes land inside `internal/audit/`. `Store` gets a `sync.WaitGroup` and a pending cap; `Record()` sanitizes URLPath/AgentCmd before append; `Open()` wraps `sql.Open` in a `syscall.Umask(0o077)` restore block; `Summary()` excludes `suspect_flag = 1`; health counters are exposed via a new `Health()` method, and persistent failure state is written to a sidecar `.health` file that `veil status` reads.

**Tech Stack:** Go 1.26, `modernc.org/sqlite`, `syscall.Umask` (unix-only build tag), existing `ui.Warnf` for user-facing warnings, build tag `audit_debug` for full-argv override.

---

## File Structure

**Modify:**
- `internal/audit/audit.go` — `Store` struct gets `wg sync.WaitGroup`, `dropped int`, `lastErr error`, `lastErrTime time.Time`, `healthPath string`, `redactedOpts`. New helpers `redactURLPath`, `redactAgentCmd`, `writeHealthSidecar`, `clearHealthSidecar`.
- `internal/audit/query.go` — `Summary()` adds `AND suspect_flag = 0` to its three queries.
- `internal/audit/audit_test.go` — new test `TestCloseWaitsForFlusher`, `TestRecordRedactsURLPathQuery`, `TestRecordRedactsAgentCmdArgv`, `TestPendingCapBoundsMemory`, `TestHealthReflectsDrops`. Fix `TestSummary` expectation for suspect exclusion.
- `internal/audit/audit_perms_test.go` — add `TestOpenSidecarNeverWorldReadable` verifying `-wal`/`-shm` are never 0644 at any instant.
- `internal/cli/status.go` — read health sidecar, surface degraded state.

**Create:**
- `internal/audit/umask_unix.go` — `//go:build darwin || linux` — `withRestrictiveUmask(func() error) error` wrapper.
- `internal/audit/redact_strict.go` — `//go:build !audit_debug` — `redactURLPath`/`redactAgentCmd` strip query strings and all but argv[0].
- `internal/audit/redact_debug.go` — `//go:build audit_debug` — same function signatures, pass-through.
- `internal/audit/health.go` — `Health` struct, `Store.Health()`, sidecar read/write helpers, `ReadHealth(dbPath)` helper for CLI use.

---

### Task 1: Shutdown synchronization — Close waits for flusher

**Files:**
- Modify: `internal/audit/audit.go` (Store struct, `Open`, `Close`, `flusher`)
- Test: `internal/audit/audit_test.go`

- [ ] **Step 1: Write failing test `TestCloseWaitsForFlusher`**

```go
// In internal/audit/audit_test.go, append:
func TestCloseWaitsForFlusher(t *testing.T) {
	// Repeat several times to stress-hit the race.
	for i := 0; i < 50; i++ {
		dbPath := filepath.Join(t.TempDir(), "audit.db")
		s, err := Open(dbPath)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		// Enqueue some rows so flushPending has work.
		for j := 0; j < 5; j++ {
			s.Record(makeInjection("close.example.com", "close-key", time.Now()))
		}
		// Close must not race with the flusher's tick-driven flushPending.
		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
}
```

- [ ] **Step 2: Run test under -race, verify it fails or flakes**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/audit/ -run TestCloseWaitsForFlusher -race -count=5 -timeout 30s`

Expected: race detector flag OR "database is closed" panic intermittently. If it passes cleanly on the first run, increase iteration count — the race is real per the audit doc.

- [ ] **Step 3: Add WaitGroup to Store and drive the flusher under it**

Modify `internal/audit/audit.go`:

```go
// Store struct — add wg field after closeErr:
type Store struct {
	db        *sql.DB
	mu        sync.Mutex
	pending   []Injection
	done      chan struct{}
	flush     chan struct{}
	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup // waits for flusher to exit
}
```

Modify `Open` to `wg.Add(1)` before starting the flusher:

```go
	s := &Store{
		db:    db,
		done:  make(chan struct{}),
		flush: make(chan struct{}, 1),
	}
	s.wg.Add(1)
	go s.flusher()
	return s, nil
```

Modify `flusher` to call `wg.Done()` on exit:

```go
func (s *Store) flusher() {
	defer s.wg.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.flushPending()
		case <-s.flush:
			s.flushPending()
		}
	}
}
```

Modify `Close` to wait on the flusher before closing the DB:

```go
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.wg.Wait()      // flusher goroutine has exited
		s.flushPending() // drain anything buffered after the last tick
		s.closeErr = s.db.Close()
	})
	return s.closeErr
}
```

- [ ] **Step 4: Run test under -race to verify pass**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/audit/ -run TestCloseWaitsForFlusher -race -count=5 -timeout 30s`

Expected: PASS, no race reports.

- [ ] **Step 5: Commit**

```bash
git add internal/audit/audit.go internal/audit/audit_test.go
git commit -m "fix(audit): wait for flusher goroutine before closing db"
```

---

### Task 2: Summary excludes suspect rows

**Files:**
- Modify: `internal/audit/query.go:125-180` (three queries in `Summary`)
- Test: `internal/audit/audit_test.go`

- [ ] **Step 1: Extend `TestSummary` to insert a suspect row and assert it does not inflate `total`**

Modify `TestSummary` in `internal/audit/audit_test.go`:

```go
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

	// Add a suspect row — must NOT count toward total or hosts.
	suspect := makeInjection("suspect.example.com", "", base.Add(7*time.Second))
	suspect.Location = "mismatch_suspected"
	suspect.SuspectFlag = true
	suspect.AuthSignal = "authorization_header"
	s.Record(suspect)

	s.flushPending()

	total, blocked, hostList, last, err := s.Summary(base)
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}

	if total != 3 {
		t.Errorf("total = %d, want 3 (suspect row must be excluded)", total)
	}
	if blocked != 2 {
		t.Errorf("blocked = %d, want 2", blocked)
	}
	if len(hostList) != 3 {
		t.Errorf("hosts = %v, want 3 distinct (suspect host must be excluded)", hostList)
	}
	for _, h := range hostList {
		if h == "suspect.example.com" {
			t.Errorf("suspect host leaked into hostList: %v", hostList)
		}
	}
	if last == nil {
		t.Fatal("lastInjection is nil")
	}
	if last.Host != "api.cohere.com" {
		t.Errorf("last host = %q, want api.cohere.com (suspect row must be excluded)", last.Host)
	}
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/audit/ -run TestSummary -timeout 30s`

Expected: FAIL with `total = 4, want 3` (or similar).

- [ ] **Step 3: Add `AND suspect_flag = 0` to the three queries in `Summary`**

In `internal/audit/query.go`, modify `Summary`:

```go
func (s *Store) Summary(since time.Time) (total int, blocked int, hosts []string, lastInjection *Row, err error) {
	sinceMillis := since.UnixMilli()

	// Total successful count — excludes blocked and suspect rows.
	err = s.db.QueryRow("SELECT COUNT(*) FROM injections WHERE ts >= ? AND location != 'blocked' AND suspect_flag = 0", sinceMillis).Scan(&total)
	if err != nil {
		return
	}

	// Blocked count.
	err = s.db.QueryRow("SELECT COUNT(*) FROM injections WHERE ts >= ? AND location = 'blocked'", sinceMillis).Scan(&blocked)
	if err != nil {
		return
	}

	// Distinct hosts (successful injections only — suspects excluded).
	rows, err := s.db.Query("SELECT DISTINCT host FROM injections WHERE ts >= ? AND location != 'blocked' AND suspect_flag = 0 ORDER BY host", sinceMillis)
	if err != nil {
		return
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var h string
		if err = rows.Scan(&h); err != nil {
			return
		}
		hosts = append(hosts, h)
	}
	if err = rows.Err(); err != nil {
		return
	}

	// Most recent successful injection — suspects excluded.
	r := &Row{}
	var tsMillis int64
	scanErr := s.db.QueryRow(
		"SELECT id, ts, request_id, host, method, url_path, credential_id, credential_name, agent_pid, agent_cmd, bytes_before, bytes_after, location FROM injections WHERE ts >= ? AND location != 'blocked' AND suspect_flag = 0 ORDER BY ts DESC LIMIT 1",
		sinceMillis,
	).Scan(
		&r.ID, &tsMillis, &r.RequestID, &r.Host, &r.Method,
		&r.URLPath, &r.CredentialID, &r.CredentialName,
		&r.AgentPID, &r.AgentCmd, &r.BytesBefore, &r.BytesAfter,
		&r.Location,
	)
	if scanErr == sql.ErrNoRows {
		lastInjection = nil
	} else if scanErr != nil {
		err = scanErr
		return
	} else {
		r.Timestamp = time.UnixMilli(tsMillis).UTC()
		lastInjection = r
	}

	return
}
```

- [ ] **Step 4: Run test to verify pass**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/audit/ -run TestSummary -timeout 30s`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/audit/query.go internal/audit/audit_test.go
git commit -m "fix(audit): exclude suspect rows from Summary totals"
```

---

### Task 3: Redact URLPath query strings and AgentCmd args at record time

**Files:**
- Create: `internal/audit/redact_strict.go` (`//go:build !audit_debug`)
- Create: `internal/audit/redact_debug.go` (`//go:build audit_debug`)
- Modify: `internal/audit/audit.go` (apply redaction in `Record`)
- Test: `internal/audit/audit_test.go`

- [ ] **Step 1: Write failing tests for URLPath and AgentCmd sanitization**

Append to `internal/audit/audit_test.go`:

```go
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
		t.Errorf("URLPath = %q, want %q — query string must be stripped at record time", rows[0].URLPath, "/v1/thing")
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

// Passing a URLPath without a query string leaves it unchanged.
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
```

- [ ] **Step 2: Run to verify failures**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/audit/ -run 'TestRecordRedacts' -timeout 30s`

Expected: FAIL — query strings and args are stored verbatim.

- [ ] **Step 3: Create `internal/audit/redact_strict.go`**

```go
//go:build !audit_debug

package audit

import "strings"

// redactURLPath strips any `?query` suffix from p, keeping only the path
// portion. Called at Record() time so even callers that pass raw URLs can't
// leak query-string secrets into the audit DB.
func redactURLPath(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

// redactAgentCmd keeps only the first whitespace-separated token — typically
// argv[0]. Set the `audit_debug` build tag to log the full argv.
func redactAgentCmd(cmd string) string {
	if i := strings.IndexFunc(cmd, func(r rune) bool {
		return r == ' ' || r == '\t'
	}); i >= 0 {
		return cmd[:i]
	}
	return cmd
}
```

- [ ] **Step 4: Create `internal/audit/redact_debug.go`**

```go
//go:build audit_debug

package audit

// Debug build: record URLPath and AgentCmd verbatim. Enable with
// `-tags audit_debug` when diagnosing a specific audit problem.
//
// Not for production binaries — URLPath will contain raw query strings and
// AgentCmd will contain raw argv, which may include tokens the user typed on
// the command line.

func redactURLPath(p string) string  { return p }
func redactAgentCmd(cmd string) string { return cmd }
```

- [ ] **Step 5: Apply redaction in `Record`**

Modify `Record` in `internal/audit/audit.go`:

```go
func (s *Store) Record(inj Injection) {
	inj.URLPath = redactURLPath(inj.URLPath)
	inj.AgentCmd = redactAgentCmd(inj.AgentCmd)

	s.mu.Lock()
	s.pending = append(s.pending, inj)
	n := len(s.pending)
	s.mu.Unlock()

	if n >= 50 {
		select {
		case s.flush <- struct{}{}:
		default:
		}
	}
}
```

- [ ] **Step 6: Run tests to verify pass**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/audit/ -run 'TestRecordRedacts' -timeout 30s`

Expected: PASS.

Also verify full audit suite still green:

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/audit/ -timeout 60s`

Expected: PASS.

Also verify injector tests still green (they rely on URLPath being path-only, which is still true):

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/proxy/ -timeout 60s`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/audit/redact_strict.go internal/audit/redact_debug.go internal/audit/audit.go internal/audit/audit_test.go
git commit -m "fix(audit): redact URL queries and argv at record time"
```

---

### Task 4: Umask-guard SQLite sidecar creation

**Files:**
- Create: `internal/audit/umask_unix.go` (`//go:build darwin || linux`)
- Modify: `internal/audit/audit.go` (wrap `sql.Open`+materialize block)
- Test: `internal/audit/audit_perms_test.go`

- [ ] **Step 1: Write failing test that watches for any world-readable sidecar instant**

Append to `internal/audit/audit_perms_test.go`:

```go
func TestOpenSidecarNeverWorldReadable(t *testing.T) {
	// Run Open many times and, in a background goroutine, repeatedly stat the
	// sidecars. If umask is not guarded, one of those stat calls will observe
	// 0644 before the chmod executes.
	for iter := 0; iter < 20; iter++ {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "audit.db")

		stop := make(chan struct{})
		bad := make(chan string, 16)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, suffix := range []string{"", "-wal", "-shm"} {
					p := dbPath + suffix
					info, err := os.Stat(p)
					if err != nil {
						continue
					}
					if info.Mode().Perm()&0o077 != 0 {
						bad <- fmt.Sprintf("%s mode %o", p, info.Mode().Perm())
					}
				}
			}
		}()

		s, err := audit.Open(dbPath)
		close(stop)
		<-done
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		_ = s.Close()

		select {
		case msg := <-bad:
			t.Fatalf("world-readable sidecar observed: %s", msg)
		default:
		}
	}
}
```

Add `"fmt"` and `"os"` imports to `audit_perms_test.go` if missing.

- [ ] **Step 2: Run to verify intermittent failure**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/audit/ -run TestOpenSidecarNeverWorldReadable -count=5 -timeout 30s`

Expected: FAIL on at least one iteration (the race is tight; iteration count compensates).

- [ ] **Step 3: Create `internal/audit/umask_unix.go`**

```go
//go:build darwin || linux

package audit

import "syscall"

// withRestrictiveUmask temporarily sets the process umask to 0077 so any
// files the wrapped call creates are 0600/0700. The previous umask is
// restored before returning, so other goroutines see no lasting effect
// *after* fn completes — but the umask is process-global, so the guard is
// only correct if Open() is not called concurrently with unrelated file
// creation. That invariant holds in Veil because Open() is called once per
// process.
func withRestrictiveUmask(fn func() error) error {
	prev := syscall.Umask(0o077)
	defer syscall.Umask(prev)
	return fn()
}
```

- [ ] **Step 4: Apply umask wrapper in `Open`**

Modify `Open` in `internal/audit/audit.go` — wrap the `sql.Open`, `Exec(schemaDDL)`, `migrateToV2`, and the materialization block:

```go
	// modernc.org/sqlite does not honour _journal_mode= / _synchronous= DSN
	// parameters; use _pragma= encoding instead.
	dsn := "file:" + dbPath + "?_pragma=journal_mode%3DWAL&_pragma=synchronous%3DNORMAL"

	var db *sql.DB
	if umaskErr := withRestrictiveUmask(func() error {
		var openErr error
		db, openErr = sql.Open("sqlite", dsn)
		if openErr != nil {
			return fmt.Errorf("sql.Open: %w", openErr)
		}
		if _, openErr = db.Exec(schemaDDL); openErr != nil {
			_ = db.Close()
			return fmt.Errorf("ddl: %w", openErr)
		}
		if openErr = migrateToV2(db); openErr != nil {
			_ = db.Close()
			return fmt.Errorf("migrate v2: %w", openErr)
		}
		// Materialize WAL/SHM sidecars under the restrictive umask.
		tx, txErr := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelSerializable})
		if txErr != nil {
			_ = db.Close()
			return fmt.Errorf("materialize wal begin: %w", txErr)
		}
		if _, txErr = tx.Exec(`UPDATE schema_version SET v = v`); txErr != nil {
			_ = tx.Rollback()
			_ = db.Close()
			return fmt.Errorf("materialize wal exec: %w", txErr)
		}
		if txErr = tx.Commit(); txErr != nil {
			_ = db.Close()
			return fmt.Errorf("materialize wal commit: %w", txErr)
		}
		return nil
	}); umaskErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrAuditOpen, umaskErr)
	}
```

Remove the three separate `sql.Open` / `Exec(schemaDDL)` / `migrateToV2` / materialization blocks that used to live above.

- [ ] **Step 5: Run race test to verify pass**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/audit/ -run TestOpenSidecarNeverWorldReadable -count=10 -timeout 30s`

Expected: PASS across all iterations.

Also verify existing perm tests still pass:

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/audit/ -timeout 60s`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/audit/umask_unix.go internal/audit/audit.go internal/audit/audit_perms_test.go
git commit -m "fix(audit): umask-guard sqlite sidecar creation"
```

---

### Task 5: Bounded pending buffer with health surface

**Files:**
- Create: `internal/audit/health.go`
- Modify: `internal/audit/audit.go` (Store fields, `Open`, `Record`, `flushPending`, `Close`)
- Modify: `internal/cli/status.go` (read and display health)
- Test: `internal/audit/audit_test.go`
- Test: `internal/cli/cli_test.go` (new `TestStatusShowsAuditHealth` — only if convenient; otherwise cover in audit_test.go)

- [ ] **Step 1: Write `Health` struct and `ReadHealth` helper in `internal/audit/health.go`**

```go
package audit

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Health summarises the audit subsystem's recent behaviour. It is safe to read
// via Store.Health() on a live store, or from disk via ReadHealth(dbPath) to
// inspect the state left behind by a previous process.
type Health struct {
	Dropped       int       // rows rejected because pending buffer was full
	LastErrorTime time.Time // zero = no error recorded
	LastErrorMsg  string    // empty = no error recorded
}

// Degraded reports whether the audit subsystem saw any failure since the
// sidecar was last cleared.
func (h Health) Degraded() bool {
	return h.Dropped > 0 || !h.LastErrorTime.IsZero()
}

// healthSidecarPath returns the path to the health sidecar for dbPath.
func healthSidecarPath(dbPath string) string { return dbPath + ".health" }

// ReadHealth loads the health sidecar next to dbPath. Returns a zero Health
// (and nil error) if no sidecar exists.
func ReadHealth(dbPath string) (Health, error) {
	f, err := os.Open(healthSidecarPath(dbPath))
	if err != nil {
		if os.IsNotExist(err) {
			return Health{}, nil
		}
		return Health{}, fmt.Errorf("open health sidecar: %w", err)
	}
	defer func() { _ = f.Close() }()

	var h Health
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch key {
		case "dropped":
			n, _ := strconv.Atoi(val)
			h.Dropped = n
		case "last_error_ms":
			ms, _ := strconv.ParseInt(val, 10, 64)
			if ms > 0 {
				h.LastErrorTime = time.UnixMilli(ms).UTC()
			}
		case "last_error":
			h.LastErrorMsg = val
		}
	}
	if err := sc.Err(); err != nil {
		return h, fmt.Errorf("read health sidecar: %w", err)
	}
	return h, nil
}

// writeHealthSidecar atomically writes the health state to dbPath.health.
// Errors are intentionally swallowed by callers — if we can't persist health,
// the user's disk is already in trouble and the in-memory state is still
// surfaced via ui.Warnf.
func writeHealthSidecar(dbPath string, h Health) error {
	tmp := healthSidecarPath(dbPath) + ".tmp"
	var b strings.Builder
	fmt.Fprintf(&b, "dropped=%d\n", h.Dropped)
	if !h.LastErrorTime.IsZero() {
		fmt.Fprintf(&b, "last_error_ms=%d\n", h.LastErrorTime.UnixMilli())
	}
	if h.LastErrorMsg != "" {
		fmt.Fprintf(&b, "last_error=%s\n", sanitizeHealthMsg(h.LastErrorMsg))
	}
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, healthSidecarPath(dbPath))
}

// clearHealthSidecar removes the sidecar, marking the audit healthy.
func clearHealthSidecar(dbPath string) error {
	err := os.Remove(healthSidecarPath(dbPath))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// sanitizeHealthMsg collapses newlines to keep the sidecar format one-per-line.
func sanitizeHealthMsg(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
```

- [ ] **Step 2: Wire health state into Store**

Modify `internal/audit/audit.go` — add fields to `Store`, initialize in `Open`, expose `Health()`:

```go
// Near top of audit.go, constant for the cap.
const pendingCap = 10_000 // ~2MB of queued Injections; drop-newest beyond this.

// Store struct — add these fields:
type Store struct {
	db        *sql.DB
	mu        sync.Mutex
	pending   []Injection
	done      chan struct{}
	flush     chan struct{}
	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup

	dbPath       string
	dropped      int
	lastErr      string
	lastErrTime  time.Time
	warnedOnce   bool // gate the ui.Warnf to once per process
	warnWriter   io.Writer // defaults to os.Stderr; injectable for tests
}
```

Add the `io` import.

Modify `Open` to record `dbPath` and `warnWriter`:

```go
	s := &Store{
		db:         db,
		done:       make(chan struct{}),
		flush:      make(chan struct{}, 1),
		dbPath:     dbPath,
		warnWriter: os.Stderr,
	}
	s.wg.Add(1)
	go s.flusher()
	return s, nil
```

Add a `Health()` method:

```go
// Health returns an in-memory snapshot of audit backpressure state. Safe to
// call concurrently with Record and flushPending.
func (s *Store) Health() Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Health{
		Dropped:       s.dropped,
		LastErrorTime: s.lastErrTime,
		LastErrorMsg:  s.lastErr,
	}
}
```

- [ ] **Step 3: Cap pending, drop-newest, warn once**

Modify `Record` to enforce the cap:

```go
func (s *Store) Record(inj Injection) {
	inj.URLPath = redactURLPath(inj.URLPath)
	inj.AgentCmd = redactAgentCmd(inj.AgentCmd)

	s.mu.Lock()
	if len(s.pending) >= pendingCap {
		s.dropped++
		firstDrop := s.dropped == 1
		dbPath := s.dbPath
		warn := s.warnWriter
		warnedOnce := s.warnedOnce
		s.warnedOnce = true
		snapshot := Health{
			Dropped:       s.dropped,
			LastErrorTime: s.lastErrTime,
			LastErrorMsg:  s.lastErr,
		}
		s.mu.Unlock()

		if firstDrop || !warnedOnce {
			ui.Warnf(warn, "audit buffer full; dropping events (cap=%d)", pendingCap)
		}
		_ = writeHealthSidecar(dbPath, snapshot)
		return
	}
	s.pending = append(s.pending, inj)
	n := len(s.pending)
	s.mu.Unlock()

	if n >= 50 {
		select {
		case s.flush <- struct{}{}:
		default:
		}
	}
}
```

Add `"github.com/8enji/veil/internal/ui"` import to `audit.go`.

- [ ] **Step 4: Record and surface flush errors**

Modify `flushPending` to capture errors into Store state:

```go
func (s *Store) flushPending() {
	s.mu.Lock()
	if len(s.pending) == 0 {
		s.mu.Unlock()
		return
	}
	batch := s.pending
	s.pending = nil
	s.mu.Unlock()

	if err := s.writeBatch(batch); err != nil {
		s.recordFlushFailure(batch, err)
		return
	}
	// Clear error state on a clean batch.
	s.mu.Lock()
	hadError := s.lastErr != ""
	if hadError {
		s.lastErr = ""
		s.lastErrTime = time.Time{}
	}
	dropped := s.dropped
	dbPath := s.dbPath
	s.mu.Unlock()
	if hadError && dropped == 0 {
		_ = clearHealthSidecar(dbPath)
	} else if hadError {
		_ = writeHealthSidecar(dbPath, Health{Dropped: dropped})
	}
}

// writeBatch inserts the batch in a single transaction. Returns the first
// error encountered; on success returns nil.
func (s *Store) writeBatch(batch []Injection) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("%w: begin: %w", ErrAuditWrite, err)
	}
	stmt, err := tx.Prepare(insertSQL)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("%w: prepare: %w", ErrAuditWrite, err)
	}
	for _, inj := range batch {
		suspect := 0
		if inj.SuspectFlag {
			suspect = 1
		}
		if _, err := stmt.Exec(
			inj.Timestamp.UnixMilli(),
			inj.RequestID,
			inj.Host,
			inj.Method,
			inj.URLPath,
			inj.CredentialID,
			inj.CredentialName,
			inj.AgentPID,
			inj.AgentCmd,
			inj.BytesBefore,
			inj.BytesAfter,
			inj.Location,
			suspect,
			inj.AuthSignal,
		); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return fmt.Errorf("%w: exec: %w", ErrAuditWrite, err)
		}
	}
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit: %w", ErrAuditWrite, err)
	}
	return nil
}

// recordFlushFailure re-queues the batch (respecting the pending cap) and
// records the error for veil status to surface.
func (s *Store) recordFlushFailure(batch []Injection, err error) {
	s.mu.Lock()
	// Requeue up to the cap; drop the overflow.
	room := pendingCap - len(s.pending)
	if room < 0 {
		room = 0
	}
	if room >= len(batch) {
		s.pending = append(batch, s.pending...)
	} else {
		// Keep the most recent rows by discarding the tail of the requeue.
		keep := batch[len(batch)-room:]
		s.pending = append(keep, s.pending...)
		s.dropped += len(batch) - room
	}
	s.lastErr = err.Error()
	s.lastErrTime = time.Now().UTC()
	firstWarn := !s.warnedOnce
	s.warnedOnce = true
	snapshot := Health{
		Dropped:       s.dropped,
		LastErrorTime: s.lastErrTime,
		LastErrorMsg:  s.lastErr,
	}
	dbPath := s.dbPath
	warn := s.warnWriter
	s.mu.Unlock()

	if firstWarn {
		ui.Warnf(warn, "audit flush failed: %v", err)
	}
	_ = writeHealthSidecar(dbPath, snapshot)
}
```

Delete the original inline error-handling in `flushPending` — it's now inside `writeBatch` / `recordFlushFailure`.

- [ ] **Step 5: On clean Close, clear the sidecar if healthy**

Modify `Close` to clear the sidecar when everything drained cleanly:

```go
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.wg.Wait()
		s.flushPending()

		s.mu.Lock()
		healthy := s.dropped == 0 && s.lastErr == ""
		dbPath := s.dbPath
		s.mu.Unlock()
		if healthy {
			_ = clearHealthSidecar(dbPath)
		}

		s.closeErr = s.db.Close()
	})
	return s.closeErr
}
```

- [ ] **Step 6: Write backpressure tests**

Append to `internal/audit/audit_test.go`:

```go
// captureWarn captures ui.Warnf output for inspection.
type captureWarn struct{ buf strings.Builder }

func (c *captureWarn) Write(p []byte) (int, error) { return c.buf.Write(p) }

func TestPendingCapBoundsMemory(t *testing.T) {
	// Stop the background flusher so pending can grow unbounded until we flip
	// the cap. We do this by opening a store with a manually-held transaction
	// that blocks writes. Simpler: use a writable-but-broken db by closing it
	// and letting flushPending's writes fail; pending then grows up to the cap.
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	warn := &captureWarn{}
	s.warnWriter = warn

	// Close the underlying DB handle so writes fail. We avoid Close() which
	// would also close s.done.
	_ = s.db.Close()

	// Hammer in more than pendingCap events.
	base := time.Now()
	const extras = 1_000
	for i := 0; i < pendingCap+extras; i++ {
		s.Record(makeInjection("bp.example.com", "bp-key", base.Add(time.Duration(i)*time.Millisecond)))
	}

	// Close flushes (which will fail) but must not hang.
	s.mu.Lock()
	pending := len(s.pending)
	dropped := s.dropped
	s.mu.Unlock()

	if pending > pendingCap {
		t.Errorf("pending = %d, want <= %d", pending, pendingCap)
	}
	if dropped < extras {
		t.Errorf("dropped = %d, want at least %d", dropped, extras)
	}
	if !strings.Contains(warn.buf.String(), "audit buffer full") {
		t.Errorf("expected ui.Warnf for full buffer, got %q", warn.buf.String())
	}

	// Let the flusher and Close exit cleanly. Even though the DB handle is
	// closed, Close should complete (the sql.Close error is captured).
	close(s.done)
	s.wg.Wait()
}

func TestHealthReflectsDrops(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = s.db.Close() // force writes to fail
	warn := &captureWarn{}
	s.warnWriter = warn

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

	// ReadHealth reads the sidecar from disk and should reflect the same state.
	persisted, err := ReadHealth(dbPath)
	if err != nil {
		t.Fatalf("ReadHealth: %v", err)
	}
	if persisted.Dropped < 5 {
		t.Errorf("persisted.Dropped = %d, want >= 5", persisted.Dropped)
	}

	close(s.done)
	s.wg.Wait()
}

func TestCloseClearsHealthSidecarWhenHealthy(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	// Pre-create a stale sidecar.
	if err := os.WriteFile(dbPath+".health", []byte("dropped=42\n"), 0o600); err != nil {
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

	if _, err := os.Stat(dbPath + ".health"); !os.IsNotExist(err) {
		t.Fatalf("health sidecar should have been removed on clean close, stat err=%v", err)
	}
}
```

Add `"os"` and `"strings"` imports if not already present.

- [ ] **Step 7: Run backpressure tests, verify pass**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/audit/ -run 'TestPendingCap|TestHealthReflectsDrops|TestCloseClearsHealthSidecar' -timeout 60s -v`

Expected: PASS.

- [ ] **Step 8: Surface health in `veil status`**

Modify `internal/cli/status.go` — after the audit open, read health and surface degradation. Add this block just before the closing `return nil`:

```go
	// Audit health from prior runs (persistent failures leave a sidecar).
	if health, herr := audit.ReadHealth(auditDBPath); herr == nil && health.Degraded() {
		_, _ = fmt.Fprintln(w)
		ui.Warn(w, "Audit subsystem reported issues in a prior session")
		if health.Dropped > 0 {
			_, _ = fmt.Fprintf(w, "    %s\n", ui.Muted.Sprintf("%d event(s) dropped due to full buffer", health.Dropped))
		}
		if !health.LastErrorTime.IsZero() {
			_, _ = fmt.Fprintf(w, "    %s\n", ui.Muted.Sprintf("last error %s: %s",
				ui.RelativeTime(health.LastErrorTime), health.LastErrorMsg))
		}
	}
```

- [ ] **Step 9: Add a status test that seeds a sidecar and verifies the warning appears**

Append to `internal/cli/cli_test.go`:

```go
func TestStatusShowsAuditHealthDegraded(t *testing.T) {
	root := initProject(t)
	dbPath := filepath.Join(root, ".veil", "audit.sqlite")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dbPath+".health",
		[]byte(fmt.Sprintf("dropped=7\nlast_error_ms=%d\nlast_error=disk full\n", time.Now().UnixMilli())),
		0o600,
	); err != nil {
		t.Fatalf("seed health sidecar: %v", err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"status", "--path", root})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("status: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "Audit subsystem reported issues") {
		t.Errorf("status output missing audit-health warning:\n%s", output)
	}
	if !strings.Contains(output, "7 event(s) dropped") {
		t.Errorf("status output missing dropped count:\n%s", output)
	}
	if !strings.Contains(output, "disk full") {
		t.Errorf("status output missing last error message:\n%s", output)
	}
}
```

- [ ] **Step 10: Run status test, verify pass**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/cli/ -run TestStatusShowsAuditHealthDegraded -timeout 60s -v`

Expected: PASS.

- [ ] **Step 11: Full suite under -race**

Run: `make test-race`

Expected: PASS. Capture full output for the deliverable.

- [ ] **Step 12: Commit**

```bash
git add internal/audit/audit.go internal/audit/health.go internal/audit/audit_test.go internal/cli/status.go internal/cli/cli_test.go
git commit -m "feat(audit): cap pending buffer and surface health in veil status"
```

---

### Task 6: Final verification

- [ ] **Step 1: Run the full race-enabled suite**

Run: `make test-race 2>&1 | tee /tmp/veil-make-test-race.out`

Expected: all packages pass, no race reports.

- [ ] **Step 2: Sanity-check build with the debug tag**

Run: `CGO_ENABLED=0 go build -tags audit_debug ./...`

Expected: clean build.

- [ ] **Step 3: Run standard test suite (no -race) as a smoke check**

Run: `make test`

Expected: PASS.

- [ ] **Step 4: Build without tags**

Run: `make build`

Expected: clean binary.

---

## Self-Review

**Spec coverage:**

- [x] Problem 1 (flusher race) → Task 1: WaitGroup, Close waits, test.
- [x] Problem 2 (suspect in totals) → Task 2: three queries updated, TestSummary extended.
- [x] Problem 3 (URL/argv over-log) → Task 3: build-tag + record-time redaction, tests, debug mode via `-tags audit_debug`.
- [x] Problem 4 (umask window) → Task 4: umask unix-file + race test.
- [x] Problem 5 (backpressure) → Task 5: pendingCap, drop-newest, ui.Warnf once, sidecar health file, `veil status` surface.

**Placeholder scan:** None (all code steps include complete code).

**Type consistency:** `Health` struct fields used consistently across `health.go`, `audit.go`, `cli/status.go`. `redactURLPath`/`redactAgentCmd` signatures identical in both build-tag files. `pendingCap` const is used in both `Record` and `recordFlushFailure`.

**Risk check:** The `TestPendingCapBoundsMemory` test closes `s.db` out from under the flusher goroutine. The flusher's `flushPending` will see a closed-db error and route into `recordFlushFailure`, which reacquires `s.mu`. Under `-race` this is safe because `s.mu` serializes all pending/dropped access. The test also closes `s.done` directly (not via `Close()`) to avoid double-close.
