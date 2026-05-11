// Package audit records secret injection events to a local SQLite database.
package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/getveil/veil/internal/ui"
	_ "modernc.org/sqlite"
)

// pendingCap bounds the in-memory Injection buffer. ~160 bytes per row, so
// 10k rows ≈ 1.6MB — enough to absorb a several-minute flush outage on a
// normal workload while keeping a hard memory ceiling.
const pendingCap = 10_000

// Injection represents a single secret-injection event.
type Injection struct {
	Timestamp      time.Time
	RequestID      string // ULID, groups multi-hit requests
	Host           string
	Method         string
	URLPath        string
	CredentialID   string
	CredentialName string
	AgentPID       int
	AgentCmd       string
	BytesBefore    int
	BytesAfter     int
	Location       string // "header", "body", "url", "blocked", or "mismatch_suspected"
	SuspectFlag    bool
	AuthSignal     string
	SignerError    string // empty unless Location == "signer_failed"
}

// Store persists injection events to a SQLite database with batched writes.
type Store struct {
	db        *sql.DB
	mu        sync.Mutex
	pending   []Injection
	done      chan struct{}
	flush     chan struct{} // signal immediate flush
	closeOnce sync.Once
	stopOnce  sync.Once // gates close(done) so Close+DrainForTest can coexist
	closeErr  error
	wg        sync.WaitGroup // tracks the flusher goroutine

	// Backpressure / health (all guarded by mu).
	dbPath          string
	dropped         int
	lastErr         string
	lastErrTime     time.Time
	warnedFullOnce  bool      // gate the buffer-full warning
	warnedFlushOnce bool      // gate the flush-failure warning
	warnWriter      io.Writer // destination for ui.Warnf; defaults to os.Stderr
}

const schemaDDL = `
CREATE TABLE IF NOT EXISTS injections (
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
CREATE INDEX IF NOT EXISTS idx_inj_ts   ON injections(ts);
CREATE INDEX IF NOT EXISTS idx_inj_host ON injections(host);
CREATE INDEX IF NOT EXISTS idx_inj_cred ON injections(credential_name);
CREATE TABLE IF NOT EXISTS schema_version (v INTEGER PRIMARY KEY);
INSERT OR IGNORE INTO schema_version VALUES (1);
`

const insertSQL = `INSERT INTO injections (
  ts, request_id, host, method, url_path,
  credential_id, credential_name, agent_pid, agent_cmd,
  bytes_before, bytes_after, location, suspect_flag, auth_signal,
  signer_error
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// Open opens (or creates) the SQLite database at dbPath and starts the
// background flush goroutine. It enforces 0600 permissions on the database
// files and 0700 on the parent directory (idempotent: corrects existing
// installs).
func Open(dbPath string) (*Store, error) {
	// Ensure parent dir is 0700 before creating the DB.
	parent := filepath.Dir(dbPath)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("%w: create parent dir: %w", ErrOpen, err)
	}
	if err := os.Chmod(parent, 0o700); err != nil { // #nosec G302 -- 0700 is correct for a directory
		return nil, fmt.Errorf("%w: chmod parent dir: %w", ErrOpen, err)
	}

	// modernc.org/sqlite does not honour _journal_mode= / _synchronous= DSN
	// parameters; use _pragma= encoding instead.
	dsn := "file:" + dbPath + "?_pragma=journal_mode%3DWAL&_pragma=synchronous%3DNORMAL"
	var db *sql.DB
	// Wrap all file-creating operations in a tightened umask. SQLite creates
	// the main DB at sql.Open time and the -wal/-shm sidecars when the first
	// write transaction runs. Without this guard the sidecars briefly exist
	// at 0644 before the subsequent Chmod tightens them.
	if err := withRestrictiveUmask(func() error {
		var openErr error
		db, openErr = sql.Open("sqlite", dsn)
		if openErr != nil {
			return fmt.Errorf("sql.Open: %w", openErr)
		}
		if _, execErr := db.Exec(schemaDDL); execErr != nil {
			_ = db.Close()
			db = nil
			return fmt.Errorf("ddl: %w", execErr)
		}
		if mErr := migrateToV2(db); mErr != nil {
			_ = db.Close()
			db = nil
			return fmt.Errorf("migrate v2: %w", mErr)
		}
		if mErr := migrateToV3(db); mErr != nil {
			_ = db.Close()
			db = nil
			return fmt.Errorf("migrate v3: %w", mErr)
		}
		// Force WAL + SHM sidecar materialization by taking a write lock.
		// BeginTx with sql.LevelSerializable maps to BEGIN IMMEDIATE on SQLite,
		// which forces SQLite to create the -wal/-shm files before the
		// transaction body runs.
		tx, txErr := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelSerializable})
		if txErr != nil {
			_ = db.Close()
			db = nil
			return fmt.Errorf("materialize wal begin: %w", txErr)
		}
		if _, txErr = tx.Exec(`UPDATE schema_version SET v = v`); txErr != nil {
			_ = tx.Rollback()
			_ = db.Close()
			db = nil
			return fmt.Errorf("materialize wal exec: %w", txErr)
		}
		if txErr = tx.Commit(); txErr != nil {
			_ = db.Close()
			db = nil
			return fmt.Errorf("materialize wal commit: %w", txErr)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrOpen, err)
	}

	// Chmod 0600 on db and sidecars. `-wal` may have been auto-checkpointed
	// away on some configurations; tolerate its absence. The main db and
	// `-shm` must exist after a successful write transaction.
	mustExist := map[string]bool{"": true, "-shm": true, "-wal": false}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := dbPath + suffix
		if err := os.Chmod(p, 0o600); err != nil {
			if errors.Is(err, os.ErrNotExist) && !mustExist[suffix] {
				continue
			}
			_ = db.Close()
			return nil, fmt.Errorf("%w: chmod %s: %w", ErrOpen, p, err)
		}
	}

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
}

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

// stopFlusher signals the flusher goroutine to exit. It is idempotent and
// safe to call from both Close() and DrainForTest().
func (s *Store) stopFlusher() {
	s.stopOnce.Do(func() { close(s.done) })
}

// DrainForTest stops the background flusher, waits for it to exit, and
// synchronously flushes any pending rows. This is a test-only helper: it
// lets tests deterministically wait for all Record() calls to land in the
// DB without a time.Sleep. Safe to call before Close(); Close() uses the
// same stopOnce so the done channel is only closed once.
func (s *Store) DrainForTest() {
	s.stopFlusher()
	s.wg.Wait()
	s.flushPending()
}

// Flush synchronously writes any pending injection rows to the database
// without stopping the background flusher. Callers that need an up-to-date
// view of the audit DB (e.g. the session-end footer that immediately
// queries Summary) must Flush first, otherwise short sessions whose
// injection count never reached the 50-row auto-flush threshold or the
// 100ms ticker tick will read zero from SQLite while the buffer still
// holds the rows.
func (s *Store) Flush() {
	s.flushPending()
}

// Record appends an injection event to the pending buffer. It is safe for
// concurrent use. When the buffer reaches 50 rows the flusher is signalled
// to write immediately.
//
// URLPath and AgentCmd are passed through redactURLPath / redactAgentCmd
// before enqueue so callers cannot accidentally persist query strings or
// full argv into the audit DB. Build with `-tags audit_debug` to disable
// redaction when diagnosing audit issues.
func (s *Store) Record(inj Injection) {
	inj.URLPath = redactURLPath(inj.URLPath)
	inj.AgentCmd = redactAgentCmd(inj.AgentCmd)

	s.mu.Lock()
	if len(s.pending) >= pendingCap {
		s.dropped++
		warnNow := !s.warnedFullOnce
		s.warnedFullOnce = true
		dbPath := s.dbPath
		warn := s.warnWriter
		snapshot := Health{
			Dropped:       s.dropped,
			LastErrorTime: s.lastErrTime,
			LastErrorMsg:  s.lastErr,
		}
		s.mu.Unlock()

		if warnNow {
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

// Close stops the background flusher, flushes remaining rows, and closes
// the database. Close is idempotent; subsequent calls return the original
// result without side effects. Close blocks until the flusher goroutine has
// exited, so any in-flight flushPending transaction completes before the
// database handle is closed.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.stopFlusher()  // idempotent: DrainForTest may have already stopped it
		s.wg.Wait()      // flusher has observed done and returned
		s.flushPending() // drain anything enqueued after the last tick

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

// flusher runs in a goroutine, periodically writing pending rows.
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

// flushPending swaps the pending buffer and inserts all rows in a single
// transaction. On failure, the batch is requeued up to pendingCap and
// the flush failure is recorded on the Store / persisted to the health
// sidecar.
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
		return fmt.Errorf("%w: begin: %w", ErrWrite, err)
	}
	stmt, err := tx.Prepare(insertSQL)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("%w: prepare: %w", ErrWrite, err)
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
			inj.SignerError,
		); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return fmt.Errorf("%w: exec: %w", ErrWrite, err)
		}
	}
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit: %w", ErrWrite, err)
	}
	return nil
}

// recordFlushFailure re-queues the batch (respecting pendingCap) and records
// the error for veil status to surface. The first failure emits a ui.Warnf
// so the user sees it in the current session; subsequent failures are
// silent (the sidecar remains the durable signal).
func (s *Store) recordFlushFailure(batch []Injection, err error) {
	s.mu.Lock()
	room := pendingCap - len(s.pending)
	if room < 0 {
		room = 0
	}
	if room >= len(batch) {
		s.pending = append(batch, s.pending...)
	} else {
		keep := batch[len(batch)-room:]
		s.pending = append(keep, s.pending...)
		s.dropped += len(batch) - room
	}
	s.lastErr = err.Error()
	s.lastErrTime = time.Now().UTC()
	firstWarn := !s.warnedFlushOnce
	s.warnedFlushOnce = true
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

// migrateToV2 adds the suspect_flag and auth_signal columns to pre-existing
// v1 schemas. It is idempotent and safe to call on already-migrated databases.
func migrateToV2(db *sql.DB) error {
	var v int
	if err := db.QueryRow(`SELECT COALESCE(MAX(v), 0) FROM schema_version`).Scan(&v); err != nil {
		return fmt.Errorf("read version: %w", err)
	}
	if v >= 2 {
		return nil
	}

	rows, err := db.Query(`PRAGMA table_info(injections)`)
	if err != nil {
		return fmt.Errorf("table_info: %w", err)
	}
	have := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan table_info: %w", err)
		}
		have[name] = true
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close table_info: %w", err)
	}

	if !have["suspect_flag"] {
		if _, err := db.Exec(`ALTER TABLE injections ADD COLUMN suspect_flag INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add suspect_flag: %w", err)
		}
	}
	if !have["auth_signal"] {
		if _, err := db.Exec(`ALTER TABLE injections ADD COLUMN auth_signal TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add auth_signal: %w", err)
		}
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_inj_suspect ON injections(suspect_flag)`); err != nil {
		return fmt.Errorf("create suspect index: %w", err)
	}

	if _, err := db.Exec(`INSERT INTO schema_version (v) VALUES (2)`); err != nil {
		return fmt.Errorf("mark v2: %w", err)
	}
	return nil
}

// migrateToV3 adds the signer_error column to pre-existing v2 schemas.
// Idempotent.
func migrateToV3(db *sql.DB) error {
	var v int
	if err := db.QueryRow(`SELECT COALESCE(MAX(v), 0) FROM schema_version`).Scan(&v); err != nil {
		return fmt.Errorf("read version: %w", err)
	}
	if v >= 3 {
		return nil
	}

	rows, err := db.Query(`PRAGMA table_info(injections)`)
	if err != nil {
		return fmt.Errorf("table_info: %w", err)
	}
	have := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan table_info: %w", err)
		}
		have[name] = true
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close table_info: %w", err)
	}
	if !have["signer_error"] {
		if _, err := db.Exec(`ALTER TABLE injections ADD COLUMN signer_error TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add signer_error: %w", err)
		}
	}
	if _, err := db.Exec(`INSERT INTO schema_version (v) VALUES (3)`); err != nil {
		return fmt.Errorf("mark v3: %w", err)
	}
	return nil
}
