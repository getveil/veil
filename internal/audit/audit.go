// Package audit records secret injection events to a local SQLite database.
package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

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
}

// Store persists injection events to a SQLite database with batched writes.
type Store struct {
	db        *sql.DB
	mu        sync.Mutex
	pending   []Injection
	done      chan struct{}
	flush     chan struct{} // signal immediate flush
	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup // tracks the flusher goroutine
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
  auth_signal     TEXT NOT NULL DEFAULT ''
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
  bytes_before, bytes_after, location, suspect_flag, auth_signal
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// Open opens (or creates) the SQLite database at dbPath and starts the
// background flush goroutine. It enforces 0600 permissions on the database
// files and 0700 on the parent directory (idempotent: corrects existing
// installs).
func Open(dbPath string) (*Store, error) {
	// Ensure parent dir is 0700 before creating the DB.
	parent := filepath.Dir(dbPath)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("%w: create parent dir: %w", ErrAuditOpen, err)
	}
	if err := os.Chmod(parent, 0o700); err != nil { // #nosec G302 -- 0700 is correct for a directory
		return nil, fmt.Errorf("%w: chmod parent dir: %w", ErrAuditOpen, err)
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
		return nil, fmt.Errorf("%w: %w", ErrAuditOpen, err)
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
			return nil, fmt.Errorf("%w: chmod %s: %w", ErrAuditOpen, p, err)
		}
	}

	s := &Store{
		db:    db,
		done:  make(chan struct{}),
		flush: make(chan struct{}, 1),
	}
	s.wg.Add(1)
	go s.flusher()
	return s, nil
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
		close(s.done)
		s.wg.Wait()      // flusher has observed done and returned
		s.flushPending() // drain anything enqueued after the last tick
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
// transaction.
func (s *Store) flushPending() {
	s.mu.Lock()
	if len(s.pending) == 0 {
		s.mu.Unlock()
		return
	}
	batch := s.pending
	s.pending = nil
	s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		// Put them back so they aren't lost.
		s.mu.Lock()
		s.pending = append(batch, s.pending...)
		s.mu.Unlock()
		return
	}

	stmt, err := tx.Prepare(insertSQL)
	if err != nil {
		_ = tx.Rollback()
		s.mu.Lock()
		s.pending = append(batch, s.pending...)
		s.mu.Unlock()
		return
	}

	for _, inj := range batch {
		suspect := 0
		if inj.SuspectFlag {
			suspect = 1
		}
		_, err := stmt.Exec(
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
		)
		if err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			s.mu.Lock()
			s.pending = append(batch, s.pending...)
			s.mu.Unlock()
			return
		}
	}
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		s.mu.Lock()
		s.pending = append(batch, s.pending...)
		s.mu.Unlock()
	}
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
