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
	Location       string // "header", "body", or "url"
}

// Store persists injection events to a SQLite database with batched writes.
type Store struct {
	db      *sql.DB
	mu      sync.Mutex
	pending []Injection
	done    chan struct{}
	flush   chan struct{} // signal immediate flush
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
  location        TEXT NOT NULL
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
  bytes_before, bytes_after, location
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

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
	if err := os.Chmod(parent, 0o700); err != nil {
		return nil, fmt.Errorf("%w: chmod parent dir: %w", ErrAuditOpen, err)
	}

	// modernc.org/sqlite does not honour _journal_mode= / _synchronous= DSN
	// parameters; use _pragma= encoding instead.
	dsn := "file:" + dbPath + "?_pragma=journal_mode%3DWAL&_pragma=synchronous%3DNORMAL"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("%w: sql.Open: %w", ErrAuditOpen, err)
	}

	if _, err := db.Exec(schemaDDL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%w: ddl: %w", ErrAuditOpen, err)
	}

	// Force WAL + SHM sidecar materialization by taking a write lock.
	// BeginTx with sql.LevelSerializable maps to BEGIN IMMEDIATE on SQLite,
	// which forces SQLite to create the -wal/-shm files before the transaction
	// body runs.
	{
		tx, txErr := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelSerializable})
		if txErr != nil {
			_ = db.Close()
			return nil, fmt.Errorf("%w: materialize wal begin: %w", ErrAuditOpen, txErr)
		}
		if _, txErr = tx.Exec(`UPDATE schema_version SET v = v`); txErr != nil {
			_ = tx.Rollback()
			_ = db.Close()
			return nil, fmt.Errorf("%w: materialize wal exec: %w", ErrAuditOpen, txErr)
		}
		if txErr = tx.Commit(); txErr != nil {
			_ = db.Close()
			return nil, fmt.Errorf("%w: materialize wal commit: %w", ErrAuditOpen, txErr)
		}
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
	go s.flusher()
	return s, nil
}

// Record appends an injection event to the pending buffer. It is safe for
// concurrent use. When the buffer reaches 50 rows the flusher is signalled
// to write immediately.
func (s *Store) Record(inj Injection) {
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
// the database.
func (s *Store) Close() error {
	close(s.done)
	s.flushPending()
	return s.db.Close()
}

// flusher runs in a goroutine, periodically writing pending rows.
func (s *Store) flusher() {
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
