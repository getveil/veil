// Package audit records secret injection events to a local SQLite database.
package audit

import (
	"database/sql"
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
// background flush goroutine.
func Open(dbPath string) (*Store, error) {
	dsn := "file:" + dbPath + "?_journal_mode=wal&_synchronous=normal"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec(schemaDDL); err != nil {
		_ = db.Close()
		return nil, err
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
