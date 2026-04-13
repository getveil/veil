package audit

import (
	"database/sql"
	"strings"
	"time"
)

// Filter controls which injection rows are returned by Query.
type Filter struct {
	Since          time.Time // zero = no lower bound
	Host           string    // empty = any
	CredentialName string    // empty = any
	Limit          int       // 0 = default 100
	IncludeBlocked bool      // false = exclude blocked events
}

// Row represents a single injection record returned by a query.
type Row struct {
	ID             int
	Timestamp      time.Time
	RequestID      string
	Host           string
	Method         string
	URLPath        string
	CredentialID   string
	CredentialName string
	AgentPID       int
	AgentCmd       string
	BytesBefore    int
	BytesAfter     int
	Location       string
}

// Query returns injection rows matching the given filter, ordered by
// timestamp descending.
func (s *Store) Query(f Filter) ([]Row, error) {
	var (
		clauses []string
		args    []any
	)

	if !f.Since.IsZero() {
		clauses = append(clauses, "ts >= ?")
		args = append(args, f.Since.UnixMilli())
	}
	if f.Host != "" {
		clauses = append(clauses, "host = ?")
		args = append(args, f.Host)
	}
	if f.CredentialName != "" {
		clauses = append(clauses, "credential_name = ?")
		args = append(args, f.CredentialName)
	}
	if !f.IncludeBlocked {
		clauses = append(clauses, "location != 'blocked'")
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	args = append(args, limit)

	q := buildSelectQuery(clauses)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var result []Row
	for rows.Next() {
		var r Row
		var tsMillis int64
		if err := rows.Scan(
			&r.ID, &tsMillis, &r.RequestID, &r.Host, &r.Method,
			&r.URLPath, &r.CredentialID, &r.CredentialName,
			&r.AgentPID, &r.AgentCmd, &r.BytesBefore, &r.BytesAfter,
			&r.Location,
		); err != nil {
			return nil, err
		}
		r.Timestamp = time.UnixMilli(tsMillis).UTC()
		result = append(result, r)
	}
	return result, rows.Err()
}

const selectBase = "SELECT id, ts, request_id, host, method, url_path, credential_id, credential_name, agent_pid, agent_cmd, bytes_before, bytes_after, location FROM injections"

// buildSelectQuery constructs the full SELECT statement from static clause fragments.
// All clause strings are hardcoded column comparisons (e.g. "ts >= ?"), never user input.
func buildSelectQuery(clauses []string) string { //nolint:gosec // clauses are static column names
	var b strings.Builder
	b.WriteString(selectBase)
	if len(clauses) > 0 {
		b.WriteString(" WHERE ")
		b.WriteString(strings.Join(clauses, " AND "))
	}
	b.WriteString(" ORDER BY ts DESC LIMIT ?")
	return b.String()
}

// Summary returns aggregate information about injections since the given time.
// It returns the total count of successful injections, a separate blocked
// count, distinct hosts (excluding blocked), and the most recent successful
// injection.
func (s *Store) Summary(since time.Time) (total int, blocked int, hosts []string, lastInjection *Row, err error) {
	sinceMillis := since.UnixMilli()

	// Total successful count.
	err = s.db.QueryRow("SELECT COUNT(*) FROM injections WHERE ts >= ? AND location != 'blocked'", sinceMillis).Scan(&total)
	if err != nil {
		return
	}

	// Blocked count.
	err = s.db.QueryRow("SELECT COUNT(*) FROM injections WHERE ts >= ? AND location = 'blocked'", sinceMillis).Scan(&blocked)
	if err != nil {
		return
	}

	// Distinct hosts (successful injections only).
	rows, err := s.db.Query("SELECT DISTINCT host FROM injections WHERE ts >= ? AND location != 'blocked' ORDER BY host", sinceMillis)
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

	// Most recent successful injection.
	r := &Row{}
	var tsMillis int64
	scanErr := s.db.QueryRow(
		"SELECT id, ts, request_id, host, method, url_path, credential_id, credential_name, agent_pid, agent_cmd, bytes_before, bytes_after, location FROM injections WHERE ts >= ? AND location != 'blocked' ORDER BY ts DESC LIMIT 1",
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
