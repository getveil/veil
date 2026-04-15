# Transformed Credential Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix HTTP Basic auth injection (Class 1 encoded forms) and add a silent-failure detector so untransformable schemes (SigV4, JWT) stop failing silently.

**Architecture:** Two additions to `internal/proxy/injector.go`'s `ProcessRequest`: (1) a pre-pass Basic-header decoder that decodes `Basic <base64>`, matches user/secret placeholders, and re-encodes with real values; (2) a post-pass heuristic detector that emits a warning audit record when a request hits a credentialed host but no injection fired. Vault `Credential` gains `Username` + `UsernamePlaceholder`; CLI `veil add` gains `--user`.

**Tech Stack:** Go, SQLite (`modernc.org/sqlite`), Cobra, existing `ahocorasick` matcher, existing `audit.Store`.

**Spec:** `docs/superpowers/specs/2026-04-15-transformed-credential-fix-design.md`

---

## File structure

**Create:**
- `internal/proxy/basic_decoder.go` — Basic-header decode, match, re-encode.
- `internal/proxy/basic_decoder_test.go` — unit tests for decoder.
- `internal/proxy/mismatch_detector.go` — heuristic detector + WARN log emission.
- `internal/proxy/mismatch_detector_test.go` — unit tests for detector.
- `internal/proxy/basic_integration_test.go` — end-to-end Basic flow + detector flow.

**Modify:**
- `internal/vault/record.go` — add `Username`, `UsernamePlaceholder`; extend `Zero()`.
- `internal/vault/vault.go` — extend `Add()` collision check; extend `PlaceholderMap()` (or add `UsernamePlaceholderMap()`).
- `internal/audit/audit.go` — schema migration for `suspect_flag`, `auth_signal` columns; extend `Injection` struct; extend `insertSQL`.
- `internal/audit/query.go` — extend `Row` struct; extend `Filter` with `SuspectOnly`; update SELECT statement and scan.
- `internal/proxy/injector.go` — wire decoder (before existing scan) and detector (after existing scan) into `ProcessRequest`.
- `internal/cli/add.go` — `--user` flag, dual placeholder generation, dual `.env` sync.
- `internal/cli/list.go` — `(basic)` tag in NAME column for credentials with `Username != ""`.
- `internal/cli/log.go` — `[!]` tag, `--suspect` filter, include mismatch rows by default.
- `docs/PRODUCT.md`, `docs/MVP.md`, `docs/THREAT_MODEL.md` — auth-scheme coverage notes.

---

## Task 1: Vault schema — add Username and UsernamePlaceholder fields

**Files:**
- Modify: `internal/vault/record.go`
- Test: `internal/vault/vault_test.go` (new test function)

- [ ] **Step 1: Write the failing test**

Add to `internal/vault/vault_test.go`:

```go
func TestCredentialBasicFields(t *testing.T) {
	c := &Credential{
		ID:                  "abc",
		Name:                "github-pat",
		Real:                "ghp_realvalue",
		Placeholder:         "VEIL_PH_SECRET",
		Username:            "johndoe",
		UsernamePlaceholder: "VEIL_PH_USER",
	}

	c.Zero()

	if c.Username != "" {
		t.Errorf("Zero() did not clear Username: %q", c.Username)
	}
	if c.UsernamePlaceholder != "" {
		t.Errorf("Zero() did not clear UsernamePlaceholder: %q", c.UsernamePlaceholder)
	}
	if c.Real != "" || c.Placeholder != "" {
		t.Error("Zero() should still clear Real and Placeholder")
	}
}

func TestCredentialJSONRoundTripBasic(t *testing.T) {
	original := &Credential{
		ID:                  "id1",
		Name:                "github-pat",
		Real:                "ghp_realvalue",
		Placeholder:         "VEIL_PH_SECRET",
		Username:            "johndoe",
		UsernamePlaceholder: "VEIL_PH_USER",
		CreatedAt:           time.Unix(1712000000, 0).UTC(),
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Credential
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Username != "johndoe" || got.UsernamePlaceholder != "VEIL_PH_USER" {
		t.Errorf("round-trip lost basic fields: %+v", got)
	}
}

func TestCredentialJSONBackwardCompat(t *testing.T) {
	// Old on-disk format had no Username / UsernamePlaceholder fields.
	oldJSON := `{"id":"x","name":"n","real":"r","placeholder":"p","source":"manual","created_at":"2024-01-01T00:00:00Z"}`
	var got Credential
	if err := json.Unmarshal([]byte(oldJSON), &got); err != nil {
		t.Fatalf("unmarshal old format: %v", err)
	}
	if got.Username != "" || got.UsernamePlaceholder != "" {
		t.Errorf("expected empty basic fields on old record, got %+v", got)
	}
}
```

Ensure the imports at the top of `vault_test.go` include `"encoding/json"` and `"time"` (add if missing).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vault/ -run TestCredentialBasic -v`
Expected: FAIL with `undefined: Username` / `UsernamePlaceholder`.

- [ ] **Step 3: Add fields and update `Zero()` in `internal/vault/record.go`**

Replace the existing `Credential` struct and `Zero()` method with:

```go
// Credential holds a single secret and its proxy placeholder.
type Credential struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Real                string    `json:"real"`
	Placeholder         string    `json:"placeholder"`
	Source              string    `json:"source"`
	AllowedHosts        []string  `json:"allowed_hosts,omitempty"`
	Username            string    `json:"username,omitempty"`
	UsernamePlaceholder string    `json:"username_placeholder,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
}

// String returns a redacted representation that never leaks secret material.
func (c *Credential) String() string {
	return fmt.Sprintf("Credential{ID:%s, Name:%s}", c.ID, c.Name)
}

// Zero clears sensitive fields. Best-effort for MVP since Go strings are
// immutable; the previous backing memory remains until GC.
func (c *Credential) Zero() {
	c.Real = ""
	c.Placeholder = ""
	c.Username = ""
	c.UsernamePlaceholder = ""
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/vault/ -v`
Expected: PASS including the three new tests. Existing tests unchanged.

- [ ] **Step 5: Commit**

```bash
git add internal/vault/record.go internal/vault/vault_test.go
git commit -m "feat(vault): add Username and UsernamePlaceholder to Credential"
```

---

## Task 2: Vault — extend Add() collision check for UsernamePlaceholder

**Files:**
- Modify: `internal/vault/vault.go:127-138` (the `Add` function)
- Test: `internal/vault/vault_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/vault/vault_test.go`:

```go
func TestAddRejectsUsernamePlaceholderCollision(t *testing.T) {
	v := newInMemoryVaultForTest(t) // use whatever helper exists in this file
	first := &Credential{
		ID: "a", Name: "first",
		Real: "r1", Placeholder: "VEIL_PH_SECRET_AAAA",
		Username: "alice", UsernamePlaceholder: "VEIL_PH_USER_SHARED",
	}
	if err := v.Add(first); err != nil {
		t.Fatalf("Add first: %v", err)
	}

	// Second credential whose Placeholder collides with first's UsernamePlaceholder.
	second := &Credential{
		ID: "b", Name: "second",
		Real: "r2", Placeholder: "VEIL_PH_USER_SHARED",
	}
	if err := v.Add(second); err == nil {
		t.Fatal("Add should have rejected placeholder colliding with existing UsernamePlaceholder")
	}

	// Third credential whose UsernamePlaceholder collides with first's Placeholder.
	third := &Credential{
		ID: "c", Name: "third",
		Real: "r3", Placeholder: "VEIL_PH_SECRET_BBBB",
		Username: "carol", UsernamePlaceholder: "VEIL_PH_SECRET_AAAA",
	}
	if err := v.Add(third); err == nil {
		t.Fatal("Add should have rejected UsernamePlaceholder colliding with existing Placeholder")
	}
}
```

If `newInMemoryVaultForTest` does not exist, look at the existing tests in `vault_test.go` and follow the same setup pattern they already use (likely `NewVault` with a test keystore). Match existing style.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vault/ -run TestAddRejectsUsernamePlaceholderCollision -v`
Expected: FAIL — the second and/or third Add succeeds because the collision check only inspects `Placeholder`.

- [ ] **Step 3: Update `Add` in `internal/vault/vault.go`**

Replace the body of `Add` (lines 127-138):

```go
// Add appends a credential after checking for duplicate names and placeholder
// collisions. It persists the vault on success.
func (v *Vault) Add(cred *Credential) error {
	for _, c := range v.credentials {
		if c.Name == cred.Name {
			return fmt.Errorf("%w: %q", ErrDuplicateCredential, cred.Name)
		}
		if collidesWithAny(cred.Placeholder, c) {
			return fmt.Errorf("%w: generated placeholder for %q matches credential %q. Remove the conflicting credential with veil remove", ErrPlaceholderCollision, cred.Name, c.Name)
		}
		if cred.UsernamePlaceholder != "" && collidesWithAny(cred.UsernamePlaceholder, c) {
			return fmt.Errorf("%w: generated username placeholder for %q matches credential %q. Remove the conflicting credential with veil remove", ErrPlaceholderCollision, cred.Name, c.Name)
		}
	}
	v.credentials = append(v.credentials, cred)
	return v.Save()
}

// collidesWithAny reports whether candidate matches either the secret
// placeholder or the username placeholder of c.
func collidesWithAny(candidate string, c *Credential) bool {
	if candidate == "" {
		return false
	}
	return candidate == c.Placeholder || (c.UsernamePlaceholder != "" && candidate == c.UsernamePlaceholder)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/vault/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/vault/vault.go internal/vault/vault_test.go
git commit -m "feat(vault): reject placeholder collisions across Username and secret placeholders"
```

---

## Task 3: Vault — PlaceholderSet and PlaceholderMap include username placeholders

**Files:**
- Modify: `internal/vault/vault.go:177-195` (`PlaceholderSet`, `PlaceholderMap`)
- Test: `internal/vault/vault_test.go`

**Rationale:** the injector's Basic decoder will look up placeholders from `PlaceholderMap`. Both halves of a Basic credential must be findable there. The placeholder-collision set used by the CLI also needs to include username placeholders so newly-generated secret placeholders can't collide with existing username placeholders.

- [ ] **Step 1: Write the failing test**

Add to `internal/vault/vault_test.go`:

```go
func TestPlaceholderMapIncludesUsernamePlaceholder(t *testing.T) {
	v := newInMemoryVaultForTest(t)
	cred := &Credential{
		ID: "a", Name: "github-pat",
		Real:                "ghp_real",
		Placeholder:         "VEIL_PH_SECRET",
		Username:            "johndoe",
		UsernamePlaceholder: "VEIL_PH_USER",
	}
	if err := v.Add(cred); err != nil {
		t.Fatalf("Add: %v", err)
	}

	m := v.PlaceholderMap()
	if got := m["VEIL_PH_SECRET"]; got == nil || got.Name != "github-pat" {
		t.Errorf("PlaceholderMap missing secret placeholder entry")
	}
	if got := m["VEIL_PH_USER"]; got == nil || got.Name != "github-pat" {
		t.Errorf("PlaceholderMap missing username placeholder entry")
	}
}

func TestPlaceholderSetIncludesUsernamePlaceholder(t *testing.T) {
	v := newInMemoryVaultForTest(t)
	cred := &Credential{
		ID: "a", Name: "gh",
		Real:                "r",
		Placeholder:         "VEIL_PH_SECRET",
		Username:            "u",
		UsernamePlaceholder: "VEIL_PH_USER",
	}
	if err := v.Add(cred); err != nil {
		t.Fatalf("Add: %v", err)
	}
	s := v.PlaceholderSet()
	if _, ok := s["VEIL_PH_SECRET"]; !ok {
		t.Error("set missing secret placeholder")
	}
	if _, ok := s["VEIL_PH_USER"]; !ok {
		t.Error("set missing username placeholder")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vault/ -run "TestPlaceholderMapIncludesUsernamePlaceholder|TestPlaceholderSetIncludesUsernamePlaceholder" -v`
Expected: FAIL — map/set only contains secret placeholder.

- [ ] **Step 3: Update `PlaceholderSet` and `PlaceholderMap` in `internal/vault/vault.go`**

Replace both functions (lines 177-195):

```go
// PlaceholderSet returns the set of currently-used placeholder strings
// (both secret and username placeholders), suitable for passing to
// placeholder.Generate to prevent collisions.
func (v *Vault) PlaceholderSet() placeholder.Set {
	out := make(placeholder.Set, len(v.credentials)*2)
	for _, c := range v.credentials {
		out[c.Placeholder] = struct{}{}
		if c.UsernamePlaceholder != "" {
			out[c.UsernamePlaceholder] = struct{}{}
		}
	}
	return out
}

// PlaceholderMap returns a map from placeholder value to credential, used by
// the injector to swap placeholders back to real secrets. For Basic credentials
// both the secret placeholder and the username placeholder map to the same
// credential record.
func (v *Vault) PlaceholderMap() map[string]*Credential {
	m := make(map[string]*Credential, len(v.credentials)*2)
	for _, c := range v.credentials {
		m[c.Placeholder] = c
		if c.UsernamePlaceholder != "" {
			m[c.UsernamePlaceholder] = c
		}
	}
	return m
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/vault/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/vault/vault.go internal/vault/vault_test.go
git commit -m "feat(vault): include username placeholders in PlaceholderMap and PlaceholderSet"
```

---

## Task 4: Audit — schema migration for suspect_flag and auth_signal columns

**Files:**
- Modify: `internal/audit/audit.go` (schemaDDL, Open)
- Test: `internal/audit/audit_test.go`

**Rationale:** The mismatch detector records a row in the audit DB with no credential but with these two fields set. Existing on-disk databases must be migrated in place via `ALTER TABLE`.

- [ ] **Step 1: Write the failing test**

Add to `internal/audit/audit_test.go` (follow existing test setup helpers for opening a temp DB):

```go
func TestSchemaHasSuspectColumns(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Query pragma to confirm the columns exist.
	rows, err := db.db.Query(`PRAGMA table_info(injections)`)
	if err != nil {
		t.Fatalf("pragma: %v", err)
	}
	defer func() { _ = rows.Close() }()

	found := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan: %v", err)
		}
		found[name] = true
	}
	for _, col := range []string{"suspect_flag", "auth_signal"} {
		if !found[col] {
			t.Errorf("missing column %q", col)
		}
	}
}

func TestSchemaMigratesFromV1(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")

	// Create a v1 database without the new columns.
	dsn := "file:" + dbPath + "?_pragma=journal_mode%3DWAL&_pragma=synchronous%3DNORMAL"
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	const v1DDL = `
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
  location        TEXT NOT NULL
);
CREATE TABLE schema_version (v INTEGER PRIMARY KEY);
INSERT INTO schema_version VALUES (1);
`
	if _, err := raw.Exec(v1DDL); err != nil {
		t.Fatalf("v1 ddl: %v", err)
	}
	_ = raw.Close()

	// Now open via Open() and verify migration completed.
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open on v1 db: %v", err)
	}
	defer func() { _ = db.Close() }()

	var v int
	if err := db.db.QueryRow(`SELECT MAX(v) FROM schema_version`).Scan(&v); err != nil {
		t.Fatalf("scan version: %v", err)
	}
	if v < 2 {
		t.Errorf("schema_version = %d, want >= 2", v)
	}

	// Insert a row using the new columns to prove they work.
	if _, err := db.db.Exec(`INSERT INTO injections
		(ts, request_id, host, method, url_path, credential_id, credential_name,
		 agent_pid, agent_cmd, bytes_before, bytes_after, location, suspect_flag, auth_signal)
		VALUES (0, '', '', '', '', '', '', 0, '', 0, 0, 'mismatch_suspected', 1, 'authorization_header')`); err != nil {
		t.Errorf("insert with new columns: %v", err)
	}
}
```

Ensure imports include `"database/sql"`, `"path/filepath"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/audit/ -run "TestSchemaHasSuspectColumns|TestSchemaMigratesFromV1" -v`
Expected: FAIL — columns do not exist; insert with 15 columns errors.

- [ ] **Step 3: Update `schemaDDL` and add migration in `internal/audit/audit.go`**

Replace `schemaDDL` (around line 42):

```go
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
CREATE INDEX IF NOT EXISTS idx_inj_suspect ON injections(suspect_flag);
CREATE TABLE IF NOT EXISTS schema_version (v INTEGER PRIMARY KEY);
INSERT OR IGNORE INTO schema_version VALUES (1);
`
```

Leave `insertSQL` at 12 placeholders for now; Task 5 updates it together with `flushPending`.

In `Open`, after `db.Exec(schemaDDL)` succeeds, add migration logic:

```go
	if _, err := db.Exec(schemaDDL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%w: ddl: %w", ErrAuditOpen, err)
	}

	if err := migrateToV2(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%w: migrate v2: %w", ErrAuditOpen, err)
	}
```

Add the helper at the bottom of `audit.go`:

```go
// migrateToV2 adds the suspect_flag and auth_signal columns to pre-existing
// v1 schemas. It is idempotent and safe to call on already-migrated databases.
func migrateToV2(db *sql.DB) error {
	// Check current version.
	var v int
	if err := db.QueryRow(`SELECT COALESCE(MAX(v), 0) FROM schema_version`).Scan(&v); err != nil {
		return fmt.Errorf("read version: %w", err)
	}
	if v >= 2 {
		return nil
	}

	// Discover existing columns to decide which ALTERs to run. This makes the
	// migration tolerant of partially-migrated databases.
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/audit/ -v`
Expected: PASS. Schema has the new columns (confirmed by `TestSchemaHasSuspectColumns` / `TestSchemaMigratesFromV1`); existing `Record`/`Query` tests still pass because `insertSQL` and `flushPending` remain at 12 values and the new columns default to zero/empty for those inserts.

- [ ] **Step 5: Commit**

```bash
git add internal/audit/audit.go internal/audit/audit_test.go
git commit -m "feat(audit): migrate schema to v2 with suspect_flag and auth_signal columns"
```

---

## Task 5: Audit — extend Injection struct and flush logic

**Files:**
- Modify: `internal/audit/audit.go` (Injection struct, `flushPending`)
- Test: `internal/audit/audit_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/audit/audit_test.go`:

```go
func TestRecordAndQuerySuspectFields(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	now := time.Now()
	db.Record(Injection{
		Timestamp:      now,
		RequestID:      "req-suspect-1",
		Host:           "api.example.com",
		Method:         "GET",
		URLPath:        "/v1/thing",
		Location:       "mismatch_suspected",
		SuspectFlag:    true,
		AuthSignal:     "authorization_header",
	})
	db.Record(Injection{
		Timestamp:      now,
		RequestID:      "req-inj-1",
		Host:           "api.example.com",
		Method:         "GET",
		URLPath:        "/v1/thing",
		CredentialID:   "c1",
		CredentialName: "gh",
		Location:       "header",
		BytesBefore:    10, BytesAfter: 20,
	})
	// Force flush.
	_ = db.Close()

	// Reopen and query.
	db2, err := Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = db2.Close() }()

	rows, err := db2.Query(Filter{Since: now.Add(-time.Hour), IncludeBlocked: true, IncludeSuspect: true})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}

	var suspect, normal *Row
	for i := range rows {
		if rows[i].SuspectFlag {
			suspect = &rows[i]
		} else {
			normal = &rows[i]
		}
	}
	if suspect == nil {
		t.Fatal("no suspect row returned")
	}
	if suspect.AuthSignal != "authorization_header" {
		t.Errorf("AuthSignal = %q", suspect.AuthSignal)
	}
	if normal == nil || normal.SuspectFlag {
		t.Error("normal injection row incorrectly marked suspect")
	}
}
```

This test depends on `Filter.IncludeSuspect`, which is added in Task 6. It will fail to compile until Task 6 lands. To keep the test file compiling now, write the test but put it inside a `//go:build never` guard at the top of the function, or comment it out with a `// TODO(task-6): enable when IncludeSuspect lands`. Alternative: go ahead and combine Tasks 5 and 6 into a single task. Combined.

**Re-scoping:** Treat Task 5 and Task 6 as a single commit. The step below includes both the struct/flush changes AND the query changes.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/audit/ -run TestRecordAndQuerySuspectFields -v`
Expected: compile failure — `Injection.SuspectFlag` unknown, `Filter.IncludeSuspect` unknown, `Row.SuspectFlag` unknown.

- [ ] **Step 3: Extend `Injection` struct, `insertSQL`, and `flushPending` in `internal/audit/audit.go`**

Update `insertSQL` (around line 65) to 14 placeholders:

```go
const insertSQL = `INSERT INTO injections (
  ts, request_id, host, method, url_path,
  credential_id, credential_name, agent_pid, agent_cmd,
  bytes_before, bytes_after, location, suspect_flag, auth_signal
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
```

Replace the `Injection` struct (around line 18):

```go
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
	Location       string // "header", "body", "url", "blocked", "mismatch_suspected"
	SuspectFlag    bool   // true on detector-emitted mismatch rows
	AuthSignal     string // e.g. "authorization_header", "cookie", "x_api_token_header"
}
```

Update the `stmt.Exec` call in `flushPending` (around line 215-229):

```go
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
```

- [ ] **Step 4: Extend `Filter`, `Row`, and `Query` in `internal/audit/query.go`**

Replace the `Filter` struct:

```go
// Filter controls which injection rows are returned by Query.
type Filter struct {
	Since          time.Time // zero = no lower bound
	Host           string    // empty = any
	CredentialName string    // empty = any
	Limit          int       // 0 = default 100
	IncludeBlocked bool      // false = exclude blocked events
	IncludeSuspect bool      // false = exclude suspect (mismatch_suspected) events
	SuspectOnly    bool      // true = return only suspect rows (overrides IncludeSuspect/IncludeBlocked)
}
```

Replace the `Row` struct:

```go
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
	SuspectFlag    bool
	AuthSignal     string
}
```

Replace `Query` body:

```go
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

	switch {
	case f.SuspectOnly:
		clauses = append(clauses, "suspect_flag = 1")
	default:
		if !f.IncludeBlocked {
			clauses = append(clauses, "location != 'blocked'")
		}
		if !f.IncludeSuspect {
			clauses = append(clauses, "suspect_flag = 0")
		}
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
		var suspectInt int
		if err := rows.Scan(
			&r.ID, &tsMillis, &r.RequestID, &r.Host, &r.Method,
			&r.URLPath, &r.CredentialID, &r.CredentialName,
			&r.AgentPID, &r.AgentCmd, &r.BytesBefore, &r.BytesAfter,
			&r.Location, &suspectInt, &r.AuthSignal,
		); err != nil {
			return nil, err
		}
		r.Timestamp = time.UnixMilli(tsMillis).UTC()
		r.SuspectFlag = suspectInt != 0
		result = append(result, r)
	}
	return result, rows.Err()
}
```

And update `selectBase`:

```go
const selectBase = "SELECT id, ts, request_id, host, method, url_path, credential_id, credential_name, agent_pid, agent_cmd, bytes_before, bytes_after, location, suspect_flag, auth_signal FROM injections"
```

Keep `Summary` as-is for now; it ignores the new columns, which is correct (summary counts don't include suspect rows).

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/audit/ -v`
Expected: PASS. All existing tests (which don't set `SuspectFlag`) continue to work because the new columns default to zero/empty.

- [ ] **Step 6: Commit**

```bash
git add internal/audit/audit.go internal/audit/query.go internal/audit/audit_test.go
git commit -m "feat(audit): record and query transform-mismatch suspect rows"
```

---

## Task 6: Basic decoder — standalone unit

**Files:**
- Create: `internal/proxy/basic_decoder.go`
- Create: `internal/proxy/basic_decoder_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/proxy/basic_decoder_test.go`:

```go
package proxy

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/8enji/veil/internal/vault"
)

func basicHeader(user, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+secret))
}

func basicCred(name, user, userPH, secret, secretPH string, hosts ...string) *vault.Credential {
	return &vault.Credential{
		ID:                  "cred-" + name,
		Name:                name,
		Real:                secret,
		Placeholder:         secretPH,
		Username:            user,
		UsernamePlaceholder: userPH,
		AllowedHosts:        hosts,
	}
}

func TestDecodeBasic_HappyPath(t *testing.T) {
	c := basicCred("gh", "johndoe", "VEIL_USER_AAAA", "ghp_real", "VEIL_SECRET_BBBB", "github.com")
	pmap := map[string]*vault.Credential{
		c.Placeholder:         c,
		c.UsernamePlaceholder: c,
	}

	hdr := http.Header{}
	hdr.Set("Authorization", basicHeader("VEIL_USER_AAAA", "VEIL_SECRET_BBBB"))

	swaps := decodeAndSwapBasic(hdr, pmap, "github.com")

	if len(swaps) != 1 {
		t.Fatalf("expected 1 swap, got %d", len(swaps))
	}
	if swaps[0].CredentialName != "gh" {
		t.Errorf("swap name = %q", swaps[0].CredentialName)
	}
	if got := hdr.Get("Authorization"); got != basicHeader("johndoe", "ghp_real") {
		t.Errorf("Authorization = %q, want %q", got, basicHeader("johndoe", "ghp_real"))
	}
}

func TestDecodeBasic_ProxyAuthorization(t *testing.T) {
	c := basicCred("gh", "u", "VEIL_USER", "s", "VEIL_SECRET", "example.com")
	pmap := map[string]*vault.Credential{c.Placeholder: c, c.UsernamePlaceholder: c}

	hdr := http.Header{}
	hdr.Set("Proxy-Authorization", basicHeader("VEIL_USER", "VEIL_SECRET"))

	swaps := decodeAndSwapBasic(hdr, pmap, "example.com")
	if len(swaps) != 1 {
		t.Fatalf("expected 1 swap, got %d", len(swaps))
	}
	if got := hdr.Get("Proxy-Authorization"); got != basicHeader("u", "s") {
		t.Errorf("Proxy-Authorization = %q", got)
	}
}

func TestDecodeBasic_CaseInsensitiveScheme(t *testing.T) {
	c := basicCred("gh", "u", "VEIL_USER", "s", "VEIL_SECRET", "example.com")
	pmap := map[string]*vault.Credential{c.Placeholder: c, c.UsernamePlaceholder: c}

	raw := base64.StdEncoding.EncodeToString([]byte("VEIL_USER:VEIL_SECRET"))
	for _, prefix := range []string{"basic ", "BASIC ", "Basic "} {
		hdr := http.Header{}
		hdr.Set("Authorization", prefix+raw)
		swaps := decodeAndSwapBasic(hdr, pmap, "example.com")
		if len(swaps) != 1 {
			t.Errorf("prefix %q: expected 1 swap, got %d", prefix, len(swaps))
		}
	}
}

func TestDecodeBasic_NonBasicSchemeUntouched(t *testing.T) {
	c := basicCred("gh", "u", "VEIL_USER", "s", "VEIL_SECRET", "example.com")
	pmap := map[string]*vault.Credential{c.Placeholder: c, c.UsernamePlaceholder: c}

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer VEIL_SECRET")

	swaps := decodeAndSwapBasic(hdr, pmap, "example.com")
	if len(swaps) != 0 {
		t.Errorf("expected 0 swaps on Bearer header, got %d", len(swaps))
	}
	if got := hdr.Get("Authorization"); got != "Bearer VEIL_SECRET" {
		t.Errorf("Bearer header mutated: %q", got)
	}
}

func TestDecodeBasic_MalformedBase64(t *testing.T) {
	c := basicCred("gh", "u", "VEIL_USER", "s", "VEIL_SECRET", "example.com")
	pmap := map[string]*vault.Credential{c.Placeholder: c, c.UsernamePlaceholder: c}

	hdr := http.Header{}
	hdr.Set("Authorization", "Basic !!!not-base64!!!")

	swaps := decodeAndSwapBasic(hdr, pmap, "example.com")
	if len(swaps) != 0 {
		t.Errorf("expected 0 swaps on malformed base64, got %d", len(swaps))
	}
	if got := hdr.Get("Authorization"); got != "Basic !!!not-base64!!!" {
		t.Errorf("malformed header mutated: %q", got)
	}
}

func TestDecodeBasic_MissingColonInPayload(t *testing.T) {
	c := basicCred("gh", "u", "VEIL_USER", "s", "VEIL_SECRET", "example.com")
	pmap := map[string]*vault.Credential{c.Placeholder: c, c.UsernamePlaceholder: c}

	hdr := http.Header{}
	hdr.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("nocolon")))

	swaps := decodeAndSwapBasic(hdr, pmap, "example.com")
	if len(swaps) != 0 {
		t.Errorf("expected 0 swaps when payload has no colon, got %d", len(swaps))
	}
}

func TestDecodeBasic_CrossCredentialMixRejected(t *testing.T) {
	a := basicCred("a", "ua", "VEIL_USER_A", "sa", "VEIL_SECRET_A", "example.com")
	b := basicCred("b", "ub", "VEIL_USER_B", "sb", "VEIL_SECRET_B", "example.com")
	pmap := map[string]*vault.Credential{
		a.Placeholder: a, a.UsernamePlaceholder: a,
		b.Placeholder: b, b.UsernamePlaceholder: b,
	}

	hdr := http.Header{}
	hdr.Set("Authorization", basicHeader("VEIL_USER_A", "VEIL_SECRET_B"))

	swaps := decodeAndSwapBasic(hdr, pmap, "example.com")
	if len(swaps) != 0 {
		t.Errorf("expected 0 swaps on cross-credential mix, got %d", len(swaps))
	}
	if got := hdr.Get("Authorization"); got != basicHeader("VEIL_USER_A", "VEIL_SECRET_B") {
		t.Errorf("cross-mix header mutated: %q", got)
	}
}

func TestDecodeBasic_EmptyAuthorizationHeader(t *testing.T) {
	c := basicCred("gh", "u", "VEIL_USER", "s", "VEIL_SECRET", "example.com")
	pmap := map[string]*vault.Credential{c.Placeholder: c, c.UsernamePlaceholder: c}

	hdr := http.Header{}
	hdr.Set("Authorization", "")

	swaps := decodeAndSwapBasic(hdr, pmap, "example.com")
	if len(swaps) != 0 {
		t.Errorf("expected 0 swaps on empty Authorization, got %d", len(swaps))
	}
}

func TestDecodeBasic_HostNotAllowed(t *testing.T) {
	c := basicCred("gh", "u", "VEIL_USER", "s", "VEIL_SECRET", "github.com")
	pmap := map[string]*vault.Credential{c.Placeholder: c, c.UsernamePlaceholder: c}

	hdr := http.Header{}
	hdr.Set("Authorization", basicHeader("VEIL_USER", "VEIL_SECRET"))

	swaps := decodeAndSwapBasic(hdr, pmap, "evil.example.com")
	if len(swaps) != 0 {
		t.Errorf("expected 0 swaps when host not in AllowedHosts, got %d", len(swaps))
	}
	if got := hdr.Get("Authorization"); got != basicHeader("VEIL_USER", "VEIL_SECRET") {
		t.Errorf("header should not mutate when host disallowed: %q", got)
	}
}

func TestDecodeBasic_PlaceholderOnlyInSecretHalf(t *testing.T) {
	// Only the secret half matches; username half is an arbitrary string
	// that does not match any UsernamePlaceholder. This is a config error
	// (credential has a Username defined but request uses a different user).
	// Expected: no swap.
	c := basicCred("gh", "johndoe", "VEIL_USER_X", "ghp_real", "VEIL_SECRET_X", "example.com")
	pmap := map[string]*vault.Credential{c.Placeholder: c, c.UsernamePlaceholder: c}

	hdr := http.Header{}
	hdr.Set("Authorization", basicHeader("someone-else", "VEIL_SECRET_X"))

	swaps := decodeAndSwapBasic(hdr, pmap, "example.com")
	if len(swaps) != 0 {
		t.Errorf("expected 0 swaps when username half does not match, got %d", len(swaps))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestDecodeBasic -v`
Expected: compile failure — `decodeAndSwapBasic` not defined.

- [ ] **Step 3: Create `internal/proxy/basic_decoder.go`**

```go
package proxy

import (
	"encoding/base64"
	"strings"
	"time"

	"github.com/8enji/veil/internal/audit"
	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/vault"
)

// basicSchemes lists the header names that carry HTTP Basic credentials.
// Values are canonical header names as produced by http.Header.Set.
var basicSchemes = []string{"Authorization", "Proxy-Authorization"}

// decodeAndSwapBasic looks for "Basic <base64(user:secret)>" in Authorization
// and Proxy-Authorization headers, and if both halves map to the same vault
// credential whose AllowedHosts covers host, rewrites the header with the real
// user:secret pair and returns an audit.Injection record per swap. The header
// values are mutated in place.
//
// On any mismatch, malformed encoding, cross-credential mix, or disallowed
// host, the header is left untouched and no injection is returned — the
// mismatch detector will observe injection==0 and emit a warning.
func decodeAndSwapBasic(hdr map[string][]string, pmap map[string]*vault.Credential, host string) []audit.Injection {
	var out []audit.Injection
	now := time.Now()

	for _, name := range basicSchemes {
		values := hdr[name]
		for i, v := range values {
			cred, newValue, ok := tryRewriteBasic(v, pmap, host)
			if !ok {
				continue
			}
			before := len(v)
			values[i] = newValue
			after := len(newValue)
			out = append(out, audit.Injection{
				Timestamp:      now,
				Host:           host,
				CredentialID:   cred.ID,
				CredentialName: cred.Name,
				BytesBefore:    before,
				BytesAfter:     after,
				Location:       "header",
			})
		}
		if len(values) > 0 {
			hdr[name] = values
		}
	}
	return out
}

// tryRewriteBasic parses one header value. Returns (credential, new-value, true)
// when a swap should be performed; (nil, "", false) otherwise.
func tryRewriteBasic(value string, pmap map[string]*vault.Credential, host string) (*vault.Credential, string, bool) {
	if value == "" {
		return nil, "", false
	}
	// Scheme prefix is case-insensitive. Require a trailing space.
	const schemeLen = len("Basic ")
	if len(value) <= schemeLen {
		return nil, "", false
	}
	if !strings.EqualFold(value[:schemeLen], "Basic ") {
		return nil, "", false
	}
	encoded := strings.TrimSpace(value[schemeLen:])
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// RFC 7617 specifies standard base64; try URL-safe as a fallback for
		// robustness with quirky clients.
		raw, err = base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, "", false
		}
	}
	userPart, secretPart, found := strings.Cut(string(raw), ":")
	if !found {
		return nil, "", false
	}

	secretCred, secretOK := pmap[secretPart]
	userCred, userOK := pmap[userPart]
	if !secretOK || !userOK {
		return nil, "", false
	}
	// Both halves must belong to the same credential record.
	if secretCred != userCred {
		return nil, "", false
	}
	cred := secretCred
	// Sanity check: the matched credential must have a Username (i.e., be a
	// Basic credential). A Bearer credential accidentally matched via its
	// Placeholder in both halves would get caught here.
	if cred.Username == "" || cred.UsernamePlaceholder == "" {
		return nil, "", false
	}
	// The halves must map to the expected roles.
	if secretPart != cred.Placeholder || userPart != cred.UsernamePlaceholder {
		return nil, "", false
	}
	// Host scoping.
	if !placeholder.HostMatches(host, cred.AllowedHosts) {
		return nil, "", false
	}

	newPayload := cred.Username + ":" + cred.Real
	newEncoded := base64.StdEncoding.EncodeToString([]byte(newPayload))
	return cred, "Basic " + newEncoded, true
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/ -run TestDecodeBasic -v`
Expected: PASS for all 10 `TestDecodeBasic_*` subtests.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/basic_decoder.go internal/proxy/basic_decoder_test.go
git commit -m "feat(proxy): add HTTP Basic auth decoder for placeholder swap"
```

---

## Task 7: Integrate Basic decoder into ProcessRequest

**Files:**
- Modify: `internal/proxy/injector.go` (`ProcessRequest`)
- Test: `internal/proxy/injector_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/proxy/injector_test.go`:

```go
func TestProcessRequestBasicAuthEndToEnd(t *testing.T) {
	cred := &vault.Credential{
		ID: "c1", Name: "gh-basic",
		Real:                "ghp_real",
		Placeholder:         "VEIL_SECRET_ZZZ",
		Username:            "johndoe",
		UsernamePlaceholder: "VEIL_USER_ZZZ",
		AllowedHosts:        []string{"api.github.com"},
	}
	pmap := map[string]*vault.Credential{
		cred.Placeholder:         cred,
		cred.UsernamePlaceholder: cred,
	}
	inj := NewInjector(pmap, nil, 1, "agent")

	hdr := http.Header{}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("VEIL_USER_ZZZ:VEIL_SECRET_ZZZ"))
	hdr.Set("Authorization", basic)

	_, newHeader, _, injections := inj.ProcessRequest(
		"req-basic-1", "GET", "https://api.github.com/user", hdr, nil)

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("johndoe:ghp_real"))
	if got := newHeader.Get("Authorization"); got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
	if len(injections) != 1 {
		t.Fatalf("expected 1 injection, got %d", len(injections))
	}
	if injections[0].CredentialName != "gh-basic" {
		t.Errorf("CredentialName = %q", injections[0].CredentialName)
	}
	if injections[0].Location != "header" {
		t.Errorf("Location = %q", injections[0].Location)
	}
}

func TestProcessRequestBasicDoesNotInterfereWithBearer(t *testing.T) {
	bearer := makeCred("bearer-tok", "VEIL_BEARER_XXXX", "Bearer real-token", "api.example.com")
	basic := &vault.Credential{
		ID: "c2", Name: "basic-cred",
		Real:                "secret",
		Placeholder:         "VEIL_SECRET_YYYY",
		Username:            "user",
		UsernamePlaceholder: "VEIL_USER_YYYY",
		AllowedHosts:        []string{"api.example.com"},
	}
	inj := NewInjector(placeholderMap(bearer, basic), nil, 1, "agent")

	hdr := http.Header{}
	hdr.Set("X-Custom", "VEIL_BEARER_XXXX")
	_, newHeader, _, injections := inj.ProcessRequest(
		"req-mixed", "GET", "https://api.example.com/v1", hdr, nil)

	if got := newHeader.Get("X-Custom"); got != "Bearer real-token" {
		t.Errorf("Bearer placeholder not replaced in non-Basic header: %q", got)
	}
	if len(injections) != 1 {
		t.Fatalf("expected 1 injection, got %d", len(injections))
	}
}
```

Add `"encoding/base64"` to imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestProcessRequestBasicAuthEndToEnd -v`
Expected: FAIL — Authorization header is not rewritten (the literal matcher would swap VEIL_USER_ZZZ and VEIL_SECRET_ZZZ individually inside the base64 blob, which produces garbage bytes rather than a valid rewrite).

- [ ] **Step 3: Wire decoder into `ProcessRequest` in `internal/proxy/injector.go`**

In `ProcessRequest`, after `newHeader = header.Clone()` but before the existing header-scanning loop, add:

```go
	// --- Basic auth pre-pass ---
	// Decode Authorization / Proxy-Authorization Basic headers and rewrite them
	// with real user:secret pairs before the literal Aho-Corasick scan sees the
	// (already-rewritten) bytes. Swaps produced here participate in the same
	// audit-injection stream as literal matches.
	basicSwaps := decodeAndSwapBasic(newHeader, creds, host)
	for _, s := range basicSwaps {
		s.RequestID = requestID
		s.Method = method
		s.URLPath = urlPath
		s.AgentPID = inj.agentPID
		s.AgentCmd = inj.agentCmd
		injections = append(injections, s)
	}
```

`decodeAndSwapBasic` fills `Timestamp`, `Host`, `CredentialID`, `CredentialName`, `BytesBefore`, `BytesAfter`, `Location`. The loop above fills the request-scoped fields the decoder does not know.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/ -v`
Expected: all tests pass, including the two new ones and the 10 existing decoder tests and all pre-existing injector tests.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/injector.go internal/proxy/injector_test.go
git commit -m "feat(proxy): run Basic auth decoder before literal scan in ProcessRequest"
```

---

## Task 8: Mismatch detector — standalone unit

**Files:**
- Create: `internal/proxy/mismatch_detector.go`
- Create: `internal/proxy/mismatch_detector_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/proxy/mismatch_detector_test.go`:

```go
package proxy

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/8enji/veil/internal/vault"
)

func detectorCred(name string, hosts ...string) *vault.Credential {
	return &vault.Credential{
		ID: "c-" + name, Name: name,
		Real: "r", Placeholder: "VEIL_PH_" + name,
		AllowedHosts: hosts,
	}
}

func buildURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return u
}

func TestDetector_FiresOnAuthorizationHeader(t *testing.T) {
	creds := []*vault.Credential{detectorCred("gh", "api.github.com")}
	u := buildURL(t, "https://api.github.com/user")
	hdr := http.Header{}
	hdr.Set("Authorization", "Basic something")

	sig, cNames, fired := detectMismatch("api.github.com", u, hdr, 0, creds)
	if !fired {
		t.Fatal("detector did not fire")
	}
	if sig != authSignalAuthorizationHeader {
		t.Errorf("signal = %q", sig)
	}
	if len(cNames) != 1 || cNames[0] != "gh" {
		t.Errorf("candidate names = %v", cNames)
	}
}

func TestDetector_FiresOnCookie(t *testing.T) {
	creds := []*vault.Credential{detectorCred("api", "api.example.com")}
	u := buildURL(t, "https://api.example.com/x")
	hdr := http.Header{}
	hdr.Set("Cookie", "session=abc")

	sig, _, fired := detectMismatch("api.example.com", u, hdr, 0, creds)
	if !fired {
		t.Fatal("detector did not fire")
	}
	if sig != authSignalCookie {
		t.Errorf("signal = %q", sig)
	}
}

func TestDetector_FiresOnXTokenHeader(t *testing.T) {
	creds := []*vault.Credential{detectorCred("api", "api.example.com")}
	u := buildURL(t, "https://api.example.com/x")
	for _, name := range []string{"X-Api-Token", "X-Foo-Key", "X-Custom-Signature", "X-Auth", "x-API-SIG"} {
		hdr := http.Header{}
		hdr.Set(name, "v")
		_, _, fired := detectMismatch("api.example.com", u, hdr, 0, creds)
		if !fired {
			t.Errorf("expected detector to fire for header %q", name)
		}
	}
}

func TestDetector_FiresOnAuthQueryParam(t *testing.T) {
	creds := []*vault.Credential{detectorCred("api", "api.example.com")}
	for _, q := range []string{"auth=x", "signature=x", "sig=x", "token=x", "api_key=x", "apikey=x", "access_token=x"} {
		u := buildURL(t, "https://api.example.com/x?"+q)
		_, _, fired := detectMismatch("api.example.com", u, http.Header{}, 0, creds)
		if !fired {
			t.Errorf("expected detector to fire for query %q", q)
		}
	}
}

func TestDetector_DoesNotFireWhenHostNotMatched(t *testing.T) {
	creds := []*vault.Credential{detectorCred("gh", "api.github.com")}
	u := buildURL(t, "https://api.openai.com/v1")
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer x")

	_, _, fired := detectMismatch("api.openai.com", u, hdr, 0, creds)
	if fired {
		t.Error("detector fired for non-credentialed host")
	}
}

func TestDetector_DoesNotFireWhenInjected(t *testing.T) {
	creds := []*vault.Credential{detectorCred("gh", "api.github.com")}
	u := buildURL(t, "https://api.github.com/")
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer x")

	_, _, fired := detectMismatch("api.github.com", u, hdr, 1, creds)
	if fired {
		t.Error("detector fired despite injectionCount>0")
	}
}

func TestDetector_DoesNotFireWithoutAuthSignal(t *testing.T) {
	creds := []*vault.Credential{detectorCred("gh", "api.github.com")}
	u := buildURL(t, "https://api.github.com/zen")
	_, _, fired := detectMismatch("api.github.com", u, http.Header{}, 0, creds)
	if fired {
		t.Error("detector fired with no auth-shaped signal")
	}
}

func TestDetector_HostWithPortMatches(t *testing.T) {
	creds := []*vault.Credential{detectorCred("gh", "api.github.com")}
	u := buildURL(t, "https://api.github.com:443/")
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer x")

	_, _, fired := detectMismatch("api.github.com:443", u, hdr, 0, creds)
	if !fired {
		t.Error("detector should match host:port against AllowedHosts")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestDetector -v`
Expected: compile failure — `detectMismatch`, `authSignalAuthorizationHeader`, `authSignalCookie` undefined.

- [ ] **Step 3: Create `internal/proxy/mismatch_detector.go`**

```go
package proxy

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/vault"
)

// Auth-signal identifiers persisted in audit rows and log fields.
const (
	authSignalAuthorizationHeader      = "authorization_header"
	authSignalProxyAuthorizationHeader = "proxy_authorization_header"
	authSignalCookie                   = "cookie"
	authSignalXCustomHeader            = "x_custom_header"
	authSignalQueryParam               = "query_param"
)

// xTokenHeaderRE matches header names of the form X-*-{token,auth,key,sig,signature}.
// The regex is case-insensitive; http.Header canonicalizes names to title case
// but client code that bypasses canonicalization (e.g., direct map writes) may
// produce mixed-case names.
var xTokenHeaderRE = regexp.MustCompile(`(?i)^x-.*-(token|auth|key|sig|signature)$|^x-(auth|token|apikey|api-key)$`)

// authQueryParams lists query parameter names that signal request-carried auth.
var authQueryParams = map[string]struct{}{
	"auth":         {},
	"signature":    {},
	"sig":          {},
	"token":        {},
	"api_key":      {},
	"apikey":       {},
	"access_token": {},
}

// detectMismatch returns (authSignal, candidateCredentialNames, fired).
// fired is true iff host matches some credential's AllowedHosts, injectionCount==0,
// and the request carries an auth-shaped signal. candidateCredentialNames is the
// set of credentials whose AllowedHosts covered host (useful for the log line;
// never the placeholder or secret values).
func detectMismatch(host string, u *url.URL, hdr http.Header, injectionCount int, creds []*vault.Credential) (string, []string, bool) {
	if injectionCount > 0 {
		return "", nil, false
	}

	var candidates []string
	for _, c := range creds {
		if placeholder.HostMatches(host, c.AllowedHosts) {
			candidates = append(candidates, c.Name)
		}
	}
	if len(candidates) == 0 {
		return "", nil, false
	}

	if v := hdr.Get("Authorization"); v != "" {
		return authSignalAuthorizationHeader, candidates, true
	}
	if v := hdr.Get("Proxy-Authorization"); v != "" {
		return authSignalProxyAuthorizationHeader, candidates, true
	}
	if v := hdr.Get("Cookie"); v != "" {
		return authSignalCookie, candidates, true
	}
	for name := range hdr {
		if xTokenHeaderRE.MatchString(strings.ToLower(name)) {
			return authSignalXCustomHeader, candidates, true
		}
	}
	if u != nil {
		q := u.Query()
		for k := range q {
			if _, ok := authQueryParams[strings.ToLower(k)]; ok {
				return authSignalQueryParam, candidates, true
			}
		}
	}
	return "", nil, false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/ -run TestDetector -v`
Expected: PASS for all 8 detector subtests.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/mismatch_detector.go internal/proxy/mismatch_detector_test.go
git commit -m "feat(proxy): add transform-mismatch detector"
```

---

## Task 9: Integrate detector into ProcessRequest

**Files:**
- Modify: `internal/proxy/injector.go` (`ProcessRequest`, `NewInjector` if needed)
- Test: `internal/proxy/injector_test.go`

**Rationale:** Detector needs access to the full credential list (not just the placeholder map) to test host membership. We extend `NewInjector` / `Reload` to store the list; alternatively derive it from the map values. Using map values is simpler — deduplicate by pointer identity.

- [ ] **Step 1: Write the failing test**

Add to `internal/proxy/injector_test.go`:

```go
func TestProcessRequestDetectorFires(t *testing.T) {
	dir := t.TempDir()
	store, err := audit.Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	cred := makeCred("gh", "VEIL_BEARER_AAAA", "ghp-real", "api.github.com")
	inj := NewInjector(placeholderMap(cred), store, 1, "agent")

	hdr := http.Header{}
	// Credential is scoped to api.github.com, but the placeholder used on the
	// wire doesn't match anything in the vault -- detector should fire.
	hdr.Set("Authorization", "Bearer some-other-token")

	_, _, _, injections := inj.ProcessRequest(
		"req-detect-1", "GET", "https://api.github.com/user", hdr, nil)

	var suspect []audit.Injection
	for _, i := range injections {
		if i.SuspectFlag {
			suspect = append(suspect, i)
		}
	}
	if len(suspect) != 1 {
		t.Fatalf("expected 1 suspect injection, got %d (all: %+v)", len(suspect), injections)
	}
	if suspect[0].Location != "mismatch_suspected" {
		t.Errorf("Location = %q", suspect[0].Location)
	}
	if suspect[0].AuthSignal != "authorization_header" {
		t.Errorf("AuthSignal = %q", suspect[0].AuthSignal)
	}
	if suspect[0].Host != "api.github.com" {
		t.Errorf("Host = %q", suspect[0].Host)
	}
	if suspect[0].CredentialName != "" || suspect[0].CredentialID != "" {
		t.Error("suspect row should carry no credential id/name")
	}
	if suspect[0].RequestID != "req-detect-1" {
		t.Errorf("RequestID = %q", suspect[0].RequestID)
	}
}

func TestProcessRequestDetectorSilentOnSuccessfulInjection(t *testing.T) {
	cred := makeCred("gh", "VEIL_PH_SUCC", "ghp-real", "api.github.com")
	inj := NewInjector(placeholderMap(cred), nil, 1, "agent")

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer VEIL_PH_SUCC")

	_, _, _, injections := inj.ProcessRequest(
		"req-succ", "GET", "https://api.github.com/user", hdr, nil)

	for _, i := range injections {
		if i.SuspectFlag {
			t.Errorf("detector fired despite successful injection: %+v", i)
		}
	}
}

func TestProcessRequestDetectorSilentOnUncredentialedHost(t *testing.T) {
	cred := makeCred("gh", "VEIL_PH_UNCRED", "ghp-real", "api.github.com")
	inj := NewInjector(placeholderMap(cred), nil, 1, "agent")

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer some-token")

	_, _, _, injections := inj.ProcessRequest(
		"req-uncred", "GET", "https://api.openai.com/v1", hdr, nil)

	for _, i := range injections {
		if i.SuspectFlag {
			t.Errorf("detector fired on uncredentialed host: %+v", i)
		}
	}
}
```

Add imports `"path/filepath"` if missing.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestProcessRequestDetector -v`
Expected: FAIL — detector is not called from ProcessRequest; no suspect injections returned.

- [ ] **Step 3: Wire detector into `ProcessRequest`**

In `internal/proxy/injector.go`, update `ProcessRequest`. After the existing body-scanning block and **before** `if inj.audit != nil` audit-record loop, add:

```go
	// --- Mismatch detector (post-pass) ---
	if len(injections) == 0 || !anyNonBlocked(injections) {
		// Reconstruct candidate credential list from the (deduplicated) map.
		credList := dedupCredentials(creds)
		parsedURL, _ := url.Parse(rawURL)
		if sig, _, fired := detectMismatch(host, parsedURL, newHeader, nonBlockedCount(injections), credList); fired {
			injections = append(injections, audit.Injection{
				Timestamp:   now,
				RequestID:   requestID,
				Host:        host,
				Method:      method,
				URLPath:     urlPath,
				AgentPID:    inj.agentPID,
				AgentCmd:    inj.agentCmd,
				Location:    "mismatch_suspected",
				SuspectFlag: true,
				AuthSignal:  sig,
			})
		}
	}
```

Add helpers near the bottom of `injector.go`:

```go
// anyNonBlocked reports whether at least one injection is a real swap (not a
// blocked entry emitted when host scoping denied the swap).
func anyNonBlocked(injections []audit.Injection) bool {
	for _, i := range injections {
		if i.Location != "blocked" && !i.SuspectFlag {
			return true
		}
	}
	return false
}

// nonBlockedCount returns the number of injections that performed an actual swap.
func nonBlockedCount(injections []audit.Injection) int {
	n := 0
	for _, i := range injections {
		if i.Location != "blocked" && !i.SuspectFlag {
			n++
		}
	}
	return n
}

// dedupCredentials returns a slice of unique credentials from the placeholder
// map. Basic credentials appear twice in the map (under secret and username
// placeholders); this collapses them to one entry per credential pointer.
func dedupCredentials(pmap map[string]*vault.Credential) []*vault.Credential {
	seen := make(map[*vault.Credential]struct{}, len(pmap))
	out := make([]*vault.Credential, 0, len(pmap))
	for _, c := range pmap {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/ -v`
Expected: PASS. Including the three new detector-integration tests.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/injector.go internal/proxy/injector_test.go
git commit -m "feat(proxy): record suspect audit rows when detector fires"
```

---

## Task 10: Emit WARN log line when detector fires

**Files:**
- Modify: `internal/proxy/injector.go` (detector wiring adds a logger call)
- Modify: `internal/proxy/mismatch_detector.go` (add logging helper that takes a logger)

**Rationale:** The spec requires a structured WARN log in addition to the audit row. Check which logger the injector already uses; if none, use `log.Printf` with a well-known prefix so downstream log aggregation can parse it.

- [ ] **Step 1: Check existing logging patterns**

Run: `grep -rn "log\.\(Print\|Warn\|Info\)" internal/proxy/ internal/runner/ internal/cli/ | head -20`

If the codebase uses `log/slog` or a custom logger, adopt that. If it uses plain `log.Printf`, use that. Pick the style already present.

For the rest of this task, assume the codebase uses plain `log.Printf`. If instead you find `slog` or a custom logger, replace the `log.Printf` call below with the equivalent WARN-level call in that style, and adjust imports.

- [ ] **Step 2: Write the failing test**

Add to `internal/proxy/mismatch_detector_test.go`:

```go
func TestDetectorLogLine(t *testing.T) {
	var buf bytes.Buffer
	origOutput := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(origOutput)
		log.SetFlags(origFlags)
	})

	logMismatch("api.github.com", "/user", "GET", authSignalAuthorizationHeader, []string{"gh"})

	out := buf.String()
	if !strings.Contains(out, "event=transform_mismatch_suspected") {
		t.Errorf("missing event= field: %q", out)
	}
	if !strings.Contains(out, "host=api.github.com") {
		t.Errorf("missing host field: %q", out)
	}
	if !strings.Contains(out, "auth_signal=authorization_header") {
		t.Errorf("missing auth_signal: %q", out)
	}
	if !strings.Contains(out, "credentials=gh") {
		t.Errorf("missing credentials list: %q", out)
	}
	if strings.Contains(strings.ToLower(out), "veil_") {
		t.Error("log line leaked a VEIL_ placeholder token")
	}
	if strings.Contains(strings.ToLower(out), "bearer") {
		t.Error("log line leaked header value")
	}
}
```

Add imports `"bytes"`, `"log"`, `"strings"`.

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestDetectorLogLine -v`
Expected: compile failure — `logMismatch` not defined.

- [ ] **Step 4: Add `logMismatch` in `internal/proxy/mismatch_detector.go`**

Append:

```go
// logMismatch emits a structured WARN-level log line. It never includes
// header values, secrets, or placeholder strings — only coarse-grained
// routing signals.
func logMismatch(host, urlPath, method, authSignal string, credentialNames []string) {
	log.Printf("WARN event=transform_mismatch_suspected host=%s method=%s path=%s auth_signal=%s credentials=%s",
		host, method, urlPath, authSignal, strings.Join(credentialNames, ","))
}
```

Add `"log"` to imports.

- [ ] **Step 5: Wire it into `ProcessRequest`**

In `internal/proxy/injector.go`, change the `if sig, _, fired := detectMismatch(...)` block to capture the candidate names and call `logMismatch`:

```go
		if sig, names, fired := detectMismatch(host, parsedURL, newHeader, nonBlockedCount(injections), credList); fired {
			logMismatch(host, urlPath, method, sig, names)
			injections = append(injections, audit.Injection{
				Timestamp:   now,
				RequestID:   requestID,
				Host:        host,
				Method:      method,
				URLPath:     urlPath,
				AgentPID:    inj.agentPID,
				AgentCmd:    inj.agentCmd,
				Location:    "mismatch_suspected",
				SuspectFlag: true,
				AuthSignal:  sig,
			})
		}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/proxy/ -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/proxy/injector.go internal/proxy/mismatch_detector.go internal/proxy/mismatch_detector_test.go
git commit -m "feat(proxy): emit WARN log line when transform mismatch is suspected"
```

---

## Task 11: CLI — `veil add --user` flag

**Files:**
- Modify: `internal/cli/add.go`
- Test: `internal/cli/cli_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/cli/cli_test.go` (follow the pattern of existing `TestAdd*` tests; adapt to the helper that creates a temporary vault root):

```go
func TestAddWithUserFlag(t *testing.T) {
	root := newTestRoot(t) // or whatever helper exists in this file
	runCLI(t, root, "init")

	out, err := runCLI(t, root, "add", "github-pat",
		"--user", "johndoe",
		"--host", "github.com",
		"--value", "ghp_realtoken",
	)
	if err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	if !strings.Contains(out, "User placeholder:") {
		t.Errorf("output missing user placeholder line:\n%s", out)
	}
	if !strings.Contains(out, "Secret placeholder:") {
		t.Errorf("output missing secret placeholder line:\n%s", out)
	}

	v, err := vault.Open(root, ...) // use existing test vault-open helper
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	c, ok := v.Get("github-pat")
	if !ok {
		t.Fatal("credential not stored")
	}
	if c.Username != "johndoe" {
		t.Errorf("Username = %q", c.Username)
	}
	if c.UsernamePlaceholder == "" {
		t.Error("UsernamePlaceholder not set")
	}
	if c.UsernamePlaceholder == c.Placeholder {
		t.Error("UsernamePlaceholder collided with Placeholder")
	}
}

func TestAddRejectsEmptyUser(t *testing.T) {
	root := newTestRoot(t)
	runCLI(t, root, "init")
	_, err := runCLI(t, root, "add", "x", "--user", "", "--host", "x.test", "--value", "v")
	if err == nil {
		t.Error("expected error for empty --user")
	}
}

func TestAddRejectsUserWithColon(t *testing.T) {
	root := newTestRoot(t)
	runCLI(t, root, "init")
	_, err := runCLI(t, root, "add", "x", "--user", "bad:user", "--host", "x.test", "--value", "v")
	if err == nil {
		t.Error("expected error for colon in --user")
	}
}
```

The exact helpers (`newTestRoot`, `runCLI`, `vault.Open`) must match existing patterns in `cli_test.go`. Read the top of that file first and mirror the style. If the existing tests use a different assertion pattern, adapt.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/ -run TestAdd -v`
Expected: FAIL — `--user` flag not recognised.

- [ ] **Step 3: Update `addCmd` and `runAdd` in `internal/cli/add.go`**

In `addCmd()`, add:

```go
	var username string
	// ...existing flags...
	cmd.Flags().StringVar(&username, "user", "", "username for HTTP Basic credentials")
```

Change the `RunE` call:

```go
			return runAdd(cmd, args[0], force, hosts, value, username)
		},
```

Change `runAdd` signature and body to validate and generate:

```go
func runAdd(cmd *cobra.Command, name string, force bool, hosts []string, flagValue, username string) error {
	root, err := resolveRoot()
	if err != nil {
		return cliError(err.Error(), "")
	}

	v, err := openVault(root)
	if err != nil {
		return cliError(fmt.Sprintf("opening vault: %v", err), "")
	}

	// Read secret value.
	var value string
	if flagValue != "" {
		value = flagValue
	} else {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Enter value for %s: ", name)
		reader := bufio.NewReader(cmd.InOrStdin())
		raw, err := reader.ReadString('\n')
		if err != nil {
			if raw == "" {
				return cliError("no value provided", "")
			}
		}
		value = strings.TrimRight(raw, "\r\n")
	}
	if value == "" {
		return cliError("no value provided", "")
	}

	// Validate username.
	isBasic := username != ""
	if isBasic {
		if strings.Contains(username, ":") {
			return cliError("username cannot contain ':' (RFC 7617)", "")
		}
	}

	// Generate secret placeholder.
	ph, err := placeholder.Generate(name, value, v.PlaceholderSet())
	if err != nil {
		return cliError(fmt.Sprintf("generating placeholder: %v", err), "")
	}

	// Generate username placeholder with collision-checking set including
	// the freshly-generated secret placeholder.
	var usernamePH string
	if isBasic {
		existing := v.PlaceholderSet()
		existing[ph] = struct{}{}
		usernamePH, err = placeholder.Generate(name+"_USER", username, existing)
		if err != nil {
			return cliError(fmt.Sprintf("generating username placeholder: %v", err), "")
		}
	}

	// Resolve allowed hosts.
	allowedHosts := hosts
	if len(allowedHosts) == 0 {
		allowedHosts = placeholder.HostsForCredential(name, value)
	}

	// Handle --force.
	var oldPlaceholder, oldUsernamePlaceholder string
	if force {
		if existing, found := v.Get(name); found {
			oldPlaceholder = existing.Placeholder
			oldUsernamePlaceholder = existing.UsernamePlaceholder
		}
		_, _ = v.Delete(name)
	}

	cred := &vault.Credential{
		ID:                  vault.NewID(),
		Name:                name,
		Real:                value,
		Placeholder:         ph,
		Source:              "manual",
		AllowedHosts:        allowedHosts,
		Username:            username,
		UsernamePlaceholder: usernamePH,
		CreatedAt:           time.Now(),
	}
	if err := v.Add(cred); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return cliError(fmt.Sprintf("credential %q already exists", name), "Use --force to overwrite")
		}
		return cliError(fmt.Sprintf("adding credential: %v", err), "")
	}

	w := cmd.OutOrStdout()

	// .env sync for --force: secret placeholder first, then username placeholder.
	if oldPlaceholder != "" && oldPlaceholder != cred.Placeholder {
		updated := syncPlaceholderInEnvFiles(root, oldPlaceholder, cred.Placeholder)
		if updated > 0 {
			ui.Step(w, fmt.Sprintf("Updated secret placeholder in %d .env %s", updated, plural(updated, "file", "files")))
		}
	}
	if oldUsernamePlaceholder != "" && oldUsernamePlaceholder != cred.UsernamePlaceholder {
		updated := syncPlaceholderInEnvFiles(root, oldUsernamePlaceholder, cred.UsernamePlaceholder)
		if updated > 0 {
			ui.Step(w, fmt.Sprintf("Updated user placeholder in %d .env %s", updated, plural(updated, "file", "files")))
		}
	}

	if isBasic {
		ui.Step(w, fmt.Sprintf("Added %s to vault (basic auth)", name))
		_, _ = fmt.Fprintf(w, "    %s %s\n", ui.Muted.Sprint("User placeholder:  "), cred.UsernamePlaceholder)
		_, _ = fmt.Fprintf(w, "    %s %s\n", ui.Muted.Sprint("Secret placeholder:"), cred.Placeholder)
	} else {
		ui.Step(w, fmt.Sprintf("Added %s to vault", name))
		_, _ = fmt.Fprintf(w, "    %s %s\n", ui.Muted.Sprint("Placeholder:"), cred.Placeholder)
	}
	if len(allowedHosts) > 0 {
		_, _ = fmt.Fprintf(w, "    %s %s\n", ui.Muted.Sprint("Hosts:"), strings.Join(allowedHosts, ", "))
	} else {
		ui.Warn(w, fmt.Sprintf("No target hosts detected for %s", name))
		_, _ = fmt.Fprintf(w, "    %s\n", ui.Muted.Sprint("Use veil add --host to scope it"))
	}

	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cli/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/add.go internal/cli/cli_test.go
git commit -m "feat(cli): add --user flag to veil add for HTTP Basic credentials"
```

---

## Task 12: CLI — `veil list` shows `(basic)` tag

**Files:**
- Modify: `internal/cli/list.go`
- Test: `internal/cli/cli_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/cli/cli_test.go`:

```go
func TestListShowsBasicTag(t *testing.T) {
	root := newTestRoot(t)
	runCLI(t, root, "init")
	runCLI(t, root, "add", "gh-basic",
		"--user", "johndoe", "--host", "github.com", "--value", "ghp_real")
	runCLI(t, root, "add", "oa-bearer",
		"--host", "api.openai.com", "--value", "sk-abc")

	out, err := runCLI(t, root, "list")
	if err != nil {
		t.Fatalf("list: %v\n%s", err, out)
	}
	// Basic credential row should carry the tag; bearer row should not.
	lines := strings.Split(out, "\n")
	var basicLine, bearerLine string
	for _, ln := range lines {
		if strings.Contains(ln, "gh-basic") {
			basicLine = ln
		}
		if strings.Contains(ln, "oa-bearer") {
			bearerLine = ln
		}
	}
	if !strings.Contains(basicLine, "(basic)") {
		t.Errorf("basic row missing (basic) tag: %q", basicLine)
	}
	if strings.Contains(bearerLine, "(basic)") {
		t.Errorf("bearer row incorrectly shows (basic): %q", bearerLine)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/ -run TestListShowsBasicTag -v`
Expected: FAIL — no `(basic)` substring in output.

- [ ] **Step 3: Update `runList` in `internal/cli/list.go`**

In the `row` struct definition and population loop, change:

```go
	type row struct {
		name, hosts, value, placeholder, source, last string
	}
	rows := make([]row, len(creds))
	for i, c := range creds {
		displayName := c.Name
		if c.Username != "" {
			displayName = c.Name + " " + ui.Muted.Sprint("(basic)")
		}
		r := row{name: displayName, source: c.Source, last: "never"}
		// ...rest unchanged...
```

Then update the column-width calculation so styling doesn't corrupt alignment. Since `ui.Muted.Sprint("(basic)")` contains ANSI codes, the plain-length check `len(r.name)` over-counts. Use a helper that strips ANSI, or store the plain name separately:

```go
	type row struct {
		name, nameStyled, hosts, value, placeholder, source, last string
	}
	rows := make([]row, len(creds))
	for i, c := range creds {
		r := row{name: c.Name, nameStyled: c.Name, source: c.Source, last: "never"}
		if c.Username != "" {
			r.name = c.Name + " (basic)"
			r.nameStyled = c.Name + " " + ui.Muted.Sprint("(basic)")
		}
		// ...continue as before, using r.name for width calc and r.nameStyled for printing...
```

Update the three printing branches (reveal / showPlaceholder / default) to use `padRight(r.nameStyled, nameW + ansiPadding(r))` — or, simpler, pad the plain `r.name` first, then substitute the styled version into the output without width adjustment. Most readable approach: pad based on plain `r.name`, but when printing emit `r.nameStyled + padding`:

```go
	// Compute widths from plain names.
	nameW := len("NAME")
	for _, r := range rows {
		nameW = maxInt(nameW, len(r.name))
	}

	// When printing, emit the styled name and pad with the width difference.
	emitName := func(r row) string {
		pad := nameW - len(r.name)
		if pad < 0 {
			pad = 0
		}
		return r.nameStyled + strings.Repeat(" ", pad)
	}
```

Replace `padRight(r.name, nameW)` in the three output branches with `emitName(r)`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cli/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/list.go internal/cli/cli_test.go
git commit -m "feat(cli): tag Basic credentials with (basic) in veil list"
```

---

## Task 13: CLI — `veil log` surfaces suspect rows

**Files:**
- Modify: `internal/cli/log.go`
- Test: `internal/cli/cli_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/cli/cli_test.go`:

```go
func TestLogShowsSuspectMarker(t *testing.T) {
	root := newTestRoot(t)
	runCLI(t, root, "init")

	// Insert a suspect row directly into the audit DB.
	dbPath := config.AuditDBFile(root)
	store, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("audit open: %v", err)
	}
	store.Record(audit.Injection{
		Timestamp:   time.Now(),
		RequestID:   "req-susp-1",
		Host:        "api.example.com",
		Method:      "GET",
		URLPath:     "/x",
		Location:    "mismatch_suspected",
		SuspectFlag: true,
		AuthSignal:  "authorization_header",
	})
	_ = store.Close()

	// Default output includes suspect rows tagged with [!].
	out, err := runCLI(t, root, "log")
	if err != nil {
		t.Fatalf("log: %v\n%s", err, out)
	}
	if !strings.Contains(out, "[!]") {
		t.Errorf("log output missing [!] marker:\n%s", out)
	}

	// --suspect filter returns only suspect rows.
	out2, err := runCLI(t, root, "log", "--suspect")
	if err != nil {
		t.Fatalf("log --suspect: %v\n%s", err, out2)
	}
	if !strings.Contains(out2, "req-susp-1") && !strings.Contains(out2, "api.example.com") {
		t.Errorf("--suspect output missing host:\n%s", out2)
	}

	// --json output includes suspect_flag field.
	out3, err := runCLI(t, root, "log", "--json")
	if err != nil {
		t.Fatalf("log --json: %v\n%s", err, out3)
	}
	if !strings.Contains(out3, `"suspect":true`) {
		t.Errorf("--json output missing suspect flag:\n%s", out3)
	}
}
```

Add any missing imports (`config`, `audit`, `time`).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/ -run TestLogShowsSuspectMarker -v`
Expected: FAIL — `--suspect` flag not defined; `[!]` marker absent; `suspect` field missing from JSON.

- [ ] **Step 3: Update `logCmd`, `runLog`, and `logEntry` in `internal/cli/log.go`**

Add `suspect` flag to `logCmd`:

```go
	var (
		// ...existing...
		suspect bool
	)
	// ...
	cmd.Flags().BoolVar(&suspect, "suspect", false, "show only transform-mismatch suspect rows")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runLog(cmd, since, host, credential, limit, jsonOutput, blocked, suspect)
	}
```

Extend `runLog` signature:

```go
func runLog(cmd *cobra.Command, since, host, credential string, limit int, jsonOutput, blocked, suspect bool) error {
```

Update the audit query:

```go
	rows, err := store.Query(audit.Filter{
		Since:          sinceTime,
		Host:           host,
		CredentialName: credential,
		Limit:          limit,
		IncludeBlocked: blocked,
		IncludeSuspect: true, // always include suspect rows in default listing
		SuspectOnly:    suspect,
	})
```

Update the plaintext renderer to tag suspect rows. In the `logRow` struct and loop:

```go
	type logRow struct {
		timestamp, host, method, credential, location string
		suspect                                       bool
	}
	logRows := make([]logRow, len(rows))
	for i, r := range rows {
		logRows[i] = logRow{
			timestamp:  ui.RelativeTime(r.Timestamp),
			host:       r.Host,
			method:     r.Method,
			credential: r.CredentialName,
			location:   r.Location,
			suspect:    r.SuspectFlag,
		}
	}
```

In the per-row `Fprintf` loop, prefix a marker column:

```go
	for _, r := range logRows {
		marker := "   "
		if r.suspect {
			marker = "[!]"
		}
		_, _ = fmt.Fprintf(w, "%s  %s%s%s%s%s%s%s%s%s\n",
			marker,
			padRight(r.timestamp, tsW), gap,
			padRight(r.host, hostW), gap,
			padRight(r.method, methodW), gap,
			padRight(r.credential, credW), gap,
			r.location)
	}
```

Prefix the header with spaces to align:

```go
	_, _ = fmt.Fprintf(w, "     %s%s%s%s%s%s%s%s%s\n", /* existing columns */)
```

Update `logEntry` JSON shape:

```go
type logEntry struct {
	Timestamp  string `json:"timestamp"`
	Host       string `json:"host"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Credential string `json:"credential"`
	Location   string `json:"location"`
	Suspect    bool   `json:"suspect,omitempty"`
	AuthSignal string `json:"auth_signal,omitempty"`
}
```

Populate in the JSON loop:

```go
		_ = enc.Encode(logEntry{
			Timestamp:  r.Timestamp.Format(time.RFC3339),
			Host:       r.Host,
			Method:     r.Method,
			Path:       r.URLPath,
			Credential: r.CredentialName,
			Location:   r.Location,
			Suspect:    r.SuspectFlag,
			AuthSignal: r.AuthSignal,
		})
```

Note: the test asserts `"suspect":true` — so do NOT use `omitempty` on Suspect. Change to:

```go
	Suspect    bool   `json:"suspect"`
```

(Keep omitempty on `AuthSignal`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cli/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/log.go internal/cli/cli_test.go
git commit -m "feat(cli): surface transform-mismatch suspect rows in veil log"
```

---

## Task 14: Integration test — Basic flow end-to-end

**Files:**
- Create: `internal/proxy/basic_integration_test.go`

**Rationale:** A black-box test that verifies the full path: placeholder `.env` → injector → real values on the wire.

- [ ] **Step 1: Write the failing test**

Create `internal/proxy/basic_integration_test.go`:

```go
package proxy

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/8enji/veil/internal/vault"
)

// TestBasicAuthEndToEnd spins up an upstream HTTP server that requires a
// specific Basic auth header, runs a request through ProcessRequest with
// placeholder Basic, and asserts the upstream sees the real credentials.
func TestBasicAuthEndToEnd(t *testing.T) {
	realUser := "johndoe"
	realSecret := "ghp_real_secret_value"
	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(realUser+":"+realSecret))

	// Upstream: reject anything that isn't the exact real Basic header.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		if got != expectedAuth {
			http.Error(w, "unauthorized: got "+got, http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	// Parse the srv URL to extract the host so AllowedHosts matches exactly.
	// httptest.Server.URL is like "http://127.0.0.1:NNNN".
	host := strings.TrimPrefix(srv.URL, "http://")
	hostOnly := strings.Split(host, ":")[0]
	allowedHost := strings.Split(host, "/")[0] // "127.0.0.1:NNNN"

	cred := &vault.Credential{
		ID: "c1", Name: "basic-e2e",
		Real:                realSecret,
		Placeholder:         "VEIL_SECRET_E2E",
		Username:            realUser,
		UsernamePlaceholder: "VEIL_USER_E2E",
		AllowedHosts:        []string{hostOnly, allowedHost},
	}
	inj := NewInjector(
		map[string]*vault.Credential{cred.Placeholder: cred, cred.UsernamePlaceholder: cred},
		nil, 1, "test-agent",
	)

	// Build the placeholder Basic header.
	phAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("VEIL_USER_E2E:VEIL_SECRET_E2E"))
	hdr := http.Header{}
	hdr.Set("Authorization", phAuth)

	_, newHeader, _, injections := inj.ProcessRequest(
		"req-e2e", "GET", srv.URL+"/ping", hdr, nil)

	req, err := http.NewRequest("GET", srv.URL+"/ping", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, vs := range newHeader {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("upstream returned %d: %s", resp.StatusCode, body)
	}
	if len(injections) != 1 {
		t.Errorf("expected 1 injection, got %d", len(injections))
	}
	for _, i := range injections {
		if i.SuspectFlag {
			t.Errorf("unexpected suspect injection: %+v", i)
		}
	}
}

// TestDetectorFiresOnSigV4Shape spins up an upstream, sends a request that
// looks AWS-SigV4-shaped to a credentialed host, and asserts the detector
// fires without any swap happening (since SigV4 isn't implemented).
func TestDetectorFiresOnSigV4Shape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "fake sigv4 rejection", http.StatusForbidden)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	hostOnly := strings.Split(host, ":")[0]

	cred := &vault.Credential{
		ID: "aws", Name: "aws-secret",
		Real:         "wJalr_real_secret",
		Placeholder:  "VEIL_AWS_PH",
		AllowedHosts: []string{hostOnly, host},
	}
	inj := NewInjector(map[string]*vault.Credential{cred.Placeholder: cred}, nil, 1, "test")

	hdr := http.Header{}
	hdr.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAFAKE/20260415/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abcd1234")
	hdr.Set("X-Amz-Date", "20260415T000000Z")

	_, _, _, injections := inj.ProcessRequest(
		"req-sigv4", "GET", srv.URL+"/bucket", hdr, nil)

	var suspect int
	for _, i := range injections {
		if i.SuspectFlag {
			suspect++
			if i.AuthSignal != "authorization_header" {
				t.Errorf("AuthSignal = %q", i.AuthSignal)
			}
		}
	}
	if suspect != 1 {
		t.Errorf("expected 1 suspect injection, got %d (all: %+v)", suspect, injections)
	}
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `go test ./internal/proxy/ -run "TestBasicAuthEndToEnd|TestDetectorFiresOnSigV4Shape" -v`
Expected: PASS (both). These exercise previously-implemented behavior, so no new implementation should be needed — if they fail, root-cause back to earlier tasks.

- [ ] **Step 3: Commit**

```bash
git add internal/proxy/basic_integration_test.go
git commit -m "test(proxy): end-to-end Basic auth and detector integration tests"
```

---

## Task 15: Product-copy updates

**Files:**
- Modify: `docs/PRODUCT.md`
- Modify: `docs/MVP.md` (if it exists — check first; if absent, skip)
- Modify: `docs/THREAT_MODEL.md`

- [ ] **Step 1: Read current docs**

Run these so the copy changes fit the existing tone:

- Read: `docs/PRODUCT.md`
- Read: `docs/THREAT_MODEL.md`
- Check: `ls docs/MVP.md` — if absent, skip that file for this task.

- [ ] **Step 2: Add an auth-scheme coverage note to `docs/PRODUCT.md`**

Find the "Control: Network Proxy + Placeholder .env" section (§3 per the findings doc) and append a paragraph along these lines:

```markdown
### Auth-scheme coverage

Veil mediates credentials that appear verbatim on the wire. As of this
release that covers:

- **Bearer tokens** in any header (`Authorization: Bearer ...`, `X-*-Token`,
  etc.) and bearer-shaped credentials in query parameters or request bodies.
- **HTTP Basic auth** (`Authorization: Basic <base64>` / `Proxy-Authorization`).
  Requires creating credentials with `veil add --user <value>`. Covers the
  common dev workflows: `git push` over HTTPS, Docker registry auth,
  `twine`/PyPI upload, npm `_auth`, Artifactory/Nexus.

Schemes that **derive** a signature or MAC from the secret (AWS SigV4,
GitHub App JWTs, webhook signing) are not mediated — the proxy can see the
request but cannot re-sign it. When a request to a credentialed host does
not result in any injection but looks authenticated, Veil emits a
`transform_mismatch_suspected` warning so the failure is visible rather
than silent. See `veil log --suspect` for the diagnostic trail.
```

Match the tone and heading style of the existing document; the text above is a starting point, not a verbatim requirement.

- [ ] **Step 3: Update `docs/MVP.md` if present**

In the Features section, clarify that Basic auth is now mediated. One sentence is enough.

- [ ] **Step 4: Update `docs/THREAT_MODEL.md`**

Add a bullet in the appropriate "what Veil does not protect" section:

```markdown
- **Keyed-cryptography auth schemes** (AWS SigV4, JWT-signed requests,
  webhook signatures). These reach the upstream unredacted-but-rejected.
  Veil surfaces a `transform_mismatch_suspected` audit row and WARN log
  line when such a request hits a credentialed host, converting a silent
  failure into a diagnosable one.
```

Match the existing bullet style.

- [ ] **Step 5: Run all tests one last time**

Run: `go test ./... -v`
Expected: full PASS.

- [ ] **Step 6: Commit**

```bash
git add docs/
git commit -m "docs: describe Basic auth coverage and transform-mismatch detector"
```

---

## Final verification

After all tasks are complete, run a final pass from the repo root:

- [ ] `go build ./...` — no build errors.
- [ ] `go test ./...` — all tests pass.
- [ ] `go vet ./...` — no vet warnings.
- [ ] If the project has a linter configured (check `Makefile`, `.golangci.yml`): run it.
- [ ] Manual smoke: `./veil init` → `./veil add gh-basic --user johndoe --host github.com --value ghp_fake` → `./veil list` (expect `(basic)` tag) → `./veil log --suspect` (expect empty but succeeds).

## Notes for the implementer

- **Existing test helpers.** The exact helper names (`newTestRoot`, `newInMemoryVaultForTest`, `runCLI`) may not exist verbatim. Read `internal/cli/cli_test.go` and `internal/vault/vault_test.go` first and substitute the actual helpers. The intent of each test is spelled out in comments above.
- **Logger choice.** Task 10 assumes `log.Printf`. If the codebase uses `slog`, translate the log call accordingly — see Task 10 Step 1.
- **No AWS provider removal.** This plan does not remove the `*.amazonaws.com` provider registration. The detector now surfaces SigV4 traffic as suspect, which is the right signal for now. Removing the registration is a separate product decision.
