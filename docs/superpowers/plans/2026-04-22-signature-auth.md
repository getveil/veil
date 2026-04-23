# Signature-Based Auth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable AWS SigV4 and GitHub App JWT authentication through Veil by re-signing at the proxy, preserving the "nothing real in `.env`" invariant.

**Architecture:** Two new signer functions (`signAWSSigV4`, `signGitHubAppJWT`) join `ProcessRequest` in `internal/proxy/` as siblings to the existing Basic decoder. The `vault.Credential` struct gains a `Scheme` discriminator plus typed per-scheme fields. Unrecognized AKIA / unknown GitHub App ID where Veil owns the host returns 502 with a `signer_failed` audit row.

**Tech Stack:** Go 1.22+, `crypto/rsa`, `crypto/hmac`, `crypto/sha256`, `encoding/base64`, `encoding/pem`, `encoding/json`, `modernc.org/sqlite`, `github.com/elazarl/goproxy`, `github.com/spf13/cobra`.

---

## File structure

### Create

- `internal/proxy/sigv4_signer.go` — `signAWSSigV4`, header-parse, canonical-request, SigV4 key-derivation.
- `internal/proxy/sigv4_signer_test.go` — AWS published test vectors + unit cases.
- `internal/proxy/github_app_signer.go` — `signGitHubAppJWT`, JWT detection + re-sign.
- `internal/proxy/github_app_signer_test.go` — happy path, detection, lookup, key-order preservation.
- `internal/proxy/jwt.go` — base64url helpers + deterministic JSON encoder preserving input key order.
- `internal/proxy/jwt_test.go` — base64url round-trip, JSON key-order preservation.
- `internal/proxy/signer_result.go` — `SignerOutcome` constants and `firstSignerFailure` helper.

### Modify

- `internal/vault/record.go` — extend `Credential` with `Scheme` + typed fields; extend `Zero()`.
- `internal/vault/vault_test.go` — round-trip new fields.
- `internal/vault/vault.go` — extend `PlaceholderMap()` and `PlaceholderSet()` to include AWS AKIA-placeholder and AWS session-token placeholder.
- `internal/audit/audit.go` — add `SignerError` field, schema v3 migration (`signer_error TEXT`), insert-SQL update.
- `internal/audit/audit_test.go` — round-trip `SignerError`.
- `internal/placeholder/provider_aws.go` — add `generateAWSSessionToken` helper (called explicitly, not via `Match`).
- `internal/placeholder/provider_github.go` — add `GenerateGitHubAppPrivateKey` (called explicitly at `veil add --scheme github_app` time).
- `internal/placeholder/provider_github_test.go` — create or extend with RSA gen tests.
- `internal/proxy/injector.go` — call `signAWSSigV4` and `signGitHubAppJWT` between Basic pre-pass and literal header scan.
- `internal/proxy/injector_test.go` — integration-style tests confirming pipeline order.
- `internal/proxy/proxy.go` — after `ProcessRequest`, check `firstSignerFailure(injections)` and return 502 if present.
- `internal/proxy/failclosed_test.go` — extend with signer-failure 502 case.
- `internal/cli/add.go` — add `--scheme`, `--aws-access-key-id`, `--aws-session-token-stdin`, `--aws-session-token-file`, `--github-app-id`, `--github-installation-id` flags and validation.
- `internal/cli/add_test.go` — cover new scheme branches.
- `internal/cli/list.go` — render `(aws)` / `(github app)` tags.
- `internal/cli/log.go` — add `--signer-failed` filter; render `SignerError` column when non-empty.
- `internal/proxy/basic_integration_test.go` — add AWS + GitHub App end-to-end tests.
- `PRODUCT.md`, `MVP.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md` — list AWS SigV4 and GitHub App as mediated schemes; note scoped gaps.

---

## Phase 1 — Foundation

### Task 1: Extend Credential schema

**Files:**
- Modify: `internal/vault/record.go`
- Test: `internal/vault/vault_test.go`

- [ ] **Step 1: Write failing round-trip test**

Append to `internal/vault/vault_test.go`:

```go
func TestCredential_AWSFieldsRoundTrip(t *testing.T) {
    dir := t.TempDir()
    ks := newMemKeystore(t)
    v, err := vault.CreateVault(dir, "pid", ks)
    if err != nil {
        t.Fatal(err)
    }

    orig := &vault.Credential{
        ID:                         vault.NewID(),
        Name:                       "aws-prod",
        Real:                       "real-secret-key",
        Placeholder:                "VeilAWSSecretVEIL",
        Scheme:                     "aws",
        AWSAccessKeyID:             "AKIAIOSFODNN7EXAMPLE",
        AWSAccessKeyIDPlaceholder:  "AKIAVEIL3X9Z2Y1W8VQR",
        AWSSessionToken:            "FwoGZXIv...realtoken",
        AWSSessionTokenPlaceholder: "VeilAWSSessTok",
        AllowedHosts:               []string{"*.amazonaws.com"},
        CreatedAt:                  time.Now(),
    }
    if err := v.Add(orig); err != nil {
        t.Fatal(err)
    }

    v2, err := vault.Open(dir, ks)
    if err != nil {
        t.Fatal(err)
    }
    got, ok := v2.Get("aws-prod")
    if !ok {
        t.Fatal("credential not found after reload")
    }
    if got.Scheme != "aws" || got.AWSAccessKeyID != orig.AWSAccessKeyID ||
        got.AWSAccessKeyIDPlaceholder != orig.AWSAccessKeyIDPlaceholder ||
        got.AWSSessionToken != orig.AWSSessionToken ||
        got.AWSSessionTokenPlaceholder != orig.AWSSessionTokenPlaceholder {
        t.Fatalf("aws fields not preserved: %+v", got)
    }
}

func TestCredential_GitHubAppFieldsRoundTrip(t *testing.T) {
    dir := t.TempDir()
    ks := newMemKeystore(t)
    v, err := vault.CreateVault(dir, "pid", ks)
    if err != nil {
        t.Fatal(err)
    }

    pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n"
    placeholder := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n"
    orig := &vault.Credential{
        ID:                   vault.NewID(),
        Name:                 "gh-app",
        Real:                 pem,
        Placeholder:          placeholder,
        Scheme:               "github_app",
        GitHubAppID:          123456,
        GitHubInstallationID: 789012,
        AllowedHosts:         []string{"api.github.com"},
        CreatedAt:            time.Now(),
    }
    if err := v.Add(orig); err != nil {
        t.Fatal(err)
    }
    v2, err := vault.Open(dir, ks)
    if err != nil {
        t.Fatal(err)
    }
    got, _ := v2.Get("gh-app")
    if got.Real != pem || got.Placeholder != placeholder ||
        got.GitHubAppID != 123456 || got.GitHubInstallationID != 789012 {
        t.Fatalf("github app fields not preserved: %+v", got)
    }
}

func TestCredential_Zero_ClearsAWSFields(t *testing.T) {
    c := &vault.Credential{
        Scheme:                     "aws",
        Real:                       "secret",
        Placeholder:                "ph",
        AWSAccessKeyID:             "AKIA",
        AWSAccessKeyIDPlaceholder:  "AKIAPH",
        AWSSessionToken:            "tok",
        AWSSessionTokenPlaceholder: "tokph",
        GitHubAppID:                1234,
    }
    c.Zero()
    if c.AWSAccessKeyID != "" || c.AWSAccessKeyIDPlaceholder != "" ||
        c.AWSSessionToken != "" || c.AWSSessionTokenPlaceholder != "" ||
        c.Scheme != "" {
        t.Fatalf("Zero did not clear aws/scheme: %+v", c)
    }
    if c.GitHubAppID != 1234 {
        t.Errorf("Zero cleared non-secret GitHubAppID")
    }
}
```

- [ ] **Step 2: Run tests — verify compile failure**

Run: `go test ./internal/vault/...`
Expected: compile error on `Scheme`, `AWSAccessKeyID`, etc. — struct fields don't exist.

- [ ] **Step 3: Extend the Credential struct**

Replace the body of `internal/vault/record.go` with:

```go
package vault

import (
    "crypto/rand"
    "fmt"
    "time"

    "github.com/oklog/ulid/v2"
)

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

    // Scheme is a discriminator: "", "basic", "aws", "github_app".
    // Empty means bearer; "basic" is implied when Username != "".
    Scheme string `json:"scheme,omitempty"`

    // AWS SigV4 fields (Scheme == "aws").
    AWSAccessKeyID             string `json:"aws_access_key_id,omitempty"`
    AWSAccessKeyIDPlaceholder  string `json:"aws_access_key_id_placeholder,omitempty"`
    AWSSessionToken            string `json:"aws_session_token,omitempty"`
    AWSSessionTokenPlaceholder string `json:"aws_session_token_placeholder,omitempty"`

    // GitHub App JWT fields (Scheme == "github_app").
    GitHubAppID          int64 `json:"github_app_id,omitempty"`
    GitHubInstallationID int64 `json:"github_installation_id,omitempty"`
}

// String returns a redacted representation that never leaks secret material.
func (c *Credential) String() string {
    return fmt.Sprintf("Credential{ID:%s, Name:%s}", c.ID, c.Name)
}

// Zero clears sensitive fields. Best-effort for MVP since Go strings are
// immutable; the previous backing memory remains until GC. IDs that are not
// secret (e.g. GitHubAppID) are not cleared.
func (c *Credential) Zero() {
    c.Real = ""
    c.Placeholder = ""
    c.Username = ""
    c.UsernamePlaceholder = ""
    c.AWSAccessKeyID = ""
    c.AWSAccessKeyIDPlaceholder = ""
    c.AWSSessionToken = ""
    c.AWSSessionTokenPlaceholder = ""
    c.Scheme = ""
}

// NewID generates a ULID suitable for use as a credential identifier.
func NewID() string {
    return ulid.MustNew(ulid.Now(), rand.Reader).String()
}
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `go test ./internal/vault/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/vault/record.go internal/vault/vault_test.go
git commit -m "feat(vault): extend Credential with Scheme and typed per-scheme fields"
```

---

### Task 2: Extend PlaceholderMap/PlaceholderSet for AWS fields

**Files:**
- Modify: `internal/vault/vault.go:203-227`
- Test: `internal/vault/vault_test.go`

- [ ] **Step 1: Write failing test**

Append to `internal/vault/vault_test.go`:

```go
func TestPlaceholderMap_IncludesAWSFields(t *testing.T) {
    dir := t.TempDir()
    ks := newMemKeystore(t)
    v, err := vault.CreateVault(dir, "pid", ks)
    if err != nil {
        t.Fatal(err)
    }
    cred := &vault.Credential{
        ID:                         vault.NewID(),
        Name:                       "aws-prod",
        Real:                       "real-secret",
        Placeholder:                "VeilAWSSecret",
        Scheme:                     "aws",
        AWSAccessKeyID:             "AKIAREAL",
        AWSAccessKeyIDPlaceholder:  "AKIAPH",
        AWSSessionToken:            "realtok",
        AWSSessionTokenPlaceholder: "VeilSess",
        AllowedHosts:               []string{"*.amazonaws.com"},
        CreatedAt:                  time.Now(),
    }
    if err := v.Add(cred); err != nil {
        t.Fatal(err)
    }
    pm := v.PlaceholderMap()
    for _, ph := range []string{"VeilAWSSecret", "AKIAPH", "VeilSess"} {
        if pm[ph] == nil {
            t.Errorf("PlaceholderMap missing %q", ph)
        }
    }

    set := v.PlaceholderSet()
    for _, ph := range []string{"VeilAWSSecret", "AKIAPH", "VeilSess"} {
        if _, ok := set[ph]; !ok {
            t.Errorf("PlaceholderSet missing %q", ph)
        }
    }
}
```

- [ ] **Step 2: Run test — verify it fails**

Run: `go test ./internal/vault/... -run TestPlaceholderMap_IncludesAWSFields`
Expected: FAIL — placeholders missing from the map.

- [ ] **Step 3: Extend PlaceholderMap/PlaceholderSet**

In `internal/vault/vault.go`, replace `PlaceholderSet` and `PlaceholderMap` with:

```go
// PlaceholderSet returns the set of currently-used placeholder strings
// across all schemes, suitable for passing to placeholder.Generate to
// prevent collisions.
func (v *Vault) PlaceholderSet() placeholder.Set {
    out := make(placeholder.Set, len(v.credentials)*4)
    for _, c := range v.credentials {
        addPlaceholders(out, c, func(s string) { out[s] = struct{}{} })
    }
    return out
}

// PlaceholderMap returns a map from placeholder value to credential, used by
// the injector to swap placeholders back to real secrets. For multi-field
// credentials (basic, aws) every placeholder maps back to the same record.
func (v *Vault) PlaceholderMap() map[string]*Credential {
    m := make(map[string]*Credential, len(v.credentials)*4)
    for _, c := range v.credentials {
        c := c
        addPlaceholders(nil, c, func(s string) { m[s] = c })
    }
    return m
}

// addPlaceholders calls emit for each non-empty placeholder string on c.
// The set argument is unused (retained for symmetry); callers pass nil.
func addPlaceholders(_ placeholder.Set, c *Credential, emit func(string)) {
    if c.Placeholder != "" {
        emit(c.Placeholder)
    }
    if c.UsernamePlaceholder != "" {
        emit(c.UsernamePlaceholder)
    }
    if c.AWSAccessKeyIDPlaceholder != "" {
        emit(c.AWSAccessKeyIDPlaceholder)
    }
    if c.AWSSessionTokenPlaceholder != "" {
        emit(c.AWSSessionTokenPlaceholder)
    }
}
```

- [ ] **Step 4: Run tests — verify all vault tests pass**

Run: `go test ./internal/vault/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/vault/vault.go internal/vault/vault_test.go
git commit -m "feat(vault): include AWS placeholders in PlaceholderMap/Set"
```

---

### Task 3: Add SignerError to audit.Injection + schema v3 migration

**Files:**
- Modify: `internal/audit/audit.go:25-40, 64-93, 349-379, 418-467`
- Test: `internal/audit/audit_test.go`

- [ ] **Step 1: Write failing test**

Append to `internal/audit/audit_test.go`:

```go
func TestInjection_SignerErrorRoundTrip(t *testing.T) {
    dir := t.TempDir()
    s, err := audit.Open(filepath.Join(dir, "audit.db"))
    if err != nil {
        t.Fatal(err)
    }
    defer s.Close()

    s.Record(audit.Injection{
        Timestamp:   time.Now(),
        RequestID:   "req-1",
        Host:        "s3.amazonaws.com",
        Method:      "GET",
        URLPath:     "/",
        Location:    "signer_failed",
        SignerError: "unknown_access_key_id",
    })
    s.DrainForTest()

    rows, err := s.RecentInjections(10)
    if err != nil {
        t.Fatal(err)
    }
    if len(rows) != 1 {
        t.Fatalf("expected 1 row, got %d", len(rows))
    }
    if rows[0].SignerError != "unknown_access_key_id" {
        t.Errorf("SignerError = %q, want unknown_access_key_id", rows[0].SignerError)
    }
}
```

*(If `RecentInjections` doesn't yet exist, use the equivalent query helper in `internal/audit/query.go` or write a minimal `SELECT signer_error FROM injections` inline via `s.DB()` if exposed. Check the current audit package for the existing test helper first.)*

- [ ] **Step 2: Run test — verify it fails**

Run: `go test ./internal/audit/... -run TestInjection_SignerErrorRoundTrip`
Expected: FAIL — `SignerError` field does not exist on `audit.Injection`.

- [ ] **Step 3: Add SignerError field + schema**

In `internal/audit/audit.go` modify the `Injection` struct to add:

```go
type Injection struct {
    // ...existing fields...
    SignerError string // empty unless Location == "signer_failed"
}
```

Update `schemaDDL` to include the new column on fresh installs:

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
  auth_signal     TEXT NOT NULL DEFAULT '',
  signer_error    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_inj_ts   ON injections(ts);
CREATE INDEX IF NOT EXISTS idx_inj_host ON injections(host);
CREATE INDEX IF NOT EXISTS idx_inj_cred ON injections(credential_name);
CREATE TABLE IF NOT EXISTS schema_version (v INTEGER PRIMARY KEY);
INSERT OR IGNORE INTO schema_version VALUES (1);
`
```

Update `insertSQL`:

```go
const insertSQL = `INSERT INTO injections (
  ts, request_id, host, method, url_path,
  credential_id, credential_name, agent_pid, agent_cmd,
  bytes_before, bytes_after, location, suspect_flag, auth_signal,
  signer_error
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
```

Add `inj.SignerError` at the end of the `stmt.Exec` args in `writeBatch`.

- [ ] **Step 4: Add migrateToV3**

Append to `internal/audit/audit.go` (below `migrateToV2`):

```go
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
```

In `Open`, call `migrateToV3(db)` immediately after `migrateToV2(db)`:

```go
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
```

- [ ] **Step 5: Update the query helper to SELECT the new column**

Find the existing `SELECT` statement in `internal/audit/query.go` (or wherever `RecentInjections` lives) and append `signer_error` to the column list. Scan it into `inj.SignerError`. If no such helper exists, add `signer_error` handling to whatever surface the tests use.

Run `grep -rn "bytes_after" internal/audit/` to find the SELECT statement to update.

- [ ] **Step 6: Run tests — verify they pass**

Run: `go test ./internal/audit/...`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/audit/
git commit -m "feat(audit): add SignerError field + schema v3 migration"
```

---

### Task 4: Signer outcome enum + firstSignerFailure helper

**Files:**
- Create: `internal/proxy/signer_result.go`
- Test: inline in the signer tests (no separate test file for the enum).

- [ ] **Step 1: Write `signer_result.go`**

```go
package proxy

import "github.com/8enji/veil/internal/audit"

// Signer Location values emitted into audit records.
const (
    LocationAWSSigV4Resigned    = "aws_sigv4_resigned"
    LocationGitHubAppJWTResigned = "github_app_jwt_resigned"
    LocationSchemeUnmediated    = "scheme_unmediated"
    LocationSignerFailed        = "signer_failed"
)

// Signer error classes recorded in Injection.SignerError.
const (
    SignerErrUnknownAccessKeyID              = "unknown_access_key_id"
    SignerErrUnknownGitHubAppID              = "unknown_github_app_id"
    SignerErrUnexpectedSessionToken          = "unexpected_session_token"
    SignerErrMissingSessionToken             = "missing_session_token"
    SignerErrAuthorizationMalformed          = "authorization_malformed"
    SignerErrCanonicalRequestReconstruction  = "canonical_request_reconstruction_failed"
    SignerErrRSASignFailed                   = "rsa_sign_failed"
    SignerErrJWTMalformed                    = "jwt_malformed"
)

// firstSignerFailure returns the first signer_failed injection or nil.
func firstSignerFailure(injections []audit.Injection) *audit.Injection {
    for i := range injections {
        if injections[i].Location == LocationSignerFailed {
            return &injections[i]
        }
    }
    return nil
}
```

- [ ] **Step 2: Verify build**

Run: `go build ./internal/proxy/...`
Expected: clean build.

- [ ] **Step 3: Commit**

```bash
git add internal/proxy/signer_result.go
git commit -m "feat(proxy): add signer outcome constants and firstSignerFailure helper"
```

---

## Phase 2 — AWS SigV4 signer

### Task 5: AWS session token placeholder generator

**Files:**
- Modify: `internal/placeholder/provider_aws.go`
- Test: `internal/placeholder/provider_aws_test.go` (create)

- [ ] **Step 1: Write failing test**

Create `internal/placeholder/provider_aws_test.go`:

```go
package placeholder

import (
    "strings"
    "testing"
)

func TestGenerateAWSSessionToken_LengthAndSentinel(t *testing.T) {
    real := "FwoGZXIvYXdzEBYaDG" + strings.Repeat("A", 400)
    ph, err := GenerateAWSSessionToken(real, Set{})
    if err != nil {
        t.Fatal(err)
    }
    if len(ph) != len(real) {
        t.Errorf("length = %d, want %d", len(ph), len(real))
    }
    if !strings.Contains(ph, Sentinel) {
        t.Errorf("placeholder missing sentinel")
    }
}

func TestGenerateAWSSessionToken_CollisionRetry(t *testing.T) {
    real := strings.Repeat("x", 200)
    // Seed the Set with the first expected output so Generate must retry.
    // Since randomness is entropy-seeded, just smoke-test uniqueness across
    // 5 calls rather than trying to force a known collision.
    seen := Set{}
    for i := 0; i < 5; i++ {
        ph, err := GenerateAWSSessionToken(real, seen)
        if err != nil {
            t.Fatal(err)
        }
        if _, dup := seen[ph]; dup {
            t.Fatalf("duplicate placeholder on iteration %d: %q", i, ph)
        }
        seen[ph] = struct{}{}
    }
}
```

- [ ] **Step 2: Run — verify it fails**

Run: `go test ./internal/placeholder/ -run TestGenerateAWSSessionToken`
Expected: FAIL — `GenerateAWSSessionToken` undefined.

- [ ] **Step 3: Implement**

Append to `internal/placeholder/provider_aws.go`:

```go
// GenerateAWSSessionToken produces a placeholder for an AWS STS session token.
// Session tokens are long base64-ish strings (~300-800 bytes). Length is
// preserved; Sentinel is embedded near the start.
func GenerateAWSSessionToken(value string, existing Set) (string, error) {
    for attempt := 0; attempt < 10; attempt++ {
        candidate := sentinelize(randBase64ish(len(value)), 0)
        if _, ok := existing[candidate]; !ok {
            return candidate, nil
        }
    }
    return "", ErrPlaceholderExhausted
}
```

*(If `ErrPlaceholderExhausted` doesn't exist in the placeholder package, use the existing error surface — check `internal/placeholder/engine.go` for how `Generate` reports exhaustion.)*

- [ ] **Step 4: Run tests — verify pass**

Run: `go test ./internal/placeholder/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/placeholder/provider_aws.go internal/placeholder/provider_aws_test.go
git commit -m "feat(placeholder): add explicit AWS session token generator"
```

---

### Task 6: CLI `--scheme aws` flag

**Files:**
- Modify: `internal/cli/add.go`
- Test: `internal/cli/add_test.go`

- [ ] **Step 1: Write failing test**

Append to `internal/cli/add_test.go`:

```go
func TestAddCmd_SchemeAWS_HappyPath(t *testing.T) {
    dir := t.TempDir()
    initProject(t, dir)

    var stdout, stderr bytes.Buffer
    cmd := RootCmd()
    cmd.SetOut(&stdout)
    cmd.SetErr(&stderr)
    cmd.SetIn(strings.NewReader("real-secret-access-key\n"))
    cmd.SetArgs([]string{
        "add", "aws-prod",
        "--scheme", "aws",
        "--aws-access-key-id", "AKIAIOSFODNN7EXAMPLE",
        "--host", "*.amazonaws.com",
        "--value-stdin",
    })
    if err := cmd.Execute(); err != nil {
        t.Fatalf("add: %v (stderr: %s)", err, stderr.String())
    }

    v := openVaultInDir(t, dir)
    cred, ok := v.Get("aws-prod")
    if !ok {
        t.Fatal("credential not added")
    }
    if cred.Scheme != "aws" {
        t.Errorf("Scheme = %q, want aws", cred.Scheme)
    }
    if cred.AWSAccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
        t.Errorf("AccessKeyID not stored")
    }
    if cred.AWSAccessKeyIDPlaceholder == "" || !strings.HasPrefix(cred.AWSAccessKeyIDPlaceholder, "AKIA") {
        t.Errorf("AccessKeyIDPlaceholder = %q, want AKIA-prefixed", cred.AWSAccessKeyIDPlaceholder)
    }
}

func TestAddCmd_SchemeAWS_RejectsBadAccessKeyID(t *testing.T) {
    dir := t.TempDir()
    initProject(t, dir)
    cmd := RootCmd()
    cmd.SetErr(io.Discard)
    cmd.SetOut(io.Discard)
    cmd.SetIn(strings.NewReader("secret\n"))
    cmd.SetArgs([]string{
        "add", "aws-prod",
        "--scheme", "aws",
        "--aws-access-key-id", "WRONGFORMAT",
        "--value-stdin",
    })
    if err := cmd.Execute(); err == nil {
        t.Fatal("expected validation error on bad access key id")
    }
}

func TestAddCmd_SchemeAWS_WithSessionTokenFile(t *testing.T) {
    dir := t.TempDir()
    initProject(t, dir)
    tokPath := filepath.Join(dir, "sess.txt")
    if err := os.WriteFile(tokPath, []byte("FwoGZXIvrealsessiontoken"), 0600); err != nil {
        t.Fatal(err)
    }

    cmd := RootCmd()
    cmd.SetOut(io.Discard)
    cmd.SetErr(io.Discard)
    cmd.SetIn(strings.NewReader("secret-access-key\n"))
    cmd.SetArgs([]string{
        "add", "aws-sts",
        "--scheme", "aws",
        "--aws-access-key-id", "ASIAIOSFODNN7EXAMPLE",
        "--aws-session-token-file", tokPath,
        "--value-stdin",
    })
    if err := cmd.Execute(); err != nil {
        t.Fatalf("add: %v", err)
    }

    cred, _ := openVaultInDir(t, dir).Get("aws-sts")
    if cred.AWSSessionToken != "FwoGZXIvrealsessiontoken" {
        t.Errorf("session token = %q", cred.AWSSessionToken)
    }
    if cred.AWSSessionTokenPlaceholder == "" {
        t.Error("session token placeholder empty")
    }
}

func TestAddCmd_SchemeAWS_MutuallyExclusiveWithUser(t *testing.T) {
    dir := t.TempDir()
    initProject(t, dir)
    cmd := RootCmd()
    cmd.SetErr(io.Discard)
    cmd.SetOut(io.Discard)
    cmd.SetIn(strings.NewReader("secret\n"))
    cmd.SetArgs([]string{
        "add", "x",
        "--scheme", "aws",
        "--user", "bob",
        "--aws-access-key-id", "AKIAIOSFODNN7EXAMPLE",
        "--value-stdin",
    })
    if err := cmd.Execute(); err == nil {
        t.Fatal("expected mutual-exclusion error between --user and --scheme aws")
    }
}
```

*(`initProject` and `openVaultInDir` exist in `internal/cli/testutil_test.go` — grep for existing helpers. If either name is different, use the actual name.)*

- [ ] **Step 2: Run — verify failure**

Run: `go test ./internal/cli/... -run TestAddCmd_SchemeAWS`
Expected: FAIL — unknown flag `--scheme`.

- [ ] **Step 3: Extend the `addCmd` flags and handler**

Modify `internal/cli/add.go` top of `addCmd()`:

```go
func addCmd() *cobra.Command {
    var force bool
    var hosts []string
    var value string
    var valueStdin bool
    var username string
    var scheme string
    var awsAccessKeyID string
    var awsSessionTokenFile string
    var awsSessionTokenStdin bool
    var githubAppID int64
    var githubInstallationID int64
    cmd := &cobra.Command{
        Use:   "add <name>",
        Short: "Add a secret to the vault",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            return runAdd(cmd, args[0], addOpts{
                force:               force,
                hosts:               hosts,
                value:               value,
                valueStdin:          valueStdin,
                username:            username,
                scheme:              scheme,
                awsAccessKeyID:      awsAccessKeyID,
                awsSessionTokenFile: awsSessionTokenFile,
                awsSessionTokenStdin: awsSessionTokenStdin,
                githubAppID:         githubAppID,
                githubInstallationID: githubInstallationID,
            })
        },
    }
    cmd.Flags().BoolVar(&force, "force", false, "overwrite existing credential")
    cmd.Flags().StringArrayVar(&hosts, "host", nil, "allowed destination host (repeatable)")
    cmd.Flags().StringVar(&value, "value", "", "secret value (UNSAFE: saved to shell history; prefer --value-stdin)")
    cmd.Flags().BoolVar(&valueStdin, "value-stdin", false, "read secret from stdin without a prompt")
    cmd.Flags().StringVar(&username, "user", "", "username for HTTP Basic credentials")
    cmd.Flags().StringVar(&scheme, "scheme", "", "credential scheme: aws, github_app (default: bearer or basic)")
    cmd.Flags().StringVar(&awsAccessKeyID, "aws-access-key-id", "", "AWS access key ID (required for --scheme aws)")
    cmd.Flags().StringVar(&awsSessionTokenFile, "aws-session-token-file", "", "path to a file containing an AWS session token")
    cmd.Flags().BoolVar(&awsSessionTokenStdin, "aws-session-token-stdin", false, "read AWS session token from stdin (mutually exclusive with --value-stdin)")
    cmd.Flags().Int64Var(&githubAppID, "github-app-id", 0, "GitHub App ID (required for --scheme github_app)")
    cmd.Flags().Int64Var(&githubInstallationID, "github-installation-id", 0, "GitHub App installation ID (optional)")
    cmd.MarkFlagsMutuallyExclusive("value", "value-stdin")
    cmd.MarkFlagsMutuallyExclusive("aws-session-token-file", "aws-session-token-stdin")
    cmd.MarkFlagsMutuallyExclusive("value-stdin", "aws-session-token-stdin")
    return cmd
}

type addOpts struct {
    force                bool
    hosts                []string
    value                string
    valueStdin           bool
    username             string
    scheme               string
    awsAccessKeyID       string
    awsSessionTokenFile  string
    awsSessionTokenStdin bool
    githubAppID          int64
    githubInstallationID int64
}
```

Refactor `runAdd` / `runAddInVault` to take `addOpts` and branch on `opts.scheme`. Add an AWS branch after the existing Basic block:

```go
if opts.scheme == "aws" {
    if opts.username != "" {
        return cliError("--user is not valid with --scheme aws", "")
    }
    if opts.awsAccessKeyID == "" {
        return cliError("--aws-access-key-id is required for --scheme aws", "")
    }
    if !awsAccessKeyIDRegex.MatchString(opts.awsAccessKeyID) {
        return cliError("access key ID must match AKIA|ASIA + 16 upper-alphanumeric", "")
    }
    akIDPh := generateAWSAccessKeyIDPlaceholder(opts.awsAccessKeyID, v.PlaceholderSet())
    secretPh := ph // the primary placeholder already generated above
    var sessTok, sessPh string
    if opts.awsSessionTokenFile != "" {
        b, err := os.ReadFile(opts.awsSessionTokenFile)
        if err != nil {
            return cliErrorf("read session token: %v", err)
        }
        sessTok = strings.TrimRight(string(b), "\r\n")
    } else if opts.awsSessionTokenStdin {
        sessTok, err = readAllStdin(cmd.InOrStdin())
        if err != nil {
            return err
        }
    }
    if sessTok != "" {
        existing := v.PlaceholderSet()
        existing[secretPh] = struct{}{}
        existing[akIDPh] = struct{}{}
        sessPh, err = placeholder.GenerateAWSSessionToken(sessTok, existing)
        if err != nil {
            return cliErrorf("generating session token placeholder: %v", err)
        }
    }

    cred := &vault.Credential{
        ID:                         vault.NewID(),
        Name:                       name,
        Real:                       value,
        Placeholder:                secretPh,
        Source:                     "manual",
        AllowedHosts:               allowedHosts,
        CreatedAt:                  time.Now(),
        Scheme:                     "aws",
        AWSAccessKeyID:             opts.awsAccessKeyID,
        AWSAccessKeyIDPlaceholder:  akIDPh,
        AWSSessionToken:            sessTok,
        AWSSessionTokenPlaceholder: sessPh,
    }

    // --force: if an existing credential of the same name is being replaced,
    // collect the old placeholders so we can rewrite them in .env files.
    var oldPhs []string
    if opts.force {
        if existing, ok := v.Get(name); ok {
            if existing.Placeholder != "" {
                oldPhs = append(oldPhs, existing.Placeholder)
            }
            if existing.AWSAccessKeyIDPlaceholder != "" {
                oldPhs = append(oldPhs, existing.AWSAccessKeyIDPlaceholder)
            }
            if existing.AWSSessionTokenPlaceholder != "" {
                oldPhs = append(oldPhs, existing.AWSSessionTokenPlaceholder)
            }
            if _, err := v.Delete(name); err != nil {
                return cliErrorf("replacing existing credential: %v", err)
            }
        }
    }

    if err := v.Add(cred); err != nil {
        return cliErrorf("adding credential: %v", err)
    }

    // Sync each old→new placeholder pair into .env. The mapping: old secret
    // → new secretPh, old AKID placeholder → akIDPh, old session placeholder
    // → sessPh. If the counts differ (e.g. user added a session token on
    // re-add), extra new placeholders simply have no .env entry to rewrite.
    newPhs := []string{secretPh, akIDPh}
    if sessPh != "" {
        newPhs = append(newPhs, sessPh)
    }
    for i, old := range oldPhs {
        if i >= len(newPhs) {
            break
        }
        if err := syncPlaceholderInEnvFiles(projectRoot, old, newPhs[i]); err != nil {
            ui.Warnf(cmd.ErrOrStderr(), "env sync failed for %s: %v", old, err)
        }
    }

    ui.Step(cmd.OutOrStdout(), fmt.Sprintf("Added %s to vault (aws)", name))
    fmt.Fprintf(cmd.OutOrStdout(), "    %s %s\n", ui.Muted.Sprint("Access key placeholder:"), akIDPh)
    fmt.Fprintf(cmd.OutOrStdout(), "    %s %s\n", ui.Muted.Sprint("Secret placeholder:"), secretPh)
    if sessPh != "" {
        fmt.Fprintf(cmd.OutOrStdout(), "    %s %s\n", ui.Muted.Sprint("Session token placeholder:"), sessPh)
    }
    if len(allowedHosts) > 0 {
        fmt.Fprintf(cmd.OutOrStdout(), "    %s %s\n", ui.Muted.Sprint("Hosts:"), strings.Join(allowedHosts, ", "))
    }
    return nil
}
```

*(Use the real helper names from the existing code: `syncPlaceholderInEnvFiles`, `projectRoot`, `cliError`/`cliErrorf`, `ui.Step`, `ui.Muted` — they're referenced identically elsewhere in `internal/cli/add.go`.)*

Add the regex as a package-level var:

```go
var awsAccessKeyIDRegex = regexp.MustCompile(`^(AKIA|ASIA)[A-Z0-9]{16}$`)
```

Add `generateAWSAccessKeyIDPlaceholder`:

```go
func generateAWSAccessKeyIDPlaceholder(realAKID string, existing placeholder.Set) string {
    p, _ := placeholder.DefaultRegistry().Get("aws")
    for i := 0; i < 10; i++ {
        cand := p.Generate(realAKID)
        if _, ok := existing[cand]; !ok {
            return cand
        }
    }
    // fall back to random
    return sentinelFallback(realAKID)
}
```

*(The helper wraps the existing AWS provider's Generate; keep the fallback simple and deterministic.)*

- [ ] **Step 4: Run — verify happy path**

Run: `go test ./internal/cli/... -run TestAddCmd_SchemeAWS`
Expected: PASS for all four tests.

- [ ] **Step 5: Run the full CLI suite**

Run: `go test ./internal/cli/...`
Expected: PASS (no regression in bearer / basic paths).

- [ ] **Step 6: Commit**

```bash
git add internal/cli/add.go internal/cli/add_test.go
git commit -m "feat(cli): add --scheme aws with access-key-id and session-token flags"
```

---

### Task 7: AWS canonical-URI and canonical-query-string helpers

**Files:**
- Create: `internal/proxy/sigv4_signer.go` (scaffold + helpers)
- Test: `internal/proxy/sigv4_signer_test.go`

- [ ] **Step 1: Write failing tests for canonicalization**

Create `internal/proxy/sigv4_signer_test.go`:

```go
package proxy

import "testing"

func TestCanonicalURI(t *testing.T) {
    cases := []struct {
        name, in, want string
        isS3           bool
    }{
        {"root path", "/", "/", false},
        {"normal path", "/foo/bar", "/foo/bar", false},
        {"percent-encoded reserved", "/a b", "/a%20b", false},
        {"s3 preserves double slash", "/foo//bar", "/foo//bar", true},
        {"non-s3 collapses double slash", "/foo//bar", "/foo/bar", false},
        {"dot segments collapsed non-s3", "/foo/./bar/..", "/foo/", false},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            got := canonicalURI(tc.in, tc.isS3)
            if got != tc.want {
                t.Errorf("canonicalURI(%q, s3=%v) = %q, want %q", tc.in, tc.isS3, got, tc.want)
            }
        })
    }
}

func TestCanonicalQueryString(t *testing.T) {
    cases := []struct{ name, in, want string }{
        {"empty", "", ""},
        {"single", "foo=bar", "foo=bar"},
        {"sort by name", "b=2&a=1", "a=1&b=2"},
        {"same name sort by value", "a=2&a=1", "a=1&a=2"},
        {"empty value keeps =", "a=", "a="},
        {"encode space", "a=1 2", "a=1%202"},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            got := canonicalQueryString(tc.in)
            if got != tc.want {
                t.Errorf("canonicalQueryString(%q) = %q, want %q", tc.in, got, tc.want)
            }
        })
    }
}

func TestCanonicalHeaders(t *testing.T) {
    hdr := map[string][]string{
        "Host":         {"s3.amazonaws.com"},
        "X-Amz-Date":   {"20150830T123600Z"},
        "Content-Type": {"  application/json   "},
    }
    signed := []string{"host", "x-amz-date", "content-type"}
    got := canonicalHeaders(hdr, signed)
    want := "host:s3.amazonaws.com\nx-amz-date:20150830T123600Z\ncontent-type:application/json\n"
    if got != want {
        t.Errorf("canonicalHeaders mismatch:\n got=%q\nwant=%q", got, want)
    }
}
```

- [ ] **Step 2: Run — verify failure**

Run: `go test ./internal/proxy/ -run TestCanonical`
Expected: FAIL — functions undefined.

- [ ] **Step 3: Implement the helpers**

Create `internal/proxy/sigv4_signer.go`:

```go
package proxy

import (
    "net/http"
    "net/url"
    "path"
    "sort"
    "strings"
)

// canonicalURI normalizes the path portion of a URL per SigV4.
// S3 preserves consecutive slashes and dot segments; other services collapse.
func canonicalURI(rawPath string, isS3 bool) string {
    if rawPath == "" {
        return "/"
    }
    if isS3 {
        return rawPath
    }
    cleaned := path.Clean(rawPath)
    // path.Clean strips a trailing slash unless path is "/"; SigV4 keeps it
    // when the original path ended with one (for non-object URIs).
    if strings.HasSuffix(rawPath, "/") && cleaned != "/" {
        cleaned += "/"
    }
    return cleaned
}

// canonicalQueryString parses, sorts by name then value, and URI-encodes
// query parameters per SigV4 rules.
func canonicalQueryString(rawQuery string) string {
    if rawQuery == "" {
        return ""
    }
    values, err := url.ParseQuery(rawQuery)
    if err != nil {
        return rawQuery
    }
    names := make([]string, 0, len(values))
    for k := range values {
        names = append(names, k)
    }
    sort.Strings(names)

    var b strings.Builder
    first := true
    for _, name := range names {
        vs := append([]string(nil), values[name]...)
        sort.Strings(vs)
        for _, v := range vs {
            if !first {
                b.WriteByte('&')
            }
            first = false
            b.WriteString(url.QueryEscape(name))
            b.WriteByte('=')
            b.WriteString(url.QueryEscape(v))
        }
    }
    return b.String()
}

// canonicalHeaders emits the selected headers, lowercased name, whitespace-
// trimmed value, terminated by '\n', in the order supplied by signedHeaders.
func canonicalHeaders(hdr http.Header, signedHeaders []string) string {
    var b strings.Builder
    for _, name := range signedHeaders {
        b.WriteString(strings.ToLower(name))
        b.WriteByte(':')
        values := hdr.Values(name)
        joined := strings.Join(values, ",")
        b.WriteString(trimInnerWhitespace(joined))
        b.WriteByte('\n')
    }
    return b.String()
}

// trimInnerWhitespace trims surrounding whitespace and collapses internal
// runs of whitespace to a single space.
func trimInnerWhitespace(s string) string {
    s = strings.TrimSpace(s)
    var b strings.Builder
    prevSpace := false
    for _, r := range s {
        if r == ' ' || r == '\t' {
            if !prevSpace {
                b.WriteByte(' ')
            }
            prevSpace = true
            continue
        }
        prevSpace = false
        b.WriteRune(r)
    }
    return b.String()
}
```

- [ ] **Step 4: Run — verify pass**

Run: `go test ./internal/proxy/ -run TestCanonical`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/sigv4_signer.go internal/proxy/sigv4_signer_test.go
git commit -m "feat(proxy): add SigV4 canonical URI/query/header helpers"
```

---

### Task 8: SigV4 signing-key derivation + HMAC primitives

**Files:**
- Modify: `internal/proxy/sigv4_signer.go`
- Test: `internal/proxy/sigv4_signer_test.go`

- [ ] **Step 1: Write failing test using AWS published vector**

Append to `internal/proxy/sigv4_signer_test.go`:

```go
// AWS SigV4 signing-key derivation test vector, published at:
// https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
func TestDeriveSigningKey_PublishedVector(t *testing.T) {
    secret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    date := "20150830"
    region := "us-east-1"
    service := "iam"
    key := deriveSigningKey(secret, date, region, service)
    got := fmt.Sprintf("%x", key)
    want := "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
    if got != want {
        t.Errorf("deriveSigningKey = %s, want %s", got, want)
    }
}
```

Add the import of `fmt` to the test file if not already present.

- [ ] **Step 2: Run — verify failure**

Run: `go test ./internal/proxy/ -run TestDeriveSigningKey`
Expected: FAIL — `deriveSigningKey` undefined.

- [ ] **Step 3: Implement**

Append to `internal/proxy/sigv4_signer.go`:

```go
import (
    "crypto/hmac"
    "crypto/sha256"
)

// deriveSigningKey computes kSigning per SigV4 spec:
// kSecret  = "AWS4" + secret
// kDate    = HMAC(kSecret, date)
// kRegion  = HMAC(kDate, region)
// kService = HMAC(kRegion, service)
// kSigning = HMAC(kService, "aws4_request")
func deriveSigningKey(secretAccessKey, date, region, service string) []byte {
    kSecret := []byte("AWS4" + secretAccessKey)
    kDate := hmacSHA256(kSecret, []byte(date))
    kRegion := hmacSHA256(kDate, []byte(region))
    kService := hmacSHA256(kRegion, []byte(service))
    return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
    h := hmac.New(sha256.New, key)
    h.Write(data)
    return h.Sum(nil)
}

func sha256Hex(b []byte) string {
    sum := sha256.Sum256(b)
    return fmt.Sprintf("%x", sum)
}
```

*(Add `"fmt"` to the file's imports alongside the crypto imports.)*

- [ ] **Step 4: Run — verify pass**

Run: `go test ./internal/proxy/ -run TestDeriveSigningKey`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/sigv4_signer.go internal/proxy/sigv4_signer_test.go
git commit -m "feat(proxy): add SigV4 signing-key derivation + HMAC/SHA256 helpers"
```

---

### Task 9: Authorization header parser

**Files:**
- Modify: `internal/proxy/sigv4_signer.go`
- Test: `internal/proxy/sigv4_signer_test.go`

- [ ] **Step 1: Write failing tests**

Append to `internal/proxy/sigv4_signer_test.go`:

```go
func TestParseSigV4Authorization(t *testing.T) {
    value := "AWS4-HMAC-SHA256 " +
        "Credential=AKIAIOSFODNN7EXAMPLE/20150830/us-east-1/iam/aws4_request, " +
        "SignedHeaders=content-type;host;x-amz-date, " +
        "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
    got, err := parseSigV4Authorization(value)
    if err != nil {
        t.Fatalf("parse: %v", err)
    }
    if got.AccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
        t.Errorf("AccessKeyID = %q", got.AccessKeyID)
    }
    if got.Date != "20150830" || got.Region != "us-east-1" || got.Service != "iam" {
        t.Errorf("scope wrong: %+v", got)
    }
    if len(got.SignedHeaders) != 3 || got.SignedHeaders[0] != "content-type" {
        t.Errorf("SignedHeaders = %v", got.SignedHeaders)
    }
    if got.Signature == "" {
        t.Error("Signature empty")
    }
}

func TestParseSigV4Authorization_Malformed(t *testing.T) {
    cases := []string{
        "",
        "Bearer foo",
        "AWS4-HMAC-SHA256 Credential=missing-slashes",
        "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=xx", // no Credential
    }
    for _, c := range cases {
        if _, err := parseSigV4Authorization(c); err == nil {
            t.Errorf("expected error for %q", c)
        }
    }
}
```

- [ ] **Step 2: Run — verify failure**

Run: `go test ./internal/proxy/ -run TestParseSigV4`
Expected: FAIL — parser undefined.

- [ ] **Step 3: Implement**

Append to `internal/proxy/sigv4_signer.go`:

```go
// sigV4Auth is the parsed form of an AWS4-HMAC-SHA256 Authorization header.
type sigV4Auth struct {
    AccessKeyID   string
    Date          string
    Region        string
    Service       string
    SignedHeaders []string
    Signature     string
}

// parseSigV4Authorization parses an "AWS4-HMAC-SHA256 …" header value.
func parseSigV4Authorization(value string) (sigV4Auth, error) {
    const prefix = "AWS4-HMAC-SHA256 "
    if !strings.HasPrefix(value, prefix) {
        return sigV4Auth{}, fmt.Errorf("not a SigV4 header")
    }
    rest := value[len(prefix):]

    var (
        cred    string
        signed  string
        sig     string
        haveAll = 0
    )
    for _, part := range strings.Split(rest, ",") {
        kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
        if len(kv) != 2 {
            continue
        }
        switch kv[0] {
        case "Credential":
            cred = kv[1]
            haveAll++
        case "SignedHeaders":
            signed = kv[1]
            haveAll++
        case "Signature":
            sig = kv[1]
            haveAll++
        }
    }
    if haveAll != 3 {
        return sigV4Auth{}, fmt.Errorf("authorization missing Credential/SignedHeaders/Signature")
    }
    parts := strings.Split(cred, "/")
    if len(parts) != 5 || parts[4] != "aws4_request" {
        return sigV4Auth{}, fmt.Errorf("malformed Credential scope: %q", cred)
    }
    return sigV4Auth{
        AccessKeyID:   parts[0],
        Date:          parts[1],
        Region:        parts[2],
        Service:       parts[3],
        SignedHeaders: strings.Split(signed, ";"),
        Signature:     sig,
    }, nil
}
```

- [ ] **Step 4: Run — verify pass**

Run: `go test ./internal/proxy/ -run TestParseSigV4`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/sigv4_signer.go internal/proxy/sigv4_signer_test.go
git commit -m "feat(proxy): parse AWS SigV4 Authorization headers"
```

---

### Task 10: Full `signAWSSigV4` with AWS published test vector

**Files:**
- Modify: `internal/proxy/sigv4_signer.go`
- Test: `internal/proxy/sigv4_signer_test.go`

- [ ] **Step 1: Write failing test for full signer (AWS vector)**

AWS publishes the "get-vanilla" test case at https://github.com/aws-samples/sigv4-test-suite. Embed the expected canonical request / string-to-sign / signature values directly.

Append to `internal/proxy/sigv4_signer_test.go`:

```go
// From AWS SigV4 test suite "get-vanilla":
// https://github.com/aws-samples/sigv4-test-suite/tree/main/aws-sig-v4-test-suite
func TestSignAWSSigV4_GetVanilla(t *testing.T) {
    secret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    akid := "AKIDEXAMPLE"
    date := "20150830T123600Z"

    req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
    req.Header.Set("Host", "example.amazonaws.com")
    req.Header.Set("X-Amz-Date", date)
    // Initial Authorization uses a placeholder signature; signer replaces it.
    req.Header.Set("Authorization",
        "AWS4-HMAC-SHA256 "+
            "Credential="+akid+"/20150830/us-east-1/service/aws4_request, "+
            "SignedHeaders=host;x-amz-date, "+
            "Signature=ignored")

    cred := &vault.Credential{
        Scheme:                    "aws",
        AWSAccessKeyID:            akid,
        AWSAccessKeyIDPlaceholder: akid,
        Real:                      secret,
        Placeholder:               "VeilPH",
        AllowedHosts:              []string{"*.amazonaws.com"},
    }
    body := []byte{}
    injections, outcome := signAWSSigV4(req, body, map[string]*vault.Credential{akid: cred}, "example.amazonaws.com")
    if outcome != LocationAWSSigV4Resigned {
        t.Fatalf("outcome = %q, want aws_sigv4_resigned", outcome)
    }
    got := req.Header.Get("Authorization")
    wantSig := "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    if !strings.Contains(got, "Signature="+wantSig) {
        t.Errorf("signature mismatch.\n got=%s\n want suffix=Signature=%s", got, wantSig)
    }
    if len(injections) != 1 || injections[0].Location != LocationAWSSigV4Resigned {
        t.Errorf("injections = %+v", injections)
    }
}

func TestSignAWSSigV4_UnknownKeyFailsClosed(t *testing.T) {
    req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
    req.Header.Set("Host", "example.amazonaws.com")
    req.Header.Set("X-Amz-Date", "20150830T123600Z")
    req.Header.Set("Authorization",
        "AWS4-HMAC-SHA256 Credential=AKIAUNKNOWN/20150830/us-east-1/service/aws4_request, "+
            "SignedHeaders=host, Signature=xx")

    cred := &vault.Credential{
        Scheme:                    "aws",
        AWSAccessKeyID:            "AKIAREAL",
        AWSAccessKeyIDPlaceholder: "AKIAOTHER",
        Real:                      "secret",
        AllowedHosts:              []string{"*.amazonaws.com"},
    }
    inj, outcome := signAWSSigV4(req, nil, map[string]*vault.Credential{"AKIAOTHER": cred}, "example.amazonaws.com")
    if outcome != LocationSignerFailed {
        t.Fatalf("outcome = %q, want signer_failed", outcome)
    }
    if inj[0].SignerError != SignerErrUnknownAccessKeyID {
        t.Errorf("SignerError = %q", inj[0].SignerError)
    }
}

func TestSignAWSSigV4_NoCredentialForHost_Unmediated(t *testing.T) {
    req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
    req.Header.Set("Host", "example.amazonaws.com")
    req.Header.Set("X-Amz-Date", "20150830T123600Z")
    req.Header.Set("Authorization",
        "AWS4-HMAC-SHA256 Credential=AKIANO/20150830/us-east-1/service/aws4_request, "+
            "SignedHeaders=host, Signature=xx")
    // Empty credential map: nothing covers this host.
    inj, outcome := signAWSSigV4(req, nil, map[string]*vault.Credential{}, "example.amazonaws.com")
    if outcome != LocationSchemeUnmediated {
        t.Errorf("outcome = %q, want scheme_unmediated", outcome)
    }
    if len(inj) != 0 {
        t.Errorf("expected no injections for unmediated, got %+v", inj)
    }
}
```

- [ ] **Step 2: Run — verify failure**

Run: `go test ./internal/proxy/ -run TestSignAWSSigV4`
Expected: FAIL — `signAWSSigV4` undefined.

- [ ] **Step 3: Implement `signAWSSigV4`**

Append to `internal/proxy/sigv4_signer.go`:

```go
import (
    "github.com/8enji/veil/internal/audit"
    "github.com/8enji/veil/internal/placeholder"
    "github.com/8enji/veil/internal/vault"
    "io"
    "time"
)

// signAWSSigV4 inspects the request for an AWS4-HMAC-SHA256 Authorization
// header and, when a matching vaulted credential exists, re-signs the request
// with the real SecretAccessKey. Returns an outcome Location constant and an
// audit.Injection slice describing what happened.
//
// body is the already-buffered request body; the signer does not mutate req.Body
// (the caller remains responsible for that).
func signAWSSigV4(req *http.Request, body []byte, creds map[string]*vault.Credential, host string) ([]audit.Injection, string) {
    // Detection.
    auth := req.Header.Get("Authorization")
    if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
        return nil, ""
    }

    parsed, err := parseSigV4Authorization(auth)
    if err != nil {
        return []audit.Injection{failInjection(host, req, SignerErrAuthorizationMalformed)}, LocationSignerFailed
    }

    // Credential lookup via the placeholder map: the SDK embedded our
    // AWSAccessKeyIDPlaceholder into the Credential= scope. We match on the
    // typed AWSAccessKeyID field rather than c.Scheme so a corrupted Scheme
    // string cannot cause wrong-signer dispatch (per spec §131-134).
    cred, lookupOK := creds[parsed.AccessKeyID]
    if !lookupOK || cred.AWSAccessKeyID == "" || !placeholder.HostMatches(host, cred.AllowedHosts) {
        // Check whether *any* aws credential covers this host. If so,
        // fail-closed; otherwise, let the request pass unchanged.
        if veilOwnsAWSHost(creds, host) {
            return []audit.Injection{failInjection(host, req, SignerErrUnknownAccessKeyID)}, LocationSignerFailed
        }
        return nil, LocationSchemeUnmediated
    }

    // Session-token sanity.
    reqTok := req.Header.Get("X-Amz-Security-Token")
    switch {
    case cred.AWSSessionToken == "" && reqTok != "":
        return []audit.Injection{failInjection(host, req, SignerErrUnexpectedSessionToken)}, LocationSignerFailed
    case cred.AWSSessionToken != "" && reqTok == "":
        return []audit.Injection{failInjection(host, req, SignerErrMissingSessionToken)}, LocationSignerFailed
    }

    // Mutate header set: replace placeholder AKID with real; swap session token.
    beforeLen := len(auth)
    newAuth := strings.Replace(auth,
        "Credential="+parsed.AccessKeyID+"/",
        "Credential="+cred.AWSAccessKeyID+"/",
        1)
    req.Header.Set("Authorization", newAuth)
    if cred.AWSSessionToken != "" {
        req.Header.Set("X-Amz-Security-Token", cred.AWSSessionToken)
    }

    // Recompute canonical request.
    isS3 := strings.HasPrefix(parsed.Service, "s3")
    canonURI := canonicalURI(req.URL.Path, isS3)
    canonQuery := canonicalQueryString(req.URL.RawQuery)
    canonHeaders := canonicalHeaders(req.Header, parsed.SignedHeaders)
    signed := strings.Join(parsed.SignedHeaders, ";")

    var payloadHash string
    if req.Header.Get("X-Amz-Content-Sha256") == "UNSIGNED-PAYLOAD" {
        payloadHash = "UNSIGNED-PAYLOAD"
    } else {
        payloadHash = sha256Hex(body)
        // Update the header so canonicalHeaders above used the same value.
        if req.Header.Get("X-Amz-Content-Sha256") != "" {
            req.Header.Set("X-Amz-Content-Sha256", payloadHash)
            canonHeaders = canonicalHeaders(req.Header, parsed.SignedHeaders)
        }
    }

    canonReq := req.Method + "\n" +
        canonURI + "\n" +
        canonQuery + "\n" +
        canonHeaders + "\n" +
        signed + "\n" +
        payloadHash

    scope := parsed.Date + "/" + parsed.Region + "/" + parsed.Service + "/aws4_request"
    stringToSign := "AWS4-HMAC-SHA256\n" +
        req.Header.Get("X-Amz-Date") + "\n" +
        scope + "\n" +
        sha256Hex([]byte(canonReq))

    key := deriveSigningKey(cred.Real, parsed.Date, parsed.Region, parsed.Service)
    newSig := fmt.Sprintf("%x", hmacSHA256(key, []byte(stringToSign)))

    // Swap Signature=<old> with Signature=<new>.
    finalAuth := strings.Replace(req.Header.Get("Authorization"),
        "Signature="+parsed.Signature, "Signature="+newSig, 1)
    req.Header.Set("Authorization", finalAuth)

    return []audit.Injection{{
        Timestamp:      time.Now(),
        Host:           host,
        CredentialID:   cred.ID,
        CredentialName: cred.Name,
        BytesBefore:    beforeLen,
        BytesAfter:     len(finalAuth),
        Location:       LocationAWSSigV4Resigned,
    }}, LocationAWSSigV4Resigned
}

func veilOwnsAWSHost(creds map[string]*vault.Credential, host string) bool {
    seen := map[*vault.Credential]bool{}
    for _, c := range creds {
        // Match on the typed field (per spec §131-134) so a corrupt Scheme
        // doesn't hide/expose AWS credentials.
        if seen[c] || c.AWSAccessKeyID == "" {
            continue
        }
        seen[c] = true
        if placeholder.HostMatches(host, c.AllowedHosts) {
            return true
        }
    }
    return false
}

func failInjection(host string, req *http.Request, errClass string) audit.Injection {
    return audit.Injection{
        Timestamp:   time.Now(),
        Host:        host,
        Method:      req.Method,
        URLPath:     req.URL.Path,
        Location:    LocationSignerFailed,
        SignerError: errClass,
    }
}

// unused but kept to satisfy the import if Placeholder.HostMatches changes.
var _ = io.Discard
```

*(Remove the `var _ = io.Discard` and the `io` import if `HostMatches` is the only placeholder import needed.)*

- [ ] **Step 4: Run — verify all three tests pass**

Run: `go test ./internal/proxy/ -run TestSignAWSSigV4`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/sigv4_signer.go internal/proxy/sigv4_signer_test.go
git commit -m "feat(proxy): implement signAWSSigV4 with re-sign, unmediated, fail-closed"
```

---

### Task 11: Wire `signAWSSigV4` into `ProcessRequest`

**Files:**
- Modify: `internal/proxy/injector.go`
- Test: `internal/proxy/injector_test.go`

- [ ] **Step 1: Write failing integration-style test**

Append to `internal/proxy/injector_test.go`:

```go
func TestProcessRequest_WiresSigV4Signer(t *testing.T) {
    cred := &vault.Credential{
        ID:                        "c1",
        Name:                      "aws-prod",
        Scheme:                    "aws",
        Real:                      "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        AWSAccessKeyID:            "AKIDEXAMPLE",
        AWSAccessKeyIDPlaceholder: "AKIAPHEXAMPLE12345",
        AllowedHosts:              []string{"*.amazonaws.com"},
    }
    pmap := map[string]*vault.Credential{
        "AKIAPHEXAMPLE12345": cred, // placeholder -> cred
    }
    inj := NewInjector(pmap, nil, 0, "")

    hdr := http.Header{}
    hdr.Set("Host", "example.amazonaws.com")
    hdr.Set("X-Amz-Date", "20150830T123600Z")
    hdr.Set("Authorization",
        "AWS4-HMAC-SHA256 "+
            "Credential=AKIAPHEXAMPLE12345/20150830/us-east-1/service/aws4_request, "+
            "SignedHeaders=host;x-amz-date, "+
            "Signature=ignored")

    _, newHeader, _, injections := inj.ProcessRequest("req-1", "GET",
        "https://example.amazonaws.com/", hdr, nil)

    got := newHeader.Get("Authorization")
    if !strings.Contains(got, "Credential=AKIDEXAMPLE/") {
        t.Errorf("AccessKeyID not rewritten: %s", got)
    }
    if !strings.Contains(got, "Signature=") || strings.Contains(got, "Signature=ignored") {
        t.Errorf("Signature not recomputed: %s", got)
    }
    sawResign := false
    for _, i := range injections {
        if i.Location == LocationAWSSigV4Resigned {
            sawResign = true
        }
    }
    if !sawResign {
        t.Errorf("no aws_sigv4_resigned injection; got %+v", injections)
    }
}
```

- [ ] **Step 2: Run — verify failure**

Run: `go test ./internal/proxy/ -run TestProcessRequest_WiresSigV4Signer`
Expected: FAIL — signer not invoked.

- [ ] **Step 3: Invoke `signAWSSigV4` after the Basic pre-pass**

Edit `internal/proxy/injector.go`. Immediately after `decodeAndSwapBasic(…)` and before the literal header scan, construct a minimal `*http.Request` stand-in or pass the pieces directly. Since `signAWSSigV4` takes `*http.Request`, build a throwaway request object for signer re-entry:

```go
    // --- AWS SigV4 signer ---
    shim := &http.Request{
        Method: method,
        Header: newHeader,
    }
    if u, err := url.Parse(newURL); err == nil {
        shim.URL = u
    } else {
        shim.URL = &url.URL{}
    }
    awsInjs, _ := signAWSSigV4(shim, body, creds, host)
    for _, s := range awsInjs {
        s.RequestID = requestID
        s.Method = method
        s.URLPath = urlPath
        s.AgentPID = inj.agentPID
        s.AgentCmd = inj.agentCmd
        injections = append(injections, s)
    }
    // signAWSSigV4 may have mutated shim.Header; persist those changes.
    newHeader = shim.Header
```

Add `"net/url"` to imports if not present (it already is) and `"net/http"` (already present).

- [ ] **Step 4: Run — verify pass**

Run: `go test ./internal/proxy/ -run TestProcessRequest_WiresSigV4Signer`
Expected: PASS

- [ ] **Step 5: Run the full proxy suite to check for regressions**

Run: `go test ./internal/proxy/...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/injector.go internal/proxy/injector_test.go
git commit -m "feat(proxy): invoke signAWSSigV4 in the injector pipeline"
```

---

### Task 12: Fail-closed 502 on signer_failed

**Files:**
- Modify: `internal/proxy/proxy.go:150-177`
- Test: `internal/proxy/failclosed_test.go`

- [ ] **Step 1: Write failing test**

Append to `internal/proxy/failclosed_test.go`:

```go
func TestProxy_FailsClosedOnSignerFailure(t *testing.T) {
    cred := &vault.Credential{
        ID:                        "c1",
        Name:                      "aws-prod",
        Scheme:                    "aws",
        Real:                      "secret",
        AWSAccessKeyID:            "AKIAREAL000000000000",
        AWSAccessKeyIDPlaceholder: "AKIAPH00000000000000",
        AllowedHosts:              []string{"*.amazonaws.com"},
    }
    vlt := newTestVaultWith(t, cred)
    srv := startProxyForTest(t, vlt)
    defer srv.Stop()

    // Deliberately send an SDK-signed header whose placeholder AKID is NOT
    // in the vault but Veil owns the host for this scheme.
    req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
    req.Header.Set("X-Amz-Date", "20150830T123600Z")
    req.Header.Set("Authorization",
        "AWS4-HMAC-SHA256 Credential=AKIAUNKNOWNXXXXXXXX/20150830/us-east-1/service/aws4_request, "+
            "SignedHeaders=host;x-amz-date, Signature=xx")

    resp := roundTripThroughProxy(t, srv, req)
    if resp.StatusCode != http.StatusBadGateway {
        t.Fatalf("status = %d, want 502", resp.StatusCode)
    }
}
```

*(`newTestVaultWith`, `startProxyForTest`, `roundTripThroughProxy` exist in `internal/proxy/*_test.go` helpers; use the real names from `failclosed_test.go` and `basic_integration_test.go`.)*

- [ ] **Step 2: Run — verify failure**

Run: `go test ./internal/proxy/ -run TestProxy_FailsClosedOnSignerFailure`
Expected: FAIL — signer failure is not currently translated to a 502.

- [ ] **Step 3: Extend `proxy.go` fail-closed check**

In `internal/proxy/proxy.go`, after `newURL, newHeader, newBody, _ := inj.ProcessRequest(...)`, change the underscore to receive the injections slice and add a firstSignerFailure check *before* the existing `detectLeak` check:

```go
    newURL, newHeader, newBody, injections := inj.ProcessRequest(
        requestID, req.Method, req.URL.String(), req.Header, body)

    if sf := firstSignerFailure(injections); sf != nil {
        ui.Warnf(os.Stderr, "veil: refusing to forward request to %s — signer failed (%s)", req.Host, sf.SignerError)
        resp := goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadGateway,
            fmt.Sprintf("veil: signer failed (%s); request blocked (see audit log)", sf.SignerError))
        resp.Header.Set("X-Veil-Error", sf.SignerError)
        return req, resp
    }
```

*(The existing `detectLeak` path below remains unchanged.)*

- [ ] **Step 4: Run — verify pass**

Run: `go test ./internal/proxy/ -run TestProxy_FailsClosedOnSignerFailure`
Expected: PASS

- [ ] **Step 5: Run full proxy suite**

Run: `go test ./internal/proxy/...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/proxy.go internal/proxy/failclosed_test.go
git commit -m "feat(proxy): return 502 + X-Veil-Error on signer_failed injections"
```

---

## Phase 3 — GitHub App JWT signer

### Task 13: JWT helpers (base64url + deterministic JSON)

**Files:**
- Create: `internal/proxy/jwt.go`
- Test: `internal/proxy/jwt_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/proxy/jwt_test.go`:

```go
package proxy

import (
    "strings"
    "testing"
)

func TestBase64URL_RoundTrip(t *testing.T) {
    in := []byte{0xFF, 0x00, 0x10, 0x20, 0x7F}
    enc := base64URLEncode(in)
    if strings.ContainsAny(enc, "+/=") {
        t.Errorf("base64url should not contain +, /, or =: %q", enc)
    }
    out, err := base64URLDecode(enc)
    if err != nil {
        t.Fatal(err)
    }
    if string(out) != string(in) {
        t.Errorf("round-trip mismatch: %v vs %v", in, out)
    }
}

func TestDeterministicJSON_PreservesKeyOrder(t *testing.T) {
    in := []byte(`{"iss":123,"iat":1700000000,"exp":1700000600}`)
    got, err := reserializeDeterministic(in)
    if err != nil {
        t.Fatal(err)
    }
    if string(got) != string(in) {
        t.Errorf("reserialize reordered keys:\n got=%s\nwant=%s", got, in)
    }
}

func TestDeterministicJSON_PreservesNumericForm(t *testing.T) {
    // iss as an int must stay as an int, not stringified.
    in := []byte(`{"iss":42}`)
    got, err := reserializeDeterministic(in)
    if err != nil {
        t.Fatal(err)
    }
    if string(got) != string(in) {
        t.Errorf("numeric form lost: got %s", got)
    }
}
```

- [ ] **Step 2: Run — verify failure**

Run: `go test ./internal/proxy/ -run "TestBase64URL|TestDeterministicJSON"`
Expected: FAIL — helpers undefined.

- [ ] **Step 3: Implement**

Create `internal/proxy/jwt.go`:

```go
package proxy

import (
    "bytes"
    "encoding/base64"
    "encoding/json"
    "fmt"
)

// base64URLEncode returns the base64url-no-padding encoding (JWT form).
func base64URLEncode(b []byte) string {
    return base64.RawURLEncoding.EncodeToString(b)
}

// base64URLDecode decodes base64url with optional padding.
func base64URLDecode(s string) ([]byte, error) {
    if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
        return b, nil
    }
    return base64.URLEncoding.DecodeString(s)
}

// reserializeDeterministic takes a JSON object as bytes and returns it
// re-serialized with the original key order preserved. It uses a token-level
// streaming decode (encoding/json Decoder) to walk the input one token at
// a time, so key order is observed rather than imposed by map iteration.
//
// Only flat objects with scalar / array / nested-object values are handled —
// which is sufficient for JWT headers and payloads.
func reserializeDeterministic(raw []byte) ([]byte, error) {
    dec := json.NewDecoder(bytes.NewReader(raw))
    dec.UseNumber()

    tok, err := dec.Token()
    if err != nil {
        return nil, err
    }
    if d, ok := tok.(json.Delim); !ok || d != '{' {
        return nil, fmt.Errorf("expected object")
    }

    var out bytes.Buffer
    out.WriteByte('{')
    first := true
    for dec.More() {
        // Key.
        kTok, err := dec.Token()
        if err != nil {
            return nil, err
        }
        key, ok := kTok.(string)
        if !ok {
            return nil, fmt.Errorf("non-string key")
        }
        // Value (possibly nested; for simplicity we consume the full value
        // into a json.RawMessage).
        var value json.RawMessage
        if err := dec.Decode(&value); err != nil {
            return nil, err
        }
        if !first {
            out.WriteByte(',')
        }
        first = false
        kb, _ := json.Marshal(key)
        out.Write(kb)
        out.WriteByte(':')
        out.Write(value)
    }
    // Closing '}'.
    if _, err := dec.Token(); err != nil {
        return nil, err
    }
    out.WriteByte('}')
    return out.Bytes(), nil
}
```

*(Note: `dec.Decode(&json.RawMessage)` after reading a key reads the next value into raw bytes. This relies on the Decoder's internal state being positioned at the value; this is a documented pattern for streaming decode.)*

- [ ] **Step 4: Run — verify pass**

Run: `go test ./internal/proxy/ -run "TestBase64URL|TestDeterministicJSON"`
Expected: PASS

If the RawMessage-after-key path doesn't work with `Decode`, switch to a simpler implementation that reads all tokens into a slice of `{key, rawValue}` pairs using the token stream. Keep the test assertions identical.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/jwt.go internal/proxy/jwt_test.go
git commit -m "feat(proxy): add JWT base64url and deterministic-JSON helpers"
```

---

### Task 14: RSA PEM placeholder generator

**Files:**
- Modify: `internal/placeholder/provider_github.go`
- Test: `internal/placeholder/provider_github_test.go` (create)

- [ ] **Step 1: Write failing test**

Create `internal/placeholder/provider_github_test.go`:

```go
package placeholder

import (
    "crypto/x509"
    "encoding/pem"
    "strings"
    "testing"
)

func TestGenerateGitHubAppPrivateKey_IsValidRSAPEM(t *testing.T) {
    p, err := GenerateGitHubAppPrivateKey()
    if err != nil {
        t.Fatal(err)
    }
    if !strings.HasPrefix(p, "-----BEGIN RSA PRIVATE KEY-----") {
        t.Errorf("missing PKCS#1 PEM header: %s", p[:80])
    }
    block, _ := pem.Decode([]byte(p))
    if block == nil {
        t.Fatal("pem.Decode returned nil")
    }
    key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        t.Fatalf("parse: %v", err)
    }
    if key.N.BitLen() != 2048 {
        t.Errorf("key bit length = %d, want 2048", key.N.BitLen())
    }
}

func TestGenerateGitHubAppPrivateKey_FreshEachCall(t *testing.T) {
    a, _ := GenerateGitHubAppPrivateKey()
    b, _ := GenerateGitHubAppPrivateKey()
    if a == b {
        t.Error("two calls returned the same PEM (keygen deterministic?)")
    }
}
```

- [ ] **Step 2: Run — verify failure**

Run: `go test ./internal/placeholder/ -run TestGenerateGitHubAppPrivateKey`
Expected: FAIL — function undefined.

- [ ] **Step 3: Implement**

Append to `internal/placeholder/provider_github.go`:

```go
import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
)

// GenerateGitHubAppPrivateKey produces a fresh RSA 2048 keypair encoded as
// a PKCS#1 PEM string. Used as the placeholder for GitHub App credentials:
// the SDK loads this PEM and signs a JWT locally; the proxy detects the
// JWT via its `iss` claim and re-signs with the real vaulted PEM.
//
// The placeholder itself does not embed the placeholder.Sentinel — RSA PEM
// bytes cannot carry the sentinel without breaking PEM parsing. See
// THREAT_MODEL.md for the scoped detectLeak gap.
func GenerateGitHubAppPrivateKey() (string, error) {
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return "", err
    }
    der := x509.MarshalPKCS1PrivateKey(key)
    block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
    return string(pem.EncodeToMemory(block)), nil
}
```

- [ ] **Step 4: Run — verify pass**

Run: `go test ./internal/placeholder/ -run TestGenerateGitHubAppPrivateKey`
Expected: PASS (note: each call runs RSA keygen, ~50-200ms).

- [ ] **Step 5: Commit**

```bash
git add internal/placeholder/provider_github.go internal/placeholder/provider_github_test.go
git commit -m "feat(placeholder): add GenerateGitHubAppPrivateKey (fresh RSA 2048 PKCS#1 PEM)"
```

---

### Task 15: CLI `--scheme github_app`

**Files:**
- Modify: `internal/cli/add.go`
- Test: `internal/cli/add_test.go`

- [ ] **Step 1: Write failing test**

Append to `internal/cli/add_test.go`:

```go
func TestAddCmd_SchemeGitHubApp_HappyPath(t *testing.T) {
    dir := t.TempDir()
    initProject(t, dir)

    // Minimal valid RSA PEM (generated once; embed as a test fixture).
    realPEM := testRSAKeyPEM(t)

    cmd := RootCmd()
    cmd.SetOut(io.Discard)
    cmd.SetErr(io.Discard)
    cmd.SetIn(strings.NewReader(realPEM))
    cmd.SetArgs([]string{
        "add", "gh-app",
        "--scheme", "github_app",
        "--github-app-id", "123456",
        "--host", "api.github.com",
        "--value-stdin",
    })
    if err := cmd.Execute(); err != nil {
        t.Fatalf("add: %v", err)
    }

    cred, _ := openVaultInDir(t, dir).Get("gh-app")
    if cred.Scheme != "github_app" {
        t.Errorf("Scheme = %q", cred.Scheme)
    }
    if cred.GitHubAppID != 123456 {
        t.Errorf("AppID = %d", cred.GitHubAppID)
    }
    if !strings.HasPrefix(cred.Placeholder, "-----BEGIN RSA PRIVATE KEY-----") {
        t.Errorf("placeholder not PEM: %s", cred.Placeholder[:80])
    }
    if cred.Placeholder == cred.Real {
        t.Error("placeholder PEM should differ from real PEM")
    }
}

// Spec §167-171: write a GitHub App credential whose placeholder is a multi-
// line PEM, confirm the .env file gets the PEM written in double-quoted form
// with \n escapes, and re-parsing the .env file restores the placeholder
// byte-identically.
func TestAddCmd_SchemeGitHubApp_MultiLinePEMEnvRoundTrip(t *testing.T) {
    dir := t.TempDir()
    initProject(t, dir)
    realPEM := testRSAKeyPEM(t)

    // Pre-create a .env file so the add command has somewhere to sync to.
    envPath := filepath.Join(dir, ".env")
    if err := os.WriteFile(envPath, []byte("GITHUB_APP_PRIVATE_KEY=\n"), 0600); err != nil {
        t.Fatal(err)
    }

    cmd := RootCmd()
    cmd.SetOut(io.Discard)
    cmd.SetErr(io.Discard)
    cmd.SetIn(strings.NewReader(realPEM))
    cmd.SetArgs([]string{
        "add", "GITHUB_APP_PRIVATE_KEY",
        "--scheme", "github_app",
        "--github-app-id", "123456",
        "--host", "api.github.com",
        "--value-stdin",
    })
    if err := cmd.Execute(); err != nil {
        t.Fatalf("add: %v", err)
    }

    cred, _ := openVaultInDir(t, dir).Get("GITHUB_APP_PRIVATE_KEY")
    if cred.Placeholder == "" {
        t.Fatal("no placeholder stored")
    }

    // Round-trip: parse the .env file and extract the value for the key.
    // The scanner must decode \n-escaped double-quoted form back to the
    // original multi-line PEM bytes.
    ef, err := scanner.ParseFile(envPath)
    if err != nil {
        t.Fatal(err)
    }
    got, ok := ef.Lookup("GITHUB_APP_PRIVATE_KEY")
    if !ok {
        t.Fatal(".env missing GITHUB_APP_PRIVATE_KEY after add")
    }
    if got != cred.Placeholder {
        t.Errorf(".env round-trip mismatch\n got=%q\nwant=%q", got, cred.Placeholder)
    }
    // Sanity: raw file bytes contain the \n escape form (double-quoted).
    raw, _ := os.ReadFile(envPath)
    if !strings.Contains(string(raw), `\n`) {
        t.Errorf("expected \\n-escaped multi-line form in .env; got:\n%s", raw)
    }
}

func TestAddCmd_SchemeGitHubApp_RejectsNonPEM(t *testing.T) {
    dir := t.TempDir()
    initProject(t, dir)
    cmd := RootCmd()
    cmd.SetOut(io.Discard)
    cmd.SetErr(io.Discard)
    cmd.SetIn(strings.NewReader("not a pem"))
    cmd.SetArgs([]string{
        "add", "gh-app",
        "--scheme", "github_app",
        "--github-app-id", "123",
        "--value-stdin",
    })
    if err := cmd.Execute(); err == nil {
        t.Fatal("expected error on non-PEM input")
    }
}

// testRSAKeyPEM returns a valid 2048-bit RSA key in PKCS#1 PEM form for
// use in tests. Generated once per test binary load.
func testRSAKeyPEM(t *testing.T) string {
    t.Helper()
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatal(err)
    }
    block := &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(key),
    }
    return string(pem.EncodeToMemory(block))
}
```

Add the imports `crypto/rand`, `crypto/rsa`, `crypto/x509`, `encoding/pem`, `os`, `path/filepath`, and `github.com/8enji/veil/internal/scanner` to the test file.

- [ ] **Step 2: Run — verify failure**

Run: `go test ./internal/cli/... -run TestAddCmd_SchemeGitHubApp`
Expected: FAIL.

- [ ] **Step 3: Extend `runAddInVault` with a `github_app` branch**

In `internal/cli/add.go`, add the branch after the AWS block:

```go
if opts.scheme == "github_app" {
    if opts.username != "" {
        return cliError("--user is not valid with --scheme github_app", "")
    }
    if opts.githubAppID <= 0 {
        return cliError("--github-app-id must be > 0 for --scheme github_app", "")
    }
    if err := validateRSAPEM(value); err != nil {
        return cliErrorf("--value must be an RSA PEM private key: %v", err)
    }
    placeholderPEM, err := placeholder.GenerateGitHubAppPrivateKey()
    if err != nil {
        return cliErrorf("generating placeholder key: %v", err)
    }

    cred := &vault.Credential{
        ID:                   vault.NewID(),
        Name:                 name,
        Real:                 value,
        Placeholder:          placeholderPEM,
        Source:               "manual",
        AllowedHosts:         allowedHosts,
        CreatedAt:            time.Now(),
        Scheme:               "github_app",
        GitHubAppID:          opts.githubAppID,
        GitHubInstallationID: opts.githubInstallationID,
    }
    if err := v.Add(cred); err != nil {
        return cliErrorf("adding credential: %v", err)
    }
    ui.Step(cmd.OutOrStdout(), fmt.Sprintf("Added %s to vault (github_app)", name))
    fmt.Fprintf(cmd.OutOrStdout(), "    %s %d\n", ui.Muted.Sprint("App ID:"), opts.githubAppID)
    fmt.Fprintf(cmd.OutOrStdout(), "    %s <generated RSA PEM — %d bytes>\n", ui.Muted.Sprint("Private key placeholder:"), len(placeholderPEM))
    if len(allowedHosts) > 0 {
        fmt.Fprintf(cmd.OutOrStdout(), "    %s %s\n", ui.Muted.Sprint("Hosts:"), strings.Join(allowedHosts, ", "))
    }
    return nil
}
```

Add `validateRSAPEM`:

```go
func validateRSAPEM(value string) error {
    block, _ := pem.Decode([]byte(value))
    if block == nil {
        return fmt.Errorf("no PEM block found")
    }
    if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
        return nil
    }
    if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
        return nil
    }
    return fmt.Errorf("not an RSA private key (PKCS#1 or PKCS#8)")
}
```

Add imports: `encoding/pem`, `crypto/x509`.

- [ ] **Step 4: Run — verify pass**

Run: `go test ./internal/cli/... -run TestAddCmd_SchemeGitHubApp`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/cli/add.go internal/cli/add_test.go
git commit -m "feat(cli): add --scheme github_app with app-id and PEM validation"
```

---

### Task 16: `signGitHubAppJWT`

**Files:**
- Create: `internal/proxy/github_app_signer.go`
- Test: `internal/proxy/github_app_signer_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/proxy/github_app_signer_test.go`:

```go
package proxy

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "net/http"
    "strings"
    "testing"

    "github.com/8enji/veil/internal/vault"
)

func genPEM(t *testing.T) (*rsa.PrivateKey, string) {
    t.Helper()
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatal(err)
    }
    block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
    return key, string(pem.EncodeToMemory(block))
}

func signJWT(t *testing.T, key *rsa.PrivateKey, iss int64) string {
    t.Helper()
    header := `{"alg":"RS256","typ":"JWT"}`
    payload := `{"iss":` + strconv.FormatInt(iss, 10) + `,"iat":1700000000,"exp":1700000600}`
    input := base64URLEncode([]byte(header)) + "." + base64URLEncode([]byte(payload))
    h := sha256.Sum256([]byte(input))
    sig, err := rsa.SignPKCS1v15(rand.Reader, key, 0, h[:])
    if err != nil {
        t.Fatal(err)
    }
    return input + "." + base64URLEncode(sig)
}

func TestSignGitHubAppJWT_HappyPath(t *testing.T) {
    realKey, realPEM := genPEM(t)
    placeholderKey, placeholderPEM := genPEM(t)

    cred := &vault.Credential{
        ID:           "c1",
        Name:         "gh-app",
        Scheme:       "github_app",
        Real:         realPEM,
        Placeholder:  placeholderPEM,
        GitHubAppID:  123456,
        AllowedHosts: []string{"api.github.com"},
    }
    creds := map[string]*vault.Credential{placeholderPEM: cred}

    // Agent signs a JWT with the placeholder key.
    jwt := signJWT(t, placeholderKey, 123456)
    req, _ := http.NewRequest("POST", "https://api.github.com/app/installations", nil)
    req.Header.Set("Authorization", "Bearer "+jwt)

    inj, outcome := signGitHubAppJWT(req, creds, "api.github.com")
    if outcome != LocationGitHubAppJWTResigned {
        t.Fatalf("outcome = %q", outcome)
    }

    // Verify the new JWT verifies against the real key.
    newJWT := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
    parts := strings.Split(newJWT, ".")
    if len(parts) != 3 {
        t.Fatalf("new JWT not 3-part: %s", newJWT)
    }
    signingInput := parts[0] + "." + parts[1]
    sig, err := base64URLDecode(parts[2])
    if err != nil {
        t.Fatal(err)
    }
    h := sha256.Sum256([]byte(signingInput))
    if err := rsa.VerifyPKCS1v15(&realKey.PublicKey, 0, h[:], sig); err != nil {
        t.Errorf("new JWT does not verify with real key: %v", err)
    }
    _ = placeholderKey
    if len(inj) != 1 || inj[0].Location != LocationGitHubAppJWTResigned {
        t.Errorf("injections = %+v", inj)
    }
}

func TestSignGitHubAppJWT_UnknownIssFailsClosed(t *testing.T) {
    _, placeholderPEM := genPEM(t)
    key, _ := genPEM(t) // Use a different key so we don't actually need the real one
    cred := &vault.Credential{
        Scheme:       "github_app",
        Real:         placeholderPEM,
        Placeholder:  placeholderPEM,
        GitHubAppID:  111,
        AllowedHosts: []string{"api.github.com"},
    }
    creds := map[string]*vault.Credential{placeholderPEM: cred}
    jwt := signJWT(t, key, 999) // iss does not match GitHubAppID

    req, _ := http.NewRequest("POST", "https://api.github.com/", nil)
    req.Header.Set("Authorization", "Bearer "+jwt)

    inj, outcome := signGitHubAppJWT(req, creds, "api.github.com")
    if outcome != LocationSignerFailed {
        t.Fatalf("outcome = %q", outcome)
    }
    if inj[0].SignerError != SignerErrUnknownGitHubAppID {
        t.Errorf("SignerError = %q", inj[0].SignerError)
    }
}

func TestSignGitHubAppJWT_PATIgnored(t *testing.T) {
    req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
    req.Header.Set("Authorization", "Bearer ghp_1234567890abcdef")
    _, outcome := signGitHubAppJWT(req, map[string]*vault.Credential{}, "api.github.com")
    if outcome != "" {
        t.Errorf("outcome should be empty for PAT, got %q", outcome)
    }
}

func TestSignGitHubAppJWT_NoCredentialForHost_Unmediated(t *testing.T) {
    key, _ := genPEM(t)
    jwt := signJWT(t, key, 42)
    req, _ := http.NewRequest("GET", "https://api.github.com/app", nil)
    req.Header.Set("Authorization", "Bearer "+jwt)
    // Empty credential map: no github_app cred covers this host.
    _, outcome := signGitHubAppJWT(req, map[string]*vault.Credential{}, "api.github.com")
    if outcome != LocationSchemeUnmediated {
        t.Errorf("outcome = %q", outcome)
    }
}
```

Add `strconv` to the imports if not already present.

- [ ] **Step 2: Run — verify failure**

Run: `go test ./internal/proxy/ -run TestSignGitHubAppJWT`
Expected: FAIL — `signGitHubAppJWT` undefined.

- [ ] **Step 3: Implement**

Create `internal/proxy/github_app_signer.go`:

```go
package proxy

import (
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/json"
    "encoding/pem"
    "errors"
    "fmt"
    "net/http"
    "strconv"
    "strings"
    "time"

    "github.com/8enji/veil/internal/audit"
    "github.com/8enji/veil/internal/placeholder"
    "github.com/8enji/veil/internal/vault"
)

// signGitHubAppJWT inspects the Authorization header for an RS256 JWT with
// an integer `iss` claim matching a vaulted GitHub App credential, and
// re-signs it with the real private key.
func signGitHubAppJWT(req *http.Request, creds map[string]*vault.Credential, host string) ([]audit.Injection, string) {
    auth := req.Header.Get("Authorization")
    const prefix = "Bearer "
    if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
        return nil, ""
    }
    token := strings.TrimSpace(auth[len(prefix):])
    parts := strings.Split(token, ".")
    if len(parts) != 3 {
        return nil, ""
    }

    headerJSON, err := base64URLDecode(parts[0])
    if err != nil {
        return nil, ""
    }
    payloadJSON, err := base64URLDecode(parts[1])
    if err != nil {
        return nil, ""
    }
    var headerObj map[string]json.RawMessage
    if err := json.Unmarshal(headerJSON, &headerObj); err != nil {
        return nil, ""
    }
    if unquote(headerObj["alg"]) != "RS256" || unquote(headerObj["typ"]) != "JWT" {
        return nil, "" // not our scheme
    }

    // Parse iss.
    var payloadObj map[string]json.RawMessage
    if err := json.Unmarshal(payloadJSON, &payloadObj); err != nil {
        return nil, ""
    }
    issRaw, ok := payloadObj["iss"]
    if !ok {
        return nil, ""
    }
    iss, err := parseIssInt(issRaw)
    if err != nil {
        return nil, ""
    }

    // Credential lookup.
    cred := lookupGitHubAppCred(creds, iss, host)
    if cred == nil {
        if veilOwnsGitHubAppHost(creds, host) {
            return []audit.Injection{failInjection(host, req, SignerErrUnknownGitHubAppID)}, LocationSignerFailed
        }
        return nil, LocationSchemeUnmediated
    }

    // Decode the real private key.
    block, _ := pem.Decode([]byte(cred.Real))
    if block == nil {
        return []audit.Injection{failInjection(host, req, SignerErrRSASignFailed)}, LocationSignerFailed
    }
    realKey, parseErr := parseRSAPrivateKey(block.Bytes)
    if parseErr != nil {
        return []audit.Injection{failInjection(host, req, SignerErrRSASignFailed)}, LocationSignerFailed
    }

    // Re-serialize header/payload deterministically.
    hdrBytes, err := reserializeDeterministic(headerJSON)
    if err != nil {
        hdrBytes = headerJSON
    }
    pldBytes, err := reserializeDeterministic(payloadJSON)
    if err != nil {
        pldBytes = payloadJSON
    }
    signingInput := base64URLEncode(hdrBytes) + "." + base64URLEncode(pldBytes)
    h := sha256.Sum256([]byte(signingInput))
    sig, err := rsa.SignPKCS1v15(rand.Reader, realKey, crypto.SHA256, h[:])
    if err != nil {
        return []audit.Injection{failInjection(host, req, SignerErrRSASignFailed)}, LocationSignerFailed
    }
    newJWT := signingInput + "." + base64URLEncode(sig)

    beforeLen := len(auth)
    req.Header.Set("Authorization", "Bearer "+newJWT)

    return []audit.Injection{{
        Timestamp:      time.Now(),
        Host:           host,
        CredentialID:   cred.ID,
        CredentialName: cred.Name,
        BytesBefore:    beforeLen,
        BytesAfter:     len("Bearer " + newJWT),
        Location:       LocationGitHubAppJWTResigned,
    }}, LocationGitHubAppJWTResigned
}

func lookupGitHubAppCred(creds map[string]*vault.Credential, iss int64, host string) *vault.Credential {
    seen := map[*vault.Credential]bool{}
    for _, c := range creds {
        // Match on the typed GitHubAppID field (per spec §131-134) so a
        // corrupt Scheme can't cause wrong-signer dispatch.
        if seen[c] || c.GitHubAppID == 0 {
            continue
        }
        seen[c] = true
        if c.GitHubAppID == iss && placeholder.HostMatches(host, c.AllowedHosts) {
            return c
        }
    }
    return nil
}

func veilOwnsGitHubAppHost(creds map[string]*vault.Credential, host string) bool {
    seen := map[*vault.Credential]bool{}
    for _, c := range creds {
        if seen[c] || c.GitHubAppID == 0 {
            continue
        }
        seen[c] = true
        if placeholder.HostMatches(host, c.AllowedHosts) {
            return true
        }
    }
    return false
}

func unquote(raw json.RawMessage) string {
    if len(raw) == 0 {
        return ""
    }
    var s string
    if err := json.Unmarshal(raw, &s); err != nil {
        return ""
    }
    return s
}

func parseIssInt(raw json.RawMessage) (int64, error) {
    var asInt int64
    if err := json.Unmarshal(raw, &asInt); err == nil {
        return asInt, nil
    }
    var asStr string
    if err := json.Unmarshal(raw, &asStr); err == nil {
        return strconv.ParseInt(asStr, 10, 64)
    }
    return 0, errors.New("iss not integer-like")
}

func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
    if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
        return k, nil
    }
    if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
        rk, ok := k.(*rsa.PrivateKey)
        if !ok {
            return nil, fmt.Errorf("PKCS#8 key is not RSA")
        }
        return rk, nil
    }
    return nil, errors.New("unknown RSA key format")
}
```

- [ ] **Step 4: Run — verify pass**

Run: `go test ./internal/proxy/ -run TestSignGitHubAppJWT`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/github_app_signer.go internal/proxy/github_app_signer_test.go
git commit -m "feat(proxy): implement signGitHubAppJWT (detect, lookup, re-sign)"
```

---

### Task 17: Wire `signGitHubAppJWT` into `ProcessRequest`

**Files:**
- Modify: `internal/proxy/injector.go`
- Test: `internal/proxy/injector_test.go`

- [ ] **Step 1: Write failing test**

Append to `internal/proxy/injector_test.go`:

```go
func TestProcessRequest_WiresGitHubAppSigner(t *testing.T) {
    realKey, realPEM := genPEM(t)
    placeholderKey, placeholderPEM := genPEM(t)
    cred := &vault.Credential{
        ID:           "c1",
        Name:         "gh-app",
        Scheme:       "github_app",
        Real:         realPEM,
        Placeholder:  placeholderPEM,
        GitHubAppID:  999,
        AllowedHosts: []string{"api.github.com"},
    }
    pmap := map[string]*vault.Credential{placeholderPEM: cred}
    inj := NewInjector(pmap, nil, 0, "")

    jwt := signJWT(t, placeholderKey, 999)
    hdr := http.Header{}
    hdr.Set("Authorization", "Bearer "+jwt)

    _, newHeader, _, injections := inj.ProcessRequest("req-2", "POST",
        "https://api.github.com/app/installations", hdr, nil)

    newJWT := strings.TrimPrefix(newHeader.Get("Authorization"), "Bearer ")
    parts := strings.Split(newJWT, ".")
    if len(parts) != 3 {
        t.Fatalf("bad JWT: %s", newJWT)
    }
    sig, _ := base64URLDecode(parts[2])
    h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
    if err := rsa.VerifyPKCS1v15(&realKey.PublicKey, 0, h[:], sig); err != nil {
        t.Errorf("new JWT does not verify with real key: %v", err)
    }
    sawResign := false
    for _, i := range injections {
        if i.Location == LocationGitHubAppJWTResigned {
            sawResign = true
        }
    }
    if !sawResign {
        t.Errorf("no github_app_jwt_resigned injection")
    }
}
```

- [ ] **Step 2: Run — verify failure**

Run: `go test ./internal/proxy/ -run TestProcessRequest_WiresGitHubAppSigner`
Expected: FAIL — signer not invoked.

- [ ] **Step 3: Invoke `signGitHubAppJWT` right after `signAWSSigV4`**

In `internal/proxy/injector.go`, after the AWS SigV4 block added in Task 11:

```go
    // --- GitHub App JWT signer ---
    ghInjs, _ := signGitHubAppJWT(shim, creds, host)
    for _, s := range ghInjs {
        s.RequestID = requestID
        s.Method = method
        s.URLPath = urlPath
        s.AgentPID = inj.agentPID
        s.AgentCmd = inj.agentCmd
        injections = append(injections, s)
    }
    newHeader = shim.Header
```

- [ ] **Step 4: Run — verify pass**

Run: `go test ./internal/proxy/ -run TestProcessRequest_WiresGitHubAppSigner`
Expected: PASS

- [ ] **Step 5: Run full proxy suite**

Run: `go test ./internal/proxy/...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/injector.go internal/proxy/injector_test.go
git commit -m "feat(proxy): invoke signGitHubAppJWT in the injector pipeline"
```

---

## Phase 4 — Polish

### Task 18: `veil list` tags + `veil log --signer-failed`

**Files:**
- Modify: `internal/cli/list.go`, `internal/cli/log.go`
- Test: `internal/cli/list_test.go`, `internal/cli/log_test.go`

- [ ] **Step 1: Write failing test for `veil list`**

Append to `internal/cli/list_test.go` (or create if absent):

```go
func TestListCmd_TagsSchemes(t *testing.T) {
    dir := t.TempDir()
    initProject(t, dir)
    v := openVaultInDir(t, dir)
    v.Add(&vault.Credential{
        ID: vault.NewID(), Name: "bearer-cred", Real: "r", Placeholder: "p",
        AllowedHosts: []string{"api.openai.com"}, CreatedAt: time.Now(),
    })
    v.Add(&vault.Credential{
        ID: vault.NewID(), Name: "aws-prod", Real: "r", Placeholder: "p2",
        Scheme: "aws", AWSAccessKeyID: "AKIAREAL000000000000", AWSAccessKeyIDPlaceholder: "AKIAPH000000000000",
        AllowedHosts: []string{"*.amazonaws.com"}, CreatedAt: time.Now(),
    })
    v.Add(&vault.Credential{
        ID: vault.NewID(), Name: "gh-app", Real: "r", Placeholder: "p3",
        Scheme: "github_app", GitHubAppID: 111,
        AllowedHosts: []string{"api.github.com"}, CreatedAt: time.Now(),
    })

    var out bytes.Buffer
    cmd := RootCmd()
    cmd.SetOut(&out)
    cmd.SetArgs([]string{"list"})
    if err := cmd.Execute(); err != nil {
        t.Fatal(err)
    }
    s := out.String()
    if !strings.Contains(s, "bearer-cred") {
        t.Error("missing bearer-cred")
    }
    if !strings.Contains(s, "(aws)") {
        t.Error("missing (aws) tag")
    }
    if !strings.Contains(s, "(github app)") {
        t.Error("missing (github app) tag")
    }
}
```

- [ ] **Step 2: Run — verify failure**

Run: `go test ./internal/cli/... -run TestListCmd_TagsSchemes`
Expected: FAIL — tags not rendered.

- [ ] **Step 3: Tag rendering in list.go**

In `internal/cli/list.go`, where each credential row is printed, compute a tag:

```go
tag := ""
switch {
case c.Scheme == "aws" || c.AWSAccessKeyID != "":
    tag = " (aws)"
case c.Scheme == "github_app" || c.GitHubAppID != 0:
    tag = " (github app)"
case c.Username != "":
    tag = " (basic)"
}
fmt.Fprintf(w, "  %s%s\n", c.Name, tag)
```

- [ ] **Step 4: Write failing test for `veil log --signer-failed`**

Append to `internal/cli/log_test.go` (or create):

```go
func TestLogCmd_SignerFailedFilter(t *testing.T) {
    dir := t.TempDir()
    initProject(t, dir)
    // Seed the audit DB with one signer_failed and one ordinary row.
    store, _ := audit.Open(filepath.Join(dir, ".veil", "audit.db"))
    store.Record(audit.Injection{
        Timestamp: time.Now(), Host: "s3.amazonaws.com",
        Location: "aws_sigv4_resigned", CredentialName: "aws-prod",
    })
    store.Record(audit.Injection{
        Timestamp: time.Now(), Host: "s3.amazonaws.com",
        Location: "signer_failed", SignerError: "unknown_access_key_id",
    })
    store.DrainForTest()
    store.Close()

    var out bytes.Buffer
    cmd := RootCmd()
    cmd.SetOut(&out)
    cmd.SetArgs([]string{"log", "--signer-failed"})
    if err := cmd.Execute(); err != nil {
        t.Fatal(err)
    }
    s := out.String()
    if !strings.Contains(s, "signer_failed") || !strings.Contains(s, "unknown_access_key_id") {
        t.Errorf("expected signer_failed row and error class; got:\n%s", s)
    }
    if strings.Contains(s, "aws_sigv4_resigned") {
        t.Error("should not include aws_sigv4_resigned when --signer-failed set")
    }
}
```

- [ ] **Step 5: Run — verify failure**

Run: `go test ./internal/cli/... -run TestLogCmd_SignerFailedFilter`
Expected: FAIL — flag unknown.

- [ ] **Step 6: Implement the flag**

In `internal/cli/log.go` add a `--signer-failed` boolean flag. In the query path, when set, filter `WHERE location = 'signer_failed'`. Append a `SignerError` column to the output when non-empty.

The exact pattern depends on the current log implementation; grep `internal/cli/log.go` for the existing filter flags (`--host`, `--credential`, etc.) and mirror their shape.

- [ ] **Step 7: Run — verify pass**

Run: `go test ./internal/cli/... -run "TestListCmd_TagsSchemes|TestLogCmd_SignerFailedFilter"`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/cli/list.go internal/cli/log.go internal/cli/list_test.go internal/cli/log_test.go
git commit -m "feat(cli): list scheme tags + log --signer-failed filter"
```

---

### Task 19: End-to-end integration tests

**Files:**
- Modify: `internal/proxy/basic_integration_test.go`

- [ ] **Step 1: Write failing AWS end-to-end test**

Append to `internal/proxy/basic_integration_test.go`:

```go
// TestIntegration_AWSSigV4_EndToEnd spins up an HTTP server that verifies a
// SigV4 signature with a known real SecretAccessKey, invokes the proxy with
// a request signed by the placeholder key, and asserts that the upstream
// verifies the real signature.
func TestIntegration_AWSSigV4_EndToEnd(t *testing.T) {
    realSecret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    realAKID := "AKIAIOSFODNN7EXAMPLE"
    placeholderAKID := "AKIAPH0000000000EXMP"
    placeholderSecret := "VeilSecretPlaceholderXXXXXXXXXXXXXXXXXXX"

    // Upstream validator: recompute canonical request + signature from the
    // incoming Authorization header and ensure it matches.
    upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        auth := r.Header.Get("Authorization")
        parsed, err := parseSigV4Authorization(auth)
        if err != nil {
            w.WriteHeader(400); return
        }
        if parsed.AccessKeyID != realAKID {
            t.Errorf("upstream saw AKID = %q, want real %q", parsed.AccessKeyID, realAKID)
        }
        // Body hash.
        body, _ := io.ReadAll(r.Body)
        canon := r.Method + "\n" +
            canonicalURI(r.URL.Path, false) + "\n" +
            canonicalQueryString(r.URL.RawQuery) + "\n" +
            canonicalHeaders(r.Header, parsed.SignedHeaders) + "\n" +
            strings.Join(parsed.SignedHeaders, ";") + "\n" +
            sha256Hex(body)
        scope := parsed.Date + "/" + parsed.Region + "/" + parsed.Service + "/aws4_request"
        sts := "AWS4-HMAC-SHA256\n" + r.Header.Get("X-Amz-Date") + "\n" + scope + "\n" + sha256Hex([]byte(canon))
        key := deriveSigningKey(realSecret, parsed.Date, parsed.Region, parsed.Service)
        want := fmt.Sprintf("%x", hmacSHA256(key, []byte(sts)))
        if parsed.Signature != want {
            t.Errorf("signature mismatch\n got=%s\nwant=%s", parsed.Signature, want)
            w.WriteHeader(403); return
        }
        w.WriteHeader(200)
    }))
    defer upstream.Close()

    cred := &vault.Credential{
        ID: vault.NewID(), Name: "aws-prod", Scheme: "aws",
        Real: realSecret, Placeholder: placeholderSecret,
        AWSAccessKeyID: realAKID, AWSAccessKeyIDPlaceholder: placeholderAKID,
        AllowedHosts: []string{upstreamHost(upstream)},
    }
    vlt := newTestVaultWith(t, cred)
    srv := startProxyForTest(t, vlt)
    defer srv.Stop()

    // Agent signs request with placeholder secret.
    req, _ := http.NewRequest("GET", upstream.URL+"/path", nil)
    req.Header.Set("Host", upstreamHost(upstream))
    req.Header.Set("X-Amz-Date", "20150830T123600Z")
    // Pre-compute the placeholder-signed signature so the request is valid
    // when it hits the proxy.
    canonReq := "GET\n/path\n\nhost:" + upstreamHost(upstream) + "\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\n" + sha256Hex(nil)
    sts := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n" + sha256Hex([]byte(canonReq))
    phKey := deriveSigningKey(placeholderSecret, "20150830", "us-east-1", "service")
    phSig := fmt.Sprintf("%x", hmacSHA256(phKey, []byte(sts)))
    req.Header.Set("Authorization",
        "AWS4-HMAC-SHA256 "+
            "Credential="+placeholderAKID+"/20150830/us-east-1/service/aws4_request, "+
            "SignedHeaders=host;x-amz-date, "+
            "Signature="+phSig)

    resp := roundTripThroughProxy(t, srv, req)
    if resp.StatusCode != 200 {
        t.Fatalf("end-to-end returned %d", resp.StatusCode)
    }
}

func upstreamHost(s *httptest.Server) string {
    u, _ := url.Parse(s.URL)
    return u.Host
}
```

*(Pattern-match against the helpers already present in `basic_integration_test.go` for `newTestVaultWith` / `startProxyForTest` / `roundTripThroughProxy`. Adjust names to match.)*

- [ ] **Step 2: Write failing GitHub App end-to-end test**

Append to `internal/proxy/basic_integration_test.go`:

```go
func TestIntegration_GitHubAppJWT_EndToEnd(t *testing.T) {
    realKey, realPEM := genPEM(t)
    placeholderKey, placeholderPEM := genPEM(t)

    upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        auth := r.Header.Get("Authorization")
        jwt := strings.TrimPrefix(auth, "Bearer ")
        parts := strings.Split(jwt, ".")
        if len(parts) != 3 {
            w.WriteHeader(400); return
        }
        sig, _ := base64URLDecode(parts[2])
        h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
        if err := rsa.VerifyPKCS1v15(&realKey.PublicKey, 0, h[:], sig); err != nil {
            t.Errorf("upstream JWT does not verify with real key: %v", err)
            w.WriteHeader(401); return
        }
        w.WriteHeader(200)
    }))
    defer upstream.Close()

    cred := &vault.Credential{
        ID: vault.NewID(), Name: "gh-app", Scheme: "github_app",
        Real: realPEM, Placeholder: placeholderPEM,
        GitHubAppID: 7777,
        AllowedHosts: []string{upstreamHost(upstream)},
    }
    vlt := newTestVaultWith(t, cred)
    srv := startProxyForTest(t, vlt)
    defer srv.Stop()

    jwt := signJWT(t, placeholderKey, 7777)
    req, _ := http.NewRequest("POST", upstream.URL+"/app/installations", nil)
    req.Header.Set("Authorization", "Bearer "+jwt)

    resp := roundTripThroughProxy(t, srv, req)
    if resp.StatusCode != 200 {
        t.Fatalf("end-to-end returned %d", resp.StatusCode)
    }
}
```

- [ ] **Step 3: Run — verify both tests pass (the signers are now wired)**

Run: `go test ./internal/proxy/ -run "TestIntegration_AWSSigV4|TestIntegration_GitHubAppJWT"`
Expected: PASS

If either FAILS, diagnose against the unit tests first — the signer code is covered in Tasks 10 and 16, so an end-to-end failure is most likely a proxy wiring / plumbing issue.

- [ ] **Step 4: Commit**

```bash
git add internal/proxy/basic_integration_test.go
git commit -m "test(proxy): add AWS SigV4 and GitHub App JWT end-to-end integration tests"
```

---

### Task 20: Docs updates

**Files:**
- Modify: `PRODUCT.md`, `MVP.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`

- [ ] **Step 1: Read current docs**

Run: `grep -n "AWS" PRODUCT.md MVP.md docs/THREAT_MODEL.md docs/ARCHITECTURE.md`

Read each hit to understand current framing of AWS / GitHub coverage.

- [ ] **Step 2: Update PRODUCT.md**

In the feature-list section, add a line to each relevant area:

```
- **AWS SigV4** (including STS session-token credentials) — Veil re-signs requests at the proxy so the real SecretAccessKey never appears in `.env`.
- **GitHub Apps** (api.github.com and GitHub Enterprise Server) — Veil re-signs the App JWT with the real RSA private key.
```

Place near existing bullets about provider coverage. If PRODUCT.md has a table of providers, add AWS and GitHub Apps rows.

- [ ] **Step 3: Update MVP.md**

Update "Features" to list AWS SigV4 and GitHub App JWT as mediated schemes. Remove any caveats that say AWS/GitHub Apps fail silently.

- [ ] **Step 4: Update docs/THREAT_MODEL.md**

Add a new subsection "Class 2 (keyed cryptography)" if one doesn't exist, describing:

```
Veil mediates AWS SigV4 and GitHub App JWT signatures at the proxy. For each
mediated scheme, the request is blocked with 502 if the scheme is recognized,
Veil owns the host, but signing cannot complete (see SignerError).

Scoped gaps:
- The fail-closed sentinel check in detectLeak cannot fire on a leaked RSA
  private key PEM, because the placeholder PEM cannot embed the sentinel
  without breaking PEM parsing. JWT-signature-based identification is the
  primary mediation mechanism.
- GitHub App installation tokens (ghs_…) returned in response bodies are
  not mediated; the agent holds a short-lived real token for up to an hour.
  This is a Class 3 (offline exchange) problem and out of scope.
```

- [ ] **Step 5: Update docs/ARCHITECTURE.md**

If there's a "Signer functions" or similar section, update it. Otherwise, add a short paragraph near the "Injector pipeline" description:

```
### Signer functions

Beyond literal placeholder substitution, two signer functions re-sign requests
whose Authorization header uses keyed cryptography:

- `signAWSSigV4` — recognises AWS4-HMAC-SHA256 headers and re-signs with the
  real SecretAccessKey.
- `signGitHubAppJWT` — recognises RS256 JWTs with an integer `iss` claim and
  re-signs with the real RSA private key.

Each signer returns one of three outcomes: `…_resigned` (sign and forward),
`scheme_unmediated` (forward unchanged — no vaulted credential covers this
host), or `signer_failed` (fail-closed 502).
```

- [ ] **Step 6: Verify docs build / lint (if the repo has a docs check)**

Run: `grep -l "markdown" Makefile .github/workflows/*.yml 2>/dev/null` to discover the docs lint command if any. If there's no docs lint, skip.

- [ ] **Step 7: Commit**

```bash
git add PRODUCT.md MVP.md docs/THREAT_MODEL.md docs/ARCHITECTURE.md
git commit -m "docs: document Class 2 re-signing for AWS SigV4 and GitHub App JWT"
```

---

## Final verification

- [ ] **Step 1: Full test suite**

Run: `go test ./...`
Expected: PASS

- [ ] **Step 2: Build CLI**

Run: `go build -o /tmp/veil ./cmd/veil`
Expected: clean build.

- [ ] **Step 3: Smoke test CLI ergonomics**

Against a scratch directory:

```bash
cd $(mktemp -d)
/tmp/veil init
echo "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" | /tmp/veil add aws-prod \
    --scheme aws --aws-access-key-id AKIAIOSFODNN7EXAMPLE \
    --host '*.amazonaws.com' --value-stdin
/tmp/veil list
```

Expected: `aws-prod (aws)` with both placeholders shown.

- [ ] **Step 4: Final commit if any stray changes remain**

Run: `git status`
Expected: clean.

---

## Verification against success criteria (from spec)

1. `aws s3 ls` through `veil run`: validated by Task 19 AWS end-to-end.
2. `aws sts get-caller-identity` with session-tokened credential: validated by Task 6 CLI test + Task 10 session-token unit tests.
3. Octokit / PyGithub listing App installations: validated by Task 19 GitHub App end-to-end.
4. Mismatch detector does not fire on `aws s3 ls`: by Task 11 the `aws_sigv4_resigned` row increments `injectionCount`, so `anyNonBlocked` returns true and `detectMismatch` is skipped (existing behaviour in [injector.go:166](internal/proxy/injector.go:166)).
5. Deliberately corrupted request → 502: Task 12 `TestProxy_FailsClosedOnSignerFailure`.
6. No regression on bearer credentials: full suite must pass at end of every task; Task 11 "Run full proxy suite" + Final "Full test suite" cover this.
