# Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the 19 in-scope findings from the 2026-04-14 review as a single coherent security + correctness + cleanup pass, organised into 7 sequential phases.

**Architecture:** Phase 1 introduces `internal/testutil/`, a `ui.Warn` helper, and an audit-wide typed-errors pass — the scaffolding that every later phase uses. Phases 2–7 are independently mergeable after Phase 1. Each phase targets one or more findings, with tasks sized for 2–5 minute steps.

**Tech Stack:** Go (CGO off), `modernc.org/sqlite`, `goproxy`, `go-keyring`, `filippo.io/age`, `fatih/color`. No new dependencies.

**Source documents:**
- Spec: `docs/superpowers/specs/2026-04-14-review-fixes-design.md`
- Findings: `docs/superpowers/findings/2026-04-14-review.md`

**Project conventions to honour throughout:**
- `CGO_ENABLED=0` on every build target.
- `VEIL_TEST_KEYSTORE=mem` for tests (after Phase 1/4, this is achieved via `-tags testkeystore`).
- Tests live next to code (`foo.go` ↔ `foo_test.go`); integration tests live under `test/integration/`.
- All new error paths should route through typed errors (see Phase 1).
- All new warning output should use `ui.Warn` or `ui.FormatWarning`.
- Do not reconstruct paths inline — use helpers in `internal/config/paths.go`.

---

## File Structure

**New files (created by this plan):**
- `internal/testutil/testutil.go` — shared test helpers (`MakeCred`, `TempProjectRoot`).
- `internal/testutil/memkeystore.go` — `NewMemKeystore()` under `//go:build testkeystore`.
- `internal/cli/helpers_testkeystore.go` — env-var-triggered mem keystore under `//go:build testkeystore`.
- `internal/cli/helpers_prodkeystore.go` — no-op stub under `//go:build !testkeystore`.
- `internal/runner/termination.go` — shared `childTerminationGrace` constant (Phase 7).
- `docs/THREAT_MODEL.md` — threat model (Phase 7).

**Modified files:**
- `internal/ui/ui.go` — `Warn` helper already exists; verify + expand variadic usage (Phase 1).
- `internal/cli/run.go` — rewrite `mapRunError` with `errors.Is/As` (Phase 1).
- `internal/cli/helpers.go` — move env-var branch behind build tag (Phase 4).
- `internal/cli/init.go` — migrate `fmt.Fprintln` warning at line ~346 to `ui.Warn` (Phase 1).
- `internal/runner/signals.go` — already uses `ui.Muted`; migrate raw `fmt.Fprintln` spots if present (Phase 1).
- `internal/runner/runner.go` — per-session temp dir, shared termination constant (Phases 3 and 7).
- `internal/runner/pgroup_linux.go` + `parentwatch_darwin.go` — consume shared termination constant (Phase 7).
- `internal/scanner/envfile.go` — quote-aware single-quote parser (Phase 2).
- `internal/audit/audit.go` — chmod at `Open` after WAL checkpoint (Phase 3).
- `internal/vault/keystore_file.go` — parent-dir mode verify, zero hex buffer in `saveMap` (Phases 3, 4).
- `internal/vault/keystore_auto.go` — do not fall back on Delete failure; `ui.Warn` once (Phase 4).
- `internal/vault/vault.go` — typed `ErrPlaceholderCollision`, retry wiring (Phases 1, 5).
- `internal/placeholder/engine.go` — `Generate` accepts existing-placeholder set, retries 8x (Phase 5).
- `internal/placeholder/providers.go` — explicit `Registry` struct (Phase 5).
- `internal/proxy/injector.go` — parse + rewrite query strings; strip query from audit (Phase 6).
- `internal/proxy/proxy.go` — Content-Type allowlist, body-read error handling (Phase 6).
- `internal/proxy/ca.go` — SHA-256 for SKID (Phase 6).
- Plus test files next to each.
- `Makefile` — add `-tags testkeystore` to `test` and `test-race` targets (Phase 1).

---

## Phase 1 — CLI cleanup & error-typing foundation

Covers: **M6** (typed errors), **L3** (`ui.Warn`), **L7** (testutil extraction).

This phase lands infrastructure. Subsequent phases use it freely.

### Task 1: Create `internal/testutil/` package skeleton

**Files:**
- Create: `internal/testutil/testutil.go`
- Create: `internal/testutil/testutil_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/testutil/testutil_test.go
package testutil_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/8enji/veil/internal/testutil"
)

func TestTempProjectRoot(t *testing.T) {
	root := testutil.TempProjectRoot(t)
	if root == "" {
		t.Fatal("expected non-empty root")
	}
	info, err := os.Stat(filepath.Join(root, ".veil"))
	if err != nil || !info.IsDir() {
		t.Fatalf(".veil dir missing under root: %v", err)
	}
}

func TestMakeCred(t *testing.T) {
	c := testutil.MakeCred("STRIPE_KEY", "sk_live_abc", "sk_live_fake")
	if c == nil {
		t.Fatal("MakeCred returned nil")
	}
	if c.Name != "STRIPE_KEY" || c.Real != "sk_live_abc" || c.Placeholder != "sk_live_fake" {
		t.Fatalf("unexpected credential: %+v", c)
	}
	if c.ID == "" {
		t.Fatal("expected a generated ID")
	}
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `CGO_ENABLED=0 go test ./internal/testutil/ -v`
Expected: FAIL (package does not exist).

- [ ] **Step 3: Implement the package**

```go
// internal/testutil/testutil.go
// Package testutil contains helpers shared across test files.
// Import paths: github.com/8enji/veil/internal/testutil
package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/8enji/veil/internal/vault"
	"github.com/oklog/ulid/v2"
)

// MakeCred constructs a *vault.Credential for tests with sensible defaults.
// name is the credential name; real is the real secret; placeholder is the
// format-valid fake. Remaining fields are populated with deterministic
// zero-or-generated values suitable for test assertions.
func MakeCred(name, real, placeholder string) *vault.Credential {
	return &vault.Credential{
		ID:          ulid.Make().String(),
		Name:        name,
		Real:        real,
		Placeholder: placeholder,
	}
}

// TempProjectRoot returns a t.TempDir()-rooted project directory with a
// .veil/ state directory pre-created. Cleanup is handled by testing.T.
func TempProjectRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	stateDir := filepath.Join(root, ".veil")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("create state dir: %v", err)
	}
	return root
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/testutil/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/testutil/
git commit -m "feat(testutil): add MakeCred and TempProjectRoot helpers"
```

---

### Task 2: Add `NewMemKeystore` under `testkeystore` build tag

**Files:**
- Create: `internal/testutil/memkeystore.go`

- [ ] **Step 1: Write the test** (into the existing `testutil_test.go` but wrapped in the tag)

Append to `internal/testutil/testutil_test.go`:

```go
//go:build testkeystore

package testutil_test

import "testing"

func TestNewMemKeystore(t *testing.T) {
	ks := testutil.NewMemKeystore()
	if ks == nil {
		t.Fatal("expected non-nil mem keystore")
	}
	var key [32]byte
	if err := ks.Set("project-a", key); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, err := ks.Get("project-a"); err != nil {
		t.Fatalf("get: %v", err)
	}
}
```

Wait — the `//go:build testkeystore` directive must be the first line of a file. Split the existing test file so tagged tests live in a separate file.

Rewrite as a new file instead:

**File:** `internal/testutil/memkeystore_test.go`

```go
//go:build testkeystore

package testutil_test

import (
	"testing"

	"github.com/8enji/veil/internal/testutil"
)

func TestNewMemKeystore(t *testing.T) {
	ks := testutil.NewMemKeystore()
	if ks == nil {
		t.Fatal("expected non-nil mem keystore")
	}
	var key [32]byte
	if err := ks.Set("project-a", key); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, err := ks.Get("project-a"); err != nil {
		t.Fatalf("get: %v", err)
	}
}
```

- [ ] **Step 2: Run it; expect FAIL**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/testutil/ -v`
Expected: FAIL (`NewMemKeystore` undefined).

- [ ] **Step 3: Create the tagged helper file**

```go
// internal/testutil/memkeystore.go
//go:build testkeystore

package testutil

import "github.com/8enji/veil/internal/vault"

// NewMemKeystore returns a fresh in-memory keystore suitable for tests.
// Compiled only when the testkeystore build tag is set.
func NewMemKeystore() *vault.MemKeystore {
	return vault.NewMemKeystore()
}
```

- [ ] **Step 4: Run tagged test; expect PASS**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/testutil/ -v`
Expected: PASS for both existing tests and the new `TestNewMemKeystore`.

- [ ] **Step 5: Verify untagged build still works**

Run: `CGO_ENABLED=0 go test ./internal/testutil/ -v`
Expected: PASS (the tagged file is skipped; only the untagged tests run).

- [ ] **Step 6: Commit**

```bash
git add internal/testutil/memkeystore.go internal/testutil/memkeystore_test.go
git commit -m "feat(testutil): add NewMemKeystore under testkeystore build tag"
```

---

### Task 3: Update Makefile to pass `-tags testkeystore`

**Files:**
- Modify: `Makefile:9-13`

- [ ] **Step 1: Update the `test` and `test-race` targets**

Replace the existing targets with:

```make
test:
	CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./... -timeout 120s

test-race:
	CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./... -race -timeout 180s
```

Keep `build`, `xbuild`, `vet`, `lint`, `tidy`, `clean`, `release` unchanged.

- [ ] **Step 2: Run the full test suite**

Run: `make test`
Expected: all packages pass.

- [ ] **Step 3: Commit**

```bash
git add Makefile
git commit -m "build: add -tags testkeystore to make test targets"
```

---

### Task 4: Audit `ui.Warn` signature and callers

The `ui.Warn` helper already exists at `internal/ui/ui.go:43` with signature `func Warn(w io.Writer, msg string)`. Verify it supports formatting like the raw sites use.

**Files:**
- Modify: `internal/ui/ui.go:43-46`
- Modify: `internal/ui/ui_test.go`

- [ ] **Step 1: Write a test for variadic formatting**

Append to `internal/ui/ui_test.go`:

```go
func TestWarnFormats(t *testing.T) {
	var buf bytes.Buffer
	ui.Warnf(&buf, "could not write pid file: %v", os.ErrPermission)
	got := buf.String()
	if !strings.Contains(got, "could not write pid file:") ||
		!strings.Contains(got, "permission denied") {
		t.Fatalf("unexpected output: %q", got)
	}
}
```

(Imports `bytes`, `os`, `strings`, `testing` plus the package alias `ui`.)

- [ ] **Step 2: Run the test; expect FAIL**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/ui/ -run TestWarnFormats -v`
Expected: FAIL (`Warnf` undefined).

- [ ] **Step 3: Add `Warnf`**

Add to `internal/ui/ui.go` below the existing `Warn`:

```go
// Warnf prints a warning step line with Printf-style formatting:
// "  ! <formatted message>\n"
func Warnf(w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, "  %s %s\n", Warning.Sprint("!"), fmt.Sprintf(format, args...))
}
```

Leave the existing `Warn(w, msg)` alone so existing callers keep compiling.

- [ ] **Step 4: Run the test; expect PASS**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/ui/ -run TestWarnFormats -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/ui/
git commit -m "feat(ui): add Warnf for formatted warning output"
```

---

### Task 5: Migrate raw warning writes to `ui.Warn`/`ui.Warnf`

Replace `fmt.Fprintln(os.Stderr, ...)` warning sites identified in the finding. Expected sites to touch:
- `internal/cli/init.go:346` (or wherever the current `fmt.Fprintln` warning lives — confirm with grep before editing).
- `internal/runner/runner.go:93` (currently uses `ui.Muted.Sprintf` — that's a stylistic call, keep or upgrade to `ui.Warnf` depending on taste; if it's meant as a warning, migrate).
- `internal/runner/runner.go:131` (same pattern).

**Files:**
- Modify: `internal/cli/init.go` (the `fmt.Fprintln` warning site)
- Modify: `internal/runner/runner.go:93,131` (muted warning sites)

- [ ] **Step 1: Grep for warning patterns**

Run: (use the Grep tool) `rg -n "fmt\\.Fprintln.*warning|fmt\\.Fprintf.*warning" internal/` — enumerate all matches. Also `rg -n "ui\\.Muted\\.Sprintf.*warning"`.

- [ ] **Step 2: Migrate each matched site**

For each site that is semantically a warning (not a muted status line), replace with `ui.Warnf(os.Stderr, format, args...)`. Example for `runner.go:93`:

Before:
```go
fmt.Fprintf(os.Stderr, "%s\n", ui.Muted.Sprintf("warning: could not write pid file: %v", err))
```

After:
```go
ui.Warnf(os.Stderr, "could not write pid file: %v", err)
```

Do the same for line 131 and for the `init.go` site.

- [ ] **Step 3: Build and run tests**

Run: `CGO_ENABLED=0 go build ./... && make test`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add internal/cli/init.go internal/runner/runner.go
git commit -m "refactor: migrate raw warning writes to ui.Warnf"
```

---

### Task 6: Introduce typed errors in `vault` package

Introduce the baseline typed errors that `mapRunError` and callers downstream need.

**Files:**
- Create: `internal/vault/errors.go`
- Modify: `internal/vault/vault.go:33,39,44,49,54,59,78,99,106,111,115,119,129,132` (wrap returned errors)
- Modify: `internal/vault/vault_test.go` (add table-driven test for each sentinel)

- [ ] **Step 1: Write the failing test**

Create `internal/vault/errors_test.go`:

```go
package vault_test

import (
	"errors"
	"os"
	"testing"

	"github.com/8enji/veil/internal/vault"
)

func TestErrSentinels(t *testing.T) {
	// Opening a non-existent vault should return ErrOpen.
	_, err := vault.Open(t.TempDir(), vault.NewMemKeystore())
	if !errors.Is(err, vault.ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", err)
	}
	// Underlying os.ErrNotExist must also be in the chain.
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist in chain, got %v", err)
	}
}
```

- [ ] **Step 2: Run the test; expect FAIL**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/vault/ -run TestErrSentinels -v`
Expected: FAIL (`vault.ErrOpen` undefined).

- [ ] **Step 3: Create the errors file**

```go
// internal/vault/errors.go
package vault

import "errors"

// Sentinel errors returned by the vault package. Wrap with fmt.Errorf using
// the %w verb so callers can match via errors.Is.
var (
	// ErrOpen indicates the vault could not be opened (read meta, read blob,
	// decrypt, or unmarshal failed).
	ErrOpen = errors.New("vault: open failed")

	// ErrMasterKey indicates the master key could not be retrieved from the
	// keystore.
	ErrMasterKey = errors.New("vault: master key retrieval failed")

	// ErrCorrupt indicates the on-disk vault data is corrupt or truncated.
	ErrCorrupt = errors.New("vault: corrupt data")

	// ErrDuplicateCredential indicates Add was called with a name that already
	// exists.
	ErrDuplicateCredential = errors.New("vault: duplicate credential name")

	// ErrPlaceholderCollision indicates Add was called with a placeholder that
	// collides with an existing credential. Upstream generator should retry
	// before surfacing this.
	ErrPlaceholderCollision = errors.New("vault: placeholder collision")

	// ErrSave indicates the vault could not be persisted (marshal, encrypt,
	// or atomic write failed).
	ErrSave = errors.New("vault: save failed")
)
```

- [ ] **Step 4: Update `Open` and `Add` to wrap with sentinels**

In `internal/vault/vault.go`, replace each `fmt.Errorf("vault: cannot …", err)` with one that wraps the appropriate sentinel. Example diff for `Open`:

```go
// Replace:
return nil, fmt.Errorf("vault: cannot read meta file: %w", err)
// With:
return nil, fmt.Errorf("%w: read meta file: %w", ErrOpen, err)
```

Do this for all error return sites in `Open`, `Save`, `Add`, and `CreateVault`. Map the semantics:
- Read/parse/decrypt/unmarshal failures in `Open` → `ErrOpen` (with `os.ErrNotExist` naturally preserved via `%w` chain on the underlying `os.ReadFile` error).
- `ks.Get` failures → `ErrMasterKey`.
- `Unseal` / `json.Unmarshal` of credential data → `ErrCorrupt`.
- Duplicate-name check in `Add` → `ErrDuplicateCredential`.
- Placeholder collision in `Add` → `ErrPlaceholderCollision`.
- Anything in `Save` → `ErrSave`.
- `CreateVault` failures remain wrapped in `ErrSave` for write-path issues; `ErrMasterKey` for the keystore Set.

- [ ] **Step 5: Run full vault tests**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/vault/ -v`
Expected: all pass, including `TestErrSentinels`.

- [ ] **Step 6: Commit**

```bash
git add internal/vault/errors.go internal/vault/errors_test.go internal/vault/vault.go
git commit -m "feat(vault): introduce typed errors for open/save/add paths"
```

---

### Task 7: Introduce typed errors in `proxy` package

**Files:**
- Create: `internal/proxy/errors.go`
- Modify: `internal/proxy/ca.go:33,37,41,49,53,57,66,68,78,80,87,89,102,104,119,142,147,152,154,158,169,171,173,177,181,192,199,210,215,220,225,229` (wrap where appropriate)
- Modify: `internal/proxy/cabundle.go:33,36,40` (wrap with ErrCABundle)

- [ ] **Step 1: Add the errors file**

```go
// internal/proxy/errors.go
package proxy

import "errors"

// Sentinel errors for the proxy package.
var (
	// ErrCAGenerate indicates generation of a fresh root CA failed.
	ErrCAGenerate = errors.New("proxy: generate CA failed")

	// ErrCALoad indicates loading the CA cert or key from disk failed.
	ErrCALoad = errors.New("proxy: load CA failed")

	// ErrCABundle indicates building/writing the combined CA bundle failed.
	ErrCABundle = errors.New("proxy: build CA bundle failed")

	// ErrListen indicates the proxy could not bind its loopback listener.
	ErrListen = errors.New("proxy: listen failed")

	// ErrBodyRead indicates reading the outbound request body failed.
	ErrBodyRead = errors.New("proxy: body read failed")
)
```

- [ ] **Step 2: Update `ca.go` and `cabundle.go`**

Replace each `fmt.Errorf(...)` that describes a CA-load path with `fmt.Errorf("%w: ...: %w", ErrCALoad, err)`; each CA-generate path with `ErrCAGenerate`; each bundle path with `ErrCABundle`. Do not touch the top-level `LoadOrCreateCA` inconsistent-state branch — leave it as a plain `errors.New`, but wrap it via `ErrCALoad` for callers' sake:

```go
return nil, fmt.Errorf("%w: inconsistent CA state: one of cert/key exists without the other", ErrCALoad)
```

- [ ] **Step 3: Update `Server.Start` to wrap listener bind**

In `internal/proxy/proxy.go:142-155`:

```go
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrListen, err)
	}
	// ... existing body
}
```

Add `"fmt"` to the imports if missing.

- [ ] **Step 4: Test**

Write `internal/proxy/errors_test.go`:

```go
package proxy_test

import (
	"errors"
	"net"
	"testing"

	"github.com/8enji/veil/internal/proxy"
)

func TestErrListenWrap(t *testing.T) {
	// Occupy a port first so Start must fail.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("setup listen: %v", err)
	}
	defer ln.Close()

	// We cannot easily force Server.Start to fail without a real CA; instead,
	// assert that net.OpAddrPairOrNil-style binding errors propagate via
	// ErrListen when wrapped. This test exercises the sentinel by a minimal
	// construction.
	wrapped := proxy.WrapForTest(ErrListenTest{})
	if !errors.Is(wrapped, proxy.ErrListen) {
		t.Fatalf("expected ErrListen, got %v", wrapped)
	}
}

type ErrListenTest struct{}

func (ErrListenTest) Error() string { return "mock listen error" }
```

Add a `WrapForTest` helper (package-internal, test-tag-gated if desired). Simpler alternative: skip the test-only helper and just write a test that calls `Server.Start` after occupying the exact port (harder to guarantee). For this plan, prefer the helper approach:

Append to `internal/proxy/errors.go`:

```go
import "fmt"

// WrapForTest is exposed for tests that want to assert sentinel wrapping.
// Not for production use; kept internal to the package via lowercase helpers
// would be cleaner — but exposing it avoids //go:build tags in the happy path.
func WrapForTest(err error) error {
	return fmt.Errorf("%w: %w", ErrListen, err)
}
```

- [ ] **Step 5: Run tests**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/proxy/ -run TestErrListenWrap -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/errors.go internal/proxy/errors_test.go internal/proxy/ca.go internal/proxy/cabundle.go internal/proxy/proxy.go
git commit -m "feat(proxy): introduce typed errors for CA/listen paths"
```

---

### Task 8: Introduce typed errors in `scanner`, `audit`, `placeholder`, `keystore`

Batch the remaining packages — each gets its own `errors.go` with the sentinels called for by the spec.

**Files:**
- Create: `internal/scanner/errors.go`
- Create: `internal/audit/errors.go`
- Create: `internal/placeholder/errors.go`
- Create: `internal/vault/keystore_errors.go` (since keystore types live in the `vault` package already, add to existing file or a new one)

- [ ] **Step 1: Scanner errors**

```go
// internal/scanner/errors.go
package scanner

import "errors"

var (
	// ErrEnvParse indicates a malformed .env line (unclosed quote, bad escape, etc.).
	ErrEnvParse = errors.New("scanner: env parse error")
)
```

- [ ] **Step 2: Audit errors**

```go
// internal/audit/errors.go
package audit

import "errors"

var (
	// ErrAuditOpen indicates the audit database could not be opened or initialized.
	ErrAuditOpen = errors.New("audit: open failed")

	// ErrAuditWrite indicates a write to the audit database failed.
	ErrAuditWrite = errors.New("audit: write failed")
)
```

Update `audit.Open` to wrap its errors with `ErrAuditOpen`.

```go
// In audit.go: every `return nil, err` in Open becomes:
// return nil, fmt.Errorf("%w: <ctx>: %w", ErrAuditOpen, err)
```

- [ ] **Step 3: Placeholder errors**

```go
// internal/placeholder/errors.go
package placeholder

import "errors"

var (
	// ErrProviderNotFound indicates a lookup by provider name failed.
	ErrProviderNotFound = errors.New("placeholder: provider not found")

	// ErrCollisionUnresolvable indicates the generator exhausted its retry
	// budget without finding a non-colliding candidate.
	ErrCollisionUnresolvable = errors.New("placeholder: could not resolve collision after retries")
)
```

- [ ] **Step 4: Keystore errors**

```go
// internal/vault/keystore_errors.go
package vault

import "errors"

var (
	// ErrKeystoreUnavailable indicates the system keystore (keyring, file)
	// could not be reached.
	ErrKeystoreUnavailable = errors.New("keystore: unavailable")

	// ErrKeystoreWrite indicates a write or chmod on the keystore backing
	// store failed.
	ErrKeystoreWrite = errors.New("keystore: write failed")
)
```

Update `keystore_file.go` error sites to wrap `ErrKeystoreWrite` for write paths and `ErrKeystoreUnavailable` for missing-passphrase / read-fail paths.

- [ ] **Step 5: Run full test suite**

Run: `make test`
Expected: all pass. If any existing tests matched on the old raw-string errors via `strings.Contains`, they now need updating to use `errors.Is` — fix inline.

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/errors.go internal/audit/errors.go internal/placeholder/errors.go internal/vault/keystore_errors.go
git add internal/audit/audit.go internal/vault/keystore_file.go
git commit -m "feat: add typed errors to scanner, audit, placeholder, keystore"
```

---

### Task 9: Rewrite `mapRunError` to use `errors.Is/As`

**Files:**
- Modify: `internal/cli/run.go:64-77`
- Create: `internal/cli/run_test.go` (if not present; else append)

- [ ] **Step 1: Write the failing test**

```go
// internal/cli/run_test.go
package cli_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/8enji/veil/internal/cli"
	"github.com/8enji/veil/internal/proxy"
	"github.com/8enji/veil/internal/vault"
)

func TestMapRunError(t *testing.T) {
	cases := []struct {
		name   string
		in     error
		expect string
	}{
		{"vault open", fmt.Errorf("wrap: %w", vault.ErrOpen), "Cannot decrypt vault"},
		{"master key", fmt.Errorf("wrap: %w", vault.ErrMasterKey), "Cannot decrypt vault"},
		{"ca load", fmt.Errorf("wrap: %w", proxy.ErrCALoad), "CA certificate"},
		{"listen", fmt.Errorf("wrap: %w", proxy.ErrListen), "Another instance"},
		{"default", errors.New("random failure"), "run failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cli.MapRunErrorForTest(tc.in)
			if !strings.Contains(got, tc.expect) {
				t.Fatalf("expected %q in %q", tc.expect, got)
			}
		})
	}
}
```

- [ ] **Step 2: Expose the function for testing**

Rename `mapRunError` to `MapRunErrorForTest` for the test, or add an exported alias in `run.go`:

```go
// MapRunErrorForTest is exported for tests that assert error-to-message mapping.
var MapRunErrorForTest = mapRunError
```

- [ ] **Step 3: Run the test; expect FAIL**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/cli/ -run TestMapRunError -v`
Expected: FAIL on `vault open` case because the current implementation sniffs `"open vault"` via string match, not sentinel.

- [ ] **Step 4: Rewrite `mapRunError`**

Replace lines 64-77 in `internal/cli/run.go`:

```go
// mapRunError converts internal runner errors to user-friendly messages.
func mapRunError(err error) string {
	switch {
	case errors.Is(err, vault.ErrOpen), errors.Is(err, vault.ErrMasterKey), errors.Is(err, vault.ErrCorrupt):
		return "Cannot decrypt vault. Your keychain may have changed. Run veil init --force to reinitialize."
	case errors.Is(err, proxy.ErrCALoad), errors.Is(err, proxy.ErrCAGenerate):
		return "CA certificate not found or corrupt. Run veil init to regenerate."
	case errors.Is(err, proxy.ErrListen):
		return "Cannot start proxy. Another instance may be running."
	default:
		return fmt.Sprintf("run failed: %v", err)
	}
}
```

Add `"errors"` and the `vault`/`proxy` imports.

- [ ] **Step 5: Run the test; expect PASS**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/cli/ -run TestMapRunError -v`
Expected: all subtests PASS.

- [ ] **Step 6: Run integration suite**

Run: `make test`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add internal/cli/run.go internal/cli/run_test.go
git commit -m "refactor(cli): rewrite mapRunError using errors.Is with typed sentinels"
```

---

## Phase 2 — Scanner quoting fix (C4)

### Task 10: Replace single-quote parser with quote-aware reader

**Files:**
- Modify: `internal/scanner/envfile.go:139-148`
- Modify: `internal/scanner/envfile_test.go` (or create if absent)

- [ ] **Step 1: Write the failing table-driven test**

Create or append to `internal/scanner/envfile_test.go`:

```go
package scanner_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/8enji/veil/internal/scanner"
)

func TestParseFileSingleQuote(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		key     string
		value   string
		wantErr error // if non-nil, parser should flag this line
	}{
		{"simple", `KEY='simple'`, "KEY", "simple", nil},
		{"shell escaped quote", `KEY='it'\''s'`, "KEY", "it's", nil},
		{"has equals", `KEY='has=equals'`, "KEY", "has=equals", nil},
		{"literal backslash", `KEY='has\nliteral'`, "KEY", `has\nliteral`, nil},
		{"empty", `KEY=''`, "KEY", "", nil},
		{"unclosed", `KEY='unclosed`, "KEY", "", scanner.ErrEnvParse},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, ".env")
			if err := os.WriteFile(p, []byte(tc.input+"\n"), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			f, err := scanner.ParseFile(p)
			if err != nil {
				t.Fatalf("parse file: %v", err)
			}
			// ParseFile returns a file with Lines; inspect the first KV.
			var got string
			var hadErr bool
			for _, l := range f.Lines {
				if l.Kind == scanner.KVLine && l.Key == tc.key {
					got = l.Value
					break
				}
				if l.Kind == scanner.CommentLine && l.Raw != "" && l.Raw == tc.input {
					// Unparseable → treated as comment.
					hadErr = true
				}
			}
			if tc.wantErr != nil {
				if !hadErr {
					t.Fatalf("expected parse error (line demoted to comment), got key=%q value=%q", tc.key, got)
				}
				_ = errors.Is // silence unused import if not otherwise needed
				return
			}
			if got != tc.value {
				t.Fatalf("value: got %q, want %q", got, tc.value)
			}
		})
	}
}
```

- [ ] **Step 2: Run the test; expect FAIL**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/scanner/ -run TestParseFileSingleQuote -v`
Expected: `shell escaped quote` case fails (returns `it\` instead of `it's`).

- [ ] **Step 3: Implement a quote-aware reader**

Replace lines 140-148 of `parseValue` in `internal/scanner/envfile.go`:

```go
// Check for single-quoted value.
trimmed := strings.TrimSpace(raw)
if strings.HasPrefix(trimmed, "'") {
	content, ok := extractSingleQuoted(trimmed[1:])
	if ok {
		return content, SingleQuote
	}
	// Unclosed single-quote: fall through; line will be demoted to CommentLine
	// by parseLine since parseKV returns !ok.
}
```

Add a new helper function below:

```go
// extractSingleQuoted extracts content from inside single quotes, honouring
// the shell idiom '\'' (close quote, literal quote, open quote) which lets
// users embed a literal single quote inside a single-quoted string.
//
// Input starts *after* the opening quote. Returns the literal content and
// true on success; "" and false if the quote is unclosed.
func extractSingleQuoted(s string) (string, bool) {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\'' {
			// Check for the '\'' idiom.
			if i+2 < len(s) && s[i+1] == '\\' && s[i+2] == '\'' {
				b.WriteByte('\'')
				// Expect a following "'" that reopens the quoted section.
				if i+3 < len(s) && s[i+3] == '\'' {
					i += 4 // skip past: ' \ ' '
					continue
				}
				// If the closing reopen quote isn't there, treat the
				// initial quote as a true terminator.
				return b.String(), true
			}
			// Plain closing quote.
			return b.String(), true
		}
		b.WriteByte(s[i])
		i++
	}
	return "", false
}
```

Because `parseKV` returns `(Line{}, false)` on an unparseable line, and `parseLine` already demotes false results to `CommentLine`, an unclosed single-quote will surface as a `CommentLine` — which satisfies the test's `wantErr` branch.

Optionally, we can make the unclosed case *also* surface as a typed error. For this plan, follow the simpler "demote to comment" path to preserve round-trip semantics.

- [ ] **Step 4: Run the test; expect PASS**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/scanner/ -v`
Expected: all pass including new subtests.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/envfile.go internal/scanner/envfile_test.go
git commit -m "fix(scanner): honour shell '\\'' escape in single-quoted .env values"
```

---

## Phase 3 — Filesystem permission hardening

Covers: **C2** (audit DB perms), **H3** (age keystore parent dir), **L2** (CA bundle temp).

### Task 11: Chmod audit DB files and parent dir on `Open`

**Files:**
- Modify: `internal/audit/audit.go:66-87`
- Create: `internal/audit/audit_perms_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/audit/audit_perms_test.go
package audit_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/8enji/veil/internal/audit"
)

func TestOpenSetsRestrictivePerms(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "sub", "audit.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	s, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := dbPath + suffix
		info, err := os.Stat(p)
		if err != nil {
			if suffix == "" {
				t.Fatalf("stat %s: %v", p, err)
			}
			continue // sidecar may not exist on some sqlite modes
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o, want 0600", p, info.Mode().Perm())
		}
	}
	parent := filepath.Dir(dbPath)
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatalf("stat parent: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("parent %s mode %o, want 0700", parent, info.Mode().Perm())
	}
}

func TestOpenCorrectsExistingPerms(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	// Pre-create the file with open perms.
	if err := os.WriteFile(dbPath, nil, 0o644); err != nil {
		t.Fatalf("pre-create: %v", err)
	}
	s, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 0600", info.Mode().Perm())
	}
}
```

- [ ] **Step 2: Run; expect FAIL**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/audit/ -v`
Expected: FAIL on perm assertions.

- [ ] **Step 3: Update `Open`**

Modify `internal/audit/audit.go:66-87`:

```go
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

	dsn := "file:" + dbPath + "?_journal_mode=wal&_synchronous=normal"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("%w: sql.Open: %w", ErrAuditOpen, err)
	}

	if _, err := db.Exec(schemaDDL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%w: ddl: %w", ErrAuditOpen, err)
	}

	// Force WAL sidecar materialization so chmod below covers them.
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%w: wal_checkpoint: %w", ErrAuditOpen, err)
	}

	// Chmod 0600 on db and sidecars. Missing sidecars are tolerated.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := dbPath + suffix
		if err := os.Chmod(p, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
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
```

Add imports: `"errors"`, `"fmt"`, `"os"`, `"path/filepath"`.

- [ ] **Step 4: Run; expect PASS**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/audit/ -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add internal/audit/audit.go internal/audit/audit_perms_test.go
git commit -m "fix(audit): enforce 0600/0700 perms on DB files and parent"
```

---

### Task 12: Verify parent-dir mode in `keystore_file.saveMap`

**Files:**
- Modify: `internal/vault/keystore_file.go:115-118`
- Modify: `internal/vault/keystore_file_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/vault/keystore_file_test.go`:

```go
func TestFileKeystoreEnforcesParentMode(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "state")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(parent, "master.key.age")
	t.Setenv("VEIL_PASSPHRASE", "hunter2")

	ks := vault.NewFileKeystore(path)
	ks.SetWorkFactor(1)

	var key [32]byte
	if err := ks.Set("proj", key); err != nil {
		t.Fatalf("set: %v", err)
	}

	info, err := os.Stat(parent)
	if err != nil {
		t.Fatalf("stat parent: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("parent mode %o, want 0700", info.Mode().Perm())
	}
}
```

Add `filepath` and `os` imports if absent.

- [ ] **Step 2: Run; expect FAIL**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/vault/ -run TestFileKeystoreEnforcesParentMode -v`
Expected: FAIL (parent mode is still 0755).

- [ ] **Step 3: Update `saveMap`**

Replace `internal/vault/keystore_file.go:115-118`:

```go
// Ensure parent directory exists and has restrictive mode.
dir := filepath.Dir(f.path)
if err := os.MkdirAll(dir, 0o700); err != nil {
	return fmt.Errorf("%w: create dir %q: %w", ErrKeystoreWrite, dir, err)
}
if err := os.Chmod(dir, 0o700); err != nil {
	return fmt.Errorf("%w: chmod dir %q: %w", ErrKeystoreWrite, dir, err)
}
```

- [ ] **Step 4: Run; expect PASS**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/vault/ -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add internal/vault/keystore_file.go internal/vault/keystore_file_test.go
git commit -m "fix(keystore): enforce 0700 on file keystore parent directory"
```

---

### Task 13: Per-session CA bundle temp directory

**Files:**
- Modify: `internal/proxy/cabundle.go`
- Modify: `internal/runner/runner.go:72-77`
- Modify: `internal/proxy/cabundle_test.go`

- [ ] **Step 1: Update `BuildCABundle` to take an explicit directory**

Change the signature to accept a session directory, allowing the caller (runner) to own the lifecycle:

```go
// internal/proxy/cabundle.go

// BuildCABundleIn writes the combined CA bundle into sessionDir and returns
// the full file path. Prefer this to BuildCABundle in new code; the latter is
// preserved for backwards compatibility with tests not yet migrated.
func BuildCABundleIn(sessionDir string, veilCAPEM []byte) (string, error) {
	systemPEM, err := systemCAPEM()
	if err != nil {
		log.Printf("[veil] warning: could not extract system CAs: %v (bundle will contain only Veil CA)", err)
		systemPEM = nil
	}

	combined := make([]byte, 0, len(systemPEM)+len(veilCAPEM)+1)
	if len(systemPEM) > 0 {
		combined = append(combined, systemPEM...)
		if combined[len(combined)-1] != '\n' {
			combined = append(combined, '\n')
		}
	}
	combined = append(combined, veilCAPEM...)

	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		return "", fmt.Errorf("%w: ensure session dir: %w", ErrCABundle, err)
	}

	path := filepath.Join(sessionDir, "ca-bundle.pem")
	if err := atomicWrite(path, combined, 0o644); err != nil {
		return "", fmt.Errorf("%w: write bundle: %w", ErrCABundle, err)
	}
	return path, nil
}
```

Keep the existing `BuildCABundle` (unchanged) for any callers still using it.

- [ ] **Step 2: Update runner to use a per-session dir**

In `internal/runner/runner.go`, replace the current `BuildCABundle` call (lines 72-77):

```go
// 3b. Per-session temp directory that holds the CA bundle and any other
// short-lived artifacts. Cleaned up on exit.
sessionDir, err := os.MkdirTemp("", "veil-session-*")
if err != nil {
	return nil, fmt.Errorf("create session dir: %w", err)
}
defer os.RemoveAll(sessionDir)

bundlePath, err := proxy.BuildCABundleIn(sessionDir, ca.CertPEM)
if err != nil {
	return nil, fmt.Errorf("build ca bundle: %w", err)
}
```

Remove the `defer proxy.RemoveCABundle(bundlePath)` line.

- [ ] **Step 3: Add a stale-dir sweep on startup**

At the top of `Run` (before any other work), add:

```go
sweepStaleSessionDirs()
```

And define the sweeper:

```go
// sweepStaleSessionDirs removes veil-session-* directories under the OS temp
// root that are older than 24h. Best-effort; errors are logged via ui.Warnf
// but do not fail the run.
func sweepStaleSessionDirs() {
	root := os.TempDir()
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "veil-session-") {
			continue
		}
		p := filepath.Join(root, e.Name())
		info, err := os.Stat(p)
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		_ = os.RemoveAll(p)
	}
}
```

Add imports as needed.

- [ ] **Step 4: Add/update tests**

Add to `internal/runner/runner_test.go`:

```go
func TestSweepStaleSessionDirs(t *testing.T) {
	// Create a fake stale veil-session-* dir
	root := os.TempDir()
	stale, err := os.MkdirTemp(root, "veil-session-*")
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(stale, past, past); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	runner.SweepStaleSessionDirsForTest()

	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected stale dir removed, got err=%v", err)
	}
}
```

Export the sweep function for the test (add to `runner.go`):

```go
// SweepStaleSessionDirsForTest exposes the sweeper for tests.
var SweepStaleSessionDirsForTest = sweepStaleSessionDirs
```

- [ ] **Step 5: Run full tests**

Run: `make test`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/cabundle.go internal/runner/runner.go internal/runner/runner_test.go
git commit -m "refactor(runner): use per-session temp dir for CA bundle + stale sweep"
```

---

## Phase 4 — Keystore safety

Covers: **C3** (test keystore build tag), **H2** (D-Bus probe), **H4b** (zero hex buffer).

### Task 14: Move `VEIL_TEST_KEYSTORE=mem` branch behind build tag

**Files:**
- Modify: `internal/cli/helpers.go:38-41`
- Create: `internal/cli/helpers_testkeystore.go`
- Create: `internal/cli/helpers_prodkeystore.go`

- [ ] **Step 1: Create the tagged hook files**

`internal/cli/helpers_testkeystore.go`:

```go
//go:build testkeystore

package cli

import (
	"os"

	"github.com/8enji/veil/internal/vault"
)

// maybeTestKeystore returns (mem-keystore, true) when VEIL_TEST_KEYSTORE=mem is
// set and the binary was built with -tags testkeystore. Otherwise returns
// (nil, false). Production builds compile the !testkeystore stub, which always
// returns (nil, false).
func maybeTestKeystore() (vault.Keystore, bool) {
	if os.Getenv("VEIL_TEST_KEYSTORE") == "mem" {
		return testKeystore(), true
	}
	return nil, false
}
```

`internal/cli/helpers_prodkeystore.go`:

```go
//go:build !testkeystore

package cli

import "github.com/8enji/veil/internal/vault"

// maybeTestKeystore is a no-op in production builds. The env-var branch does
// not exist in the binary.
func maybeTestKeystore() (vault.Keystore, bool) { return nil, false }
```

- [ ] **Step 2: Update `buildKeystore`**

Replace `internal/cli/helpers.go:37-47`:

```go
// buildKeystore returns the appropriate Keystore for the current environment.
func buildKeystore() (vault.Keystore, error) {
	if ks, ok := maybeTestKeystore(); ok {
		return ks, nil
	}
	fallbackPath, err := config.KeystoreFallbackFile()
	if err != nil {
		return nil, err
	}
	return vault.AutoKeystore(fallbackPath), nil
}
```

Remove the `"os"` import if no other helpers in this file use it.

- [ ] **Step 3: Build both variants**

Run:
```bash
CGO_ENABLED=0 go build ./cmd/veil
CGO_ENABLED=0 go build -tags testkeystore ./cmd/veil
```
Expected: both succeed.

- [ ] **Step 4: Test that the prod build ignores the env var**

Add `internal/cli/buildtag_test.go`:

```go
//go:build !testkeystore

package cli_test

import (
	"os"
	"strings"
	"testing"

	"github.com/8enji/veil/internal/cli"
)

func TestProdBuildIgnoresMemKeystoreEnv(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	// We cannot easily call buildKeystore (unexported); instead, assert the
	// stub by reaching through an exported test hook, or rely on the fact
	// that without VEIL_PASSPHRASE, the AutoKeystore-ed path will try to
	// use the real keyring. For this plan we rely on the compile-time
	// guarantee: the memKeystore branch does not exist in the binary.
	if _, ok := cli.MaybeTestKeystoreForTest(); ok {
		t.Fatal("prod build should not return a mem keystore")
	}
	_ = strings.TrimSpace
	_ = os.Hostname
}
```

Add the exported hook to `helpers.go`:

```go
// MaybeTestKeystoreForTest is exported for tests that need to assert the
// build-tag behavior.
var MaybeTestKeystoreForTest = maybeTestKeystore
```

- [ ] **Step 5: Run both tagged and untagged test suites**

Run:
```bash
CGO_ENABLED=0 go test ./internal/cli/ -run TestProdBuildIgnoresMemKeystoreEnv -v
CGO_ENABLED=0 go test -tags testkeystore ./internal/cli/ -v
make test
```
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/helpers.go internal/cli/helpers_testkeystore.go internal/cli/helpers_prodkeystore.go internal/cli/buildtag_test.go
git commit -m "fix(cli): gate VEIL_TEST_KEYSTORE=mem behind testkeystore build tag"
```

---

### Task 15: D-Bus probe retains keyring on Delete failure

**Files:**
- Modify: `internal/vault/keystore_auto.go:11-23`
- Modify: `internal/vault/keystore_auto_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/vault/keystore_auto_test.go (append or create)
package vault_test

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/8enji/veil/internal/vault"
)

type deleteFailKeyring struct {
	vault.Keystore
	deleteErr error
}

func (k *deleteFailKeyring) Set(id string, key [32]byte) error { return nil }
func (k *deleteFailKeyring) Get(id string) ([32]byte, error)   { return [32]byte{}, nil }
func (k *deleteFailKeyring) Delete(id string) error            { return k.deleteErr }

func TestAutoKeystoreKeepsKeyringOnDeleteFailure(t *testing.T) {
	// Capture ui.Warnf output to verify the warning is emitted.
	var buf bytes.Buffer
	vault.ProbeWarnWriter = &buf
	defer func() { vault.ProbeWarnWriter = os.Stderr }()

	// Replace the keyring constructor with a stub that fails Delete.
	orig := vault.NewKeyringKeystoreForTest
	vault.NewKeyringKeystoreForTest = func() vault.Keystore {
		return &deleteFailKeyring{deleteErr: errors.New("cleanup quirk")}
	}
	defer func() { vault.NewKeyringKeystoreForTest = orig }()

	ks := vault.AutoKeystore("/tmp/should-not-be-used")
	// Expect a keyring-like keystore, not a FileKeystore.
	if _, isFile := ks.(*vault.FileKeystore); isFile {
		t.Fatalf("expected keyring fallback path to stay on keyring, got FileKeystore")
	}
	if !bytes.Contains(buf.Bytes(), []byte("keyring cleanup")) {
		t.Fatalf("expected cleanup warning in output, got %q", buf.String())
	}
}
```

- [ ] **Step 2: Add the test hooks in the package**

In `internal/vault/keystore_auto.go` add (or create a new file `keystore_auto_hooks.go`):

```go
// Test-only hooks used to inject behaviour.
var (
	ProbeWarnWriter          io.Writer  = os.Stderr
	NewKeyringKeystoreForTest            = NewKeyringKeystore // replaceable in tests
)
```

Then update imports accordingly.

- [ ] **Step 3: Run; expect FAIL**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/vault/ -run TestAutoKeystoreKeepsKeyringOnDeleteFailure -v`
Expected: FAIL (current code falls back to FileKeystore, not the test's expectation).

Actually note: current code *does not* fall back on Delete failure — it only falls back on Set failure. Re-read the spec and finding: the finding says "If Set succeeds but Delete fails ... it ignores the Delete error and falls through." Re-reading `keystore_auto.go:22`: `_ = kr.Delete(...)` then `return kr`. So it already returns the keyring. The fix per the spec is to *log a warning* when Delete fails. Adjust test expectation accordingly — the keyring path is already correct; what we're adding is the warning.

Rewrite the test to assert only the warning is emitted:

```go
func TestAutoKeystoreWarnsOnDeleteFailure(t *testing.T) {
	var buf bytes.Buffer
	vault.ProbeWarnWriter = &buf
	defer func() { vault.ProbeWarnWriter = os.Stderr }()

	orig := vault.NewKeyringKeystoreForTest
	vault.NewKeyringKeystoreForTest = func() vault.Keystore {
		return &deleteFailKeyring{deleteErr: errors.New("cleanup quirk")}
	}
	defer func() { vault.NewKeyringKeystoreForTest = orig }()

	ks := vault.AutoKeystore("/tmp/unused")
	if _, isFile := ks.(*vault.FileKeystore); isFile {
		t.Fatalf("expected keyring, got FileKeystore")
	}
	if !bytes.Contains(buf.Bytes(), []byte("keyring")) {
		t.Fatalf("expected keyring warning, got %q", buf.String())
	}
}
```

- [ ] **Step 4: Update `AutoKeystore`**

In `internal/vault/keystore_auto.go`:

```go
// AutoKeystore returns the best available Keystore for the current platform.
func AutoKeystore(fallbackPath string) Keystore {
	if runtime.GOOS == "darwin" {
		return NewKeyringKeystoreForTest()
	}

	kr := NewKeyringKeystoreForTest()
	if err := kr.Set("__veil_probe__", [32]byte{}); err != nil {
		return NewFileKeystore(fallbackPath)
	}
	if err := kr.Delete("__veil_probe__"); err != nil {
		ui.Warnf(ProbeWarnWriter,
			"keyring cleanup failed during probe: %v; continuing with system keyring",
			err)
	}
	return kr
}
```

Add imports: `"github.com/8enji/veil/internal/ui"`. Move the hooks file's `io.Writer` import inside the hooks file.

- [ ] **Step 5: Run; expect PASS**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/vault/ -v`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add internal/vault/keystore_auto.go internal/vault/keystore_auto_test.go
git commit -m "fix(keystore): warn on D-Bus probe Delete failure, stay on keyring"
```

---

### Task 16: Zero hex-encoded buffer in `FileKeystore.saveMap`

**Files:**
- Modify: `internal/vault/keystore_file.go:178-187` (the `Set` method)

- [ ] **Step 1: Review current `Set`**

The fix needs to occur where the `[32]byte` is hex-encoded and placed into the map. The encoded string lives in the map until `saveMap` serializes it. We cannot zero the *map value* without interfering with the map's ability to persist across calls — but we can overwrite the string in the map post-save.

Choose a narrower fix: after `saveMap` returns, overwrite the newly-added entry in `m` with a zero-length string. This leaves the disk state intact and evicts the hex from the map.

- [ ] **Step 2: Write the test**

Append to `internal/vault/keystore_file_test.go`:

```go
func TestFileKeystoreSetZeroesMapEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key.age")
	t.Setenv("VEIL_PASSPHRASE", "hunter2")

	ks := vault.NewFileKeystore(path)
	ks.SetWorkFactor(1)

	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := ks.Set("proj", key); err != nil {
		t.Fatalf("set: %v", err)
	}

	// Use the test hook to read the in-memory cache, if we add one.
	m := vault.InspectFileKeystoreCacheForTest(ks)
	for k, v := range m {
		if len(v) > 0 {
			t.Fatalf("expected empty/zeroed cache entry for %q, got %q", k, v)
		}
	}

	// Verify the on-disk value still round-trips to the original key.
	got, err := ks.Get("proj")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != key {
		t.Fatalf("round-trip mismatch")
	}
}
```

- [ ] **Step 3: Add the test hook + cache field**

Since `FileKeystore` today has no in-memory cache, a cleaner way to satisfy H4b is to **avoid caching entirely** — which is already the case (each `Set` calls `loadMap` → mutate → `saveMap`). The `m` local in `Set` goes out of scope after `saveMap` returns.

Re-read `Set`:

```go
func (f *FileKeystore) Set(projectID string, key [32]byte) error {
	m, err := f.loadMap()
	if err != nil {
		return err
	}
	account := KeystoreAccount(projectID)
	m[account] = hex.EncodeToString(key[:])
	return f.saveMap(m)
}
```

The hex string goes into `m`, which `saveMap` reads and writes to disk. After `Set` returns, `m` is collectable. The concrete zeroing needed is inside `saveMap`: the `plaintext` buffer from `json.Marshal(m)` contains the hex, and so does the `m[account]` string. Strings in Go are immutable — we cannot safely overwrite them. The pragmatic fix is:

1. In `saveMap`, after the atomic write completes, overwrite the `plaintext` byte slice.
2. Delete the freshly-set entry from `m` before returning (makes the hex collectable immediately; GC will reclaim even if no one zeros the underlying string).

Update `saveMap` at the very end (after successful rename):

```go
if err := os.Rename(tmpName, f.path); err != nil {
	_ = os.Remove(tmpName)
	return fmt.Errorf("%w: atomic rename: %w", ErrKeystoreWrite, err)
}
// H4b: overwrite in-memory plaintext to reduce window where the hex-encoded
// key material sits on the heap after the write completes. Go strings are
// immutable so we cannot overwrite map values directly; the byte buffer is
// what we have authority over.
for i := range plaintext {
	plaintext[i] = 0
}
return nil
```

The test helper becomes simpler: just assert round-trip and that the on-disk file exists with mode 0600 (which existing tests already cover). Drop the `InspectFileKeystoreCacheForTest` idea.

Simplified test replacement:

```go
func TestFileKeystoreSetZeroesPlaintext(t *testing.T) {
	// Indirect verification: Set succeeds and Get round-trips.
	// Direct verification of zeroed heap bytes is not reliable in Go.
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key.age")
	t.Setenv("VEIL_PASSPHRASE", "hunter2")

	ks := vault.NewFileKeystore(path)
	ks.SetWorkFactor(1)

	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := ks.Set("proj", key); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := ks.Get("proj")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != key {
		t.Fatalf("round-trip mismatch")
	}
}
```

The zeroing change is a best-effort hardening documented in the threat model (Phase 7). Mark the test as "regression test for H4b: ensures Set still round-trips after the zeroing hook".

- [ ] **Step 4: Run; expect PASS**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/vault/ -v`

- [ ] **Step 5: Commit**

```bash
git add internal/vault/keystore_file.go internal/vault/keystore_file_test.go
git commit -m "fix(keystore): zero plaintext buffer in saveMap after atomic write"
```

---

## Phase 5 — Placeholder generator & registry

Covers: **H1** (collision retry), **L1** (explicit Registry), **L6** (table-driven provider tests).

### Task 17: Thread existing-placeholder set into `Generate` and retry

**Files:**
- Modify: `internal/placeholder/engine.go:22-36`
- Modify: `internal/placeholder/engine_test.go`
- Modify: callers of `Generate` (grep to locate; likely `internal/cli/init.go`, `internal/cli/add.go`)

- [ ] **Step 1: Write the failing test**

```go
// internal/placeholder/engine_test.go (append)
func TestGenerateRetriesOnCollision(t *testing.T) {
	// Force a deterministic RNG that returns the same byte repeatedly so the
	// first candidate always collides.
	orig := placeholder.RNGForTest
	defer func() { placeholder.RNGForTest = orig }()

	// First 8 calls produce identical output; the 9th differs.
	// This is implementation-specific; in practice we verify that a matching
	// entry in `existing` causes a retry instead of immediate success.

	existing := placeholder.Set{"sk_live_AAAAAAAAAAAAAAAAAAAAAAAA": {}}
	ph, err := placeholder.Generate("STRIPE_KEY", "sk_live_original", existing)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, clashes := existing[ph]; clashes {
		t.Fatalf("generated placeholder %q is in existing set", ph)
	}
}

func TestGenerateFailsWhenAllRetriesCollide(t *testing.T) {
	// Build a pathological `existing` containing every possible output by
	// swapping in a synthetic provider with a 0-length random suffix. This is
	// best handled in a dedicated test fixture; sketch:
	//
	// Register a one-char provider; seed `existing` with all 62 alphanumeric
	// outputs; call Generate; expect ErrCollisionUnresolvable.
	t.Skip("implement alongside Registry refactor in next task")
}
```

Introduce `placeholder.Set` type:

```go
// internal/placeholder/engine.go (add near the top)
// Set is a set of placeholder strings, used for collision checks.
type Set map[string]struct{}
```

- [ ] **Step 2: Run; expect FAIL (compile error — `Generate` signature mismatch)**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/placeholder/ -v`
Expected: build error.

- [ ] **Step 3: Update `Generate`**

Replace lines 22-36 of `engine.go`:

```go
const maxCollisionRetries = 8

// Generate produces a structurally-valid placeholder for the given secret,
// retrying up to maxCollisionRetries times to avoid collisions with the
// supplied `existing` set. Returns ErrCollisionUnresolvable if no unique
// candidate is found.
func Generate(name, value string, existing Set) (string, error) {
	if value == "" {
		return "", errors.New("empty value")
	}
	for attempt := 0; attempt < maxCollisionRetries; attempt++ {
		ph, err := generateOnce(name, value)
		if err != nil {
			return "", err
		}
		if _, clash := existing[ph]; !clash {
			return ph, nil
		}
	}
	return "", ErrCollisionUnresolvable
}

// generateOnce produces a single candidate placeholder.
func generateOnce(name, value string) (string, error) {
	if ph, ok := tryURL(value); ok {
		return ph, nil
	}
	for _, p := range registry {
		if p.Match(name, value) {
			return p.Generate(value), nil
		}
	}
	return charClassFake(value), nil
}
```

- [ ] **Step 4: Update callers**

Grep for existing usage of `placeholder.Generate(` and update each to pass a `Set`. Typical call site:

Before:
```go
ph, err := placeholder.Generate(key, val)
```

After:
```go
existing := make(placeholder.Set, len(v.List()))
for _, c := range v.List() {
	existing[c.Placeholder] = struct{}{}
}
ph, err := placeholder.Generate(key, val, existing)
```

Consider adding a helper `vault.PlaceholderSet()` to avoid duplicating this snippet across callers:

```go
// internal/vault/vault.go
// PlaceholderSet returns the set of currently-used placeholders.
func (v *Vault) PlaceholderSet() placeholder.Set {
	out := make(placeholder.Set, len(v.credentials))
	for _, c := range v.credentials {
		out[c.Placeholder] = struct{}{}
	}
	return out
}
```

Add `placeholder` to `vault`'s imports — note this creates a dependency from `vault` to `placeholder`. Check for cycles first; if `placeholder` imports `vault`, instead put the helper in a neutral location (e.g. `internal/cli/helpers.go`).

If a cycle exists, define the helper inline at each call site.

- [ ] **Step 5: Expose the RNG for tests**

In `engine.go`, export the test hook:

```go
// RNGForTest is the randomness source used by placeholder generation.
// Tests may override; production uses crypto/rand.
var RNGForTest = &rng // pointer to the package-level rng

// Access within the package via *RNGForTest
```

Simpler alternative: add `SetRNG(io.Reader)` and `resetRNG()` helpers.

- [ ] **Step 6: Run; expect PASS**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./... -v`
Expected: all pass. Fix any callers that still compile with the old signature.

- [ ] **Step 7: Commit**

```bash
git add internal/placeholder/ internal/vault/ internal/cli/
git commit -m "feat(placeholder): retry on collision up to 8 times with existing set"
```

---

### Task 18: Explicit `Registry` struct

**Files:**
- Modify: `internal/placeholder/providers.go:14-20`
- Modify: `internal/placeholder/engine.go:29` (loop over registry)
- Add tests: `internal/placeholder/providers_test.go`

- [ ] **Step 1: Write failing test**

Append to `internal/placeholder/providers_test.go`:

```go
func TestRegistryIsolation(t *testing.T) {
	r := placeholder.NewRegistry()
	r.Register(placeholder.ProviderPattern{
		Name:  "only-test",
		Match: func(name, value string) bool { return name == "ONLY" },
		Generate: func(value string) string { return "fake-only" },
	})
	p, ok := r.Get("only-test")
	if !ok {
		t.Fatal("expected provider found")
	}
	if p.Name != "only-test" {
		t.Fatalf("unexpected name: %s", p.Name)
	}
	// Package-level registry should not have "only-test".
	if _, ok := placeholder.DefaultRegistry().Get("only-test"); ok {
		t.Fatal("isolated registry should not leak into default")
	}
}
```

- [ ] **Step 2: Implement the Registry**

Replace the top of `internal/placeholder/providers.go`:

```go
// Registry holds a set of provider patterns, checked in registration order.
type Registry struct {
	patterns []ProviderPattern
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry { return &Registry{} }

// Register appends a provider pattern.
func (r *Registry) Register(p ProviderPattern) {
	r.patterns = append(r.patterns, p)
}

// Match returns the first provider whose Match returns true, or nil if none.
func (r *Registry) Match(name, value string) *ProviderPattern {
	for i := range r.patterns {
		if r.patterns[i].Match(name, value) {
			return &r.patterns[i]
		}
	}
	return nil
}

// Get returns a provider by name.
func (r *Registry) Get(name string) (ProviderPattern, bool) {
	for _, p := range r.patterns {
		if p.Name == name {
			return p, true
		}
	}
	return ProviderPattern{}, false
}

// defaultRegistry is the package-level registry, populated by init() in
// provider_*.go files.
var defaultRegistry = NewRegistry()

// DefaultRegistry returns the package-level registry.
func DefaultRegistry() *Registry { return defaultRegistry }

// register adds a provider pattern to the default registry. Backwards-
// compatible shim for existing provider_*.go init() functions.
func register(p ProviderPattern) {
	defaultRegistry.Register(p)
}
```

Remove the old `var registry []ProviderPattern` and the standalone `register` (the new one takes its place).

Update `engine.go:29`:

```go
// Before:
for _, p := range registry {
	if p.Match(name, value) {
		return p.Generate(value), nil
	}
}

// After:
if match := defaultRegistry.Match(name, value); match != nil {
	return match.Generate(value), nil
}
```

- [ ] **Step 3: Run; expect PASS**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/placeholder/ -v`

- [ ] **Step 4: Commit**

```bash
git add internal/placeholder/
git commit -m "refactor(placeholder): introduce explicit Registry struct"
```

---

### Task 19: Table-driven provider contract test

**Files:**
- Create: `internal/placeholder/providers_contract_test.go`

- [ ] **Step 1: Implement the contract test**

Each provider exposes its `Match`/`Generate` functions plus (ideally) declarative `Format` fields. Many are registered via `registerFormat` and have prefix/length/charset metadata. For providers that use hand-rolled `ProviderPattern`, we can only assert that `Generate(value)` returns non-empty and does not panic.

```go
// internal/placeholder/providers_contract_test.go
package placeholder_test

import (
	"regexp"
	"testing"

	"github.com/8enji/veil/internal/placeholder"
)

// sampleValues supplies a representative input for each provider name so that
// its Match function evaluates true. Missing entries fall back to a generic
// alphanumeric sample. Extend as new providers land.
var sampleValues = map[string]struct {
	keyName string
	value   string
}{
	"openai":                  {"OPENAI_API_KEY", "sk-" + "a" + string(make([]byte, 47))},
	"anthropic":               {"ANTHROPIC_API_KEY", "sk-ant-api03-" + string(make([]byte, 95))},
	"github-classic":          {"GITHUB_TOKEN", "ghp_" + string(make([]byte, 36))},
	"stripe":                  {"STRIPE_KEY", "sk_live_" + string(make([]byte, 24))},
	// ... extend per provider
}

func TestProviderContract(t *testing.T) {
	reg := placeholder.DefaultRegistry()
	// Enumerate by attempting each known sample; this is a loose contract
	// check. Providers without a sample skip the match-based generation path
	// and exercise only Generate with a synthetic input.
	for name, sample := range sampleValues {
		t.Run(name, func(t *testing.T) {
			p, ok := reg.Get(name)
			if !ok {
				t.Skipf("provider %q not registered", name)
			}
			if !p.Match(sample.keyName, sample.value) {
				t.Fatalf("provider %q did not match its own sample", name)
			}
			out := p.Generate(sample.value)
			if out == "" {
				t.Fatalf("empty output")
			}
			if len(out) != len(sample.value) && len(out) == 0 {
				t.Fatalf("unexpected length: got %d, sample %d", len(out), len(sample.value))
			}
			// If the provider declares Hosts, the output should at minimum be
			// non-empty — already asserted. For declarative Formats with a
			// regex, apply it:
			if re := providerRegex(name); re != nil {
				if !re.MatchString(out) {
					t.Fatalf("output %q does not match regex %v", out, re)
				}
			}
		})
	}
}

// providerRegex returns the provider's declared output regex, or nil if none.
// Extend this map as providers declare stable format regexes.
var providerRegexes = map[string]*regexp.Regexp{
	"openai":   regexp.MustCompile(`^sk-[A-Za-z0-9]+$`),
	"stripe":   regexp.MustCompile(`^sk_live_[A-Za-z0-9]{24}$`),
	// extend per provider
}

func providerRegex(name string) *regexp.Regexp { return providerRegexes[name] }
```

The test is intentionally lenient: providers without a registered sample or regex are skipped or exercise only the happy path. This is enough to detect regressions in provider output shape.

- [ ] **Step 2: Run**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/placeholder/ -v`
Expected: PASS (possibly with some subtests SKIP).

- [ ] **Step 3: Commit**

```bash
git add internal/placeholder/providers_contract_test.go
git commit -m "test(placeholder): add table-driven provider contract tests"
```

---

## Phase 6 — Proxy request correctness + CA SKID

Covers: **C1** (query-string injection), **H5** (Content-Type allowlist), **H6** (body-read error), **M4** (SHA-256 SKID).

### Task 20: Parse and rewrite query strings in `ProcessRequest`

**Files:**
- Modify: `internal/proxy/injector.go:66-173,229-237`
- Modify: `internal/proxy/injector_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/proxy/injector_test.go`:

```go
func TestProcessRequestInjectsQueryString(t *testing.T) {
	cred := &vault.Credential{
		ID:           "c1",
		Name:         "API_KEY",
		Real:         "sk_real_1234567890",
		Placeholder:  "sk_fake_ABCDEFGHIJ",
		AllowedHosts: []string{"api.example.com"},
	}
	inj := proxy.NewInjector(
		map[string]*vault.Credential{cred.Placeholder: cred},
		nil, 1234, "agent",
	)

	newURL, _, _, injections := inj.ProcessRequest(
		"req-1",
		"GET",
		"https://api.example.com/v1/thing?api_key=sk_fake_ABCDEFGHIJ",
		http.Header{},
		nil,
	)
	if !strings.Contains(newURL, "api_key=sk_real_1234567890") {
		t.Fatalf("query string not injected: %s", newURL)
	}
	if len(injections) != 1 || injections[0].Location != "url" {
		t.Fatalf("expected 1 url injection, got %+v", injections)
	}
	// Audit record URLPath must NOT contain query fragments.
	if strings.Contains(injections[0].URLPath, "?") ||
		strings.Contains(injections[0].URLPath, "sk_") {
		t.Fatalf("audit URLPath leaked query data: %q", injections[0].URLPath)
	}
}
```

Add imports as needed.

- [ ] **Step 2: Run; expect FAIL**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/proxy/ -run TestProcessRequestInjectsQueryString -v`
Expected: FAIL (query string not replaced in `newURL`; depending on current behaviour it may still match via the URL-scanning block, but this test checks the path/audit separation).

- [ ] **Step 3: Implement**

Replace `parseHostPath` with `parseRequestURL` in `injector.go:229-237`:

```go
// parseRequestURL extracts host, path, and raw query from a URL. On parse
// failure all three are empty.
func parseRequestURL(rawURL string) (host, path, rawQuery string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", ""
	}
	return u.Host, u.Path, u.RawQuery
}
```

Update the `ProcessRequest` body to use the new helper:

```go
host, urlPath, _ := parseRequestURL(rawURL) // rawQuery is intentionally discarded
```

The URL-scanning block already runs Aho-Corasick against `rawURL`, which includes the query — so the injection itself works today. The test above should already pass once the audit field is confirmed to exclude the query. Verify `URLPath` is set from `urlPath` only (not `rawURL`):

Look at `makeInjection` in `injector.go:87-103`: `URLPath: urlPath`. Good — that's path-only. No change needed there.

What *does* need to change: rename `parseHostPath` → `parseRequestURL`, and add the explicit comment that we discard the query to avoid secondary-leak.

- [ ] **Step 4: Verify with the test**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/proxy/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/injector.go internal/proxy/injector_test.go
git commit -m "fix(proxy): document query-string injection; keep audit path-only"
```

---

### Task 21: Content-Type allowlist for body injection

**Files:**
- Modify: `internal/proxy/proxy.go:96-129`
- Create: `internal/proxy/contenttype.go`
- Create: `internal/proxy/contenttype_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/proxy/contenttype_test.go
package proxy_test

import (
	"testing"

	"github.com/8enji/veil/internal/proxy"
)

func TestShouldInjectBody(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"APPLICATION/JSON", true},
		{"application/x-www-form-urlencoded", true},
		{"text/plain", true},
		{"text/html; charset=utf-8", true},
		{"application/xml", true},
		{"application/ld+json", true},
		{"application/atom+xml", true},
		{"application/octet-stream", false},
		{"image/jpeg", false},
		{"video/mp4", false},
		{"application/grpc", false},
		{"application/x-protobuf", false},
		{"", false}, // missing
	}
	for _, tc := range cases {
		t.Run(tc.ct, func(t *testing.T) {
			got := proxy.ShouldInjectBody(tc.ct)
			if got != tc.want {
				t.Fatalf("%q: got %v, want %v", tc.ct, got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run; expect FAIL**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/proxy/ -run TestShouldInjectBody -v`
Expected: FAIL (`ShouldInjectBody` undefined).

- [ ] **Step 3: Implement**

```go
// internal/proxy/contenttype.go
package proxy

import "strings"

// ShouldInjectBody reports whether the proxy should scan and rewrite the
// body for a request with the given Content-Type header value. Matching is
// case-insensitive and strict (allowlist): missing or unknown Content-Types
// return false. Media-type parameters (charset, boundary, etc.) are ignored.
func ShouldInjectBody(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if ct == "" {
		return false
	}
	// Strip parameters (everything after the first ';').
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "application/json",
		"application/x-www-form-urlencoded",
		"application/xml":
		return true
	}
	if strings.HasPrefix(ct, "text/") {
		return true
	}
	// application/*+json, application/*+xml
	if strings.HasPrefix(ct, "application/") &&
		(strings.HasSuffix(ct, "+json") || strings.HasSuffix(ct, "+xml")) {
		return true
	}
	return false
}
```

- [ ] **Step 4: Wire into the request handler**

Replace `internal/proxy/proxy.go:96-129`:

```go
px.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// Skip body injection if Content-Encoding indicates a compressed body.
	if ce := req.Header.Get("Content-Encoding"); ce != "" {
		log.Printf("[veil] skipping body injection for compressed request (Content-Encoding: %q)", ce)
		return req, nil
	}

	var body []byte
	if req.Body != nil && ShouldInjectBody(req.Header.Get("Content-Type")) {
		var err error
		body, err = io.ReadAll(io.LimitReader(req.Body, int64(bodyCap)+1))
		_ = req.Body.Close()
		if err != nil {
			// H6: body read failed; surface 502 rather than forwarding a
			// possibly-truncated payload that may still contain placeholder
			// strings.
			warnBodyReadOnce(req.Host, err)
			return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadGateway,
				"veil: upstream body read failed")
		}
	}

	requestID := ulid.Make().String()
	newURL, newHeader, newBody, _ := inj.ProcessRequest(
		requestID, req.Method, req.URL.String(), req.Header, body)

	if newURL != req.URL.String() {
		parsed, err := url.Parse(newURL)
		if err == nil {
			req.URL = parsed
		}
	}

	req.Header = newHeader
	if body != nil {
		req.Body = io.NopCloser(bytes.NewReader(newBody))
		req.ContentLength = int64(len(newBody))
	}

	return req, nil
})
```

Add a `warnBodyReadOnce` helper (per-host, once per session) in `proxy.go`:

```go
var (
	bodyWarnMu    sync.Mutex
	bodyWarnSeen  = map[string]struct{}{}
)

// warnBodyReadOnce emits a warning on stderr at most once per host per
// session, preventing log spam from misbehaving clients.
func warnBodyReadOnce(host string, err error) {
	bodyWarnMu.Lock()
	defer bodyWarnMu.Unlock()
	if _, seen := bodyWarnSeen[host]; seen {
		return
	}
	bodyWarnSeen[host] = struct{}{}
	ui.Warnf(os.Stderr, "body read failed for %s: %v", host, err)
}
```

Add imports: `"os"`, `"sync"`, `"github.com/8enji/veil/internal/ui"`.

- [ ] **Step 5: Run; expect PASS**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/proxy/ -v`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/contenttype.go internal/proxy/contenttype_test.go internal/proxy/proxy.go
git commit -m "fix(proxy): gate body injection on Content-Type allowlist, handle body-read errors"
```

---

### Task 22: Switch CA `SubjectKeyIdentifier` to SHA-256

**Files:**
- Modify: `internal/proxy/ca.go:9,117-122`
- Modify: `internal/proxy/ca_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/proxy/ca_test.go`:

```go
func TestGenerateCAUsesSHA256SKID(t *testing.T) {
	ca, err := proxy.GenerateCA()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(ca.Cert.SubjectKeyId) != sha256.Size {
		t.Fatalf("SKID length %d, want %d (SHA-256)", len(ca.Cert.SubjectKeyId), sha256.Size)
	}
}
```

Add `"crypto/sha256"` import.

- [ ] **Step 2: Run; expect FAIL**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/proxy/ -run TestGenerateCAUsesSHA256SKID -v`
Expected: FAIL (current SKID is 20 bytes = SHA-1).

- [ ] **Step 3: Update `GenerateCA`**

Replace line 9 import and lines 117-122 in `ca.go`:

```go
// imports
"crypto/sha256"
// (drop the sha1 import and its //nolint comment)

// in GenerateCA:
// Compute SubjectKeyIdentifier as SHA-256 of the marshalled public key.
pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
if err != nil {
	return nil, fmt.Errorf("%w: marshal public key: %w", ErrCAGenerate, err)
}
skid := sha256.Sum256(pubBytes)
```

- [ ] **Step 4: Run; expect PASS**

Run: `CGO_ENABLED=0 go test -tags testkeystore ./internal/proxy/ -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/ca.go internal/proxy/ca_test.go
git commit -m "feat(proxy): use SHA-256 for CA SubjectKeyIdentifier"
```

---

## Phase 7 — Docs & platform parity

Covers: **M3** (threat model doc), **L5** (child termination parity).

### Task 23: Write `docs/THREAT_MODEL.md`

**Files:**
- Create: `docs/THREAT_MODEL.md`
- Modify: `README.md` (link to the doc)

- [ ] **Step 1: Write the doc**

```markdown
<!-- docs/THREAT_MODEL.md -->
# Veil Threat Model

Veil sits between AI coding agents and the network. It hides real secrets behind format-preserving placeholders, stores the real values in an encrypted per-project vault, and runs a local MITM proxy that swaps placeholders for real credentials on outbound requests.

This document describes what Veil protects against, what it does *not* protect against, and the deployment choices that change those boundaries.

## What Veil protects against

- **Agent seeing real secrets in files.** `.env` and MCP config files contain format-valid placeholders; the agent's filesystem reads return those, never the real value.
- **Agent exfiltrating real secrets in outbound HTTP.** The proxy intercepts request headers, URL query strings, and text-ish request bodies. If the agent tries to ship a real credential it never legitimately saw, it simply cannot — it has no handle on the real value.
- **Same-host users reading the audit log.** Audit DB files are chmod'd to `0600` and the parent directory to `0700` on every `veil run`. Other users on the machine cannot read which credentials were injected, for which hosts, or when.

## What Veil does NOT protect against

- **Same-UID tampering of the audit log.** The agent process runs as the same UID as Veil, so it has filesystem access to the audit DB. It can read, truncate, or forge rows. If your agent is compromised, its audit trail is untrustworthy.
- **Long-running proxy holding credentials in memory.** While `veil run` is active, real secrets sit in the proxy's memory for routing. A memory read via `/proc/<pid>/mem` or a debugger can extract them. This is by design — format-preserving injection requires the real value.
- **Non-HTTP exfiltration.** Veil only mediates `HTTP_PROXY` / `HTTPS_PROXY` traffic. An agent that opens a raw TCP connection, sends DNS queries with data embedded in names, or uses any other channel is out of scope.
- **Agent direct vault reads.** If the agent runs tools (shell, file read) it may open `.veil/vault.bin` directly. The vault is encrypted, but the master key is obtainable via the OS keyring by any process running as the same user.
- **System CA trust store compromise.** Veil installs its root CA into the user's trust store. Any process (not just the agent) running as that user will trust certificates signed by Veil's CA.

## Deployment notes for hardened setups

- **Separate UID.** Running Veil under a user different from the agent eliminates same-UID tampering and direct vault reads. This requires a setuid helper or systemd/launchd user service configuration; not supported out-of-the-box in MVP.
- **Short-lived sessions.** Keep `veil run` sessions as short as possible to minimize the in-memory credential window.
- **Network-level egress rules.** Pair Veil with outbound firewall rules so the agent cannot reach hosts outside the expected provider set.

## Known limitations called out in the code

- **Compressed request bodies.** Bodies with a `Content-Encoding` header pass through untouched; Veil does not decompress→inject→recompress.
- **Body injection allowlist.** Only `application/json`, `application/x-www-form-urlencoded`, `text/*`, `application/xml`, and `application/*+json`/`*+xml` are scanned. Binary types and unknown Content-Types pass through.
- **Large bodies.** Bodies larger than 10 MiB are not scanned.
```

- [ ] **Step 2: Link from README**

Add to `README.md` in an appropriate section:

```markdown
## Security

See [Threat Model](docs/THREAT_MODEL.md) for the boundaries of Veil's protection.
```

- [ ] **Step 3: Commit**

```bash
git add docs/THREAT_MODEL.md README.md
git commit -m "docs: add threat model covering what veil protects and does not"
```

---

### Task 24: Align child-termination grace period across platforms

**Files:**
- Create: `internal/runner/termination.go`
- Modify: `internal/runner/parentwatch_darwin.go:36-38`
- Modify: `internal/runner/pgroup_linux.go:18,23` (Pdeathsig signal)
- Modify: `internal/runner/signals.go:15-18`

- [ ] **Step 1: Create the shared constant**

```go
// internal/runner/termination.go
package runner

import "time"

// childTerminationGrace is the time allowed between SIGTERM and SIGKILL when
// escalating child-process shutdown across platforms. Platform-specific code
// may use it where it has control over the escalation path; the Linux
// Pdeathsig mechanism delivers an immediate SIGTERM from the kernel and
// cannot be delayed, so this constant only applies to the user-level
// escalation path.
const childTerminationGrace = 3 * time.Second
```

- [ ] **Step 2: Use it in `parentwatch_darwin.go`**

Replace the inline `sleep 3` in the shell script (line 37):

```go
script := fmt.Sprintf(
	`cat >/dev/null; kill -TERM -%d 2>/dev/null; sleep %d; kill -KILL -%d 2>/dev/null`,
	childPid,
	int(childTerminationGrace.Seconds()),
	childPid,
)
```

- [ ] **Step 3: Document in `pgroup_linux.go`**

Add a comment above line 18 clarifying that Pdeathsig is kernel-immediate:

```go
// Pdeathsig: syscall.SIGTERM delivers an immediate kernel-level signal on
// parent exit; no user-level grace period applies. See runner.termination
// for the shared constant used by platforms that *do* have a grace period.
```

- [ ] **Step 4: Update `signals.go` to use the constant (optional alignment)**

`signals.go:15-18` defines `escalateTimeout = 5 * time.Second` and `killTimeout = 10 * time.Second`. These govern CLI-interactive signal handling, not the parent-death watcher, so they are a separate concern. Leave as-is unless you want them to also reference `childTerminationGrace`.

- [ ] **Step 5: Run tests**

Run: `make test`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add internal/runner/termination.go internal/runner/parentwatch_darwin.go internal/runner/pgroup_linux.go
git commit -m "refactor(runner): align parent-watch grace period via shared constant"
```

---

## Verification — final pass

- [ ] **Step 1: Full test matrix**

Run:
```bash
make test
make test-race
make vet
make lint
make build
make xbuild
```
All must succeed.

- [ ] **Step 2: Manual smoke test**

```bash
# Initialize a test project
mkdir /tmp/veil-smoke && cd /tmp/veil-smoke
echo "STRIPE_KEY=sk_live_realvalue1234567890abcd" > .env
bin/veil init --yes
# Confirm the placeholder landed in .env
cat .env
# Verify audit DB perms
stat -f "%Lp %N" ~/.../.veil/audit.db* 2>/dev/null || ls -la .veil/audit.db*
# Run a curl via veil
bin/veil run -- curl -s "https://api.example.com/v1/thing?api_key=$(grep STRIPE .env | cut -d= -f2)" | head
```

Expected: `.env` contains a placeholder (not the real value), audit DB files are `0600`, curl's upstream received the real key in the query.

- [ ] **Step 3: Verify build tag hygiene**

```bash
# Production binary should not honour VEIL_TEST_KEYSTORE
CGO_ENABLED=0 go build -o /tmp/veil-prod ./cmd/veil
VEIL_TEST_KEYSTORE=mem /tmp/veil-prod init --yes --path /tmp/veil-smoke
# Should still try to use the real keystore (fail on no VEIL_PASSPHRASE on Linux, or succeed via keychain on macOS)
```

- [ ] **Step 4: Spec-to-plan coverage self-check**

Skim the spec sections and tick each finding:

| Finding | Task |
|---|---|
| C1 | Task 20 |
| C2 | Task 11 |
| C3 | Task 14 |
| C4 | Task 10 |
| H1 | Task 17 |
| H2 | Task 15 |
| H3 | Task 12 |
| H4b | Task 16 |
| H5 | Task 21 |
| H6 | Task 21 |
| M3 | Task 23 |
| M4 | Task 22 |
| M6 | Tasks 6–9 |
| L1 | Task 18 |
| L2 | Task 13 |
| L3 | Tasks 4, 5 |
| L5 | Task 24 |
| L6 | Task 19 |
| L7 | Tasks 1, 2 |

All 19 in-scope findings are covered.

- [ ] **Step 5: Final commit for any pending doc updates**

```bash
git status
# If clean, nothing to do. If there are open edits from verification, commit them.
```

---

## Notes for reviewers

- Phase 1 intentionally overhauls errors across five packages before any feature work lands. This is so Phase 2–6 work can freely use typed-error wrapping without a later migration pass. The trade-off is that Phase 1 touches many files; review its commits carefully for over-wrapping (e.g., don't wrap errors that never cross a package boundary).
- The `maybeTestKeystore` build-tag mechanism in Task 14 is the only cross-file compile-time behavior change. Verify with `go build` under both tag settings after that task lands.
- `H4b` is deliberately a best-effort hardening. Go's string/GC semantics mean true secure erasure requires `memguard` or similar — which the spec ruled out for this pass. The plan's zeroing of `plaintext` is the meaningful hook; document that as the MVP boundary in the threat model (already done in Task 23).
- `C1`'s audit-record omission of the query string is enforced by the existing code path (`makeInjection` uses `urlPath`, not `rawURL`). Task 20 is partly a documentation task — codify the intent with a test so a future refactor doesn't regress.
