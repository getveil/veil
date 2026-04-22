# Testing Gaps Remediation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the test-coverage gaps flagged in the 2026-04-22 codebase audit §6.2/§6.3 — add fuzzing for parsers, remove flaky sleep-based timing, eliminate `/tmp` global-state writes, exercise the HTTPS path end-to-end, isolate e2e keystore state from the real OS keychain, and deduplicate test helpers — **without touching production code** (except to expose narrow test helpers if unavoidable).

**Architecture:** Eight independent test-only tasks. Tasks 1–3 (consolidation, audit sleeps, tmp dirs) are small surgical refactors that rely on existing internal APIs. Tasks 4–6 add Go native fuzzing (`go test -fuzz=`) to the scanner, placeholder, and proxy packages — each ~20 LoC plus a seed corpus. Task 7 adds one E2E that shells curl against an `httptest.NewTLSServer` through a real proxy subprocess. Task 8 repoints e2e `HOME` at a per-test temp dir so the file-fallback keystore replaces the login-keychain path — no more persistent entries in whoever runs `make test`.

**Tech Stack:** Go 1.22+ native fuzzing, `testing.T.TempDir`, `httptest.NewTLSServer`, curl (assumed present on CI macOS/Linux), modernc.org/sqlite (audit), existing `internal/testutil` package.

---

## File Structure

**Files to create:**
- `internal/scanner/fuzz_test.go` — `FuzzParseEnvFile`
- `internal/scanner/testdata/fuzz/FuzzParseEnvFile/seed_comprehensive` — seed from `test/fixtures/envs/comprehensive.env`
- `internal/scanner/testdata/fuzz/FuzzParseEnvFile/seed_edge` — edge cases (unclosed quotes, export prefix, inline comments)
- `internal/placeholder/fuzz_test.go` — `FuzzPlaceholderReplace`
- `internal/placeholder/testdata/fuzz/FuzzPlaceholderReplace/seed_*` — per-provider seed files
- `internal/proxy/fuzz_test.go` — `FuzzDecodeBasic`
- `internal/proxy/testdata/fuzz/FuzzDecodeBasic/seed_*` — valid + adversarial base64 inputs
- `test/integration/https_e2e_test.go` — `TestE2E_ProxyHTTPSInjection` with curl subprocess

**Files to modify:**
- `internal/testutil/testutil.go` — extend `MakeCred` with variadic hosts; add `SetupVaultProject`
- `internal/testutil/testutil_test.go` — extend existing tests to cover new signature
- `internal/proxy/injector_test.go` — replace local `makeCred` with `testutil.MakeCred`
- `internal/runner/runner_test.go` — replace `setupProject` with `testutil.SetupVaultProject`; fix `TestSweepStaleSessionDirs` to use scoped temp dir
- `internal/runner/runner.go` — expose `sweepStaleSessionDirsIn(root string)` or extend the existing test hook so the sweeper accepts a custom root (narrow test helper, no production behavior change)
- `internal/audit/audit_test.go` — replace `time.Sleep(300ms)` / `time.Sleep(500ms)` with `s.flushPending()` calls
- `test/integration/run_e2e_test.go` — `makeEnv()` now sets `HOME=t.TempDir()` per test so the file-fallback keystore is used (not login keychain)

**Files NOT to touch:** any file under `internal/` that is not a `*_test.go` file, except the narrow `sweepStaleSessionDirsIn` helper noted above.

---

## Task 1: Consolidate test helpers into internal/testutil

**Files:**
- Modify: `internal/testutil/testutil.go` (extend `MakeCred`, add `SetupVaultProject`)
- Modify: `internal/testutil/testutil_test.go` (cover new signature)
- Modify: `internal/proxy/injector_test.go` (remove local `makeCred`)
- Modify: `internal/runner/runner_test.go` (remove local `setupProject`)

**Why not move `openTestStore` (audit) or `initProject` (cli) too:** moving either creates an import cycle. `testutil` would need to import `audit` to return `*audit.Store`, but `audit_test.go` uses `package audit` (internal test), so it would import `testutil` → `audit` → cycle. Same for `cli`. Both helpers are used in exactly one package each (not duplicated), so there is no DRY payoff to justify restructuring audit/cli tests to external test packages.

- [ ] **Step 1.1: Extend `testutil.MakeCred` signature**

File: `internal/testutil/testutil.go` — change the `MakeCred` function body to accept optional hosts (new arg: `hosts ...string`) and populate `AllowedHosts`.

```go
// MakeCred constructs a *vault.Credential for tests with sensible defaults.
// Optional hosts populate AllowedHosts (empty → no host scoping).
func MakeCred(name, real, placeholder string, hosts ...string) *vault.Credential {
	return &vault.Credential{
		ID:           ulid.Make().String(),
		Name:         name,
		Real:         real,
		Placeholder:  placeholder,
		AllowedHosts: hosts,
	}
}
```

- [ ] **Step 1.2: Add `SetupVaultProject` helper**

Append to `internal/testutil/testutil.go`. It creates a temp project root, a fresh `MemKeystore`, a vault with one credential, and returns all three. Mirror what `runner_test.go:setupProject` currently does.

```go
// SetupVaultProject creates a temp project root with a vault and one
// test credential. Returns (root, keystore). Cleanup is via t.TempDir.
// The returned keystore is a *vault.MemKeystore so multiple vault.Open
// calls in the same test see the same project key.
func SetupVaultProject(t *testing.T) (string, *vault.MemKeystore) {
	t.Helper()
	root := t.TempDir()
	ks := vault.NewMemKeystore()

	v, err := vault.CreateVault(root, "test-project", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	cred := &vault.Credential{
		ID:          vault.NewID(),
		Name:        "TEST_SECRET",
		Real:        "real-secret-value",
		Placeholder: "VEIL_PH_test_secret",
		Source:      "manual",
		CreatedAt:   time.Now().UTC(),
	}
	if err := v.Add(cred); err != nil {
		t.Fatalf("Add credential: %v", err)
	}
	return root, ks
}
```

Add `"time"` to the imports in `testutil.go` if not already present.

- [ ] **Step 1.3: Update `testutil_test.go` to cover new behavior**

Extend `TestMakeCred` with a sub-test that passes hosts:

```go
func TestMakeCredWithHosts(t *testing.T) {
	c := testutil.MakeCred("GH", "ghp_real", "ghp_fake", "api.github.com", "*.github.com")
	if len(c.AllowedHosts) != 2 {
		t.Fatalf("AllowedHosts = %v, want 2 entries", c.AllowedHosts)
	}
	if c.AllowedHosts[0] != "api.github.com" {
		t.Errorf("AllowedHosts[0] = %q", c.AllowedHosts[0])
	}
}
```

Add `TestSetupVaultProject` that asserts the project root contains `.veil/vault.bin` and that `vault.Open(root, ks)` returns a vault with 1 credential.

- [ ] **Step 1.4: Run testutil tests**

Run: `go test -tags testkeystore ./internal/testutil/...`
Expected: PASS

- [ ] **Step 1.5: Remove local `makeCred` from `injector_test.go`; switch to `testutil.MakeCred`**

File: `internal/proxy/injector_test.go`

Delete lines 14–22 (local `makeCred`). Add import `"github.com/8enji/veil/internal/testutil"`. Note the arg-order difference:

- Old local: `makeCred(name, placeholder, real string, hosts ...string)`
- New shared: `testutil.MakeCred(name, real, placeholder string, hosts ...string)`

Replace every call. Either do it mechanically with sed-like edits, or write a thin wrapper at the top of `injector_test.go`:

```go
func makeCred(name, placeholder, real string, hosts ...string) *vault.Credential {
	return testutil.MakeCred(name, real, placeholder, hosts...)
}
```

Using the thin wrapper is strictly cleaner here because it preserves ~30 existing call sites without reordering args. Keep the file-local `makeCred` as a 3-line delegate so this task stays about plumbing, not mechanical renames. The wrapper does NOT re-duplicate the logic — it's a single-line passthrough.

- [ ] **Step 1.6: Replace `setupProject` in `runner_test.go`**

File: `internal/runner/runner_test.go`. Delete lines 17–40 (local `setupProject`). Add import `"github.com/8enji/veil/internal/testutil"`. Replace all `setupProject(t)` calls with `testutil.SetupVaultProject(t)` — the return types match (`string, vault.Keystore` vs `string, *vault.MemKeystore` — `*vault.MemKeystore` satisfies the `vault.Keystore` interface, so direct substitution works).

Also remove the now-unused `"time"` and `"github.com/8enji/veil/internal/vault"` imports if no other references remain. (Check: `vault.NewMemKeystore`, `vault.Credential`, `vault.NewID`, `vault.CreateVault` were all only used by `setupProject`. Search the file after the delete.)

- [ ] **Step 1.7: Verify all affected tests pass**

Run: `go test -tags testkeystore ./internal/proxy/... ./internal/runner/... ./internal/testutil/...`
Expected: PASS (no test outcome changes)

- [ ] **Step 1.8: Commit**

```bash
git add internal/testutil/ internal/proxy/injector_test.go internal/runner/runner_test.go
git commit -m "test: consolidate makeCred and setupProject into internal/testutil"
```

---

## Task 2: Replace sleep-based timing in audit tests

**Files:**
- Modify: `internal/audit/audit_test.go:147` (TestRecordBatching)
- Modify: `internal/audit/audit_test.go:292` (TestConcurrentRecords)

**Why:** `flushPending()` already exists on `*Store` (audit.go:202) and is already used in this test file at lines 90, 180, 245, 317, 505. The two remaining `time.Sleep` calls are leftover flakes that race the 100ms ticker under `-race` and CI load.

- [ ] **Step 2.1: Write failing test (skipped — this is a refactor of passing tests)**

Not applicable — we are removing a flaky wait. The tests already assert 60 / 200 rows; the change is how we wait. Verify the current tests pass first so we have a baseline:

Run: `go test -tags testkeystore -run 'TestRecordBatching|TestConcurrentRecords' ./internal/audit/ -count=1`
Expected: PASS (one run; the flake is under `-race`/CI).

- [ ] **Step 2.2: Replace `time.Sleep(300ms)` in TestRecordBatching**

File: `internal/audit/audit_test.go`, around line 147.

Before:
```go
// Wait for the flusher to process (100ms tick + some margin).
time.Sleep(300 * time.Millisecond)
```

After:
```go
// Flush synchronously — this is the same flush the ticker would eventually do.
s.flushPending()
```

- [ ] **Step 2.3: Replace `time.Sleep(500ms)` in TestConcurrentRecords**

File: `internal/audit/audit_test.go`, around line 292.

Before:
```go
// Wait for the background flusher to process all pending records.
// Records accumulate past the 50-row threshold which triggers the flush
// signal, plus the 100ms ticker ensures everything gets flushed.
time.Sleep(500 * time.Millisecond)
```

After:
```go
// Synchronously flush anything the 50-row signal left pending.
s.flushPending()
```

Delete the now-stale comment about the 100ms ticker — the behavior it described is no longer load-bearing for this test.

- [ ] **Step 2.4: Confirm `time` import still needed**

Grep the file for other `time.` usages. It is still used heavily (`time.Now`, `time.Date`, `time.Duration`, `time.Second`, `time.Millisecond`) — keep the import. Do NOT remove.

- [ ] **Step 2.5: Run the audit test suite under `-race` to confirm no flake**

Run: `go test -tags testkeystore -race -run 'TestRecordBatching|TestConcurrentRecords' ./internal/audit/ -count=10`
Expected: PASS 10/10 (no flakes).

- [ ] **Step 2.6: Commit**

```bash
git add internal/audit/audit_test.go
git commit -m "test(audit): replace time.Sleep with flushPending in batching/concurrent tests"
```

---

## Task 3: Fix TestSweepStaleSessionDirs /tmp global state

**Files:**
- Modify: `internal/runner/runner.go` — add a narrow test helper `sweepStaleSessionDirsIn(dir string)`; rewire `SweepStaleSessionDirsForTest` to accept an optional root.
- Modify: `internal/runner/runner_test.go:372-405` — pass a `t.TempDir()` root to the sweeper.

**Why:** the current test creates `veil-session-*` dirs in the shared OS temp dir, then runs the sweeper which walks the *entire* OS temp dir. Two concurrent `make test` runs collide; the sweeper can delete another runner's sessions. Also not parallel-safe.

**Design decision:** extend the existing test hook rather than refactoring `sweepStaleSessionDirs`. Production code keeps the zero-arg form that reads from `os.TempDir()`. The test hook becomes a 1-arg variant.

- [ ] **Step 3.1: Add `sweepStaleSessionDirsIn` to `runner.go`**

File: `internal/runner/runner.go`. Extract the body of `sweepStaleSessionDirs` into a helper that takes a root. Production callers unchanged.

Before (lines 292–312):
```go
// sweepStaleSessionDirs removes veil-session-* directories under the OS temp
// root that are older than 24h. Best-effort; errors are silently tolerated.
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

// SweepStaleSessionDirsForTest exposes the sweeper for tests.
var SweepStaleSessionDirsForTest = sweepStaleSessionDirs
```

After:
```go
// sweepStaleSessionDirs removes veil-session-* directories under the OS temp
// root that are older than 24h. Best-effort; errors are silently tolerated.
func sweepStaleSessionDirs() {
	sweepStaleSessionDirsIn(os.TempDir())
}

// sweepStaleSessionDirsIn is the inner form of sweepStaleSessionDirs that
// accepts a custom root. Exposed (via SweepStaleSessionDirsForTest) so tests
// can point the sweeper at t.TempDir() instead of the shared OS temp dir.
func sweepStaleSessionDirsIn(root string) {
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

// SweepStaleSessionDirsForTest exposes the sweeper for tests. Callers can
// pass a custom root to avoid interfering with the shared OS temp dir.
func SweepStaleSessionDirsForTest(root string) {
	if root == "" {
		sweepStaleSessionDirs()
		return
	}
	sweepStaleSessionDirsIn(root)
}
```

Note: this changes `SweepStaleSessionDirsForTest` from a `var` to a `func`. Both tests in `runner_test.go` that call `SweepStaleSessionDirsForTest()` (with no args) need to be updated — see next step.

- [ ] **Step 3.2: Update `TestSweepStaleSessionDirs` to use `t.TempDir`**

File: `internal/runner/runner_test.go:372-405`. Replace both tests so neither touches `os.TempDir()`.

```go
func TestSweepStaleSessionDirs(t *testing.T) {
	root := t.TempDir()
	stale, err := os.MkdirTemp(root, "veil-session-*")
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(stale, past, past); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	SweepStaleSessionDirsForTest(root)

	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected stale dir removed, got err=%v", err)
	}
}

func TestSweepStaleSessionDirsLeavesFresh(t *testing.T) {
	root := t.TempDir()
	fresh, err := os.MkdirTemp(root, "veil-session-*")
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	SweepStaleSessionDirsForTest(root)

	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("fresh dir should survive, got err=%v", err)
	}
}
```

Delete the `t.Cleanup(func() { _ = os.RemoveAll(stale) })` / `...RemoveAll(fresh)` lines — `t.TempDir()` handles cleanup automatically, and the stale dir is deleted by the sweeper anyway.

- [ ] **Step 3.3: Build + verify**

Run: `go build ./...`
Expected: SUCCESS (confirms the `var → func` change didn't break any other caller).

Run: `go test -tags testkeystore -race ./internal/runner/ -count=5`
Expected: PASS 5/5.

- [ ] **Step 3.4: Commit**

```bash
git add internal/runner/runner.go internal/runner/runner_test.go
git commit -m "test(runner): scope TestSweepStaleSessionDirs to t.TempDir()"
```

---

## Task 4: Add FuzzParseEnvFile

**Files:**
- Create: `internal/scanner/fuzz_test.go`
- Create: `internal/scanner/testdata/fuzz/FuzzParseEnvFile/seed_comprehensive`
- Create: `internal/scanner/testdata/fuzz/FuzzParseEnvFile/seed_edge`

**Why:** `scanner.ParseFile` is a byte-for-byte `.env` parser that users run on untrusted input (they paste .env files they didn't write). It has already had one bug (unclosed quote handling) fixed in the history. Fuzzing is the cheapest guard against a regression.

**Design decision:** fuzz `ParseFile` indirectly by writing the fuzzed bytes to a temp file and calling `ParseFile(path)`. We don't want to add an in-memory parser API just for the fuzzer. Also assert `Bytes()` round-trip fidelity when no lines are dirty — that's the property most likely to break silently.

- [ ] **Step 4.1: Write the failing test**

File: `internal/scanner/fuzz_test.go`. Create:

```go
package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseEnvFile feeds random bytes to ParseFile and asserts no panic.
// For any input that parses successfully without dirty lines, Bytes() must
// round-trip to the original bytes — a property the production parser
// promises callers that edit .env files in place.
func FuzzParseEnvFile(f *testing.F) {
	// Seed from real fixture + edge cases.
	seedFromFile(f, "../../test/fixtures/envs/comprehensive.env")
	f.Add([]byte(""))
	f.Add([]byte("\n"))
	f.Add([]byte("KEY=val\n"))
	f.Add([]byte("export FOO='bar'\n"))
	f.Add([]byte("KEY=\"unclosed\n"))
	f.Add([]byte("# comment only\n"))
	f.Add([]byte("KEY=val # inline\n"))
	f.Add([]byte("=noKey\n"))

	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(dir, "fuzz.env")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		ef, err := ParseFile(path)
		if err != nil {
			// ParseFile only errors on I/O; since the file exists and is
			// readable, any error here is a real bug.
			t.Fatalf("ParseFile returned error on readable file: %v", err)
		}
		// Round-trip: no line has been SetValue'd, so Bytes() must equal
		// the input exactly.
		if got := ef.Bytes(); !bytes.Equal(got, data) {
			t.Fatalf("round-trip mismatch\n input: %q\n output: %q", data, got)
		}
	})
}

// seedFromFile reads `path` and adds its contents as a fuzz seed. It's a
// helper because every fuzz file benefits from real-world corpus seeds.
func seedFromFile(f *testing.F, path string) {
	f.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		f.Fatalf("read seed %s: %v", path, err)
	}
	f.Add(data)
}
```

- [ ] **Step 4.2: Run fuzz as a regular test (seed corpus only, no fuzzing time)**

Run: `go test -tags testkeystore -run FuzzParseEnvFile ./internal/scanner/`
Expected: PASS. `go test` without `-fuzz=` runs the seed corpus as regular tests and does NOT do mutation — this catches obvious seed failures.

- [ ] **Step 4.3: Run `-fuzz=` for 30 seconds and report results**

Run: `go test -tags testkeystore -run '^$' -fuzz=FuzzParseEnvFile -fuzztime=30s ./internal/scanner/`
Expected: no new crashes. If the fuzzer finds a regression, the failing input is written under `internal/scanner/testdata/fuzz/FuzzParseEnvFile/`. Do NOT delete the crash artifact — it becomes a permanent regression seed.

**If fuzz finds a bug:**
- If it's a parser crash (panic or index-out-of-range), file in `docs/superpowers/findings/` as a follow-up and leave the crash seed in place so future runs reproduce.
- If it's a round-trip fidelity issue, decide whether to weaken the round-trip assertion (e.g. accept certain legal normalization) or fix the parser. Production fix is out of scope for this plan; file as follow-up.

- [ ] **Step 4.4: Commit**

```bash
git add internal/scanner/fuzz_test.go internal/scanner/testdata/
git commit -m "test(scanner): add FuzzParseEnvFile with round-trip assertion"
```

---

## Task 5: Add FuzzPlaceholderReplace

**Files:**
- Create: `internal/placeholder/fuzz_test.go`
- Create: `internal/placeholder/testdata/fuzz/FuzzPlaceholderReplace/seed_*`

**Why:** the placeholder engine runs on every secret discovered during init. A crash here breaks the entire onboarding flow. The full match+generate path (url → provider → charclass fallback) has 10+ provider implementations; fuzzing guards against new providers that mis-handle edge-case inputs.

**Design decision:** fuzz the full `Generate` entry point (not `generateOnce`), passing both `name` and `value` as fuzzed strings. Assert:
1. No panic.
2. `Generate` returns either a non-empty placeholder or `ErrCollisionUnresolvable` / "empty value".
3. The returned placeholder is NOT equal to the input value (never echo the secret).

- [ ] **Step 5.1: Write the fuzz test**

File: `internal/placeholder/fuzz_test.go`. Create:

```go
package placeholder

import (
	"strings"
	"testing"
)

// FuzzPlaceholderReplace fuzzes the full Generate() path (url → provider →
// charclass fallback) with adversarial names and values. Asserts:
//  1. No panic.
//  2. Non-empty value → non-empty placeholder (or defined error).
//  3. Returned placeholder never equals the input value.
func FuzzPlaceholderReplace(f *testing.F) {
	// Real-world seeds from every provider test.
	seeds := []struct{ name, value string }{
		{"OPENAI_API_KEY", "sk-proj-abcdef123456"},
		{"ANTHROPIC_API_KEY", "sk-ant-api03-abcdef123456"},
		{"GITHUB_TOKEN", "ghp_abcdef1234567890abcdef"},
		{"GITHUB_FINE_PAT", "github_pat_11ABCDEFGHIJKLMNOPQRST_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXa"},
		{"STRIPE_SECRET_KEY", "sk_live_abcdef123456abcdef"},
		{"SLACK_BOT_TOKEN", "xoxb-123-456-abc789def"},
		{"AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"},
		{"AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{"SENDGRID_API_KEY", "SG.abcdefghij0123456789._-abcdefghijklmnopqrstuvwxyz0123456789abcd"},
		{"SUPABASE_SERVICE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def"},
		{"TWILIO_AUTH_TOKEN", "abcdef01234567890abcdef0123456789"},
		{"DATABASE_URL", "postgres://user:supersecretpassword@localhost:5432/db"},
		{"REDIS_URL", "redis://:secret123@redis.example.com:6379/0"},
		{"FALLBACK", "just-some-opaque-value-that-hits-charclass"},
		{"", ""},
		{"", "only-value"},
		{"ONLY_NAME", ""},
	}
	for _, s := range seeds {
		f.Add(s.name, s.value)
	}

	f.Fuzz(func(t *testing.T, name, value string) {
		ph, err := Generate(name, value, nil)
		if err != nil {
			// Only ErrCollisionUnresolvable and "empty value" are valid errors.
			msg := err.Error()
			if !strings.Contains(msg, "collision") && !strings.Contains(msg, "empty value") {
				t.Fatalf("unexpected error %q for name=%q value=%q", err, name, value)
			}
			return
		}
		if ph == "" {
			t.Fatalf("empty placeholder for name=%q value=%q", name, value)
		}
		if ph == value {
			t.Fatalf("placeholder equals input (would leak secret)\n name=%q\n value=%q\n ph=%q", name, value, ph)
		}
	})
}
```

- [ ] **Step 5.2: Run seed corpus**

Run: `go test -tags testkeystore -run FuzzPlaceholderReplace ./internal/placeholder/`
Expected: PASS

- [ ] **Step 5.3: Run `-fuzz=` for 30 seconds**

Run: `go test -tags testkeystore -run '^$' -fuzz=FuzzPlaceholderReplace -fuzztime=30s ./internal/placeholder/`
Expected: no crashes.

**If a bug is found:** follow the same policy as Task 4 — keep the crash seed, file a follow-up issue unless the fix is trivial.

- [ ] **Step 5.4: Commit**

```bash
git add internal/placeholder/fuzz_test.go internal/placeholder/testdata/
git commit -m "test(placeholder): add FuzzPlaceholderReplace across full Generate path"
```

---

## Task 6: Add FuzzDecodeBasic

**Files:**
- Create: `internal/proxy/fuzz_test.go`

**Why:** `tryRewriteBasic` decodes base64 from arbitrary HTTP headers. Adversarial inputs (non-UTF8 bytes inside base64, padding variants, nested schemes) are a classic attack surface. The existing unit tests cover happy paths but not the fuzz space.

**Design decision:** fuzz `tryRewriteBasic` directly (package-private — we're in `package proxy`). Pass a fuzzed header value plus a deterministic placeholder map + host. Assert:
1. No panic.
2. If `ok==true`, the returned cred is a real pointer from the map AND the new value starts with `"Basic "`.
3. If the input header does not begin with `"Basic "` (case-insensitive), `ok` must be false.

- [ ] **Step 6.1: Write the fuzz test**

File: `internal/proxy/fuzz_test.go`. Create:

```go
package proxy

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/8enji/veil/internal/vault"
)

// FuzzDecodeBasic fuzzes the Basic-auth header decode+swap path with valid
// and adversarial base64 inputs. The placeholder map is fixed across runs so
// we can assert the returned credential identity.
func FuzzDecodeBasic(f *testing.F) {
	cred := &vault.Credential{
		ID:                  "cred-fuzz",
		Name:                "fuzz",
		Real:                "real-secret-value",
		Placeholder:         "VEIL_SECRET_FUZZ",
		Username:            "realuser",
		UsernamePlaceholder: "VEIL_USER_FUZZ",
		AllowedHosts:        []string{"example.com"},
	}
	pmap := map[string]*vault.Credential{
		cred.Placeholder:         cred,
		cred.UsernamePlaceholder: cred,
	}

	// Valid happy-path seed.
	valid := "Basic " + base64.StdEncoding.EncodeToString([]byte(cred.UsernamePlaceholder+":"+cred.Placeholder))
	f.Add(valid)

	// Adversarial seeds.
	f.Add("")
	f.Add("Basic ")
	f.Add("Basic !@#$%")                                          // invalid base64
	f.Add("Basic " + base64.StdEncoding.EncodeToString([]byte(""))) // empty payload
	f.Add("Basic " + base64.StdEncoding.EncodeToString([]byte(":")))
	f.Add("Basic " + base64.StdEncoding.EncodeToString([]byte("nouser")))
	f.Add("Basic " + base64.StdEncoding.EncodeToString([]byte("\x00\x01\x02:\x00\x01\x02"))) // binary
	f.Add("Bearer " + base64.StdEncoding.EncodeToString([]byte("u:p")))                        // wrong scheme
	f.Add("BASIC " + base64.StdEncoding.EncodeToString([]byte("u:p")))                         // case fold
	f.Add("Basic " + base64.URLEncoding.EncodeToString([]byte("VEIL_USER_FUZZ:VEIL_SECRET_FUZZ")))

	f.Fuzz(func(t *testing.T, value string) {
		got, newVal, ok := tryRewriteBasic(value, pmap, "example.com")

		if !ok {
			if got != nil {
				t.Fatalf("ok=false but cred != nil: %v", got)
			}
			if newVal != "" {
				t.Fatalf("ok=false but newVal = %q", newVal)
			}
			return
		}

		// ok==true contract:
		if got != cred {
			t.Fatalf("ok=true but returned cred is not the registered one: %+v", got)
		}
		if !strings.HasPrefix(newVal, "Basic ") {
			t.Fatalf("rewritten value must start with 'Basic ': %q", newVal)
		}
		// The rewritten payload must carry the real credential, not the
		// placeholder. Decoding and checking is overkill for this fuzz —
		// assert by substring on the base64 payload.
		expected := base64.StdEncoding.EncodeToString([]byte(cred.Username + ":" + cred.Real))
		if newVal != "Basic "+expected {
			t.Fatalf("rewritten value = %q, want %q", newVal, "Basic "+expected)
		}
	})
}
```

- [ ] **Step 6.2: Run seed corpus**

Run: `go test -tags testkeystore -run FuzzDecodeBasic ./internal/proxy/`
Expected: PASS

- [ ] **Step 6.3: Run `-fuzz=` for 30 seconds**

Run: `go test -tags testkeystore -run '^$' -fuzz=FuzzDecodeBasic -fuzztime=30s ./internal/proxy/`
Expected: no crashes.

- [ ] **Step 6.4: Commit**

```bash
git add internal/proxy/fuzz_test.go internal/proxy/testdata/
git commit -m "test(proxy): add FuzzDecodeBasic for adversarial Basic-auth headers"
```

---

## Task 7: Add HTTPS E2E test with curl --cacert

**Files:**
- Create: `test/integration/https_e2e_test.go`

**Why:** `run_e2e_test.go` only exercises plain HTTP via `httptest.NewServer`. The CA bundle write path (`cabundle.go` → `SSL_CERT_FILE` env → child process → validated TLS handshake via the proxy's MITM cert) is verified only by a `strings.HasSuffix("ca-bundle.pem")` check in unit tests. A real curl-through-proxy-through-MITM-through-upstream flow has never been exercised end-to-end.

**Design decision & the subtle part — how the proxy trusts the httptest upstream:**

`httptest.NewTLSServer` presents a self-signed leaf cert. The veil proxy is a separate subprocess (spawned by `veil run`) and by default uses `http.DefaultTransport`, which calls `x509.SystemCertPool()` for outbound TLS verification. That pool won't include our ephemeral httptest cert.

Go's `crypto/x509` on all platforms honors `SSL_CERT_FILE` when building the system pool (with `CGO_ENABLED=0`, which the Makefile sets for test). So: set `SSL_CERT_FILE=<path-to-httptest-ca-pem>` in **veil's** parent environment. This is read by the proxy process when it constructs its outbound transport.

Crucially: `runner.go:buildChildEnv` **strips** `SSL_CERT_FILE` from the child's env and sets its own (the Veil CA bundle). So the child (curl) sees the Veil CA bundle, and `curl --cacert "$SSL_CERT_FILE"` trusts the Veil-signed leaf presented by the proxy. Meanwhile the veil parent process continues to use the httptest CA to verify the upstream. Two separate trust decisions, one env var name, different scopes — by design.

**Tradeoff noted:** if a future refactor has veil re-exec itself (so the "parent" becomes a child of the CLI frontend), `SSL_CERT_FILE` would be stripped before the proxy starts. The test will catch this by turning red. That is the right failure mode.

- [ ] **Step 7.1: Write the E2E test**

File: `test/integration/https_e2e_test.go`. Create:

```go
package integration

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2E_ProxyHTTPSInjection verifies the full HTTPS path end-to-end:
//   test → spawn `veil run curl https://<upstream>` → proxy MITMs with
//   Veil-signed leaf → curl validates leaf using SSL_CERT_FILE (Veil CA) →
//   proxy forwards to httptest.NewTLSServer using SSL_CERT_FILE (upstream CA)
//   set in the veil parent env → upstream returns 200 with injected header.
//
// Asserts:
//   - curl exits 0 (the full TLS handshake works).
//   - httptest received the real secret (proving injection happened through MITM).
//   - audit log has a non-blocked injection entry.
func TestE2E_ProxyHTTPSInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available on PATH; skipping HTTPS e2e test")
	}

	// 1. Upstream HTTPS server.
	type captured struct{ Auth string }
	captureCh := make(chan captured, 1)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captureCh <- captured{Auth: r.Header.Get("Authorization")}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer ts.Close()

	// 2. Write the upstream's self-signed cert to a PEM file the veil parent
	// process can load via SSL_CERT_FILE.
	upstreamCAFile := filepath.Join(t.TempDir(), "upstream-ca.pem")
	certDER := ts.Certificate().Raw
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(upstreamCAFile, certPEM, 0o600); err != nil {
		t.Fatalf("write upstream CA: %v", err)
	}
	// Sanity check: parse it back.
	if _, err := x509.ParseCertificate(certDER); err != nil {
		t.Fatalf("parse upstream cert: %v", err)
	}

	// 3. Build binaries.
	env := makeEnv()
	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)

	// 4. Create project with a credential.
	projDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projDir, ".git"), 0755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	originalKey := "ghp_httpstest1234567890abcdef1234567890"
	envContent := fmt.Sprintf("GITHUB_TOKEN=%s\n", originalKey)
	if err := os.WriteFile(filepath.Join(projDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	// 5. veil init.
	initCmd := exec.Command(veilBin, "init", "--path", projDir)
	initCmd.Env = env
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("veil init: %v\n%s", err, out)
	}

	// 6. Read placeholder.
	rewritten, err := os.ReadFile(filepath.Join(projDir, ".env"))
	if err != nil {
		t.Fatalf("reading .env: %v", err)
	}
	var placeholder string
	for _, line := range strings.Split(string(rewritten), "\n") {
		if strings.HasPrefix(line, "GITHUB_TOKEN=") {
			placeholder = strings.TrimPrefix(line, "GITHUB_TOKEN=")
			break
		}
	}
	if placeholder == "" || placeholder == originalKey {
		t.Fatal("could not find placeholder in rewritten .env")
	}

	// 7. Scope the credential to the httptest host.
	tsHost, _, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "https://"))
	addCmd := exec.Command(veilBin, "add", "--path", projDir, "--force",
		"--value", originalKey, "--host", tsHost, "GITHUB_TOKEN")
	addCmd.Env = env
	if out, err := addCmd.CombinedOutput(); err != nil {
		t.Fatalf("veil add: %v\n%s", err, out)
	}

	// Re-read (the add may have re-generated the placeholder).
	rewritten2, err := os.ReadFile(filepath.Join(projDir, ".env"))
	if err != nil {
		t.Fatalf("reading .env: %v", err)
	}
	for _, line := range strings.Split(string(rewritten2), "\n") {
		if strings.HasPrefix(line, "GITHUB_TOKEN=") {
			placeholder = strings.TrimPrefix(line, "GITHUB_TOKEN=")
			break
		}
	}

	// 8. Run curl through veil. Tell veil's outbound transport to trust the
	// httptest upstream via SSL_CERT_FILE; runner.go strips this from the
	// child env so curl inside the child will see the Veil CA bundle instead.
	runEnv := append(env, "SSL_CERT_FILE="+upstreamCAFile)
	curlCmd := fmt.Sprintf(
		`curl -sS -o /dev/null -w '%%{http_code}' --cacert "$SSL_CERT_FILE" -H "Authorization: Bearer %s" %s/repos`,
		placeholder, ts.URL,
	)
	runCmd := exec.Command(veilBin, "run", "--path", projDir, "--", "sh", "-c", curlCmd)
	runCmd.Env = runEnv
	runOut, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil run curl failed: %v\n%s", err, runOut)
	}
	// curl's -w prints the status code to stdout; the rest of runCmd output
	// is veil's startup/shutdown lines on stderr. Just search for 200.
	if !strings.Contains(string(runOut), "200") {
		t.Fatalf("expected HTTP 200 from curl, got output:\n%s", runOut)
	}

	// 9. Assert upstream received the REAL secret (injection happened through MITM).
	cap := <-captureCh
	expectedAuth := "Bearer " + originalKey
	if cap.Auth != expectedAuth {
		t.Errorf("upstream Auth header: got %q, want %q", cap.Auth, expectedAuth)
	}

	// 10. Assert audit log recorded a non-blocked injection for GITHUB_TOKEN.
	logCmd := exec.Command(veilBin, "log", "--path", projDir, "--json")
	logCmd.Env = env
	logOut, err := logCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil log: %v\n%s", err, logOut)
	}
	logStr := strings.TrimSpace(string(logOut))
	if logStr == "" {
		t.Fatal("audit log is empty; expected injection event")
	}
	var entry map[string]interface{}
	lines := strings.Split(logStr, "\n")
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("parsing audit log JSON: %v\nline: %s", err, lines[0])
	}
	if entry["location"] == "blocked" {
		t.Error("injection should not be blocked for authorized host")
	}
	if entry["credential"] != "GITHUB_TOKEN" {
		t.Errorf("expected credential GITHUB_TOKEN, got %v", entry["credential"])
	}
}
```

- [ ] **Step 7.2: Verify the test runs and passes**

Run: `go test -tags testkeystore -run TestE2E_ProxyHTTPSInjection ./test/integration/ -count=1 -timeout 120s`
Expected: PASS.

Possible failure modes to debug if it doesn't pass:
- `curl: SSL certificate problem: unable to get local issuer certificate` → the child's `SSL_CERT_FILE` isn't pointing at the Veil CA bundle. Check `runner.go:buildChildEnv` set it.
- `x509: certificate signed by unknown authority` reported by the proxy → the veil parent's `SSL_CERT_FILE` didn't take effect. Possible causes: (a) Go's cert pool was cached before the env was read (unlikely — pool is lazy); (b) platform-specific `crypto/x509` path ignores the env var. In that case, fall back to loading the cert into a file the Go stdlib is documented to respect: on Linux, `/etc/ssl/certs/ca-certificates.crt` is canonical; on macOS without cgo, `SSL_CERT_FILE` works per `root_unix.go`. If macOS fails, skip the test with `t.Skip("httptest self-signed cert not in macOS trust store")` only as a last resort — preferable to fix by using a CA that actually gets loaded.
- Timeout / hang → check that `runCmd.Env` was applied; assert `len(runEnv) > 0`.

- [ ] **Step 7.3: Commit**

```bash
git add test/integration/https_e2e_test.go
git commit -m "test(integration): add HTTPS e2e through proxy with real curl"
```

---

## Task 8: Point e2e HOME at t.TempDir() for keychain isolation

**Files:**
- Modify: `test/integration/run_e2e_test.go:78-90` (the `makeEnv()` function)

**Why:** today, `makeEnv` strips `VEIL_TEST_KEYSTORE=mem` from the env (so multi-process e2e tests can share state through the file/keychain fallback), but leaves `HOME` pointing at the real user's home dir. Result: `veil init` creates keychain entries in the user's **real** login keychain. Running `make test` leaves real entries. On a CI runner with no keychain, the file-fallback path is never exercised.

Fix: per-test `HOME=t.TempDir()`. This forces the file-fallback keystore (under `$HOME/.veil/keystore/`). Multiple binary invocations in the same test share the same `HOME`, so they see the same file keystore. CI gets real test coverage of the fallback path.

**Design decision:** make `makeEnv` take `t *testing.T` so each test gets its own `HOME`. Every caller of `makeEnv` has `t` in scope.

- [ ] **Step 8.1: Change `makeEnv` signature to accept t**

File: `test/integration/run_e2e_test.go`, starting at line 68.

Before:
```go
// makeEnv constructs environment variables for veil CLI invocations.
//
// We keep the real HOME so the macOS keychain is accessible (the keyring
// is tied to the login keychain, not HOME). The CA certificate is stored
// under HOME too and is shared/idempotent. All project-specific state
// lives under the --path directory, so tests are isolated via t.TempDir().
//
// We do NOT set VEIL_TEST_KEYSTORE=mem because e2e tests span multiple
// processes (veil init, veil run, veil status, ...) that must share the
// keystore.
func makeEnv() []string {
	env := os.Environ()
	// Strip any leftover VEIL_TEST_KEYSTORE from the parent process
	// (e.g. if `make test` sets it). We need the real keystore.
	filtered := env[:0]
	for _, kv := range env {
		if strings.HasPrefix(kv, "VEIL_TEST_KEYSTORE=") {
			continue
		}
		filtered = append(filtered, kv)
	}
	return filtered
}
```

After:
```go
// makeEnv constructs environment variables for veil CLI invocations.
//
// We point HOME at t.TempDir() so the file-fallback keystore is used
// instead of the user's login keychain — e2e runs don't pollute the real
// keychain, and CI systems without a keychain exercise the fallback path.
// All binary invocations in one test share the same HOME, so the file
// keystore is visible across veil init / veil run / veil status.
//
// We do NOT set VEIL_TEST_KEYSTORE=mem because e2e tests span multiple
// processes that must share the keystore via disk.
func makeEnv(t *testing.T) []string {
	t.Helper()
	home := t.TempDir()
	src := os.Environ()
	out := make([]string, 0, len(src)+1)
	for _, kv := range src {
		if strings.HasPrefix(kv, "VEIL_TEST_KEYSTORE=") {
			continue
		}
		if strings.HasPrefix(kv, "HOME=") {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, "HOME="+home)
	return out
}
```

- [ ] **Step 8.2: Update every caller of `makeEnv()`**

Callers (grep `makeEnv()` in `test/integration/`):

In `run_e2e_test.go`: lines 107, 248, 369, 514, 627, 743, 801, 850. Each becomes `makeEnv(t)`.

In the new `https_e2e_test.go` (from Task 7): update the `makeEnv()` call to `makeEnv(t)`.

Batch-replace with an Edit `replace_all` on `makeEnv()` → `makeEnv(t)` in each file. (Grep to confirm count before and after.)

- [ ] **Step 8.3: Run the full e2e suite**

Run: `go test -tags testkeystore -run TestE2E ./test/integration/ -count=1 -timeout 180s`
Expected: PASS.

If a test fails with "keychain unavailable" or similar, it means the file-fallback path has a regression that the old (kept-real-HOME) version masked. That's a useful finding — file as a separate task and keep the fix for later. For this plan, either the tests pass or the failure is flagged.

- [ ] **Step 8.4: Verify the user's real keychain is not touched**

Before running the test, enumerate entries with name prefix "veil" in the login keychain:

On macOS:
```bash
security dump-keychain -d login.keychain 2>&1 | grep -c '"svce"<blob>="veil' || echo 0
```
Capture the count, run the test suite, capture again. Counts should be identical.

On Linux with `libsecret`:
```bash
secret-tool search service veil 2>/dev/null | wc -l
```

If the counts differ, the isolation is incomplete — review.

- [ ] **Step 8.5: Commit**

```bash
git add test/integration/
git commit -m "test(integration): isolate e2e HOME to t.TempDir() to avoid real keychain writes"
```

---

## Task 9: Full verification suite

**Files:** None — this is a verification gate before declaring done.

- [ ] **Step 9.1: Run `make test` (non-race)**

Run: `make test`
Expected: PASS. Capture the summary output for the deliverable report.

- [ ] **Step 9.2: Run `make test-race`**

Run: `make test-race`
Expected: PASS. Capture the summary output for the deliverable report (the user explicitly asked for this).

- [ ] **Step 9.3: Run `go vet` for good measure**

Run: `make vet`
Expected: PASS (no new vet warnings from test files).

- [ ] **Step 9.4: Run each new fuzz target for the full 30 seconds one more time, back-to-back**

Run:
```bash
go test -tags testkeystore -run '^$' -fuzz=FuzzParseEnvFile        -fuzztime=30s ./internal/scanner/
go test -tags testkeystore -run '^$' -fuzz=FuzzPlaceholderReplace  -fuzztime=30s ./internal/placeholder/
go test -tags testkeystore -run '^$' -fuzz=FuzzDecodeBasic         -fuzztime=30s ./internal/proxy/
```
Expected: all three complete cleanly, reporting `"fuzzing ... completed"` and no new entries under `testdata/fuzz/`.

- [ ] **Step 9.5: Verify no production code was modified except the narrow test helper in Task 3**

Run: `git diff main --stat -- internal/ cmd/ | grep -v _test.go | grep -v testdata`
Expected output: only `internal/runner/runner.go` (the `sweepStaleSessionDirsIn` extraction from Task 3). If anything else appears, audit it.

- [ ] **Step 9.6: Write the deliverable summary**

In the final response, report:
- (a) Fuzz tests added and findings — names, locations, `-fuzztime=30s` result (crash found / no crash).
- (b) Flaky-sleep replacements — file:line of each replacement.
- (c) HTTPS E2E added — filename and what it asserts.
- (d) Keychain-independence — before/after counts of real-keychain entries.
- (e) Testutil consolidation — what moved, what stayed and why (import cycle note for `audit`/`cli`).
- (f) `make test-race` output — PASS/FAIL and wall-clock time.

---

## Self-review notes (from plan author)

- **Spec coverage:** all six numbered problems from the brief have at least one task (1→Task1; 2→Task2; 3→Task3; 4→Task7; 5→Task8; 6→Task1). The three fuzz tests map to three tasks (4, 5, 6).
- **Placeholders:** no "TBD" / "similar to" / "implement error handling" placeholders. Every code block is self-contained.
- **Type consistency:** `testutil.MakeCred(name, real, placeholder string, hosts ...string)` — arg order matches existing testutil convention, extended with variadic. `injector_test.go` local wrapper preserves its old arg order for minimal churn. `SweepStaleSessionDirsForTest(root string)` — all two callers updated.
- **Import-cycle analysis for consolidation (Task 1):** documented inline — `openTestStore` and `initProject` not moved because moving them would require `testutil → audit` / `testutil → cli`, and the respective internal tests (`package audit`, `package cli`) would then need `testutil → audit → testutil` — a cycle.
- **One production-code edit:** only `internal/runner/runner.go` (extracting `sweepStaleSessionDirsIn`) — explicitly allowed by the brief's "narrow test helper if unavoidable" clause, and needed to make Task 3's test fix non-global.
