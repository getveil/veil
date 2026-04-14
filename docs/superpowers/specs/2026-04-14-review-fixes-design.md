# Review Fixes — Security, Correctness, and Cleanup Pass

**Date:** 2026-04-14
**Source findings:** `docs/superpowers/findings/2026-04-14-review.md`

## Summary

This spec addresses 19 findings from the 2026-04-14 in-depth review. The work is grouped into 7 themes executed in order. Phase 1 (CLI cleanup + error-typing foundation + testutil) lands infrastructure that later phases build on; phases 2–7 are independently mergeable after that.

## Scope

**In scope (19):** C1, C2, C3, C4, H1, H2, H3, H4(b), H5, H6, M3, M4, M6, L1, L2, L3, L5, L6, L7.

**Deferred (out of scope for this spec):**

- **M1** — Leaf cert cache rework. High-cardinality SNI is not realistic for a single-agent CLI; deferred until load justifies.
- **M2** — CA rotation tooling. Whole new subcommand; only matters if the CA key is compromised.
- **M5** — Split `init.go` into phases. Pure refactor; touching the core setup path risks regressions without behavioral benefit.
- **L4** — Structured logging. Finding itself notes this is not urgent for MVP.

**Downscoped:**

- **H4** — Addressed via option (b) only: zero the hex-encoded key buffer in `FileKeystore.saveMap` after write, and document long-running-proxy in-memory credential residency as a known MVP limitation in the threat model. No `memguard` introduction.

## Phase 1 — CLI cleanup & error-typing foundation (M6, L3, L7)

Lands infrastructure used by every subsequent phase.

### L7 — `internal/testutil/` extraction (minimal)

New package `internal/testutil/` containing only helpers duplicated ≥2 places today:

- `MakeCred(...)` — consolidates `makeCred` duplication across `vault_test.go`, `injector_test.go`, etc.
- `TempProjectRoot(t)` — returns a `t.TempDir()`-rooted project directory with `ProjectStateDir` seeded.
- `NewMemKeystore()` — in-memory keystore constructor for tests. Introduced already behind the `//go:build testkeystore` tag from day one (Phase 1 also updates the Makefile to pass `-tags testkeystore` on test targets). Phase 4 reuses this infrastructure; no retroactive gating needed.

No fixture standardization beyond this (ambitious variant explicitly out of scope).

### L3 — `ui.Warn`

Add `ui.Warn(w io.Writer, format string, args ...any)` to `internal/ui`. Migrate the stragglers:

- `internal/cli/init.go:346`
- `internal/runner/signals.go:22`
- Any other `fmt.Fprintln(os.Stderr, "warning:"...)` sites surfaced by a grep sweep during the phase.

Styling consistent with existing `ui.Bold`/`ui.Muted` and color-state resolution from `root.go`.

### M6 — Audit-wide typed errors

Introduce typed errors at package boundaries where callers care about the kind. Replace every string-sniffing `strings.Contains(err.Error(), ...)` pattern with `errors.Is`/`errors.As`.

Concrete taxonomy (to be refined during implementation but these are the initial targets):

- `vault`: `ErrVaultOpen`, `ErrVaultLocked`, `ErrPlaceholderCollision` (new for H1), `ErrCredentialNotFound`.
- `proxy`: `ErrCAGenerate`, `ErrCALoad`, `ErrListen`, `ErrBodyRead` (new for H6).
- `scanner`: `ErrEnvParse` (new for C4).
- `audit`: `ErrAuditOpen`, `ErrAuditWrite`.
- `keystore`: `ErrKeystoreUnavailable`, `ErrKeystoreWrite`.
- `placeholder`: `ErrProviderNotFound`, `ErrCollisionUnresolvable` (new for H1).

`mapRunError` in `internal/cli/run.go` rewritten to match with `errors.Is/As`. Old branches deleted once equivalents exist.

Package-private helpers may keep `fmt.Errorf` — the pass targets errors that *cross* package boundaries.

### Phase 1 tests

- `testutil` smoke tests.
- `ui.Warn` rendering test (with and without color).
- `mapRunError` table-driven test exercising each typed-error branch.

---

## Phase 2 — Scanner quoting fix (C4)

Replace the `strings.IndexByte`-based single-quote parser in `internal/scanner/envfile.go:~142-147` with a quote-aware reader.

**Semantics implemented:**

- Single-quoted values do **not** process escapes (shell semantics).
- The standard shell idiom `'\''` (close quote → literal quote → open quote) is recognized and produces a literal `'` in the value.
- Unclosed single-quote reaches EOF → error (typed as `scanner.ErrEnvParse`).
- Double-quoted values retain existing behavior (unchanged by this fix) but covered in new tests.

**Tests** — new table-driven suite in `envfile_test.go`:

| Input | Expected |
|---|---|
| `KEY='simple'` | `simple` |
| `KEY='it'\''s'` | `it's` |
| `KEY='has=equals'` | `has=equals` |
| `KEY='has\nliteral'` | `has\nliteral` (backslash is literal inside single quotes) |
| `KEY='` (unclosed) | error |
| `KEY=''` (empty) | `` (empty string) |
| `KEY='with\r\ncrlf'` | `with\r\ncrlf` |
| `KEY="double"` | `double` (unchanged) |

Ensures scanner false negatives on edge-case quoted secrets are eliminated.

---

## Phase 3 — Filesystem permission hardening (C2, H3, L2)

### C2 — Audit SQLite perms

In `internal/audit/audit.go:Open`:

1. `sql.Open("sqlite", dsn)` as today.
2. Force materialization of WAL sidecars via `PRAGMA wal_checkpoint(TRUNCATE)` (or a sentinel `INSERT` + rollback — whichever is simpler; WAL checkpoint preferred).
3. `os.Chmod` on `.db`, `.db-wal`, `.db-shm` to `0600`. Missing sidecars tolerated (not all SQLite modes create both).
4. `os.Chmod` on the parent directory (`ProjectStateDir(root)/audit/` or equivalent) to `0700`.
5. Idempotent: runs every `veil run` so existing installs with `0644` get silently corrected.

Errors wrapped as `audit.ErrAuditOpen`.

### H3 — Age keystore parent-dir mode

In `internal/vault/keystore_file.go:saveMap` (or the `MkdirAll` caller at `~/.local/state/veil/`):

1. `os.MkdirAll(dir, 0700)` unchanged.
2. After, `os.Stat` the immediate parent directory.
3. If mode is not `0700`, `os.Chmod` to `0700`.
4. If `Chmod` fails, return a typed error (`keystore.ErrKeystoreWrite`) rather than silently proceeding with a world-listable parent.

### L2 — CA bundle temp handling

In `internal/runner/runner.go`:

- Switch from single temp-file writes to a per-session `os.MkdirTemp(pattern="veil-session-*")` directory.
- All session artifacts (CA bundle, any future temp files) go inside it.
- `RemoveCABundle` becomes `RemoveSessionDir` — removes the whole directory on clean shutdown.
- On `veil run` startup, sweep `/tmp/veil-session-*` directories owned by the current UID older than 24h (best-effort; log but don't fail on errors).

### Phase 3 tests

- Integration test in `internal/audit/` that calls `Open`, then `os.Stat`s `.db`, `.db-wal`, `.db-shm`, and parent dir; asserts modes `0600`/`0600`/`0600`/`0700`.
- Pre-create the DB files at `0644` in a test, re-open, assert corrected to `0600` (idempotency).
- `keystore_file` test: create parent at `0755` pre-existing, invoke save, assert parent reset to `0700`.
- `runner` test: assert per-session temp directory exists during run and is removed after clean shutdown.

---

## Phase 4 — Keystore safety (C3, H2, H4b)

### C3 — Test-keystore build tag

1. Move the `os.Getenv("VEIL_TEST_KEYSTORE") == "mem"` branch from `internal/cli/helpers.go:buildKeystore` into a new file `internal/cli/helpers_testkeystore.go` guarded by `//go:build testkeystore`.
2. Provide a stub for the opposite build (`//go:build !testkeystore`) — e.g., `helpers_notestkeystore.go` — so `buildKeystore` calls the hook unconditionally; the stub is a no-op returning `(nil, false)`.
3. Makefile: add `-tags testkeystore` to `make test`, `make test-race`, and the integration-test target. `make build` and `make xbuild` unchanged.
4. `NewMemKeystore` in `internal/testutil/` moves behind the same build tag.
5. Production binaries silently ignore `VEIL_TEST_KEYSTORE` — the code path does not compile in. No runtime rejection, no warning.

### H2 — D-Bus probe Delete-failure semantics

In `internal/vault/keystore_auto.go`:

1. Probe runs `Set` then `Delete`.
2. On `Set` success + `Delete` failure: log via `ui.Warn` exactly once at probe time (not once per operation), stay on the keyring keystore.
3. On `Set` failure: fall back to file keystore as today.

Warning text: `"warning: keyring cleanup failed during probe (keep an eye on ~/.cache/keyring or similar); veil will continue using the system keyring"` — or similar. Finalized during implementation.

### H4b — Zero hex buffer in `saveMap`

In `FileKeystore.saveMap`:

1. After writing the hex-encoded buffer to disk, overwrite the byte slice with zeros before returning.
2. The in-memory map itself (with raw-byte key values) is left as-is — that's the MVP tradeoff documented in the threat model (Phase 7).
3. `CreateVault`'s existing deferred zeroing of the local `[]byte` retained.

### Phase 4 tests

- Build-tag test: compile `internal/cli` without `testkeystore` tag and assert `VEIL_TEST_KEYSTORE=mem` produces the real auto-keystore (via behavior test, since the code path is gone).
- D-Bus probe test with a mock keyring where `Delete` errors: assert keystore returned is the keyring (not file fallback) and a warning was emitted.
- `saveMap` test: write, then inspect the buffer that was passed in; assert all zero bytes.

---

## Phase 5 — Placeholder generator & registry (H1, L1, L6)

### H1 — Collision retry in generator

1. `Generate(provider, existing PlaceholderSet) (string, error)` — signature change accepting the existing set.
2. Up to 8 retries (hardcoded constant `maxCollisionRetries`), each sampling a fresh candidate.
3. On exhaustion, return `placeholder.ErrCollisionUnresolvable`. Caller (`Vault.Add`) wraps as `vault.ErrPlaceholderCollision` with the provider name.
4. For realistic providers (long random tails) collision probability per retry is ≈10⁻¹⁵; the fail branch is effectively unreachable but cheap.

### L1 — Explicit `Registry` API

1. New `Registry` struct in `internal/placeholder/providers.go` with methods `Register(Provider)`, `Match(input string) Provider`, `Get(name string) Provider`.
2. Default package-level `registry` populated by existing `init()` functions in `provider_*.go` — backwards-compatible, no behavioral change by default.
3. Tests can construct isolated `Registry` instances with only the providers under test.

### L6 — Table-driven provider tests

Single test file `internal/placeholder/providers_contract_test.go` with a table iterating every registered provider, asserting output:

- Matches the provider's declared regex.
- Has the expected length (if the provider declares one).
- Has the expected prefix (if declared).
- Has the expected character class (via `charclass.go` helpers).

Replaces (or supplements) per-provider ad-hoc assertion tests; those may be kept where they cover provider-specific quirks.

### Phase 5 tests

- Collision retry test: pre-seed `existing` with N collisions; assert generator succeeds within budget or errors cleanly beyond it.
- Registry isolation test: construct a registry with a single test provider; assert `Match`/`Get` ignore package-level registrations.
- Contract test table as described above.

---

## Phase 6 — Proxy request correctness + CA SKID (C1, H5, H6, M4)

### C1 — Query-string injection

1. Rename `parseHostPath` → `parseRequestURL` in `internal/proxy/injector.go`. Return `host`, `path`, `query` (raw query string).
2. `ProcessRequest` scans the raw query and rewrites placeholder matches the same way it rewrites host/path/body. Aho-Corasick match against the vault's placeholder set.
3. Audit record: `url_path` stores path only. Query content is **not** persisted to audit — consistent with Veil's goal of not leaking secrets via side channels. No new column.
4. Unit test: request with placeholder in `?api_key=<placeholder>` must emit a real secret on the wire; audit row must have `url_path = "/path"` with no query fragments.

### H5 — Content-Type allowlist for body injection

Body injection gated on Content-Type:

**Allowed** (inject):
- `application/json`
- `application/x-www-form-urlencoded`
- `text/*` (any)
- `application/xml`
- `application/*+json`
- `application/*+xml`

**Skip** (pass through untouched):
- Anything else.
- **Missing or empty Content-Type** → skip (strict).

Match is case-insensitive on the media type; parameters (e.g., `; charset=utf-8`) are ignored.

Injector refactored to accept a `Content-Type` string and return a boolean decision; unit tests drive the allowlist table.

### H6 — Body-read error handling

In `internal/proxy/proxy.go:106`:

1. `body, err := io.ReadAll(io.LimitReader(req.Body, int64(bodyCap)+1))`.
2. On `err != nil`: do not forward. Proxy returns `502 Bad Gateway` with a minimal body. Log via `ui.Warn` once per host per session (tracked in a small map on the proxy) to prevent log spam.
3. Typed error `proxy.ErrBodyRead` used internally.

### M4 — SHA-256 for SubjectKeyIdentifier

In `internal/proxy/ca.go:122`: replace SHA-1 with SHA-256 for the `SubjectKeyIdentifier` computation. No other CA changes in this phase.

### Phase 6 tests

- Query-string injection: end-to-end via goproxy test harness — request with placeholder in query, assert upstream sees real secret, audit row omits query.
- Content-Type gating: table-driven test covering each allowed/denied media type; binary body fixture (JPEG bytes containing an incidental placeholder-byte pattern) passes through unmodified.
- Body-read error: `io.ReadAll` returns error via a broken `io.Reader`; assert 502 returned, no forwarded request.
- CA SKID: generate a fresh CA, parse the extension, assert the hash is SHA-256 length.

---

## Phase 7 — Docs & platform parity (M3, L5)

### M3 — Threat model doc

New file `docs/THREAT_MODEL.md` (linked from `README.md`). Contents:

- **What Veil protects against:** agent seeing real secrets in `.env`/MCP configs; agent exfiltrating real secrets via outbound HTTP bodies/headers/query.
- **What Veil does NOT protect against:**
  - Same-UID agent process reading, truncating, or forging audit DB rows (M3 finding).
  - Long-running proxy process holding real credentials in memory for the duration of the session (H4 context).
  - Agent using a non-HTTP channel (DNS, raw TCP) — only `HTTP_PROXY`/`HTTPS_PROXY` traffic is mediated.
  - Agent code-execution tools that read the vault file directly (file permissions mitigate but a same-UID attacker can still read).
- **CA trust install scope:** the per-user CA is installed in the user's trust stores only; it is not system-wide. Agents running as the same user validate proxied TLS; other users on the machine do not.
- **Deployment notes for hardened setups:** running Veil under a separate UID from the agent (setuid helper, systemd user service with different user, launchd equivalent) eliminates same-UID tampering; not supported out-of-the-box in MVP.

### L5 — Platform-asymmetric child termination

1. New constant `runner.childTerminationGrace = 3 * time.Second` in a shared file.
2. `internal/runner/parentwatch_darwin.go:36-38` uses it.
3. `internal/runner/pgroup_linux.go:18` uses it where applicable (may still use `Pdeathsig` for the kernel-level kill, but any user-level grace period uses the shared constant).
4. If platform behaviors are fundamentally asymmetric (Pdeathsig is immediate SIGKILL by kernel), document the asymmetry in a comment above each platform file and make the user-visible timeout the same.

### Phase 7 tests

- Doc file presence + link from README checked in a simple test or lint.
- Constant usage grep test (if reasonable — alternatively just code review).

---

## Cross-cutting concerns

- **No new external dependencies.** Everything is stdlib + existing deps (`goproxy`, `modernc.org/sqlite`, `go-keyring`, `age`).
- **No schema migrations.** The audit DB schema is unchanged — C2 only chmod's files; C1's decision to omit query data means no new column.
- **No changes to `Makefile` build targets** beyond adding `-tags testkeystore` to `make test`/`make test-race`/integration targets.
- **Build tags added:** `testkeystore` (new; for test builds only). No other new tags.
- **Backwards compatibility:** existing installs get audit-DB perms corrected silently on first run under the new binary. Existing `.env` files are not re-scanned automatically; users who hit the C4 quoting bug previously will need to re-run `veil init` to pick up the now-recognized secrets. This is called out in release notes.
- **Rollout order is risk-driven, not dependency-driven.** After Phase 1 (infrastructure), phases 2–7 do not strictly depend on each other — they can be split across PRs or bundled at implementation-time discretion.

## Testing strategy

- **Per-phase unit tests** as enumerated above, co-located with the code they exercise.
- **Integration tests** added to `test/integration/` for the two cross-system behaviors: query-string injection end-to-end (C1), and audit DB permission verification after a real `veil run` (C2).
- **`VEIL_TEST_KEYSTORE=mem`** continues to work across all tests via `-tags testkeystore`.
- **No new test frameworks.** Table-driven `testing` package, as per existing convention.

## Success criteria

- All 19 in-scope findings have landed fixes.
- `make test` and `make test-race` pass with `-tags testkeystore`.
- `make lint` and `make vet` clean.
- `make xbuild` produces darwin/linux × amd64/arm64 binaries that do not contain the `VEIL_TEST_KEYSTORE` branch (verified by `grep` / `strings` on a cross-compiled binary if practical, or inferred from build-tag coverage).
- Threat model doc published.
- Release notes call out: audit DB perm correction on first run, re-run `veil init` if you hit C4 previously.
