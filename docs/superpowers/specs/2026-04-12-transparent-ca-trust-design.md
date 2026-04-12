# Transparent CA Trust via Combined Bundle

**Date:** 2026-04-12
**Status:** Draft

## Problem

Veil's MITM proxy requires the child process to trust Veil's locally-generated CA certificate. Currently, `veil trust` installs the CA into the macOS Keychain, which covers OS-native TLS clients. But many tools ship with bundled CA stores and ignore the system keychain entirely — Homebrew curl, Python's `certifi`, Ruby's bundled certs, etc. These tools fail with TLS errors unless manually configured.

The goal is for `veil run` to be fully self-sufficient: no system-level CA installation, no sudo prompts, no permanent artifacts. The agent and every tool it invokes should work through the proxy without any knowledge that Veil exists.

## Approach

**Combined PEM bundle + env var injection.** At `veil run` startup, Veil builds a temporary PEM file containing the system's CA roots plus Veil's root CA, then injects environment variables pointing every major runtime at that bundle.

### Alternatives Considered

**Append-to-existing strategy:** Detect what CA bundle each tool already uses and create patched copies. Rejected — requires locating per-runtime bundle paths, handling virtualenvs, multiple Python versions, etc. Fragile and hard to test.

**DYLD_INSERT_LIBRARIES / LD_PRELOAD hook:** Intercept TLS verification at the library level. Rejected — SIP on macOS blocks this for system binaries, breaks code signing, different hook points for different TLS libraries. A maintenance nightmare.

## Design

### 1. Combined CA Bundle

At proxy startup (inside `Run()` in `internal/runner/runner.go`), Veil builds a combined PEM bundle:

1. **Extract system CAs** (platform-specific):
   - **macOS:** `security export -t certs -p -k /System/Library/Keychains/SystemRootCertificates.keychain` + `/Library/Keychains/System.keychain`
   - **Linux:** Read from the first existing well-known path:
     - `/etc/ssl/certs/ca-certificates.crt` (Debian, Ubuntu, Alpine)
     - `/etc/pki/tls/certs/ca-bundle.crt` (RHEL, Fedora, CentOS)
     - `/etc/ssl/ca-bundle.pem` (openSUSE)
2. **Append Veil's root CA PEM** to the system certs
3. **Write to `~/.veil/ca-bundle.pem`** (overwritten each run, cleaned up on proxy stop)

This happens once at startup, not per-request.

**New file: `internal/proxy/cabundle.go`**
- `BuildCABundle(veilCAPEM []byte) (path string, err error)` — orchestrates extraction, append, and write. Returns the bundle file path.

**New file: `internal/proxy/cabundle_darwin.go`**
- `systemCAPEM() ([]byte, error)` — runs `security export` against both system keychains, concatenates PEM output.

**New file: `internal/proxy/cabundle_linux.go`**
- `systemCAPEM() ([]byte, error)` — reads from the first existing well-known CA bundle path.

**Error handling:** If system CA extraction fails, fall back to a bundle containing only Veil's CA and log a warning. The proxy will function but tools making requests to non-proxied hosts may fail. Acceptable degradation.

### 2. Env Var Injection

`buildChildEnv()` in `internal/runner/runner.go` is expanded to inject the combined bundle path into every known CA env var:

| Env Var | Runtime |
|---|---|
| `NODE_EXTRA_CA_CERTS` | Node.js (already present, retarget to combined bundle) |
| `SSL_CERT_FILE` | Go, OpenSSL-based tools |
| `CURL_CA_BUNDLE` | curl, libcurl |
| `REQUESTS_CA_BUNDLE` | Python requests, httpx |
| `HTTPLIB2_CA_CERTS` | Python httplib2 |

All point to the same `~/.veil/ca-bundle.pem` file. `SSL_CERT_DIR` is not set — a single file is sufficient and avoids hash-directory complexity.

Existing CA env vars are stripped from the parent environment before injection (same pattern as proxy var stripping). This prevents a pre-existing `SSL_CERT_FILE` or `REQUESTS_CA_BUNDLE` from overriding Veil's bundle. Implemented via an `isCAEnvKey()` function parallel to the existing `isProxyEnvKey()`.

### 3. Bundle Lifecycle

- **Created:** at the start of `Run()`, after loading the CA but before starting the proxy
- **Overwritten:** every `veil run` invocation regenerates it (system CAs may have changed)
- **Cleaned up:** in the deferred cleanup path of `Run()`, after child exit and proxy stop. File is deleted.

The bundle only exists on disk while `veil run` is active. No permanent artifacts.

If Veil crashes or receives SIGKILL, the file is orphaned. This is acceptable — it contains only public CA certificates (no secrets), is a few hundred KB, and is overwritten on the next run.

### 4. Removal of `veil trust`

The `veil trust` command and its supporting code are removed entirely:

- **Delete:** `internal/cli/trust.go` — the CLI command and `trustCmd()` registration
- **Delete:** `internal/proxy/trust.go` — `InstallCA()`, `UninstallCA()`, `IsTrusted()`
- **Delete:** `internal/proxy/trust_test.go`
- **Remove:** trust preflight warning in `runner.go` (lines 76-79, the `IsTrusted()` check)
- **Remove:** `smallstep/truststore` dependency from `go.mod` if nothing else uses it

**Kept:** `LoadOrCreateCA()`, `GenerateCA()`, `SaveCA()`, and leaf cert machinery — all still needed for MITM signing. The CA is still generated and stored on disk for leaf signing; it is just no longer installed into the system keychain.

### 5. Files Changed

| File | Action |
|---|---|
| `internal/proxy/cabundle.go` | **New** — `BuildCABundle()` |
| `internal/proxy/cabundle_darwin.go` | **New** — `systemCAPEM()` for macOS |
| `internal/proxy/cabundle_linux.go` | **New** — `systemCAPEM()` for Linux |
| `internal/proxy/cabundle_test.go` | **New** — tests for bundle building |
| `internal/runner/runner.go` | **Modify** — call `BuildCABundle()`, expand `buildChildEnv()`, remove trust preflight, add bundle cleanup |
| `internal/runner/runner_test.go` | **Modify** — update `TestBuildChildEnv` for new CA env vars |
| `internal/cli/trust.go` | **Delete** |
| `internal/proxy/trust.go` | **Delete** |
| `internal/proxy/trust_test.go` | **Delete** |
| `go.mod` / `go.sum` | **Modify** — remove `smallstep/truststore` if unused |

### 6. Testing

- **Unit:** `BuildCABundle()` — test by calling on the real platform (no mocking needed; `systemCAPEM()` is a build-tagged package-level function). Verify the output file contains valid PEM blocks and includes Veil's CA
- **Unit:** `buildChildEnv()` — verify all CA env vars are set and pre-existing ones are stripped
- **Integration:** `veil run curl https://httpbin.org/get` through the proxy — verify success without `veil trust`
- **Integration:** `veil run python -c "import requests; requests.get('https://httpbin.org/get')"` — verify Python with certifi works
