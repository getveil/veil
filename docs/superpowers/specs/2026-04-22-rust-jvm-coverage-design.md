# CA Trust Coverage for Cargo and JVM Tools

**Date:** 2026-04-22
**Status:** Draft

## Problem

Veil's current CA trust delivery (`internal/runner/runner.go:244`) injects five env vars into the child process: `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `HTTPLIB2_CA_CERTS`. This covers Node, curl, Python `requests`, Python `httplib2`, and `CGO_ENABLED=0` Go binaries — the MVP's target toolchain.

It does not cover:

- **JVM tools** (`mvn`, `gradle`, `bazel-java`) — read `$JAVA_HOME/lib/security/cacerts` (a JKS/PKCS12 truststore), ignore env vars.
- **`cargo`** — uses rustls and honors its own `CARGO_HTTP_CAINFO` env var, but not the five above.
- **Other rustls binaries, `.NET`, cgo-enabled Go on macOS, GUI apps launched via URL scheme** — each has its own reason for not seeing Veil's CA.

Agents that invoke JVM or cargo subprocesses inside `veil run` get `x509: certificate signed by unknown authority`. This spec closes that specific gap without introducing any system-level trust modification, per the architectural decision in `docs/superpowers/specs/2026-04-12-transparent-ca-trust-design.md` (no sudo, no keychain writes, no permanent artifacts).

The remaining gaps (`.NET`, rustls-native-certs, cgo Go on macOS, URL-scheme GUI apps) are documented in `docs/USE_CASES.md` as known gaps rather than fixed here. The post-MVP kernel-level enforcement path (`NETransparentProxyProvider` / iptables) is the intended long-term fix for those.

## Approach

**Extend the existing per-session env-var machinery with two more runtime targets:**

1. **Cargo** — inject `CARGO_HTTP_CAINFO=<bundle.pem>` pointing at the combined PEM bundle Veil already builds.
2. **JVM** — generate a PKCS12 truststore at session start from the same combined PEM, inject `JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=<p12> -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit`. Merge with any pre-existing `JAVA_TOOL_OPTIONS` value so unrelated user flags survive.

Both artifacts live in the existing `veil-session-*` tempdir created at `runner.go:72` and are cleaned up by the existing deferred `os.RemoveAll` at `runner.go:76`. No new lifecycle.

### Alternatives Considered

**Runtime detection (inspect the child command; only inject JVM vars when the child looks Java-ish).** Rejected — brittle with shell-script wrappers, transitive Java invocation, `./gradlew`, and indirect callers. Unused env vars are harmless, so the detection buys nothing but risk.

**Separate `internal/runtimetrust` package.** Rejected — premature abstraction for two extra env vars. The existing `buildChildEnv` already applies the same pattern to five vars; adding two more is a linear extension.

**Shell out to `keytool`.** Rejected — makes `veil run` startup depend on the host having a JDK installed, which is a regression even though Java-using agents probably do have one. Pure-Go PKCS12 generation via `software.sslmate.com/src/go-pkcs12` (BSD-2-Clause) keeps Veil hermetic.

**System trust store install.** Explicitly out of scope per the architectural decision preserved from 2026-04-12. That path would cover more runtimes (`.NET`, rustls-native-certs) but re-introduces the sudo/keychain-residue cost the previous design ripped out.

## Design

### 1. New function: `BuildJavaTruststoreIn`

**File:** `internal/proxy/cabundle.go` (alongside the existing `BuildCABundleIn`).

```go
// BuildJavaTruststoreIn writes a PKCS12 truststore to sessionDir containing
// every CERTIFICATE block in bundlePEM as a trust anchor. Returns the path.
// Uses password "changeit" (JDK convention); the file is in a private tempdir
// so the password is a formality.
func BuildJavaTruststoreIn(sessionDir string, bundlePEM []byte) (string, error)
```

**Internals:**
1. Walk PEM blocks with `pem.Decode`; collect CERTIFICATE-typed blocks into `[]*x509.Certificate` via `x509.ParseCertificate`. Skip non-CERTIFICATE blocks silently.
2. If the resulting slice is empty, return an error — a truststore with zero anchors breaks JVM TLS validation for every host.
3. Call `pkcs12.Modern.EncodeTrustStore(rand.Reader, certs, "changeit")`.
4. Write via the existing `atomicWrite` helper with mode `0644`.
5. Return the path `<sessionDir>/java-truststore.p12`.

**Error handling:** hard-fail on any error (parse, encode, write). Unlike `BuildCABundleIn`, which degrades gracefully when system CA extraction fails (Veil-only bundle + warning), a missing or malformed truststore breaks TLS validation for *every* JVM host — there is no useful degraded mode. A failure here aborts `Run()`.

### 2. Env var additions

**File:** `internal/envkeys/envkeys.go`

Add `CARGO_HTTP_CAINFO` to the `CAKeys` list. This places it on the strip-and-replace path: any pre-existing value in the parent env is stripped by the loop at `runner.go:229` before Veil sets its own.

`JAVA_TOOL_OPTIONS` is **not** added to `CAKeys` — it needs merge semantics, handled inline in `buildChildEnv` rather than strip-and-replace.

### 3. Runner changes

**File:** `internal/runner/runner.go`

**3a. `Run()` — insert PKCS12 build after `BuildCABundleIn`:**

```go
bundlePath, err := proxy.BuildCABundleIn(sessionDir, ca.CertPEM)
if err != nil { return nil, fmt.Errorf("build ca bundle: %w", err) }

bundlePEM, err := os.ReadFile(bundlePath)
if err != nil {
    return nil, fmt.Errorf("read ca bundle: %w", err)
}
javaTruststorePath, err := proxy.BuildJavaTruststoreIn(sessionDir, bundlePEM)
if err != nil {
    return nil, fmt.Errorf("build java truststore: %w", err)
}
```

No new `defer` — `os.RemoveAll(sessionDir)` already covers the PKCS12.

**3b. `buildChildEnv` signature:**

```go
func buildChildEnv(
    environ []string,
    proxyURL, bundlePath, javaTruststorePath string,  // new parameter
    skipHosts, vaultNames []string,
) ([]string, []string)
```

**3c. `buildChildEnv` body — JAVA_TOOL_OPTIONS merge:**

After the existing strip loop but before the final `append(...)`:

```go
veilJavaFlags := fmt.Sprintf(
    "-Djavax.net.ssl.trustStore=%s -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit",
    javaTruststorePath,
)
javaToolOpts := veilJavaFlags
for _, kv := range environ {
    if k, v, ok := strings.Cut(kv, "="); ok && strings.EqualFold(k, "JAVA_TOOL_OPTIONS") {
        if existing := strings.TrimSpace(v); existing != "" {
            javaToolOpts = existing + " " + veilJavaFlags
        }
        break
    }
}
```

Veil's flags come **after** the user's value. Java processes `JAVA_TOOL_OPTIONS` as if it were appended to the command line; later `-D` flags win for the same property. Putting Veil's truststore flag last means it overrides any user-supplied `javax.net.ssl.trustStore`. Intentional: the proxy must be trusted or HTTPS breaks, so Veil's truststore has to win for the duration of `veil run`.

**3d. Strip loop — skip pre-existing JAVA_TOOL_OPTIONS:**

```go
if isProxyEnvKey(key) || isCAEnvKey(key) || strings.EqualFold(key, "JAVA_TOOL_OPTIONS") {
    continue
}
```

This prevents the user's value from being passed through as-is; the merged value is emitted in the final append instead.

**3e. Final append block — add two lines:**

```go
"CARGO_HTTP_CAINFO="+bundlePath,
"JAVA_TOOL_OPTIONS="+javaToolOpts,
```

### 4. Lifecycle & Invariants

- PKCS12 is built once per `veil run`, at the same point as the PEM bundle.
- Both files live in `sessionDir`.
- Both are removed by the existing deferred `os.RemoveAll(sessionDir)`.
- No system trust store is touched.
- No sudo prompts.
- No permanent artifacts survive a clean `veil run` exit. Crashes leave a per-session tempdir containing only public CA certs; the existing `sweepStaleSessionDirs` at `runner.go:365` reaps it within 24h.

### 5. Files Changed

| File | Action |
|---|---|
| `internal/proxy/cabundle.go` | **Modify** — add `BuildJavaTruststoreIn` |
| `internal/proxy/cabundle_test.go` | **Modify** — add `TestBuildJavaTruststoreIn` |
| `internal/runner/runner.go` | **Modify** — call `BuildJavaTruststoreIn`, extend `buildChildEnv` |
| `internal/runner/runner_test.go` | **Modify** — extend `TestBuildChildEnv` |
| `internal/envkeys/envkeys.go` | **Modify** — add `CARGO_HTTP_CAINFO` to `CAKeys` |
| `test/integration/jvm_cargo_e2e_test.go` | **New** — gated integration tests |
| `docs/USE_CASES.md` | **Modify** — add cargo/JVM rows + Known gaps section |
| `docs/ARCHITECTURE.md` | **Modify** — note PKCS12 generation in the Runner row |
| `go.mod` / `go.sum` | **Modify** — add `software.sslmate.com/src/go-pkcs12` |

### 6. Testing

**Unit — `TestBuildJavaTruststoreIn`:**
- Generate a CA via `GenerateCA()`.
- Build a PEM bundle via `BuildCABundleIn`, read it back.
- Call `BuildJavaTruststoreIn`, decode the result with `pkcs12.DecodeTrustStore`.
- Assert cert count matches the PEM bundle's CERTIFICATE-block count.
- Assert Veil CA is present in the decoded set.
- Assert the file is written inside the provided `sessionDir`.
- Assert removing `sessionDir` removes the PKCS12.

**Unit — extend `TestBuildChildEnv`:**
- With pre-existing `JAVA_TOOL_OPTIONS=-Xmx2g`: assert output is `JAVA_TOOL_OPTIONS=-Xmx2g -Djavax.net.ssl.trustStore=... -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit` (user flag first, Veil flags after).
- With no pre-existing value: assert output is exactly Veil's flags.
- With pre-existing `CARGO_HTTP_CAINFO=/old/ca.pem`: assert it is stripped and replaced with the bundle path.

**Integration — `test/integration/jvm_cargo_e2e_test.go`:**
- `cargo search serde --limit 1` through `veil run`. Assert exit 0 and non-empty stdout. `t.Skip()` if `cargo` is not on PATH.
- A one-off Java HTTPS request (e.g., a small source file written to `t.TempDir()` and invoked via `java Foo.java` in Java 11+ source-file mode, or piped through `jshell -s`) hitting `https://api.github.com/`. Assert exit 0. `t.Skip()` if no JDK on PATH.

Both integration tests are gated on toolchain presence so hosts without Java or Rust installed pass the suite.

### 7. Documentation

**`docs/USE_CASES.md`** — add to the "CLI tools and subprocesses" table:
- `cargo publish` / `cargo install` — Supported (via `CARGO_HTTP_CAINFO`).
- `mvn deploy`, `./gradlew publish` — Supported (via `JAVA_TOOL_OPTIONS` + per-session PKCS12 truststore).

New section **"Known gaps"** at the end of the file:

> The following categories fall outside the env-var trust-delivery model and are not covered by the MVP. Users hitting x509 errors from these can add the affected host to the skip list via `veil skip <host>`, accepting that the traffic bypasses the proxy entirely.
>
> - **`.NET` tools on macOS/Windows.** Use the native cert store; no env-var escape hatch. Covered by post-MVP kernel-level enforcement.
> - **Rust binaries using `rustls-native-certs`** (e.g., `sccache`). Read Security.framework on macOS, `/etc/ssl/certs` on Linux; ignore env vars.
> - **Rust binaries using baked-in `rustls::webpki_roots`.** Trust list is compiled into the binary; no runtime escape hatch at all.
> - **cgo-enabled Go binaries on macOS.** Use Security.framework via cgo. Rare in practice — most distributed Go binaries (`gh`, `kubectl`, `docker` CLI, `terraform`) are `CGO_ENABLED=0` and honor `SSL_CERT_FILE`.
> - **GUI apps launched via URL scheme or `open(1)`.** Inherit no env vars, bypass the proxy entirely. Out of scope for the MVP; covered by post-MVP kernel-level enforcement.

**`docs/ARCHITECTURE.md`** — update the Runner row of the Components table to note that the runner also generates a per-session PKCS12 truststore for JVM children. One line, no structural change.

### 8. Out of Scope

Called out explicitly so future readers don't mistake these for oversights:

- No system trust store modification (neither user-level nor admin-level keychain writes; no `/usr/local/share/ca-certificates/`).
- No `veil trust` / `veil untrust` commands. These were deliberately removed in 2026-04-12 and are not reintroduced.
- No `.NET` coverage.
- No coverage for rustls binaries beyond cargo.
- No runtime detection of child commands; env vars are injected unconditionally and tolerated harmlessly by non-Java / non-cargo children.
