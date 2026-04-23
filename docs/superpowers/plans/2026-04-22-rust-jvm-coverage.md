# Rust/JVM CA Trust Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the env-var CA-trust gap for `cargo` (via `CARGO_HTTP_CAINFO`) and JVM tools (via a per-session PKCS12 truststore + merged `JAVA_TOOL_OPTIONS`), without modifying the system trust store.

**Architecture:** Extend the existing `veil run` env-var injection pipeline. A new `BuildJavaTruststoreIn` function emits a PKCS12 alongside the existing PEM bundle in the per-session tempdir. `buildChildEnv` gains a `javaTruststorePath` parameter and emits two new env vars (`CARGO_HTTP_CAINFO`, `JAVA_TOOL_OPTIONS`). JVM options merge with any user-supplied value; Veil's flags come last so the truststore wins. Same tempdir, same lifecycle, same cleanup.

**Tech Stack:** Go 1.26, `software.sslmate.com/src/go-pkcs12` (new dep), existing `internal/proxy` + `internal/runner` + `internal/envkeys` packages.

**Spec:** `docs/superpowers/specs/2026-04-22-rust-jvm-coverage-design.md`

---

### Task 1: Add CARGO_HTTP_CAINFO to envkeys.CAKeys

**Files:**
- Modify: `internal/envkeys/envkeys.go:29-35`
- Modify: `internal/envkeys/envkeys_test.go:29-51`

- [ ] **Step 1: Update the coverage test to expect the new key**

Edit `internal/envkeys/envkeys_test.go`, replace the `want` map in `TestCAKeysCoverage`:

```go
func TestCAKeysCoverage(t *testing.T) {
	want := map[string]bool{
		"NODE_EXTRA_CA_CERTS": true,
		"SSL_CERT_FILE":       true,
		"CURL_CA_BUNDLE":      true,
		"REQUESTS_CA_BUNDLE":  true,
		"HTTPLIB2_CA_CERTS":   true,
		"CARGO_HTTP_CAINFO":   true,
	}
	got := make(map[string]bool, len(CAKeys))
	for _, k := range CAKeys {
		got[k] = true
	}
	for k := range want {
		if !got[k] {
			t.Errorf("CAKeys missing %q", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("CAKeys has unexpected %q", k)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/envkeys/ -run TestCAKeysCoverage -v`

Expected: FAIL — `CAKeys missing "CARGO_HTTP_CAINFO"`.

- [ ] **Step 3: Add the key to CAKeys**

Edit `internal/envkeys/envkeys.go`, update the `CAKeys` var:

```go
// CAKeys lists environment variables that configure CA certificate bundles
// across common runtimes (Node, curl, Python requests, httplib2, OpenSSL,
// cargo). The runner strips these and replaces them with Veil's combined
// bundle path.
var CAKeys = []string{
	"NODE_EXTRA_CA_CERTS",
	"SSL_CERT_FILE",
	"CURL_CA_BUNDLE",
	"REQUESTS_CA_BUNDLE",
	"HTTPLIB2_CA_CERTS",
	"CARGO_HTTP_CAINFO",
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/envkeys/ -v`

Expected: PASS (all three tests in the file).

- [ ] **Step 5: Commit**

```bash
git add internal/envkeys/envkeys.go internal/envkeys/envkeys_test.go
git commit -m "feat(envkeys): add CARGO_HTTP_CAINFO to CA env keys"
```

---

### Task 2: Add go-pkcs12 dependency

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`

- [ ] **Step 1: Fetch the dependency**

Run: `go get software.sslmate.com/src/go-pkcs12@latest`

Expected: go.mod gains a line `require software.sslmate.com/src/go-pkcs12 vX.Y.Z` (current stable is v0.5.x as of 2026-04). go.sum picks up the corresponding hashes.

- [ ] **Step 2: Tidy the module**

Run: `go mod tidy`

Expected: No errors. go.sum is consistent.

- [ ] **Step 3: Verify everything still builds**

Run: `go build ./...`

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "chore(deps): add software.sslmate.com/src/go-pkcs12 for JVM truststore generation"
```

---

### Task 3: Implement BuildJavaTruststoreIn

**Files:**
- Modify: `internal/proxy/cabundle.go`
- Modify: `internal/proxy/cabundle_test.go`

- [ ] **Step 1: Write the failing test**

Edit `internal/proxy/cabundle_test.go`, add at the bottom:

```go
func TestBuildJavaTruststoreIn(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	sessionDir := t.TempDir()
	bundlePath, err := BuildCABundleIn(sessionDir, ca.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundleIn: %v", err)
	}
	bundlePEM, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}

	p12Path, err := BuildJavaTruststoreIn(sessionDir, bundlePEM)
	if err != nil {
		t.Fatalf("BuildJavaTruststoreIn: %v", err)
	}

	// Must live inside sessionDir (not a shared global path).
	if !strings.HasPrefix(p12Path, sessionDir) {
		t.Fatalf("PKCS12 path %q is outside sessionDir %q", p12Path, sessionDir)
	}

	// File must exist and be non-empty.
	info, err := os.Stat(p12Path)
	if err != nil {
		t.Fatalf("stat PKCS12: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("PKCS12 file is empty")
	}

	// PKCS12 must decode and contain the same cert count as the PEM bundle.
	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		t.Fatalf("read PKCS12: %v", err)
	}
	decoded, err := pkcs12.DecodeTrustStore(p12Data, "changeit")
	if err != nil {
		t.Fatalf("DecodeTrustStore: %v", err)
	}

	pemCount := 0
	rest := bundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			pemCount++
		}
	}
	if len(decoded) != pemCount {
		t.Fatalf("PKCS12 has %d certs, want %d (match PEM bundle)", len(decoded), pemCount)
	}

	// Veil CA specifically must be present in the decoded set.
	veilBlock, _ := pem.Decode(ca.CertPEM)
	if veilBlock == nil {
		t.Fatal("could not decode Veil CA PEM")
	}
	veilCert, err := x509.ParseCertificate(veilBlock.Bytes)
	if err != nil {
		t.Fatalf("parse Veil CA: %v", err)
	}
	found := false
	for _, c := range decoded {
		if c.Equal(veilCert) {
			found = true
			break
		}
	}
	if !found {
		t.Error("Veil CA not found in decoded PKCS12 truststore")
	}
}

func TestBuildJavaTruststoreIn_CleanedByRemoveAll(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	sessionDir := t.TempDir()
	bundlePath, err := BuildCABundleIn(sessionDir, ca.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundleIn: %v", err)
	}
	bundlePEM, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	p12Path, err := BuildJavaTruststoreIn(sessionDir, bundlePEM)
	if err != nil {
		t.Fatalf("BuildJavaTruststoreIn: %v", err)
	}

	if err := os.RemoveAll(sessionDir); err != nil {
		t.Fatalf("RemoveAll sessionDir: %v", err)
	}
	if _, err := os.Stat(p12Path); !os.IsNotExist(err) {
		t.Fatalf("PKCS12 still exists after RemoveAll sessionDir: stat err=%v", err)
	}
}

func TestBuildJavaTruststoreIn_EmptyPEMReturnsError(t *testing.T) {
	sessionDir := t.TempDir()
	_, err := BuildJavaTruststoreIn(sessionDir, nil)
	if err == nil {
		t.Fatal("expected error for empty PEM input")
	}
}
```

The existing file already imports `bytes`, `encoding/pem`, `os`, `testing`. Add the missing imports so the block becomes:

```go
import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy/ -run TestBuildJavaTruststoreIn -v`

Expected: FAIL — `undefined: BuildJavaTruststoreIn`.

- [ ] **Step 3: Implement BuildJavaTruststoreIn**

Edit `internal/proxy/cabundle.go`. Update the imports block:

```go
import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/ui"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)
```

Append at the bottom of the file:

```go
// javaTruststorePassword is the conventional JDK default password. The PKCS12
// lives in a per-session 0700 tempdir, so the password is a formality — any
// process that can read the file can already read any secret on the host.
const javaTruststorePassword = "changeit"

// BuildJavaTruststoreIn writes a PKCS12 truststore to sessionDir containing
// every CERTIFICATE block in bundlePEM as a trust anchor. Returns the full
// path to the written file.
//
// Unlike BuildCABundleIn, this function hard-fails on any error. A missing or
// malformed truststore breaks TLS for every JVM host — there is no useful
// degraded mode.
func BuildJavaTruststoreIn(sessionDir string, bundlePEM []byte) (string, error) {
	var certs []*x509.Certificate
	rest := bundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("%w: parse cert: %w", ErrCABundle, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return "", fmt.Errorf("%w: no CERTIFICATE blocks found in PEM bundle", ErrCABundle)
	}

	p12Data, err := pkcs12.Modern.EncodeTrustStore(rand.Reader, certs, javaTruststorePassword)
	if err != nil {
		return "", fmt.Errorf("%w: encode PKCS12: %w", ErrCABundle, err)
	}

	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		return "", fmt.Errorf("%w: ensure session dir: %w", ErrCABundle, err)
	}

	path := filepath.Join(sessionDir, "java-truststore.p12")
	if err := atomicWrite(path, p12Data, 0o644); err != nil {
		return "", fmt.Errorf("%w: write PKCS12: %w", ErrCABundle, err)
	}
	return path, nil
}
```

Note: `config` and `ui` stay imported because `BuildCABundle` still uses them. `atomicWrite` is an existing helper in the package.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/ -v`

Expected: PASS — all three new tests plus all existing `BuildCABundle` tests still pass.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/cabundle.go internal/proxy/cabundle_test.go
git commit -m "feat(proxy): add BuildJavaTruststoreIn for JVM CA trust delivery"
```

---

### Task 4: Plumb javaTruststorePath through buildChildEnv

**Files:**
- Modify: `internal/runner/runner.go:127` (call site), `runner.go:212` (signature)
- Modify: `internal/runner/runner_test.go` (all `buildChildEnv` test calls)

This task only changes the signature — no behavior change, no new env vars emitted yet. Emissions come in Tasks 5 and 6.

- [ ] **Step 1: Update all test call sites to pass the new arg**

Edit `internal/runner/runner_test.go`. Update each `buildChildEnv(...)` call to insert `/tmp/fake-truststore.p12` after the bundle path argument.

Call at line 371 (in `TestBuildChildEnv`):

```go
result, _ := buildChildEnv(base, "http://127.0.0.1:9999", "/tmp/fake-bundle.pem", "/tmp/fake-truststore.p12", nil, nil)
```

Call at line 429 (in `TestBuildChildEnv_MergesSkipHosts`):

```go
env, _ := buildChildEnv([]string{"HOME=/home/user"}, "http://127.0.0.1:8080", "/tmp/bundle.pem", "/tmp/fake-truststore.p12", []string{"staging.internal.com", "*.metrics.corp"}, nil)
```

Call at line 454 (in `TestBuildChildEnv_EmptySkipHosts`):

```go
env, _ := buildChildEnv([]string{"HOME=/home/user"}, "http://127.0.0.1:8080", "/tmp/bundle.pem", "/tmp/fake-truststore.p12", nil, nil)
```

Call at line 481 (in `TestBuildChildEnv_StripsVaultNamedEnvVar`):

```go
env, stripped := buildChildEnv(base, "http://127.0.0.1:8080", "/tmp/bundle.pem", "/tmp/fake-truststore.p12", nil, []string{"OPENAI_API_KEY", "AWS_ACCESS_KEY_ID"})
```

Call at line 513 (in `TestBuildChildEnv_PassesThroughNonMatchingVar`):

```go
env, stripped := buildChildEnv(base, "http://127.0.0.1:8080", "/tmp/bundle.pem", "/tmp/fake-truststore.p12", nil, []string{"OPENAI_API_KEY"})
```

Call at line 535 (in `TestBuildChildEnv_StripVaultNameCaseInsensitive`):

```go
env, stripped := buildChildEnv(base, "http://127.0.0.1:8080", "/tmp/bundle.pem", "/tmp/fake-truststore.p12", nil, []string{"openai_api_key"})
```

- [ ] **Step 2: Update the production call site**

Edit `internal/runner/runner.go`, line 127. Replace:

```go
env, strippedVault := buildChildEnv(os.Environ(), proxyURL, bundlePath, cfg.SkipHosts, vlt.Names())
```

With (using an empty string for the PKCS12 path until Task 5 wires the build; this placeholder is removed in Task 7):

```go
env, strippedVault := buildChildEnv(os.Environ(), proxyURL, bundlePath, "", cfg.SkipHosts, vlt.Names())
```

- [ ] **Step 3: Update buildChildEnv signature**

Edit `internal/runner/runner.go`, replace the `buildChildEnv` signature and leading comment block (around line 203-212):

```go
// buildChildEnv takes the current env, strips proxy-related, CA-related, and
// vault-managed credential vars, and adds the proxy vars pointing to proxyURL
// and CA vars pointing to bundlePath. skipHosts are appended to the default
// NO_PROXY list. javaTruststorePath is the per-session PKCS12 that JVM
// children use via JAVA_TOOL_OPTIONS (see Task 5/6). vaultNames is the set of
// credential names loaded from the vault; any env var whose key matches
// (case-insensitively) is removed so the child process cannot observe the
// real secret that the user exported in their shell. The names of env vars
// actually stripped because of the vault match are returned (using the
// original casing from the environment), so the caller can surface a startup
// warning.
func buildChildEnv(environ []string, proxyURL, bundlePath, javaTruststorePath string, skipHosts, vaultNames []string) ([]string, []string) {
```

No body change yet; `javaTruststorePath` is unused for now. Go will warn on unused parameters only inside function bodies, not on parameters themselves, so the build still passes.

- [ ] **Step 4: Run tests to verify nothing regressed**

Run: `go test ./internal/runner/ -v`

Expected: PASS — all existing tests still green. The new parameter is inert.

- [ ] **Step 5: Commit**

```bash
git add internal/runner/runner.go internal/runner/runner_test.go
git commit -m "refactor(runner): thread javaTruststorePath through buildChildEnv"
```

---

### Task 5: Emit CARGO_HTTP_CAINFO from buildChildEnv

**Files:**
- Modify: `internal/runner/runner.go:244-256` (final append block in `buildChildEnv`)
- Modify: `internal/runner/runner_test.go` (`TestBuildChildEnv`)

- [ ] **Step 1: Add failing assertion in TestBuildChildEnv**

Edit `internal/runner/runner_test.go`. In `TestBuildChildEnv`, add `CARGO_HTTP_CAINFO` to the pre-existing base env (so we can prove it is stripped), and extend the assertion list.

Add to the `base` slice in `TestBuildChildEnv`:

```go
base := []string{
	"PATH=/usr/bin",
	"HOME=/home/test",
	"HTTP_PROXY=http://old-proxy:8080",
	"HTTPS_PROXY=http://old-proxy:8080",
	"http_proxy=http://old-proxy:8080",
	"https_proxy=http://old-proxy:8080",
	"NO_PROXY=old-no-proxy",
	"no_proxy=old-no-proxy",
	"OTHER_VAR=keep-me",
	"SSL_CERT_FILE=/old/ca.pem",
	"CURL_CA_BUNDLE=/old/curl-ca.pem",
	"REQUESTS_CA_BUNDLE=/old/requests-ca.pem",
	"CARGO_HTTP_CAINFO=/old/cargo-ca.pem",
}
```

Extend the `caVars` slice:

```go
caVars := []string{
	"NODE_EXTRA_CA_CERTS",
	"SSL_CERT_FILE",
	"CURL_CA_BUNDLE",
	"REQUESTS_CA_BUNDLE",
	"HTTPLIB2_CA_CERTS",
	"CARGO_HTTP_CAINFO",
}
```

The existing `/old/` strip check already covers `/old/cargo-ca.pem`, so no additional strip assertion is needed.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/runner/ -run TestBuildChildEnv$ -v`

Expected: FAIL — `CARGO_HTTP_CAINFO = "", want "/tmp/fake-bundle.pem"`.

- [ ] **Step 3: Add CARGO_HTTP_CAINFO to the append block**

Edit `internal/runner/runner.go`. In `buildChildEnv`, update the final append block to include `CARGO_HTTP_CAINFO`:

```go
env := append(stripped,
	"HTTP_PROXY="+proxyURL,
	"HTTPS_PROXY="+proxyURL,
	"http_proxy="+proxyURL,
	"https_proxy="+proxyURL,
	"NO_PROXY="+noProxy,
	"no_proxy="+noProxy,
	"NODE_EXTRA_CA_CERTS="+bundlePath,
	"SSL_CERT_FILE="+bundlePath,
	"CURL_CA_BUNDLE="+bundlePath,
	"REQUESTS_CA_BUNDLE="+bundlePath,
	"HTTPLIB2_CA_CERTS="+bundlePath,
	"CARGO_HTTP_CAINFO="+bundlePath,
)
return env, strippedVault
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/runner/ -run TestBuildChildEnv$ -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/runner/runner.go internal/runner/runner_test.go
git commit -m "feat(runner): inject CARGO_HTTP_CAINFO for cargo CA trust"
```

---

### Task 6: Emit JAVA_TOOL_OPTIONS with merge semantics

**Files:**
- Modify: `internal/runner/runner.go` (`buildChildEnv` strip loop + append block)
- Modify: `internal/runner/runner_test.go` (new test function)

- [ ] **Step 1: Write the failing test**

Edit `internal/runner/runner_test.go`. Add a new test function at the end of the `buildChildEnv` test cluster (after `TestBuildChildEnv_StripVaultNameCaseInsensitive`):

```go
// TestBuildChildEnv_InjectsJavaToolOptions verifies that buildChildEnv emits
// JAVA_TOOL_OPTIONS pointing at the per-session PKCS12 truststore when no
// pre-existing value is set. Veil's flags include the truststore path, type,
// and the conventional "changeit" password.
func TestBuildChildEnv_InjectsJavaToolOptions(t *testing.T) {
	base := []string{"PATH=/usr/bin"}
	env, _ := buildChildEnv(base, "http://127.0.0.1:9999", "/tmp/bundle.pem", "/tmp/ts.p12", nil, nil)

	var got string
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "JAVA_TOOL_OPTIONS" {
			got = v
			break
		}
	}
	if got == "" {
		t.Fatal("JAVA_TOOL_OPTIONS not set in child env")
	}
	want := "-Djavax.net.ssl.trustStore=/tmp/ts.p12 -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit"
	if got != want {
		t.Fatalf("JAVA_TOOL_OPTIONS = %q, want %q", got, want)
	}
}

// TestBuildChildEnv_MergesJavaToolOptions verifies that a pre-existing
// JAVA_TOOL_OPTIONS value is preserved, with Veil's flags appended AFTER the
// user's. Later -D flags win for the same Java system property, so Veil's
// truststore override is effective even if the user set their own.
func TestBuildChildEnv_MergesJavaToolOptions(t *testing.T) {
	base := []string{
		"PATH=/usr/bin",
		"JAVA_TOOL_OPTIONS=-Xmx2g -Dfoo=bar",
	}
	env, _ := buildChildEnv(base, "http://127.0.0.1:9999", "/tmp/bundle.pem", "/tmp/ts.p12", nil, nil)

	var got string
	count := 0
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "JAVA_TOOL_OPTIONS" {
			got = v
			count++
		}
	}
	if count != 1 {
		t.Fatalf("JAVA_TOOL_OPTIONS set %d times, want exactly 1", count)
	}
	want := "-Xmx2g -Dfoo=bar -Djavax.net.ssl.trustStore=/tmp/ts.p12 -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit"
	if got != want {
		t.Fatalf("JAVA_TOOL_OPTIONS = %q, want %q", got, want)
	}
}

// TestBuildChildEnv_EmptyJavaToolOptionsTreatedAsUnset verifies that an
// environment with JAVA_TOOL_OPTIONS set to the empty string is treated
// identically to one with the var unset — no leading whitespace, no
// pathological concatenation.
func TestBuildChildEnv_EmptyJavaToolOptionsTreatedAsUnset(t *testing.T) {
	base := []string{"JAVA_TOOL_OPTIONS="}
	env, _ := buildChildEnv(base, "http://127.0.0.1:9999", "/tmp/bundle.pem", "/tmp/ts.p12", nil, nil)

	var got string
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "JAVA_TOOL_OPTIONS" {
			got = v
			break
		}
	}
	want := "-Djavax.net.ssl.trustStore=/tmp/ts.p12 -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit"
	if got != want {
		t.Fatalf("JAVA_TOOL_OPTIONS = %q, want %q (no leading space)", got, want)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/runner/ -run "TestBuildChildEnv_(Injects|Merges|Empty)JavaToolOptions" -v`

Expected: FAIL — `JAVA_TOOL_OPTIONS not set in child env` for the first two, and unexpected leading-space content for the third.

- [ ] **Step 3: Update the strip loop and append block**

Edit `internal/runner/runner.go`. In `buildChildEnv`, update the strip loop (currently at line 229) to also skip pre-existing `JAVA_TOOL_OPTIONS` so Veil's merged value is emitted later:

```go
for _, kv := range environ {
	key, _, ok := strings.Cut(kv, "=")
	if !ok {
		stripped = append(stripped, kv)
		continue
	}
	if isProxyEnvKey(key) || isCAEnvKey(key) || strings.EqualFold(key, "JAVA_TOOL_OPTIONS") {
		continue
	}
	if _, hit := vaultSet[strings.ToUpper(key)]; hit {
		strippedVault = append(strippedVault, key)
		continue
	}
	stripped = append(stripped, kv)
}
```

Then, just above the `noProxy` construction, compute the merged `JAVA_TOOL_OPTIONS` value:

```go
veilJavaFlags := fmt.Sprintf(
	"-Djavax.net.ssl.trustStore=%s -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit",
	javaTruststorePath,
)
javaToolOpts := veilJavaFlags
for _, kv := range environ {
	k, v, ok := strings.Cut(kv, "=")
	if !ok {
		continue
	}
	if strings.EqualFold(k, "JAVA_TOOL_OPTIONS") {
		if existing := strings.TrimSpace(v); existing != "" {
			javaToolOpts = existing + " " + veilJavaFlags
		}
		break
	}
}
```

Add `JAVA_TOOL_OPTIONS` to the final append block after `CARGO_HTTP_CAINFO`:

```go
env := append(stripped,
	"HTTP_PROXY="+proxyURL,
	"HTTPS_PROXY="+proxyURL,
	"http_proxy="+proxyURL,
	"https_proxy="+proxyURL,
	"NO_PROXY="+noProxy,
	"no_proxy="+noProxy,
	"NODE_EXTRA_CA_CERTS="+bundlePath,
	"SSL_CERT_FILE="+bundlePath,
	"CURL_CA_BUNDLE="+bundlePath,
	"REQUESTS_CA_BUNDLE="+bundlePath,
	"HTTPLIB2_CA_CERTS="+bundlePath,
	"CARGO_HTTP_CAINFO="+bundlePath,
	"JAVA_TOOL_OPTIONS="+javaToolOpts,
)
return env, strippedVault
```

The `fmt` package is already imported in `runner.go`, no new imports needed.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/runner/ -v`

Expected: PASS — all three new tests plus all existing tests in the file.

- [ ] **Step 5: Commit**

```bash
git add internal/runner/runner.go internal/runner/runner_test.go
git commit -m "feat(runner): inject JAVA_TOOL_OPTIONS with merge for JVM CA trust"
```

---

### Task 7: Wire BuildJavaTruststoreIn into Run()

**Files:**
- Modify: `internal/runner/runner.go` (inside `Run`)
- Modify: `internal/runner/runner_test.go` (extend `TestRunChildCAEnvVars` or add new test)

- [ ] **Step 1: Write the failing integration-style test**

Edit `internal/runner/runner_test.go`. Add a new test function after `TestRunChildCAEnvVars`:

```go
// TestRunChildJavaTruststore verifies that Run() builds a per-session PKCS12
// truststore and exposes its path via JAVA_TOOL_OPTIONS. The child sh reads
// back JAVA_TOOL_OPTIONS and we assert the path points to a file with the
// expected suffix inside a tempdir that exists while the child runs.
func TestRunChildJavaTruststore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	root, ks := testutil.SetupVaultProject(t)
	outFile := filepath.Join(t.TempDir(), "java-opts.txt")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := Run(ctx, Config{
		Root:     root,
		Command:  "sh",
		Args:     []string{"-c", "printenv JAVA_TOOL_OPTIONS > " + outFile},
		Keystore: ks,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read env output: %v", err)
	}
	got := strings.TrimSpace(string(data))
	if !strings.Contains(got, "-Djavax.net.ssl.trustStore=") {
		t.Fatalf("JAVA_TOOL_OPTIONS missing trustStore flag: %q", got)
	}
	if !strings.Contains(got, "java-truststore.p12") {
		t.Fatalf("JAVA_TOOL_OPTIONS does not reference java-truststore.p12: %q", got)
	}
	if !strings.Contains(got, "-Djavax.net.ssl.trustStoreType=PKCS12") {
		t.Fatalf("JAVA_TOOL_OPTIONS missing trustStoreType=PKCS12: %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/runner/ -run TestRunChildJavaTruststore -v`

Expected: FAIL — `JAVA_TOOL_OPTIONS` refers to an empty path, since Task 4 threaded `""` to `buildChildEnv` and Task 7 hasn't built the PKCS12 yet. The test will fail on the `java-truststore.p12` substring check.

- [ ] **Step 3: Build the PKCS12 in Run() and pass it through**

Edit `internal/runner/runner.go`. In `Run()`, just after the existing `BuildCABundleIn` call (around line 78), insert the PKCS12 build:

```go
bundlePath, err := proxy.BuildCABundleIn(sessionDir, ca.CertPEM)
if err != nil {
	return nil, fmt.Errorf("build ca bundle: %w", err)
}

bundlePEM, err := os.ReadFile(bundlePath)
if err != nil {
	return nil, fmt.Errorf("read ca bundle: %w", err)
}
javaTruststorePath, err := proxy.BuildJavaTruststoreIn(sessionDir, bundlePEM)
if err != nil {
	return nil, fmt.Errorf("build java truststore: %w", err)
}
```

Then update the `buildChildEnv` call (around line 127) to pass the real path instead of the empty placeholder from Task 4:

```go
env, strippedVault := buildChildEnv(os.Environ(), proxyURL, bundlePath, javaTruststorePath, cfg.SkipHosts, vlt.Names())
```

No new imports; `os` and `proxy` are already imported.

- [ ] **Step 4: Run the full runner test suite**

Run: `go test ./internal/runner/ -v`

Expected: PASS — all existing tests plus the new `TestRunChildJavaTruststore`.

- [ ] **Step 5: Commit**

```bash
git add internal/runner/runner.go internal/runner/runner_test.go
git commit -m "feat(runner): build per-session PKCS12 truststore for JVM children"
```

---

### Task 8: End-to-end integration test for cargo and JVM

**Files:**
- Create: `test/integration/jvm_cargo_e2e_test.go`

This test exercises the full `veil init` + `veil run` path with real toolchain binaries. It is gated on `cargo` and `java` being present on PATH — hosts without them get `t.Skip()`, so CI without these tools stays green.

- [ ] **Step 1: Write the test file**

Create `test/integration/jvm_cargo_e2e_test.go`:

```go
package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2E_CargoThroughVeil runs `cargo search` through `veil run`. Cargo uses
// rustls and honors CARGO_HTTP_CAINFO; if Veil's injection works end-to-end,
// cargo successfully hits crates.io through the MITM proxy and returns
// results. Skipped if cargo is not on PATH.
func TestE2E_CargoThroughVeil(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skipf("cargo not on PATH: %v", err)
	}

	env := makeEnv(t)

	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)

	projDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projDir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	initCmd := exec.Command(veilBin, "init", "--path", projDir, "--yes")
	initCmd.Env = env
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("veil init: %v\n%s", err, out)
	}

	// cargo search uses HTTPS to crates.io; a success exit + non-empty stdout
	// proves the rustls client trusted Veil's MITM cert via CARGO_HTTP_CAINFO.
	runCmd := exec.Command(veilBin, "run", "--path", projDir, "--", "cargo", "search", "serde", "--limit", "1")
	runCmd.Env = env
	out, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil run cargo search: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "serde") {
		t.Fatalf("cargo search output does not contain 'serde': %s", out)
	}
}

// TestE2E_JavaThroughVeil runs a Java HTTPS request through `veil run` using
// Java 11+ source-file mode. If Veil's PKCS12 truststore + JAVA_TOOL_OPTIONS
// injection works, the JVM trusts Veil's MITM cert and the request succeeds.
// Skipped if java is not on PATH or is older than Java 11.
func TestE2E_JavaThroughVeil(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	javaBin, err := exec.LookPath("java")
	if err != nil {
		t.Skipf("java not on PATH: %v", err)
	}

	// Require Java 11+ for source-file mode.
	verOut, err := exec.Command(javaBin, "-version").CombinedOutput()
	if err != nil {
		t.Skipf("java -version failed: %v", err)
	}
	// Java prints version to stderr; -version output looks like:
	//   openjdk version "17.0.10" 2024-01-16
	// or "1.8.0_402" for Java 8.
	// Java 5-8 used the "1.X.Y" scheme; Java 9+ is just "X.Y.Z".
	// Only Java 5-8 match `version "1.`. Java 11's "11.0.22" starts with 11, not 1.,
	// so `version "11.` does NOT contain `version "1.` prefix.
	verStr := string(verOut)
	if strings.Contains(verStr, "version \"1.") {
		t.Skipf("java is pre-11 (source-file mode unavailable): %s", verStr)
	}

	env := makeEnv(t)

	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)

	projDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projDir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	initCmd := exec.Command(veilBin, "init", "--path", projDir, "--yes")
	initCmd.Env = env
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("veil init: %v\n%s", err, out)
	}

	javaSrc := `public class Probe {
    public static void main(String[] args) throws Exception {
        var url = new java.net.URL("https://api.github.com/");
        try (var in = url.openStream()) {
            byte[] buf = new byte[1024];
            int n = in.read(buf);
            if (n <= 0) throw new RuntimeException("empty response");
        }
        System.out.println("ok");
    }
}
`
	javaFile := filepath.Join(projDir, "Probe.java")
	if err := os.WriteFile(javaFile, []byte(javaSrc), 0o644); err != nil {
		t.Fatalf("write Probe.java: %v", err)
	}

	runCmd := exec.Command(veilBin, "run", "--path", projDir, "--", "java", "Probe.java")
	runCmd.Env = env
	runCmd.Dir = projDir
	out, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil run java: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ok") {
		t.Fatalf("java probe did not print 'ok': %s", out)
	}
}
```

- [ ] **Step 2: Run the integration tests**

Run: `go test ./test/integration/ -run "TestE2E_(Cargo|Java)ThroughVeil" -v`

Expected:
- On a host with both `cargo` and `java` (Java 11+): both PASS. Requires network access to crates.io and api.github.com.
- On a host missing either: the missing one reports SKIP; the other runs as above.
- On a host with neither: both SKIP.

If either test fails due to network flakiness (crates.io / api.github.com unreachable), re-run once; if it still fails, investigate — the injection is broken.

- [ ] **Step 3: Commit**

```bash
git add test/integration/jvm_cargo_e2e_test.go
git commit -m "test(integration): add cargo + JVM e2e through veil run"
```

---

### Task 9: Update USE_CASES.md and ARCHITECTURE.md

**Files:**
- Modify: `docs/USE_CASES.md`
- Modify: `docs/ARCHITECTURE.md`

- [ ] **Step 1: Update the CLI tools intro paragraph**

Edit `docs/USE_CASES.md`. Replace the three-line intro under `## CLI tools and subprocesses` (currently at lines 47-50) with:

```markdown
Subprocesses inherit `HTTP_PROXY` / `HTTPS_PROXY` and the CA bundle env vars
(`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`,
`REQUESTS_CA_BUNDLE`, `HTTPLIB2_CA_CERTS`, `CARGO_HTTP_CAINFO`) plus
`JAVA_TOOL_OPTIONS` for JVM children, so their HTTPS traffic flows through
the same proxy.
```

- [ ] **Step 2: Renumber existing rows 21-32 to make room**

The doc uses continuous numbering across sections. To insert two new rows between rows 20 and the current row 21, first renumber the existing rows 21-32 → 23-34.

Run this `sed` (high→low order prevents cascading double-increments):

```bash
sed -i.bak -E '
s/^\| 32 /| 34 /
s/^\| 31 /| 33 /
s/^\| 30 /| 32 /
s/^\| 29 /| 31 /
s/^\| 28 /| 30 /
s/^\| 27 /| 29 /
s/^\| 26 /| 28 /
s/^\| 25 /| 27 /
s/^\| 24 /| 26 /
s/^\| 23 /| 25 /
s/^\| 22 /| 24 /
s/^\| 21 /| 23 /
' docs/USE_CASES.md && rm docs/USE_CASES.md.bak
```

Verify with:

```bash
grep -E '^\| [0-9]+ ' docs/USE_CASES.md
```

Expected: rows 1-20 unchanged; rows 23-34 present (was 21-32); no rows numbered 21 or 22 yet. F1-F6 unchanged.

- [ ] **Step 3: Insert the new cargo and JVM rows**

Edit `docs/USE_CASES.md`. After the existing row `| 20 | Agent spawns MCP server subprocess — inherits proxy env, outbound calls intercepted. | Supported |`, insert two new rows:

```markdown
| 21 | `cargo publish` / `cargo search` / `cargo install` — rustls honors `CARGO_HTTP_CAINFO`. | Supported |
| 22 | `mvn deploy`, `./gradlew publish`, Bazel Java — JVM honors `JAVA_TOOL_OPTIONS` with per-session PKCS12 truststore. Merged with any pre-existing `JAVA_TOOL_OPTIONS`. | Supported |
```

Verify final state:

```bash
grep -E '^\| [0-9]+ ' docs/USE_CASES.md | head -40
```

Expected: rows 1-34 contiguous, no gaps, no duplicates.

- [ ] **Step 4: Add a "Known gaps" section**

Append a new section to the bottom of `docs/USE_CASES.md`:

```markdown
## Known gaps

The following categories fall outside the env-var trust-delivery model and are
not covered by the MVP. Users hitting x509 errors from these can add the
affected host to the skip list via `veil skip <host>`, accepting that the
traffic bypasses the proxy entirely.

- **`.NET` tools on macOS / Windows.** Use the native cert store; no env-var
  escape hatch. Covered by post-MVP kernel-level enforcement.
- **Rust binaries using `rustls-native-certs`** (e.g., `sccache`). Read
  Security.framework on macOS, `/etc/ssl/certs` on Linux; ignore env vars.
- **Rust binaries using baked-in `rustls::webpki_roots`.** Trust list is
  compiled into the binary; no runtime escape hatch at all.
- **cgo-enabled Go binaries on macOS.** Use Security.framework via cgo. Rare
  in practice — most distributed Go binaries (`gh`, `kubectl`, `docker` CLI,
  `terraform`) are `CGO_ENABLED=0` and honor `SSL_CERT_FILE`.
- **GUI apps launched via URL scheme or `open(1)`.** Inherit no env vars,
  bypass the proxy entirely. Out of scope for the MVP; covered by post-MVP
  kernel-level enforcement.
```

- [ ] **Step 5: Update the Runner row in ARCHITECTURE.md**

Edit `docs/ARCHITECTURE.md`. Find the Runner row in the Components table (around line 79) and replace:

```markdown
| Runner | `internal/runner` | Agent process lifecycle — spawn with proxy + CA env vars, forward signals, reclaim foreground tty, clean session temp dir. |
```

With:

```markdown
| Runner | `internal/runner` | Agent process lifecycle — spawn with proxy + CA env vars, generate per-session PKCS12 truststore for JVM children (exposed via `JAVA_TOOL_OPTIONS`), forward signals, reclaim foreground tty, clean session temp dir. |
```

- [ ] **Step 6: Sanity-check docs render**

Run: `go build ./... && go test ./...`

Expected: PASS. (Docs-only changes don't break builds, but we run tests to confirm nothing else regressed.)

- [ ] **Step 7: Commit**

```bash
git add docs/USE_CASES.md docs/ARCHITECTURE.md
git commit -m "docs: document cargo/JVM CA trust and known coverage gaps"
```

---

## Closeout

After Task 9 commits, the branch contains 9 commits implementing the spec. Run the full test suite once more:

```bash
go test ./...
```

All tests should pass on the host. If any integration tests were skipped (no cargo / no Java), note that in any PR description.
