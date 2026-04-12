# Transparent CA Trust Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `veil run` fully self-sufficient for CA trust — no `veil trust`, no system keychain modification, no sudo prompts. Every tool the child process invokes trusts Veil's CA via a combined PEM bundle injected through environment variables.

**Architecture:** At `veil run` startup, extract system CA roots (platform-specific), append Veil's CA, write to a temp bundle file, and inject env vars (`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, etc.) pointing all major runtimes at that bundle. Remove the `veil trust` command and all trust-store-related code.

**Tech Stack:** Go, build-tagged platform files (`_darwin.go`, `_linux.go`), `security` CLI (macOS), PEM encoding

**Spec:** `docs/superpowers/specs/2026-04-12-transparent-ca-trust-design.md`

---

### Task 1: Extract system CAs on macOS

**Files:**
- Create: `internal/proxy/cabundle_darwin.go`
- Create: `internal/proxy/cabundle_darwin_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/proxy/cabundle_darwin_test.go`:

```go
//go:build darwin

package proxy

import (
	"encoding/pem"
	"testing"
)

func TestSystemCAPEM_Darwin(t *testing.T) {
	data, err := systemCAPEM()
	if err != nil {
		t.Fatalf("systemCAPEM: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("systemCAPEM returned empty data")
	}

	// Verify at least one valid PEM CERTIFICATE block.
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block found in systemCAPEM output")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("first PEM block type = %q, want CERTIFICATE", block.Type)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestSystemCAPEM_Darwin -v`
Expected: FAIL — `systemCAPEM` undefined

- [ ] **Step 3: Write the implementation**

Create `internal/proxy/cabundle_darwin.go`:

```go
//go:build darwin

package proxy

import (
	"fmt"
	"os/exec"
)

// systemCAPEM extracts system root CA certificates as PEM from the macOS
// keychains. It exports from both the system roots keychain and the admin
// keychain.
func systemCAPEM() ([]byte, error) {
	keychains := []string{
		"/System/Library/Keychains/SystemRootCertificates.keychain",
		"/Library/Keychains/System.keychain",
	}

	var combined []byte
	for _, kc := range keychains {
		out, err := exec.Command("security", "export", "-t", "certs", "-p", "-k", kc).Output()
		if err != nil {
			// System.keychain may not exist or may be empty; skip it.
			continue
		}
		combined = append(combined, out...)
	}

	if len(combined) == 0 {
		return nil, fmt.Errorf("no system CA certificates found in any keychain")
	}
	return combined, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/ -run TestSystemCAPEM_Darwin -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/cabundle_darwin.go internal/proxy/cabundle_darwin_test.go
git commit -m "feat(proxy): extract system CAs on macOS via security export"
```

---

### Task 2: Extract system CAs on Linux

**Files:**
- Create: `internal/proxy/cabundle_linux.go`
- Create: `internal/proxy/cabundle_linux_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/proxy/cabundle_linux_test.go`:

```go
//go:build linux

package proxy

import (
	"encoding/pem"
	"testing"
)

func TestSystemCAPEM_Linux(t *testing.T) {
	data, err := systemCAPEM()
	if err != nil {
		t.Fatalf("systemCAPEM: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("systemCAPEM returned empty data")
	}

	// Verify at least one valid PEM CERTIFICATE block.
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block found in systemCAPEM output")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("first PEM block type = %q, want CERTIFICATE", block.Type)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestSystemCAPEM_Linux -v`
Expected: FAIL — `systemCAPEM` undefined

- [ ] **Step 3: Write the implementation**

Create `internal/proxy/cabundle_linux.go`:

```go
//go:build linux

package proxy

import (
	"fmt"
	"os"
)

// linuxCAPaths lists well-known CA bundle paths across Linux distributions.
var linuxCAPaths = []string{
	"/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Alpine
	"/etc/pki/tls/certs/ca-bundle.crt",   // RHEL, Fedora, CentOS
	"/etc/ssl/ca-bundle.pem",             // openSUSE
}

// systemCAPEM reads the system CA certificate bundle from the first
// well-known path that exists.
func systemCAPEM() ([]byte, error) {
	for _, path := range linuxCAPaths {
		data, err := os.ReadFile(path)
		if err == nil && len(data) > 0 {
			return data, nil
		}
	}
	return nil, fmt.Errorf("no system CA bundle found (tried: %v)", linuxCAPaths)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/ -run TestSystemCAPEM_Linux -v`
Expected: PASS (on Linux). On macOS this test is skipped by build tag.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/cabundle_linux.go internal/proxy/cabundle_linux_test.go
git commit -m "feat(proxy): extract system CAs on Linux from well-known paths"
```

---

### Task 3: Build combined CA bundle

**Files:**
- Create: `internal/proxy/cabundle.go`
- Create: `internal/proxy/cabundle_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/proxy/cabundle_test.go`:

```go
package proxy

import (
	"bytes"
	"encoding/pem"
	"os"
	"testing"
)

func TestBuildCABundle(t *testing.T) {
	// Generate a CA to get realistic PEM bytes.
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	bundlePath, err := BuildCABundle(ca.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundle: %v", err)
	}
	defer os.Remove(bundlePath)

	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}

	// Bundle must contain the Veil CA.
	if !bytes.Contains(data, ca.CertPEM) {
		t.Error("bundle does not contain Veil CA PEM")
	}

	// Bundle must contain at least one other certificate (system CAs).
	// Count all CERTIFICATE blocks.
	rest := data
	count := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			count++
		}
	}
	if count < 2 {
		t.Fatalf("bundle has %d certificates, want at least 2 (system + veil)", count)
	}
}

func TestBuildCABundle_Cleanup(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	bundlePath, err := BuildCABundle(ca.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundle: %v", err)
	}

	// File should exist.
	if _, err := os.Stat(bundlePath); err != nil {
		t.Fatalf("bundle file does not exist: %v", err)
	}

	// Clean up and verify.
	RemoveCABundle(bundlePath)
	if _, err := os.Stat(bundlePath); !os.IsNotExist(err) {
		t.Fatalf("bundle file still exists after RemoveCABundle")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestBuildCABundle -v`
Expected: FAIL — `BuildCABundle` and `RemoveCABundle` undefined

- [ ] **Step 3: Write the implementation**

Create `internal/proxy/cabundle.go`:

```go
package proxy

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/8enji/veil/internal/config"
)

// BuildCABundle creates a combined PEM file containing the system CA
// certificates plus the provided Veil CA PEM. Returns the path to the
// bundle file. Call RemoveCABundle to clean up.
func BuildCABundle(veilCAPEM []byte) (string, error) {
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

	bundlePath, err := bundleFilePath()
	if err != nil {
		return "", fmt.Errorf("bundle file path: %w", err)
	}

	if err := config.EnsureDir(filepath.Dir(bundlePath), 0700); err != nil {
		return "", fmt.Errorf("ensure bundle dir: %w", err)
	}

	if err := atomicWrite(bundlePath, combined, 0644); err != nil {
		return "", fmt.Errorf("write ca bundle: %w", err)
	}

	return bundlePath, nil
}

// RemoveCABundle deletes the combined CA bundle file.
func RemoveCABundle(path string) {
	_ = os.Remove(path)
}

// bundleFilePath returns the path for the combined CA bundle, stored
// alongside the Veil CA files.
func bundleFilePath() (string, error) {
	dir, err := config.CADir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ca-bundle.pem"), nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/ -run TestBuildCABundle -v`
Expected: PASS (both `TestBuildCABundle` and `TestBuildCABundle_Cleanup`)

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/cabundle.go internal/proxy/cabundle_test.go
git commit -m "feat(proxy): build combined CA bundle with system + Veil CAs"
```

---

### Task 4: Expand env var injection in runner

**Files:**
- Modify: `internal/runner/runner.go:33-36` (proxyEnvKeys, isProxyEnvKey)
- Modify: `internal/runner/runner.go:134-157` (buildChildEnv)
- Modify: `internal/runner/runner_test.go:139-186` (TestBuildChildEnv)

- [ ] **Step 1: Update the test**

In `internal/runner/runner_test.go`, update `TestBuildChildEnv` to verify the new CA env vars are set and pre-existing ones are stripped. Replace the existing `TestBuildChildEnv` function:

```go
func TestBuildChildEnv(t *testing.T) {
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
	}

	result := buildChildEnv(base, "http://127.0.0.1:9999", "/tmp/fake-bundle.pem")

	env := make(map[string]string)
	for _, kv := range result {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}

	// Verify old proxy vars are stripped.
	for _, kv := range result {
		if strings.Contains(kv, "old-proxy") || strings.Contains(kv, "old-no-proxy") {
			t.Fatalf("old proxy var not stripped: %s", kv)
		}
	}

	// Verify old CA vars are stripped.
	for _, kv := range result {
		if strings.Contains(kv, "/old/") {
			t.Fatalf("old CA var not stripped: %s", kv)
		}
	}

	// Verify new proxy vars are present.
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if env[key] != "http://127.0.0.1:9999" {
			t.Fatalf("%s = %q, want %q", key, env[key], "http://127.0.0.1:9999")
		}
	}
	for _, key := range []string{"NO_PROXY", "no_proxy"} {
		if env[key] != "localhost,127.0.0.1,::1" {
			t.Fatalf("%s = %q, want %q", key, env[key], "localhost,127.0.0.1,::1")
		}
	}

	// Verify CA env vars all point to the bundle.
	caVars := []string{
		"NODE_EXTRA_CA_CERTS",
		"SSL_CERT_FILE",
		"CURL_CA_BUNDLE",
		"REQUESTS_CA_BUNDLE",
		"HTTPLIB2_CA_CERTS",
	}
	for _, key := range caVars {
		if env[key] != "/tmp/fake-bundle.pem" {
			t.Fatalf("%s = %q, want %q", key, env[key], "/tmp/fake-bundle.pem")
		}
	}

	// Verify non-proxy vars are preserved.
	if env["PATH"] != "/usr/bin" {
		t.Fatalf("PATH = %q, want /usr/bin", env["PATH"])
	}
	if env["OTHER_VAR"] != "keep-me" {
		t.Fatalf("OTHER_VAR = %q, want keep-me", env["OTHER_VAR"])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/runner/ -run TestBuildChildEnv -v`
Expected: FAIL — old CA vars not stripped, new CA vars missing

- [ ] **Step 3: Update the implementation**

In `internal/runner/runner.go`, make three changes:

**a)** Add `caEnvKeys` list and `isCAEnvKey()` below the existing `proxyEnvKeys`/`isProxyEnvKey`:

```go
// caEnvKeys lists environment variable names that configure CA certificate
// bundles across runtimes. These are stripped and replaced with Veil's
// combined bundle.
var caEnvKeys = []string{
	"NODE_EXTRA_CA_CERTS",
	"SSL_CERT_FILE",
	"CURL_CA_BUNDLE",
	"REQUESTS_CA_BUNDLE",
	"HTTPLIB2_CA_CERTS",
}

// isCAEnvKey returns true if the given key is a CA-related environment
// variable that should be stripped and replaced.
func isCAEnvKey(key string) bool {
	for _, k := range caEnvKeys {
		if strings.EqualFold(key, k) {
			return true
		}
	}
	return false
}
```

**b)** Update `buildChildEnv` to accept `bundlePath` instead of `caCertPath`, strip CA env vars, and inject all CA vars. Change the signature from:

```go
func buildChildEnv(environ []string, proxyURL, caCertPath string) []string {
```

to:

```go
func buildChildEnv(environ []string, proxyURL, bundlePath string) []string {
```

Update the stripping logic to also strip CA env vars:

```go
		if isProxyEnvKey(key) || isCAEnvKey(key) {
			continue
		}
```

Update the appended vars at the end:

```go
	return append(stripped,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
		"NO_PROXY=localhost,127.0.0.1,::1",
		"no_proxy=localhost,127.0.0.1,::1",
		"NODE_EXTRA_CA_CERTS="+bundlePath,
		"SSL_CERT_FILE="+bundlePath,
		"CURL_CA_BUNDLE="+bundlePath,
		"REQUESTS_CA_BUNDLE="+bundlePath,
		"HTTPLIB2_CA_CERTS="+bundlePath,
	)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/runner/ -run TestBuildChildEnv -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/runner/runner.go internal/runner/runner_test.go
git commit -m "feat(runner): inject CA bundle env vars for all major runtimes"
```

---

### Task 5: Wire bundle into runner lifecycle

**Files:**
- Modify: `internal/runner/runner.go:40-130` (Run function)

- [ ] **Step 1: Write the failing test**

Add a new test in `internal/runner/runner_test.go` that verifies the child process receives the CA bundle env vars:

```go
func TestRunChildCAEnvVars(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	root, ks := setupProject(t)
	outFile := filepath.Join(t.TempDir(), "ca-env-out.txt")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := Run(ctx, Config{
		Root:     root,
		Command:  "sh",
		Args:     []string{"-c", "printenv SSL_CERT_FILE > " + outFile},
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
	if !strings.HasSuffix(got, "ca-bundle.pem") {
		t.Fatalf("SSL_CERT_FILE = %q, want suffix ca-bundle.pem", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/runner/ -run TestRunChildCAEnvVars -v`
Expected: FAIL — `SSL_CERT_FILE` not set or points to wrong file

- [ ] **Step 3: Update Run() to build and clean up the bundle**

In `internal/runner/runner.go`, modify the `Run` function. After loading the CA (step 3) and before starting the proxy (step 5), add the bundle build. Replace the `caCertPath` resolution (lines 69-73) and trust preflight (lines 76-79) with:

```go
	// 3b. Build combined CA bundle (system CAs + Veil CA).
	bundlePath, err := proxy.BuildCABundle(ca.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("build ca bundle: %w", err)
	}
	defer proxy.RemoveCABundle(bundlePath)
```

Update the `buildChildEnv` call (line 94) to pass `bundlePath` instead of `caCertPath`:

```go
	env := buildChildEnv(os.Environ(), proxyURL, bundlePath)
```

Remove the import of `"github.com/8enji/veil/internal/config"` only if it is no longer used elsewhere in the file. (It is still used for `config.KeystoreFallbackFile()` and `config.AuditDBFile()`, so keep it.)

Remove the `caCertPath` variable and `config.CAFile()` call that was on lines 69-73 — no longer needed.

Remove the trust preflight check on lines 76-79 (the `IsTrusted` check and warning).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/runner/ -v`
Expected: All tests PASS, including `TestRunChildCAEnvVars`

- [ ] **Step 5: Commit**

```bash
git add internal/runner/runner.go internal/runner/runner_test.go
git commit -m "feat(runner): build CA bundle at startup, clean up on exit"
```

---

### Task 6: Remove `veil trust` command and trust code

**Files:**
- Delete: `internal/cli/trust.go`
- Delete: `internal/proxy/trust.go`
- Delete: `internal/proxy/trust_test.go`
- Modify: `internal/cli/root.go:32` (remove trustCmd registration)
- Modify: `internal/cli/init.go:208` (remove "Run 'veil trust'" message)
- Modify: `internal/cli/status.go:50-53` (remove IsTrusted check)
- Modify: `go.mod` (remove smallstep/truststore)

- [ ] **Step 1: Remove trustCmd from root**

In `internal/cli/root.go`, delete line 32:

```go
	root.AddCommand(trustCmd())
```

- [ ] **Step 2: Remove "veil trust" message from init**

In `internal/cli/init.go`, delete line 208:

```go
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Run 'veil trust' to install the CA into your system trust store.")
```

- [ ] **Step 3: Remove IsTrusted from status**

In `internal/cli/status.go`, replace lines 46-54:

```go
	caStatus := caFile
	ca, caErr := proxy.LoadOrCreateCA()
	if caErr != nil {
		caStatus += " (error: " + caErr.Error() + ")"
	} else if proxy.IsTrusted(ca) {
		caStatus += " (trusted)"
	} else {
		caStatus += " (NOT trusted)"
	}
```

with:

```go
	caStatus := caFile
	if _, caErr := proxy.LoadOrCreateCA(); caErr != nil {
		caStatus += " (error: " + caErr.Error() + ")"
	}
```

Also remove `"github.com/8enji/veil/internal/proxy"` from the imports in `status.go` if no longer used. (Check: `proxy.LoadOrCreateCA()` is still called, so keep the import.)

- [ ] **Step 4: Delete trust files**

```bash
rm internal/cli/trust.go
rm internal/proxy/trust.go
rm internal/proxy/trust_test.go
```

- [ ] **Step 5: Remove truststore dependency**

```bash
go mod tidy
```

This removes `github.com/smallstep/truststore` and any indirect deps only it required.

- [ ] **Step 6: Verify everything compiles and tests pass**

Run: `go build ./... && go test ./...`
Expected: Build succeeds. All tests pass. No references to `trustCmd`, `IsTrusted`, `InstallCA`, `UninstallCA`, or `truststore`.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor: remove veil trust command and system trust store dependency"
```

---

### Task 7: End-to-end verification

**Files:** None (manual testing)

- [ ] **Step 1: Build the binary**

```bash
go build -o veil ./cmd/veil
```

- [ ] **Step 2: Verify `veil trust` is gone**

```bash
./veil trust
```

Expected: `unknown command "trust"` error

- [ ] **Step 3: Verify `veil run` sets CA env vars**

```bash
./veil run sh -c 'echo "SSL_CERT_FILE=$SSL_CERT_FILE"; echo "CURL_CA_BUNDLE=$CURL_CA_BUNDLE"; echo "REQUESTS_CA_BUNDLE=$REQUESTS_CA_BUNDLE"; echo "NODE_EXTRA_CA_CERTS=$NODE_EXTRA_CA_CERTS"'
```

Expected: All four vars point to a path ending in `ca-bundle.pem`

- [ ] **Step 4: Verify bundle contains system CAs + Veil CA**

```bash
./veil run sh -c 'grep -c "BEGIN CERTIFICATE" "$SSL_CERT_FILE"'
```

Expected: A number significantly greater than 1 (typically 100+)

- [ ] **Step 5: Verify bundle is cleaned up after exit**

After the `veil run` from step 3 exits, check the bundle path printed in step 3:

```bash
ls ~/Library/Application\ Support/veil/ca/ca-bundle.pem
```

Expected: `No such file or directory`

- [ ] **Step 6: Run full test suite**

```bash
go test ./... -v
```

Expected: All tests pass
