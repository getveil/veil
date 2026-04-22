# Shell Environment Secret Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the residual gap in SEC-1 where shell-exported secrets (e.g., `OPENAI_API_KEY` in `~/.zshrc`) that never appear in a `.env` file pass through to the agent because `veil init` does not scan `os.Environ()`.

**Architecture:** Three layered changes. (A) `buildChildEnv` re-injects the vault placeholder when stripping a shell-exported var so a shell-only credential still reaches the child as a placeholder. (B) A new `scanner.ScanEnviron` surfaces secret-like shell env vars; `veil init` prompts the user to vault them. (C) At `veil run` startup, a pre-exec scan warns (interactive) or fail-closes (non-interactive) when shell env still contains secret-like unvaulted values; `--allow-env-secret NAME` escape hatch for false positives.

**Tech Stack:** Go, cobra CLI, existing `placeholder.IsSecretLike`, existing `vault.Vault` API.

**Explicit non-goals (YAGNI):**
- No allowlist-style env filtering (option 3 from the design discussion). Heuristic defense only.
- No tightening of `IsSecretLike` (tracked separately as audit finding #10).
- No GUI / alternate keystore changes. Existing vault plumbing reused as-is.
- No new config surface. `--allow-env-secret` is CLI-only; no persistent config field.

---

## File Structure

**Create:**
- `internal/scanner/environ.go` — `ScanEnviron` + obvious-noise denylist
- `internal/scanner/environ_test.go` — unit tests for `ScanEnviron`
- `internal/cli/init_shellenv.go` — `processShellEnv` helper (mirrors `processEnvFile`)
- `internal/cli/init_shellenv_test.go` — unit tests for shell-env init flow
- `internal/runner/envscan.go` — `scanUnvaultedSecretLikes` runtime scan + warning/fail-closed logic
- `internal/runner/envscan_test.go` — unit tests for runtime scan

**Modify:**
- `internal/runner/runner.go` — `buildChildEnv` signature + re-inject placeholder; call runtime scan before `child.Start()`
- `internal/runner/runner_test.go` — update existing `buildChildEnv` tests for new signature; add re-injection cases
- `internal/cli/init.go` — call `processShellEnv` after MCP scanning
- `internal/cli/run.go` — add `--allow-env-secret` flag; plumb into `runner.Config`
- `docs/superpowers/findings/2026-04-22-codebase-audit.md` — mark SEC-1 mitigated; document residual risk

---

## Task 1: `buildChildEnv` re-injects vault placeholder for stripped shell exports

**Rationale:** Currently, if a vault credential's name matches a shell-exported env var, `buildChildEnv` strips the name entirely. This is correct when the placeholder arrives via a rewritten `.env` file that the agent loads itself, but for credentials that live *only* in the shell (the case we're about to enable in Task 3), the child would have no value under that name at all. Re-injecting the placeholder makes the behavior uniform.

**Files:**
- Modify: `internal/runner/runner.go:212-258`
- Modify: `internal/runner/runner.go:127` (caller site)
- Modify: `internal/runner/runner_test.go:355-570` (existing `TestBuildChildEnv*` suite)

- [ ] **Step 1: Write a new failing test for placeholder re-injection**

Add to `internal/runner/runner_test.go`:

```go
// TestBuildChildEnv_ReinjectsPlaceholderForStrippedVar verifies that when a
// shell-exported env var's name matches a vault credential, the real value
// is stripped AND the credential's placeholder is re-injected under the same
// name so the child still has a value (the placeholder) to send upstream.
func TestBuildChildEnv_ReinjectsPlaceholderForStrippedVar(t *testing.T) {
	base := []string{
		"HOME=/home/user",
		"OPENAI_API_KEY=sk-real-secret-value-1234567890",
	}
	vaultEntries := []VaultEntry{
		{Name: "OPENAI_API_KEY", Placeholder: "VEIL_OPENAI_API_KEY_XYZ"},
	}

	env, stripped := buildChildEnv(base, "http://127.0.0.1:8080", "/tmp/bundle.pem", nil, vaultEntries)

	if len(stripped) != 1 || stripped[0] != "OPENAI_API_KEY" {
		t.Fatalf("stripped = %v, want [OPENAI_API_KEY]", stripped)
	}
	// Real value must NOT appear.
	for _, kv := range env {
		if strings.Contains(kv, "sk-real-secret-value-1234567890") {
			t.Fatalf("real secret leaked into env: %q", kv)
		}
	}
	// Placeholder MUST appear, keyed by the original var name.
	want := "OPENAI_API_KEY=VEIL_OPENAI_API_KEY_XYZ"
	found := false
	for _, kv := range env {
		if kv == want {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("env missing re-injected placeholder %q; env=%v", want, env)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/runner/ -run TestBuildChildEnv_ReinjectsPlaceholderForStrippedVar -v`
Expected: FAIL with compile error (`VaultEntry` undefined) or assertion mismatch.

- [ ] **Step 3: Introduce `VaultEntry` type and update `buildChildEnv` signature**

In `internal/runner/runner.go`, replace the existing `buildChildEnv` (lines 203-258) with:

```go
// VaultEntry is the minimum subset of a vault credential that buildChildEnv
// needs: the env var name that may be shell-exported, and the placeholder to
// substitute in its place so the child still has a value (the placeholder)
// associated with that name.
type VaultEntry struct {
	Name        string
	Placeholder string
}

// buildChildEnv takes the current env, strips proxy-related, CA-related, and
// vault-managed credential vars, and adds the proxy vars pointing to proxyURL
// and CA vars pointing to bundlePath. skipHosts are appended to the default
// NO_PROXY list. vaultEntries is the set of credentials loaded from the vault;
// any env var whose key matches (case-insensitively) has its real value
// stripped and replaced with the credential's placeholder, so the child
// process cannot observe the real secret that the user exported in their
// shell. The names of env vars actually stripped because of the vault match
// are returned (using the original casing from the environment), so the
// caller can surface a startup warning.
func buildChildEnv(environ []string, proxyURL, bundlePath string, skipHosts []string, vaultEntries []VaultEntry) ([]string, []string) {
	vaultMap := make(map[string]string, len(vaultEntries))
	for _, e := range vaultEntries {
		if e.Name == "" {
			continue
		}
		vaultMap[strings.ToUpper(e.Name)] = e.Placeholder
	}

	stripped := make([]string, 0, len(environ))
	strippedVault := make([]string, 0)
	reinject := make([]string, 0)
	for _, kv := range environ {
		key, _, ok := strings.Cut(kv, "=")
		if !ok {
			stripped = append(stripped, kv)
			continue
		}
		if isProxyEnvKey(key) || isCAEnvKey(key) {
			continue
		}
		if ph, hit := vaultMap[strings.ToUpper(key)]; hit {
			strippedVault = append(strippedVault, key)
			reinject = append(reinject, key+"="+ph)
			continue
		}
		stripped = append(stripped, kv)
	}

	noProxy := "localhost,127.0.0.1,::1"
	if len(skipHosts) > 0 {
		noProxy = noProxy + "," + strings.Join(skipHosts, ",")
	}

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
	)
	env = append(env, reinject...)
	return env, strippedVault
}
```

- [ ] **Step 4: Update the caller site at `runner.go:127`**

Replace:

```go
env, strippedVault := buildChildEnv(os.Environ(), proxyURL, bundlePath, cfg.SkipHosts, vlt.Names())
```

with:

```go
entries := make([]VaultEntry, 0, len(vlt.List()))
for _, c := range vlt.List() {
	entries = append(entries, VaultEntry{Name: c.Name, Placeholder: c.Placeholder})
}
env, strippedVault := buildChildEnv(os.Environ(), proxyURL, bundlePath, cfg.SkipHosts, entries)
```

- [ ] **Step 5: Update existing `buildChildEnv` tests to pass `VaultEntry` slices**

In `internal/runner/runner_test.go`, update every call to `buildChildEnv` to pass a `[]VaultEntry` instead of `[]string`:

- Line 371 (`TestBuildChildEnv`):

```go
result, _ := buildChildEnv(base, "http://127.0.0.1:9999", "/tmp/fake-bundle.pem", nil, nil)
```

No change needed — `nil` still works. But the variadic name is now `vaultEntries`; if the test uses a named argument, update it.

- Line 429 (`TestBuildChildEnv_MergesSkipHosts`):

```go
env, _ := buildChildEnv([]string{"HOME=/home/user"}, "http://127.0.0.1:8080", "/tmp/bundle.pem", []string{"staging.internal.com", "*.metrics.corp"}, nil)
```

No change needed.

- Line 454 (`TestBuildChildEnv_EmptySkipHosts`): no change.

- Line 481 (`TestBuildChildEnv_StripsVaultNamedEnvVar`): replace

```go
env, stripped := buildChildEnv(base, "http://127.0.0.1:8080", "/tmp/bundle.pem", nil, []string{"OPENAI_API_KEY", "AWS_ACCESS_KEY_ID"})
```

with:

```go
env, stripped := buildChildEnv(base, "http://127.0.0.1:8080", "/tmp/bundle.pem", nil, []VaultEntry{
	{Name: "OPENAI_API_KEY", Placeholder: "VEIL_OPENAI_KEY_AAA"},
	{Name: "AWS_ACCESS_KEY_ID", Placeholder: "VEIL_AWS_BBB"},
})
```

Add an assertion to this test that the placeholder is present for each stripped name (extend the existing test body):

```go
// New assertion: each stripped name must be re-injected with its placeholder.
for _, want := range []string{"OPENAI_API_KEY=VEIL_OPENAI_KEY_AAA", "AWS_ACCESS_KEY_ID=VEIL_AWS_BBB"} {
	found := false
	for _, kv := range env {
		if kv == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("env missing placeholder re-injection %q", want)
	}
}
```

- Line 513 (`TestBuildChildEnv_PassesThroughNonMatchingVar`): replace

```go
env, stripped := buildChildEnv(base, "http://127.0.0.1:8080", "/tmp/bundle.pem", nil, []string{"OPENAI_API_KEY"})
```

with:

```go
env, stripped := buildChildEnv(base, "http://127.0.0.1:8080", "/tmp/bundle.pem", nil, []VaultEntry{
	{Name: "OPENAI_API_KEY", Placeholder: "VEIL_OPENAI_KEY_AAA"},
})
```

- Line 535 (`TestBuildChildEnv_StripVaultNameCaseInsensitive`): replace

```go
env, stripped := buildChildEnv(base, "http://127.0.0.1:8080", "/tmp/bundle.pem", nil, []string{"openai_api_key"})
```

with:

```go
env, stripped := buildChildEnv(base, "http://127.0.0.1:8080", "/tmp/bundle.pem", nil, []VaultEntry{
	{Name: "openai_api_key", Placeholder: "VEIL_OPENAI_KEY_AAA"},
})
```

- [ ] **Step 6: Run the full runner test suite**

Run: `go test ./internal/runner/ -v`
Expected: all tests PASS, including the new `TestBuildChildEnv_ReinjectsPlaceholderForStrippedVar`.

- [ ] **Step 7: Commit**

```bash
git add internal/runner/runner.go internal/runner/runner_test.go
git commit -m "$(cat <<'EOF'
refactor(runner): reinject vault placeholder for stripped shell exports

buildChildEnv now accepts []VaultEntry (name+placeholder) instead of
[]string. When a shell-exported env var matches a vault credential, the
real value is stripped and replaced with the placeholder under the same
name, so shell-only credentials still reach the child as placeholders.
EOF
)"
```

---

## Task 2: `scanner.ScanEnviron` with obvious-noise denylist

**Rationale:** `veil init` must be able to inspect `os.Environ()` for likely secrets without producing a prompt drowning in noise (`PATH`, `HOME`, `TERM`, etc.). A denylist of common non-secret env vars is applied before `placeholder.IsSecretLike`.

**Files:**
- Create: `internal/scanner/environ.go`
- Create: `internal/scanner/environ_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/scanner/environ_test.go`:

```go
package scanner

import (
	"testing"
)

func TestScanEnviron_DetectsSecretLike(t *testing.T) {
	environ := []string{
		"HOME=/home/user",
		"PATH=/usr/bin:/bin",
		"OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrst",
		"EDITOR=vim",
	}

	got := ScanEnviron(environ)

	if len(got) != 1 {
		t.Fatalf("ScanEnviron returned %d candidates, want 1: %+v", len(got), got)
	}
	if got[0].Name != "OPENAI_API_KEY" {
		t.Errorf("Name = %q, want OPENAI_API_KEY", got[0].Name)
	}
	if got[0].Value != "sk-proj-abcdefghijklmnopqrst" {
		t.Errorf("Value = %q, want full secret value", got[0].Value)
	}
}

func TestScanEnviron_SkipsDenylistedNames(t *testing.T) {
	// Names on the denylist are skipped even if their values look secret-like.
	environ := []string{
		// High-entropy paths and IDs that would otherwise trip IsSecretLike.
		"PATH=/usr/local/opt/rust/bin:/Users/x/.cargo/bin:/Users/x/.rbenv/shims",
		"HOMEBREW_PREFIX=/opt/homebrew",
		"TERM_PROGRAM_VERSION=444.1.2",
		"XDG_RUNTIME_DIR=/run/user/1000/abc123def456",
	}

	got := ScanEnviron(environ)

	if len(got) != 0 {
		t.Fatalf("ScanEnviron returned %d candidates for denylisted names, want 0: %+v", len(got), got)
	}
}

func TestScanEnviron_SkipsNonSecretLike(t *testing.T) {
	environ := []string{
		"FOO=bar",
		"COUNT=42",
		"ENABLED=true",
	}

	got := ScanEnviron(environ)

	if len(got) != 0 {
		t.Fatalf("ScanEnviron returned %d candidates for non-secret values, want 0: %+v", len(got), got)
	}
}

func TestScanEnviron_DeduplicatesByName(t *testing.T) {
	// If the same name appears twice (last assignment wins in real shells,
	// but os.Environ() returns the last-set value once; defensively handle dupes).
	environ := []string{
		"API_TOKEN=first-high-entropy-zzzzzzzzzzz",
		"API_TOKEN=second-high-entropy-yyyyyyyyyy",
	}

	got := ScanEnviron(environ)

	if len(got) != 1 {
		t.Fatalf("ScanEnviron returned %d candidates for duplicate name, want 1: %+v", len(got), got)
	}
	if got[0].Value != "second-high-entropy-yyyyyyyyyy" {
		t.Errorf("Value = %q, want last-wins value", got[0].Value)
	}
}

func TestScanEnviron_SkipsMalformedEntries(t *testing.T) {
	environ := []string{
		"NO_EQUALS_SIGN",
		"=VALUE_WITH_EMPTY_NAME",
		"OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrst",
	}

	got := ScanEnviron(environ)

	if len(got) != 1 || got[0].Name != "OPENAI_API_KEY" {
		t.Fatalf("ScanEnviron = %+v, want only OPENAI_API_KEY", got)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/scanner/ -run TestScanEnviron -v`
Expected: FAIL with "ScanEnviron undefined" compile error.

- [ ] **Step 3: Implement `ScanEnviron`**

Create `internal/scanner/environ.go`:

```go
package scanner

import (
	"strings"

	"github.com/8enji/veil/internal/placeholder"
)

// EnvironCandidate is a shell-exported env var that looked secret-like.
type EnvironCandidate struct {
	Name  string
	Value string
}

// environDenylist is a set of env var names we consider *obviously* non-secret
// and therefore skip before running the secret-like heuristic. The goal is to
// reduce prompt noise during `veil init` shell-env capture; it is NOT a
// security boundary — any name not on this list is still evaluated by
// placeholder.IsSecretLike.
//
// Rules for additions:
//   - The name is ubiquitous in POSIX / common shells.
//   - Its value has no plausible reason to be a credential.
//   - Omission would produce confusing / noisy prompts.
//
// When in doubt, leave it off. False positives in the prompt are annoying but
// correctable by the user; false negatives here risk silently exempting a
// real secret from capture, which is the exact gap this feature closes.
var environDenylist = map[string]struct{}{
	// Identity / shell
	"HOME": {}, "USER": {}, "LOGNAME": {}, "SHELL": {}, "UID": {}, "EUID": {},
	// Paths
	"PATH": {}, "MANPATH": {}, "INFOPATH": {}, "LD_LIBRARY_PATH": {},
	"DYLD_LIBRARY_PATH": {}, "DYLD_FALLBACK_LIBRARY_PATH": {},
	// Working dir / temp
	"PWD": {}, "OLDPWD": {}, "TMPDIR": {}, "TMP": {}, "TEMP": {},
	// Locale
	"LANG": {}, "LC_ALL": {}, "LC_CTYPE": {}, "LC_MESSAGES": {},
	"LC_NUMERIC": {}, "LC_TIME": {}, "LC_COLLATE": {}, "LC_MONETARY": {},
	// Terminal
	"TERM": {}, "COLORTERM": {}, "TERM_PROGRAM": {}, "TERM_PROGRAM_VERSION": {},
	"TERM_SESSION_ID": {}, "ITERM_PROFILE": {}, "ITERM_SESSION_ID": {},
	// Display (desktop)
	"DISPLAY": {}, "WAYLAND_DISPLAY": {}, "XDG_RUNTIME_DIR": {},
	"XDG_SESSION_TYPE": {}, "XDG_SESSION_DESKTOP": {}, "XDG_CURRENT_DESKTOP": {},
	"XDG_CONFIG_HOME": {}, "XDG_DATA_HOME": {}, "XDG_CACHE_HOME": {},
	"DESKTOP_SESSION": {}, "GDMSESSION": {},
	// Editor / pager
	"EDITOR": {}, "VISUAL": {}, "PAGER": {}, "MANPAGER": {},
	// Language runtimes (paths/versions, not credentials)
	"GOPATH": {}, "GOROOT": {}, "GOCACHE": {}, "GOMODCACHE": {}, "GOBIN": {},
	"NODE_PATH": {}, "NVM_DIR": {}, "NVM_BIN": {}, "NVM_CD_FLAGS": {}, "NVM_INC": {},
	"PYENV_ROOT": {}, "PYENV_SHELL": {}, "PYENV_VERSION": {},
	"RBENV_ROOT": {}, "RBENV_SHELL": {}, "RBENV_VERSION": {},
	// Homebrew
	"HOMEBREW_PREFIX": {}, "HOMEBREW_CELLAR": {}, "HOMEBREW_REPOSITORY": {},
	"HOMEBREW_SHELLENV_PREFIX": {},
	// Veil's own env keys (see envkeys package)
	"VEIL_TEST_KEYSTORE": {}, "VEIL_MCP_CONFIG_PATH": {},
	// Proxy / CA vars — already handled by the runner, and would confuse the user.
	"HTTP_PROXY": {}, "HTTPS_PROXY": {}, "NO_PROXY": {},
	"NODE_EXTRA_CA_CERTS": {}, "SSL_CERT_FILE": {},
	"CURL_CA_BUNDLE": {}, "REQUESTS_CA_BUNDLE": {}, "HTTPLIB2_CA_CERTS": {},
	// Shell options
	"IFS": {}, "PS1": {}, "PS2": {}, "PROMPT_COMMAND": {}, "HISTFILE": {},
	"HISTSIZE": {}, "HISTFILESIZE": {}, "BASH_VERSION": {}, "ZSH_VERSION": {},
	"ZSH_NAME": {}, "SHLVL": {}, "_": {}, "OSTYPE": {}, "MACHTYPE": {},
	"HOSTTYPE": {}, "HOSTNAME": {},
	// SSH (paths/sockets, not credentials themselves)
	"SSH_AUTH_SOCK": {}, "SSH_AGENT_PID": {},
}

// ScanEnviron returns the shell-exported env vars that look secret-like.
// Names on environDenylist are skipped up-front as obvious non-secrets to
// avoid prompt noise. Remaining entries are evaluated by
// placeholder.IsSecretLike. If the same name appears more than once in
// environ, only the last occurrence is returned (matching the shell's
// "last assignment wins" semantics; os.Environ() normally yields unique
// names but we handle dupes defensively).
func ScanEnviron(environ []string) []EnvironCandidate {
	byName := make(map[string]string, len(environ))
	order := make([]string, 0, len(environ))
	for _, kv := range environ {
		key, value, ok := strings.Cut(kv, "=")
		if !ok || key == "" {
			continue
		}
		if _, deny := environDenylist[key]; deny {
			continue
		}
		if _, seen := byName[key]; !seen {
			order = append(order, key)
		}
		byName[key] = value
	}

	out := make([]EnvironCandidate, 0, len(order))
	for _, name := range order {
		value := byName[name]
		if !placeholder.IsSecretLike(name, value) {
			continue
		}
		out = append(out, EnvironCandidate{Name: name, Value: value})
	}
	return out
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/scanner/ -run TestScanEnviron -v`
Expected: all four subtests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/environ.go internal/scanner/environ_test.go
git commit -m "$(cat <<'EOF'
feat(scanner): add ScanEnviron for shell-env secret detection

Returns os.Environ() entries that look secret-like, filtered through a
denylist of obviously non-secret names (PATH, HOME, TERM, language
runtimes, etc.) to keep the init prompt focused on real candidates.
EOF
)"
```

---

## Task 3: Wire shell-env scan into `veil init`

**Rationale:** With `ScanEnviron` available, add a phase to `veil init` that presents detected shell-exported secrets, prompts the user (yes/no/select), and vaults the chosen entries. Skip any whose name is already in the vault (e.g., rerun after a `.env` capture).

**Files:**
- Create: `internal/cli/init_shellenv.go`
- Create: `internal/cli/init_shellenv_test.go`
- Modify: `internal/cli/init.go:99-167`

- [ ] **Step 1: Write a failing test for `processShellEnv`**

Create `internal/cli/init_shellenv_test.go`:

```go
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8enji/veil/internal/scanner"
	"github.com/8enji/veil/internal/vault"
)

func TestProcessShellEnv_VaultsSecrets(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	tmp := t.TempDir()

	ks, err := buildKeystore()
	if err != nil {
		t.Fatalf("buildKeystore: %v", err)
	}
	v, err := vault.CreateVault(tmp, vault.NewID(), ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	candidates := []scanner.EnvironCandidate{
		{Name: "OPENAI_API_KEY", Value: "sk-proj-abcdefghijklmnopqrst"},
	}
	var out bytes.Buffer

	// Non-interactive path: all candidates are vaulted.
	count, scoped, err := processShellEnv(&out, strings.NewReader(""), v, candidates, /*dryRun*/ false, /*interactive*/ false)
	if err != nil {
		t.Fatalf("processShellEnv: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
	_ = scoped // may be 0 or 1 depending on provider registry — not asserting

	if _, ok := v.Get("OPENAI_API_KEY"); !ok {
		t.Error("vault missing OPENAI_API_KEY after processShellEnv")
	}

	// Ensure the literal keeps TempDir from being unused.
	_ = filepath.Base(tmp)
}

func TestProcessShellEnv_SkipsNamesAlreadyInVault(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	tmp := t.TempDir()

	ks, err := buildKeystore()
	if err != nil {
		t.Fatalf("buildKeystore: %v", err)
	}
	v, err := vault.CreateVault(tmp, vault.NewID(), ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	// Pre-populate vault with OPENAI_API_KEY (simulating a prior .env capture).
	if err := v.Add(&vault.Credential{
		ID:          vault.NewID(),
		Name:        "OPENAI_API_KEY",
		Real:        "sk-from-env-file",
		Placeholder: "VEIL_XXX",
		Source:      "init",
	}); err != nil {
		t.Fatalf("v.Add: %v", err)
	}

	candidates := []scanner.EnvironCandidate{
		{Name: "OPENAI_API_KEY", Value: "sk-from-shell"},
		{Name: "NEW_TOKEN", Value: "tk-highentropy-1234567890xyzxyz"},
	}
	var out bytes.Buffer

	count, _, err := processShellEnv(&out, strings.NewReader(""), v, candidates, false, false)
	if err != nil {
		t.Fatalf("processShellEnv: %v", err)
	}
	// Only NEW_TOKEN should have been added (OPENAI_API_KEY was pre-existing).
	if count != 1 {
		t.Errorf("count = %d, want 1 (skip duplicate)", count)
	}
	// Original vault entry must be untouched (value unchanged).
	c, ok := v.Get("OPENAI_API_KEY")
	if !ok {
		t.Fatal("vault lost OPENAI_API_KEY")
	}
	if c.Real != "sk-from-env-file" {
		t.Errorf("OPENAI_API_KEY value changed: got %q, want sk-from-env-file", c.Real)
	}

	_ = filepath.Base(tmp)
}

func TestInit_CapturesShellEnvSecrets(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	// Simulate a user with OPENAI_API_KEY exported in their shell but no .env.
	t.Setenv("OPENAI_API_KEY", "sk-proj-shell-1234567890abcdef")

	tmp := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmp, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	// --yes = non-interactive; all detected secrets are vaulted by default.
	cmd.SetArgs([]string{"init", "--path", tmp, "--yes"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v\n%s", err, out.String())
	}

	// Open the vault and confirm OPENAI_API_KEY was captured from the shell.
	ks, err := buildKeystore()
	if err != nil {
		t.Fatalf("buildKeystore: %v", err)
	}
	v, err := vault.Open(tmp, ks)
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	c, ok := v.Get("OPENAI_API_KEY")
	if !ok {
		t.Fatalf("vault missing OPENAI_API_KEY; vault names = %v", v.Names())
	}
	if c.Real != "sk-proj-shell-1234567890abcdef" {
		t.Errorf("vaulted value = %q, want sk-proj-shell-1234567890abcdef", c.Real)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cli/ -run "TestProcessShellEnv|TestInit_CapturesShellEnvSecrets" -v`
Expected: FAIL with "processShellEnv undefined" compile error and/or the init test assertion failing because shell scanning isn't wired in yet.

- [ ] **Step 3: Implement `processShellEnv`**

Create `internal/cli/init_shellenv.go`:

```go
package cli

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/scanner"
	"github.com/8enji/veil/internal/ui"
	"github.com/8enji/veil/internal/vault"
)

// processShellEnv presents shell-exported secret-like candidates, prompts the
// user (interactive) or accepts-all (non-interactive), and vaults the
// selected entries. Candidates whose name already exists in the vault are
// skipped silently — typically because they were already captured from a .env
// or MCP config earlier in the same init run. Returns (vaulted, scoped).
//
// `interactive` mirrors the convention used by processEnvFile / processMCPConfig:
// when false, all candidates are vaulted (matching the --yes / non-TTY path).
func processShellEnv(w io.Writer, in io.Reader, v *vault.Vault, candidates []scanner.EnvironCandidate, dryRun, interactive bool) (int, int, error) {
	// Filter out anything already in the vault (prior phase captured it).
	filtered := make([]scanner.EnvironCandidate, 0, len(candidates))
	for _, c := range candidates {
		if _, exists := v.Get(c.Name); exists {
			continue
		}
		filtered = append(filtered, c)
	}
	if len(filtered) == 0 {
		return 0, 0, nil
	}

	selected := selectShellEnvKeys(in, w, filtered, interactive)
	if len(selected) == 0 {
		return 0, 0, nil
	}

	seen := v.PlaceholderSet()
	var vaulted, scoped int
	for _, c := range filtered {
		if !selected[c.Name] {
			continue
		}

		ph, err := placeholder.Generate(c.Name, c.Value, seen)
		if err != nil {
			return vaulted, scoped, wrapErr(fmt.Sprintf("generating placeholder for %s", c.Name), err)
		}

		credHosts := placeholder.HostsForCredential(c.Name, c.Value)
		cred := &vault.Credential{
			ID:           vault.NewID(),
			Name:         c.Name,
			Real:         c.Value,
			Placeholder:  ph,
			Source:       "init",
			AllowedHosts: credHosts,
			CreatedAt:    time.Now(),
		}
		if err := v.Add(cred); err != nil {
			if errors.Is(err, vault.ErrDuplicateCredential) {
				ui.Warnf(w, "duplicate key %q, skipping", c.Name)
				continue
			}
			return vaulted, scoped, wrapErr(fmt.Sprintf("vaulting %s", c.Name), err)
		}
		seen[ph] = struct{}{}

		vaulted++
		if len(credHosts) > 0 {
			scoped++
		}

		if dryRun {
			ui.Dimf(w, "  would vault: %s -> %s (from shell)", c.Name, ph)
		}
	}
	return vaulted, scoped, nil
}

// selectShellEnvKeys returns the set of candidate names the user chose to
// vault. In non-interactive mode all names are selected.
func selectShellEnvKeys(in io.Reader, w io.Writer, candidates []scanner.EnvironCandidate, interactive bool) map[string]bool {
	selected := make(map[string]bool, len(candidates))
	if !interactive {
		for _, c := range candidates {
			selected[c.Name] = true
		}
		return selected
	}

	_, _ = fmt.Fprintf(w, "\nDetected %d shell-exported %s:\n",
		len(candidates), plural(len(candidates), "secret", "secrets"))
	ui.Dim(w, "(these are in your current shell environment, not in any .env file)")
	names := make([]string, len(candidates))
	for i, c := range candidates {
		_, _ = fmt.Fprintf(w, "  %-32s %s\n", c.Name, ui.Muted.Sprint(redactValue(c.Value)))
		names[i] = c.Name
	}
	_, _ = fmt.Fprintln(w)
	switch promptYNS(in, w, "Vault all?") {
	case choiceYes:
		for _, c := range candidates {
			selected[c.Name] = true
		}
	case choiceNo:
		return nil
	case choiceSelect:
		for _, name := range promptMultiSelect(in, w, names) {
			selected[name] = true
		}
	}
	return selected
}
```

- [ ] **Step 4: Wire `processShellEnv` into `runInit`**

In `internal/cli/init.go`, modify the body of `runInit` (between the MCP processing at line 157 and the summary at line 159). Insert a new phase that calls `processShellEnv`:

Find (around line 99):

```go
ui.Phase(w, "Scanning project...")

envPaths, err := scanner.Scan(root)
```

And later (around line 146-157):

```go
mcpConfigsProcessed := 0
if mcpConfigPath != "" {
	n, s, err := processMCPConfig(cmd, in, v, mcpConfigPath, force, dryRun, interactive)
	if err != nil {
		return err
	}
	secretsVaulted += n
	secretsScoped += s
	if n > 0 {
		mcpConfigsProcessed = 1
	}
}
```

Add immediately after the MCP block and before the totals:

```go
// Scan shell environment for secret-like exports that never made it into
// a .env file. Closes SEC-1 residual gap: shell-exported secrets would
// otherwise never enter the vault and would pass through to the agent.
shellCandidates := scanner.ScanEnviron(os.Environ())
if len(shellCandidates) > 0 {
	ui.Phase(w, "Scanning shell environment...")
	n, s, err := processShellEnv(w, in, v, shellCandidates, dryRun, interactive)
	if err != nil {
		return err
	}
	secretsVaulted += n
	secretsScoped += s
	_, _ = fmt.Fprintln(w)
}
```

- [ ] **Step 5: Run tests**

Run: `go test ./internal/cli/ -run "TestProcessShellEnv|TestInit_CapturesShellEnvSecrets|TestInitHappyPath" -v`
Expected: all tests PASS.

- [ ] **Step 6: Run the full test suite for regressions**

Run: `go test ./...`
Expected: PASS. If any existing init test now picks up accidental shell-env noise (e.g., test runner env), it must be fixed with `t.Setenv` to clear offending vars, or by asserting on specific vault entries rather than total counts.

- [ ] **Step 7: Commit**

```bash
git add internal/cli/init.go internal/cli/init_shellenv.go internal/cli/init_shellenv_test.go
git commit -m "$(cat <<'EOF'
feat(cli): capture shell-exported secrets during veil init

init now runs ScanEnviron after .env and MCP scanning, prompts the user
for detected shell-exported secrets (yes/no/select), and vaults the
chosen entries. Names already present in the vault are skipped silently.
Closes the residual SEC-1 gap where shell-only secrets bypassed the vault.
EOF
)"
```

---

## Task 4: Runtime pre-exec scan + `--allow-env-secret` flag

**Rationale:** Even after `veil init` scans shell env, a user can add a new `export FOO_API_KEY=...` afterward, or run `veil run` in a fresh shell that init never saw. At `veil run` startup, scan `os.Environ()` for secret-like names that aren't in the vault; in interactive mode warn loudly; in non-interactive mode fail-closed unless the name is listed via `--allow-env-secret`.

**Files:**
- Create: `internal/runner/envscan.go`
- Create: `internal/runner/envscan_test.go`
- Modify: `internal/runner/runner.go` (add call before `child.Start()`)
- Modify: `internal/runner/runner.go` (`Config` struct: new `AllowEnvSecrets []string` field)
- Modify: `internal/cli/run.go` (new `--allow-env-secret` cobra flag)

- [ ] **Step 1: Write failing tests for the scan**

Create `internal/runner/envscan_test.go`:

```go
package runner

import (
	"bytes"
	"strings"
	"testing"
)

func TestScanUnvaultedSecretLikes_FindsUnvaulted(t *testing.T) {
	environ := []string{
		"HOME=/home/user",
		"OPENAI_API_KEY=sk-proj-notvaulted1234567890abc",
		"ANTHROPIC_API_KEY=sk-ant-alsonotvaultedxyz1234567",
	}
	vaultNames := []string{"GITHUB_TOKEN"}
	allow := map[string]struct{}{}

	got := scanUnvaultedSecretLikes(environ, vaultNames, allow)

	if len(got) != 2 {
		t.Fatalf("got %d names, want 2: %v", len(got), got)
	}
}

func TestScanUnvaultedSecretLikes_IgnoresVaultedNames(t *testing.T) {
	environ := []string{
		"OPENAI_API_KEY=sk-proj-realvalue1234567890abc",
	}
	vaultNames := []string{"OPENAI_API_KEY"}
	allow := map[string]struct{}{}

	got := scanUnvaultedSecretLikes(environ, vaultNames, allow)

	if len(got) != 0 {
		t.Fatalf("got %d names, want 0 (already in vault): %v", len(got), got)
	}
}

func TestScanUnvaultedSecretLikes_IgnoresAllowlisted(t *testing.T) {
	environ := []string{
		"MY_PRIVATE_JWT=eyJhbGciOiJIUzI1NiJ9.really-looks-like-a-secret.0123456789abcdef",
	}
	vaultNames := []string{}
	allow := map[string]struct{}{"MY_PRIVATE_JWT": {}}

	got := scanUnvaultedSecretLikes(environ, vaultNames, allow)

	if len(got) != 0 {
		t.Fatalf("got %d names, want 0 (allowlisted): %v", len(got), got)
	}
}

func TestScanUnvaultedSecretLikes_CaseInsensitiveVaultMatch(t *testing.T) {
	environ := []string{
		"openai_api_key=sk-proj-notvaulted1234567890abc",
	}
	vaultNames := []string{"OPENAI_API_KEY"}
	allow := map[string]struct{}{}

	got := scanUnvaultedSecretLikes(environ, vaultNames, allow)

	if len(got) != 0 {
		t.Fatalf("got %d names, want 0 (vault match is case-insensitive): %v", len(got), got)
	}
}

func TestPrintUnvaultedWarning_FormatsLoud(t *testing.T) {
	var buf bytes.Buffer
	printUnvaultedWarning(&buf, []string{"FOO_TOKEN", "BAR_SECRET"})
	out := buf.String()

	for _, want := range []string{"FOO_TOKEN", "BAR_SECRET", "--allow-env-secret"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning missing %q:\n%s", want, out)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/runner/ -run "TestScanUnvaultedSecretLikes|TestPrintUnvaultedWarning" -v`
Expected: FAIL with undefined-symbol compile errors.

- [ ] **Step 3: Implement the scan and formatter**

Create `internal/runner/envscan.go`:

```go
package runner

import (
	"fmt"
	"io"
	"strings"

	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/ui"
)

// scanUnvaultedSecretLikes returns the names of env vars in environ that look
// secret-like (per placeholder.IsSecretLike) but are not in the vault and
// not on the user-provided allow set. Name matching against the vault is
// case-insensitive (to match the child-env stripping semantics).
//
// Runs against os.Environ() at veil-run startup as a belt-and-suspenders
// check: init should have captured these already, but a user may have
// added a new export since init, or run veil in a shell that init never saw.
func scanUnvaultedSecretLikes(environ, vaultNames []string, allow map[string]struct{}) []string {
	vaulted := make(map[string]struct{}, len(vaultNames))
	for _, n := range vaultNames {
		if n == "" {
			continue
		}
		vaulted[strings.ToUpper(n)] = struct{}{}
	}

	out := make([]string, 0)
	for _, kv := range environ {
		key, value, ok := strings.Cut(kv, "=")
		if !ok || key == "" {
			continue
		}
		if _, v := vaulted[strings.ToUpper(key)]; v {
			continue
		}
		if _, a := allow[key]; a {
			continue
		}
		if !placeholder.IsSecretLike(key, value) {
			continue
		}
		out = append(out, key)
	}
	return out
}

// printUnvaultedWarning emits a loud stderr warning listing env vars whose
// values look secret-like but are not in the vault. Format mirrors
// printStrippedEnvWarning so users see parallel structure.
func printUnvaultedWarning(w io.Writer, names []string) {
	_, _ = fmt.Fprintf(w, "  %s %d shell env %s look like secrets but are NOT in the vault:\n",
		ui.Warning.Sprint("!"), len(names), plural(len(names), "var", "vars"))
	for _, n := range names {
		_, _ = fmt.Fprintf(w, "      %s\n", ui.Warning.Sprint(n))
	}
	_, _ = fmt.Fprintf(w, "    %s\n",
		ui.Muted.Sprint("the agent will see their real values. run `veil init --force` to capture them,"))
	_, _ = fmt.Fprintf(w, "    %s\n",
		ui.Muted.Sprint("or pass --allow-env-secret NAME (repeatable) to confirm pass-through."))
}

// plural is a local helper to avoid depending on the cli package.
func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return singular
	}
	return pluralForm
}
```

- [ ] **Step 4: Run envscan tests**

Run: `go test ./internal/runner/ -run "TestScanUnvaultedSecretLikes|TestPrintUnvaultedWarning" -v`
Expected: all PASS.

- [ ] **Step 5: Wire the scan into `Run`**

In `internal/runner/runner.go`:

Add a new field to `Config` (around line 23-30):

```go
type Config struct {
	Root             string         // project root
	Command          string         // child command
	Args             []string       // child args
	Verbose          bool           //nolint:unused // reserved for future use
	SkipHosts        []string       // hosts to exclude from proxying (added to NO_PROXY)
	Keystore         vault.Keystore // optional; nil means AutoKeystore
	AllowEnvSecrets  []string       // env var names to pass through even if secret-like and not in vault
}
```

Between the `printStrippedEnvWarning` block (line 128-130) and the exec-child block (line 134), add:

```go
// Belt-and-suspenders: scan for secret-like env vars that slipped past
// init (e.g., a new export since `veil init` ran). Warn interactively;
// fail-closed non-interactively unless --allow-env-secret covers them.
allowSet := make(map[string]struct{}, len(cfg.AllowEnvSecrets))
for _, n := range cfg.AllowEnvSecrets {
	allowSet[n] = struct{}{}
}
unvaulted := scanUnvaultedSecretLikes(os.Environ(), vlt.Names(), allowSet)
if len(unvaulted) > 0 {
	printUnvaultedWarning(os.Stderr, unvaulted)
	if !isStdinTTY() {
		return nil, fmt.Errorf("refusing to launch: %d shell env var(s) look like unvaulted secrets (%s); rerun with --allow-env-secret or veil init --force",
			len(unvaulted), strings.Join(unvaulted, ", "))
	}
}
```

Add a helper near the top of the file:

```go
// isStdinTTY reports whether os.Stdin is a terminal. A thin wrapper so tests
// can stub it via a package var if they ever need to; for now the wrapper
// simply checks stdinTTYFd, which returns -1 on non-TTY stdin.
func isStdinTTY() bool {
	return stdinTTYFd() >= 0
}
```

- [ ] **Step 6: Add `--allow-env-secret` flag in `veil run`**

Replace the entire `runCmd()` and `runRun()` in `internal/cli/run.go` with:

```go
func runCmd() *cobra.Command {
	var ephemeralSkip []string
	var allowEnvSecrets []string
	cmd := &cobra.Command{
		Use:   "run [flags] -- <command> [args...]",
		Short: "Run a command with secrets injected via proxy",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRun(cmd, args, ephemeralSkip, allowEnvSecrets)
		},
	}
	cmd.Flags().SetInterspersed(false)
	cmd.Flags().StringArrayVar(&ephemeralSkip, "skip", nil, "host to pass through without proxying (non-persistent, repeatable)")
	cmd.Flags().StringArrayVar(&allowEnvSecrets, "allow-env-secret", nil, "env var name to pass through even if it looks secret-like and is not in the vault (repeatable)")
	return cmd
}

func runRun(cmd *cobra.Command, args []string, ephemeralSkip, allowEnvSecrets []string) error {
	root, err := requireInitializedProject(cmd)
	if err != nil {
		return err
	}

	// Load persistent skip hosts.
	skipHosts, err := skiphost.Load(config.SkipHostsFile(root))
	if err != nil {
		return wrapErr("reading skip hosts", err)
	}

	// Merge ephemeral --skip flags.
	skipHosts = append(skipHosts, ephemeralSkip...)

	result, err := runner.Run(cmd.Context(), runner.Config{
		Root:            root,
		Command:         args[0],
		Args:            args[1:],
		Verbose:         flagVerbose,
		SkipHosts:       skipHosts,
		AllowEnvSecrets: allowEnvSecrets,
	})
	if err != nil {
		return cliError(mapRunError(err), "")
	}

	os.Exit(result.ExitCode)
	return nil // unreachable
}
```

The rest of the file (`mapRunError`, `MapRunErrorForTest`) is unchanged.

- [ ] **Step 7: Write an integration test for fail-closed non-interactive mode**

Add to `internal/runner/runner_test.go`:

```go
// TestRun_FailsClosedOnUnvaultedShellSecrets verifies that in non-interactive
// mode, a shell-exported secret-like env var that is not in the vault causes
// veil to refuse to launch the child. The product's single promise is that
// the agent never sees real tokens; silently passing an unvaulted secret
// through would violate it.
func TestRun_FailsClosedOnUnvaultedShellSecrets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	// Drive stdin from a non-TTY io.Pipe so isStdinTTY() returns false.
	// The simplest signal: runner.Run pulls from os.Stdin directly, which
	// in `go test` is already non-TTY. Set a secret-like env var we know
	// won't be in the empty vault.
	t.Setenv("FAKE_PROVIDER_API_KEY", "sk-fake-highentropy-1234567890abcdef")

	root, ks := testutil.SetupVaultProject(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := Run(ctx, Config{
		Root:     root,
		Command:  "echo",
		Args:     []string{"hello"},
		Keystore: ks,
	})
	if err == nil {
		t.Fatal("Run succeeded with unvaulted shell secret; expected fail-closed error")
	}
	if !strings.Contains(err.Error(), "FAKE_PROVIDER_API_KEY") {
		t.Errorf("err = %v, want message naming FAKE_PROVIDER_API_KEY", err)
	}
}

// TestRun_AllowEnvSecretBypass verifies that --allow-env-secret permits a
// secret-like shell export to pass through.
func TestRun_AllowEnvSecretBypass(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Setenv("FAKE_PROVIDER_API_KEY", "sk-fake-highentropy-1234567890abcdef")

	root, ks := testutil.SetupVaultProject(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := Run(ctx, Config{
		Root:            root,
		Command:         "echo",
		Args:            []string{"hello"},
		Keystore:        ks,
		AllowEnvSecrets: []string{"FAKE_PROVIDER_API_KEY"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}
}
```

- [ ] **Step 8: Run the full runner suite**

Run: `go test ./internal/runner/ -v`
Expected: all tests PASS, including the two new integration tests.

- [ ] **Step 9: Run the full test suite**

Run: `go test ./...`
Expected: PASS. If a test in another package now trips on a shell env picked up by the CI environment (e.g., `GITHUB_TOKEN` in GitHub Actions), address it by either adding `t.Setenv("GITHUB_TOKEN", "")` in that test, by passing `AllowEnvSecrets`, or by expanding `environDenylist` if the var is actually non-secret (be conservative here — default should be to vault/allow).

- [ ] **Step 10: Commit**

```bash
git add internal/runner/envscan.go internal/runner/envscan_test.go internal/runner/runner.go internal/runner/runner_test.go internal/cli/run.go
git commit -m "$(cat <<'EOF'
feat(runner): fail-closed on unvaulted shell secrets at run time

veil run now scans os.Environ() for secret-like names not in the vault
before launching the child. Interactive stderr warning; non-interactive
refuses to launch. --allow-env-secret NAME (repeatable) bypasses the
check per-invocation. Closes the residual SEC-1 gap for secrets added
to the shell after veil init ran.
EOF
)"
```

---

## Task 5: Update SEC-1 audit finding

**Files:**
- Modify: `docs/superpowers/findings/2026-04-22-codebase-audit.md`

- [ ] **Step 1: Mark SEC-1 mitigated in the top-10 table**

In the finding doc, find the line:

```
| 1 | CRITICAL | runner | Parent shell secrets (`OPENAI_API_KEY`, `AWS_*`, etc.) pass through to the agent via `os.Environ()` | Strip env vars whose names match loaded vault entries; warn when intersection is non-empty ([runner.go:117](internal/runner/runner.go:117)) |
```

Replace with:

```
| 1 | ~~CRITICAL~~ MITIGATED | runner | Parent shell secrets (`OPENAI_API_KEY`, `AWS_*`, etc.) pass through to the agent via `os.Environ()` | **Fixed (YYYY-MM-DD)**: init scans shell env; run-time fail-closes on unvaulted secret-likes; vault stripping re-injects placeholder. Residual: heuristic-based (IsSecretLike FP/FN); see SEC-1 detail. |
```

(Replace `YYYY-MM-DD` with today's date.)

- [ ] **Step 2: Expand the SEC-1 body**

Locate the `#### SEC-1.` section and add at the end, before SEC-2:

```markdown
**Status (YYYY-MM-DD):** MITIGATED via three-layer heuristic defense:

1. `veil init` runs `scanner.ScanEnviron(os.Environ())` after .env/MCP scanning and prompts the user to vault detected secrets ([internal/scanner/environ.go](internal/scanner/environ.go), [internal/cli/init_shellenv.go](internal/cli/init_shellenv.go)).
2. `buildChildEnv` re-injects the vault placeholder when stripping a name-matched shell export, so shell-only credentials still reach the child ([runner.go buildChildEnv](internal/runner/runner.go)).
3. `veil run` fail-closes non-interactively on unvaulted secret-like shell env vars; `--allow-env-secret NAME` escape hatch ([runner.go envscan](internal/runner/envscan.go)).

**Residual risk:** the guarantee sits on `placeholder.IsSecretLike`. Finding #10 (entropy floor too low) compounds; an unfamiliar name pattern with a non-maximum-entropy value can slip. Structural defense (env allowlist) not implemented; tracked for a later hardening pass.
```

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/findings/2026-04-22-codebase-audit.md
git commit -m "docs(findings): mark SEC-1 mitigated, document residual risk"
```

---

## Self-review checklist

After implementing the plan, verify:

1. **Happy path end-to-end.** Export `OPENAI_API_KEY=sk-proj-abcdef...` in a shell, run `veil init --path /tmp/proj --yes` on a fresh project, confirm vault contains `OPENAI_API_KEY`, run `veil run env`, confirm the output contains `OPENAI_API_KEY=VEIL_...` (placeholder) and not the real key.
2. **Fail-closed path.** Same shell export, on a project whose vault is empty, run `veil run env` (non-interactive stdin). Confirm exit is non-zero and stderr names `OPENAI_API_KEY`.
3. **Escape hatch.** Same setup, run `veil run --allow-env-secret OPENAI_API_KEY env`. Confirm success and that the real value reaches the child (intended behavior when the user explicitly allows pass-through).
4. **No regression on existing flows.** Run `go test ./...`.
5. **Linter.** Run `go vet ./...` and whatever linter the repo uses.
6. **No new config surface leaked.** Grep for `AllowEnvSecret` — should appear in runner `Config`, CLI flag wiring, and tests only. No persistent config file field.
