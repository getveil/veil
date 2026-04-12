# Host-Scoped Credential Injection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent the proxy from injecting credentials into requests to non-matching hosts by scoping each credential to its allowed destination hosts.

**Architecture:** Add `AllowedHosts` to `vault.Credential`, add `Hosts` to provider patterns, build a resolution chain (`provider → URL parse → manual --host → empty`), and filter replacements in the injector's `ProcessRequest` by checking the destination host against each credential's allowed hosts before replacing.

**Tech Stack:** Go, Aho-Corasick (existing), SQLite audit (existing), cobra CLI (existing)

**Spec:** `docs/superpowers/specs/2026-04-12-host-scoped-injection-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `internal/vault/record.go` | Modify | Add `AllowedHosts` field to `Credential` |
| `internal/placeholder/providers.go` | Modify | Add `Hosts` field to `ProviderPattern` |
| `internal/placeholder/provider_github.go` | Modify | Add GitHub host set |
| `internal/placeholder/provider_openai.go` | Modify | Add OpenAI host set |
| `internal/placeholder/provider_anthropic.go` | Modify | Add Anthropic host set |
| `internal/placeholder/provider_stripe.go` | Modify | Add Stripe host set |
| `internal/placeholder/provider_aws.go` | Modify | Add AWS host set |
| `internal/placeholder/provider_slack.go` | Modify | Add Slack host set |
| `internal/placeholder/hosts.go` | Create | `HostsForCredential()`, `HostMatches()`, `ExtractURLHost()` |
| `internal/placeholder/hosts_test.go` | Create | Tests for host resolution and matching |
| `internal/proxy/injector.go` | Modify | Filter replacements by host authorization |
| `internal/proxy/injector_test.go` | Modify | Update existing tests + add host-scoping tests |
| `internal/cli/add.go` | Modify | Add `--host` flag, populate `AllowedHosts` |
| `internal/cli/init.go` | Modify | Populate `AllowedHosts` during init, update summary |
| `internal/cli/list.go` | Modify | Show `HOSTS` column in output |

---

### Task 1: Add `AllowedHosts` to `Credential`

**Files:**
- Modify: `internal/vault/record.go:12-19`

- [ ] **Step 1: Add the field**

In `internal/vault/record.go`, add `AllowedHosts` to the `Credential` struct:

```go
type Credential struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Real         string    `json:"real"`
	Placeholder  string    `json:"placeholder"`
	Source       string    `json:"source"`
	AllowedHosts []string  `json:"allowed_hosts,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}
```

- [ ] **Step 2: Run existing tests to verify nothing breaks**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/vault/...`
Expected: All tests PASS. The `omitempty` tag means existing JSON without the field deserializes to nil — backward compatible.

- [ ] **Step 3: Commit**

```bash
git add internal/vault/record.go
git commit -m "feat(vault): add AllowedHosts field to Credential"
```

---

### Task 2: Add `Hosts` field to `ProviderPattern` and populate all providers

**Files:**
- Modify: `internal/placeholder/providers.go:4-9`
- Modify: `internal/placeholder/provider_github.go`
- Modify: `internal/placeholder/provider_openai.go`
- Modify: `internal/placeholder/provider_anthropic.go`
- Modify: `internal/placeholder/provider_stripe.go`
- Modify: `internal/placeholder/provider_aws.go`
- Modify: `internal/placeholder/provider_slack.go`

- [ ] **Step 1: Add `Hosts` field to `ProviderPattern`**

In `internal/placeholder/providers.go`:

```go
type ProviderPattern struct {
	Name     string
	Match    func(name, value string) bool
	Generate func(value string) string
	Hosts    []string // curated host set for this provider
}
```

- [ ] **Step 2: Add hosts to GitHub provider**

In `internal/placeholder/provider_github.go`, update the `register` call:

```go
register(ProviderPattern{
	Name: "github",
	Match: func(name, value string) bool {
		for _, p := range githubPrefixes {
			if strings.HasPrefix(value, p) {
				return true
			}
		}
		return strings.Contains(strings.ToUpper(name), "GITHUB")
	},
	Generate: func(value string) string {
		prefix := ""
		for _, p := range githubPrefixes {
			if strings.HasPrefix(value, p) {
				prefix = p
				break
			}
		}
		rest := len(value) - len(prefix)
		return prefix + randAlphanumeric(rest)
	},
	Hosts: []string{"api.github.com", "uploads.github.com", "raw.githubusercontent.com"},
})
```

- [ ] **Step 3: Add hosts to OpenAI provider**

In `internal/placeholder/provider_openai.go`, add to the `register` call:

```go
Hosts: []string{"api.openai.com"},
```

- [ ] **Step 4: Add hosts to Anthropic provider**

In `internal/placeholder/provider_anthropic.go`, add to the `register` call:

```go
Hosts: []string{"api.anthropic.com"},
```

- [ ] **Step 5: Add hosts to Stripe provider**

In `internal/placeholder/provider_stripe.go`, add to the `register` call:

```go
Hosts: []string{"api.stripe.com", "files.stripe.com"},
```

- [ ] **Step 6: Add hosts to AWS provider**

In `internal/placeholder/provider_aws.go`, add to the `register` call:

```go
Hosts: []string{"*.amazonaws.com"},
```

- [ ] **Step 7: Add hosts to Slack provider**

In `internal/placeholder/provider_slack.go`, add to the `register` call:

```go
Hosts: []string{"slack.com", "api.slack.com", "files.slack.com"},
```

- [ ] **Step 8: Run existing tests to confirm nothing breaks**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/placeholder/...`
Expected: All tests PASS. Adding a field to a struct with no behavioral changes should not break anything.

- [ ] **Step 9: Commit**

```bash
git add internal/placeholder/providers.go internal/placeholder/provider_*.go
git commit -m "feat(placeholder): add Hosts field to ProviderPattern with curated host sets"
```

---

### Task 3: Implement host matching and resolution logic

**Files:**
- Create: `internal/placeholder/hosts.go`
- Create: `internal/placeholder/hosts_test.go`

- [ ] **Step 1: Write tests for `HostMatches`**

Create `internal/placeholder/hosts_test.go`:

```go
package placeholder

import "testing"

func TestHostMatches_ExactMatch(t *testing.T) {
	if !HostMatches("api.github.com", []string{"api.github.com"}) {
		t.Error("expected exact match to succeed")
	}
}

func TestHostMatches_NoMatch(t *testing.T) {
	if HostMatches("api.anthropic.com", []string{"api.github.com"}) {
		t.Error("expected no match for different host")
	}
}

func TestHostMatches_WildcardSuffix(t *testing.T) {
	if !HostMatches("s3.us-east-1.amazonaws.com", []string{"*.amazonaws.com"}) {
		t.Error("expected wildcard suffix match to succeed")
	}
}

func TestHostMatches_WildcardNoPartialMatch(t *testing.T) {
	if HostMatches("notamazonaws.com", []string{"*.amazonaws.com"}) {
		t.Error("expected wildcard to not match partial host")
	}
}

func TestHostMatches_WildcardExactBase(t *testing.T) {
	// *.amazonaws.com should NOT match bare "amazonaws.com"
	if HostMatches("amazonaws.com", []string{"*.amazonaws.com"}) {
		t.Error("expected wildcard to not match bare base domain")
	}
}

func TestHostMatches_EmptyAllowedHosts(t *testing.T) {
	if HostMatches("api.github.com", nil) {
		t.Error("expected no match with nil allowed hosts")
	}
	if HostMatches("api.github.com", []string{}) {
		t.Error("expected no match with empty allowed hosts")
	}
}

func TestHostMatches_MultipleHosts(t *testing.T) {
	hosts := []string{"api.github.com", "uploads.github.com"}
	if !HostMatches("uploads.github.com", hosts) {
		t.Error("expected match on second host in list")
	}
}

func TestHostMatches_PortStripped(t *testing.T) {
	if !HostMatches("api.github.com:443", []string{"api.github.com"}) {
		t.Error("expected match after stripping port")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/placeholder/ -run TestHostMatches -v`
Expected: FAIL — `HostMatches` not defined.

- [ ] **Step 3: Implement `HostMatches`**

Create `internal/placeholder/hosts.go`:

```go
package placeholder

import (
	"net"
	"net/url"
	"strings"
)

// HostMatches checks whether the given request host is authorized by the
// allowed hosts list. The host may include a port (e.g. "api.github.com:443")
// which is stripped before comparison. Allowed hosts entries are either exact
// hostnames or wildcard patterns like "*.amazonaws.com" (suffix match with
// leading dot to prevent partial matches).
func HostMatches(host string, allowedHosts []string) bool {
	if len(allowedHosts) == 0 {
		return false
	}
	host = stripPort(host)
	for _, allowed := range allowedHosts {
		if strings.HasPrefix(allowed, "*.") {
			// Wildcard suffix match: *.foo.com matches bar.foo.com
			// but not foo.com or notfoo.com.
			suffix := allowed[1:] // ".foo.com"
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				return true
			}
		} else if host == allowed {
			return true
		}
	}
	return false
}

// stripPort removes the port from a host:port string. If there is no port,
// the host is returned unchanged.
func stripPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return h
}

// ExtractURLHost attempts to parse value as a URL and return the hostname
// (without port). Returns "" if value is not a parseable URL with a host.
func ExtractURLHost(value string) string {
	u, err := url.Parse(value)
	if err != nil {
		return ""
	}
	if u.Host == "" || u.Scheme == "" {
		return ""
	}
	return stripPort(u.Host)
}

// HostsForCredential resolves the allowed hosts for a credential using the
// resolution chain:
//  1. Provider registry — if a provider matches, return its Hosts
//  2. URL parsing — if the value is URL-shaped, extract the host
//  3. Return nil (credential is inert until manually scoped)
func HostsForCredential(name, value string) []string {
	// 1. Check provider registry.
	for _, p := range registry {
		if p.Match(name, value) && len(p.Hosts) > 0 {
			hosts := make([]string, len(p.Hosts))
			copy(hosts, p.Hosts)
			return hosts
		}
	}

	// 2. Try URL host extraction.
	if h := ExtractURLHost(value); h != "" {
		return []string{h}
	}

	// 3. No hosts detected.
	return nil
}
```

- [ ] **Step 4: Run `HostMatches` tests to verify they pass**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/placeholder/ -run TestHostMatches -v`
Expected: All PASS.

- [ ] **Step 5: Write tests for `ExtractURLHost`**

Append to `internal/placeholder/hosts_test.go`:

```go
func TestExtractURLHost_PostgresURL(t *testing.T) {
	host := ExtractURLHost("postgres://user:pass@db.prod.internal:5432/mydb")
	if host != "db.prod.internal" {
		t.Errorf("expected db.prod.internal, got %q", host)
	}
}

func TestExtractURLHost_HTTPS(t *testing.T) {
	host := ExtractURLHost("https://api.example.com/v1")
	if host != "api.example.com" {
		t.Errorf("expected api.example.com, got %q", host)
	}
}

func TestExtractURLHost_PlainString(t *testing.T) {
	host := ExtractURLHost("sk-ant-api03-something")
	if host != "" {
		t.Errorf("expected empty string for non-URL, got %q", host)
	}
}

func TestExtractURLHost_NoScheme(t *testing.T) {
	host := ExtractURLHost("db.example.com:5432")
	if host != "" {
		t.Errorf("expected empty string for host without scheme, got %q", host)
	}
}
```

- [ ] **Step 6: Run `ExtractURLHost` tests**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/placeholder/ -run TestExtractURLHost -v`
Expected: All PASS.

- [ ] **Step 7: Write tests for `HostsForCredential`**

Append to `internal/placeholder/hosts_test.go`:

```go
func TestHostsForCredential_GitHubToken(t *testing.T) {
	hosts := HostsForCredential("GITHUB_TOKEN", "ghp_abc123def456")
	if len(hosts) == 0 {
		t.Fatal("expected hosts for GitHub token")
	}
	found := false
	for _, h := range hosts {
		if h == "api.github.com" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected api.github.com in hosts, got %v", hosts)
	}
}

func TestHostsForCredential_OpenAIKey(t *testing.T) {
	hosts := HostsForCredential("OPENAI_API_KEY", "sk-proj-abc123")
	if len(hosts) != 1 || hosts[0] != "api.openai.com" {
		t.Errorf("expected [api.openai.com], got %v", hosts)
	}
}

func TestHostsForCredential_DatabaseURL(t *testing.T) {
	hosts := HostsForCredential("DATABASE_URL", "postgres://user:pass@db.prod.internal:5432/mydb")
	if len(hosts) != 1 || hosts[0] != "db.prod.internal" {
		t.Errorf("expected [db.prod.internal], got %v", hosts)
	}
}

func TestHostsForCredential_UnknownSecret(t *testing.T) {
	hosts := HostsForCredential("CUSTOM_SECRET", "some-opaque-value-1234567890")
	if hosts != nil {
		t.Errorf("expected nil for unknown secret, got %v", hosts)
	}
}

func TestHostsForCredential_NameMatchGitHub(t *testing.T) {
	// Name contains GITHUB but value has no prefix — should still match provider.
	hosts := HostsForCredential("GITHUB_ENTERPRISE_TOKEN", "custom-token-value")
	if len(hosts) == 0 {
		t.Fatal("expected hosts for name-matched GitHub credential")
	}
	found := false
	for _, h := range hosts {
		if h == "api.github.com" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected api.github.com in hosts, got %v", hosts)
	}
}
```

- [ ] **Step 8: Run `HostsForCredential` tests**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/placeholder/ -run TestHostsForCredential -v`
Expected: All PASS.

- [ ] **Step 9: Run all placeholder tests**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/placeholder/... -v`
Expected: All PASS (existing + new).

- [ ] **Step 10: Commit**

```bash
git add internal/placeholder/hosts.go internal/placeholder/hosts_test.go
git commit -m "feat(placeholder): add host resolution and matching logic"
```

---

### Task 4: Add host-scoped filtering to the injector

**Files:**
- Modify: `internal/proxy/injector.go:66-160`
- Modify: `internal/proxy/injector_test.go`

- [ ] **Step 1: Write test for blocked injection on non-matching host**

Add to `internal/proxy/injector_test.go`:

```go
func TestHostScoping_BlockedInjection(t *testing.T) {
	cred := makeCred("github-token", "VEIL_PLACEHOLDER_HOST0001", "ghp-real-secret")
	cred.AllowedHosts = []string{"api.github.com"}
	inj := NewInjector(placeholderMap(cred), nil, 1, "agent")

	body := []byte(`{"context":"VEIL_PLACEHOLDER_HOST0001"}`)
	_, _, newBody, injections := inj.ProcessRequest(
		"req-host-1", "POST", "https://api.anthropic.com/v1/messages", http.Header{}, body)

	// Placeholder should NOT be replaced.
	if !strings.Contains(string(newBody), "VEIL_PLACEHOLDER_HOST0001") {
		t.Error("placeholder should not be replaced for non-matching host")
	}
	if strings.Contains(string(newBody), "ghp-real-secret") {
		t.Error("real secret should not appear in body for non-matching host")
	}
	// Should have a blocked audit entry.
	if len(injections) != 1 {
		t.Fatalf("expected 1 blocked injection, got %d", len(injections))
	}
	if injections[0].Location != "blocked" {
		t.Errorf("expected location 'blocked', got %q", injections[0].Location)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/proxy/ -run TestHostScoping_BlockedInjection -v`
Expected: FAIL — the placeholder is currently replaced regardless of host.

- [ ] **Step 3: Write test for allowed injection on matching host**

Add to `internal/proxy/injector_test.go`:

```go
func TestHostScoping_AllowedInjection(t *testing.T) {
	cred := makeCred("github-token", "VEIL_PLACEHOLDER_HOST0002", "ghp-real-secret")
	cred.AllowedHosts = []string{"api.github.com"}
	inj := NewInjector(placeholderMap(cred), nil, 1, "agent")

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer VEIL_PLACEHOLDER_HOST0002")
	_, newHeader, _, injections := inj.ProcessRequest(
		"req-host-2", "GET", "https://api.github.com/repos", hdr, nil)

	if newHeader.Get("Authorization") != "Bearer ghp-real-secret" {
		t.Errorf("expected real secret in header, got %q", newHeader.Get("Authorization"))
	}
	if len(injections) != 1 {
		t.Fatalf("expected 1 injection, got %d", len(injections))
	}
	if injections[0].Location != "header" {
		t.Errorf("expected location 'header', got %q", injections[0].Location)
	}
}
```

- [ ] **Step 4: Write test for mixed authorization in one request**

Add to `internal/proxy/injector_test.go`:

```go
func TestHostScoping_MixedAuthorization(t *testing.T) {
	ghCred := makeCred("github-token", "VEIL_PLACEHOLDER_HOST0003", "ghp-real")
	ghCred.AllowedHosts = []string{"api.github.com"}

	oaiCred := makeCred("openai-key", "VEIL_PLACEHOLDER_HOST0004", "sk-real")
	oaiCred.AllowedHosts = []string{"api.openai.com"}

	inj := NewInjector(placeholderMap(ghCred, oaiCred), nil, 1, "agent")

	body := []byte(`gh=VEIL_PLACEHOLDER_HOST0003&oai=VEIL_PLACEHOLDER_HOST0004`)
	_, _, newBody, injections := inj.ProcessRequest(
		"req-host-3", "POST", "https://api.github.com/graphql", http.Header{}, body)

	s := string(newBody)
	// GitHub cred should be replaced (matching host).
	if !strings.Contains(s, "ghp-real") {
		t.Error("expected github credential to be replaced")
	}
	// OpenAI cred should NOT be replaced (non-matching host).
	if !strings.Contains(s, "VEIL_PLACEHOLDER_HOST0004") {
		t.Error("expected openai placeholder to remain")
	}
	if strings.Contains(s, "sk-real") {
		t.Error("openai secret should not appear for github host")
	}

	// Should have 2 audit entries: 1 injection + 1 blocked.
	if len(injections) != 2 {
		t.Fatalf("expected 2 injections, got %d", len(injections))
	}
	locations := map[string]int{}
	for _, inj := range injections {
		locations[inj.Location]++
	}
	if locations["body"] != 1 {
		t.Errorf("expected 1 body injection, got %d", locations["body"])
	}
	if locations["blocked"] != 1 {
		t.Errorf("expected 1 blocked injection, got %d", locations["blocked"])
	}
}
```

- [ ] **Step 5: Write test for empty `AllowedHosts` (never injected)**

Add to `internal/proxy/injector_test.go`:

```go
func TestHostScoping_EmptyAllowedHosts(t *testing.T) {
	cred := makeCred("inert", "VEIL_PLACEHOLDER_HOST0005", "real-secret")
	// AllowedHosts is nil — should never inject.
	inj := NewInjector(placeholderMap(cred), nil, 1, "agent")

	body := []byte(`token=VEIL_PLACEHOLDER_HOST0005`)
	_, _, newBody, injections := inj.ProcessRequest(
		"req-host-4", "POST", "https://any-host.example.com/api", http.Header{}, body)

	if !strings.Contains(string(newBody), "VEIL_PLACEHOLDER_HOST0005") {
		t.Error("placeholder should not be replaced with empty AllowedHosts")
	}
	if len(injections) != 1 || injections[0].Location != "blocked" {
		t.Errorf("expected 1 blocked injection, got %v", injections)
	}
}
```

- [ ] **Step 6: Write test for wildcard host match via injector**

Add to `internal/proxy/injector_test.go`:

```go
func TestHostScoping_WildcardMatch(t *testing.T) {
	cred := makeCred("aws-key", "VEIL_PLACEHOLDER_HOST0006", "AKIA-real-key")
	cred.AllowedHosts = []string{"*.amazonaws.com"}
	inj := NewInjector(placeholderMap(cred), nil, 1, "agent")

	rawURL := "https://s3.us-east-1.amazonaws.com/bucket?key=VEIL_PLACEHOLDER_HOST0006"
	newURL, _, _, injections := inj.ProcessRequest(
		"req-host-5", "GET", rawURL, http.Header{}, nil)

	if strings.Contains(newURL, "VEIL_PLACEHOLDER_HOST0006") {
		t.Error("placeholder should be replaced for wildcard-matching host")
	}
	if !strings.Contains(newURL, "AKIA-real-key") {
		t.Error("expected real value in URL")
	}
	if len(injections) != 1 || injections[0].Location != "url" {
		t.Errorf("expected 1 url injection, got %v", injections)
	}
}
```

- [ ] **Step 7: Implement host-scoped filtering in `ProcessRequest`**

In `internal/proxy/injector.go`, add the import for the `placeholder` package and a `hostAuthorized` helper, then modify the three replacement sections (URL, header, body) to check host authorization:

Add import:
```go
"github.com/8enji/veil/internal/placeholder"
```

Add helper method after `ProcessRequest`:
```go
// hostAuthorized checks if a credential is allowed to be injected for the given host.
func hostAuthorized(cred *vault.Credential, host string) bool {
	return placeholder.HostMatches(host, cred.AllowedHosts)
}
```

Replace the URL scanning section (lines 104-115) with:

```go
	// --- URL scanning ---
	newURL = rawURL
	if matcher != nil {
		matched := matchedPatterns(matcher, []byte(rawURL), patterns)
		for _, ph := range matched {
			cred := creds[ph]
			if hostAuthorized(cred, host) {
				before := len(newURL)
				newURL = strings.ReplaceAll(newURL, ph, cred.Real)
				after := len(newURL)
				injections = append(injections, makeInjection(cred, "url", before, after))
			} else {
				injections = append(injections, makeInjection(cred, "blocked", 0, 0))
			}
		}
	}
```

Replace the header scanning section (lines 118-132) with:

```go
	// --- Header scanning ---
	newHeader = header.Clone()
	if matcher != nil {
		for name, values := range newHeader {
			for i, v := range values {
				matched := matchedPatterns(matcher, []byte(v), patterns)
				for _, ph := range matched {
					cred := creds[ph]
					if hostAuthorized(cred, host) {
						before := len(values[i])
						values[i] = strings.ReplaceAll(values[i], ph, cred.Real)
						after := len(values[i])
						injections = append(injections, makeInjection(cred, "header", before, after))
					} else {
						injections = append(injections, makeInjection(cred, "blocked", 0, 0))
					}
				}
			}
			newHeader[name] = values
		}
	}
```

Replace the body scanning section (lines 136-150) with:

```go
	// --- Body scanning ---
	newBody = body
	if matcher != nil && len(body) > 0 && len(body) <= inj.bodyCap {
		matched := matchedPatterns(matcher, body, patterns)
		if len(matched) > 0 {
			s := string(body)
			for _, ph := range matched {
				cred := creds[ph]
				if hostAuthorized(cred, host) {
					before := len(s)
					s = strings.ReplaceAll(s, ph, cred.Real)
					after := len(s)
					injections = append(injections, makeInjection(cred, "body", before, after))
				} else {
					injections = append(injections, makeInjection(cred, "blocked", 0, 0))
				}
			}
			newBody = []byte(s)
		}
	}
```

- [ ] **Step 8: Run the new host-scoping tests**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/proxy/ -run TestHostScoping -v`
Expected: All PASS.

- [ ] **Step 9: Update existing injector tests to set `AllowedHosts`**

The existing tests use URLs like `https://api.example.com/...`, `https://example.com/...`, `https://db.example.com/...`. Update the `makeCred` helper and each test to set `AllowedHosts` matching their test URLs.

Update `makeCred` to accept optional hosts:

```go
func makeCred(name, placeholder, real string, hosts ...string) *vault.Credential {
	return &vault.Credential{
		ID:           "cred-" + name,
		Name:         name,
		Placeholder:  placeholder,
		Real:         real,
		AllowedHosts: hosts,
	}
}
```

Then update each test's `makeCred` call to include the host used in that test:

- `TestReplaceURL`: `makeCred("api-key", "VEIL_PLACEHOLDER_AAAA1111", "sk-real-secret-value", "api.example.com")`
- `TestReplaceHeader`: `makeCred("token", "VEIL_PLACEHOLDER_BBBB2222", "Bearer real-token-value", "api.example.com")`
- `TestReplaceBody`: `makeCred("db-pass", "VEIL_PLACEHOLDER_CCCC3333", "s3cret-db-pass!", "db.example.com")`
- `TestMultipleMatches`: each cred gets `"example.com"` — e.g. `makeCred("key1", "VEIL_PLACEHOLDER_XXXX0001", "real-val-1", "example.com")`
- `TestBodyCap`: `makeCred("key", "VEIL_PLACEHOLDER_DDDD4444", "real-value", "example.com")`
- `TestNoMatch`: `makeCred("key", "VEIL_PLACEHOLDER_EEEE5555", "real-value", "example.com")`
- `TestAuditInjectionFields`: `makeCred("my-secret", "VEIL_PLACEHOLDER_FFFF6666", "the-real-deal", "api.example.com")`
- `TestOverlappingPlaceholderInMultipleLocations`: `makeCred("shared", "VEIL_PLACEHOLDER_GGGG7777", "replaced-value", "example.com")`
- `TestReplaceFunction`: `makeCred("key", "VEIL_PH_ABCDEF123456", "real-secret")` — `Replace()` doesn't use host scoping, so no hosts needed.
- `TestEmptyPlaceholderMap`: no change needed.
- `TestReload`: `makeCred("old-key", "VEIL_PLACEHOLDER_OLD_0001", "old-real")` and `makeCred("new-key", "VEIL_PLACEHOLDER_NEW_0002", "new-real")` — `Replace()` doesn't use host scoping, so no hosts needed.

Also update the new host-scoping tests' `makeCred` calls to use the variadic form — they already set `AllowedHosts` directly on the struct, so change them to use the variadic param instead for consistency:

- `TestHostScoping_BlockedInjection`: `makeCred("github-token", "VEIL_PLACEHOLDER_HOST0001", "ghp-real-secret", "api.github.com")` and remove the `cred.AllowedHosts = ...` line.
- `TestHostScoping_AllowedInjection`: same pattern.
- `TestHostScoping_MixedAuthorization`: same pattern for both creds.
- `TestHostScoping_EmptyAllowedHosts`: `makeCred("inert", "VEIL_PLACEHOLDER_HOST0005", "real-secret")` with no hosts (variadic empty).
- `TestHostScoping_WildcardMatch`: `makeCred("aws-key", "VEIL_PLACEHOLDER_HOST0006", "AKIA-real-key", "*.amazonaws.com")`.

- [ ] **Step 10: Run all proxy tests**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/proxy/... -v`
Expected: All PASS (existing updated + new host-scoping tests).

- [ ] **Step 11: Commit**

```bash
git add internal/proxy/injector.go internal/proxy/injector_test.go
git commit -m "feat(proxy): filter credential injection by allowed hosts"
```

---

### Task 5: Update `veil add` with `--host` flag

**Files:**
- Modify: `internal/cli/add.go`

- [ ] **Step 1: Add `--host` flag and `AllowedHosts` population**

Replace the contents of `internal/cli/add.go`:

```go
package cli

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/vault"
	"github.com/spf13/cobra"
)

func addCmd() *cobra.Command {
	var force bool
	var hosts []string
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a secret to the vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAdd(cmd, args[0], force, hosts)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing credential")
	cmd.Flags().StringArrayVar(&hosts, "host", nil, "allowed destination host (repeatable)")
	return cmd
}

func runAdd(cmd *cobra.Command, name string, force bool, hosts []string) error {
	root, err := resolveRoot()
	if err != nil {
		return exitError(err.Error())
	}

	v, err := openVault(root)
	if err != nil {
		return exitError(fmt.Sprintf("opening vault: %v", err))
	}

	// Read value from stdin.
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Enter value for %s: ", name)
	reader := bufio.NewReader(cmd.InOrStdin())
	value, err := reader.ReadString('\n')
	if err != nil {
		// Accept EOF without newline (e.g. piped input).
		if value == "" {
			return exitError("no value provided")
		}
	}
	value = strings.TrimRight(value, "\r\n")

	if value == "" {
		return exitError("no value provided")
	}

	// Generate placeholder.
	ph, err := placeholder.Generate(name, value)
	if err != nil {
		return exitError(fmt.Sprintf("generating placeholder: %v", err))
	}

	// Resolve allowed hosts.
	allowedHosts := hosts
	if len(allowedHosts) == 0 {
		allowedHosts = placeholder.HostsForCredential(name, value)
	}

	// Handle --force: delete existing credential first.
	if force {
		_, _ = v.Delete(name)
	}

	cred := &vault.Credential{
		ID:           vault.NewID(),
		Name:         name,
		Real:         value,
		Placeholder:  ph,
		Source:       "manual",
		AllowedHosts: allowedHosts,
		CreatedAt:    time.Now(),
	}
	if err := v.Add(cred); err != nil {
		return exitError(fmt.Sprintf("adding credential: %v", err))
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Added %s to vault\n", name)
	if len(allowedHosts) > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Hosts: %s\n", strings.Join(allowedHosts, ", "))
	} else {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
			"Warning: no target hosts detected for %s. It won't be injected until scoped with --host.\n", name)
	}

	return nil
}
```

- [ ] **Step 2: Run existing CLI tests**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/cli/... -v`
Expected: All PASS. The function signature change is internal to the command closure.

- [ ] **Step 3: Commit**

```bash
git add internal/cli/add.go
git commit -m "feat(cli): add --host flag to veil add for host scoping"
```

---

### Task 6: Update `veil init` to populate `AllowedHosts`

**Files:**
- Modify: `internal/cli/init.go:100-165` (env file processing loop)
- Modify: `internal/cli/init.go:186-195` (summary output)
- Modify: `internal/cli/init.go:215-250` (MCP config processing)

- [ ] **Step 1: Add host resolution to env file credential creation**

In `internal/cli/init.go`, in the env file processing loop (around line 134), add `AllowedHosts` to the credential and track scoping counts. Replace the credential creation block and the summary section.

In the env file loop, change the credential creation (around line 134-140) to:

```go
			credHosts := placeholder.HostsForCredential(line.Key, line.Value)

			cred := &vault.Credential{
				ID:           vault.NewID(),
				Name:         line.Key,
				Real:         line.Value,
				Placeholder:  ph,
				Source:       "init",
				AllowedHosts: credHosts,
				CreatedAt:    time.Now(),
			}
```

Add a counter variable before the env file loop (after `var secretsVaulted int` around line 102):

```go
	var secretsVaulted int
	var secretsScoped int
```

After `secretsVaulted++` (around line 150), add:

```go
			if len(credHosts) > 0 {
				secretsScoped++
			}
```

- [ ] **Step 2: Add host resolution to MCP config credential creation**

In the `processMCPConfig` function, update the credential creation (around line 234) to include host resolution. Change the function signature to also return the scoped count:

```go
func processMCPConfig(cmd *cobra.Command, v *vault.Vault, configPath string, force, dryRun bool) (int, int, error) {
```

Add `credHosts` resolution before credential creation:

```go
			credHosts := placeholder.HostsForCredential(key, value)
```

Add `AllowedHosts: credHosts,` to the credential struct literal.

Track scoped count:

```go
	var count int
	var scoped int
	configChanged := false
```

After `count++`, add:

```go
			if len(credHosts) > 0 {
				scoped++
			}
```

Change the return to `return count, scoped, nil` (and update all early returns to `return 0, 0, ...`).

Update the caller in `runInit` (around line 170-178):

```go
	var mcpConfigsProcessed int
	if mcpConfigPath != "" {
		n, s, err := processMCPConfig(cmd, v, mcpConfigPath, force, dryRun)
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

- [ ] **Step 3: Update summary output**

Replace the summary section (around line 186-195) with:

```go
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Veil initialized for %s\n", root)
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Secrets vaulted: %d\n", secretsVaulted)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Auto-scoped to hosts: %d\n", secretsScoped)
	unscoped := secretsVaulted - secretsScoped
	if unscoped > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Unscoped (needs --host): %d\n", unscoped)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  .env files processed: %d\n", len(envPaths))
	if mcpConfigsProcessed > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  MCP configs processed: %d\n", mcpConfigsProcessed)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  CA: %s\n", caFile)
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Run 'veil trust' to install the CA into your system trust store.")
```

- [ ] **Step 4: Run init tests**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/cli/... -v`
Expected: All PASS (init tests should still work since `AllowedHosts` is additive).

- [ ] **Step 5: Commit**

```bash
git add internal/cli/init.go
git commit -m "feat(cli): populate AllowedHosts during veil init"
```

---

### Task 7: Update `veil list` to show hosts

**Files:**
- Modify: `internal/cli/list.go:59-88`

- [ ] **Step 1: Add HOSTS column to list output**

In `internal/cli/list.go`, update the table headers and row formatting to include a HOSTS column.

Replace the tabwriter section (lines 59-88) with:

```go
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 4, ' ', 0)
	if reveal {
		_, _ = fmt.Fprintln(w, "NAME\tHOSTS\tVALUE\tSOURCE\tCREATED\tLAST INJECTED")
	} else {
		_, _ = fmt.Fprintln(w, "NAME\tHOSTS\tSOURCE\tCREATED\tLAST INJECTED")
	}
	for _, c := range creds {
		last := "never"
		if t, ok := lastInjected[c.Name]; ok {
			last = t
		}
		hostsStr := "(none)"
		if len(c.AllowedHosts) > 0 {
			hostsStr = strings.Join(c.AllowedHosts, ", ")
		}
		if reveal {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				c.Name,
				hostsStr,
				c.Real,
				c.Source,
				c.CreatedAt.Format("2006-01-02 15:04"),
				last,
			)
		} else {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				c.Name,
				hostsStr,
				c.Source,
				c.CreatedAt.Format("2006-01-02 15:04"),
				last,
			)
		}
	}
	_ = w.Flush()
```

Add `"strings"` to the import block.

- [ ] **Step 2: Run CLI tests**

Run: `cd /Users/ben/Workspace/Veil && go test ./internal/cli/... -v`
Expected: All PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/cli/list.go
git commit -m "feat(cli): show AllowedHosts in veil list output"
```

---

### Task 8: Full test suite and build verification

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `cd /Users/ben/Workspace/Veil && go test ./... -v`
Expected: All PASS.

- [ ] **Step 2: Build the binary**

Run: `cd /Users/ben/Workspace/Veil && go build -o veil ./cmd/veil/`
Expected: Clean build, no errors.

- [ ] **Step 3: Verify `--host` flag is visible**

Run: `cd /Users/ben/Workspace/Veil && ./veil add --help`
Expected: Output includes `--host` flag documentation.

- [ ] **Step 4: Commit if any fixes were needed**

If any test failures or build issues were fixed, commit those fixes.
