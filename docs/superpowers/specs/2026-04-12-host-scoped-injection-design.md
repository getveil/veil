# Host-Scoped Credential Injection

**Date:** 2026-04-12
**Status:** Approved

## Problem

The proxy performs blind placeholder-to-credential replacement on all outbound request bodies regardless of destination host. When running `veil run claude`, the agent's conversation context (which contains `.env` placeholder values) is sent to `api.anthropic.com`. The proxy sees these placeholders in the request body and replaces them all with real credentials before forwarding. This means every Claude API call leaks all managed credentials to Anthropic.

Evidence from `veil log`:

```
2026-04-12T22:18:01Z    api.anthropic.com:443    POST      DATABASE_URL      body
2026-04-12T22:18:01Z    api.anthropic.com:443    POST      OPENAI_API_KEY    body
2026-04-12T22:18:01Z    api.anthropic.com:443    POST      GITHUB_TOKEN      body
2026-04-12T22:09:11Z    api.github.com:443       GET       GITHUB_TOKEN      header   <- correct
```

## Success Criteria

1. Each credential is only injected into requests where the destination host matches the credential's allowed hosts
2. Placeholders appearing in request bodies to non-matching hosts are left as-is
3. Blocked injections are logged as warning-level audit entries
4. `veil log` after a `veil run claude` session shows zero credential injections for `api.anthropic.com`

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| How credentials know their hosts | Hybrid: auto-infer from provider patterns, URL parsing, then `--host` flag as fallback | Covers most cases automatically, escape hatch for the rest |
| Behavior on non-matching host | Skip replacement + audit warning | Gives visibility without corrupting agent context |
| Manual host specification | `--host` flag on `veil add` | Keeps CLI surface small, no new commands |
| Host matching semantics | Provider patterns define host sets (including wildcards), `--host` is exact only | Providers handle complexity they know about, user-specified hosts stay predictable |

## Data Model

### `vault.Credential`

Add one field:

```go
AllowedHosts []string `json:"allowed_hosts,omitempty"`
```

- Empty slice = credential is never injected (secure-by-default)
- Populated by: provider host sets, URL parsing, or `--host` flag
- Backward compatible via `omitempty` (old vaults decode to nil/empty)

### `placeholder.ProviderPattern`

Add one field:

```go
Hosts []string // curated host set for this provider
```

Provider host sets:

| Provider | Hosts |
|----------|-------|
| GitHub | `api.github.com`, `uploads.github.com`, `raw.githubusercontent.com` |
| OpenAI | `api.openai.com` |
| Anthropic | `api.anthropic.com` |
| Stripe | `api.stripe.com`, `files.stripe.com` |
| AWS | `*.amazonaws.com` (suffix match for regional endpoints) |
| Slack | `slack.com`, `api.slack.com`, `files.slack.com` |

### `HostsForCredential(name, value string) []string`

New function in the `placeholder` package. Resolution chain:

1. Check provider registry -- if a provider matches, return its `Hosts`
2. Try URL parsing -- if the value is URL-shaped, extract the host
3. Return `nil` (credential is inert until manually scoped)

## Injector Changes

### Host matching logic

Exact string match for all hosts, except entries prefixed with `*.` which use suffix matching (strip `*.` prefix, check `strings.HasSuffix`). Only provider-defined patterns use wildcards.

### `ProcessRequest` new flow

1. AC matcher finds all placeholders in URL/headers/body (unchanged)
2. Parse destination host from the request URL
3. For each matched placeholder, check if `cred.AllowedHosts` contains the destination host
4. If authorized: replace and log injection as today
5. If not authorized: skip replacement, log audit entry with `Location: "blocked"`

The `Injector` struct and `PlaceholderMap()` method are unchanged. The injector reads `AllowedHosts` from each credential in the existing `creds` map.

### Blocked injection audit entry

```go
audit.Injection{
    // ...same fields as today...
    Location: "blocked",  // new sentinel, distinct from "url"/"header"/"body"
}
```

Reuses the existing `Injection` struct and audit pipeline.

## CLI Changes

### `veil add --host`

```
veil add MY_TOKEN --host api.example.com --host api2.example.com
```

Resolution order for `AllowedHosts`:
1. If `--host` flags provided: use those
2. Else: call `HostsForCredential(name, value)`

If resolution produces an empty list, print a warning:
```
Warning: no target hosts detected for MY_TOKEN. It won't be injected until scoped with --host.
```

### `veil init`

No CLI surface change. Internally, each credential calls `HostsForCredential(name, value)` to populate `AllowedHosts`. Summary output adds:

```
  Secrets vaulted: 8
  Auto-scoped to hosts: 6
  Unscoped (needs --host): 2
```

### `veil list`

Show allowed hosts alongside each credential:

```
NAME              HOSTS
GITHUB_TOKEN      api.github.com, uploads.github.com, raw.githubusercontent.com
OPENAI_API_KEY    api.openai.com
DATABASE_URL      db.prod.internal
CUSTOM_SECRET     (none)
```

## Testing

### Injector unit tests (`injector_test.go`)

- Placeholder matched but host not in `AllowedHosts`: no replacement, `"blocked"` audit entry
- Placeholder matched and host authorized: replacement as today
- Wildcard suffix matching (`*.amazonaws.com` matches `s3.us-east-1.amazonaws.com`)
- Multiple credentials, mixed authorization for same request
- Empty `AllowedHosts`: never injected

### Placeholder unit tests (`placeholder/`)

- `HostsForCredential` returns provider hosts for recognized credentials
- `HostsForCredential` extracts host from URL-shaped values
- `HostsForCredential` returns nil for unrecognizable values

### Integration test (`test/integration/`)

- `veil run` with a test HTTP server: credential injected to matching host, placeholder left as-is for non-matching host

### Existing test updates

Current `injector_test.go` tests need `AllowedHosts` set on test credentials to match the URLs used in each test.

## Files Changed

| File | Change |
|------|--------|
| `internal/vault/record.go` | Add `AllowedHosts` field to `Credential` |
| `internal/placeholder/providers.go` | Add `Hosts` field to `ProviderPattern` |
| `internal/placeholder/provider_github.go` | Add GitHub host set |
| `internal/placeholder/provider_openai.go` | Add OpenAI host set |
| `internal/placeholder/provider_anthropic.go` | Add Anthropic host set |
| `internal/placeholder/provider_stripe.go` | Add Stripe host set |
| `internal/placeholder/provider_aws.go` | Add AWS host set |
| `internal/placeholder/provider_slack.go` | Add Slack host set |
| `internal/placeholder/hosts.go` | New file: `HostsForCredential()` function, host matching logic |
| `internal/proxy/injector.go` | Filter replacements by host authorization |
| `internal/proxy/injector_test.go` | Update existing tests, add host-scoping tests |
| `internal/placeholder/hosts_test.go` | New file: tests for `HostsForCredential` and host matching |
| `internal/cli/add.go` | Add `--host` flag, call `HostsForCredential` |
| `internal/cli/init.go` | Call `HostsForCredential` when creating credentials, update summary |
| `internal/cli/list.go` | Show allowed hosts in output |
