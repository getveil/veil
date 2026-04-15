# Veil Architecture

How Veil works today, what it covers, what it doesn't, and where it's headed.

## Current Architecture (MVP)

Veil is a single Go binary with no background daemon, no cloud dependency, and no runtime prerequisites beyond the OS keychain. The core component is a **local HTTPS MITM proxy** started in-process by `veil run` and torn down when the agent exits.

```
┌─────────────────────────────────────────────────────┐
│ veil run claude                                     │
│                                                     │
│  ┌──────────┐    HTTP_PROXY/    ┌────────────────┐  │
│  │          │    HTTPS_PROXY    │                │  │
│  │  Agent   │ ──────────────►  │  MITM Proxy    │  │
│  │ (child)  │                  │  (in-process)  │  │
│  │          │  ◄────────────── │                │  │
│  └──────────┘    responses     └───────┬────────┘  │
│                                        │           │
│                                        │ swap      │
│                                        │ placeholders
│                                        │ for real   │
│                                        │ creds      │
│                                ┌───────┴────────┐  │
│                                │  OS Keychain   │  │
│                                └───────┬────────┘  │
│                                        │           │
│                                ┌───────┴────────┐  │
│                                │  Audit (SQLite)│  │
│                                └────────────────┘  │
└─────────────────────────────────────────────────────┘
                        │
                        ▼
               ┌────────────────┐
               │  Upstream API  │
               │  (real creds)  │
               └────────────────┘
```

### Components

| Component | Package | Role |
|---|---|---|
| CLI | `internal/cli` | Command definitions: `init`, `run`, `status`, `add`, `list`, `log`, `skip`, `remove` |
| Proxy | `internal/proxy` | HTTPS MITM proxy via `goproxy`. TLS termination, leaf cert cache, credential injection. |
| Injector | `internal/proxy` | Aho-Corasick multi-pattern matching. Scans URL, headers, and body for placeholder strings. Replaces with real credentials from the vault. |
| Vault | `internal/vault` | Encrypted credential store. Backed by OS keychain (macOS Keychain, Linux Secret Service) with age-encrypted file fallback. |
| Placeholder | `internal/placeholder` | Format-aware placeholder generation. 14+ providers with correct prefix, length, and charset per service (GitHub PAT, Stripe, AWS, Slack, etc.). |
| Audit | `internal/audit` | SQLite-backed injection log. Records timestamp, request ID, host, method, URL path, credential ID, agent PID, and byte counts. |
| Scanner | `internal/scanner` | `.env` and MCP config file discovery. Locates secrets for migration to the vault. |
| Runner | `internal/runner` | Agent process lifecycle. Spawns child with proxy env vars, manages signals, handles cleanup. |
| MCP Config | `internal/mcpconfig` | MCP configuration file parsing and credential extraction. |
| CA | `internal/proxy` | Root CA generation and management. Per-host leaf cert generation with in-memory cache. |

### Credential Store

Secrets are stored in the OS keychain, encrypted at rest by the operating system:

- **macOS:** macOS Keychain (`security` framework)
- **Linux:** Secret Service (D-Bus) with fallback to an age-encrypted file at `~/.local/state/veil/`
- **Encryption key:** Derived from the OS keychain, never stored on disk

The vault is per-project (keyed by project root path). `veil init` migrates secrets from `.env` files and MCP configs into the vault and replaces originals with format-aware placeholders.

### Audit Log

Every credential injection is recorded to a local SQLite database:

- Timestamp, request ID, destination host, HTTP method, URL path
- Credential ID and credential name (never the credential value)
- Agent PID and agent command
- Injection location (URL, header, body, or blocked)
- Byte counts before/after injection

The database is chmod'd `0600` with parent directory `0700`. Queryable via `veil log` with `--since`, `--host`, and `--credential` filters.

## Interception Model

`veil run <agent>` performs the following sequence:

1. **Load vault** — opens the encrypted credential store for the project.
2. **Open audit DB** — creates or opens the SQLite audit log.
3. **Load/create CA** — loads the Veil root CA certificate and key (or generates on first run).
4. **Build CA bundle** — creates a temporary CA bundle that combines the system trusted roots with Veil's root CA.
5. **Start proxy** — starts the MITM proxy on a random loopback port (`127.0.0.1:0`).
6. **Spawn agent** — launches the agent command as a child process with environment variables:
   - `HTTP_PROXY` / `HTTPS_PROXY` → `http://127.0.0.1:<proxy-port>`
   - `NO_PROXY` → `localhost,127.0.0.1,::1` (plus any `--skip` hosts)
   - `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `HTTPLIB2_CA_CERTS` → path to the combined CA bundle
7. **Forward signals** — SIGINT, SIGTERM, etc. are forwarded to the child process.
8. **Wait** — proxy runs until the child exits.
9. **Cleanup** — proxy stopped, PID file removed, session temp directory swept.

### How Credential Injection Works

When the agent makes an HTTPS request:

1. Agent connects to the proxy via `HTTPS_PROXY`.
2. Proxy handles the CONNECT tunnel by performing TLS termination with a leaf certificate signed by Veil's CA (trusted by the agent via the CA bundle).
3. Proxy receives the plaintext HTTP request inside the tunnel.
4. **Aho-Corasick multi-pattern matcher** scans the URL, headers, and request body for any known placeholder strings.
5. For each match, the proxy checks host authorization (credential is scoped to specific hosts).
6. Authorized matches are replaced with the real credential from the vault.
7. Every injection is recorded to the audit log.
8. Proxy re-encrypts and forwards the request to the upstream API with real credentials.
9. Agent receives the response as normal — it has no visibility into the swap.

## What This Covers

All HTTP/HTTPS traffic from any tool that respects `HTTP_PROXY`/`HTTPS_PROXY` environment variables:

- **AI coding agents:** Claude Code, Cursor, Copilot, Windsurf
- **CLI tools:** `curl`, `wget`, `gh` (GitHub CLI), `npm`, `pip`, `twine`, `docker push`
- **SDKs and libraries:** Most HTTP client libraries in Node.js, Python, Ruby, and Java respect proxy env vars by default
- **Subprocesses:** All descendants of the agent inherit the proxy env vars, including MCP server subprocesses, test runners, and deploy scripts

## What This Doesn't Cover

| Gap | Reason | Mitigation |
|---|---|---|
| Agent clears `HTTP_PROXY`/`HTTPS_PROXY` | Enforcement is cooperative (env-var-based) | Planned: kernel-level enforcement (see below) |
| HTTP/2 (gRPC) | The proxy handles HTTP/1.1 CONNECT tunnels | Planned: transparent proxy with protocol-aware handlers |
| Raw TCP (database wire protocols, Redis) | Non-HTTP traffic bypasses the HTTP proxy | Planned: per-protocol handlers |
| SSH | Does not use HTTP proxy env vars | Planned: kernel-level interception |
| QUIC / UDP | UDP protocols bypass the TCP proxy | Planned: kernel-level interception |
| mTLS / client certificates | TLS handshake layer, below HTTP | Architectural constraint of the proxy model |
| HTTP Basic auth (Base64-encoded credentials) | Proxy performs literal placeholder matching only | Tracked: [Transformed Credential Problem](superpowers/findings/2026-04-13-transformed-credential-problem.md) |
| AWS SigV4 (HMAC-signed requests) | Credential used as signing key, never appears on wire | Tracked: requires per-provider signing adapters |
| Compressed request bodies | `Content-Encoding` bodies pass through un-inspected | By design: decompression risks are higher than the gap |
| Request bodies > 10 MiB | Performance boundary | Configurable in future release |

## Future Architecture (Post-MVP)

The MVP proxy model covers the realistic threat surface — AI coding agents make HTTP/HTTPS API calls using standard libraries that respect proxy env vars. But cooperative enforcement has a known limitation: an agent (or compromised dependency) that clears the env vars bypasses the proxy entirely.

The planned post-funding upgrade moves enforcement to the kernel level:

### macOS: NETransparentProxyProvider

Apple's Network Extension framework provides `NETransparentProxyProvider`, a system extension that intercepts TCP and UDP flows per-process at the network layer. This is the same mechanism used by corporate VPNs and endpoint security products.

- Non-bypassable by user-space code
- Per-process flow interception for all protocols
- Requires Apple Developer ID ($99/yr), notarization, and System Settings approval
- Design work completed — see [Egress Enforcement Design](superpowers/specs/2026-04-14-egress-enforcement-design.md) (parked)

### Linux: Network Namespaces + iptables

The child process is launched inside a dedicated network namespace with iptables `REDIRECT` rules routing traffic through the proxy.

- Non-bypassable within the namespace
- Per-process isolation via namespace boundaries
- Requires `CAP_NET_ADMIN` (one-time `setcap` at install time)
- Design work completed — see [Egress Enforcement Design](superpowers/specs/2026-04-14-egress-enforcement-design.md) (parked)

### What Changes

Both approaches wrap the existing proxy in a kernel-enforced traffic funnel. The proxy, injector, vault, and audit components are unchanged — only the enforcement primitive upgrades from "set env vars and hope" to "kernel-level redirect that cannot be bypassed."

The daemon architecture (IPC protocol, session lifecycle management) is already designed. Only the platform-specific enforcement primitive needs implementation.

### Why MVP Ships First

- The proxy model validates the core credential isolation concept.
- Kernel enforcement requires Apple Developer ID, notarization, Swift bridge (macOS), and `CAP_NET_ADMIN` packaging (Linux) — significant infrastructure overhead.
- AI coding agents (the primary threat surface) universally respect `HTTP_PROXY`/`HTTPS_PROXY`.
- MVP → user validation → funding → kernel enforcement is the correct sequencing of risk.
