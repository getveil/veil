# Veil MVP Spec

## What Veil Is

A CLI that secures AI coding agents. It sits between the agent and the network via HTTP proxy environment variables — a local HTTPS MITM proxy that injects real credentials at request time so agents never see actual secrets. Ships as a single binary, zero cloud dependency.

## Features

### 1. Credential Proxy

A local MITM HTTPS proxy that intercepts outgoing agent requests and injects real credentials from a local encrypted store before they hit the wire. The agent never touches a real secret.

### 2. Placeholder .env

On setup, scan the project for `.env` files, vault the real values into the credential store, and replace them with format-aware placeholders. Placeholders must look structurally valid (match format, length, and any known prefixes like `sk-`) so agents treat them as real and proceed normally. The proxy swaps in real values at the network layer.

### 3. Audit Log

Every credential injection is logged locally: timestamp, credential name, destination host, and agent PID. The log must be queryable by time range, destination host, and credential name.

## CLI Surface

| Command | What it does |
|---|---|
| `veil init` | Scan project for secrets, vault them, write placeholder `.env`, set up proxy CA |
| `veil run <command>` | Start the proxy, set `HTTP_PROXY`/`HTTPS_PROXY` in the child environment, launch the given command (e.g. `veil run claude`). Proxy exits when the child exits. |
| `veil status` | Show proxy state, managed credential count, recent activity |
| `veil add <name>` | Manually add a credential to the store |
| `veil list` | List managed credentials (names only, never values) |
| `veil log` | Query the audit log. Supports `--since`, `--host`, `--credential` filters |

## Constraints

- macOS and Linux only. No Windows for MVP.
- Local-first. No cloud, no accounts, no network dependency.
- Must work with any agent that respects `HTTP_PROXY`/`HTTPS_PROXY` — no agent-specific integrations.
- Credential store encryption key must be derived from the OS keychain, not stored on disk.
- Single binary distribution. No runtime dependencies.

## Out of Scope

- MCP server scanning
- OAuth token refresh / rotation
- Team credential sharing
- Cloud dashboard or GUI
- Agent-specific integrations

## Known Limitations

- **Advisory enforcement.** The proxy relies on `HTTP_PROXY`/`HTTPS_PROXY` environment variables. An agent or subprocess that clears these variables bypasses the proxy entirely. Kernel-level enforcement (NetworkExtension on macOS, network namespaces on Linux) is planned for a future release.
- **HTTP/HTTPS only.** The proxy does not intercept HTTP/2 (gRPC), QUIC/UDP, raw TCP, or any non-HTTP protocol. Database wire protocols (Postgres, MySQL, MongoDB), SSH, and mTLS are out of scope.
- **No credential injection for non-HTTP auth schemes.** Credentials that are transformed before hitting the wire — such as HTTP Basic auth (Base64-encoded), AWS SigV4 (HMAC-signed), or JWT-signed requests — are not injected. The proxy performs literal placeholder matching only. See [Transformed Credential Problem](docs/superpowers/findings/2026-04-13-transformed-credential-problem.md) for details.
- **Compressed bodies pass through.** Requests with a `Content-Encoding` header are forwarded without placeholder injection.
- **Large bodies pass through.** Request bodies larger than 10 MiB are forwarded without placeholder injection.

## Success Criteria

- A developer goes from `veil init` to `veil run claude` in under 2 minutes.
- An AI agent (Claude Code, Cursor, Copilot) makes API calls through the proxy without ever seeing real credentials.
- Every credential injection is logged with destination, credential name, and timestamp.
- Placeholder `.env` values are structurally valid — agents don't error or prompt the user about malformed keys.
- The proxy adds less than 50ms latency to requests.
- `veil run` cleanly shuts down the proxy when the child process exits — no orphaned processes.
