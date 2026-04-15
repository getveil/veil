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
| `veil add <name>` | Manually add a credential to the store. Pass `--user <value>` to create an HTTP Basic credential (username + secret pair) instead of a single-value token. |
| `veil list` | List managed credentials (names only, never values). Basic credentials are tagged `(basic)`. |
| `veil log` | Query the audit log. Supports `--since`, `--host`, `--credential`, and `--suspect` filters. `--suspect` shows records flagged by the transform-mismatch detector (marked with `[!]`). |

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
- **No credential injection for keyed-crypto auth schemes.** Credentials that are cryptographically transformed before hitting the wire — AWS SigV4 (HMAC-signed), GitHub App / JWT-signed requests, HMAC webhook signatures, and mTLS client certificates — are not injected. The proxy performs literal placeholder matching plus Basic-header decoding; keyed transforms produce bytes that can't be matched back to a placeholder. When a request to a credentialed host carries an auth-shaped signal (Authorization/Proxy-Authorization/Cookie, `X-*-(token|auth|key|sig|signature)` headers, or auth-shaped query params) but no injection fires, Veil's transform-mismatch detector logs a structured WARN and flags the audit record; `veil log --suspect` surfaces these. See [Transformed Credential Problem](docs/superpowers/findings/2026-04-13-transformed-credential-problem.md) for details.
- **HTTP Basic auth IS mediated.** `Authorization: Basic base64(user:secret)` (including `Proxy-Authorization` and OAuth 2.0 `client_secret_basic`) is decoded, matched against vault placeholders, and rewritten with real values. Covers `git push`, `docker push`, `twine`, `npm publish` with `_auth`, Artifactory/Nexus, and `.npmrc` registry credentials.
- **Compressed bodies pass through.** Requests with a `Content-Encoding` header are forwarded without placeholder injection.
- **Large bodies pass through.** Request bodies larger than 10 MiB are forwarded without placeholder injection.

## Success Criteria

- A developer goes from `veil init` to `veil run claude` in under 2 minutes.
- An AI agent (Claude Code, Cursor, Copilot) makes API calls through the proxy without ever seeing real credentials.
- Every credential injection is logged with destination, credential name, and timestamp.
- Placeholder `.env` values are structurally valid — agents don't error or prompt the user about malformed keys.
- The proxy adds less than 50ms latency to requests.
- `veil run` cleanly shuts down the proxy when the child process exits — no orphaned processes.
