# Veil Use Cases

How `veil run` interacts with an AI coding agent across a session: which
outbound behaviors are intercepted, which are passed through, and where
the architecture does and doesn't reach.

The `veil run` proxy is **in-process** — it starts when `veil run` starts,
lives inside the same OS process, and shuts down when the agent exits. It
is not a background daemon.

## Scope

**MVP (shipped today):** All cases below rely on the HTTPS MITM proxy
started by `veil run`, with enforcement via `HTTP_PROXY`/`HTTPS_PROXY`
environment variables. This covers any agent or tool that respects standard
proxy env vars — including Claude Code, Cursor, curl, the GitHub CLI, npm,
pip, and most HTTP clients.

**Post-MVP (planned):** Kernel-level enforcement via
`NETransparentProxyProvider` (macOS) and network namespaces + iptables
(Linux) will make interception non-bypassable and extend to all protocols.
See [Architecture](ARCHITECTURE.md) for details.

## Reading credential files

| # | Case | Status |
|---|---|---|
| 1 | Agent reads `.env` with format-aware placeholders (`ghp_veil_…`). | Supported |
| 2 | Agent reads MCP config JSON; placeholders in env blocks look structurally valid. | Supported |
| 3 | Agent generates code using `os.getenv("STRIPE_KEY")`; placeholder passes surface validation. | Supported |
| 4 | Agent reads multiple `.env` files (`.env`, `.env.local`, `.env.production`). | Supported |

## Direct API calls

| # | Case | Status |
|---|---|---|
| 5 | GitHub API (`ghp_veil_…` → `api.github.com`) gets real PAT injected. | Supported |
| 6 | Slack API (`xoxb-` → `api.slack.com`). | Supported |
| 7 | OpenAI / Anthropic (`sk-veil_…`). | Supported |
| 8 | AWS SigV4 — re-signed at the proxy (including STS session tokens). Google Cloud — `AIza`-prefixed API keys via the `*.googleapis.com` wildcard; service-account JSON keys and OAuth refresh tokens require manual `veil add --host` scoping (case 9). | Partial |
| 9 | Custom/internal API — manual `veil add --host api.mycompany.com`. | Supported (manual scoping) |
| 10 | Parallel requests to multiple services; per-hostname credential. | Supported |
| 11 | Host with no credential mapping (httpbin.org) — passthrough. | Supported |
| 12 | Retry after 401 — both attempts proxied and logged. | Supported |

## CLI tools and subprocesses

Subprocesses inherit `HTTP_PROXY` / `HTTPS_PROXY` and the CA bundle env vars
(`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`,
`REQUESTS_CA_BUNDLE`, `HTTPLIB2_CA_CERTS`, `CARGO_HTTP_CAINFO`) plus
`JAVA_TOOL_OPTIONS` for JVM children, so their HTTPS traffic flows through
the same proxy.

| # | Case | Status |
|---|---|---|
| 13 | `gh` CLI — inherits `HTTPS_PROXY`, GitHub token injected. | Supported |
| 14 | `curl -H "Authorization: Bearer $GITHUB_TOKEN"` — header swap. | Supported |
| 15 | `npm publish` / `twine upload` — registry host covered. | Supported |
| 16 | `psql` / `mysql` / `mongosh` — works when conn URL carries the credential and traffic is HTTPS; unix-socket transports bypass. | Partial |
| 17 | `docker push` — Docker Hub / GHCR / Quay / GCR / Artifact Registry / ECR hosts covered. | Supported |
| 18 | `pytest` / `npm test` — test processes inherit proxy + CA. | Supported |
| 19 | `./deploy.sh` calling cloud APIs — descendant processes inherit. | Supported |
| 20 | Agent spawns MCP server subprocess — inherits proxy env, outbound calls intercepted. | Supported |
| 21 | `cargo publish` / `cargo search` / `cargo install` — rustls honors `CARGO_HTTP_CAINFO`. | Supported |
| 22 | `mvn deploy`, `./gradlew publish`, Bazel Java — JVM honors `JAVA_TOOL_OPTIONS` with per-session PKCS12 truststore. Merged with any pre-existing `JAVA_TOOL_OPTIONS`. | Supported |

## Session lifecycle

| # | Case | Status |
|---|---|---|
| 23 | Agent launches via `veil run claude` — unaware of Veil; proxy vars in env. | Supported |
| 24 | Long session (hours) — in-process proxy persists with the parent; audit store batched. | Supported |
| 25 | Agent exits cleanly — `child.Wait()` returns; deferred cleanup tears down proxy, pidfile, CA bundle. | Supported |
| 26 | Agent crashes or is killed — signal forwarder forwards SIGINT, then escalates: SIGTERM 5s later, SIGKILL 10s after the initial SIGINT. Linux uses `Pdeathsig` for parent-death; macOS uses a pipe-based watchdog helper. | Supported |
| 27 | Multiple concurrent or sequential sessions — per-session pidfile (`proxy-<pid>.pid`), `veil status` enumerates all live sessions. | Supported |

## Edge cases

| # | Case | Status |
|---|---|---|
| 28 | Agent concatenates `ghp_` + variable at runtime. Proxy sees only the final string; swap happens iff that string matches a placeholder. | Out of scope |
| 29 | Placeholder hardcoded into source — inert by design; no scanner, no leak. | Supported (inert) |
| 30 | Base64-encoded placeholder in HTTP Basic (`Authorization` / `Proxy-Authorization`). | Supported — pre-pass decodes Basic, matches both halves, rewrites with real values. |
| 31 | Other transformed payloads — keyed crypto (SigV4, GitHub App JWT, HMAC), mTLS handshake. | Out of scope (MVP); flagged by transform-mismatch detector |
| 32 | Request without any credential — passthrough. | Supported |
| 33 | Localhost / internal services — `NO_PROXY` covers `localhost`, `127.0.0.1`, `::1`; `--skip <host>` (ephemeral) and `veil skip <host>` (persistent) extend it. | Supported |
| 34 | Auth-shaped request to a credentialed host with no injection fired — Veil emits structured WARN and flags the audit row (`veil log --suspect`). | Supported (signal, not enforcement) |

## What requires kernel-level enforcement (post-MVP)

The following scenarios are **not covered** by the MVP proxy model and
require the planned kernel-level enforcement layer:

| # | Case | Why |
|---|---|---|
| F1 | Agent clears or ignores `HTTP_PROXY`/`HTTPS_PROXY` env vars. | Proxy depends on cooperative env-var adoption. Kernel enforcement intercepts at the network layer regardless of env vars. |
| F2 | gRPC / HTTP/2 traffic. | The MITM proxy handles HTTP/1.1 CONNECT tunnels. Native HTTP/2 multiplexed streams require transparent proxy interception. |
| F3 | Raw TCP database connections (Postgres, MySQL, MongoDB native wire protocol). | Non-HTTP protocols bypass the HTTP proxy entirely. |
| F4 | SSH connections (git over SSH, remote server access). | SSH does not use HTTP proxy env vars. |
| F5 | QUIC / UDP traffic. | UDP-based protocols bypass the TCP proxy. |
| F6 | mTLS / client certificate authentication. | Client certs are used in the TLS handshake, below the HTTP layer. Unfixable under the HTTP-proxy-only constraint. |

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
