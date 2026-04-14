# Veil Use Cases

How `veil run` interacts with an AI coding agent across a session: which
outbound behaviors are intercepted, which are passed through, and where
the architecture does and doesn't reach.

The `veil run` proxy is **in-process** — it starts when `veil run` starts,
lives inside the same OS process, and shuts down when the agent exits. It
is not a background daemon.

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
| 8 | AWS / GCP (STS, `oauth2.googleapis.com`). | Supported |
| 9 | Custom/internal API — manual `veil add --host api.mycompany.com`. | Supported (manual scoping) |
| 10 | Parallel requests to multiple services; per-hostname credential. | Supported |
| 11 | Host with no credential mapping (httpbin.org) — passthrough. | Supported |
| 12 | Retry after 401 — both attempts proxied and logged. | Supported |

## CLI tools and subprocesses

Subprocesses inherit `HTTP_PROXY` / `HTTPS_PROXY` and the CA bundle env vars
(`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`,
`REQUESTS_CA_BUNDLE`, `HTTPLIB2_CA_CERTS`) so their HTTPS traffic flows
through the same proxy.

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

## Session lifecycle

| # | Case | Status |
|---|---|---|
| 21 | Agent launches via `veil run claude` — unaware of Veil; proxy vars in env. | Supported |
| 22 | Long session (hours) — in-process proxy persists with the parent; audit store batched. | Supported |
| 23 | Agent exits cleanly — `child.Wait()` returns; deferred cleanup tears down proxy, pidfile, CA bundle. | Supported |
| 24 | Agent crashes or is killed — signal forwarder escalates SIGTERM → SIGKILL. Linux uses `Pdeathsig` for parent-death; macOS uses a pipe-based watchdog helper. | Supported |
| 25 | Multiple concurrent or sequential sessions — per-session pidfile (`proxy-<pid>.pid`), `veil status` enumerates all live sessions. | Supported |

## Edge cases

| # | Case | Status |
|---|---|---|
| 26 | Agent concatenates `ghp_` + variable at runtime. Proxy sees only the final string; swap happens iff that string matches a placeholder. | Out of scope |
| 27 | Placeholder hardcoded into source — inert by design; no scanner, no leak. | Supported (inert) |
| 28 | Base64-encoded placeholder in Basic auth / transformed payloads. | See [specs/2026-04-13-transformed-credential-problem.md](./superpowers/specs/2026-04-13-transformed-credential-problem.md) |
| 29 | Request without any credential — passthrough. | Supported |
| 30 | Localhost / internal services — `NO_PROXY` covers `localhost`, `127.0.0.1`, `::1`; `--skip-hosts` extends it. | Supported |
