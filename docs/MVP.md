# Veil v1 Scope Contract

What ships in Veil v1, what a developer can rely on, and where the edges
are. For the threat boundary, see [`THREAT_MODEL.md`](THREAT_MODEL.md).
This document is the scope contract — load-bearing exclusions are listed
explicitly so users do not have to infer them.

---

## 1. What ships

A single Go binary, `veil`. Local mediation of agent egress via an
in-process HTTPS MITM proxy started by `veil run` and torn down when the
agent exits. macOS and Linux. No daemon, no cloud, no account, no network
dependency at runtime.

---

## 2. What v1 covers

**Credentials.** HTTP `Authorization: Bearer` only, sourced from `.env`
files in the project root. The proxy rewrites placeholders with the real
value at request time. Bearer in headers and Bearer in URL query strings
are mediated.

**Providers (curated Bearer formats).** OpenAI, Anthropic, Stripe (secret
keys only), Slack, Google, GitHub PATs, Resend, Vercel, Replicate, Hugging
Face, GitLab, SendGrid, Supabase. Each has its own placeholder shape so
agents treat the placeholder as a real key.

**Unknown Bearer secrets.** `.env` values that look high-entropy and have
a credential-like name (e.g. `API_KEY`, `_TOKEN`) are detected and
reported by `veil init`, but are *not* automatically vaulted — a
credential with no inferred host has nowhere to fire on injection. To
vault and scope one, run `veil add NAME --value-stdin --host <host>`.

**Authorization primitive.** Host-scoping. A credential fires only against
the hosts on its allow-list, derived automatically from the provider
registry or set manually via `veil add --host`.

**Audit.** Every credential swap and blocked event is written to a local
SQLite database. The DB is chmod'd `0600`, parent directory `0700`, on
every `veil run`. Queryable via `veil log` with `--since`, `--host`,
`--credential`, `--limit`, `--json`.

**Substrate.** macOS and Linux. Any tool that respects `HTTP_PROXY` /
`HTTPS_PROXY` — Claude Code, Cursor, Copilot, Windsurf, `curl`, `wget`,
`gh`. Subprocesses inherit the proxy environment.

---

## 3. CLI surface

The public contract. Names and flags below are stable for the v1 series.

| Command | Behavior |
|---|---|
| `veil init` | Scan the project for `.env` files, vault any Bearer secrets found, write placeholders back, install the local CA. Flags: `--force`, `--yes`, `--dry-run`, `--path`. |
| `veil run <command>` | Start the proxy on a random loopback port, inject `HTTP_PROXY` / `HTTPS_PROXY` / CA bundle env vars into the child, run `<command>`. Proxy exits when the child exits. Flag: `--skip <host>` (repeatable, ephemeral). |
| `veil status` | Show proxy state, managed credential count, recent activity. |
| `veil add <name>` | Add a Bearer credential to the vault. Secret via `--value` (unsafe; lands in shell history) or `--value-stdin`. `--host` (repeatable) scopes the credential. `--force` overwrites an existing entry. |
| `veil list` | List managed credentials by name. Values are never printed. |
| `veil log` | Query the audit log. Filters: `--since`, `--host`, `--credential`, `--limit`, `--json`. |
| `veil remove <name>` | Delete a credential from the vault. `--force` / `--yes` to skip confirmation. |
| `veil uninstall` | Reverse `veil init`: restore original `.env` files from backups, wipe vault and audit state. `--dry-run` previews the plan; `--yes` / `--force` skip confirmation. |

---

## 4. Operating requirements

- **macOS** — uses the system Keychain for the vault master key. No additional setup.
- **Linux with Secret Service** (GNOME Keyring, KWallet) — probed at startup. If available, used transparently.
- **Linux without Secret Service** — vault master key is held in an age-encrypted file under `~/.local/state/veil/`, scrypt-protected. Every vault operation requires `VEIL_PASSPHRASE` in the environment.
- **CA trust** — `veil init` installs Veil's root CA into the user's trust store. Required for HTTPS interception.

The vault is **per project**, keyed by project root path. Switching
projects switches vaults.

---

## 5. Out of scope — by design

These are not "not yet." They are load-bearing exclusions for v1: each
one represents either a feature whose security guarantee Veil cannot
make today, or a market Veil is intentionally not entering.

| Excluded | Why |
|---|---|
| HTTP Basic auth | Mixed-token format prevents safe rewriting; users continue to manage Basic creds manually. |
| Keyed cryptography (AWS SigV4, GitHub App JWTs, HMAC webhook signing, mTLS) | The credential never appears on the wire — only a transform of it does. Veil cannot rewrite what it cannot match. |
| OAuth offline token exchange (`gcloud`, Azure CLI) | Secret exchanged for a bearer before the request reaches us. |
| Shell-environment secrets (no `.env`) | v1 scans `.env` files only. Secrets exported in `~/.zshrc` or `~/.bashrc` are not migrated. |
| MCP config files | v1 does not parse MCP server configs. Tokens in those files remain in place. |
| Non-HTTP protocols (raw TCP, SSH, QUIC, gRPC) | Proxy is HTTP/1.1 CONNECT only. |
| Windows | No proxy substrate yet. |
| Docker daemon (macOS Docker Desktop) | Daemon runs in a Linux VM that does not inherit shell `HTTPS_PROXY`. Out of scope for v1. |
| MCP supply-chain scanning | A different market (MCPScan, Invariant, Snyk agent-scan). |
| Agent-behavior / prompt observability | A different market (Prompt Security, Lakera, Lasso). |

These exclusions are also reflected in the threat-model boundary — see
[`THREAT_MODEL.md`](THREAT_MODEL.md).

---

## 6. Known runtime gaps

| Gap | Behavior |
|---|---|
| Agent clears `HTTP_PROXY` / `HTTPS_PROXY` | Cooperative enforcement. Out of scope. |
| Compressed request bodies | Fail-closed: non-`identity` `Content-Encoding` rejected with 502, not forwarded. |
| Request bodies > 10 MiB | Not scanned. |
| Binary or unknown Content-Type | Passes through unscanned. |

---

## 7. Success criteria

A shipped v1 means all of the following hold:

- A developer goes from `veil init` to `veil run claude` in under two minutes.
- An AI coding agent (Claude Code, Cursor, Copilot, Windsurf) makes API calls through the proxy without ever seeing real Bearer credentials for the supported providers.
- Every credential injection is recorded with destination, credential name, and timestamp.
- Placeholder values are structurally valid — agents do not error or prompt the user about malformed keys.
- Proxy adds less than 50 ms of latency to mediated requests.
- `veil run` cleanly tears down the proxy when the child exits — no orphaned processes, no leaked listeners.
