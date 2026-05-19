# Veil MVP Spec

What ships today, what a developer can rely on, and where the edges are. For mechanism — how the proxy, vault, and audit log work — see [`ARCHITECTURE.md`](ARCHITECTURE.md). For the threat boundary, see [`THREAT_MODEL.md`](THREAT_MODEL.md). This document is the scope contract.

---

## 1. What ships

A single Go binary, `veil`. Local mediation of agent egress via an in-process HTTPS MITM proxy started by `veil run` and torn down when the agent exits. macOS and Linux. No daemon, no cloud, no account, no network dependency at runtime.

The MVP free tier is this binary. Everything below is what that binary does today.

---

## 2. What you get, by outcome

Mapped to the four outcomes Veil targets.

**Agents don't hold credentials.** `veil init` migrates secrets out of `.env` files (and, with `--scan-mcp`, MCP configs) into a per-project encrypted vault and replaces them with format-aware placeholders — correct prefix, length, and charset, so agents treat them as real. The proxy rewrites placeholders with the real value at request time. HTTP Bearer is mediated end-to-end (Authorization headers, `git push` over HTTPS with a Bearer token). Keyed-crypto schemes — HMAC webhook signatures, mTLS client certs — and HTTP Basic credentials are not silently dropped; the transform-mismatch detector flags them (see §5).

**Agents can only do what you've authorized.** Host-scoping is the authorization primitive today. A credential fires only against the hosts on its allow-list, derived automatically from the provider registry, the URL it was first seen on, or manual configuration. No declarative policy language — that's Part II in [`ARCHITECTURE.md`](ARCHITECTURE.md).

**Every action is on the record.** Every credential swap, blocked event, and mismatch-detector flag is written to a local SQLite database. The DB is chmod'd `0600`, parent directory `0700`, on every `veil run`. Queryable via `veil log` with `--since`, `--host`, `--credential`. This is the same event shape every Part II audit subscriber will read from — see [`ARCHITECTURE.md`](ARCHITECTURE.md#audit-plane).

**Same rules everywhere.** macOS and Linux. Any tool that respects `HTTP_PROXY` / `HTTPS_PROXY` — Claude Code, Cursor, Copilot, Windsurf, `curl`, `wget`, `gh`. Subprocesses inherit the proxy environment, so MCP servers, test runners, and deploy scripts launched by the agent are mediated too.

---

## 3. CLI surface

The public contract. Names and flags below are stable for the MVP series.

| Command | Behavior |
|---|---|
| `veil init` | Scan the project for `.env` files (and, with `--scan-mcp`, MCP configs), vault any secrets found, write placeholders back, install the local CA. |
| `veil run <command>` | Start the proxy on a random loopback port, inject `HTTP_PROXY` / `HTTPS_PROXY` / CA bundle env vars into the child, run `<command>`. Proxy exits when the child exits. |
| `veil status` | Show proxy state, managed credential count, recent activity. |
| `veil add <name>` | Add a Bearer credential to the vault. Secret via `--value` (unsafe; lands in shell history) or `--value-stdin`. `--host` (repeatable) scopes the credential. |
| `veil list` | List managed credentials by name. Values are never printed unless `--reveal` is passed. |
| `veil log` | Query the audit log. Filters: `--since`, `--host`, `--credential`. |
| `veil skip <host>` | Add a host to the per-project `NO_PROXY` list. `--list` shows the current list; `--remove <host>` deletes an entry. |
| `veil remove <name>` | Delete a credential from the vault. |
| `veil uninstall` | Reverse `veil init`: restore original `.env` and MCP files from backups, wipe vault and audit state. `--dry-run` previews the plan. |

---

## 4. Operating requirements

- **macOS** — uses the system Keychain for the vault master key. No additional setup.
- **Linux with Secret Service** (GNOME Keyring, KWallet) — probed at startup. If available, used transparently.
- **Linux without Secret Service** — vault master key is held in an age-encrypted file under `~/.local/state/veil/`, scrypt-protected. Every vault operation requires `VEIL_PASSPHRASE` in the environment.
- **CA trust** — `veil init` installs Veil's root CA into the user's trust store. Required for HTTPS interception.

The vault is **per project**, keyed by project root path. Switching projects switches vaults.

---

## 5. Gaps you should plan around

These are the live edges of MVP coverage. Each links to where it's addressed in the roadmap.

| Gap | Why it exists today | Where it's solved |
|---|---|---|
| Agent clears `HTTP_PROXY` / `HTTPS_PROXY` | Cooperative enforcement | Kernel enforcement — [`ARCHITECTURE.md`](ARCHITECTURE.md) Part II |
| HTTP/2 (gRPC), QUIC, raw TCP, SSH | Proxy is HTTP/1.1 CONNECT only | Per-protocol handlers / kernel interception — Part II |
| HMAC webhook signing | Credential is a signing key, never on the wire | Native signer adapters — Part II. Surfaced today by transform-mismatch detector. |
| mTLS client certs | Used in TLS handshake, never at HTTP layer | Architectural |
| OAuth offline token exchange (`gcloud`, Azure CLI) | Secret exchanged for a bearer before the request reaches us | Ephemeral brokering — Part II |
| Compressed request bodies | Fail-closed: non-`identity` `Content-Encoding` rejected with 502, not forwarded | Decompression risk exceeds the gap |
| Request bodies > 10 MiB | Performance boundary | Configurable in a future release |
| Windows | No proxy substrate yet | Part II |

The transform-mismatch detector deserves a specific note: when a request to a credentialed host carries an auth-shaped signal (Authorization / Proxy-Authorization / Cookie / `X-*-{token,auth,key,sig,signature}` / auth-shaped query params) but no injection fires, Veil emits a structured WARN and flags the audit row. It is **a signal, not enforcement** — the real secret still exists wherever the agent read it from.

---

## 6. Out of scope — by design

These are not "not yet." We hold them as load-bearing exclusions.

- **MCP supply-chain scanning.** MCPScan, Invariant Labs, Snyk's agent-scan serve that market.
- **Agent-behavior / prompt observability.** Prompt Security, Lakera, Lasso serve that market.

[`ARCHITECTURE.md`](ARCHITECTURE.md) Part IV explains why the moat depends on staying narrow.

---

## 7. Success criteria

A shipped MVP means all of the following hold:

- A developer goes from `veil init` to `veil run claude` in under two minutes.
- An AI coding agent (Claude Code, Cursor, Copilot, Windsurf) makes API calls through the proxy without ever seeing real credentials.
- Every credential injection is recorded with destination, credential name, and timestamp.
- Placeholder values are structurally valid — agents do not error or prompt the user about malformed keys.
- Proxy adds less than 50 ms of latency to mediated requests.
- `veil run` cleanly tears down the proxy when the child exits — no orphaned processes, no leaked listeners.
