# Veil Architecture

How Veil works today, how it evolves into the full broker described in [`PRODUCT_FINAL.md`](PRODUCT_FINAL.md), and the invariants that hold across both.

This document has two parts:

- **Part I — MVP Architecture (shipping today).** What the code actually does, verified against the tree. This is ground truth, not intent.
- **Part II — Aspirational Architecture (on the roadmap).** The full identity broker. Lighter — one paragraph per plane, naming the mechanism and the seam it attaches to, not re-specifying it.

Parts III and IV cover the evolution path and what is explicitly out of scope.

---

## Architectural position

Veil sits *below the agent*, on the wire, as a local mediation layer every outbound request passes through. The agent cannot opt out, cannot be lied to about what the identity layer sees, and does not need to cooperate for the layer to function. This is the structural commitment inherited from [`PRODUCT_FINAL.md`](PRODUCT_FINAL.md) §1–3; every design decision downstream of it is constrained by it.

Three invariants hold across every stage of the roadmap:

1. **One chokepoint per machine.** All agent egress passes through a single local mediation process.
2. **One event model.** Every mediation event — credential swap, policy verdict, anomaly flag — emits the same envelope shape into the same store. The dataset is the asset ([`PRODUCT_FINAL.md`](PRODUCT_FINAL.md) §5); it compounds only if the shape stays stable.
3. **No agent cooperation required.** No SDK, no callback, no framework adoption. The agent reads its `.env`, constructs headers, makes requests; Veil is the wire beneath it.

Any feature that would weaken these invariants is excluded, regardless of immediate utility.

---

# Part I — MVP Architecture (shipping today)

Veil ships as a single Go binary with no background daemon, no cloud dependency, and no runtime prerequisites beyond the OS keychain (or a passphrase-encrypted key file on Linux systems without one). The proxy is started in-process by `veil run` and torn down when the agent exits.

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
│                                        │ resolve   │
│                                        │ placeholder
│                                        │ → real     │
│                                        │ credential │
│                                ┌───────┴────────┐  │
│                                │  OS Keychain   │  │
│                                │  / age-file    │  │
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

## Components

| Component | Package | Role |
|---|---|---|
| CLI | `internal/cli` | Command definitions: `init`, `run`, `status`, `add`, `list`, `log`, `skip`, `remove` |
| Proxy | `internal/proxy` | HTTPS MITM proxy via `goproxy`. TLS termination, leaf cert cache, per-request injection pipeline. |
| Injector | `internal/proxy/injector.go` | Aho-Corasick multi-pattern matching over URL, headers, and text-like request bodies. Replaces matched placeholders with real credentials subject to host-scoping. |
| Basic decoder | `internal/proxy/basic_decoder.go` | Pre-pass that decodes `Authorization: Basic` and `Proxy-Authorization: Basic` headers, matches both username and secret halves to a vault record, rewrites with real values. |
| Mismatch detector | `internal/proxy/mismatch_detector.go` | Post-pass that flags requests to credentialed hosts carrying an auth-shaped signal (Authorization / Cookie / `X-*-{token,auth,key,sig,signature}` / auth-shaped query params) when no injection fired. |
| Vault | `internal/vault` | Encrypted credential store (per-project). Sealed blob on disk, master key held by the keystore. |
| Keystore | `internal/vault/keystore_*.go` | Pluggable backend for the vault master key. Today: macOS Keychain (always), Linux Secret Service (probed at startup), age-encrypted file with `VEIL_PASSPHRASE` as fallback. |
| Placeholder | `internal/placeholder` | Format-aware placeholder generation. 14 curated providers + a declarative `Format` registry. Correct prefix, length, and charset per service. Includes provider→host resolution so credentials are scoped automatically. |
| Audit | `internal/audit` | SQLite-backed injection log. WAL mode, batched writes, v2 schema with `suspect_flag` and `auth_signal` columns for the mismatch detector. |
| Scanner | `internal/scanner` | `.env` file discovery (curated basenames; `.example` / `.sample` excluded). |
| MCP config | `internal/mcpconfig` | Parses MCP server configs and extracts embedded credentials for migration to the vault. |
| Runner | `internal/runner` | Agent process lifecycle — spawn with proxy + CA env vars, forward signals, reclaim foreground tty, clean session temp dir. |
| CA | `internal/proxy/ca.go` + `leaf.go` | Root CA generation, persistent on-disk; per-host leaf certs signed on demand and cached in memory. |

## Lifecycle of a request

`veil run <agent>` performs the following sequence (`internal/runner/runner.go:44`):

1. **Load vault.** Opens the per-project sealed blob, master key retrieved from the keystore.
2. **Open audit DB.** Creates/opens the SQLite store, forces WAL + SHM materialization, chmods DB + sidecars to 0600 and the parent dir to 0700.
3. **Load CA.** Loads the Veil root CA (generated on first run).
4. **Build session CA bundle.** Writes a temp file combining system roots with Veil's CA for runtime injection into the child.
5. **Start proxy.** Listens on `127.0.0.1:0` — random loopback port, never routable.
6. **Spawn child.** Agent process is launched with:
   - `HTTP_PROXY` / `HTTPS_PROXY` → `http://127.0.0.1:<proxy-port>`
   - `NO_PROXY` → `localhost,127.0.0.1,::1` plus any `--skip` hosts
   - `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `HTTPLIB2_CA_CERTS` → session CA bundle
7. **Forward signals.** SIGINT, SIGTERM, SIGHUP forwarded to the child's process group.
8. **Wait.** Proxy runs until the child exits.
9. **Cleanup.** Proxy stopped, PID file removed, session temp dir swept.

When the agent issues an HTTPS request:

1. Agent connects to the proxy via `HTTPS_PROXY`.
2. Proxy handles the CONNECT tunnel, terminating TLS with a per-host leaf cert signed by Veil's CA (trusted via the bundle above).
3. Proxy receives the plaintext HTTP request inside the tunnel.
4. **Basic pre-pass** — Authorization / Proxy-Authorization `Basic` headers are base64-decoded, matched against vault placeholders, rewritten with real user:secret pairs.
5. **Literal scan** — Aho-Corasick matcher runs over URL, header values, and (if Content-Type is on the allowlist) the request body. Matches are replaced with real credentials subject to host-scoping.
6. **Mismatch post-pass** — if the request targets a credentialed host and carries an auth-shaped signal but no injection fired, Veil emits a structured WARN log and flags the audit record (`SuspectFlag`, `AuthSignal`). Surfaces via `veil log --suspect`.
7. **Audit.** Every swap (and every blocked / suspect event) is recorded.
8. **Forward.** Proxy re-encrypts and forwards the request upstream.
9. Agent receives the response unchanged.

## Credential store

The vault is **per-project** (keyed by project root path, `vault.meta` on disk records the project ID). The stored blob is sealed with a 32-byte master key generated at `veil init` time via `crypto/rand` and held by the keystore — it is never written to disk in clear text.

- **macOS:** `security` framework (macOS Keychain), always selected.
- **Linux:** Secret Service (D-Bus) probed at startup with a test Set/Delete (`keystore_auto.go:16`). If the probe fails, falls back to an age-encrypted key file at `~/.local/state/veil/` — this fallback requires `VEIL_PASSPHRASE` in the environment for every vault operation.
- **Fallback on-disk file** is scrypt-protected via `filippo.io/age` with the parent dir chmod'd to 0700 and the file itself chmod'd to 0600.

The keystore is a pluggable interface (`internal/vault/keystore.go`) — the same seam accepts external backing stores in the aspirational architecture (see Part II).

## Audit log

Every mediation event is recorded to a local SQLite database (`internal/audit/audit.go`):

- Timestamp, request ID (ULID, groups multi-hit requests), destination host, HTTP method, URL path
- Credential ID and credential name (never the credential value)
- Agent PID and agent command
- Injection location — `header`, `body`, `url`, `blocked`, or `mismatch_suspected`
- Byte counts before/after injection
- `suspect_flag` + `auth_signal` for records flagged by the mismatch detector

The schema is versioned (`schema_version` table, currently v2). The database is chmod'd 0600 with parent directory 0700 on every open — idempotent, corrects existing installs. Queryable via `veil log` with `--since`, `--host`, `--credential`, `--suspect` filters.

This schema is the dataset referenced in [`PRODUCT_FINAL.md`](PRODUCT_FINAL.md) §5. Every downstream capability in Part II — OTEL export, team dashboard, anomaly baselines, threat intelligence — subscribes to this same event stream. New columns are added under schema versioning; the shape never gets replaced.

## How the MVP delivers the four outcomes

Mapped to the four-outcome framing in [`PRODUCT_FINAL.md`](PRODUCT_FINAL.md) §2:

- **Agents don't hold credentials.** Static substitution. `veil init` migrates secrets out of `.env` / MCP configs into the vault, replaces them with format-aware placeholders. The proxy rewrites placeholders on outbound requests. HTTP Bearer and HTTP Basic are both end-to-end. Keyed-crypto schemes (AWS SigV4, GitHub App JWT, HMAC webhook signatures, mTLS client certs) are **surfaced** by the transform-mismatch detector rather than silently failing.
- **Agents can only do what you've authorized.** Host-scoping is the current authorization primitive — credentials fire only for hosts on their `AllowedHosts` list (derived automatically by provider match, URL parsing, or manual configuration, see `internal/placeholder/hosts.go`). Not yet a declarative policy language.
- **Every action is on the record.** Local SQLite as described above. Queryable via `veil log`.
- **Same rules everywhere.** macOS and Linux. Any agent or tool respecting `HTTP_PROXY` / `HTTPS_PROXY`. Tested with Claude Code, Cursor, Copilot, `curl`, `gh`, `npm`, `pip`, `docker push`. Subprocesses of the agent inherit the proxy env vars — MCP server subprocesses, test runners, deploy scripts are all covered.

## What the MVP covers

HTTP/HTTPS traffic from any tool that respects `HTTP_PROXY` / `HTTPS_PROXY`:

- **AI coding agents** — Claude Code, Cursor, Copilot, Windsurf.
- **CLI tools** — `curl`, `wget`, `gh`, `npm`, `pip`, `twine`, `docker push`, `git push` over HTTPS (Basic with PAT).
- **SDKs and libraries** — most HTTP clients in Node.js, Python, Ruby, Java honor proxy env vars by default.
- **Subprocesses** — all descendants of the agent inherit the environment, including MCP server subprocesses.
- **Auth schemes** — Bearer end-to-end. Basic end-to-end (Authorization, Proxy-Authorization, OAuth 2.0 `client_secret_basic`, `.npmrc` `_auth`, Artifactory/Nexus, `twine`, `docker push`).

## What the MVP doesn't cover

| Gap | Reason | Disposition |
|---|---|---|
| Agent clears `HTTP_PROXY` / `HTTPS_PROXY` | Enforcement is cooperative (env-var-based) | Kernel enforcement — Part II |
| HTTP/2 (gRPC) | Proxy handles HTTP/1.1 CONNECT tunnels | Protocol-aware handlers — Part II |
| Raw TCP (Postgres, MySQL, Redis, MongoDB wire protocols) | Non-HTTP, bypasses HTTP proxy | Per-protocol handlers — Part II |
| SSH | Does not use HTTP proxy env vars | Kernel interception — Part II |
| QUIC / UDP | UDP bypasses TCP proxy | Kernel interception — Part II |
| mTLS / client certificates | Credential used in TLS handshake, never at HTTP layer | Architectural constraint of the proxy model — see [findings](superpowers/findings/2026-04-13-transformed-credential-problem.md) Class 4 |
| AWS SigV4 (HMAC-signed requests) | Credential used as signing key, never appears on wire | **Surfaced by mismatch detector**; native signing — Part II |
| GitHub App JWTs, webhook HMAC signatures | Same as SigV4 (keyed-crypto, Class 2) | **Surfaced by mismatch detector**; native signing — Part II |
| OAuth offline token exchange (`gcloud`, Azure CLI) | Secret is traded for a bearer token *before* the request we see | Ephemeral brokering — Part II |
| Compressed request bodies | `Content-Encoding` bodies forwarded un-inspected | By design — decompression risks exceed the gap |
| Request bodies > 10 MiB | Performance boundary | Configurable in future release |
| Windows | No proxy substrate yet | Part II |

For a fuller treatment of what happens when mediation can't fire (and why the mismatch detector exists), see [`THREAT_MODEL.md`](THREAT_MODEL.md) and the [transformed-credential findings](superpowers/findings/2026-04-13-transformed-credential-problem.md).

---

# Part II — Aspirational Architecture (on the roadmap)

The MVP in Part I is the *primitive*. Part II is how that primitive expands into the full identity broker described in [`PRODUCT_FINAL.md`](PRODUCT_FINAL.md) §2 and §4, organized by the four outcomes. Each plane names its mechanism and the code seam it attaches to; detailed design is deferred to per-plane specs when the work is scheduled.

## Credential plane

- **Next — OAuth 2.1 ephemeral brokering.** Tokens minted at call-time by the proxy against an upstream issuer, scoped per-operation, cached for the operation's lifetime, never persisted to the agent. MCP is standardizing on OAuth 2.1, which makes this the natural first target. Seam: the current injection point (`Injector.ProcessRequest`) gains an ephemeral-resolution branch ahead of the literal-match path.
- **Horizon — native signer adapters.** AWS SigV4, GitHub App JWT, HMAC webhook signing, mTLS client-cert presentation. The proxy re-signs the request with the real credential after reconstructing the canonical form. Seam is the same transformation point as injection — "match a placeholder" becomes the narrow case of a broader "recognize a credential-shaped request, apply the correct transform." See [transformed-credential findings](superpowers/findings/2026-04-13-transformed-credential-problem.md) for the class-1/2/3 taxonomy this work follows.
- **Horizon — external backing stores.** HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault. Plugs into the existing `Keystore` interface (`internal/vault/keystore.go`). The Keychain and age-file backends are two of N; no other component changes.

## Policy plane

- **Next — declarative YAML policy engine.** Rules evaluate between injection and forward. Primitives: per-agent, per-service, per-operation — host allowlist, verb blocklist, path scope, rate limit. Denied requests return structured errors to the agent and flag the audit record. Seam: a new step in the proxy `OnRequest` pipeline, between the injector and the goproxy forward.
- **Horizon — learned scoping.** Per-credential, per-endpoint, per-agent baselines computed from the audit corpus. Veil suggests tighter policies when usage stabilizes; the user approves; next rotation enforces. This is the policy-recommendation loop in [`PRODUCT_FINAL.md`](PRODUCT_FINAL.md) §5.
- **Horizon — team inheritance and anomaly alerting.** Team-wide policy defaults, per-developer overrides. Anomaly signals on policy violations — "credential that has only ever hit `/users/me` just hit `/admin/keys`."

## Audit plane

- **Next — centralized team audit dashboard.** Local SQLite remains the source of truth per machine; events are additionally exported upstream. OpenTelemetry export subscribes at the same `audit.Store.Record` seam. Configurable retention.
- **Horizon — SIEM integrations.** Datadog, Splunk, Sumo Logic as additional subscribers. Compliance-evidence generation (SOC 2, ISO 27001) from the same corpus.
- **Horizon — anomaly baselines and threat-intel feed.** Rolling baselines per credential / endpoint / agent. Curated cross-customer threat signatures derived from the aggregate dataset — the compounding moat in [`PRODUCT_FINAL.md`](PRODUCT_FINAL.md) §5.

Every audit-plane capability reuses the MVP event shape. New columns are added under schema versioning; the envelope never gets replaced.

## Enforcement plane

- **Next — Windows.** Cooperative enforcement, same proxy model as macOS and Linux today. Mostly a distribution and CA-trust task, not an architecture change.
- **Next — shared credential store for teams.** End-to-end encrypted sync between team members' keystores. Same `Credential` record shape; sync mechanism is a new peer-level component above the keystore interface.
- **Horizon — kernel-level enforcement.** macOS `NETransparentProxyProvider` (system extension), Linux network namespaces + iptables `REDIRECT`. Non-bypassable by user-space code, per-process flow interception for all protocols. Closes the env-var bypass and the "non-standard HTTP client" bypass. Design is complete in [`docs/superpowers/specs/2026-04-14-egress-enforcement-design.md`](superpowers/specs/2026-04-14-egress-enforcement-design.md) (parked until funded). macOS requires an Apple Developer ID ($99/yr) and notarization; Linux requires a one-time `setcap CAP_NET_ADMIN` at install time.

The existing proxy, injector, vault, and audit components are unchanged by kernel enforcement — the enforcement primitive wraps them in a non-bypassable traffic funnel.

## Daemonization

[`PRODUCT_FINAL.md`](PRODUCT_FINAL.md) §3 describes "a local daemon on every developer machine." Today Veil is a per-session process — `veil run` starts it, it exits when the child exits. The step between is a long-running local daemon that persists the listener, the audit DB, and (in team mode) the synced credential store.

The parked egress-enforcement spec already describes the session-scoped primitives the daemon reuses: session-tagged proxy lifecycle, per-child scoping, graceful teardown. Daemonization adds a longer-lived parent process and an IPC surface for the CLI; it does not introduce a second mediation path.

---

# Part III — Evolution path

**What stays fixed across every stage:**

- The four core components and their boundaries — proxy, injector, vault, audit.
- The chokepoint. No stage introduces a second mediation path.
- The audit event envelope. New columns are added under schema versioning; the shape itself is stable.
- The "no agent cooperation" constraint. No stage introduces an SDK, callback, or required agent integration.

**What gets replaced:**

- **Enforcement primitive** — env-var → kernel funnel. Proxy code unchanged; its substrate changes.
- **Credential resolution** — literal match → literal match + Basic decoding (done) → + signer adapters → + ephemeral brokering. All attached to the same injection point.

**What gets added:**

- **Policy evaluator** between injection and forward.
- **Audit subscribers** (OTEL exporter, team sync, anomaly engine) on the existing event stream.
- **Keystore backends** (Vault, AWS/GCP/Azure SM) behind the existing interface.
- **Parent daemon** wrapping the current session-scoped runner.

The point of this layout is that none of Part II requires re-architecture. Every horizon capability attaches to a seam that already exists in Part I — which is the load-bearing claim.

---

# Part IV — Explicitly out of scope

Mirrors [`PRODUCT_FINAL.md`](PRODUCT_FINAL.md) §4 — two adjacent categories are *not* Veil's territory:

- **MCP supply-chain scanning.** MCPScan, Invariant Labs, and Snyk's agent-scan serve that market. Veil's mediation telemetry can complement scanners; Veil is not one.
- **Agent-behavior / prompt observability.** Prompt Security, Lakera, and Lasso serve that market. Veil emits credential and access events; Veil does not monitor general agent behavior.

These are load-bearing exclusions. Staying narrow is what makes the primitive compound — the moat in [`PRODUCT_FINAL.md`](PRODUCT_FINAL.md) §5 is one event type in one store, and that breaks if the architecture absorbs adjacent categories.

---

## References

- [`PRODUCT_FINAL.md`](PRODUCT_FINAL.md) — vision, four-outcome model, compounding-dataset thesis.
- [`MVP.md`](MVP.md) — shipping scope, CLI surface, success criteria.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — what Veil protects against, what it doesn't, deployment notes for hardened setups.
- [`superpowers/specs/2026-04-14-egress-enforcement-design.md`](superpowers/specs/2026-04-14-egress-enforcement-design.md) — parked kernel-enforcement design.
- [`superpowers/findings/2026-04-13-transformed-credential-problem.md`](superpowers/findings/2026-04-13-transformed-credential-problem.md) — transformation-class taxonomy that shapes the credential plane roadmap.
