> **Status: PARKED** — This design describes kernel-level enforcement (NetworkExtension on macOS, network namespaces + iptables on Linux) which is deferred to post-YC/post-funding. The MVP ships with env-var-based HTTPS proxy enforcement. See [docs/ARCHITECTURE.md](../../ARCHITECTURE.md) for the current architecture.

# Veil Egress Enforcement

**Date:** 2026-04-14
**Scope:** Control stage hardening. Closes the env-var bypass and the "non-standard HTTP client" bypass for HTTP/HTTPS traffic. Establishes the substrate for future protocol-aware credential handlers.
**Target threat model:** Cooperative-but-clumsy agents (A) and prompt-injected agents using standard tools (B). Fully adversarial agents with arbitrary code execution (C) are out of scope.
**Defining use case:** `veil run claude` preserves full feature parity with bare `claude` for every legitimate dev workflow, while making every outbound HTTP/HTTPS request from the child process tree route through Veil regardless of environment variables, HTTP client library, or bypass attempts.

---

## Motivation

Today, Veil forces agent traffic through the proxy by setting `HTTP_PROXY` and `HTTPS_PROXY` on the child environment. This is advisory, not enforced:

- `env -u HTTPS_PROXY curl https://api.example.com` bypasses the proxy.
- HTTP client libraries that don't honor `HTTP_PROXY` (many Go, Rust, and custom SDK clients) bypass the proxy.
- Raw `connect()` to any host on any port bypasses the proxy.

The pitch — "the security layer that works when the agent goes off-script" — implies enforcement the architecture does not deliver. This design closes that gap for HTTP/HTTPS traffic and establishes the mechanism for eventually extending enforcement to every protocol.

---

## Constraints

- macOS and Linux only. No Windows.
- `veil run` itself remains unprivileged. Any setup requiring root happens once at `veil init` time (Linux) or is gated by a prompt (macOS pf anchor installation).
- Full feature parity with bare `claude` in default mode. SSH, remote DB clients, Redis, Mongo, raw TCP — all continue to work.
- Non-HTTP credential vaulting (Postgres password swap, SSH key swap, etc.) is explicitly **out of scope** for this spec. The firewall is designed so these can be added later without re-architecture.
- No cloud dependency, no external daemons. Firewall rules are installed and torn down by `veil run` itself.

---

## Non-Goals

- Sandboxing the agent process against filesystem access.
- Blocking non-HTTP exfiltration in default mode. (Strict mode blocks it.)
- Credential injection for non-HTTP protocols.
- Controlled DNS resolution. DNS continues to use the host resolver.
- Windows support.

---

## Section 1: Core Design

### 1.1 Enforcement Primitive

Veil enforces egress via **per-session NAT redirect** scoped to the child process tree. Packets from the child (or its descendants) destined for port 443 or port 80 are rewritten at the kernel level to arrive on Veil's loopback listener. The proxy uses the original destination to perform MITM as it does today.

This replaces reliance on the child process respecting `HTTP_PROXY`. The env vars remain set for clients that prefer explicit proxying, but they are no longer the enforcement boundary — the kernel is.

### 1.2 Per-Session Scoping

Rules are scoped so they cannot affect processes outside the current `veil run` invocation:

- **Linux:** the child is launched inside a new network namespace. Rules are installed in that netns. Namespace and rules are destroyed when the child exits. The netns communicates with the host network via a veth pair; the host end is tagged for cleanup by session id.
- **macOS:** Veil installs a pf anchor scoped by the child's process group id. On shutdown, the anchor's rules are flushed. The top-level anchor loader in `/etc/pf.anchors/veil` is installed once at `veil init` time and persists; it loads Veil's per-session sub-anchors only when the pf ruleset references them.

Session scoping guarantees: (a) rules from a crashed `veil run` cannot leak and block unrelated traffic, (b) two concurrent `veil run` invocations in different terminals don't interfere, (c) the user's other shells see no change in networking.

### 1.3 Handler Dispatcher

The proxy's entry point is a port-agnostic connection acceptor. For each incoming connection it:

1. Looks up the original destination via `SO_ORIGINAL_DST` (Linux) or pf state lookup (macOS).
2. Peeks the first bytes of the stream to identify the protocol.
3. Dispatches to a registered handler by `(port, protocol)`.

Today's handlers: `(443, TLS)` → MITM TLS termination and HTTP proxy; `(80, HTTP)` → plain HTTP proxy. Both reuse the existing `goproxy`-backed code path.

Future handlers (Postgres, MySQL, etc.) register against new ports. The firewall rule set grows by one line per protocol; the dispatcher gains one branch. No other architectural change.

---

## Section 2: Modes

### 2.1 Default Mode — `veil run <agent>`

- Ports 80 and 443 from the child tree are redirected to the proxy.
- All other outbound traffic passes through unchanged.
- Non-HTTP outbound connections (destination host, destination port, child pid, timestamp) are recorded to the audit DB as `egress` events. These are visible via `veil log --egress` but do not block traffic.
- DNS uses the host resolver.
- Loopback traffic (`127.0.0.0/8`, `::1`) is exempt from all rules. Local dev servers and IPC continue to work.

Feature parity with bare `claude`:

| Use case | Behavior |
|---|---|
| `curl https://api.github.com` | Redirected to proxy, MITM'd, placeholder swapped. |
| `env -u HTTPS_PROXY curl https://api.github.com` | Redirected to proxy anyway. Env var is no longer load-bearing. |
| `git push` over HTTPS | Redirected, works. |
| `git push` over SSH | Passes through unchanged, works. Destination logged. |
| `psql postgresql://db.internal:5432/app` | Passes through unchanged, works. Destination logged. Password is still a placeholder (not vaulted for non-HTTP; see Non-Goals). |
| `ssh user@host` | Passes through unchanged. Destination logged. |
| Local dev server on `localhost:3000` | Unaffected. |
| Agent opens raw TCP to `collector.attacker.com:9000` | Passes through. Destination logged — visible in audit. Not blocked. |

### 2.2 Strict Mode — `veil run --strict <agent>`

- Everything default mode does.
- Plus: a default-drop rule for the child tree. Any outbound connection not redirected to the proxy and not on the explicit allowlist is dropped.
- The allowlist is managed via `veil allow <host> <port>` / `veil deny <host> <port>`, persisted per-project alongside `skip_hosts`.
- Connections dropped by the strict rule are recorded as `blocked` events and visible via `veil log --blocked`.
- `--strict` can be set as the project default via `veil init --strict`, which persists a flag in project state that `veil run` honors without the flag.
- DNS (UDP/53 and TCP/53 to the host-configured resolvers) is exempt from the default-drop rule so name resolution continues to work. This is a known gap — a compromised agent could use DNS queries as a low-bandwidth exfil channel. Controlled DNS is an explicit non-goal for this spec; the gap is tracked for a follow-up that binds a Veil-owned resolver in the child's netns.

Feature-parity impact in strict mode:

| Use case | Behavior |
|---|---|
| `curl https://api.github.com` | Redirected, works. |
| `git push` over SSH | Dropped unless `github.com:22` is allowlisted. Clear error + audit event. |
| `psql postgresql://db.internal:5432/app` | Dropped unless `db.internal:5432` is allowlisted. |
| Agent opens raw TCP to `collector.attacker.com:9000` | Dropped. Audit event. |

Strict mode is opt-in precisely because it breaks workflows that default mode preserves. The tradeoff is made explicit.

---

## Section 3: Platform Mechanics

### 3.1 Linux

- At `veil run` start: create a new network namespace, set up a veth pair (`veilN0` in host, `veth0` in netns), assign `10.0.N.1/30` to the host end, `10.0.N.2/30` to the netns end, configure default route through the host end, NAT traffic from `10.0.N.0/30` on the host. `N` is derived from the session id.
- Inside the netns, install:
  - `iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports <proxy-port>`
  - `iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports <proxy-port>`
  - (Strict only) `iptables -A OUTPUT -j LOG --log-prefix "veil-blocked "` then `-j DROP` for anything not matched by the allowlist and not redirected.
- The proxy binds to loopback inside the netns (the child's loopback). The existing proxy server continues to bind loopback; it simply runs in the netns context.
- On shutdown, destroy the netns. All rules and the veth pair go with it.
- Privilege: requires `CAP_NET_ADMIN`. We document a one-time `setcap cap_net_admin+ep /usr/local/bin/veil` during `veil init` (or distribute as a setcap'd binary via package managers). No per-run `sudo`.

### 3.2 macOS

- At `veil init` time, with user confirmation, Veil installs a loader anchor at `/etc/pf.anchors/veil` and a `pf.conf` include referencing it. This is the only step requiring `sudo`.
- At `veil run` start: Veil writes a per-session anchor file (e.g., `/etc/pf.anchors/veil/session-<id>`) containing:
  - `rdr on lo0 proto tcp from any to any port 443 -> 127.0.0.1 port <proxy-port>` scoped by `user <child-uid>` or by a pf-tagged group id.
  - `rdr` for port 80 similarly.
  - (Strict only) `block out quick proto tcp` for the scope, with explicit `pass` rules for allowlisted destinations.
- `pfctl -a veil/session-<id> -f <anchor-file>` loads the rules; the existing loader anchor picks them up.
- On shutdown, `pfctl -a veil/session-<id> -F all` flushes the session's rules.
- Scoping: macOS pf supports `user` and `group` filters. Veil launches the child with a stable per-session gid (inherited by descendants) and scopes rules to that gid. No per-session uid is needed, which avoids filesystem permission complications.
- Privilege: `pfctl` invocations during `veil run` require membership in group `_pfctl` or equivalent. We prefer a small setuid helper binary (`veil-pf-helper`) installed at `veil init` time that only accepts anchor load/flush for anchor names matching `veil/session-*`, rather than running the whole CLI with elevated privilege.

---

## Section 4: Audit Extensions

### 4.1 New Event Types

The audit DB gains two event kinds in addition to `injection`:

- `egress` — non-HTTP outbound connection observed in default mode. Columns: `timestamp`, `session_id`, `agent_pid`, `dest_host`, `dest_port`, `protocol_hint` (best-effort classification from first bytes, e.g., "ssh", "postgres", "unknown").
- `blocked` — connection dropped by strict mode. Same columns as `egress`.

### 4.2 Query Surface

`veil log` gains:

- `--egress` — show only egress events.
- `--blocked` — show only blocked events.
- `--all` — show all event kinds (injections, egress, blocked) interleaved by timestamp.

Existing filters (`--since`, `--host`) work across all event kinds.

---

## Section 5: CLI Surface Changes

| Command | Change | Phase |
|---|---|---|
| `veil init` | Installs pf loader anchor on macOS (with `sudo` prompt). Prints one-time setcap instructions on Linux if needed. | 1 |
| `veil init` | New `--strict` flag. Persists strict default in project state. | 2 |
| `veil run` | New `--strict` / `--no-strict` flags override the project default. | 2 |
| `veil log` | New `--egress` and `--all` flags. | 1 |
| `veil log` | New `--blocked` flag. | 2 |
| `veil allow <host> <port>` | New command. Adds an entry to the strict-mode allowlist for this project. | 2 |
| `veil deny <host> <port>` | New command. Removes an allowlist entry. | 2 |
| `veil list --allow` | New flag. Lists strict-mode allowlist entries. | 2 |
| `veil status` | Reports whether strict mode is enabled and the current allowlist size. | 2 |

The existing `veil skip` (proxy bypass via `NO_PROXY`) remains for a different purpose: it tells the proxy not to MITM specific hosts even though traffic is still redirected. Skip and allow are orthogonal.

---

## Section 6: Pitch Honesty

With this shipped, the updated pitch reads:

> *Every HTTP request your agent makes — however it makes it, whether via a standard library, a custom client, or even after clearing `HTTP_PROXY` — routes through Veil. Non-HTTP traffic is logged by default and can be blocked with strict mode. Protocol-aware credential vaulting for databases and SSH is on the roadmap.*

This is defensible: the architecture delivers what the words claim. The "off-script agent" language becomes honest for HTTP, with an explicit roadmap to honesty across all protocols.

---

## Section 7: Rollout

This spec is large enough to split into two implementation phases:

**Phase 1 — Default mode.** NAT redirect for 80/443 + per-session scoping + handler dispatcher + egress audit events. No strict mode, no allowlist, no new `veil allow`/`deny` commands. Ships the core architectural change with minimal CLI surface.

**Phase 2 — Strict mode.** Default-drop rule + allowlist + `veil allow`/`deny` + blocked audit events + strict-related `veil log` flags.

Phase 1 is the architectural bet: if the redirect substrate works cleanly on both platforms and doesn't regress workflows, Phase 2 is straightforward. Implementation plans should be written independently for each phase.

---

## Section 8: Open Questions for Implementation

These are items the implementation plan needs to resolve but that don't block the design:

- Linux: whether to ship with `setcap` requirement or use a setuid helper analogous to the macOS approach, for consistency across platforms.
- macOS: exact pf syntax for pgroup-scoped rules across 12+ macOS versions. May need a compatibility matrix.
- Netns IP allocation: how to pick non-conflicting `10.0.N.0/30` blocks when `N` collisions happen across users or other local consumers of RFC1918 space.
- Protocol detection for audit hints: how many bytes to peek before giving up and labeling "unknown". Affects both latency and classification accuracy.
- Strict mode first-run UX: should `veil init --strict` run a workflow probe to pre-populate the allowlist with obvious entries (git remotes, package registries)?
- How to observe non-HTTP connections in default mode for the `egress` audit events without redirecting the traffic. Candidates: Linux `iptables -j NFLOG` with a userspace consumer; macOS pf `log` interface + `pflog0` sniffer; or eBPF/`dtrace` as alternatives. Picked mechanism affects the audit engine's runtime dependencies.
