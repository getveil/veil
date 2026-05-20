# Veil Threat Model

Veil sits between AI coding agents and the network. It hides real Bearer
secrets behind format-preserving placeholders, stores the real values in
an encrypted per-project vault, and runs a local MITM proxy that swaps
placeholders for real credentials on outbound HTTPS requests.

This document describes what Veil protects against, what it does *not*
protect against, and the deployment choices that change those boundaries.

## What Veil protects against

- **Agent seeing real secrets in `.env` files.** `.env` files contain
  format-valid placeholders; the agent's filesystem reads return those,
  never the real value.
- **Agent exfiltrating real secrets in outbound HTTP.** The proxy
  intercepts request headers, URL query strings, and text-ish request
  bodies. If the agent tries to ship a real credential it never
  legitimately saw, it simply cannot — it has no handle on the real
  value.
- **Same-host users reading the audit log.** Audit DB files are chmod'd
  to `0600` and the parent directory to `0700` on every `veil run`.
  Other users on the machine cannot read which credentials were
  injected, for which hosts, or when.

## What Veil does NOT protect against

- **Same-UID tampering of the audit log.** The agent process runs as the
  same UID as Veil, so it has filesystem access to the audit DB. It can
  read, truncate, or forge rows. If your agent is compromised, its
  audit trail is untrustworthy.
- **Long-running proxy holding credentials in memory.** While `veil run`
  is active, real secrets sit in the proxy's memory for routing. A
  memory read via `/proc/<pid>/mem` or a debugger can extract them. We
  accept this by design — format-preserving injection requires the real
  value.
- **Non-HTTP exfiltration.** Veil only mediates `HTTP_PROXY` /
  `HTTPS_PROXY` traffic. An agent that opens a raw TCP connection,
  sends DNS queries with data embedded in names, or uses any other
  channel is out of scope.
- **Secrets Veil does not manage.** v1 covers `Authorization: Bearer`
  credentials sourced from `.env` files. Secrets stored elsewhere
  (shell environment, MCP config files, application-managed
  credential stores) and credentials consumed by schemes Veil does not
  rewrite (HTTP Basic, AWS SigV4, GitHub App JWT, HMAC webhook
  signing, mTLS) remain in their original form. The agent reads and
  uses those real values unmediated. v1 is explicit about this — it
  is not silent failure but a documented exclusion (see
  [MVP.md §5](MVP.md)).
- **Agent direct vault reads.** If the agent runs tools (shell, file
  read) it may open `.veil/vault.bin` directly. The vault is
  encrypted, but the master key is obtainable via the OS keyring by
  any process running as the same user.
- **Placeholder fingerprinting via sentinel substring.** Every
  Veil-generated placeholder embeds a literal `VEIL` substring as a
  fail-closed leak sentinel; an agent that scans its inputs for
  `VEIL` can identify which `.env` values are placeholders. The agent
  learns nothing about the real secret. This is consistent with the
  *cooperative-but-curious* model — guaranteed detectability of a
  leaked placeholder is a stronger property than indistinguishability.
- **Same-session CA misuse.** Veil's CA is not installed in any OS or
  browser trust store. At `veil run` time, the CA is exposed to the child
  process only — via `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`,
  `CURL_CA_BUNDLE`, and `REQUESTS_CA_BUNDLE`. Anything launched by that
  child (subprocesses, shell-outs) inherits those vars and therefore
  trusts the CA for the duration of the session. Veil does not protect
  against a compromised agent abusing its own session-scoped trust to
  intercept TLS within its own process tree. This is a deliberately
  narrower scope than a system-installed root would have.

## What's not covered by the CA bundle injection

Some HTTPS clients ignore the standard `SSL_CERT_FILE` /
`NODE_EXTRA_CA_CERTS` / `CURL_CA_BUNDLE` / `REQUESTS_CA_BUNDLE`
environment variables and therefore will *not* trust Veil's CA when
launched under `veil run`. These include the JVM (which reads
`$JAVA_HOME/lib/security/cacerts`), Firefox (which uses its own NSS
store), native macOS apps that go through Apple's SecureTransport /
Network.framework APIs directly, and Go binaries that compile in their
own root pool via `crypto/x509`. Requests from these clients will fail
TLS verification at Veil's proxy. We accept this as an intentional limit
on blast radius: a CA that's only trusted by processes Veil itself
launched cannot be silently abused by anything else on the user's
machine.

## Deployment notes for hardened setups

- **Separate UID.** Running Veil under a user different from the agent
  eliminates same-UID tampering and direct vault reads. This requires
  a setuid helper or systemd/launchd user service configuration; not
  supported out-of-the-box in v1.
- **Short-lived sessions.** Keep `veil run` sessions as short as
  possible to minimize the in-memory credential window.
- **Network-level egress rules.** Pair Veil with outbound firewall
  rules so the agent cannot reach hosts outside the expected provider
  set.

## Known limitations called out in the code

- **Compressed request bodies.** Requests with a non-`identity`
  `Content-Encoding` header are rejected with HTTP 502 (fail-closed).
  Veil does not decompress→inject→recompress, and refuses to forward
  payloads it cannot scan.
- **Body injection allowlist.** Only `application/json`,
  `application/x-www-form-urlencoded`, `application/xml`,
  `application/yaml`, `application/x-yaml`, `application/toml`,
  `application/x-ndjson`, `application/graphql`, `text/*`, and
  `application/*+json`/`*+xml` are scanned. Binary types and unknown
  Content-Types pass through.
- **Large bodies.** Bodies larger than 10 MiB are not scanned.
