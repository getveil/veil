# Veil Threat Model

Veil sits between AI coding agents and the network. It hides real secrets behind format-preserving placeholders, stores the real values in an encrypted per-project vault, and runs a local MITM proxy that swaps placeholders for real credentials on outbound requests.

This document describes what Veil protects against, what it does *not* protect against, and the deployment choices that change those boundaries.

## What Veil protects against

- **Agent seeing real secrets in files.** `.env` and MCP config files contain format-valid placeholders; the agent's filesystem reads return those, never the real value.
- **Agent exfiltrating real secrets in outbound HTTP.** The proxy intercepts request headers, URL query strings, and text-ish request bodies. If the agent tries to ship a real credential it never legitimately saw, it simply cannot — it has no handle on the real value.
- **Same-host users reading the audit log.** Audit DB files are chmod'd to `0600` and the parent directory to `0700` on every `veil run`. Other users on the machine cannot read which credentials were injected, for which hosts, or when.

## What Veil does NOT protect against

- **Same-UID tampering of the audit log.** The agent process runs as the same UID as Veil, so it has filesystem access to the audit DB. It can read, truncate, or forge rows. If your agent is compromised, its audit trail is untrustworthy.
- **Long-running proxy holding credentials in memory.** While `veil run` is active, real secrets sit in the proxy's memory for routing. A memory read via `/proc/<pid>/mem` or a debugger can extract them. This is by design — format-preserving injection requires the real value.
- **Non-HTTP exfiltration.** Veil only mediates `HTTP_PROXY` / `HTTPS_PROXY` traffic. An agent that opens a raw TCP connection, sends DNS queries with data embedded in names, or uses any other channel is out of scope.
- **Agent direct vault reads.** If the agent runs tools (shell, file read) it may open `.veil/vault.bin` directly. The vault is encrypted, but the master key is obtainable via the OS keyring by any process running as the same user.
- **System CA trust store compromise.** Veil installs its root CA into the user's trust store. Any process (not just the agent) running as that user will trust certificates signed by Veil's CA.
- **Secrets consumed by keyed cryptography (unmediated schemes).** Credentials that an agent combines with request bytes via HMAC, asymmetric signing, or a similar keyed transform (e.g. webhook HMAC signatures, mTLS handshakes) never appear in the outgoing request in a form Veil can match. The placeholder reaches Veil unchanged; the request fails upstream with 401/403. Veil's transform-mismatch detector emits a diagnostic WARN when this happens on a credentialed host, but it is a signal, not enforcement — the real secret still exists wherever the agent read it from, and a malicious agent could exfiltrate it before signing. AWS SigV4 and GitHub App JWT are no longer in this category — see "Class 2 (keyed cryptography)" below.

## Class 2 (keyed cryptography)

Veil mediates AWS SigV4 and GitHub App JWT signatures at the proxy. For each
mediated scheme, the request is blocked with 502 if the scheme is recognized,
Veil owns the host, but signing cannot complete (see `SignerError` in the
audit log).

Scoped gaps:
- The fail-closed sentinel check in `detectLeak` cannot fire on a leaked RSA
  private key PEM, because the placeholder PEM cannot embed the sentinel
  without breaking PEM parsing. JWT-signature-based identification is the
  primary mediation mechanism.
- GitHub App installation tokens (`ghs_…`) returned in response bodies are
  not mediated; the agent holds a short-lived real token for up to an hour.
  This is a Class 3 (offline exchange) problem and out of scope.

## Deployment notes for hardened setups

- **Separate UID.** Running Veil under a user different from the agent eliminates same-UID tampering and direct vault reads. This requires a setuid helper or systemd/launchd user service configuration; not supported out-of-the-box in MVP.
- **Short-lived sessions.** Keep `veil run` sessions as short as possible to minimize the in-memory credential window.
- **Network-level egress rules.** Pair Veil with outbound firewall rules so the agent cannot reach hosts outside the expected provider set.
- **Kernel-level enforcement (planned).** Post-MVP, Veil will support `NETransparentProxyProvider` (macOS) and network namespaces + iptables (Linux) for non-bypassable, per-process traffic interception across all protocols. This eliminates the env-var bypass vector and extends coverage beyond HTTP/HTTPS. See [Architecture](ARCHITECTURE.md) for the planned path.

## Known limitations called out in the code

- **Compressed request bodies.** Bodies with a `Content-Encoding` header pass through untouched; Veil does not decompress→inject→recompress.
- **Body injection allowlist.** Only `application/json`, `application/x-www-form-urlencoded`, `text/*`, `application/xml`, and `application/*+json`/`*+xml` are scanned. Binary types and unknown Content-Types pass through.
- **Large bodies.** Bodies larger than 10 MiB are not scanned.
