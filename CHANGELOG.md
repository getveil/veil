# Changelog

All notable changes to Veil are documented in this file. The format is based on
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org). While Veil is pre-1.0,
expect breaking changes in any 0.x release; we will call them out under
**Changed** / **Removed** where they occur.

## [Unreleased]

## [0.1.0] — 2026-MM-DD

First public release. The date will be filled in at tag time — see
[`docs/LAUNCH_v0.1.0.md`](docs/LAUNCH_v0.1.0.md), pre-flight step 1.

### Added

#### Proxy and credential injection
- Local HTTPS proxy that intercepts outbound traffic from any HTTP client
  respecting `HTTP_PROXY` / `HTTPS_PROXY` — Claude Code, Cursor, `curl`, the
  standard language SDKs, and `gh`. The agent sees only placeholders; Veil
  swaps in real credentials at the network boundary.
- Format-aware placeholders for 22+ providers across cloud, AI, dev tooling,
  and messaging: AWS (access keys + secret + STS session tokens), GitHub
  (PATs + App private keys), OpenAI, Anthropic, Google, Stripe, Slack,
  Twilio, SendGrid, Resend, Postmark, Supabase, Vercel, Replicate, Hugging
  Face, Datadog, GitLab, npm, PyPI, Docker Hub, Quay, GCR. Plus a
  character-class fallback for unknown formats — the placeholder matches the
  original credential's length and character class so regex-based consumers
  still see the right type.
- SigV4 re-signing for AWS requests so swapped credentials produce correct
  signatures at the proxy boundary.
- Fail-closed guard: if a placeholder body or basic-auth header somehow
  reaches the outbound request after rewriting, the request is rejected
  rather than forwarded raw.

#### Vault and keystores
- OS keychain abstraction with auto-detect:
  - **macOS:** Keychain via the `zalando/go-keyring` Security framework
    bridge.
  - **Linux:** Secret Service (libsecret / gnome-keyring) via D-Bus.
  - **Fallback:** age-encrypted file keystore when no OS keystore is
    available, with a passphrase prompted on first use and cached in the
    OS keystore where possible.
- Per-secret metadata: name, placeholder, source file, created/updated
  timestamps, surfaced by `veil list` and `veil status`.

#### Scanning and migration
- `veil init` scans `.env` files at the project root, detects secret-like
  values, and migrates them into the vault — leaving format-aware
  placeholders behind. Atomic per-file: a partial migration leaves the
  original `.env` intact.
- MCP config scanning: auto-detects plaintext tokens in MCP server
  configuration files (Claude Desktop, Cursor, etc.) and migrates them
  alongside `.env` secrets.
- `veil uninstall` reverses everything: restores original `.env` and MCP
  files from backups, wipes the vault, removes audit state. Diff-then-
  confirm by default; `--dry-run` previews the plan without changes.

#### Audit log
- SQLite audit log at `.veil/audit.db` records every credential injection,
  agent action, and proxy decision with a correlation ID.
- `veil log` query interface with `--since`, `--placeholder`, `--host`, and
  `--correlate` filters for triage and audit replay.

#### CLI subcommands
- `veil init`, `run`, `status`, `add`, `list`, `log`, `remove`, `skip`,
  `uninstall`.
- Shell completions for bash, zsh, and fish, auto-installed via Homebrew.
- TTY-aware coloured output with `--color` / `--no-color` overrides and
  honour for the `NO_COLOR` environment variable.

#### Distribution and verification
- Homebrew tap install: `brew install getveil/tap/veil` on macOS and Linux.
- Pre-built static binaries (`CGO_ENABLED=0`) for darwin and linux
  (amd64 + arm64) on every tagged release.
- SHA-256 `checksums.txt` per release.
- Sigstore/cosign keyless signature on `checksums.txt`, anchored to the
  GitHub Actions OIDC issuer for the `getveil/veil` release workflow.
- syft-generated SBOM per archive, attached to the release.
- SLSA build-provenance attestations via `actions/attest-build-provenance@v2`,
  verifiable with `gh attestation verify <file> --repo getveil/veil`.

#### Platform support
- macOS amd64 and arm64.
- Linux amd64 and arm64.
- Windows: deferred. The dependency chain (`zalando/go-keyring`, `modernc.org/sqlite`)
  supports it, but it is not exercised in CI and has not been hardened.

### Security

- Vulnerability disclosure policy in [SECURITY.md](SECURITY.md): GitHub
  private advisory reporting, 72-hour response target, coordinated disclosure
  with a 90-day default window.
- Threat model documented in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md):
  Veil assumes a *cooperative-but-curious* agent and is not a sandbox for an
  agent with arbitrary code execution. Hostile-agent scenarios need OS-level
  isolation, not a proxy.
- The proxy's CA certificate is generated locally, stored in the **user-scoped**
  trust store only (never system-wide), and its private key never leaves the
  machine.
- Release artifacts are signed (cosign) and attested (SLSA). End-user
  verification instructions live in [README.md](README.md#direct-download).

[Unreleased]: https://github.com/getveil/veil/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/getveil/veil/releases/tag/v0.1.0
