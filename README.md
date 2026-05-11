# Veil

**.gitignore protected your secrets from git. Veil protects them from AI.**

Veil is a local CLI that sits between your AI coding agents and the network via a local HTTPS proxy. It replaces real secrets with format-aware placeholders, then injects the real credentials at the proxy layer — so the agent never sees them. Works with any agent or tool that respects `HTTP_PROXY`/`HTTPS_PROXY` environment variables, including Claude Code, Cursor, curl, and most HTTP clients.

## How it works

1. `veil init` scans your `.env` files and MCP configs, moves secrets into your OS keychain, and drops in placeholders that look real (correct prefix, length, charset).
2. `veil run <agent>` starts a local HTTPS proxy and launches your agent with `HTTP_PROXY`/`HTTPS_PROXY` set. The proxy swaps placeholders for real credentials on outbound requests.
3. Every credential injection and agent action is logged to local SQLite. Query with `veil log`.

The agent thinks it has real tokens. It doesn't.

## Install

### Homebrew (macOS, Linux)

```
brew install getveil/tap/veil
```

This is the recommended path — installs are auto-deduplicated and the
binary is placed by a trusted local process, so macOS Gatekeeper does
not flag it.

### Direct download

Grab the tarball for your platform from the
[Releases page](https://github.com/getveil/veil/releases/latest),
then verify and install:

```bash
# Pick your platform
PLAT=darwin_arm64   # or darwin_amd64, linux_amd64, linux_arm64
TAG=v0.1.0          # latest release tag

# Verify SHA-256 checksum
grep "veil_${TAG#v}_${PLAT}.tar.gz" checksums.txt | shasum -a 256 -c -

# Verify Sigstore signature on checksums.txt
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/getveil/veil/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# Optional: verify GitHub build-provenance attestation
gh attestation verify "veil_${TAG#v}_${PLAT}.tar.gz" --repo getveil/veil

# Install
tar -xzf "veil_${TAG#v}_${PLAT}.tar.gz"
sudo mv veil /usr/local/bin/
```

> **macOS Gatekeeper note:** if you downloaded the tarball through a
> browser, the extracted binary may be quarantined. Run once via right-click
> → Open, or strip the attribute: `xattr -d com.apple.quarantine
> /usr/local/bin/veil`. Apple Developer ID notarization is tracked for a
> future release. Homebrew installs are not affected.

### From source (developers)

```
go install github.com/getveil/veil/cmd/veil@latest
```

Or:

```
git clone https://github.com/getveil/veil.git
cd veil
make build
# binary at bin/veil
```

## Usage

```bash
# Initialize - migrate secrets to keychain, drop in placeholders
veil init

# Run an agent through the proxy
veil run claude
veil run cursor

# Check what's managed
veil status
veil list

# Add a secret manually
veil add GITHUB_TOKEN --value ghp_abc123

# View audit logs
veil log
veil log --since 1h

# Reverse it - restore original .env/MCP files, wipe vault and state
veil uninstall              # prompts with diff before touching anything
veil uninstall --dry-run    # preview the plan without changes
```

## What it supports

- **Secrets**: AWS, Stripe, GitHub PATs, OpenAI, Slack, Twilio, SendGrid, Supabase, and more — with format-aware placeholders for each
- **Keychain**: macOS Keychain, Linux Secret Service (with age-encrypted file fallback)
- **Agents**: Anything that respects `HTTP_PROXY` / `HTTPS_PROXY`
- **MCP configs**: Auto-detects and migrates plaintext tokens from MCP configuration files

## Project structure

```
cmd/veil/       CLI entrypoint
internal/
  cli/          Command definitions (init, run, status, add, list, log, remove, skip, uninstall)
  proxy/        HTTPS proxy with credential injection
  vault/        OS keychain abstraction
  placeholder/  Format-aware placeholder generation
  scanner/      .env file discovery
  audit/        SQLite audit logging
  config/       Project config management
  envkeys/      Canonical env-var key list (proxy + CA bundle)
  mcpconfig/    MCP config file parsing
  runner/       Agent process management
  skiphost/     Persistent skip-host list
  ui/           Terminal output
```

## Development

```bash
make build      # build binary
make test       # run tests
make test-race  # run tests with race detector
make vet        # go vet
make lint       # golangci-lint
```

## Security

See [Threat Model](docs/THREAT_MODEL.md) for the boundaries of Veil's protection.

## License

MIT
