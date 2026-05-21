<img src=".github/banner.png" alt="veil — the .gitignore for AI agents" width="100%" />

[![CI](https://github.com/getveil/veil/actions/workflows/ci.yml/badge.svg)](https://github.com/getveil/veil/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/getveil/veil.svg)](https://pkg.go.dev/github.com/getveil/veil)
![Go Version](https://img.shields.io/github/go-mod/go-version/getveil/veil)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Made for AI agents](https://img.shields.io/badge/made_for-AI_agents-7c3aed)

**.gitignore protected your secrets from git. Veil protects them from AI.**

Veil moves the Bearer API keys in your `.env` into your OS keychain, leaves
format-preserving placeholders behind, and injects the real values at a local
HTTPS proxy so the agent never sees them. One promise, one wire, no daemon.

> **What's in scope.** v1 mediates HTTP `Authorization: Bearer` credentials
> for the providers listed below, sourced from `.env` files. HTTP Basic,
> keyed-crypto schemes (AWS SigV4, GitHub App JWTs, HMAC webhooks), shell
> environment variables, MCP config files, and non-HTTP protocols are not in
> scope — Veil leaves them alone. See [docs/MVP.md](docs/MVP.md) for the full
> contract.

## Demo

![Veil blocks an AI agent from leaking a GitHub token to the wrong host](.github/demo.gif)

> Want to run it yourself? `make build && ./scripts/record-demo.sh` records this end-to-end against a synthetic `.env`.

## Why this exists

Your AI agent can read every secret in your project — every `.env` it
stumbles across in your code. `.gitignore` stopped this at the git boundary
years ago. Nothing has stopped it at the AI boundary. Veil is that
gap-filler.

## How it works

1. `veil init` scans your `.env` files, moves Bearer secrets into your OS keychain, and drops in placeholders that look real (correct prefix, length, charset).
2. `veil run <agent>` starts a local HTTPS proxy and launches your agent with `HTTP_PROXY` / `HTTPS_PROXY` set. The proxy swaps placeholders for real credentials on outbound `Authorization: Bearer` requests.
3. Every credential injection and agent action is logged to local SQLite. Query with `veil log`.

The agent thinks it has real tokens. It doesn't.

## Quick start

```
brew install getveil/tap/veil
veil init
veil run claude
```

That's the whole flow. `veil init` migrates secrets out of `.env` and
generates a local CA on disk; `veil run claude` (or `cursor`, `curl`,
anything that honours `HTTPS_PROXY`) routes outbound traffic through the
proxy and injects the CA into that child process only — your system trust
store is left untouched.

## Install

### Homebrew (macOS, Linux)

```
brew install getveil/tap/veil
```

This is the recommended path — installs are auto-deduplicated and the
binary is placed by a trusted local process, so macOS Gatekeeper does
not flag it.

> **Linux without a system keyring** (CI, headless servers, minimal
> containers): Veil cannot reach a Secret Service daemon, so it falls
> back to an age-encrypted key file under `~/.local/state/veil/`. You
> must set `VEIL_PASSPHRASE` in your environment before every `veil init`
> / `veil run` invocation — Veil exits with an error if it is missing.
> See [docs/MVP.md §4](docs/MVP.md#4-operating-requirements) for the full
> contract.

<details>
<summary><strong>Other install methods</strong> (<code>go install</code>, from source)</summary>

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

</details>

## Usage

```bash
# Initialize — migrate Bearer secrets in .env to keychain, drop in placeholders
veil init

# Run an agent through the proxy
veil run claude
veil run cursor

# Check what's managed
veil status
veil list

# Add a Bearer credential manually (e.g. for a custom internal API)
veil add INTERNAL_TOKEN --value-stdin --host api.mycompany.com

# View audit logs
veil log
veil log --since 1h
veil log --blocked   # see what veil prevented from leaving

# Reverse it — restore original .env files, wipe vault and state
veil uninstall              # prompts with diff before touching anything
veil uninstall --dry-run    # preview the plan without changes
```

## What it supports

| | Status |
|---|---|
| **Bearer providers** | GitHub PATs · OpenAI · Anthropic · Stripe · Slack · SendGrid · Resend · Supabase · Vercel · Replicate · Hugging Face · Google · GitLab |
| **Unknown Bearer secrets** | Detected and reported by `veil init`, but not auto-vaulted; run `veil add NAME --host <host>` to vault and scope |
| **Agents** | Anything respecting `HTTP_PROXY` / `HTTPS_PROXY` — Claude Code, Cursor, Copilot, Windsurf, `curl`, `gh`, `npm`, `pip` |
| **Keychain** | macOS Keychain, Linux Secret Service; age-file fallback on headless Linux |

## How Veil compares

Veil isn't a replacement for a secrets manager — it sits beside one. Secrets managers inject credentials **into your application**. Veil hides them **from the AI agent you're using to write that application**.

| | Stores secrets | Scans for leaks | Hides from running agent | Local-first | Free |
|---|:---:|:---:|:---:|:---:|:---:|
| Doppler | ✓ | — | — | — | freemium |
| Infisical | ✓ | partial | — | self-host | ✓ |
| gitleaks | — | ✓ | — | ✓ | ✓ |
| **Veil** | OS keychain | — | **✓** | ✓ | ✓ |

## FAQ

<details>
<summary><strong>What secrets does Veil manage today?</strong></summary>

Anything sent as HTTP `Authorization: Bearer` for the providers listed in
the support table — OpenAI, Anthropic, Stripe, Slack, GitHub PATs, and the
rest. Unknown Bearer-shaped secrets in `.env` are detected and reported
but not automatically vaulted — run `veil add NAME --value-stdin --host <host>`
to vault them with host scope.
**Not in scope:** HTTP Basic, AWS SigV4, GitHub App JWTs, Google
service-accounts, HMAC webhook signing, shell-environment secrets, MCP
config files. If Veil can't safely manage a credential, `veil init` leaves
it in `.env` and tells you — it never half-manages a secret.
</details>

<details>
<summary><strong>How is this different from Doppler / Infisical / 1Password CLI?</strong></summary>

They inject secrets *into your app at runtime*. Veil hides secrets *from the agent that's writing your app*. They're complementary: use both. The threat models differ — secrets managers protect against credentials leaking through your application's logs and configs; Veil protects against credentials leaking through an AI agent's context window, tool calls, or training data.
</details>

<details>
<summary><strong>Does the AI agent need to know about Veil?</strong></summary>

No. That's the design. Any HTTP client that respects `HTTP_PROXY` / `HTTPS_PROXY` works unchanged — Claude Code, Cursor, `curl`, language SDKs that use the standard env-var conventions. The agent sees placeholders and routes outbound calls through Veil; Veil substitutes the real credentials at the network boundary.
</details>

<details>
<summary><strong>Veil MITMs TLS. Is that safe?</strong></summary>

Yes, and the trust scope is narrower than typical "install a root CA" tooling. `veil init` generates a CA on disk under Veil's state directory — it is **not** added to your OS, browser, or system trust store. At `veil run` time, Veil builds a per-session CA bundle and injects it into the child process via the standard `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `CURL_CA_BUNDLE`, and `REQUESTS_CA_BUNDLE` environment variables. Only that child process and its subprocesses trust the CA; the rest of your system continues to ignore it.

The trade-off is honest: clients that bypass those env vars will not trust Veil's CA — Java's `cacerts` keystore, Firefox's NSS store, native macOS apps that pin via SecureTransport, some Go binaries that compile in their own roots. We treat this as a security positive — the CA's blast radius is bounded to processes Veil launched, not your whole user account. The CA's private key is generated locally and never leaves your machine. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full assumptions.
</details>

<details>
<summary><strong>What if a malicious agent ignores <code>HTTP_PROXY</code>?</strong></summary>

Then Veil doesn't protect you. Veil is not a sandbox. It assumes a *cooperative-but-curious* agent — one that follows standard HTTP conventions but might leak secrets it has seen. If you're worried about a hostile agent with arbitrary code execution, you need OS-level isolation, not a proxy.
</details>

<details>
<summary><strong>Is this production-ready?</strong></summary>

No. Pre-1.0. Designed for **dev-machine** use with AI coding agents. Veil is not a substitute for runtime secret management in production services.
</details>

## Project structure

```
cmd/veil/       CLI entrypoint
internal/
  cli/          Command definitions (init, run, status, add, list, log, remove, uninstall)
  proxy/        HTTPS proxy with credential injection
  vault/        OS keychain abstraction
  placeholder/  Format-aware placeholder generation
  scanner/      .env file discovery
  audit/        SQLite audit logging
  config/       Project config management
  envkeys/      Canonical env-var key list (proxy + CA bundle)
  runner/       Agent process management
  skiphost/     NO_PROXY allow-list (ephemeral --skip + persistent file)
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

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor guide.

## Security

See [SECURITY.md](SECURITY.md) for the disclosure policy and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the boundaries of Veil's protection.

## License

MIT
