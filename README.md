# Veil

**.gitignore protected your secrets from git. Veil protects them from AI.**

Veil is a local CLI that sits between your AI coding agents and the network via a local HTTPS proxy. It replaces real secrets with format-aware placeholders, then injects the real credentials at the proxy layer — so the agent never sees them. Works with any agent or tool that respects `HTTP_PROXY`/`HTTPS_PROXY` environment variables, including Claude Code, Cursor, curl, and most HTTP clients.

## How it works

1. `veil init` scans your `.env` files and MCP configs, moves secrets into your OS keychain, and drops in placeholders that look real (correct prefix, length, charset).
2. `veil run <agent>` starts a local HTTPS proxy and launches your agent with `HTTP_PROXY`/`HTTPS_PROXY` set. The proxy swaps placeholders for real credentials on outbound requests.
3. Every credential injection and agent action is logged to local SQLite. Query with `veil log`.

The agent thinks it has real tokens. It doesn't.

## Install

```
go install github.com/8enji/veil/cmd/veil@latest
```

Or build from source:

```
git clone https://github.com/8enji/veil.git
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
veil add --key GITHUB_TOKEN --value ghp_abc123

# View audit logs
veil log
veil log --today
```

## What it supports

- **Secrets**: AWS, Stripe, GitHub PATs, OpenAI, Slack, Twilio, SendGrid, Supabase, and more — with format-aware placeholders for each
- **Keychain**: macOS Keychain, Linux Secret Service, Windows Credential Manager
- **Agents**: Anything that respects `HTTP_PROXY` / `HTTPS_PROXY`
- **MCP configs**: Auto-detects and migrates plaintext tokens from MCP configuration files

## Project structure

```
cmd/veil/       CLI entrypoint
internal/
  cli/          Command definitions (init, run, status, add, list, log)
  proxy/        HTTPS proxy with credential injection
  vault/        OS keychain abstraction
  placeholder/  Format-aware placeholder generation
  scanner/      MCP supply chain scanner
  audit/        SQLite audit logging
  config/       Project config management
  mcpconfig/    MCP config file parsing
  runner/       Agent process management
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
