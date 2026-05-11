# Security Policy

Veil is a security tool. We take vulnerability reports seriously and aim to acknowledge them within 72 hours.

## Reporting a Vulnerability

**Please do not open public issues for security vulnerabilities.**

Use GitHub's private vulnerability reporting:

1. Go to https://github.com/getveil/veil/security/advisories/new
2. Provide a description, reproduction steps, and impact
3. We will respond within 72 hours

If you cannot use GitHub Security Advisories, open a minimal public issue asking for a private contact channel — do not include vulnerability details in the issue.

## Scope

In scope:

- The Veil CLI and proxy (`cmd/veil`, `internal/proxy`, `internal/vault`)
- Placeholder generation and matching (`internal/placeholder`)
- Audit logging integrity (`internal/audit`)
- Project secret discovery (`internal/scanner` for `.env` files; `internal/mcpconfig` for MCP server configs)
- Keychain integration (`internal/vault/keystore_keyring.go`)

Out of scope (report upstream where applicable):

- Vulnerabilities in third-party Go dependencies — report to the upstream project; we will pick up patched versions
- Social engineering of project maintainers
- Threats explicitly excluded by [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) (e.g. a fully compromised host, a malicious agent with arbitrary code execution outside the proxy)

## Supported Versions

Veil is pre-1.0. Only the latest tagged release on `main` receives security fixes. Once 1.0 ships, this policy will be updated to define a longer support window.

## Disclosure

We follow a coordinated disclosure model:

- We will work with you on a fix and a disclosure timeline
- Default disclosure window is 90 days from initial report, or sooner once a patched release is available
- We credit reporters in release notes and the advisory unless you request otherwise
