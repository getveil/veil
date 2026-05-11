# Contributing to Veil

Thanks for considering a contribution. Veil is small and pre-1.0; the scope is intentionally tight (keep secrets out of AI coding agents), so before sinking time into a large change, open an issue to discuss.

## Build and test

```
make build       # binary at bin/veil
make test        # unit + integration tests
make test-race   # tests with the race detector
make lint        # golangci-lint
make vet         # go vet
```

Tests use a swappable keystore controlled by `VEIL_TEST_KEYSTORE=mem` (set automatically by `make test`). The keychain on macOS and libsecret on Linux are exercised by `make test-race` builds.

## Commit style

Commits use [Conventional Commits](https://www.conventionalcommits.org/) — see `git log` for the prevailing pattern. `feat(scope):`, `fix(scope):`, `test(scope):`, `docs(scope):`, `chore(scope):`.

## Filing issues

- **Bugs:** use the bug template. Include `veil --version`, OS + version, the exact command, and a redacted log snippet if relevant.
- **Features:** use the feature template. Lead with the problem, not the implementation.
- **Security vulnerabilities:** do **not** open a public issue. See [SECURITY.md](SECURITY.md) — use GitHub's private vulnerability reporting.

## Pull requests

- Branch off `main`. One logical change per PR.
- Add or update tests for behavior changes. New providers (placeholder patterns) need at least one positive and one negative match test.
- The CI matrix runs on macOS and Ubuntu. Don't ignore failures on either.
- Be patient with review — this is a side project.

## License

By contributing, you agree that your contributions are licensed under the project's [MIT License](LICENSE). No CLA.

## Where things live

The README has a project-structure map. In short: CLI entrypoint in `cmd/veil/`, command definitions in `internal/cli/`, the proxy in `internal/proxy/`, keychain abstraction in `internal/vault/`, and audit logging in `internal/audit/`. Each `internal/<pkg>/` has its own tests next to the code.
