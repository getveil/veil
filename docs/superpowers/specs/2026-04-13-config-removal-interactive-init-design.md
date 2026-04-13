# Config Removal + Interactive Init Design

## Summary

Remove the per-project config file (`.veil/config.yaml`) and everything that supports it. Replace with an interactive `veil init` flow and a `veil skip` command for persistent host skipping. The vault becomes the sole source of truth for credential data.

## Motivation

The config feature introduces a second source of truth for host scoping. The vault stores `AllowedHosts` on every `Credential` record. The config file stores the same data under `scoping:`. A `veil sync` command and drift detection exist solely to reconcile these two stores. This is complexity the MVP does not need.

The three config capabilities (`scoping`, `ignore`, `skip_hosts`) solve problems that can be addressed more simply:

- **Scoping** duplicates vault data. The vault already owns `AllowedHosts`. `veil add --host` already lets users scope credentials.
- **Ignore** is better solved by letting users choose what to vault interactively at init time.
- **Skip hosts** needs persistence but not a YAML config file. A flat file and a CLI command are sufficient.

The config feature adds ~1,400 lines of code, a `sync` command, drift detection logic, config loading in three commands, and generation logic. This is significant surface area for an MVP that should be focused on the proxy working flawlessly.

## What Gets Removed

### Files deleted

- `internal/config/config.go` (ProjectConfig type, Load, validation)
- `internal/config/config_test.go`
- `internal/config/generate.go` (Generate, GenerateFromConfig)
- `internal/config/generate_test.go`
- `internal/config/sync.go` (Sync, SyncResult)
- `internal/config/sync_test.go`
- `internal/cli/sync.go` (veil sync command)

### Types and functions deleted

- `config.ProjectConfig`
- `config.ScopingEntry`
- `config.Load()`
- `config.Generate()`
- `config.GenerateFromConfig()`
- `config.Sync()`
- `config.SyncResult`
- `config.ConfigFile()`

### Logic removed from existing commands

- **`veil init`:** Config loading, config-based scoping lookups, config file generation/writing.
- **`veil run`:** Config loading, `checkConfigDrift()`, config-based `SkipHosts` passthrough.
- **`veil add`:** Config loading, config-based scoping defaults.

### Feature removed

- `# veil:skip` inline comment support. Hard removed, not deprecated.

### What stays in `internal/config/`

`paths.go` and `project.go` (and their tests) handle path resolution and project root detection. These are unrelated to the config file and remain unchanged.

### What stays unchanged

- `vault.Credential.AllowedHosts` remains the single source of truth for host scoping.
- The proxy and injector read hosts from vault credentials. No changes.
- `veil add --host` remains the way to scope credentials to hosts.

## Interactive `veil init`

The current `veil init` silently vaults everything `IsSecretLike()` returns true for. The new flow adds decision points.

### File selection

```
Scanning project...

Found 3 .env files:
  .env
  .env.test
  .env.example

Scan all? (Y/n/select): select
  [x] .env
  [ ] .env.test
  [x] .env.example
```

- Default is Y (scan all). Enter key does the right thing.
- `n` skips all .env files (proceeds to MCP config if present).
- `select` opens a granular picker.
- Files that aren't selected are simply not scanned. No ignore patterns stored.

### Token selection (per file)

```
Detected 4 secrets in .env:
  GITHUB_TOKEN          ghp_****
  OPENAI_API_KEY        sk-****
  DATABASE_URL          postgres://****
  STRIPE_SECRET_KEY     sk_live_****

Vault all? (Y/n/select): select
  [x] GITHUB_TOKEN
  [x] OPENAI_API_KEY
  [ ] DATABASE_URL
  [x] STRIPE_SECRET_KEY
```

- Default is Y (vault all). Fast path for users who want everything.
- `n` skips the entire file's secrets.
- `select` lets the user pick individually.
- Secrets not selected are not vaulted. The vault is the record of what the user chose.

### MCP config handling

Same interactive pattern applies to MCP configs. Detect servers with secrets, prompt to vault all or select per-server.

```
Found 1 MCP config (claude_desktop_config.json):
  Server: github — 1 secret (GITHUB_TOKEN)
  Server: slack  — 2 secrets (SLACK_TOKEN, SLACK_SIGNING_SECRET)

Vault all MCP secrets? (Y/n/select): Y
```

### Skip hosts prompt

After vaulting, prompt for skip hosts:

```
Skip hosts — any hosts the proxy should pass through untouched?
Common examples: api.anthropic.com, *.internal.company.com
(You can manage these later with: veil skip)

Hosts to skip (comma-separated, or Enter to skip): api.anthropic.com

  ✓ api.anthropic.com added to skip list
```

- Clearly optional. Enter skips it.
- Mentions `veil skip` so the user knows the escape hatch exists.
- Hosts entered here are written to `.veil/skip_hosts`.

### Non-interactive mode

`veil init --yes` accepts all defaults: scan all files, vault all detected secrets, no skip hosts. Used for scripting and CI.

If stdin is not a TTY (piped input, CI), fall back to `--yes` behavior automatically with a notice: `Non-interactive mode: vaulting all detected secrets`.

### Re-init (`--force`)

`veil init --force` is a clean-slate re-init. It wipes the existing vault and goes through the full interactive flow from zero. Not incremental.

```
$ veil init --force

This will replace your existing vault. Continue? (y/N): y

Scanning project...
```

Note: `.env` files will contain placeholders from the previous init. The scanner already detects placeholders via `IsSecretLike()` — placeholder values are not secret-like, so they won't be re-vaulted. The user's real secrets need to be available (e.g., restored from the `.veil-backup` MCP config or re-entered via `veil add`) for the new vault to be useful. This is the expected behavior for a destructive reset.

The user makes all choices again. If they want to add a single new secret incrementally, that's what `veil add` is for.

## `veil skip` Command

Manages persistent per-project host skipping through the CLI.

### Adding (default action)

```
$ veil skip api.anthropic.com
  ✓ Added api.anthropic.com to skip list

$ veil skip "*.internal.corp.com"
  ✓ Added *.internal.corp.com to skip list
```

- Positional argument. Adding is the default action.
- Supports wildcard prefix matching (`*.example.com`), same syntax as `NO_PROXY`.
- Duplicate entries are silently ignored.

### Listing

```
$ veil skip --list
  api.anthropic.com
  *.internal.corp.com
```

### Removing

```
$ veil skip --remove api.anthropic.com
  ✓ Removed api.anthropic.com from skip list
```

Error if the host is not in the list.

### Storage

Flat file at `.veil/skip_hosts`. One host per line.

```
# Managed by veil skip
api.anthropic.com
*.internal.corp.com
```

The file lives inside `.veil/` which is already gitignored. Users never need to edit it directly. The file is created on first `veil skip` invocation or when the user adds skip hosts during `veil init`. If the file does not exist, `veil run` treats it as an empty list. No error, no warning.

## `veil run` Changes

- Reads `.veil/skip_hosts` (not config.yaml) and merges entries into `NO_PROXY`.
- Accepts `--skip <host>` flag for ephemeral per-run skipping. Not persisted.
- Hardcoded defaults (`localhost`, `127.0.0.1`, `::1`) are always included.
- Drift detection removed entirely.
- Config loading removed entirely.

## `veil add` Changes

- Config loading removed.
- Host resolution simplified: `--host` flags if provided, otherwise `HostsForCredential()` auto-detection. Two paths, not three.

## CLI Surface

| Command | Change |
|---|---|
| `veil init` | Interactive prompts added, config generation removed |
| `veil run` | Config loading replaced by skip_hosts file, drift detection removed, `--skip` flag added |
| `veil add` | Config loading removed, simpler host resolution |
| `veil skip` | New command |
| `veil sync` | Deleted |
| `veil list` | No change |
| `veil log` | No change |
| `veil status` | No change |
| `veil remove` | No change |

8 commands to 8 commands (swap `sync` for `skip`), with significantly less hidden complexity.

## What This Does Not Include

- **Config file of any kind.** All settings are managed through CLI commands.
- **Global/user-level skip hosts.** Per-project only.
- **Incremental re-init.** `--force` is a clean slate. Use `veil add` for incremental changes.
- **`# veil:skip` inline comments.** Removed entirely.
