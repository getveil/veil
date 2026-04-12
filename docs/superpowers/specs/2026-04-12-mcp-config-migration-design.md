# MCP Config Migration in `veil init`

## Context

PRODUCT.md identifies "24,000 secrets found in public MCP config files" as a headline pain point. The Phase 1 demo shows `veil init` processing "1 MCP config." Without MCP config migration, the init story is incomplete — users still have plaintext tokens in their MCP configs after running `veil init`.

This spec extends `veil init` to scan Claude Desktop's MCP configuration file, vault plaintext tokens from server `env` blocks, and replace them with format-aware placeholders — the same flow that already works for `.env` files.

## Scope

- **In scope:** Claude Desktop config (`claude_desktop_config.json`) on macOS and Linux
- **Out of scope:** Cursor, VS Code, Windows, project-local `.mcp.json`, `args` array scanning

## Discovery

A new `internal/mcpconfig` package provides MCP config file operations.

`Discover() (string, error)` returns the path to the Claude Desktop config if it exists:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

Returns `("", nil)` if the file does not exist. No `--mcp-config` flag for custom paths in MVP.

## Config Structure

Standard Claude Desktop MCP config format:

```json
{
  "mcpServers": {
    "server-name": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_abc123..."
      }
    }
  }
}
```

The config may contain other top-level keys (e.g. `preferences`). These must be preserved.

## Parsing

- Unmarshal with `encoding/json` into a typed struct for the `mcpServers` field
- Use a top-level `map[string]json.RawMessage` to preserve unknown fields
- The `mcpServers` value is parsed into `map[string]ServerConfig` where:

```go
type ServerConfig struct {
    Command string            `json:"command"`
    Args    []string          `json:"args,omitempty"`
    Env     map[string]string `json:"env,omitempty"`
    // Remaining fields preserved via custom marshal/unmarshal
}
```

For round-trip fidelity of unknown fields within server configs, use an overflow map pattern or `json.RawMessage` approach so that fields beyond `command`/`args`/`env` are not dropped.

## Secret Extraction

For each server in `mcpServers`:
1. Iterate over the server's `env` map
2. Call `placeholder.IsSecretLike(key, value)` — reuse existing heuristics
3. If secret-like, call `placeholder.Generate(key, value)` for the placeholder
4. Create a `vault.Credential` with:
   - `Name`: `mcp:<serverName>:<KEY>` (e.g. `mcp:github:GITHUB_TOKEN`)
   - `Real`: original secret value
   - `Placeholder`: generated placeholder
   - `Source`: `"init"`
5. Add to vault via `v.Add(cred)`
6. Replace the value in the parsed config's env map with the placeholder

## Credential Naming

Vault entries from MCP configs use the format `mcp:<serverName>:<KEY>`:
- Prevents collisions with `.env` entries (which use flat names like `GITHUB_TOKEN`)
- Prevents collisions across MCP servers (two servers could both have `API_KEY`)
- Clear provenance in `veil list` output

## Config Rewriting

**Backup:** Before modifying, copy the original to `claude_desktop_config.json.veil-backup` in the same directory. If a backup already exists, overwrite it only with `--force`. Without `--force`, warn and skip if backup exists (config was already migrated).

**Serialization:** Write modified JSON with `json.MarshalIndent` using 2-space indentation and no HTML escaping (matching Claude Desktop's own formatting). Use `atomicWriteFile` for safe writes.

**Dry-run:** Print what would be vaulted, don't modify the config file or create a backup.

## Integration into `runInit()`

### Modified Flow

1. Steps 1-2: Resolve root, check `.veil/` — unchanged
2. Step 3: Scan `.env` files — unchanged
3. **Step 3b (NEW):** Call `mcpconfig.Discover()` to find MCP config
4. **Early exit check (CHANGED):** Return early only if no `.env` files AND no MCP config found
5. Steps 4-7: Project ID, keystore, vault, CA — unchanged
6. Step 8: Process `.env` files — unchanged
7. **Step 8b (NEW):** Process MCP config:
   - Parse config file
   - Extract and vault secrets from env blocks
   - Rewrite config file with placeholders
   - Create backup (unless dry-run)
8. Steps 9-10: Gitignore, summary — summary updated to include MCP config count

### Updated Summary Output

```
Veil initialized for /path/to/project

  Secrets vaulted: 8
  .env files processed: 2
  MCP configs processed: 1
  CA: /path/to/ca.pem

Run 'veil trust' to install the CA into your system trust store.
```

When no MCP config is found, omit the "MCP configs processed" line.

## Package Structure

New package: `internal/mcpconfig/`

```
internal/mcpconfig/
    mcpconfig.go      # Discover(), Parse(), types
    mcpconfig_test.go  # Unit tests
```

### Public API

```go
// Discover returns the path to Claude Desktop's config file, or "" if not found.
func Discover() (string, error)

// ConfigFile represents a parsed Claude Desktop configuration.
type ConfigFile struct { ... }

// Parse reads and parses the config file at the given path.
func Parse(path string) (*ConfigFile, error)

// Servers returns the MCP server configurations with env blocks.
func (c *ConfigFile) Servers() map[string]*ServerConfig

// SetEnvValue replaces an env var value for a specific server.
func (c *ConfigFile) SetEnvValue(server, key, value string)

// Bytes serializes the config back to JSON.
func (c *ConfigFile) Bytes() ([]byte, error)
```

## Testing

### Unit Tests (`internal/mcpconfig/mcpconfig_test.go`)

- Parse valid config with multiple servers and env blocks
- Parse config with no `mcpServers` key — returns empty servers
- Parse config with servers but no `env` blocks — no secrets found
- Secret detection within env blocks (delegates to existing `placeholder.IsSecretLike`)
- Round-trip: parse, modify env values, serialize — preserves `preferences` and other keys
- Round-trip: unknown fields within server configs are preserved
- `Discover()` returns correct platform-specific path
- `Discover()` returns `""` when config doesn't exist

### Init Integration Tests (`internal/cli/init_test.go`)

- `veil init` processes both `.env` and MCP config in one run
- `veil init --dry-run` output includes MCP config findings
- MCP-only project (no `.env`) still initializes vault successfully
- Backup file `claude_desktop_config.json.veil-backup` is created
- Second `veil init` without `--force` warns about existing backup
- Credential names use `mcp:<server>:<key>` format in vault

### Test Fixture

`test/fixtures/mcp/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_test1234567890abcdef1234567890abcdef"
      }
    },
    "slack": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-slack"],
      "env": {
        "SLACK_TOKEN": "xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx",
        "WORKSPACE_NAME": "my-workspace"
      }
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
      "env": {}
    }
  },
  "preferences": {
    "theme": "dark"
  }
}
```

Expected behavior: `GITHUB_TOKEN` and `SLACK_TOKEN` are vaulted; `WORKSPACE_NAME` is skipped (not secret-like); `filesystem` server has no secrets; `preferences` is preserved unchanged.

## Verification

1. Run `go test ./internal/mcpconfig/...` — all unit tests pass
2. Run `go test ./internal/cli/ -run TestInit` — integration tests pass
3. Manual test: create a temp Claude Desktop config with known tokens, run `veil init`, verify:
   - Backup file exists with original content
   - Config file has placeholders (same prefix/length/charset as originals)
   - `veil list --reveal` shows correct real values
   - `veil run` proxy injects real credentials when placeholders appear in requests
