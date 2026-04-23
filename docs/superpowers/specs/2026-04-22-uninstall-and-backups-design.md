# Uninstall & `.env` Backup Symmetry

**Date:** 2026-04-22
**Trigger:** Code-review feedback — `veil init` rewrites `.env` files in place with no backup (`init_phases.go:193`), while MCP configs do get `.veil-backup` (`init.go:214`). Combined with the absence of a `veil uninstall` subcommand, a user whose agent breaks after running `veil init` has no first-party path back to their working state. They must restore from git or hand-edit placeholders back into real secrets. This is the single most likely "uninstall and never come back" failure mode.

## Summary

Close the backup asymmetry and ship a first-party `veil uninstall`.

1. `veil init` writes `<path>.veil-backup` before rewriting any `.env` file, mirroring existing MCP behaviour.
2. New `veil uninstall` subcommand restores every project file veil touched (both `.env` and MCP configs), purges the vault's master key from the keystore, and removes `.veil/`.
3. Uninstall detects user edits made between init and uninstall, shows a diff, and prompts for confirmation.

Exit state after a successful uninstall equals the pre-init state for all secret-bearing files: `.env` files and MCP configs are bit-identical to their original contents, no `.veil/` directory, no keystore entry. Caveat: the `/.veil/` and `*.veil-backup` lines veil appended to the project `.gitignore` are left in place (harmless stray lines; removing them would require parsing the user's `.gitignore`). Documented in § 6.

## Scope

**In scope:**
- Init-time `.env` backup (symmetric with MCP).
- `veil uninstall` subcommand with `--dry-run`, `--yes`, `--force` flags.
- Active-proxy guard preventing destructive operations while `veil run` is live.
- `*.veil-backup` gitignore entry.
- Tests: unit for each new helper, integration for the round-trip init→uninstall.

**Out of scope (deferred):**
- `veil restore <path>` — per-file surgical rollback. Add when a user asks.
- Vault-based reconstruction fallback when backup is missing. Adds a second code path for a one-time migration problem; better handled by clear manual-recovery instructions.
- `.veil/init-manifest.json` — the `.veil-backup` files themselves serve as the manifest.
- Retroactive backup creation for pre-feature installs (users that ran `veil init` before this ships). Uninstall will detect the missing backup and print a clear recovery message.
- Reworking MCP's "skip if backup exists" path to match `.env` — the current MCP behaviour is correct and untouched.

## Architecture

### New files

- `internal/cli/uninstall.go` — subcommand implementation.
- `internal/cli/uninstall_test.go` — unit + integration tests for the subcommand.

### Modified files

- `internal/cli/init_phases.go` — call the new backup helper before `atomicWriteFile` in `processEnvFile`.
- `internal/cli/init.go` — refactor the existing MCP backup-write into a shared helper (`writeBackupIfMissing`) so `.env` and MCP go through the same code path; no behavioural change to MCP.
- `internal/cli/init_test.go` — update existing MCP tests if the helper refactor changes internal structure. Public behaviour unchanged.
- `internal/cli/root.go` — register the `uninstall` command.

### Shared primitive

New helper in `internal/cli/init.go`:

```go
// writeBackupIfMissing writes src's content to src+".veil-backup" at mode
// 0600. If the backup already exists and force is false, it returns
// (false, nil) — signaling "caller should skip processing this file." If
// force is true, the backup is overwritten. Returns (true, nil) if a
// backup was written.
func writeBackupIfMissing(src string, force bool) (written bool, err error)
```

Both `processEnvFile` and `processMCPConfig` call this before modifying their file. This consolidates the two `configPath + ".veil-backup"` sites (`init.go:214`, new `.env` site) into one.

## § 1 — Init-time backup for `.env`

**Change site:** `internal/cli/init_phases.go`, inside `processEnvFile` immediately before the existing `atomicWriteFile` at line 193.

Before calling `atomicWriteFile(envPath, envFile.Bytes())`, call:

```go
wrote, err := writeBackupIfMissing(envPath, force)
if err != nil {
    return vaulted, scoped, wrapErr(fmt.Sprintf("writing backup for %s", envPath), err)
}
if !wrote && !force {
    ui.Warnf(cmd.ErrOrStderr(), "%s already has a backup (use --force to re-vault)", envPath)
    return 0, 0, nil
}
```

Semantics: identical to MCP. Backup is never overwritten without `--force`. Skipping returns zero counts so the init summary remains accurate.

**Permissions:** Backup files are mode `0600`. Content is the exact pre-modification bytes (read from disk before scanner parsing).

**Gitignore:** `veil init` has `appendGitignore(root)` at `internal/cli/init.go:392` that appends `/.veil/` to an existing project-root `.gitignore` (no-op if `.gitignore` doesn't exist). Extend this helper to also append `*.veil-backup` using the same idempotent pattern (check substring, append if missing). Do not create `.gitignore` if it doesn't exist — users without one aren't using git. A stray `.veil-backup` checked into git would leak real secrets, so the entry matters for git-tracked projects.

## § 2 — `veil uninstall` subcommand

**Surface:**

```
veil uninstall [--dry-run] [--yes] [--force]
```

- `--dry-run`: plan only, no writes.
- `--yes`: skip the interactive confirmation.
- `--force`: proceed past the "no backups found" and "active proxy" guards.

**Flow:**

1. **Root resolution:** `config.FindProjectRoot(cwd)` — same as every other command.
2. **Active-proxy guard:** see § 5.
3. **Discover backups:**
   - For `.env` files: mirror `scanner.Scan` — `scanner` is shallow by design (it only looks at a curated list of basenames in the project root: `.env`, `.env.local`, `.env.development`, `.env.production`; see `internal/scanner/scanner.go:12`). For each curated name, check whether `<root>/<name>` or `<root>/<name>.veil-backup` exists. Include the pair if either does.
   - For MCP: call `mcpconfig.Discover()` (returns a path under `~/Library/Application Support/Claude/...` on darwin; outside the project). If `<mcpPath>.veil-backup` exists, include the pair.
   - No recursive walk. Subdirectory `.env` files are not processed by `veil init` today, so they cannot have backups to restore.
4. **Plan & classify:** for each (backup, original) pair, produce a `Plan` entry with classification (see § 3).
5. **Summary & confirm:** print a table of actions. In interactive mode (not `--yes`, TTY present), ask a single yes/no prompt. `--dry-run` stops here.
6. **Execute:**
   - For each entry, `os.Rename(backup, original)`. Atomic on POSIX; replaces the target in one syscall.
   - Abort on first rename error, print what was restored, suggest `--dry-run` to re-plan.
7. **Purge state:**
   - Resolve project ID: open the vault just far enough to read `projectID` (`vault.Meta` → `ProjectID`), or load it directly from `config.VaultMetaFile(root)`.
   - `keystore.Delete(projectID)` via `vault.AutoKeystore(fallbackPath)` at `internal/vault/keystore_auto.go:16` (the same auto-selecting helper init uses). Warn on failure, continue.
   - `os.RemoveAll(config.ProjectStateDir(root))`.
8. **Summary:** print `restored: N files | state wiped | keystore entry removed` with per-file list.

**Guarded no-op:** if no backups are found AND `.veil/` doesn't exist, exit 0 with `already uninstalled`. If no backups are found but `.veil/` exists, refuse unless `--force` (this shouldn't normally happen and may indicate user manually deleted backups — we want them to confirm before we wipe the vault).

## § 3 — Modification detection & diff

For each (backup, original) pair, classify:

- **`unmodified`** — current file bytes equal backup bytes after substituting real values into placeholder sites. Safe to restore silently; no diff needed.
- **`modified`** — bytes differ beyond the placeholder↔real-value swap. User made edits (or file has no placeholders, which is unusual but handled identically). Show a unified diff and require confirmation.
- **`original-missing`** — backup exists, original file is gone. Restore silently; the rename puts it back.

**Algorithm for "unmodified" check:**

1. Read the current file (post-init state, possibly with user edits).
2. For `.env`: parse with `scanner.ParseFile`. For each `KVLine` whose value matches a known vault placeholder, look up the real value from the vault and substitute in-place via `SetValue`. Produce "expected original bytes" via `envFile.Bytes()`.
3. For MCP configs: parse JSON, walk server envs, substitute placeholders with real values, re-serialize with `json.MarshalIndent` matching `mcpconfig` formatting. Produce "expected original bytes."
4. Compare byte-for-byte with backup. Equal → `unmodified`. Unequal → `modified`.

**Diff rendering:** simple line-based unified diff (+/-), coloured via the existing `ui` palette when colour is enabled. No external dependency. Target: when a user edited the file, the diff makes the delta obvious.

**Vault lookup:** requires the vault to be openable. If the keystore refuses (user rotated keychain, locked laptop in a state that blocks prompts, etc.), fall back to `modified` classification — we can't prove equivalence, so we ask the user. Don't fail the uninstall; offer to proceed without silent-restore.

## § 4 — State directory and keystore cleanup

Order: `keystore.Delete(projectID)` first, then `os.RemoveAll(stateDir)`.

**Why that order:** `keystore.Delete` may need `vault.meta` to resolve the project ID (depending on keystore backend). Wiping the state dir first could orphan the keystore entry.

**Project ID resolution:** read `config.VaultMetaFile(root)` directly rather than opening the vault. Meta is a small JSON blob with `ProjectID`. This avoids needing the master key just to uninstall.

**Failure handling:**
- `keystore.Delete` failure → log a warning (`ui.Warnf`), continue. A stranded keystore entry with no matching ciphertext is harmless; the user can purge manually via platform tools if they care.
- `os.RemoveAll` failure → return an error. The state dir must be gone for uninstall to claim success.

**Missing state dir:** if `.veil/` doesn't exist at uninstall time, skip both keystore and removeall steps silently — a partial-init may have left backups but no state.

## § 5 — Active-proxy guard

`veil run` writes `<stateDir>/proxy-<pid>.pid`. Glob: `config.PidFileGlob(root)` (defined at `internal/config/paths.go:82`).

Before any destructive step:

```go
matches, _ := filepath.Glob(config.PidFileGlob(root))
var live []int
for _, p := range matches {
    pid, err := readPIDFile(p)
    if err != nil {
        continue
    }
    if isProcessAlive(pid) {
        live = append(live, pid)
    }
}
if len(live) > 0 && !force {
    return cliError(
        fmt.Sprintf("active proxy processes found (PIDs: %v); stop them or pass --force", live),
        "Run `veil status` to identify, then `kill <pid>`.",
    )
}
```

`isProcessAlive`: `os.FindProcess(pid)` + `p.Signal(syscall.Signal(0))`. `ErrProcessDone` or `ESRCH` → dead. Any other error → assume alive (fail-safe).

**Stale PID files:** dead PIDs are tolerated silently. Optionally sweep them during uninstall (the whole `.veil/` goes anyway, so no dedicated cleanup needed).

## § 6 — Errors, exit codes, edge cases

| Scenario | Exit | Behavior |
|---|---|---|
| Success, files restored | 0 | Summary printed |
| No `.veil/`, no backups | 0 | `already uninstalled` |
| No backups but `.veil/` exists | 1 | Refuse; suggest `--force` |
| `--force` wipes state-only (no backups) | 0 | State removed, no file changes |
| Active proxy without `--force` | 1 | Abort with PID list |
| `keystore.Delete` fails | 0 | Warn, state dir still removed |
| `os.Rename` fails mid-loop | 1 | Partial restore reported |
| User runs from subdir | — | `FindProjectRoot` handles it |
| No project root | 1 | Standard project-root error |
| Usage error (bad flag) | 1 | Cobra returns error; standard `cliError` path |

**cliError vs cliErrorf:** use the existing error-wrapping helpers established by the 2026-04-14 review-fixes spec.

**`.gitignore` leftovers:** the `/.veil/` and `*.veil-backup` lines veil appended remain after uninstall. Removing them would require parsing and rewriting the user's `.gitignore`, which is more invasive than the benefit justifies. Users who care can delete the lines manually.

## § 7 — Testing

### Unit tests (`internal/cli/uninstall_test.go`, `internal/cli/init_test.go`)

- `writeBackupIfMissing`:
  - creates backup with correct content and 0600 permissions.
  - refuses when backup exists, `!force`.
  - overwrites when `force`.
  - returns `(false, nil)` when skipping; caller observes.
- Discovery:
  - finds `.env.veil-backup` at project root, also `.env.local.veil-backup`, etc.
  - includes MCP backup from `mcpconfig.Discover()`.
  - ignores `.veil-backup` files inside subdirectories (mirrors scanner's shallow behaviour).
- Classification:
  - `unmodified` — bit-identical after substitution.
  - `modified` — bytes differ, diff output contains expected `+`/`-` lines.
  - `original-missing` — backup exists, original deleted.
  - Vault unopenable → falls back to `modified`.
- Active-proxy guard:
  - live PID blocks without `--force`.
  - dead PID proceeds.
  - `--force` overrides.

### Integration tests (`internal/cli/uninstall_test.go`)

Uses `testutil.TempProjectRoot` + `NewMemKeystore()` behind the `testkeystore` build tag (established by the 2026-04-14 spec).

- **Round-trip fidelity:** create project with a `.env` containing secrets; run init; run uninstall; assert the `.env` bytes are bit-identical to the pre-init state, `.veil/` is gone, and the keystore's project entry is gone.
- **Multi-file:** project with `.env`, `.env.local`, plus an MCP config. Init all. Uninstall restores all three. (Subdirectory `.env` files are not covered because init doesn't process them today.)
- **User edit between init and uninstall:** after init, append a new non-secret line to `.env`. Uninstall with `--yes` (simulating user confirmation). Expected: file ends up as the pre-init backup content (user's post-init edits are overwritten — documented behaviour, consistent with `--yes` semantics).
- **Dry-run:** `init` then `uninstall --dry-run`. No file changes on disk. State dir still present.
- **Active proxy blocks:** write a fake live PID file → uninstall fails; `--force` proceeds.
- **No-op after uninstall:** second `veil uninstall` returns the `already uninstalled` no-op exit.

### Not tested (explicitly)

- Keychain/system-keyring integration: covered by the existing `//go:build integration_keychain` tests. Uninstall's keystore-delete path is exercised via the mem keystore.
- Huge projects: discovery is O(len(curatedNames)) stat calls plus one MCP lookup, independent of project size.

## Rollout

Single PR. No feature flag. The new `.env` backup behaviour is backwards-compatible — existing projects that already ran `veil init` will not have `.env.veil-backup` files, but they aren't worse off than today. When those users eventually run `veil uninstall`, they'll hit the "no backups found, `.veil/` exists" branch and be prompted for `--force` with a clear recovery message pointing them at `veil list` to reconstruct their real values manually.

## Open questions

None. This spec is self-contained; ambiguities were settled during brainstorming.
