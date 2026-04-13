# Veil MVP Feature Gap Analysis

**Date:** 2026-04-13
**Scope:** Control + Prove stages only. No Discover stage. No docs cleanup (handled separately).
**Target user:** Indie developer working solo or in a small team.
**Target experience:** Polished, intuitive, professional.
**Defining use case:** All workflows reachable from `veil run claude`.

---

## Constraints

- macOS and Linux only. No Windows.
- Local-first. No cloud, no accounts.
- Audit scope: credential injections and blocked attempts only (no file/process monitoring).
- No `veil trust` — CA injection via env vars (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, etc.) is sufficient.
- No `--today` or other log convenience aliases — `--since` is the only time filter, docs will be updated separately.

---

## Section 1: User Journey Gaps

### 1.1 Credential Removal (`veil remove`)

**Problem:** No way to remove a credential from the vault. User must `veil init --force` to start over.

**Solution:** `veil remove <name>` — deletes a credential from the vault by name. Confirms before deleting unless `--force` is passed. Warns that the placeholder in `.env` will stop working unless manually replaced.

**CLI signature:**
```
veil remove <name> [--force]
```

### 1.2 Credential Update (`veil add --force` Placeholder Sync)

**Problem:** `veil add --force` deletes and recreates the credential, but doesn't update the `.env` file with the new placeholder. If the new value produces a different placeholder format, the old placeholder in `.env` becomes stale.

**Solution:** Two improvements:
1. When `--force` replaces a credential, print the new placeholder value so the user knows what to update in `.env`.
2. If the previous placeholder exists in any `.env` file in the project, automatically rewrite it with the new placeholder and print a message confirming the update.

### 1.3 Non-Interactive `veil add`

**Problem:** `veil add` only reads the secret from an interactive stdin prompt. Cannot pipe from a password manager or script.

**Solution:** Accept a `--value` flag for explicit non-interactive use. Additionally, detect piped stdin (no TTY) and read the first line without prompting. Both paths produce the same result.

**CLI signature:**
```
veil add <name> --value <secret> [--host <host>] [--force]
echo "secret" | veil add <name> [--host <host>] [--force]
```

---

## Section 2: Inspection & Observability Gaps

### 2.1 `veil log` Empty State Messaging

**Problem:** After a `veil run` session where the agent didn't trigger any managed credentials, `veil log` shows "No injection events found." This is correct but potentially confusing — the user may think Veil wasn't active.

**Solution:** When the audit DB exists and has zero injections for the queried period, improve the message to: "No credential injections during this period. The proxy was active but no managed credentials were used in outbound requests."

### 2.2 `veil list` — Show Placeholder Values

**Problem:** `veil list` shows name, hosts, source, and last injected — but not the placeholder value. After `veil add`, the user needs the placeholder to paste into config files. The only way to see it is `--reveal`, which shows the real secret.

**Solution:** Add a `--placeholder` flag to `veil list` that adds a PLACEHOLDER column showing each credential's placeholder value. Useful for manual config wiring.

**CLI signature:**
```
veil list [--placeholder] [--reveal]
```

### 2.3 `veil status` — Proxy Running Indicator

**Problem:** `veil status` shows credential count, CA state, and last 24h activity, but doesn't indicate whether the proxy is currently running.

**Solution:** Check for a running proxy (write a PID file during `veil run`, check if that PID is alive) and display:
- "Proxy: active (PID NNNNN)" if running
- "Proxy: not running" if not

**Dependency:** This requires `veil run` to write a PID file to `.veil/proxy.pid` on proxy start and clean it up on exit (both normal and signal-based). The PID file work is part of this item, not a separate task.

---

## Section 3: Edge Cases & Defensive Behavior

### 3.1 `veil run` With Zero Credentials

**Problem:** If the vault has zero credentials, `veil run` starts the proxy and prints "0 credentials loaded." Technically correct but confusing — the proxy is doing nothing useful.

**Solution:** After the startup line, print a warning: "No credentials to inject. Add secrets with `veil add` or create a `.env` file and re-run `veil init`."

### 3.2 `veil run` Exit Summary Accuracy

**Problem:** The exit summary always says "session complete" regardless of how the child exited.

**Solution:** Reflect the child's exit status:
- Exit 0: "session complete"
- Non-zero exit: "session ended (exit N)"
- Signal death: "session terminated (SIGTERM)" or similar

### 3.3 Vault Corruption Recovery Messaging

**Problem:** If `vault.bin` is corrupted, commands fail with a cryptic Go error chain. A backup exists (`vault.bin.bak`) but the user doesn't know about it.

**Solution:** When vault open fails, check for `vault.bin.bak` and improve the error message: "Vault appears corrupted. A backup exists at `.veil/vault.bin.bak`. Run `veil init --force` to reinitialize, or manually restore the backup."

### 3.4 Placeholder Collision Error Messaging

**Problem:** If two secrets generate the same placeholder, the error message ("placeholder collision") doesn't explain the cause or fix.

**Solution:** Improve to: "Placeholder collision: the generated placeholder for `<name>` matches an existing credential. Use `veil add` with a differently formatted value, or remove the conflicting credential with `veil remove`."

---

## Section 4: Polish Layer

### 4.1 `veil add` Output Consistency

**Problem:** `veil add` prints minimal output that doesn't match the styled output of other commands.

**Solution:** Align with the CLI style guide:
- Use `ui.Step` for the success line
- Show the generated placeholder value (so the user can copy it)
- Show auto-detected or explicit hosts
- Use `ui.Warn` if no hosts were detected

**Example output:**
```
  Added GITHUB_TOKEN to vault
  Placeholder: ghp_veil_a8f3c2e9d1b4...
  Hosts: api.github.com
```

### 4.2 `veil remove` Output Style

**Problem:** New command (Section 1.1) needs to match established CLI conventions.

**Solution:** Use styled output:
```
  Removed GITHUB_TOKEN from vault
  Warning: placeholder in .env will no longer be injected
```

### 4.3 Graceful Proxy Startup Failure Messages

**Problem:** Proxy startup failures surface raw Go error chains.

**Solution:** Map common failures to actionable messages:
- CA cert missing/corrupt: "CA certificate not found. Run `veil init` to regenerate."
- Vault decrypt failure: "Cannot decrypt vault. Your keychain may have changed. Run `veil init --force` to reinitialize."
- Port bind failure: "Cannot start proxy. Another instance may be running."

### 4.4 Signal Handling Escalation

**Problem:** After Ctrl+C, `veil run` forwards SIGINT to the child but waits indefinitely if the child doesn't exit.

**Solution:** Escalation sequence:
1. Forward SIGINT to child process group
2. After 5 seconds: send SIGTERM, print "Waiting for process to exit..."
3. After 5 more seconds: SIGKILL the process group, print "Force-killed child process."

### 4.5 Branded `--version` and `--help`

**Problem:** `--version` prints "veil version dev". `--help` uses cobra defaults.

**Solution:**
- Version output: `veil v0.1.0 (darwin/arm64)`
- Custom root help that leads with the one-liner, then shows the primary workflow:
  ```
  Veil — protect your secrets from AI agents

  Quick start:
    veil init          Scan project, vault secrets, write placeholders
    veil run claude    Launch agent with credential injection active
    veil log           See what credentials were used

  Commands:
    init       Initialize Veil for the current project
    run        Run a command with secrets injected via proxy
    ...
  ```

---

## Summary: Work Items

| # | Item | Section | Type |
|---|------|---------|------|
| 1 | `veil remove` command | 1.1 | New feature |
| 2 | `veil add --force` placeholder sync | 1.2 | Enhancement |
| 3 | `veil add --value` + piped stdin | 1.3 | Enhancement |
| 4 | `veil log` empty state messaging | 2.1 | Copy fix |
| 5 | `veil list --placeholder` flag | 2.2 | Enhancement |
| 6 | `veil status` proxy running indicator | 2.3 | Enhancement |
| 7 | Zero-credential warning in `veil run` | 3.1 | Defensive |
| 8 | Exit summary accuracy | 3.2 | Defensive |
| 9 | Vault corruption recovery message | 3.3 | Defensive |
| 10 | Placeholder collision error message | 3.4 | Defensive |
| 11 | `veil add` output consistency | 4.1 | Polish |
| 12 | `veil remove` output style | 4.2 | Polish |
| 13 | Proxy startup failure messages | 4.3 | Polish |
| 14 | Signal handling escalation | 4.4 | Polish |
| 15 | Branded `--version` and `--help` | 4.5 | Polish |
