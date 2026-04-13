# MVP Feature Gaps — Manual Test Plan

Run these tests from a clean temporary project. Each section is independent unless noted.

## Setup

```bash
# Build from source
make build

# Create a throwaway test project
mkdir /tmp/veil-test && cd /tmp/veil-test
git init
echo 'OPENAI_API_KEY=sk-proj-abc123def456ghi789jklmnopqrstuvwxyz01234567890ABC' > .env
echo 'STRIPE_SECRET_KEY=sk_live_abcdefghijklmnopqrstuvwx' >> .env
```

Alias for convenience:
```bash
alias veil=/Users/ben/Workspace/Veil/bin/veil
```

Initialize the project:
```bash
veil init
```

---

## 1. Branded `--version` and `--help`

```bash
veil --version
```
- [ ] Output format: `veil v<version> (darwin/arm64)` (not cobra default `veil version <version>`)

```bash
veil --help
```
- [ ] Shows "Quick start:" section
- [ ] Lists `veil init`, `veil run claude`, `veil log`
- [ ] Shows "Veil -- protect your secrets from AI agents" header

---

## 2. `veil list` basics

```bash
veil list
```
- [ ] Shows NAME, HOSTS, SOURCE, LAST INJECTED columns
- [ ] OPENAI_API_KEY and STRIPE_SECRET_KEY appear
- [ ] LAST INJECTED shows "never" for both

---

## 3. `veil list --placeholder`

```bash
veil list --placeholder
```
- [ ] Shows PLACEHOLDER column between HOSTS and SOURCE
- [ ] OPENAI_API_KEY placeholder starts with `sk-proj-`
- [ ] STRIPE_SECRET_KEY placeholder starts with `sk_live_`

```bash
veil list --reveal --placeholder 2>&1
```
- [ ] Error: flags are mutually exclusive

---

## 4. `veil add --value` (non-interactive)

```bash
veil add GITHUB_TOKEN --value ghp_abcdefghijklmnopqrstuvwxyz0123456789
```
- [ ] Output: "Added GITHUB_TOKEN to vault"
- [ ] Shows "Placeholder: ghp_..." line
- [ ] Shows "Hosts: api.github.com" (auto-detected)

```bash
veil list
```
- [ ] GITHUB_TOKEN now appears in the list

---

## 5. `veil add` output styling

```bash
veil add NO_HOST_KEY --value randomvalue12345
```
- [ ] Output: "Added NO_HOST_KEY to vault"
- [ ] Shows "Placeholder:" line
- [ ] Shows warning: "No target hosts detected for NO_HOST_KEY"
- [ ] Shows hint: "Use veil add --host to scope it"

---

## 6. `veil add --force` placeholder sync

Check the current .env:
```bash
cat .env
```
Note the OPENAI_API_KEY placeholder value.

```bash
veil add OPENAI_API_KEY --force --value sk-proj-newkey9876543210fedcba9876543210fedcba99999
```
- [ ] Output: "Added OPENAI_API_KEY to vault"
- [ ] If placeholder changed: "Updated placeholder in 1 .env file"

```bash
cat .env
```
- [ ] The OPENAI_API_KEY value in .env should be the NEW placeholder (not the old one)

---

## 7. `veil remove`

```bash
veil remove NO_HOST_KEY
```
- [ ] Prompts for confirmation: "Remove NO_HOST_KEY? [y/N]"
- Type `y`
- [ ] Output: "Removed NO_HOST_KEY from vault"
- [ ] Warning about placeholder in .env

```bash
veil list
```
- [ ] NO_HOST_KEY no longer appears

```bash
veil remove NONEXISTENT
```
- [ ] Error: credential "NONEXISTENT" not found

```bash
veil add TEMP_KEY --value tempval123456789
veil remove TEMP_KEY --force
```
- [ ] No confirmation prompt, removed immediately

---

## 8. `veil status` — proxy not running

```bash
veil status
```
- [ ] Shows "Proxy" line with "not running"
- [ ] Shows credential count
- [ ] Shows CA status

---

## 9. `veil run` — happy path + proxy status

In one terminal:
```bash
veil run -- sleep 30
```
- [ ] Startup line shows "proxy active" with credential count
- [ ] No zero-credential warning (since vault has credentials)

In another terminal (while sleep 30 is running):
```bash
cd /tmp/veil-test && veil status
```
- [ ] Shows "Proxy" line with "active (PID NNNNN)"

Check PID file exists:
```bash
ls -la /tmp/veil-test/.veil/proxy.pid
```
- [ ] File exists with a PID number

Back in the first terminal, wait for sleep to finish:
- [ ] Exit summary: "session complete"
- [ ] Shows "Duration:" line

Check PID file cleaned up:
```bash
ls /tmp/veil-test/.veil/proxy.pid 2>&1
```
- [ ] File no longer exists

---

## 10. `veil run` — exit code accuracy

```bash
veil run -- sh -c 'exit 42'
```
- [ ] Exit summary: "session ended (exit 42)"

```bash
echo $?
```
- [ ] Prints `42`

---

## 11. `veil run` — zero credentials

```bash
# Create a fresh project with no credentials
mkdir /tmp/veil-empty && cd /tmp/veil-empty
git init
veil init
veil run -- echo hello
```
- [ ] Warning after startup: "No credentials to inject. Add secrets with veil add..."
- [ ] "echo hello" still runs and prints "hello"
- [ ] Exit summary: "session complete"

---

## 12. `veil run` — signal escalation

```bash
cd /tmp/veil-test
veil run -- sleep 600
```
Press Ctrl+C:
- [ ] Process exits (sleep respects SIGINT, so it should exit quickly)
- [ ] Exit summary shown

For escalation test (if you have a signal-ignoring program):
```bash
veil run -- sh -c 'trap "" INT; sleep 600'
```
Press Ctrl+C:
- [ ] After ~5 seconds: "Waiting for process to exit..."
- [ ] After ~5 more seconds: "Force-killed child process."

---

## 13. `veil log` — empty state messaging

```bash
cd /tmp/veil-empty
veil log
```
- [ ] Message: "No credential injections during this period."
- [ ] Hint: "The proxy was active but no managed credentials were used in outbound requests."

---

## 14. Proxy startup error — corrupted vault

```bash
mkdir /tmp/veil-corrupt && cd /tmp/veil-corrupt
git init
mkdir -p .veil
echo '{"project_id":"test","version":1}' > .veil/vault.meta
echo 'garbage' > .veil/vault.bin
veil run -- echo hi
```
- [ ] Error message references "decrypt" or "vault" or "keychain"
- [ ] Suggests "Run veil init --force to reinitialize"
- [ ] NOT a raw Go error chain

---

## 15. Vault collision error

```bash
cd /tmp/veil-test
```

This is hard to trigger naturally (placeholder generation is format-aware), so just verify via the test suite:
```bash
cd /Users/ben/Workspace/Veil
CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test ./internal/vault/ -run TestAddPlaceholderCollision -v
```
- [ ] `TestAddPlaceholderCollisionMessage` passes
- [ ] Error message mentions both credential names and "veil remove"

---

## Cleanup

```bash
rm -rf /tmp/veil-test /tmp/veil-empty /tmp/veil-corrupt
```
