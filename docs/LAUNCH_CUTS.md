# Veil v1 Launch — Scope Cuts

**Goal:** distill Veil to its core promise — _discover Bearer API keys in `.env` files, vault them in the OS keychain, inject them on outbound HTTPS requests_ — and harden only that surface for launch.

Every item below is **out of v1**. Each entry lists: what to cut, why, the files affected, and downstream cleanup. Sequenced for safest extraction.

---

## Order of operations

Each phase is independent and lands as one PR. Tests stay green after each.

1. **Phase 1 — Signers (AWS SigV4 + GitHub App JWT)**
2. **Phase 2 — Basic auth (providers + correlator + decoder)**
3. **Phase 3 — MCP scanning**
4. **Phase 4 — Shell-env scanning**
5. **Phase 5 — URL-with-password DSN handling**
6. **Phase 6 — Mismatch detector + audit schema simplification**
7. **Phase 7 — Niche surface (reveal, Java truststore, bypass warnings, skip command)**
8. **Phase 8 — Docs + CHANGELOG cleanup**
9. **Phase 9 — Final code-path simplifications**

---

## Phase 1 — Signers (AWS SigV4 + GitHub App JWT)

Both are already `--experimental` and outside the stable contract. Removing them eliminates ~1,000 LOC, the entire `--experimental` gate, and a class of fail-closed errors. **Lowest risk, highest leverage cut.**

### Files to delete

- [ ] `internal/proxy/sigv4_signer.go`
- [ ] `internal/proxy/sigv4_signer_test.go`
- [ ] `internal/proxy/github_app_signer.go`
- [ ] `internal/proxy/github_app_signer_test.go`
- [ ] `internal/proxy/jwt.go` (only used by GH-App signer)
- [ ] `internal/proxy/jwt_test.go`
- [ ] `internal/proxy/signer_result.go`
- [ ] `internal/cli/aws_placeholder.go`
- [ ] `internal/cli/correlate/aws.go`
- [ ] `internal/cli/correlate/aws_test.go`
- [ ] `internal/placeholder/provider_aws.go`
- [ ] `internal/placeholder/provider_aws_test.go`

### Files to edit

- [ ] `internal/proxy/injector.go` — remove `signAWSSigV4` and `signGitHubAppJWT` calls; remove `shim` request construction; remove signer-result handling
- [ ] `internal/proxy/proxy.go` — remove `firstSignerFailure` check + 502 path
- [ ] `internal/proxy/errors.go` — remove signer error sentinels
- [ ] `internal/cli/add.go` — remove `--scheme aws`, `--scheme github_app`, `--experimental` (hidden), `--aws-access-key-id`, `--aws-session-token-file`, `--aws-session-token-stdin`, `--github-app-id`, `--github-installation-id` flags. Remove `addAWS`/`addGitHubApp` paths. Update Example block (currently shows AWS).
- [ ] `internal/cli/add_test.go` — drop scheme/experimental tests
- [ ] `internal/cli/log.go` — remove hidden `--signer-failed` flag
- [ ] `internal/cli/init_phases.go` — remove `aws` case in `buildEnvFileCredentials`, `applyEnvFileMutations`, `printDryRunVaultLines`, `selectEnvKeys` (header AWS counts)
- [ ] `internal/placeholder/auth_scheme.go` — remove `AuthSigV4`, `AuthJWT_RS256` enum values + their `AuthSchemeReason` cases
- [ ] `internal/vault/record.go` — remove `AWSAccessKeyID`, `AWSAccessKeyIDPlaceholder`, `AWSSessionToken`, `AWSSessionTokenPlaceholder`, `GitHubAppID`, `GitHubInstallationID`, `GitHubAppPrivateKeyPEM` fields and `Scheme: "aws" / "github_app"` paths
- [ ] `internal/vault/vault.go` — `addPlaceholders` drops AWS placeholder fields
- [ ] `internal/placeholder/engine.go` — sentinel comment mentions hex providers; tidy
- [ ] `internal/cli/correlate/correlate.go` — remove `awsCorrelator` from chain; remove AWS fields from `Group` struct

### Docs to edit

- [ ] `docs/MVP.md` — delete §5 "Experimental, not yet stable" block; drop AWS/GitHub-App from gaps table
- [ ] `README.md` — drop "AWS SigV4 / GitHub App" from roadmap line; revise v0.1.x scope sentence
- [ ] `CHANGELOG.md` — note signers removed

---

## Phase 2 — Basic auth (providers + correlator + decoder)

Every wire-failure launch blocker from the review involved Basic auth. Without a paired username, the proxy fail-closes with 502. Cut Basic entirely for v1; users can `veil add NAME --value-stdin` if they really need it (Bearer fallback).

### Providers to remove from registry

- [ ] `npm` (Format in `provider_formats.go`)
- [ ] `pypi` (Format in `provider_formats.go`)
- [ ] `docker_hub` (Format in `provider_formats.go`)
- [ ] `twilio` (handwritten in `provider_twilio.go`)

### Files to delete

- [ ] `internal/placeholder/provider_twilio.go`
- [ ] `internal/placeholder/provider_twilio_test.go`
- [ ] `internal/cli/correlate/basic.go`
- [ ] `internal/cli/correlate/basic_test.go`
- [ ] `internal/cli/correlate/twilio.go`
- [ ] `internal/cli/correlate/twilio_test.go`
- [ ] `internal/proxy/basic_decoder.go`
- [ ] `internal/proxy/basic_decoder_test.go`
- [ ] `internal/proxy/basic_integration_test.go`

### Files to edit

- [ ] `internal/placeholder/provider_formats.go` — delete `npm`, `pypi`, `docker_hub` Format registrations
- [ ] `internal/placeholder/auth_scheme.go` — remove `AuthBasic` from enum + `VaultEligible` check (only AuthBearer survives)
- [ ] `internal/proxy/injector.go` — delete `decodeAndSwapBasic` pre-pass call; delete `ClassifyBasicLeak` method
- [ ] `internal/proxy/proxy.go` — delete `isBasicAuthHeader`, `basicAuthLeaked` helpers; remove `(basic)` location suffix; remove `basic_unpaired` X-Veil-Error
- [ ] `internal/cli/add.go` — remove `--user` flag, `isBasic` branch, `addBasic` path
- [ ] `internal/cli/init_phases.go` — remove `basic` case in `buildEnvFileCredentials`, `applyEnvFileMutations`, `printDryRunVaultLines`, `selectEnvKeys` headers, `recoverPendingEnvRewrite` UsernameVar divergence check
- [ ] `internal/vault/record.go` — remove `Username`, `UsernamePlaceholder`, `UsernameVar` fields and `Scheme: "basic"` paths
- [ ] `internal/vault/vault.go` — `addPlaceholders` drops UsernamePlaceholder
- [ ] `internal/cli/list.go` — remove `(basic)` tag rendering
- [ ] `internal/cli/correlate/correlate.go` — remove `basicCorrelator`, `twilioCorrelator` from chain; remove `Basic` field from `Group`; remove `BasicGroup` struct entirely; whole package may collapse to nothing — DELETE THE PACKAGE if nothing else uses `Group`
- [ ] `internal/scanner/environ.go` — drop `ScanEnvironForPairs` (only used by basic correlator)

### Docs to edit

- [ ] `README.md` — drop "Basic" from headline; drop Twilio, npm, PyPI, Docker Hub from provider table
- [ ] `docs/MVP.md` — drop "HTTP Basic" mediation language; drop npm/PyPI/Docker examples
- [ ] `internal/placeholder/readme_contract_test.go` — update expected provider list

---

## Phase 3 — MCP scanning

Largest cut. MCP config rewriting has cross-project blast radius (user-scope `~/Library/.../claude_desktop_config.json` affects every project), doubles init's code path, lacks recovery parity with `.env` path, and is the source of two launch blockers (Twilio-in-MCP, missing recovery). Cut entirely.

### Files to delete

- [ ] `internal/mcpconfig/` — entire package (mcpconfig.go and tests, locations.go, etc.)

### Files to edit

- [ ] `internal/cli/init.go` — remove `--scan-mcp` flag, `processMCPConfig` function, `mcpDisplayLabel`, `skippedMCP`, `managedMCP`, `mcpSecret`, all MCP loops in `runInit`
- [ ] `internal/cli/init_phases.go` — remove `mcpconfig` import; remove MCP parent-anchor loop in `refuseSymlinkedInputs`; remove `mcpSentinelHits`; remove MCP loops in `refusePlaceholderInputs`, `filterInputs`
- [ ] `internal/scanner/scanner.go` — remove `MCPConfigs` from `ScanResult`; rename `ScanAll` → `Scan` or merge
- [ ] `internal/scanner/walker.go` — remove project-MCP discovery (`.mcp.json`, `.cursor/mcp.json`) from walk
- [ ] `internal/cli/uninstall.go` — remove MCP backup discovery, MCP classification, MCP-specific paths; simplify `discoverBackups` to env-only
- [ ] `internal/vault/meta.go` — `FileKind` can drop `KindMCP`, becomes single-kind; consider simplifying `VaultedFiles` to `[]string`
- [ ] `internal/envkeys/envkeys.go` — remove `VEIL_MCP_CONFIG_PATH`, `VEIL_MCP_DISABLE_DISCOVERY` from VeilInternalKeys

### Docs to edit

- [ ] `README.md` — remove `--scan-mcp` mentions; remove MCP row from support table
- [ ] `docs/MVP.md` — remove `--scan-mcp` from `veil init` row; remove MCP §3 mentions

---

## Phase 4 — Shell-env scanning (`--scan-shell-env`)

Niche, bypasses `VaultEligible` gate (per init reviewer C4), and the runner already has a belt-and-suspenders `scanUnvaultedSecretLikes` warning. Cut the init flag.

### Files to delete

- [ ] `internal/cli/init_shellenv.go`
- [ ] `internal/cli/init_shellenv_test.go` (if exists)

### Files to edit

- [ ] `internal/cli/init.go` — remove `--scan-shell-env` flag and `processShellEnv` call
- [ ] `internal/scanner/environ.go` — drop the entire file (only used by `--scan-shell-env`)
- [ ] `internal/scanner/environ_test.go` — drop
- [ ] `internal/runner/envscan.go` — keep but simplify; could collapse to plain name-match warning without IsSecretLike
- [ ] `internal/cli/run.go` — consider whether `--allow-env-secret` is still needed; keep for now

### Docs to edit

- [ ] `README.md` — drop `--scan-shell-env` mentions
- [ ] `docs/MVP.md` — drop from `veil init` flag list

---

## Phase 5 — URL-with-password DSN handling

`postgres://`, `mysql://`, `mongodb://`, `redis://`, `amqp://` are TCP protocols, not HTTP. Vaulting them produces placeholders the proxy cannot inject (the connection bypasses Veil entirely). Either restrict to `http`/`https` only, or cut the whole path.

### Recommended: cut entirely

- [ ] `internal/placeholder/url.go` — delete file
- [ ] `internal/placeholder/url_test.go` — delete
- [ ] `internal/placeholder/engine.go` — remove `tryURL` call in `generateOnce`
- [ ] `internal/placeholder/hosts.go` — `ExtractURLHost` may still be wanted for provider URL detection; check and remove if unused
- [ ] `internal/placeholder/reason.go` — remove `ReasonURLUserinfo` kind
- [ ] `internal/cli/init_phases.go` — remove URL-with-password branch in `classifyCredential`
- [ ] `internal/placeholder/secretlike.go` — remove `IsURLWithPassword` references in `DetectWithReason`

### Alternative: restrict to http/https

- [ ] `internal/placeholder/url.go` — change `allowedSchemes` to `{http, https}` only
- [ ] Add regression test for `postgres://` falling through to `bucketUnrecognized`

---

## Phase 6 — Mismatch detector + audit schema simplification

The mismatch detector is diagnostic, not enforcement. It exists to surface "agent sent an Authorization header but no injection fired" — useful but not load-bearing for the core promise. Drop it along with the audit columns that only support it and signers.

### Files to delete

- [ ] `internal/proxy/mismatch_detector.go`
- [ ] `internal/proxy/mismatch_detector_test.go`

### Files to edit

- [ ] `internal/proxy/injector.go` — remove mismatch post-pass (lines ~209-228); remove `anyNonBlocked` if no other caller
- [ ] `internal/audit/audit.go` — schema simplification:
  - Drop `suspect_flag` column
  - Drop `auth_signal` column
  - Drop `signer_error` column
  - Revert to schema v1 or v2 (rename current to v4 with migration if you want safety)
  - Drop indexes on `suspect_flag`
- [ ] `internal/audit/query.go` — drop `IncludeSuspect`, `SuspectOnly` filter fields; remove `[!]` suspect-row marker logic
- [ ] `internal/cli/log.go` — remove hidden `--blocked`, `--suspect` flags (signer-failed already removed in Phase 1); remove ANSI markers for suspect rows; remove `LOCATION` column conditional
- [ ] `internal/cli/status.go` — remove "Run `veil log --suspect`" hint when leaks > 0; just show count
- [ ] `internal/audit/audit_test.go` and `query_test.go` — drop tests for removed columns

### Docs to edit

- [ ] `docs/MVP.md` — drop transform-mismatch-detector paragraph and `--suspect` / `--blocked` / `--signer-failed` from `veil log` flag list
- [ ] `README.md` — drop any mismatch-detector language

---

## Phase 7 — Niche surface

Small, independent cuts. Each reduces test burden and onboarding friction.

### `veil list --reveal`

- [ ] `internal/cli/list.go` — remove `--reveal`, `--yes` flags; remove `--placeholder` (keep names+hosts only); drop TTY safety check, ReadPassword path; drop audit `reveal` location entry
- [ ] `internal/audit/audit.go` — remove `reveal` from valid Location values (if enumerated anywhere)
- [ ] `internal/cli/list_test.go` — drop reveal tests

### Java truststore

- [ ] `internal/proxy/cabundle.go` — drop `BuildJavaTruststoreIn`, `JavaToolOptionsFlags`
- [ ] `internal/runner/runner.go` — drop Java truststore build + JAVA_TOOL_OPTIONS merge in `buildChildEnv`; simplify env construction
- [ ] `internal/envkeys/envkeys.go` — drop `JavaToolOptions` constant
- [ ] `go.mod` — drop `software.sslmate.com/src/go-pkcs12` dependency

### Bypass warnings

- [ ] `internal/runner/bypasscheck.go` — delete (docker on darwin, dotnet, sccache warnings)
- [ ] `internal/runner/bypasscheck_test.go` — delete
- [ ] `internal/runner/runner.go` — remove `bypassWarningForCommand` call in banner

### `veil skip` as a standalone command

Collapse to `veil run --skip` only. The persistent skip-host file becomes internal-only (no CLI surface).

- [ ] `internal/cli/skip.go` — delete entirely
- [ ] `internal/cli/root.go` — remove `skipCmd()` from root command registration
- [ ] `internal/skiphost/` — keep package but drop `--list`/`--remove` API; only `Validate` + ephemeral pass-through stays

### Hidden `--experimental`

(Already removed in Phase 1, but explicit:)

- [ ] `internal/cli/add.go` — remove `MarkHidden("experimental")` call

---

## Phase 8 — Docs + CHANGELOG cleanup

Once code is stable, prune the documentation surface so v1 docs match v1 code.

### Files to delete

- [ ] `docs/USE_CASES.md` (34 use cases, most are out-of-scope post-cuts)
- [ ] `docs/ARCHITECTURE.md` (aspirational Part II; revisit post-v1)
- [ ] `docs/DOCKER.md` (Docker bypass requires per-platform workarounds; defer to issue tracker)
- [ ] `docs/RELEASING.md` — keep internal-only; do not link from README

### Files to rewrite

- [ ] `README.md` — rewrite around single promise: "Bearer API keys in .env → keychain → inject on outbound HTTPS"
  - Drop FAQ items about non-HTTP protocols, MCP, Basic auth, Docker, signers
  - Trim provider list to surviving Bearer providers only
  - Single quick-start: `brew install` → `veil init` → `veil run claude`
  - Threat model section: keep it brief, link to THREAT_MODEL.md
- [ ] `docs/MVP.md` — rewrite as v1 scope contract: Bearer only, .env only, macOS+Linux, no signers, no MCP, no Basic, no DSN, no shell-env
- [ ] `docs/THREAT_MODEL.md` — remove signer / Basic / MCP sections; remove the "AuthScheme" gap table rows that no longer apply
- [ ] `CHANGELOG.md` — fix v0.1.0 entry to remove Postmark/Datadog/Quay/GCR/AWS/GH-App from provider list. Add a v1.0.0 (or v0.2.0) entry summarizing the scope reduction.

### Files to verify

- [ ] `SECURITY.md` — verify still accurate
- [ ] `CONTRIBUTING.md` — drop references to dropped subsystems

---

## Phase 9 — Final code-path simplifications

These become possible only after the cuts above. Land last.

- [ ] **Simplify `auth_scheme.go` to a boolean.** With only `AuthBearer` and `AuthUnknown` surviving, the whole `AuthScheme` enum can become `VaultEligible bool` on `ProviderPattern`. Delete `AuthSchemeReason`, `placeholder.Reason` annotation system.

- [ ] **Simplify `bucketEligible` / `bucketNotManaged` / `bucketUnrecognized`.** With no signers and no Basic, "not managed" no longer means "wrong scheme" — it just means "not a Bearer provider and no host scope". Collapse `classifyCredential` to a binary: vault-eligible or not.

- [ ] **Simplify init summary output.** Three sections (Managed / Not managed / Unrecognized) can become two (Vaulted / Skipped).

- [ ] **Simplify `vault.meta`.** Without MCP cross-root restore, `VaultedFiles` registry is redundant — backups live next to their .env. Drop the registry, simplify uninstall.

- [ ] **Drop scheme field from Credential.** With only Bearer remaining, `Credential.Scheme` is constant.

- [ ] **Drop `Reload` API on injector.** Unused in production.

- [ ] **Collapse `Format` and `ProviderPattern` into one type.** With no AWS handwritten provider, every provider can be declarative.

- [ ] **Drop `priority.go` priority tiers.** Without handwritten vs declarative distinction, priority becomes uniform.

- [ ] **Drop `IsObviouslyNotSecret` from runner's envscan.** Simpler name-match.

---

## What survives — the v1 surface

For reference, after all cuts:

**Commands:** `init`, `run`, `status`, `add`, `list`, `remove`, `uninstall` (7 total)

**Flags:**
- `veil init` — `--force`, `--yes`, `--dry-run`, `--path`
- `veil run` — `--skip` (ephemeral)
- `veil add` — `--value`, `--value-stdin`, `--host`, `--force`
- `veil list` — none beyond global
- `veil log` — `--since`, `--host`, `--credential`, `--limit`, `--json`
- `veil remove` — `--force`/`--yes`
- `veil uninstall` — `--dry-run`, `--yes`, `--force`

**Providers (Bearer only):** OpenAI, Anthropic, Stripe (secret keys only), Slack, Google, GitHub PAT, Resend, Vercel, Replicate, Hugging Face, GitLab, SendGrid, Supabase. Plus entropy/name-pattern fallback for unknown Bearer-shaped secrets (manual `--host` required).

**Subsystems:** Scanner (.env only), Vault (AES-GCM + OS keychain + file fallback), Proxy (MITM + AC injector + sentinel guard), Audit (minimal), Runner (process + signals), CA management.

**Estimated cut:** ~5,000 LOC + ~2,650 test LOC + ~800 doc lines (≈18% of codebase).

---

## Risk register

Things to watch for during the cuts:

- **Vault on-disk format changes** (Phase 9 — dropping `Scheme`, AWS/Basic placeholder fields). Either:
  - (a) Bump vault meta version and refuse to open older vaults (forces `veil init --force` on upgrade), or
  - (b) Tolerant unmarshal — old fields ignored, never re-written. Recommended.
- **Audit schema migration** (Phase 6). SQLite has cheap `ALTER TABLE DROP COLUMN` only on newer versions; safer to write a new schema_v4 migration that creates a clean table and copies rows. Or just `DROP TABLE` since audit is ephemeral session data.
- **Keystore entries** for AWS/Basic creds in users' existing vaults. After cut, those creds become unreadable. Mitigation: on `veil run`, log + skip credentials whose scheme is no longer supported, don't fail open.
- **Provider lint test** (`readme_contract_test.go`) — must be updated in lockstep with each provider removal or CI breaks.
- **Integration tests** — `test/integration/` exercises real keystore. After Phase 2, drop Basic-pair integration tests.
