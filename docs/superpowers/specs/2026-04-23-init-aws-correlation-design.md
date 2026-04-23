# `veil init` AWS Credential Correlation — Design

**Status:** design, approved for implementation planning.
**Predecessors:**
- `docs/superpowers/specs/2026-04-22-signature-auth-design.md` — established the `Scheme: "aws"` credential shape and the explicit-add flow (`veil add --scheme aws`). Also explicitly deferred init-time auto-detection, citing the risk of heuristic mis-pairing and pointing users at the runtime mismatch_detector as the compensating signal.

**Scope:** teach `veil init` to detect AWS credential groups (access key ID + secret access key + optional session token) in `.env` files and the shell environment, vault each group as a single `Scheme: "aws"` credential, and rewrite the source with the appropriate placeholders — replacing the current behavior of emitting three independent bearer-style credentials that the AWS SigV4 signer cannot use.

---

## Goals

1. Running `veil init` against a project whose `.env` (or shell environment) contains canonical AWS credentials produces a working `Scheme: "aws"` credential without the user having to run `veil remove` + `veil add --scheme aws` by hand.
2. Multiple AWS accounts in the same file (distinguished by env-var prefix/suffix) produce one credential each — no mis-pairing across accounts.
3. Non-AWS or partially-present AWS variables continue to flow through the existing bearer-style path unchanged. No regressions for non-AWS projects.
4. Non-interactive (`--yes` / non-TTY) runs apply correlation automatically on unambiguous groups; they do not require a human prompt to get a signed credential.
5. The abstraction used for AWS correlation is shaped so that adding GitHub App correlation later is a file-add + one dispatch-list line, not a refactor.

## Non-goals

- GitHub App (`Scheme: "github_app"`) correlation. GitHub App requires pairing a PEM-shaped secret with a non-secret App ID (and optional installation ID) that the current secret-scanner does not surface. Deferred; covered by a future spec.
- MCP-config (`mcp.json`) correlation. Real-world MCP servers rarely carry AWS credentials; the added complexity isn't justified. If usage emerges, the same `Correlator` interface applies.
- Upgrading existing bearer-style AWS credentials left in the vault by pre-correlation init runs. Users wanting the upgrade run `veil remove <name>` followed by `veil init --force` or `veil add --scheme aws --force`.
- Host overrides per correlated group during init. Init hard-codes `*.amazonaws.com` (matching `veil add --scheme aws` default). FIPS regions or GovCloud are handled post-init via `veil add --scheme aws --force --host ...`.
- Cross-file correlation. Each `.env` file and the shell environment are correlated independently; the scanner never pairs an ID from one file with a secret in another.
- Replacing the runtime `mismatch_detector`. It remains in place for users who decline correlation, use invalid AKID values, run older versions, or produce partially-present groups.

---

## Relationship to the signature-auth spec

The signature-auth design (`docs/superpowers/specs/2026-04-22-signature-auth-design.md` §`veil init (.env auto-detection)`) recorded init's current bearer-only behavior as an explicit choice, with two rationales:

1. **Heuristic pairing is error-prone** — multiple AWS accounts in one `.env` risk mis-pairing.
2. **The mismatch_detector surfaces the failure** — bearer-AWS credentials fail to sign at request time, and the detector tells the user to run `veil add --scheme aws`.

This spec overrides rationale (1) with a *strict decoration-matching* rule (see §Correlation algorithm) that makes mis-pairing structurally impossible — the algorithm either produces a clean pairing or falls through to bearer, never pairs an ID from one account with a secret from another. Rationale (2) is preserved: the mismatch_detector stays for all the cases correlation doesn't cover (partial groups, invalid value shapes, declined prompts).

The §`veil init` paragraph of the signature-auth spec should be annotated "superseded by 2026-04-23-init-aws-correlation-design.md" after this design is implemented.

---

## Architecture

### Package layout

New package: `internal/cli/correlate` — CLI-adjacent because correlation is init-time-only policy, not a vault-level or proxy-level concern.

Files:
- `internal/cli/correlate/correlate.go` — `Correlator` interface, `Group` / `Candidate` types, `DetectAll` dispatch function.
- `internal/cli/correlate/aws.go` — `awsCorrelator` implementing `Correlator`.
- `internal/cli/correlate/correlate_test.go`, `internal/cli/correlate/aws_test.go` — unit coverage.

### Types

```go
// Candidate is one secret-like key/value pair passed into the correlator.
// Matches what processEnvFile and processShellEnv already build internally.
type Candidate struct {
    Key   string
    Value string
}

// Group is one correlated credential, ready to be vaulted as a scheme.
// Scheme-specific payload is scoped by Scheme.
type Group struct {
    Scheme  string      // "aws" for now
    Name    string      // vault credential name (access-key-ID var's name)
    Members []Candidate // candidates consumed by this group
    AWS     *AWSGroup   // non-nil iff Scheme == "aws"
}

// AWSGroup carries the real values and source variable names for an AWS
// credential group. Populated by awsCorrelator.Detect.
type AWSGroup struct {
    AccessKeyID     string // real AKIA/ASIA value
    SecretKey       string // real secret access key
    SessionToken    string // empty if group has no session token

    AccessKeyIDVar  string // source env-var name for AccessKeyID
    SecretKeyVar    string // source env-var name for SecretKey
    SessionTokenVar string // source env-var name for SessionToken ("" iff no session)
}

// Correlator consumes a flat list of secret-like candidates (per file, per
// shell env) and returns correlation groups plus the remaining uncorrelated
// candidates that fall back to bearer-style vaulting.
type Correlator interface {
    Detect(candidates []Candidate) (groups []Group, remaining []Candidate)
}
```

### Dispatch

```go
// DetectAll runs each registered correlator in order. Candidates consumed by
// one correlator are not passed to subsequent correlators. Order of
// registration determines precedence when schemes overlap (in practice they
// don't — PEMs and AKIDs are structurally distinct).
func DetectAll(candidates []Candidate) (groups []Group, remaining []Candidate)
```

Implementation detail: `DetectAll` holds a hardcoded slice `[]Correlator{awsCorrelator{}}`. No public `Register` surface, no plugin loading — adding github_app later is a file add plus one slice entry. A formal registry can be introduced if and when a third scheme arrives.

### Call sites

- `internal/cli/init_phases.go:processEnvFile` calls `correlate.DetectAll` on the post-`IsSecretLike` candidates for one file.
- `internal/cli/init_shellenv.go:processShellEnv` calls `correlate.DetectAll` on the filtered shell-env candidates.
- `internal/cli/init.go:processMCPConfig` is **not** modified (MCP correlation is out of scope).

---

## Correlation algorithm (AWS)

### Decoration extraction

For each candidate whose key matches `^(.*?)AWS_ACCESS_KEY_ID(.*)$` (case-sensitive, uppercase only — AWS SDKs do not honor lowercase env var names), capture `(prefix, suffix)`. That pair is the group's *decoration* and acts as the unique key for pairing the other two members.

### Detection loop

```
for each candidate c with key matching the access-key-ID regex:
    (prefix, suffix) = decoration(c.Key)

    // Value-shape guard: only real AKIA|ASIA values trigger correlation.
    if c.Value doesn't match ^(AKIA|ASIA)[A-Z0-9]{16}$:
        continue   // c stays in the bearer stream

    // Exact-decoration pairing with the secret access key.
    secretKey = find candidate with Key == prefix + "AWS_SECRET_ACCESS_KEY" + suffix
    if secretKey is nil:
        continue   // c stays in bearer; secretKey absent means no group

    // Optional session token, same decoration.
    sessionToken = find candidate with Key == prefix + "AWS_SESSION_TOKEN" + suffix

    members := [c, secretKey]
    if sessionToken != nil: members = append(members, sessionToken)

    emit Group{
        Scheme: "aws",
        Name:   c.Key,     // the access-key-ID var name; deterministic, no new naming convention
        Members: members,
        AWS: &AWSGroup{
            AccessKeyID:     c.Value,
            SecretKey:       secretKey.Value,
            SessionToken:    sessionToken.Value if present else "",
            AccessKeyIDVar:  c.Key,
            SecretKeyVar:    secretKey.Key,
            SessionTokenVar: sessionToken.Key if present else "",
        },
    }
    mark {c, secretKey, sessionToken} as consumed

remaining = candidates not consumed by any group
```

### Scenario coverage

| Input | Outcome |
|---|---|
| `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` | 1 group, decoration `("", "")`, no session token. |
| Canonical triple (ID + SAK + session) | 1 group, 3 members. |
| `PROD_AWS_*` + `DEV_AWS_*` in same file | 2 groups, decorations `("PROD_", "")` and `("DEV_", "")`. |
| `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` + `AWS_ACCESS_KEY_ID_OLD` | 1 group (canonical). `AWS_ACCESS_KEY_ID_OLD` has no `AWS_SECRET_ACCESS_KEY_OLD` → stays bearer. |
| Access key ID value that doesn't match `AKIA|ASIA` (e.g., test fixture) | No group. All three members fall through as bearer. |
| ID present, secret absent | No group; ID stays bearer. |
| Secret present, ID absent | No group; secret stays bearer. |
| Session token without ID+secret pair | No group; token stays bearer. |
| Two `.env` files, one with ID, one with secret | Correlator runs per-file. No cross-file group. |

### Why strict matching eliminates the "multiple accounts" concern

Decoration is a structural key, not a heuristic. `PROD_AWS_ACCESS_KEY_ID` has decoration `("PROD_", "")`; it can only pair with `PROD_AWS_SECRET_ACCESS_KEY`, never with `DEV_AWS_SECRET_ACCESS_KEY`. The original "heuristic pairing is error-prone" rationale from the signature-auth spec does not apply here — there is no heuristic, only exact string matching. Invalid decorations or missing partners fall through to bearer silently; the runtime mismatch_detector catches anything that escapes.

---

## Integration with init phases

### Changes to `processEnvFile` (internal/cli/init_phases.go)

Insert correlation between the existing `IsSecretLike` filter and the selector:

```go
// Existing: build secrets []secretLine from IsSecretLike-passing lines.

candidates := toCandidates(secrets)               // []correlate.Candidate
groups, remaining := correlate.DetectAll(candidates)
remainingSecrets := filterByKey(secrets, remaining)  // preserve file order

selectedGroups, selectedSecrets := selectEnvKeys(
    in, w, root, envPath,
    groups, remainingSecrets, interactive,
)

// New: vault groups (see §Group vaulting below).
for _, g := range selectedGroups { ... }

// Unchanged: vault selectedSecrets via existing bearer loop.
```

### Changes to `processShellEnv` (internal/cli/init_shellenv.go)

Similar shape to `processEnvFile`, with one critical difference: the existing "drop candidates already in vault" filter must be applied *after* correlation, not before. See §Edge cases "Shell-env de-dup" for the reasoning. Sketch:

```go
candidates := toCorrelateCandidates(shellCandidates)
candidates = dropEmpty(candidates)
groups, remaining := correlate.DetectAll(candidates)
groups = dropGroupsAlreadyInVault(v, groups)
remaining = dropCandidatesAlreadyInVault(v, remaining)
// then: selectShellEnvKeys(... groups, remaining ...)
```

Shell-env vaulting of a group produces no file rewriting (there is no file).

### Selector signature

```go
func selectEnvKeys(
    in io.Reader, w io.Writer, root, envPath string,
    groups []correlate.Group, secrets []secretLine, interactive bool,
) (selectedGroups []correlate.Group, selectedSecrets []secretLine)
```

Behavior:
- Non-interactive (`--yes` or non-TTY): returns all groups + all secrets.
- Interactive Y: all.
- Interactive N: nil, nil.
- Interactive S (multi-select): each `[aws] <group name>` is one atomic row. Selecting it pulls in all members; members cannot be split. Standalone bearer secrets remain individually selectable.

### Display format

Single group:
```
Detected 5 secrets in .env.local (3 correlated as AWS):
  [aws]  AWS_ACCESS_KEY_ID       AKIA****
         AWS_SECRET_ACCESS_KEY   ****
         AWS_SESSION_TOKEN       FwoG****
  DATABASE_URL                   post****
  ANTHROPIC_API_KEY              sk-a****

Vault all? [Y/n/s]
```

Multiple groups:
```
Detected 6 secrets in .env (2 AWS credentials):
  [aws]  PROD_AWS_ACCESS_KEY_ID      AKIA****
         PROD_AWS_SECRET_ACCESS_KEY  ****
         PROD_AWS_SESSION_TOKEN      FwoG****
  [aws]  DEV_AWS_ACCESS_KEY_ID       AKIA****
         DEV_AWS_SECRET_ACCESS_KEY   ****

Vault all? [Y/n/s]
```

The summary line reads `(N correlated as AWS)` when all correlated vars belong to one group and `(N AWS credentials)` when multiple groups are present.

### Group vaulting

```go
for _, g := range selectedGroups {
    secretPh, err := placeholder.Generate(g.Name, g.AWS.SecretKey, seen)
    // error handling mirrors existing bearer flow
    seen[secretPh] = struct{}{}

    akIDPh := generateAWSAccessKeyIDPlaceholder(g.AWS.AccessKeyID, seen)
    seen[akIDPh] = struct{}{}

    var sessPh string
    if g.AWS.SessionToken != "" {
        sessPh, err = placeholder.GenerateAWSSessionToken(g.AWS.SessionToken, seen)
        seen[sessPh] = struct{}{}
    }

    cred := &vault.Credential{
        ID: vault.NewID(), Name: g.Name, Source: "init",
        Real: g.AWS.SecretKey, Placeholder: secretPh,
        Scheme: "aws",
        AWSAccessKeyID: g.AWS.AccessKeyID,
        AWSAccessKeyIDPlaceholder: akIDPh,
        AWSSessionToken: g.AWS.SessionToken,
        AWSSessionTokenPlaceholder: sessPh,
        AllowedHosts: []string{"*.amazonaws.com"},
        CreatedAt: time.Now(),
    }
    if err := v.Add(cred); err != nil {
        if errors.Is(err, vault.ErrDuplicateCredential) {
            ui.Warnf(...)
            continue
        }
        return // wrapErr
    }

    // File rewrite (processEnvFile only; processShellEnv has no file).
    envFile.SetValue(g.AWS.AccessKeyIDVar, akIDPh)
    envFile.SetValue(g.AWS.SecretKeyVar, secretPh)
    if g.AWS.SessionTokenVar != "" {
        envFile.SetValue(g.AWS.SessionTokenVar, sessPh)
    }

    vaulted++; scoped++  // one credential, scoped by default
}
```

The helper `generateAWSAccessKeyIDPlaceholder` already exists in `internal/cli/add.go`. Move it to a shared location (proposal: `internal/cli/aws_placeholder.go`) so both `runAddAWS` and the init group-vaulting loop call the same function.

### Counts

`secretsVaulted` and `secretsScoped` count *credentials* (rows in `veil list`), not underlying secret values. An AWS group is one credential regardless of whether it holds 2 or 3 values. This preserves the meaning of the final `N secrets stored in keychain` line and matches what the user sees in `veil list`.

### Dry-run output

```
  would vault (aws): AWS_ACCESS_KEY_ID
    AWS_ACCESS_KEY_ID      -> <AKIA placeholder>
    AWS_SECRET_ACCESS_KEY  -> <base64ish placeholder>
    AWS_SESSION_TOKEN      -> <long base64ish placeholder>
```

---

## Edge cases and behavior details

**`--force` re-migration.** Semantics unchanged. If a prior run vaulted a credential with the same name as a newly-correlated group (bearer or aws), `v.Add` returns `ErrDuplicateCredential` → warn-and-skip. The user runs `veil remove <name>` before re-init-ing if they want a clean upgrade. No special bearer→aws in-place upgrade logic.

**`IsSecretLike` coverage.** Implementation must verify that `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` all pass `placeholder.IsSecretLike`. If any miss, the group silently fails to form. If the existing patterns don't cover these names, extend them explicitly — this is a prerequisite for correlation to function.

**Value-shape guard is silent.** An `AWS_ACCESS_KEY_ID` whose value does not match `AKIA|ASIA` + 16 upper-alphanumeric (local dev stubs, mock fixtures) does not form a group and emits no warning. Falling through to bearer is the correct behavior for test data.

**Shell-env de-dup.** The existing `processShellEnv` implementation filters candidates against the vault (by `Candidate.Key == Credential.Name`) *before* vaulting, to avoid re-adding .env-sourced creds. With correlation, this filter must move to *after* the correlator runs and must operate on both arms:

1. `correlate.DetectAll(candidates)` → `(groups, remaining)`.
2. Drop any `Group` whose `Name` already exists in the vault (whole group is dropped — its members do not fall back to bearer).
3. Drop any `Candidate` in `remaining` whose `Key` already exists in the vault.

Reason for the reshuffle: if we filter by name first (current behavior), a shell that exports the full AWS triple after `.env` has vaulted an aws-scheme credential named `AWS_ACCESS_KEY_ID` would drop the ID but keep the orphan `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, which then correlate-fail (no ID partner) and get vaulted as two redundant bearer credentials. Filtering *after* correlation drops the entire would-be-duplicate group cleanly, with no orphan siblings.

Edge sub-case — partial shell export: shell exports only `AWS_SESSION_TOKEN` (e.g., a session-token rotation flow) while the prior AWS credential is in the vault. The token lacks an ID partner in the shell candidates → correlator produces no group → token falls through to `remaining` → the post-correlation name-filter checks whether the vault has a credential named `AWS_SESSION_TOKEN` (it doesn't — the aws-scheme credential is named `AWS_ACCESS_KEY_ID`) → the loose token gets vaulted as a bearer credential. This is a genuine redundancy, but also a genuine rare case (partial rotation without touching the ID). The user is directed to `veil add --scheme aws --force` to rotate properly; documented in release notes.

**Host override.** Init hard-codes `AllowedHosts: []string{"*.amazonaws.com"}`, matching `veil add --scheme aws` default. Users needing FIPS region (`*.amazonaws.com.cn`), GovCloud, or endpoint-specific scoping run `veil add --scheme aws --force --host ...` post-init. No init-level `--host` flag per group.

**Interaction with `mismatch_detector`.** Unchanged. Still active for:
- Users who decline the correlation prompt (press `n`).
- Users whose AWS var values don't match `AKIA|ASIA`.
- Users who have partial groups (ID without secret, etc.).
- Legacy vaults created before correlation shipped.
- Multi-select "s" choice that picks bearer-only members.

---

## Testing strategy

### Unit tests

**`internal/cli/correlate/aws_test.go`** — table-driven, covering every scenario in the algorithm table:
- Empty input → `(nil, nil)`.
- Lone ID → `(nil, [ID])`.
- Canonical pair → 1 group, 2 members.
- Canonical triple → 1 group, 3 members.
- Prefixed pair → 1 group, name = prefixed ID var.
- Suffix pair → 1 group, name = suffixed ID var.
- Two disjoint groups (PROD_ + DEV_) → 2 groups.
- Canonical + `_OLD` suffixed ID with no matching secret → 1 group (canonical), OLD stays remaining.
- Invalid value (not AKIA|ASIA) → no group, all three remain.
- ID alone, secret alone, session alone → each stays bearer.
- Non-AWS noise alongside a group → group formed, noise preserved.

**`internal/cli/correlate/correlate_test.go`** — DetectAll dispatch:
- No correlators registered → input returned as remaining.
- Single correlator → consumed candidates don't leak into remaining.
- Synthetic second correlator → each sees only un-consumed candidates.

**Selector tests (extend `internal/cli/init_test.go`):**
- 0 groups, N secrets → matches current output (regression guard).
- 1 group, 0 secrets → `(N correlated as AWS)` line + indented members.
- 2+ groups → `(M AWS credentials)` plural line.
- Non-interactive → all groups + all secrets returned.
- Y / N / S paths.
- S with group-only / bearer-only selection.

### Integration tests (`internal/cli/init_test.go`)

- Canonical AWS triple + `--yes`: one aws-scheme credential in vault with correct fields; `.env` rewritten with three placeholders.
- Prefixed pair + `--yes`: one aws-scheme credential named `PROD_AWS_ACCESS_KEY_ID`; two placeholders in `.env`.
- Two AWS accounts (PROD_ + DEV_) + `--yes`: two aws-scheme credentials.
- Incomplete AWS (ID only): 1 bearer credential, 0 aws credentials.
- Fake AWS value (`not_akia`): 3 bearer credentials, 0 aws credentials.
- Shell env with exported AWS triple: one aws-scheme credential, no `.env` touched.
- Mixed (.env with AWS triple + DATABASE_URL + ANTHROPIC_API_KEY): 1 aws + 2 bearer.
- Regression (.env with no AWS vars): identical output and vault state to pre-change.
- Interactive with mocked stdin: `y`, `n`, `s` + subset paths.

### Cross-cutting

- All existing `init_test.go` assertions must continue to pass; correlation is additive.
- `add_test.go` AWS-scheme tests are unaffected.
- Proxy signer tests (`internal/proxy/sigv4_signer_test.go`) are unaffected because init-created AWS credentials are byte-compatible with add-created ones — they populate the same `vault.Credential` fields.
- One spot-check integration: init creates an AWS credential → load the vault record → feed a plausible SigV4 request through the proxy injector → verify re-signing succeeds. Reuses existing signer test fixtures.

### Out of testing scope

- Performance. Correlation is O(N) with N = secrets per file, typically < 30.
- Fuzzing env-var names. Table-driven tests are more targeted and more readable than fuzzed garbage.
