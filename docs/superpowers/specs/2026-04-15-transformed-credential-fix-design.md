# Transformed Credential Fix — Design

**Status:** design, approved for implementation planning.
**Predecessor:** `docs/superpowers/findings/2026-04-13-transformed-credential-problem.md`.
**Scope:** fix HTTP Basic auth injection (Class 1 encoded forms) and convert silent failures into diagnosable warnings. Class 2 (keyed crypto) and beyond are out of scope.

---

## Goals

1. Make HTTP Basic auth work end-to-end through Veil for the common dev workflows: `git push`, `docker push`, `twine` upload, `npm publish` via `_auth`, Artifactory/Nexus, `.npmrc`-style registries.
2. Convert silent failures into visible ones so users diagnosing a 401/403 can tell Veil failed to mediate — for transforms we haven't fixed yet (AWS SigV4, JWT signing, etc.).
3. Leave the injector shape amenable to future per-scheme decoders and per-provider signers without building that framework now.

## Non-goals

- Class 2 (keyed crypto): AWS SigV4, GitHub App JWTs, webhook signing.
- Class 3 (OAuth exchange): `gcloud`, Azure CLI.
- Class 4 (mTLS): structurally unfixable under HTTP-proxy-only.
- Basic auth in non-header locations (request body, query param).
- Non-Basic encoded schemes (Digest, DPoP). Left for future demand surfaced by the detector.
- Interactive CLI prompt for the username field (flag-only in v1).

---

## Architecture overview

Two independent pieces land on the `internal/proxy/injector.go` `ProcessRequest` pipeline:

1. **Pre-pass Basic decoder.** Runs before the existing Aho-Corasick literal scan. Parses `Authorization` / `Proxy-Authorization` values, decodes `Basic <base64>`, matches placeholders against the `user:secret` cleartext, swaps in real values, re-encodes. Non-Basic schemes fall through to the literal matcher unchanged.

2. **Post-pass mismatch detector.** Runs after all injection passes. Fires when the request's host matches a credential's `AllowedHosts`, the request looks authed, and zero injections occurred. Emits a structured warning and flags the audit record.

Vault schema gains two fields on `Credential`: `Username` and `UsernamePlaceholder`. A credential is "Basic" iff `Username != ""` — no separate scheme enum.

CLI gains `--user <value>` on `veil add`. Presence of `--user` triggers Basic mode and generates the username placeholder.

No new provider framework, no signer hook, no Class 2 machinery. The decoder is a scheme-specific function inside `internal/proxy/`; future decoders (Digest, etc.) are sibling functions.

---

## Vault schema

```go
// internal/vault/record.go
type Credential struct {
    // ...existing fields unchanged...
    Username            string `json:"username,omitempty"`
    UsernamePlaceholder string `json:"username_placeholder,omitempty"`
}
```

- Both fields are optional and empty for Bearer-style credentials.
- `omitempty` preserves on-disk compatibility with existing vault files; old records load without modification and re-serialize without the new fields.
- `Credential.Zero()` additionally clears `Username` and `UsernamePlaceholder`. Both can be sensitive (see design decision in Section "Username placeholder-ization" below).

### Username placeholder-ization

The username is placeholder-ized symmetrically with the secret, rather than stored plain in `.env`. Rationale: Veil's invariant is "nothing real in `.env`." Storing usernames plain works for the common case (public GitHub usernames, public registry accounts) but quietly leaks for the uncommon case (internal LDAP accounts, customer-tenant identifiers). The cost of symmetry is one extra generated string and one extra `.env` entry — no real complexity.

---

## CLI

### `veil add --user <value>`

```
veil add github-pat --user johndoe --host github.com --value ghp_xxx
```

- Flag `--user <value>` added to `veil add` (`internal/cli/add.go`).
- Validates: `--user` cannot be empty; username cannot contain `:` (RFC 7617 forbids `:` in the user-id).
- When `--user` is present, Veil generates `UsernamePlaceholder` using the existing placeholder-generation machinery in `internal/placeholder/` with a distinct name seed (e.g., `<name>_USER`) so username and secret placeholders don't collide in a single `.env`.
- Interactive stdin prompt still handles the secret value; username is flag-only for v1.

Output example:

```
✓ Added github-pat to vault (basic auth)
    User placeholder:   VEIL_GITHUB_PAT_USER_a1b2c3
    Secret placeholder: VEIL_GITHUB_PAT_x9y8z7
    Hosts: github.com
```

### `veil add --force` for Basic credentials

Existing `--force` replacement path (`add.go:79–86`) captures old placeholder for `.env` sync. For Basic credentials, it performs two sequential sync passes: old-user-placeholder → new-user-placeholder, then old-secret-placeholder → new-secret-placeholder. Reuses existing `syncPlaceholderInEnvFiles`.

### `veil list`

Appends `(basic)` tag next to the credential name when `Username != ""`. No secret, placeholder, or username values leak.

### `veil remove`

No behavior change.

---

## Injector: Basic decoder

**Location:** new file `internal/proxy/basic_decoder.go`, invoked from `ProcessRequest` in `injector.go` before the existing Aho-Corasick scan over header values.

### Per-header flow

For each `Authorization` and `Proxy-Authorization` header value:

1. Parse. If scheme prefix is not `Basic ` (case-insensitive), skip — the existing literal matcher sees the header value unchanged.
2. Base64-decode the credential portion. Decode error → skip (malformed Basic is a client bug; let upstream reject).
3. Split on the first `:`. Missing `:` → skip.
4. Look up both halves against the vault snapshot.
5. Both halves must match placeholders from the **same** credential record. Cross-credential mix (user-placeholder from A, secret-placeholder from B) → no swap. Silently picking one record's values would send the wrong secret upstream; this is almost certainly a config error and the detector will flag it.
6. On match, build `real_user:real_secret`, base64-encode, rewrite the header value as `Basic <new_b64>`. Record the injection in the existing injection counter (same counter the literal matcher feeds, so the detector sees injection > 0).

### Matcher data structure

Flat map `map[string]*Credential` keyed by `UsernamePlaceholder` and by `Placeholder`, built once per `ProcessRequest` from the vault snapshot. Lookup is O(1) per half. For expected N (<100 credentials), no need to integrate with Aho-Corasick.

### Interaction with the existing literal pass

The decoder runs first and mutates the header value in place, swapping the full `Basic <b64>` token. The literal pass then runs over the mutated headers and finds no placeholder text in the already-swapped Basic header. Non-Basic headers are untouched by the decoder and handled normally by the literal pass. No double-swap; order is well-defined.

### Auto-covered by the Basic decoder

OAuth 2.0 `client_secret_basic` token-exchange requests use HTTP Basic with `client_id:client_secret`. Same header form, same decoder path — no extra code needed. A `client_id` vaulted as `Username` and `client_secret` as the secret works identically to the `git push` case.

### Out of scope for the decoder

- Other schemes (`Digest`, `DPoP`, etc.).
- Basic auth in request bodies or query params (RFC 7617 puts Basic in headers; real-world exceptions are vanishingly rare).
- Nested decoding (e.g., Basic inside a JSON body).

---

## Mismatch detector

**Location:** new file `internal/proxy/mismatch_detector.go`. Called from `ProcessRequest` after all injection passes, before the request is forwarded.

### Trigger

```
fires iff:
  injectionCount == 0
  AND request.Host matches some credential's AllowedHosts
  AND request looks authed:
        has non-empty Authorization header
     OR has non-empty Proxy-Authorization header
     OR has Cookie header
     OR any header name matches (case-insensitive) /^x-.*-(token|auth|key|sig|signature)$/
     OR URL query contains key in {auth, signature, sig, token, api_key, apikey, access_token}
```

Host match reuses the existing `AllowedHosts` wildcard logic in `internal/placeholder/hosts.go`.

### Effects when the detector fires

1. **Structured WARN log.** One line via the existing logger. Fields: `event=transform_mismatch_suspected`, `host`, `path`, `method`, `credential_names` (names of credentials whose `AllowedHosts` covered this host — not real/placeholder values), `auth_signal` (which heuristic triggered). Never logs any secret, placeholder, or header value.

2. **Audit record flag.** New boolean field `TransformMismatchSuspected` on the audit record plus the `auth_signal` string. Lands in the existing audit sink.

3. **`veil log` surfacing.** Existing `veil log` command renders audit records; adds a `[!]` tag on flagged records. New `--suspect` flag filters to only flagged records.

### What the detector does NOT do

- Does not block the request. Forwarded unchanged; upstream will 401/403 and Veil provides a parallel diagnostic.
- Does not inject a response header back to the agent. Coupling to agent behavior is fragile.
- Does not rate-limit warnings. A misconfigured integration hammering a credentialed host generates many warnings — that is the correct signal, bounded by request volume.

### False-positive posture

The heuristic will occasionally fire on a legitimate no-auth request to a credentialed host (rare: `api.github.com/zen` with no auth header would not trigger because no auth signal; the actual FP shape is something like an OAuth device-code request using an unvaulted token on a credentialed host). The worst outcome is a log line. False positives are preferable to silent misses.

---

## Testing strategy

### Vault schema tests

- Round-trip a Basic credential (with `Username` + `UsernamePlaceholder`) through save → load; values preserved.
- Load a vault file written by the pre-change schema; new fields default empty; credential treated as Bearer.
- `Zero()` clears `Username` and `UsernamePlaceholder`.

### CLI tests (extend `internal/cli/cli_test.go`)

- `veil add --user johndoe` on a fresh vault produces a credential with both placeholders, prints both, writes both to `.env` if a `.env` exists.
- Rejects empty `--user`.
- Rejects `--user "bad:user"` (contains `:`).
- `--user ... --force` on an existing Basic credential triggers both sync passes.
- `veil list` shows `(basic)` tag for Basic credentials.

### Decoder unit tests (new `internal/proxy/basic_decoder_test.go`)

- Happy path: `Basic base64(user_ph:secret_ph)` → `Basic base64(real_user:real_secret)`, injection count = 1.
- `Proxy-Authorization` handled identically.
- Case-insensitive scheme (`basic `, `BASIC `).
- Non-Basic scheme (`Bearer ...`) untouched.
- Malformed base64 → untouched, falls through.
- Missing `:` in decoded payload → untouched.
- Cross-credential mix → untouched, no swap.
- Plain secret placeholder in a non-Basic header handled by the existing literal matcher (regression test).
- Empty Authorization header → untouched.

### Detector unit tests (new `internal/proxy/mismatch_detector_test.go`)

- Fires when host in AllowedHosts, zero injections, Authorization header present.
- Fires on Cookie header / `X-Api-Token` header / `?auth=xxx` query param.
- Does not fire when host not in any AllowedHosts.
- Does not fire when injectionCount > 0.
- Does not fire when no auth-shaped signal.
- Audit record field set; log line emitted with expected fields and no sensitive values.

### `veil log` tests

- `[!]` tag appears on records where `TransformMismatchSuspected=true`.
- `--suspect` filter returns only those records.

### Integration test — Basic flow end-to-end

- Local HTTP server expects `Authorization: Basic base64(johndoe:ghp_real)` and returns 401 otherwise.
- `veil run` a curl process with `.env` containing the two placeholders; curl uses `-u "$PH_USER:$PH_SECRET"`.
- Assert upstream sees real credentials and returns 200; audit shows one injection, no suspect flag.

### Integration test — detector end-to-end

- Same harness. Configure a credential with `AllowedHosts=[localhost]` that won't be matched on the wire (e.g., Authorization header carries a bearer-shaped value the decoder skips and whose literal bytes don't match any placeholder).
- Assert upstream returns 401; warning logged; audit record flagged.

### Out of scope for tests

- Real AWS SigV4 vectors (Class 2, separate workstream).
- Basic in request bodies.
- Property-based fuzzing of the decoder.

---

## Product-copy followups

Ship in the same PR as the code so docs and code don't drift:

- `PRODUCT.md` §3 and §4: add an auth-scheme coverage note — bearer tokens and HTTP Basic are mediated; other schemes (SigV4, JWT-signed, mTLS) are not yet.
- `MVP.md` Features section: same clarification.
- `docs/THREAT_MODEL.md`: note that keyed-crypto credentials reach upstream unredacted-but-rejected, with the detector as diagnostic signal rather than enforcement.
- Hold back AWS-specific "works" language wherever it implies a working integration. The `*.amazonaws.com` provider registration stays for now; removing it is a separate product call, and the detector firing on AWS CLI traffic is the correct near-term signal.

---

## Success criteria

1. `git push https://github.com/...` via `veil run` with a Basic credential in `.env` succeeds; audit record shows one injection.
2. `aws s3 ls` via `veil run` with AWS credentials in `.env` fails (Class 2 still unhandled) **and** emits a `transform_mismatch_suspected` warning + flagged audit record.
3. `curl https://api.openai.com/...` via `veil run` with a Bearer credential is unchanged — no new warnings, no regression.

---

## Pointers to existing code

- Injector pipeline: `internal/proxy/injector.go` (`ProcessRequest` at :66).
- Placeholder host scoping: `internal/placeholder/hosts.go`; `internal/vault/record.go:18` (`AllowedHosts`).
- Placeholder generation: `internal/placeholder/providers.go:70–79`, `charclass.go`.
- CLI add path: `internal/cli/add.go` (flags and sync at :28–33, :126–150).
- Existing injector tests (Bearer coverage): `internal/proxy/injector_test.go`.
- `veil log` rendering: `internal/cli/log.go`.
