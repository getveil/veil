# Format-Aware Placeholder Expansion

## Problem

Veil replaces real secrets in `.env` files with placeholder values. These placeholders must be convincing at two levels:

1. **SDK validation** — Client SDKs often validate key format (prefix, length, charset) before making network calls. If the placeholder fails validation, the SDK throws before the request reaches Veil's proxy, and the agent notices something is wrong.
2. **LLM pattern recognition** — AI coding agents read `.env` files on every request. If placeholders look structurally wrong (missing known prefixes, wrong length, uniform random noise), the agent may recognize them as fake and behave differently.

Today, Veil has 6 hand-authored providers (GitHub, OpenAI, Anthropic, Stripe, AWS, Slack). Any key that doesn't match falls through to a `charClassFake` fallback that preserves character classes but loses provider-specific structure. Real-world tokens like `github_pat_*` (fine-grained PATs) are not recognized and produce visibly fake replacements.

## Goal

Expand format-aware placeholder coverage to 20 providers. Placeholders must be **structurally correct** — right prefix, right length, right charset. This is sufficient to pass SDK validation and avoid raising LLM suspicion.

## Design

### Hybrid approach

Two registration paths coexist in the same `registry` slice:

- **Format-based** — A `Format` struct declares prefix, length, charset, and hosts. A generic engine auto-generates `Match` and `Generate` functions. Used for providers with simple prefix+random patterns (~14 providers).
- **Hand-authored** — Custom `Match`/`Generate` functions in dedicated `provider_*.go` files. Used for providers with complex structural rules (~6 providers).

### The Format struct

```go
type Format struct {
    Name     string
    Prefixes []string  // e.g. ["ghp_", "github_pat_"]
    KeyHints []string  // substrings to match in env key name, e.g. ["GOOGLE_API", "FIREBASE_API"]
    Length   int       // total length including prefix (0 = match input length)
    Charset  string    // "alphanumeric", "hex", "base64", "upper-alphanumeric"
    Hosts    []string
}
```

Match logic: value starts with any prefix, OR key name contains any KeyHint (case-insensitive).

Generate logic: preserve matched prefix, fill remainder with random characters from the specified charset to the specified length. If Length is 0, preserve the input's length.

### Registration and priority

`registerFormat(f Format)` constructs a `ProviderPattern` from a `Format` and calls `register()`. All format-based providers register in a single `init()` in `provider_zzz_formats.go`. Go's lexicographic `init()` ordering within a package means hand-authored `provider_*.go` files register first. The existing first-match-wins iteration in `Generate()` ensures hand-authored providers take priority.

### Provider coverage

#### Existing hand-authored (updated)

| Provider | Change |
|---|---|
| GitHub | Add `github_pat_` prefix. Handle two-part structure: `github_pat_` + 22 alnum + `_` + 59 alnum. |
| OpenAI | No changes. |
| Anthropic | No changes. |
| Stripe | No changes. |
| AWS | No changes. |
| Slack | No changes. |

#### New format-based (in `provider_zzz_formats.go`)

| Provider | Prefixes | KeyHints | Length | Charset | Hosts |
|---|---|---|---|---|---|
| Google AI / Firebase | `AIza` | `GOOGLE_API`, `FIREBASE_API` | 39 | alphanumeric | `generativelanguage.googleapis.com`, `firebaseapp.com`, `*.googleapis.com` |
| Replicate | `r8_` | `REPLICATE` | 40 | alphanumeric | `api.replicate.com` |
| HuggingFace | `hf_` | `HUGGING`, `HF_` | 37 | alphanumeric | `huggingface.co`, `api-inference.huggingface.co` |
| Vercel | `vercel_` | `VERCEL` | 0 | alphanumeric | `api.vercel.com` |
| GitLab | `glpat-` | `GITLAB` | 26 | alphanumeric | `gitlab.com` |
| npm | `npm_` | `NPM_TOKEN` | 36 | alphanumeric | `registry.npmjs.org` |
| Resend | `re_` | `RESEND` | 0 | alphanumeric | `api.resend.com` |
| Postmark | (none) | `POSTMARK` | 36 | hex | `api.postmarkapp.com` |
| Datadog | (none) | `DATADOG`, `DD_API` | 32 | hex | `api.datadoghq.com`, `*.datadoghq.com` |

#### New hand-authored (new `provider_*.go` files)

| Provider | File | Why hand-authored |
|---|---|---|
| SendGrid | `provider_sendgrid.go` | Two base64 segments separated by `.` — format is `SG.` + 22 base64 chars + `.` + 43 base64 chars. |
| Twilio | `provider_twilio.go` | Two distinct key types: API Key SID (`SK` + 32 hex) and Auth Token (32 hex, no prefix, matched by name). Different generation logic per key type. |
| Supabase | `provider_supabase.go` | JWTs with three dot-separated base64url segments. Header must decode to valid JSON. |

### JWT generation (Supabase)

Supabase `.env` files contain `SUPABASE_ANON_KEY` and `SUPABASE_SERVICE_ROLE_KEY`, both JWTs.

**Generation strategy:**

1. **Header** — fixed: `{"alg":"HS256","typ":"JWT"}`, base64url-encoded to `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`. All real Supabase keys use this header.
2. **Payload** — valid JSON: `{"iss":"supabase","ref":"<random 20 chars>","role":"<role>","iat":<recent>,"exp":<future>}`. Role inferred from key name: `anon` for anon keys, `service_role` for service role keys. Base64url-encoded.
3. **Signature** — 43 random base64url characters. Not verifiable without the signing secret, so random is correct.

**Match logic:** key name contains `SUPABASE`, or value is a JWT (three dot-separated segments where the first decodes to JSON with an `alg` field).

**Hosts:** `*.supabase.co`, `*.supabase.com`

### Files changed

**Modified:**
- `providers.go` — add `Format` struct and `registerFormat()` function
- `provider_github.go` — add `github_pat_` prefix, handle two-part structure

**New:**
- `provider_zzz_formats.go` — single `init()` registering 9 format-based providers
- `provider_sendgrid.go` — `SG.` + two base64 segments
- `provider_twilio.go` — SID + auth token
- `provider_supabase.go` — JWT generation with decodable header

**New tests:**
- `provider_zzz_formats_test.go` — table-driven test: correct prefix, length, charset, hosts for all 9 entries
- `provider_sendgrid_test.go` — validates two-segment structure
- `provider_twilio_test.go` — validates SID format and auth token format
- `provider_supabase_test.go` — validates JWT structure, decodable header, role inference
- Update existing `providers_test.go` — add `github_pat_` test case

**No changes outside `internal/placeholder/`.** The vault, proxy, injector, and CLI consume providers through the existing `Generate()` and `HostsForCredential()` functions.

### What this does NOT change

- The `charClassFake` fallback — still handles unknown providers
- The `secretlike.go` detection heuristics — unchanged
- The proxy injector — unchanged, consumes placeholders as before
- The vault data model — unchanged
- The CLI surface — unchanged
