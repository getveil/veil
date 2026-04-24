# `veil init` AWS Credential Correlation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Teach `veil init` to correlate `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (+ optional `AWS_SESSION_TOKEN`) in `.env` files and the shell environment into a single `Scheme: "aws"` vault credential, instead of three independent bearer-style credentials that the SigV4 signer cannot use.

**Architecture:** New CLI-adjacent package `internal/cli/correlate` exposes a `Correlator` interface, `Candidate`/`Group` types, and a hard-coded `DetectAll` dispatch. One concrete correlator (`awsCorrelator`) uses strict decoration matching (`^(.*?)AWS_ACCESS_KEY_ID(.*)$` prefix/suffix, exact string equality for partners). `processEnvFile` and `processShellEnv` call `DetectAll` between the `IsSecretLike` filter and the selector; groups vault as one aws-scheme credential, remaining candidates vault via the existing bearer path. The shell-env "already in vault" filter moves post-correlation to avoid orphan-sibling leaks.

**Tech Stack:** Go 1.22+, existing packages (`internal/cli`, `internal/placeholder`, `internal/scanner`, `internal/vault`). Standard library only — no new dependencies. Tests use the existing `t.Setenv`/`openVault` helpers.

**Spec:** `docs/superpowers/specs/2026-04-23-init-aws-correlation-design.md`.

---

## File Structure

**Create:**
- `internal/cli/correlate/correlate.go` — `Correlator` interface, `Candidate`/`Group`/`AWSGroup` types, `DetectAll` dispatch.
- `internal/cli/correlate/correlate_test.go` — `DetectAll` dispatch tests.
- `internal/cli/correlate/aws.go` — `awsCorrelator` with decoration-matching algorithm + value-shape guard.
- `internal/cli/correlate/aws_test.go` — table-driven unit tests for every scenario row in the spec.
- `internal/cli/aws_placeholder.go` — shared home for `generateAWSAccessKeyIDPlaceholder` (moved from `add.go`).

**Modify:**
- `internal/cli/init_phases.go` — thread `[]correlate.Group` + `[]correlate.Candidate` through `processEnvFile` and `selectEnvKeys`; vault groups; render grouped display.
- `internal/cli/init_shellenv.go` — move vault-existence filter post-correlation; vault groups; update selector signature.
- `internal/cli/add.go` — delete the local `generateAWSAccessKeyIDPlaceholder` definition (reference the moved copy).
- `internal/cli/init_test.go` — extend with AWS correlation integration scenarios.
- `internal/cli/init_shellenv_test.go` — add shell-AWS correlation integration tests.
- `docs/superpowers/specs/2026-04-22-signature-auth-design.md` — annotate the `veil init` paragraph as superseded.

Why this decomposition: correlation logic is pure and testable in its own package. Init callers keep orchestration (read file, prompt user, write file), not correlation policy. The `generateAWSAccessKeyIDPlaceholder` move makes `add.go` and the init group-vaulting loop call the same helper — DRY.

**secretLine note:** The `index` field on `secretLine` (init_phases.go:107-112) is already unused by callers. This plan does not rename or eliminate the struct — it keeps churn minimal. `selectEnvKeys` gains one additional parameter (`groups []correlate.Group`) but keeps taking `[]secretLine`.

---

## Task 1: Scaffold the `correlate` package

**Files:**
- Create: `internal/cli/correlate/correlate.go`
- Create: `internal/cli/correlate/correlate_test.go`

- [ ] **Step 1: Write the failing test for `DetectAll` pass-through**

Create `internal/cli/correlate/correlate_test.go`:

```go
package correlate

import (
	"reflect"
	"testing"
)

func TestDetectAll_EmptyInput(t *testing.T) {
	groups, remaining := DetectAll(nil)
	if len(groups) != 0 {
		t.Errorf("groups = %v, want empty", groups)
	}
	if len(remaining) != 0 {
		t.Errorf("remaining = %v, want empty", remaining)
	}
}

func TestDetectAll_NoCorrelationJustPassesThrough(t *testing.T) {
	in := []Candidate{
		{Key: "OPENAI_API_KEY", Value: "sk-proj-1234567890abcdef"},
		{Key: "DATABASE_URL", Value: "postgres://user:pw@h/db"},
	}
	groups, remaining := DetectAll(in)
	if len(groups) != 0 {
		t.Errorf("groups = %v, want empty", groups)
	}
	if !reflect.DeepEqual(remaining, in) {
		t.Errorf("remaining = %v, want %v", remaining, in)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cli/correlate/...`
Expected: FAIL with "no Go files" or undefined identifiers (`Candidate`, `DetectAll`).

- [ ] **Step 3: Write the minimal implementation**

Create `internal/cli/correlate/correlate.go`:

```go
// Package correlate detects related credential groups among flat lists of
// secret-like env-var candidates. Init phases call DetectAll to distinguish
// scheme-requiring groups (e.g., AWS SigV4 triples) from loose bearer-style
// secrets. This file is the dispatch + types only; per-scheme logic lives
// in sibling files (aws.go, etc.).
package correlate

// Candidate is one secret-like key/value pair fed into the correlator.
// Matches the shape already built internally by processEnvFile and
// processShellEnv.
type Candidate struct {
	Key   string
	Value string
}

// Group is one correlated credential, ready to be vaulted as a scheme.
// Scheme-specific payload is discriminated by Scheme.
type Group struct {
	Scheme  string
	Name    string
	Members []Candidate
	AWS     *AWSGroup
}

// AWSGroup carries the real values and source variable names for an AWS
// credential group.
type AWSGroup struct {
	AccessKeyID     string
	SecretKey       string
	SessionToken    string
	AccessKeyIDVar  string
	SecretKeyVar    string
	SessionTokenVar string
}

// Correlator consumes a flat list of secret-like candidates and returns
// correlation groups plus the remaining uncorrelated candidates.
type Correlator interface {
	Detect(candidates []Candidate) (groups []Group, remaining []Candidate)
}

// correlators is the fixed dispatch list. Adding a new scheme is one line
// here plus the sibling file. Order matters when schemes could overlap
// (in practice PEMs and AKIDs are structurally distinct, so overlap is
// unreachable).
var correlators = []Correlator{}

// DetectAll runs each registered correlator in order, passing only
// remaining (un-consumed) candidates to later correlators.
func DetectAll(candidates []Candidate) (groups []Group, remaining []Candidate) {
	remaining = candidates
	for _, c := range correlators {
		g, r := c.Detect(remaining)
		groups = append(groups, g...)
		remaining = r
	}
	return groups, remaining
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cli/correlate/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/correlate/correlate.go internal/cli/correlate/correlate_test.go
git commit -m "feat(correlate): scaffold init-time credential correlation package"
```

---

## Task 2: Implement `awsCorrelator` (TDD, table-driven)

**Files:**
- Create: `internal/cli/correlate/aws.go`
- Create: `internal/cli/correlate/aws_test.go`

- [ ] **Step 1: Write the failing test file**

Create `internal/cli/correlate/aws_test.go`:

```go
package correlate

import (
	"reflect"
	"sort"
	"testing"
)

// sortCandidates returns a copy sorted by Key for deterministic comparisons.
func sortCandidates(cs []Candidate) []Candidate {
	out := append([]Candidate(nil), cs...)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func TestAWSCorrelator(t *testing.T) {
	tests := []struct {
		name       string
		input      []Candidate
		wantGroups []Group
		wantRem    []Candidate
	}{
		{
			name:       "empty input",
			input:      nil,
			wantGroups: nil,
			wantRem:    nil,
		},
		{
			name: "lone access-key-ID stays bearer",
			input: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7EXAMPLE"},
			},
			wantGroups: nil,
			wantRem: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7EXAMPLE"},
			},
		},
		{
			name: "canonical pair (no session)",
			input: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7EXAMPLE"},
				{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
			},
			wantGroups: []Group{{
				Scheme: "aws",
				Name:   "AWS_ACCESS_KEY_ID",
				Members: []Candidate{
					{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7EXAMPLE"},
					{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
				},
				AWS: &AWSGroup{
					AccessKeyID:    "AKIAIOSFODNN7EXAMPLE",
					SecretKey:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					AccessKeyIDVar: "AWS_ACCESS_KEY_ID",
					SecretKeyVar:   "AWS_SECRET_ACCESS_KEY",
				},
			}},
			wantRem: nil,
		},
		{
			name: "canonical triple",
			input: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID", Value: "ASIAIOSFODNN7EXAMPLE"},
				{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
				{Key: "AWS_SESSION_TOKEN", Value: "FwoGZXIvYXdzEJr//////////wEaDP"},
			},
			wantGroups: []Group{{
				Scheme: "aws",
				Name:   "AWS_ACCESS_KEY_ID",
				Members: []Candidate{
					{Key: "AWS_ACCESS_KEY_ID", Value: "ASIAIOSFODNN7EXAMPLE"},
					{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
					{Key: "AWS_SESSION_TOKEN", Value: "FwoGZXIvYXdzEJr//////////wEaDP"},
				},
				AWS: &AWSGroup{
					AccessKeyID:     "ASIAIOSFODNN7EXAMPLE",
					SecretKey:       "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					SessionToken:    "FwoGZXIvYXdzEJr//////////wEaDP",
					AccessKeyIDVar:  "AWS_ACCESS_KEY_ID",
					SecretKeyVar:    "AWS_SECRET_ACCESS_KEY",
					SessionTokenVar: "AWS_SESSION_TOKEN",
				},
			}},
			wantRem: nil,
		},
		{
			name: "prefixed pair",
			input: []Candidate{
				{Key: "PROD_AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7EXAMPLE"},
				{Key: "PROD_AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
			},
			wantGroups: []Group{{
				Scheme: "aws",
				Name:   "PROD_AWS_ACCESS_KEY_ID",
				Members: []Candidate{
					{Key: "PROD_AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7EXAMPLE"},
					{Key: "PROD_AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
				},
				AWS: &AWSGroup{
					AccessKeyID:    "AKIAIOSFODNN7EXAMPLE",
					SecretKey:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					AccessKeyIDVar: "PROD_AWS_ACCESS_KEY_ID",
					SecretKeyVar:   "PROD_AWS_SECRET_ACCESS_KEY",
				},
			}},
			wantRem: nil,
		},
		{
			name: "suffixed pair",
			input: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID_OLD", Value: "AKIAIOSFODNN7EXAMPLE"},
				{Key: "AWS_SECRET_ACCESS_KEY_OLD", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
			},
			wantGroups: []Group{{
				Scheme: "aws",
				Name:   "AWS_ACCESS_KEY_ID_OLD",
				Members: []Candidate{
					{Key: "AWS_ACCESS_KEY_ID_OLD", Value: "AKIAIOSFODNN7EXAMPLE"},
					{Key: "AWS_SECRET_ACCESS_KEY_OLD", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
				},
				AWS: &AWSGroup{
					AccessKeyID:    "AKIAIOSFODNN7EXAMPLE",
					SecretKey:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					AccessKeyIDVar: "AWS_ACCESS_KEY_ID_OLD",
					SecretKeyVar:   "AWS_SECRET_ACCESS_KEY_OLD",
				},
			}},
			wantRem: nil,
		},
		{
			name: "two disjoint groups (PROD_ and DEV_)",
			input: []Candidate{
				{Key: "PROD_AWS_ACCESS_KEY_ID", Value: "AKIAPRODEXAMPLE00001"},
				{Key: "PROD_AWS_SECRET_ACCESS_KEY", Value: "prod/secret/example"},
				{Key: "DEV_AWS_ACCESS_KEY_ID", Value: "AKIADEVEXAMPLE000001"},
				{Key: "DEV_AWS_SECRET_ACCESS_KEY", Value: "dev/secret/example"},
			},
			wantGroups: []Group{
				{
					Scheme: "aws",
					Name:   "PROD_AWS_ACCESS_KEY_ID",
					Members: []Candidate{
						{Key: "PROD_AWS_ACCESS_KEY_ID", Value: "AKIAPRODEXAMPLE00001"},
						{Key: "PROD_AWS_SECRET_ACCESS_KEY", Value: "prod/secret/example"},
					},
					AWS: &AWSGroup{
						AccessKeyID:    "AKIAPRODEXAMPLE00001",
						SecretKey:      "prod/secret/example",
						AccessKeyIDVar: "PROD_AWS_ACCESS_KEY_ID",
						SecretKeyVar:   "PROD_AWS_SECRET_ACCESS_KEY",
					},
				},
				{
					Scheme: "aws",
					Name:   "DEV_AWS_ACCESS_KEY_ID",
					Members: []Candidate{
						{Key: "DEV_AWS_ACCESS_KEY_ID", Value: "AKIADEVEXAMPLE000001"},
						{Key: "DEV_AWS_SECRET_ACCESS_KEY", Value: "dev/secret/example"},
					},
					AWS: &AWSGroup{
						AccessKeyID:    "AKIADEVEXAMPLE000001",
						SecretKey:      "dev/secret/example",
						AccessKeyIDVar: "DEV_AWS_ACCESS_KEY_ID",
						SecretKeyVar:   "DEV_AWS_SECRET_ACCESS_KEY",
					},
				},
			},
			wantRem: nil,
		},
		{
			name: "canonical + orphan _OLD suffix stays bearer",
			input: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7EXAMPLE"},
				{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
				{Key: "AWS_ACCESS_KEY_ID_OLD", Value: "AKIAOLDROTATED000001"},
			},
			wantGroups: []Group{{
				Scheme: "aws",
				Name:   "AWS_ACCESS_KEY_ID",
				Members: []Candidate{
					{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7EXAMPLE"},
					{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
				},
				AWS: &AWSGroup{
					AccessKeyID:    "AKIAIOSFODNN7EXAMPLE",
					SecretKey:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					AccessKeyIDVar: "AWS_ACCESS_KEY_ID",
					SecretKeyVar:   "AWS_SECRET_ACCESS_KEY",
				},
			}},
			wantRem: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID_OLD", Value: "AKIAOLDROTATED000001"},
			},
		},
		{
			name: "invalid AKID shape — all three stay bearer",
			input: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID", Value: "not_akia_value_12345"},
				{Key: "AWS_SECRET_ACCESS_KEY", Value: "some_long_entropy_enough_sk"},
				{Key: "AWS_SESSION_TOKEN", Value: "FwoGZXIvYXdzEJr//////////wEaDP"},
			},
			wantGroups: nil,
			wantRem: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID", Value: "not_akia_value_12345"},
				{Key: "AWS_SECRET_ACCESS_KEY", Value: "some_long_entropy_enough_sk"},
				{Key: "AWS_SESSION_TOKEN", Value: "FwoGZXIvYXdzEJr//////////wEaDP"},
			},
		},
		{
			name: "secret without ID stays bearer",
			input: []Candidate{
				{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
			},
			wantGroups: nil,
			wantRem: []Candidate{
				{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
			},
		},
		{
			name: "session token without pair stays bearer",
			input: []Candidate{
				{Key: "AWS_SESSION_TOKEN", Value: "FwoGZXIvYXdzEJr//////////wEaDP"},
			},
			wantGroups: nil,
			wantRem: []Candidate{
				{Key: "AWS_SESSION_TOKEN", Value: "FwoGZXIvYXdzEJr//////////wEaDP"},
			},
		},
		{
			name: "non-AWS noise preserved alongside group",
			input: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7EXAMPLE"},
				{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
				{Key: "DATABASE_URL", Value: "postgres://u:p@h/db"},
				{Key: "OPENAI_API_KEY", Value: "sk-proj-1234567890abcdef"},
			},
			wantGroups: []Group{{
				Scheme: "aws",
				Name:   "AWS_ACCESS_KEY_ID",
				Members: []Candidate{
					{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7EXAMPLE"},
					{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
				},
				AWS: &AWSGroup{
					AccessKeyID:    "AKIAIOSFODNN7EXAMPLE",
					SecretKey:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					AccessKeyIDVar: "AWS_ACCESS_KEY_ID",
					SecretKeyVar:   "AWS_SECRET_ACCESS_KEY",
				},
			}},
			wantRem: []Candidate{
				{Key: "DATABASE_URL", Value: "postgres://u:p@h/db"},
				{Key: "OPENAI_API_KEY", Value: "sk-proj-1234567890abcdef"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c awsCorrelator
			gotGroups, gotRem := c.Detect(tt.input)

			if !reflect.DeepEqual(gotGroups, tt.wantGroups) {
				t.Errorf("groups mismatch:\n got = %#v\nwant = %#v", gotGroups, tt.wantGroups)
			}
			if !reflect.DeepEqual(sortCandidates(gotRem), sortCandidates(tt.wantRem)) {
				t.Errorf("remaining mismatch:\n got = %#v\nwant = %#v", gotRem, tt.wantRem)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cli/correlate/... -run TestAWSCorrelator -v`
Expected: FAIL — undefined `awsCorrelator`.

- [ ] **Step 3: Implement `awsCorrelator`**

Create `internal/cli/correlate/aws.go`:

```go
package correlate

import "regexp"

// awsKeyIDRegex captures decoration around the AWS_ACCESS_KEY_ID token.
// Case-sensitive, uppercase only — AWS SDKs do not honor lowercase env
// var names, so loosening case would invite false positives against
// user-owned lowercase keys like my_aws_access_key_id_override.
var awsKeyIDRegex = regexp.MustCompile(`^(.*?)AWS_ACCESS_KEY_ID(.*)$`)

// awsAccessKeyIDValue mirrors the add-time regex used by runAddAWS. Only
// real AKIA|ASIA-shaped values trigger correlation; local dev stubs and
// mock fixtures fall through to bearer.
var awsAccessKeyIDValue = regexp.MustCompile(`^(AKIA|ASIA)[A-Z0-9]{16}$`)

// awsCorrelator pairs an AWS access key ID with its secret (and optional
// session token) using strict decoration matching.
type awsCorrelator struct{}

// Detect emits one Group per valid access-key-ID candidate that has a
// decoration-matched secret partner. Optional session token is included
// when present under the same decoration. Consumed candidates (including
// the session token) are removed from remaining.
func (awsCorrelator) Detect(candidates []Candidate) (groups []Group, remaining []Candidate) {
	byKey := make(map[string]Candidate, len(candidates))
	for _, c := range candidates {
		byKey[c.Key] = c
	}
	consumed := make(map[string]struct{}, len(candidates))

	for _, c := range candidates {
		m := awsKeyIDRegex.FindStringSubmatch(c.Key)
		if m == nil {
			continue
		}
		if !awsAccessKeyIDValue.MatchString(c.Value) {
			continue
		}
		prefix, suffix := m[1], m[2]

		secretKeyName := prefix + "AWS_SECRET_ACCESS_KEY" + suffix
		secretKey, ok := byKey[secretKeyName]
		if !ok {
			continue
		}

		sessionTokenName := prefix + "AWS_SESSION_TOKEN" + suffix
		sessionToken, hasSession := byKey[sessionTokenName]

		members := []Candidate{c, secretKey}
		if hasSession {
			members = append(members, sessionToken)
		}

		aws := &AWSGroup{
			AccessKeyID:    c.Value,
			SecretKey:      secretKey.Value,
			AccessKeyIDVar: c.Key,
			SecretKeyVar:   secretKey.Key,
		}
		if hasSession {
			aws.SessionToken = sessionToken.Value
			aws.SessionTokenVar = sessionToken.Key
		}

		groups = append(groups, Group{
			Scheme:  "aws",
			Name:    c.Key,
			Members: members,
			AWS:     aws,
		})
		consumed[c.Key] = struct{}{}
		consumed[secretKey.Key] = struct{}{}
		if hasSession {
			consumed[sessionToken.Key] = struct{}{}
		}
	}

	for _, c := range candidates {
		if _, done := consumed[c.Key]; done {
			continue
		}
		remaining = append(remaining, c)
	}
	return groups, remaining
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cli/correlate/... -run TestAWSCorrelator -v`
Expected: PASS, all 12 table entries.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/correlate/aws.go internal/cli/correlate/aws_test.go
git commit -m "feat(correlate): implement strict-decoration AWS correlator"
```

---

## Task 3: Register `awsCorrelator` with `DetectAll`

**Files:**
- Modify: `internal/cli/correlate/correlate.go`
- Modify: `internal/cli/correlate/correlate_test.go`

- [ ] **Step 1: Write the failing test for dispatch that consumes candidates**

Append to `internal/cli/correlate/correlate_test.go`:

```go
func TestDetectAll_AWSTripleIsConsumed(t *testing.T) {
	in := []Candidate{
		{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7EXAMPLE"},
		{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{Key: "AWS_SESSION_TOKEN", Value: "FwoGZXIvYXdzEJr//////////wEaDP"},
		{Key: "OPENAI_API_KEY", Value: "sk-proj-1234567890abcdef"},
	}
	groups, remaining := DetectAll(in)
	if len(groups) != 1 || groups[0].Scheme != "aws" {
		t.Fatalf("expected 1 aws group, got %v", groups)
	}
	if len(remaining) != 1 || remaining[0].Key != "OPENAI_API_KEY" {
		t.Errorf("remaining = %v, want only OPENAI_API_KEY", remaining)
	}
}
```

- [ ] **Step 2: Run tests to verify the new one fails**

Run: `go test ./internal/cli/correlate/... -run TestDetectAll_AWSTripleIsConsumed -v`
Expected: FAIL — `DetectAll` still returns no groups because the dispatch list is empty.

- [ ] **Step 3: Wire `awsCorrelator` into the dispatch list**

Edit `internal/cli/correlate/correlate.go`. Change:

```go
var correlators = []Correlator{}
```

to:

```go
var correlators = []Correlator{
	awsCorrelator{},
}
```

- [ ] **Step 4: Run all correlate tests to verify**

Run: `go test ./internal/cli/correlate/... -v`
Expected: PASS (including the pre-existing pass-through test, which still passes because its inputs contain no AWS vars).

- [ ] **Step 5: Commit**

```bash
git add internal/cli/correlate/correlate.go internal/cli/correlate/correlate_test.go
git commit -m "feat(correlate): register awsCorrelator with DetectAll dispatch"
```

---

## Task 4: Move `generateAWSAccessKeyIDPlaceholder` to a shared file

**Rationale:** The init group-vaulting loop in Task 5 needs this helper. Leaving it in `add.go` means importing across command files; extracting it to a neutral `aws_placeholder.go` keeps the callers symmetric and makes future shared AWS-specific helpers have a home.

**Files:**
- Create: `internal/cli/aws_placeholder.go`
- Modify: `internal/cli/add.go`

- [ ] **Step 1: Create the new file with the extracted function**

Create `internal/cli/aws_placeholder.go`:

```go
package cli

import "github.com/8enji/veil/internal/placeholder"

// generateAWSAccessKeyIDPlaceholder asks the AWS provider for a placeholder
// of the given access key ID, retrying up to a small budget to avoid
// collisions with already-issued placeholders. Shared by runAddAWS and the
// init-time AWS correlation flow.
func generateAWSAccessKeyIDPlaceholder(realAKID string, existing placeholder.Set) string {
	p, ok := placeholder.DefaultRegistry().Get("aws")
	if !ok {
		// Should never happen: aws provider is registered at init.
		return realAKID
	}
	for i := 0; i < 10; i++ {
		cand := p.Generate(realAKID)
		if _, clash := existing[cand]; !clash {
			return cand
		}
	}
	// Fallback: shouldn't happen with 16-char random bodies.
	return p.Generate(realAKID)
}
```

- [ ] **Step 2: Delete the original definition from `add.go`**

In `internal/cli/add.go`, delete the full function definition that currently lives around line 434-451:

```go
// generateAWSAccessKeyIDPlaceholder asks the AWS provider for a placeholder
// of the given access key ID, retrying up to a small budget to avoid
// collisions with already-issued placeholders.
func generateAWSAccessKeyIDPlaceholder(realAKID string, existing placeholder.Set) string {
	p, ok := placeholder.DefaultRegistry().Get("aws")
	if !ok {
		// Should never happen: aws provider is registered at init.
		return realAKID
	}
	for i := 0; i < 10; i++ {
		cand := p.Generate(realAKID)
		if _, clash := existing[cand]; !clash {
			return cand
		}
	}
	// Fallback: shouldn't happen with 16-char random bodies.
	return p.Generate(realAKID)
}
```

Use the Edit tool to remove that block (including the leading blank line). If `placeholder` is no longer referenced elsewhere in `add.go`, keep its import — it is still used by `placeholder.Generate`, `placeholder.GenerateAWSSessionToken`, `placeholder.IsSecretLike`, etc. in `add.go`. Verify with a grep after the edit.

- [ ] **Step 3: Run all tests under `internal/cli/` to verify no regressions**

Run: `go test ./internal/cli/... -count=1`
Expected: PASS. In particular, the existing `TestAddAWS_*` tests in `add_test.go` still pass because the function was moved, not renamed.

- [ ] **Step 4: Commit**

```bash
git add internal/cli/aws_placeholder.go internal/cli/add.go
git commit -m "refactor(cli): move generateAWSAccessKeyIDPlaceholder to shared file"
```

---

## Task 5: Wire correlation into `processEnvFile`

**Files:**
- Modify: `internal/cli/init_phases.go`

- [ ] **Step 1: Write the failing end-to-end test for `.env` AWS correlation**

Append to `internal/cli/init_test.go`:

```go
func TestInit_CorrelatesAWSTripleInEnvFile(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	clearShellEnvTestNoise(t)

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	envContent := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n" +
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n" +
		"AWS_SESSION_TOKEN=FwoGZXIvYXdzEJr//////////wEaDPexample\n" +
		"DATABASE_URL=postgres://u:pw@h/db\n"
	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	v, err := openVault(tmpDir)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}

	// Exactly one AWS-scheme credential (named after the access-key-ID var).
	awsCred, ok := v.Get("AWS_ACCESS_KEY_ID")
	if !ok {
		t.Fatalf("vault missing AWS_ACCESS_KEY_ID; names = %v", v.Names())
	}
	if awsCred.Scheme != "aws" {
		t.Errorf("Scheme = %q, want aws", awsCred.Scheme)
	}
	if awsCred.AWSAccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("AWSAccessKeyID = %q", awsCred.AWSAccessKeyID)
	}
	if awsCred.Real != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Errorf("Real (secret access key) = %q", awsCred.Real)
	}
	if awsCred.AWSSessionToken != "FwoGZXIvYXdzEJr//////////wEaDPexample" {
		t.Errorf("AWSSessionToken = %q", awsCred.AWSSessionToken)
	}
	if awsCred.AWSAccessKeyIDPlaceholder == "" {
		t.Error("AWSAccessKeyIDPlaceholder is empty")
	}
	if awsCred.AWSSessionTokenPlaceholder == "" {
		t.Error("AWSSessionTokenPlaceholder is empty")
	}
	if len(awsCred.AllowedHosts) != 1 || awsCred.AllowedHosts[0] != "*.amazonaws.com" {
		t.Errorf("AllowedHosts = %v, want [*.amazonaws.com]", awsCred.AllowedHosts)
	}

	// Separate sibling bearer secrets were NOT created.
	for _, name := range []string{"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		if _, found := v.Get(name); found {
			t.Errorf("unexpected bearer credential %q in vault (should be absorbed into aws group)", name)
		}
	}

	// DATABASE_URL vaulted as bearer.
	if _, ok := v.Get("DATABASE_URL"); !ok {
		t.Error("vault missing DATABASE_URL")
	}

	// .env rewritten: all three AWS values replaced.
	envData, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	envStr := string(envData)
	for _, real := range []string{
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"FwoGZXIvYXdzEJr//////////wEaDPexample",
	} {
		if strings.Contains(envStr, real) {
			t.Errorf(".env still contains real value %q:\n%s", real, envStr)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/cli/ -run TestInit_CorrelatesAWSTripleInEnvFile -v`
Expected: FAIL — three separate bearer creds are in the vault, `AWS_ACCESS_KEY_ID` has no `Scheme=aws`.

- [ ] **Step 3: Update `processEnvFile` to call `correlate.DetectAll` and vault groups**

Edit `internal/cli/init_phases.go`.

1. Add the import:

```go
"github.com/8enji/veil/internal/cli/correlate"
```

2. Replace the block in `processEnvFile` that currently reads:

```go
	var secrets []secretLine
	w := cmd.OutOrStdout()
	for i, line := range envFile.Lines {
		if line.Kind != scanner.KVLine {
			continue
		}
		if !placeholder.IsSecretLike(line.Key, line.Value) {
			if flagVerbose {
				ui.Dimf(w, "  skip (not secret-like): %s", line.Key)
			}
			continue
		}
		secrets = append(secrets, secretLine{key: line.Key, value: line.Value, index: i})
	}
	if len(secrets) == 0 {
		return 0, 0, nil
	}

	selectedKeys := selectEnvKeys(in, w, root, envPath, secrets, interactive)
	if len(selectedKeys) == 0 {
		return 0, 0, nil
	}

	var vaulted, scoped int
	fileChanged := false
	for _, s := range secrets {
		if !selectedKeys[s.key] {
			continue
		}

		ph, err := placeholder.Generate(s.key, s.value, seen)
		if err != nil {
			return vaulted, scoped, wrapErr(fmt.Sprintf("generating placeholder for %s", s.key), err)
		}

		credHosts := placeholder.HostsForCredential(s.key, s.value)

		cred := &vault.Credential{
			ID:           vault.NewID(),
			Name:         s.key,
			Real:         s.value,
			Placeholder:  ph,
			Source:       "init",
			AllowedHosts: credHosts,
			CreatedAt:    time.Now(),
		}
		if err := v.Add(cred); err != nil {
			if errors.Is(err, vault.ErrDuplicateCredential) {
				ui.Warnf(cmd.ErrOrStderr(), "duplicate key %q, skipping", s.key)
				continue
			}
			return vaulted, scoped, wrapErr(fmt.Sprintf("vaulting %s", s.key), err)
		}
		seen[ph] = struct{}{}

		vaulted++
		if len(credHosts) > 0 {
			scoped++
		}

		if dryRun {
			ui.Dimf(w, "  would vault: %s -> %s", s.key, ph)
		} else {
			envFile.SetValue(s.key, ph)
			fileChanged = true
		}
	}
```

with:

```go
	var secrets []secretLine
	w := cmd.OutOrStdout()
	for i, line := range envFile.Lines {
		if line.Kind != scanner.KVLine {
			continue
		}
		if !placeholder.IsSecretLike(line.Key, line.Value) {
			if flagVerbose {
				ui.Dimf(w, "  skip (not secret-like): %s", line.Key)
			}
			continue
		}
		secrets = append(secrets, secretLine{key: line.Key, value: line.Value, index: i})
	}
	if len(secrets) == 0 {
		return 0, 0, nil
	}

	// Correlate multi-value schemes (e.g., AWS triples) before prompting so
	// the user sees grouped rows and members cannot be split individually.
	cands := make([]correlate.Candidate, len(secrets))
	for i, s := range secrets {
		cands[i] = correlate.Candidate{Key: s.key, Value: s.value}
	}
	groups, remaining := correlate.DetectAll(cands)
	remainingSecrets := filterSecretsByRemaining(secrets, remaining)

	selectedGroups, selectedSecrets := selectEnvKeys(in, w, root, envPath, groups, remainingSecrets, interactive)
	if len(selectedGroups) == 0 && len(selectedSecrets) == 0 {
		return 0, 0, nil
	}

	var vaulted, scoped int
	fileChanged := false

	for _, g := range selectedGroups {
		n, s, changed, err := vaultAWSGroup(cmd, v, seen, envFile, g, dryRun)
		if err != nil {
			return vaulted, scoped, err
		}
		vaulted += n
		scoped += s
		if changed {
			fileChanged = true
		}
	}

	for _, s := range selectedSecrets {
		ph, err := placeholder.Generate(s.key, s.value, seen)
		if err != nil {
			return vaulted, scoped, wrapErr(fmt.Sprintf("generating placeholder for %s", s.key), err)
		}

		credHosts := placeholder.HostsForCredential(s.key, s.value)

		cred := &vault.Credential{
			ID:           vault.NewID(),
			Name:         s.key,
			Real:         s.value,
			Placeholder:  ph,
			Source:       "init",
			AllowedHosts: credHosts,
			CreatedAt:    time.Now(),
		}
		if err := v.Add(cred); err != nil {
			if errors.Is(err, vault.ErrDuplicateCredential) {
				ui.Warnf(cmd.ErrOrStderr(), "duplicate key %q, skipping", s.key)
				continue
			}
			return vaulted, scoped, wrapErr(fmt.Sprintf("vaulting %s", s.key), err)
		}
		seen[ph] = struct{}{}

		vaulted++
		if len(credHosts) > 0 {
			scoped++
		}

		if dryRun {
			ui.Dimf(w, "  would vault: %s -> %s", s.key, ph)
		} else {
			envFile.SetValue(s.key, ph)
			fileChanged = true
		}
	}
```

3. Change the `selectEnvKeys` signature and body. Replace the existing function with:

```go
// selectEnvKeys returns the groups and bearer secrets the user chose to
// vault. In non-interactive mode everything is selected. Callers that
// receive two empty slices should skip the file.
func selectEnvKeys(
	in io.Reader, w io.Writer, root, envPath string,
	groups []correlate.Group, secrets []secretLine, interactive bool,
) (selectedGroups []correlate.Group, selectedSecrets []secretLine) {
	if !interactive {
		return groups, secrets
	}

	rel, _ := filepath.Rel(root, envPath)
	if rel == "" {
		rel = filepath.Base(envPath)
	}

	total := len(secrets)
	for _, g := range groups {
		total += len(g.Members)
	}
	header := fmt.Sprintf("\nDetected %d %s in %s", total, plural(total, "secret", "secrets"), rel)
	switch len(groups) {
	case 0:
		header += ":"
	case 1:
		header += fmt.Sprintf(" (%d correlated as AWS):", len(groups[0].Members))
	default:
		header += fmt.Sprintf(" (%d AWS credentials):", len(groups))
	}
	_, _ = fmt.Fprintln(w, header)

	var names []string
	for _, g := range groups {
		label := fmt.Sprintf("[aws] %s", g.Name)
		for i, m := range g.Members {
			key := m.Key
			if i == 0 {
				_, _ = fmt.Fprintf(w, "  %-7s %-24s %s\n", "[aws]", key, ui.Muted.Sprint(redactValue(m.Value)))
			} else {
				_, _ = fmt.Fprintf(w, "  %-7s %-24s %s\n", "", key, ui.Muted.Sprint(redactValue(m.Value)))
			}
		}
		names = append(names, label)
	}
	for _, s := range secrets {
		_, _ = fmt.Fprintf(w, "  %-7s %-24s %s\n", "", s.key, ui.Muted.Sprint(redactValue(s.value)))
		names = append(names, s.key)
	}
	_, _ = fmt.Fprintln(w)

	switch promptYNS(in, w, "Vault all?") {
	case choiceYes:
		return groups, secrets
	case choiceNo:
		return nil, nil
	case choiceSelect:
		picked := make(map[string]bool)
		for _, n := range promptMultiSelect(in, w, names) {
			picked[n] = true
		}
		for _, g := range groups {
			if picked[fmt.Sprintf("[aws] %s", g.Name)] {
				selectedGroups = append(selectedGroups, g)
			}
		}
		for _, s := range secrets {
			if picked[s.key] {
				selectedSecrets = append(selectedSecrets, s)
			}
		}
		return selectedGroups, selectedSecrets
	}
	return nil, nil
}
```

4. Add the helper `filterSecretsByRemaining` below `selectEnvKeys`:

```go
// filterSecretsByRemaining keeps secretLine entries whose key is still in
// the remaining (un-correlated) candidate set, preserving the original
// file-order of secrets so dry-run and prompt output stay stable.
func filterSecretsByRemaining(secrets []secretLine, remaining []correlate.Candidate) []secretLine {
	keep := make(map[string]struct{}, len(remaining))
	for _, c := range remaining {
		keep[c.Key] = struct{}{}
	}
	out := secrets[:0:0]
	for _, s := range secrets {
		if _, ok := keep[s.key]; ok {
			out = append(out, s)
		}
	}
	return out
}
```

5. Add the group-vaulting helper `vaultAWSGroup` below `filterSecretsByRemaining`:

```go
// vaultAWSGroup writes one Scheme:"aws" credential for g, rewrites the
// three (or two) source env-var placeholders in envFile, and reports
// (vaulted, scoped, fileChanged). An AWS group counts as one credential
// regardless of member count, matching what the user sees in `veil list`.
func vaultAWSGroup(
	cmd *cobra.Command, v *vault.Vault, seen placeholder.Set,
	envFile *scanner.EnvFile, g correlate.Group, dryRun bool,
) (vaulted, scoped int, fileChanged bool, err error) {
	w := cmd.OutOrStdout()

	secretPh, err := placeholder.Generate(g.Name, g.AWS.SecretKey, seen)
	if err != nil {
		return 0, 0, false, wrapErr(fmt.Sprintf("generating placeholder for %s", g.AWS.SecretKeyVar), err)
	}
	seen[secretPh] = struct{}{}

	akIDPh := generateAWSAccessKeyIDPlaceholder(g.AWS.AccessKeyID, seen)
	seen[akIDPh] = struct{}{}

	var sessPh string
	if g.AWS.SessionToken != "" {
		sessPh, err = placeholder.GenerateAWSSessionToken(g.AWS.SessionToken, seen)
		if err != nil {
			return 0, 0, false, wrapErr(fmt.Sprintf("generating placeholder for %s", g.AWS.SessionTokenVar), err)
		}
		seen[sessPh] = struct{}{}
	}

	cred := &vault.Credential{
		ID:                         vault.NewID(),
		Name:                       g.Name,
		Real:                       g.AWS.SecretKey,
		Placeholder:                secretPh,
		Source:                     "init",
		AllowedHosts:               []string{"*.amazonaws.com"},
		CreatedAt:                  time.Now(),
		Scheme:                     "aws",
		AWSAccessKeyID:             g.AWS.AccessKeyID,
		AWSAccessKeyIDPlaceholder:  akIDPh,
		AWSSessionToken:            g.AWS.SessionToken,
		AWSSessionTokenPlaceholder: sessPh,
	}
	if err := v.Add(cred); err != nil {
		if errors.Is(err, vault.ErrDuplicateCredential) {
			ui.Warnf(cmd.ErrOrStderr(), "duplicate key %q, skipping", g.Name)
			return 0, 0, false, nil
		}
		return 0, 0, false, wrapErr(fmt.Sprintf("vaulting %s", g.Name), err)
	}

	if dryRun {
		ui.Dimf(w, "  would vault (aws): %s", g.Name)
		ui.Dimf(w, "    %-24s -> %s", g.AWS.AccessKeyIDVar, akIDPh)
		ui.Dimf(w, "    %-24s -> %s", g.AWS.SecretKeyVar, secretPh)
		if g.AWS.SessionToken != "" {
			ui.Dimf(w, "    %-24s -> %s", g.AWS.SessionTokenVar, sessPh)
		}
	} else {
		envFile.SetValue(g.AWS.AccessKeyIDVar, akIDPh)
		envFile.SetValue(g.AWS.SecretKeyVar, secretPh)
		if g.AWS.SessionTokenVar != "" {
			envFile.SetValue(g.AWS.SessionTokenVar, sessPh)
		}
		fileChanged = true
	}

	// One credential, scoped to AWS hosts by default.
	return 1, 1, fileChanged, nil
}
```

- [ ] **Step 4: Run the correlation integration test**

Run: `go test ./internal/cli/ -run TestInit_CorrelatesAWSTripleInEnvFile -v`
Expected: PASS.

- [ ] **Step 5: Run the full cli test suite to confirm no regressions**

Run: `go test ./internal/cli/... -count=1`
Expected: PASS. `TestInitHappyPath`, `TestInitDryRun`, `TestInitForce`, MCP tests, shell-env tests — all unchanged because the pre-existing scenarios don't contain AWS triples.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/init_phases.go internal/cli/init_test.go
git commit -m "feat(init): vault .env AWS triples as a single aws-scheme credential"
```

---

## Task 6: Wire correlation into `processShellEnv` (post-correlation vault filter)

**Files:**
- Modify: `internal/cli/init_shellenv.go`
- Modify: `internal/cli/init_shellenv_test.go`

- [ ] **Step 1: Write the failing test for shell-env AWS correlation**

Append to `internal/cli/init_shellenv_test.go`:

```go
func TestInit_CorrelatesAWSTripleFromShellEnv(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	clearShellEnvTestNoise(t)

	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_SESSION_TOKEN", "FwoGZXIvYXdzEJr//////////wEaDPshell")

	tmp := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmp, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmp, "--yes"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v\n%s", err, out.String())
	}

	ks, err := buildKeystore()
	if err != nil {
		t.Fatalf("buildKeystore: %v", err)
	}
	v, err := vault.Open(tmp, ks)
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}

	awsCred, ok := v.Get("AWS_ACCESS_KEY_ID")
	if !ok {
		t.Fatalf("vault missing AWS_ACCESS_KEY_ID; names = %v", v.Names())
	}
	if awsCred.Scheme != "aws" {
		t.Errorf("Scheme = %q, want aws", awsCred.Scheme)
	}
	if awsCred.AWSAccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("AWSAccessKeyID = %q", awsCred.AWSAccessKeyID)
	}
	if awsCred.Real != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Errorf("Real = %q", awsCred.Real)
	}
	if awsCred.AWSSessionToken != "FwoGZXIvYXdzEJr//////////wEaDPshell" {
		t.Errorf("AWSSessionToken = %q", awsCred.AWSSessionToken)
	}

	for _, name := range []string{"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		if _, found := v.Get(name); found {
			t.Errorf("unexpected bearer credential %q in vault", name)
		}
	}
}

func TestInit_ShellAWSWithSameNameInVaultDropsWholeGroup(t *testing.T) {
	// Regression guard for the "orphan sibling" scenario: .env already
	// vaulted AWS_ACCESS_KEY_ID as an aws-scheme credential; shell exports
	// the same triple. The post-correlation name filter must drop the
	// whole shell group — not drop only the ID and then vault the two
	// siblings as redundant bearer credentials.
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	clearShellEnvTestNoise(t)

	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_SESSION_TOKEN", "FwoGZXIvYXdzEJr//////////wEaDPshell")

	tmp := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmp, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	// .env with the same AWS triple — init will vault this first and the
	// shell-env phase must see AWS_ACCESS_KEY_ID as already in the vault.
	envContent := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n" +
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n" +
		"AWS_SESSION_TOKEN=FwoGZXIvYXdzEJr//////////wEaDPshell\n"
	if err := os.WriteFile(filepath.Join(tmp, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmp, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	ks, err := buildKeystore()
	if err != nil {
		t.Fatalf("buildKeystore: %v", err)
	}
	v, err := vault.Open(tmp, ks)
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}

	names := v.Names()
	if len(names) != 1 || names[0] != "AWS_ACCESS_KEY_ID" {
		t.Fatalf("vault names = %v, want [AWS_ACCESS_KEY_ID] exactly", names)
	}
	for _, leaked := range []string{"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		if _, ok := v.Get(leaked); ok {
			t.Errorf("leaked bearer credential %q in vault (orphan sibling)", leaked)
		}
	}
}
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `go test ./internal/cli/ -run 'TestInit_CorrelatesAWSTripleFromShellEnv|TestInit_ShellAWSWithSameNameInVaultDropsWholeGroup' -v`
Expected: FAIL — shell-env path still emits three bearer creds.

- [ ] **Step 3: Update `processShellEnv` to correlate and filter post-correlation**

Edit `internal/cli/init_shellenv.go`. Replace the entire body of `processShellEnv` and add a new selector shape. Final file contents should be:

```go
package cli

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/8enji/veil/internal/cli/correlate"
	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/scanner"
	"github.com/8enji/veil/internal/ui"
	"github.com/8enji/veil/internal/vault"
)

// nonEmptyShellCandidates returns candidates whose Value is not empty.
// Empty-valued candidates can arise when a variable matches a secret-like
// name pattern but is exported with an empty value (e.g., `export API_KEY=""`),
// and they carry no secret material worth vaulting. Used by the init early-exit
// gate so it matches the behavior of processShellEnv's internal filter.
func nonEmptyShellCandidates(candidates []scanner.EnvironCandidate) []scanner.EnvironCandidate {
	out := candidates[:0:0]
	for _, c := range candidates {
		if c.Value == "" {
			continue
		}
		out = append(out, c)
	}
	return out
}

// processShellEnv presents shell-exported secret-like candidates, prompts the
// user (interactive) or accepts-all (non-interactive), and vaults the
// selected entries. Correlates AWS triples before the "already in vault"
// filter so an existing aws-scheme credential named AWS_ACCESS_KEY_ID drops
// the whole would-be-duplicate shell group instead of leaking orphan
// siblings as redundant bearer credentials.
func processShellEnv(w io.Writer, in io.Reader, v *vault.Vault, candidates []scanner.EnvironCandidate, dryRun, interactive bool) (int, int, error) {
	// Drop empty-valued candidates first (placeholder.Generate rejects empty).
	// We do NOT drop vault-duplicate names here — that check moves
	// post-correlation below.
	nonEmpty := make([]correlate.Candidate, 0, len(candidates))
	for _, c := range candidates {
		if c.Value == "" {
			continue
		}
		nonEmpty = append(nonEmpty, correlate.Candidate{Key: c.Name, Value: c.Value})
	}
	if len(nonEmpty) == 0 {
		return 0, 0, nil
	}

	groups, remaining := correlate.DetectAll(nonEmpty)

	// Now drop groups whose name is already in the vault, and drop loose
	// candidates whose key is already in the vault. Applying the name
	// filter AFTER correlation ensures we drop the whole AWS group cleanly
	// when the .env phase has already vaulted it — no orphan siblings
	// leaking through as bearer credentials.
	filteredGroups := make([]correlate.Group, 0, len(groups))
	for _, g := range groups {
		if _, exists := v.Get(g.Name); exists {
			continue
		}
		filteredGroups = append(filteredGroups, g)
	}
	filteredRemaining := make([]correlate.Candidate, 0, len(remaining))
	for _, c := range remaining {
		if _, exists := v.Get(c.Key); exists {
			continue
		}
		filteredRemaining = append(filteredRemaining, c)
	}
	if len(filteredGroups) == 0 && len(filteredRemaining) == 0 {
		return 0, 0, nil
	}

	selectedGroups, selectedRemaining := selectShellEnvKeys(in, w, filteredGroups, filteredRemaining, interactive)
	if len(selectedGroups) == 0 && len(selectedRemaining) == 0 {
		return 0, 0, nil
	}

	seen := v.PlaceholderSet()
	var vaulted, scoped int

	for _, g := range selectedGroups {
		n, s, err := vaultShellAWSGroup(w, v, seen, g, dryRun)
		if err != nil {
			return vaulted, scoped, err
		}
		vaulted += n
		scoped += s
	}

	for _, c := range selectedRemaining {
		ph, err := placeholder.Generate(c.Key, c.Value, seen)
		if err != nil {
			return vaulted, scoped, wrapErr(fmt.Sprintf("generating placeholder for %s", c.Key), err)
		}

		credHosts := placeholder.HostsForCredential(c.Key, c.Value)
		cred := &vault.Credential{
			ID:           vault.NewID(),
			Name:         c.Key,
			Real:         c.Value,
			Placeholder:  ph,
			Source:       "init",
			AllowedHosts: credHosts,
			CreatedAt:    time.Now(),
		}
		if err := v.Add(cred); err != nil {
			if errors.Is(err, vault.ErrDuplicateCredential) {
				ui.Warnf(w, "duplicate key %q, skipping", c.Key)
				continue
			}
			return vaulted, scoped, wrapErr(fmt.Sprintf("vaulting %s", c.Key), err)
		}
		seen[ph] = struct{}{}

		vaulted++
		if len(credHosts) > 0 {
			scoped++
		}

		if dryRun {
			ui.Dimf(w, "  would vault: %s -> %s (from shell)", c.Key, ph)
		}
	}
	return vaulted, scoped, nil
}

// vaultShellAWSGroup writes one Scheme:"aws" credential for g. Unlike the
// .env flow there is no file to rewrite — the user's shell export remains
// unchanged; init only vaults.
func vaultShellAWSGroup(
	w io.Writer, v *vault.Vault, seen placeholder.Set,
	g correlate.Group, dryRun bool,
) (vaulted, scoped int, err error) {
	secretPh, err := placeholder.Generate(g.Name, g.AWS.SecretKey, seen)
	if err != nil {
		return 0, 0, wrapErr(fmt.Sprintf("generating placeholder for %s", g.AWS.SecretKeyVar), err)
	}
	seen[secretPh] = struct{}{}

	akIDPh := generateAWSAccessKeyIDPlaceholder(g.AWS.AccessKeyID, seen)
	seen[akIDPh] = struct{}{}

	var sessPh string
	if g.AWS.SessionToken != "" {
		sessPh, err = placeholder.GenerateAWSSessionToken(g.AWS.SessionToken, seen)
		if err != nil {
			return 0, 0, wrapErr(fmt.Sprintf("generating placeholder for %s", g.AWS.SessionTokenVar), err)
		}
		seen[sessPh] = struct{}{}
	}

	cred := &vault.Credential{
		ID:                         vault.NewID(),
		Name:                       g.Name,
		Real:                       g.AWS.SecretKey,
		Placeholder:                secretPh,
		Source:                     "init",
		AllowedHosts:               []string{"*.amazonaws.com"},
		CreatedAt:                  time.Now(),
		Scheme:                     "aws",
		AWSAccessKeyID:             g.AWS.AccessKeyID,
		AWSAccessKeyIDPlaceholder:  akIDPh,
		AWSSessionToken:            g.AWS.SessionToken,
		AWSSessionTokenPlaceholder: sessPh,
	}
	if err := v.Add(cred); err != nil {
		if errors.Is(err, vault.ErrDuplicateCredential) {
			ui.Warnf(w, "duplicate key %q, skipping", g.Name)
			return 0, 0, nil
		}
		return 0, 0, wrapErr(fmt.Sprintf("vaulting %s", g.Name), err)
	}

	if dryRun {
		ui.Dimf(w, "  would vault (aws): %s (from shell)", g.Name)
		ui.Dimf(w, "    %-24s -> %s", g.AWS.AccessKeyIDVar, akIDPh)
		ui.Dimf(w, "    %-24s -> %s", g.AWS.SecretKeyVar, secretPh)
		if g.AWS.SessionToken != "" {
			ui.Dimf(w, "    %-24s -> %s", g.AWS.SessionTokenVar, sessPh)
		}
	}
	return 1, 1, nil
}

// selectShellEnvKeys returns the groups and bearer candidates the user chose
// to vault. In non-interactive mode everything is selected.
func selectShellEnvKeys(
	in io.Reader, w io.Writer,
	groups []correlate.Group, remaining []correlate.Candidate, interactive bool,
) (selectedGroups []correlate.Group, selectedRemaining []correlate.Candidate) {
	if !interactive {
		return groups, remaining
	}

	total := len(remaining)
	for _, g := range groups {
		total += len(g.Members)
	}
	header := fmt.Sprintf("\nDetected %d shell-exported %s", total, plural(total, "secret", "secrets"))
	switch len(groups) {
	case 0:
		header += ":"
	case 1:
		header += fmt.Sprintf(" (%d correlated as AWS):", len(groups[0].Members))
	default:
		header += fmt.Sprintf(" (%d AWS credentials):", len(groups))
	}
	_, _ = fmt.Fprintln(w, header)
	ui.Dim(w, "(these are in your current shell environment, not in any .env file)")

	var names []string
	for _, g := range groups {
		label := fmt.Sprintf("[aws] %s", g.Name)
		for i, m := range g.Members {
			if i == 0 {
				_, _ = fmt.Fprintf(w, "  %-7s %-32s %s\n", "[aws]", m.Key, ui.Muted.Sprint(redactValue(m.Value)))
			} else {
				_, _ = fmt.Fprintf(w, "  %-7s %-32s %s\n", "", m.Key, ui.Muted.Sprint(redactValue(m.Value)))
			}
		}
		names = append(names, label)
	}
	for _, c := range remaining {
		_, _ = fmt.Fprintf(w, "  %-7s %-32s %s\n", "", c.Key, ui.Muted.Sprint(redactValue(c.Value)))
		names = append(names, c.Key)
	}
	_, _ = fmt.Fprintln(w)

	switch promptYNS(in, w, "Vault all?") {
	case choiceYes:
		return groups, remaining
	case choiceNo:
		return nil, nil
	case choiceSelect:
		picked := make(map[string]bool)
		for _, n := range promptMultiSelect(in, w, names) {
			picked[n] = true
		}
		for _, g := range groups {
			if picked[fmt.Sprintf("[aws] %s", g.Name)] {
				selectedGroups = append(selectedGroups, g)
			}
		}
		for _, c := range remaining {
			if picked[c.Key] {
				selectedRemaining = append(selectedRemaining, c)
			}
		}
		return selectedGroups, selectedRemaining
	}
	return nil, nil
}
```

Note on the previous tests (`TestProcessShellEnv_VaultsSecrets`, `TestProcessShellEnv_SkipsNamesAlreadyInVault`): both construct `[]scanner.EnvironCandidate` and call `processShellEnv(&out, ..., false)` non-interactively. Their assertions remain valid — non-AWS inputs flow entirely through the `selectedRemaining` path, which has the same semantics as the old bearer path. No test change needed for those.

- [ ] **Step 4: Run the new and regression tests**

Run: `go test ./internal/cli/ -run 'TestInit|TestProcessShellEnv' -v -count=1`
Expected: PASS — correlation tests plus all existing shell-env tests.

- [ ] **Step 5: Run the full suite**

Run: `go test ./... -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/init_shellenv.go internal/cli/init_shellenv_test.go
git commit -m "feat(init): correlate shell-exported AWS triples post vault-dedup"
```

---

## Task 7: Additional end-to-end integration coverage

**Files:**
- Modify: `internal/cli/init_test.go`

- [ ] **Step 1: Write the multi-account, partial-group, and dry-run integration tests**

Append to `internal/cli/init_test.go`:

```go
func TestInit_CorrelatesTwoAWSAccountsInEnvFile(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	clearShellEnvTestNoise(t)

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envContent := "PROD_AWS_ACCESS_KEY_ID=AKIAPRODEXAMPLE00001\n" +
		"PROD_AWS_SECRET_ACCESS_KEY=prod/secret/access/key/example00001\n" +
		"DEV_AWS_ACCESS_KEY_ID=AKIADEVEXAMPLE000001\n" +
		"DEV_AWS_SECRET_ACCESS_KEY=dev/secret/access/key/example000001\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	v, err := openVault(tmpDir)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}
	for _, groupName := range []string{"PROD_AWS_ACCESS_KEY_ID", "DEV_AWS_ACCESS_KEY_ID"} {
		c, ok := v.Get(groupName)
		if !ok {
			t.Errorf("missing aws credential %q", groupName)
			continue
		}
		if c.Scheme != "aws" {
			t.Errorf("%s.Scheme = %q, want aws", groupName, c.Scheme)
		}
	}
	for _, leaked := range []string{"PROD_AWS_SECRET_ACCESS_KEY", "DEV_AWS_SECRET_ACCESS_KEY"} {
		if _, ok := v.Get(leaked); ok {
			t.Errorf("unexpected bearer credential %q (should be absorbed)", leaked)
		}
	}
	// PROD AWS must not pair with DEV AWS — verify each group has the
	// correct partner values.
	prodCred, _ := v.Get("PROD_AWS_ACCESS_KEY_ID")
	if prodCred.AWSAccessKeyID != "AKIAPRODEXAMPLE00001" {
		t.Errorf("PROD AWSAccessKeyID = %q", prodCred.AWSAccessKeyID)
	}
	if prodCred.Real != "prod/secret/access/key/example00001" {
		t.Errorf("PROD secret cross-paired: %q", prodCred.Real)
	}
	devCred, _ := v.Get("DEV_AWS_ACCESS_KEY_ID")
	if devCred.AWSAccessKeyID != "AKIADEVEXAMPLE000001" {
		t.Errorf("DEV AWSAccessKeyID = %q", devCred.AWSAccessKeyID)
	}
	if devCred.Real != "dev/secret/access/key/example000001" {
		t.Errorf("DEV secret cross-paired: %q", devCred.Real)
	}
}

func TestInit_PartialAWSFallsThroughToBearer(t *testing.T) {
	// Only AWS_ACCESS_KEY_ID is present — no secret partner means no group.
	// The lone ID must vault as a plain bearer credential.
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	clearShellEnvTestNoise(t)

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envContent := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	v, err := openVault(tmpDir)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}
	c, ok := v.Get("AWS_ACCESS_KEY_ID")
	if !ok {
		t.Fatal("vault missing AWS_ACCESS_KEY_ID")
	}
	if c.Scheme != "" {
		t.Errorf("Scheme = %q, want empty (bearer)", c.Scheme)
	}
	if c.AWSAccessKeyID != "" {
		t.Errorf("AWSAccessKeyID = %q on bearer credential", c.AWSAccessKeyID)
	}
}

func TestInit_FakeAWSValueStaysBearer(t *testing.T) {
	// AWS_ACCESS_KEY_ID whose value doesn't match AKIA|ASIA — common for
	// test fixtures and local dev stubs — must not trigger correlation.
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	clearShellEnvTestNoise(t)

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envContent := "AWS_ACCESS_KEY_ID=fake-access-key-test\n" +
		"AWS_SECRET_ACCESS_KEY=fake-secret-key-for-testing-purposes\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--path", tmpDir, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	v, err := openVault(tmpDir)
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
		c, ok := v.Get(name)
		if !ok {
			t.Errorf("missing credential %q", name)
			continue
		}
		if c.Scheme != "" {
			t.Errorf("%s.Scheme = %q, want empty (bearer, not aws)", name, c.Scheme)
		}
	}
}

func TestInit_DryRunShowsGroupedAWS(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	clearShellEnvTestNoise(t)

	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	envContent := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n" +
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"init", "--dry-run", "--path", tmpDir, "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	outStr := out.String()
	if !strings.Contains(outStr, "would vault (aws)") {
		t.Errorf("dry-run output missing grouped AWS line:\n%s", outStr)
	}

	// .env must be unchanged in dry-run mode.
	gotBytes, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotBytes) != envContent {
		t.Errorf(".env changed in dry-run:\n got = %q\nwant = %q", string(gotBytes), envContent)
	}
}
```

- [ ] **Step 2: Run the new tests**

Run: `go test ./internal/cli/ -run 'TestInit_CorrelatesTwoAWSAccountsInEnvFile|TestInit_PartialAWSFallsThroughToBearer|TestInit_FakeAWSValueStaysBearer|TestInit_DryRunShowsGroupedAWS' -v -count=1`
Expected: PASS, all four.

- [ ] **Step 3: Run the full suite**

Run: `go test ./... -count=1`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/cli/init_test.go
git commit -m "test(init): AWS correlation integration coverage"
```

---

## Task 8: Annotate the signature-auth spec as superseded

**Rationale:** The predecessor spec explicitly deferred init-time auto-correlation. Now that it ships, readers arriving at the old paragraph need a forward pointer so they don't interpret the deferral as current policy.

**Files:**
- Modify: `docs/superpowers/specs/2026-04-22-signature-auth-design.md`

- [ ] **Step 1: Locate the init paragraph**

Run: `grep -n 'veil init' docs/superpowers/specs/2026-04-22-signature-auth-design.md`
Expected: at least one match around lines 261-263 (per prior context). Identify the paragraph that reasons about init's bearer-only behavior.

- [ ] **Step 2: Add a "superseded" callout at the top of that paragraph**

Use the Edit tool to prepend the following line to the paragraph that begins with "`veil init (.env auto-detection)`" (or the equivalent heading):

```markdown
> **Superseded by [`2026-04-23-init-aws-correlation-design.md`](./2026-04-23-init-aws-correlation-design.md)** — init now correlates AWS triples into a single `Scheme: "aws"` credential via strict decoration matching, making the mis-pairing concern below moot. The `mismatch_detector` fallback described elsewhere in this spec remains active for declined prompts, invalid AKID values, and partial groups.
```

Place this callout as the first line of the paragraph, preserving the existing text unchanged.

- [ ] **Step 3: Verify the spec still renders cleanly**

Run: `head -n 280 docs/superpowers/specs/2026-04-22-signature-auth-design.md | tail -n 40`
Expected: the callout appears above the original paragraph; original text intact.

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/specs/2026-04-22-signature-auth-design.md
git commit -m "docs(signature-auth): mark init bearer-only behavior as superseded"
```

---

## Verification checklist

After all tasks, run the full suite from a clean state:

```bash
go test ./... -count=1
go build ./...
go vet ./...
```

All three must pass. Additionally, a manual smoke:

```bash
cd /tmp && mkdir -p veil-aws-smoke && cd veil-aws-smoke
git init -q
printf 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n' > .env
veil init --yes
veil list
# Expect one row: AWS_ACCESS_KEY_ID (aws)
cat .env
# Expect placeholders, no AKIA/base64 secret literals
```

Revert the smoke directory after verification.
