# Placeholder DRY & Extensibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the placeholder-provider DRY smell (§4.1 of the 2026-04-22 audit) by fixing the declarative `Format` API, replacing the filename-ordering hack with explicit `Priority`, migrating four hand-written providers to `Format`, and closing three related correctness gaps (`ExtractURLHost` scheme allowlist, `IsSecretLike` calibration, dynamic contract-test discovery).

**Architecture:** The `internal/placeholder` package resolves secrets through a registry of `ProviderPattern` values. A declarative `Format` struct already exists but has a silent prefix-ordering bug and is underused. After this plan:

1. `registerFormat` sorts `Prefixes` by length descending before closing over them, so the longest prefix always wins at match and generate time.
2. `ProviderPattern` grows a `Priority int` field. The `Registry` sorts its backing slice (stable) by `Priority` descending on first use. Filename ordering is no longer load-bearing.
3. `openai`, `anthropic`, `stripe`, `slack` move from hand-written to `Format` entries (~60 LoC net removed). Remaining hand-written providers (`github`, `aws`, `twilio`, `supabase`, `sendgrid`) stay custom because their token shapes are non-declarative (JWT, multi-segment, length-gated).
4. `ExtractURLHost` enforces the scheme allowlist. `IsSecretLike` raises the entropy floor and adds a distinct-byte requirement. `Registry` exposes `Names()` and `All()` so the contract test discovers providers dynamically.
5. `provider_zzz_formats.go` → `provider_formats.go`. Every `provider_*.go` has a matching `provider_*_test.go`.

**Tech Stack:** Go 1.22, standard library only. Tests via `go test` / `make test`. Target package: `internal/placeholder`.

**Prereq note:** The "Placeholder sentinel + proxy fail-closed" work (P2) is merged (`bb2364c`, `sentinel_test.go`, `placeholder.Sentinel = "VEIL"`). `registerFormat` already calls `sentinelize(prefix+body, len(prefix))`, so Format-generated placeholders carry the sentinel and need no changes to the fail-closed scheme. Migrations must preserve this invariant — the existing `sentinel_test.go` table already asserts it for every provider.

**Constraints:**
- No changes to `internal/proxy`, `internal/cli`, `internal/runner`, `internal/audit`, `internal/vault`.
- Every `provider_*.go` must have a matching `provider_*_test.go`.
- `make test` must be green at every commit.
- Sentinel scheme from P2 is fixed — no edits to `Sentinel` constant or `sentinelize`.

---

## File Structure

**Modified:**
- `internal/placeholder/providers.go` — add `Priority` field to `ProviderPattern`; add `Registry.All()`, `Registry.Names()`, `Registry.sortPatterns()`; fix `registerFormat` to sort `f.Prefixes` by length descending
- `internal/placeholder/engine.go` — replace direct `registry` iteration with `DefaultRegistry().Match(...)`
- `internal/placeholder/hosts.go` — `HostsForCredential` uses `DefaultRegistry().All()`; `ExtractURLHost` enforces scheme allowlist
- `internal/placeholder/secretlike.go` — raise entropy threshold; add `distinctBytes` gate; use `DefaultRegistry().All()`
- `internal/placeholder/url.go` — export `allowedSchemes` (rename to `AllowedURLSchemes` or keep unexported and share via helper; see Task 8)
- `internal/placeholder/providers_contract_test.go` — use `Names()` for dynamic discovery; remove hardcoded `known` list
- `internal/placeholder/providers_test.go` — remove `TestProviderOpenAI/Anthropic/Stripe/Slack` and slack's `generate_preserves_dashes` subtest (behavior moved to `provider_formats_test.go` table)

**Created:**
- `internal/placeholder/priority.go` — `Priority` constants (`PriorityHandwritten`, `PriorityFormat`)
- `internal/placeholder/provider_aws_test.go` — extracted from `providers_test.go::TestProviderAWS`
- `internal/placeholder/provider_github_test.go` — extracted from `providers_test.go::TestProviderGitHub` + `TestProviderGitHub_FinegrainedPAT`

**Renamed:**
- `internal/placeholder/provider_zzz_formats.go` → `internal/placeholder/provider_formats.go` (now contains migrated `openai`, `anthropic`, `stripe`, `slack` alongside existing Format entries)
- `internal/placeholder/provider_zzz_formats_test.go` → `internal/placeholder/provider_formats_test.go` (add table entries for the four migrated providers)

**Deleted:**
- `internal/placeholder/provider_openai.go`
- `internal/placeholder/provider_anthropic.go`
- `internal/placeholder/provider_stripe.go`
- `internal/placeholder/provider_slack.go`

**Per-provider test coverage check after migration:**
- `provider_aws.go` + `provider_aws_test.go` ✓ (created in this plan)
- `provider_github.go` + `provider_github_test.go` ✓ (created in this plan)
- `provider_sendgrid.go` + `provider_sendgrid_test.go` ✓ (exists)
- `provider_supabase.go` + `provider_supabase_test.go` ✓ (exists)
- `provider_twilio.go` + `provider_twilio_test.go` ✓ (exists)
- `provider_formats.go` + `provider_formats_test.go` ✓ (renamed)

---

## Task 1: Fix `registerFormat` prefix-ordering bug (HIGH)

**Why this is first:** Without this fix, migrating `anthropic` (prefixes `sk-ant-api`, `sk-ant-`) loses the longer prefix segment. Every other migration also relies on this being correct.

**Files:**
- Modify: `internal/placeholder/providers.go:79-129` (`registerFormat`)
- Modify: `internal/placeholder/providers_test.go` (add new test)

- [ ] **Step 1: Write the failing test**

Append to `internal/placeholder/providers_test.go` just before `TestRegistryIsolation`:

```go
// TestRegisterFormat_LongerPrefixWins asserts that when a Format is registered
// with overlapping prefixes, the LONGER prefix is the one extracted by
// Generate regardless of caller-provided order. This is the correctness
// invariant required to migrate anthropic (prefixes "sk-ant-api", "sk-ant-")
// to a Format entry.
func TestRegisterFormat_LongerPrefixWins(t *testing.T) {
	before := len(registry)
	registerFormat(Format{
		Name:     "testprefixorder",
		Prefixes: []string{"sk-", "sk-ant-api", "sk-ant-"}, // shortest first; intentionally unordered
		KeyHints: nil,
		Length:   40,
		Charset:  "alphanumeric",
	})
	defer func() { registry = registry[:before] }()

	var prov ProviderPattern
	for _, p := range registry[before:] {
		if p.Name == "testprefixorder" {
			prov = p
			break
		}
	}
	if prov.Name == "" {
		t.Fatal("testprefixorder not registered")
	}

	// Value has the longest prefix. Generate must emit output starting with
	// that full longer prefix, not the shorter "sk-" substring.
	result := prov.Generate("sk-ant-api-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	if !strings.HasPrefix(result, "sk-ant-api") {
		t.Fatalf("expected longest prefix sk-ant-api to win, got: %s", result)
	}

	// Value has the medium prefix. Output must start with "sk-ant-", not
	// "sk-".
	result = prov.Generate("sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	if !strings.HasPrefix(result, "sk-ant-") {
		t.Fatalf("expected medium prefix sk-ant- to win, got: %s", result)
	}

	// Value has only the short prefix.
	result = prov.Generate("sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	if !strings.HasPrefix(result, "sk-") {
		t.Fatalf("expected short prefix sk- to match, got: %s", result)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./internal/placeholder/ -run TestRegisterFormat_LongerPrefixWins -v`
Expected: FAIL. For input `"sk-ant-api-xxx..."`, output starts with `"sk-"` (the first prefix in the caller-provided order wins) instead of `"sk-ant-api"`.

- [ ] **Step 3: Fix `registerFormat` to sort prefixes**

Edit `internal/placeholder/providers.go`. Replace the body of `registerFormat` (lines 79-129) with:

```go
func registerFormat(f Format) {
	// Sort prefixes by length descending so that Match and Generate always
	// pick the longest matching prefix. Without this, callers who register
	// ["sk-", "sk-ant-"] see Generate produce "sk-..." losing the "ant-"
	// segment — a silent correctness bug that blocked migrating anthropic
	// to a Format entry.
	prefixes := make([]string, len(f.Prefixes))
	copy(prefixes, f.Prefixes)
	sort.SliceStable(prefixes, func(i, j int) bool {
		return len(prefixes[i]) > len(prefixes[j])
	})

	p := ProviderPattern{
		Name:  f.Name,
		Hosts: f.Hosts,
		Match: func(name, value string) bool {
			for _, pfx := range prefixes {
				if strings.HasPrefix(value, pfx) {
					return true
				}
			}
			upper := strings.ToUpper(name)
			for _, hint := range f.KeyHints {
				if strings.Contains(upper, strings.ToUpper(hint)) {
					return true
				}
			}
			return false
		},
		Generate: func(value string) string {
			prefix := ""
			for _, pfx := range prefixes {
				if strings.HasPrefix(value, pfx) {
					prefix = pfx
					break
				}
			}
			total := f.Length
			if total == 0 {
				total = len(value)
			}
			rest := total - len(prefix)
			if rest < 0 {
				rest = 0
			}
			var body string
			switch f.Charset {
			case "hex":
				body = randFromAlphabet(rest, "0123456789abcdef")
			case "base64":
				body = randBase64ish(rest)
			case "upper-alphanumeric":
				body = randUpperAlphanumeric(rest)
			default:
				body = randAlphanumeric(rest)
			}
			// Embed Sentinel at the start of the body (see engine.go).
			return sentinelize(prefix+body, len(prefix))
		},
	}
	register(p)
}
```

And add `"sort"` to the import block at the top of `providers.go`:

```go
import (
	"sort"
	"strings"
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./internal/placeholder/ -run TestRegisterFormat_LongerPrefixWins -v`
Expected: PASS.

- [ ] **Step 5: Run full placeholder suite to ensure no regression**

Run: `CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./internal/placeholder/ -v`
Expected: PASS (no regressions; all existing tests still green).

- [ ] **Step 6: Commit**

```bash
git add internal/placeholder/providers.go internal/placeholder/providers_test.go
git commit -m "fix(placeholder): sort Format prefixes by length so longest wins

registerFormat iterated caller-provided Prefixes in order for both Match
and Generate, so a Format registered with [\"sk-\", \"sk-ant-\"] lost the
\"ant-\" segment on generation. Sorting by len desc inside registerFormat
makes the longest matching prefix win, unblocking the anthropic/openai
migration from hand-written to declarative Format entries.

Refs: docs/superpowers/findings/2026-04-22-codebase-audit.md §4.1"
```

---

## Task 2: Add `Priority` field and sorted resolution (MEDIUM)

**Why:** Engine's first-match-wins iteration is load-bearing on filename alphabetical order via `provider_zzz_formats.go`. Replace with explicit `Priority int`. Hand-written providers get `PriorityHandwritten = 100`; Format providers get `PriorityFormat = 50` (default in `registerFormat`). Higher runs first. Stable sort preserves registration order within a priority tier.

**Files:**
- Create: `internal/placeholder/priority.go`
- Modify: `internal/placeholder/providers.go` — add `Priority` to `ProviderPattern`; add `sortPatterns`, `All`, to `Registry`; set Priority in `registerFormat`
- Modify: `internal/placeholder/engine.go` — replace direct `for _, p := range registry` with `DefaultRegistry().Match(...)`
- Modify: `internal/placeholder/hosts.go` — `HostsForCredential` uses `DefaultRegistry().All()`
- Modify: `internal/placeholder/secretlike.go` — `IsSecretLike` uses `DefaultRegistry().All()`
- Modify: every hand-written provider (`provider_anthropic.go`, `provider_aws.go`, `provider_github.go`, `provider_openai.go`, `provider_sendgrid.go`, `provider_slack.go`, `provider_stripe.go`, `provider_supabase.go`, `provider_twilio.go`) — set `Priority: PriorityHandwritten`

- [ ] **Step 1: Write the failing test**

Append to `internal/placeholder/providers_test.go` (just after `TestRegisterFormat_LongerPrefixWins`):

```go
// TestPriority_HandwrittenBeforeFormat asserts that a hand-written provider
// (PriorityHandwritten) is matched before a Format provider (PriorityFormat)
// when both would match the same input, regardless of init-order / filename.
func TestPriority_HandwrittenBeforeFormat(t *testing.T) {
	before := len(registry)
	// Register the Format FIRST, then the hand-written. Without Priority
	// sorting, first-registered wins. With Priority sorting, the
	// hand-written entry must still be picked because its Priority is higher.
	registerFormat(Format{
		Name:     "fmtfoo",
		Prefixes: []string{"foo_"},
		Length:   20,
		Charset:  "alphanumeric",
	})
	register(ProviderPattern{
		Name:     "hwfoo",
		Priority: PriorityHandwritten,
		Match:    func(name, value string) bool { return strings.HasPrefix(value, "foo_") },
		Generate: func(value string) string { return "HANDWRITTEN-WON" },
	})
	defer func() { registry = registry[:before] }()

	r := DefaultRegistry()
	p := r.Match("ANY", "foo_abcdefghij1234567890")
	if p == nil {
		t.Fatal("expected a match")
	}
	if p.Name != "hwfoo" {
		t.Fatalf("expected hand-written hwfoo to win via Priority, got %q", p.Name)
	}
}

// TestPriority_StableWithinTier asserts that providers registered within the
// same Priority tier are matched in registration order (stable sort).
func TestPriority_StableWithinTier(t *testing.T) {
	before := len(registry)
	register(ProviderPattern{
		Name:     "tier1a",
		Priority: PriorityFormat,
		Match:    func(name, value string) bool { return value == "shared" },
		Generate: func(value string) string { return "a" },
	})
	register(ProviderPattern{
		Name:     "tier1b",
		Priority: PriorityFormat,
		Match:    func(name, value string) bool { return value == "shared" },
		Generate: func(value string) string { return "b" },
	})
	defer func() { registry = registry[:before] }()

	r := DefaultRegistry()
	p := r.Match("ANY", "shared")
	if p == nil {
		t.Fatal("expected a match")
	}
	if p.Name != "tier1a" {
		t.Fatalf("expected first-registered tier1a to win stable sort, got %q", p.Name)
	}
}

// TestRegistryAll_ReturnsSortedSnapshot asserts Registry.All() returns the
// patterns in Priority-descending order (higher first).
func TestRegistryAll_ReturnsSortedSnapshot(t *testing.T) {
	r := DefaultRegistry()
	all := r.All()
	if len(all) == 0 {
		t.Fatal("All() returned empty slice")
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Priority < all[i].Priority {
			t.Fatalf("All() not sorted descending by Priority: %q(%d) before %q(%d)",
				all[i-1].Name, all[i-1].Priority, all[i].Name, all[i].Priority)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./internal/placeholder/ -run "TestPriority|TestRegistryAll" -v`
Expected: FAIL. `PriorityHandwritten` / `PriorityFormat` are undefined; `Registry.All()` does not exist; `ProviderPattern.Priority` does not exist.

- [ ] **Step 3: Create `priority.go` with constants**

Create `internal/placeholder/priority.go`:

```go
package placeholder

// Priority controls the order in which the registry resolves matches.
// Higher Priority runs first. Providers registered within the same tier
// are matched in registration order (stable sort).
//
// The Registry sorts its backing slice on first call to Match/All/Names
// via a sync.Once, so adding a provider after resolution has started is
// not supported (all init() calls run before any Generate is called).
const (
	// PriorityHandwritten is the priority for hand-written providers that
	// implement custom Match/Generate logic — e.g. supabase's JWT builder,
	// github's multi-segment fine-grained PAT structure, aws's two-shape
	// access-key / secret-key split. These run before declarative Format
	// providers so that a value matching a specific hand-written shape is
	// resolved by that provider even if a Format entry would also match by
	// keyhint.
	PriorityHandwritten = 100

	// PriorityFormat is the default priority for declarative Format
	// providers registered via registerFormat. Format providers are matched
	// after any applicable hand-written provider.
	PriorityFormat = 50
)
```

- [ ] **Step 4: Add `Priority` field + `Registry.All()` + `sortPatterns` in `providers.go`**

Edit `internal/placeholder/providers.go`. Replace the entire content with:

```go
package placeholder

import (
	"sort"
	"strings"
	"sync"
)

// ProviderPattern describes a secret pattern that can be matched and replaced
// with a structurally-valid placeholder.
type ProviderPattern struct {
	Name     string
	Match    func(name, value string) bool
	Generate func(value string) string
	Hosts    []string // curated host set for this provider
	Priority int      // higher runs first; see priority.go for tiers
}

// registry holds all registered provider patterns, checked in order of
// Priority (descending). This is the package-level default, populated by
// init() in provider_*.go files. Isolated Registry instances (for tests) do
// not share this slice.
var registry []ProviderPattern

// register adds a provider pattern to the default registry.
func register(p ProviderPattern) {
	registry = append(registry, p)
}

// Registry holds a set of provider patterns. Use NewRegistry to construct an
// isolated registry for tests; DefaultRegistry returns a view over the
// package-level slice populated at init() time.
//
// Patterns are sorted by Priority (descending, stable) on first call to
// Match/All/Names. Calling register() after sortPatterns has fired produces
// undefined ordering — in practice all register() calls run during package
// init(), before any user code invokes these methods.
type Registry struct {
	patterns []ProviderPattern
	sortOnce sync.Once
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry { return &Registry{} }

// Register appends a provider pattern.
func (r *Registry) Register(p ProviderPattern) {
	r.patterns = append(r.patterns, p)
}

// sortPatterns sorts r.patterns by Priority descending (stable) the first
// time it is called. Subsequent calls are no-ops. Because DefaultRegistry
// shares its backing slice with the package-level registry, a single sort
// affects every DefaultRegistry view — this is intentional: the first
// consumer pays the sort cost and every later consumer sees sorted order.
func (r *Registry) sortPatterns() {
	r.sortOnce.Do(func() {
		sort.SliceStable(r.patterns, func(i, j int) bool {
			return r.patterns[i].Priority > r.patterns[j].Priority
		})
	})
}

// Match returns the first provider whose Match returns true, or nil if none.
// Patterns are checked in Priority-descending order.
func (r *Registry) Match(name, value string) *ProviderPattern {
	r.sortPatterns()
	for i := range r.patterns {
		if r.patterns[i].Match(name, value) {
			return &r.patterns[i]
		}
	}
	return nil
}

// Get returns the provider with the given name, or (zero, false).
func (r *Registry) Get(name string) (ProviderPattern, bool) {
	r.sortPatterns()
	for _, p := range r.patterns {
		if p.Name == name {
			return p, true
		}
	}
	return ProviderPattern{}, false
}

// All returns the registered patterns sorted by Priority descending. The
// returned slice shares backing storage with the registry and must not be
// mutated by callers.
func (r *Registry) All() []ProviderPattern {
	r.sortPatterns()
	return r.patterns
}

// Names returns the names of all registered providers in Priority-descending
// order. Useful for contract tests that want to enumerate the registry
// without hard-coding a list.
func (r *Registry) Names() []string {
	r.sortPatterns()
	out := make([]string, len(r.patterns))
	for i, p := range r.patterns {
		out[i] = p.Name
	}
	return out
}

// DefaultRegistry returns a Registry view over the package-level registry.
// Each call returns a fresh wrapper so tests that mutate the package-level
// slice (e.g. `registry = registry[:before]`) still see the correct length.
// The underlying array is shared, so sortPatterns affects every view.
func DefaultRegistry() *Registry { return &Registry{patterns: registry} }

// Format describes a secret format that can be matched and replaced using
// declarative fields instead of hand-authored Match/Generate functions.
type Format struct {
	Name     string
	Prefixes []string // value prefixes to match, e.g. ["ghp_", "github_pat_"]
	KeyHints []string // substrings to match in env key name (case-insensitive)
	Length   int      // total output length including prefix (0 = match input length)
	Charset  string   // "alphanumeric", "hex", "base64", "upper-alphanumeric"
	Hosts    []string
	Priority int      // optional; defaults to PriorityFormat if zero
}

// registerFormat constructs a ProviderPattern from a Format and appends it
// to the registry.
func registerFormat(f Format) {
	// Sort prefixes by length descending so Match and Generate always pick
	// the longest matching prefix. Without this, callers who register
	// ["sk-", "sk-ant-"] see Generate produce "sk-..." losing the "ant-"
	// segment — a silent correctness bug.
	prefixes := make([]string, len(f.Prefixes))
	copy(prefixes, f.Prefixes)
	sort.SliceStable(prefixes, func(i, j int) bool {
		return len(prefixes[i]) > len(prefixes[j])
	})

	priority := f.Priority
	if priority == 0 {
		priority = PriorityFormat
	}

	p := ProviderPattern{
		Name:     f.Name,
		Hosts:    f.Hosts,
		Priority: priority,
		Match: func(name, value string) bool {
			for _, pfx := range prefixes {
				if strings.HasPrefix(value, pfx) {
					return true
				}
			}
			upper := strings.ToUpper(name)
			for _, hint := range f.KeyHints {
				if strings.Contains(upper, strings.ToUpper(hint)) {
					return true
				}
			}
			return false
		},
		Generate: func(value string) string {
			prefix := ""
			for _, pfx := range prefixes {
				if strings.HasPrefix(value, pfx) {
					prefix = pfx
					break
				}
			}
			total := f.Length
			if total == 0 {
				total = len(value)
			}
			rest := total - len(prefix)
			if rest < 0 {
				rest = 0
			}
			var body string
			switch f.Charset {
			case "hex":
				body = randFromAlphabet(rest, "0123456789abcdef")
			case "base64":
				body = randBase64ish(rest)
			case "upper-alphanumeric":
				body = randUpperAlphanumeric(rest)
			default:
				body = randAlphanumeric(rest)
			}
			// Embed Sentinel at the start of the body (see engine.go).
			return sentinelize(prefix+body, len(prefix))
		},
	}
	register(p)
}
```

- [ ] **Step 5: Set `Priority: PriorityHandwritten` on each hand-written provider**

Edit each hand-written provider file to set `Priority: PriorityHandwritten` on the registered struct. The edit is one line added inside the `ProviderPattern{...}` literal.

`internal/placeholder/provider_anthropic.go`: inside the `register(ProviderPattern{...})` call, after `Name: "anthropic",` add:
```go
		Priority: PriorityHandwritten,
```

Do the same for:
- `internal/placeholder/provider_aws.go` (Name: "aws")
- `internal/placeholder/provider_github.go` (Name: "github")
- `internal/placeholder/provider_openai.go` (Name: "openai")
- `internal/placeholder/provider_sendgrid.go` (Name: "sendgrid")
- `internal/placeholder/provider_slack.go` (Name: "slack")
- `internal/placeholder/provider_stripe.go` (Name: "stripe")
- `internal/placeholder/provider_supabase.go` (Name: "supabase")
- `internal/placeholder/provider_twilio.go` (Name: "twilio")

- [ ] **Step 6: Switch `engine.go` generateOnce to use `DefaultRegistry().Match()`**

Edit `internal/placeholder/engine.go`. Replace the body of `generateOnce` (starting around line 98):

```go
func generateOnce(name, value string) (string, error) {
	if ph, ok := tryURL(value); ok {
		return ph, nil
	}
	if p := DefaultRegistry().Match(name, value); p != nil {
		return p.Generate(value), nil
	}
	return sentinelize(charClassFake(value), 0), nil
}
```

- [ ] **Step 7: Switch `hosts.go::HostsForCredential` to `DefaultRegistry().All()`**

Edit `internal/placeholder/hosts.go`, lines 62-79 (the `HostsForCredential` function). Replace the provider-registry loop:

```go
func HostsForCredential(name, value string) []string {
	// 1. Check provider registry (Priority-sorted; hand-written before Format).
	for _, p := range DefaultRegistry().All() {
		if p.Match(name, value) && len(p.Hosts) > 0 {
			hosts := make([]string, len(p.Hosts))
			copy(hosts, p.Hosts)
			return hosts
		}
	}

	// 2. Try URL host extraction.
	if h := ExtractURLHost(value); h != "" {
		return []string{h}
	}

	// 3. No hosts detected.
	return nil
}
```

- [ ] **Step 8: Switch `secretlike.go::IsSecretLike` to `DefaultRegistry().All()`**

Edit `internal/placeholder/secretlike.go`. Replace the provider loop in `IsSecretLike`:

```go
func IsSecretLike(name, value string) bool {
	// 1. Check provider patterns (Priority-sorted).
	for _, p := range DefaultRegistry().All() {
		if p.Match(name, value) {
			return true
		}
	}

	// 2. Check URL with password.
	if isURLWithPassword(value) {
		return true
	}

	// 3. Check key name heuristic.
	if secretNamePattern.MatchString(name) {
		return true
	}

	// 4. Length + entropy check.
	if len(value) >= 20 && shannonEntropy(value) >= 3.0 {
		return true
	}

	return false
}
```

(The entropy calibration is done in Task 5. Step 8 only swaps the iteration source.)

- [ ] **Step 9: Run the new Priority tests**

Run: `CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./internal/placeholder/ -run "TestPriority|TestRegistryAll" -v`
Expected: PASS.

- [ ] **Step 10: Run the full placeholder suite**

Run: `CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./internal/placeholder/ -v`
Expected: PASS. All existing tests still green; new Priority tests pass.

- [ ] **Step 11: Run the full repo suite to catch callers of placeholder API**

Run: `make test`
Expected: PASS. No callers in `internal/proxy`, `internal/runner`, etc. should break (they use `placeholder.Generate`, `placeholder.HostsForCredential`, `placeholder.IsSecretLike`, `placeholder.Sentinel` — none of which changed signatures).

- [ ] **Step 12: Commit**

```bash
git add internal/placeholder/priority.go internal/placeholder/providers.go internal/placeholder/engine.go internal/placeholder/hosts.go internal/placeholder/secretlike.go internal/placeholder/provider_*.go internal/placeholder/providers_test.go
git commit -m "feat(placeholder): add Priority field and sorted registry resolution

Replace the filename-ordering hack (provider_zzz_formats.go) with an
explicit Priority int on ProviderPattern. PriorityHandwritten=100 for
custom-logic providers; PriorityFormat=50 default for Format entries.
Registry sorts its backing slice (stable) on first Match/All/Names call
via sync.Once. Direct 'for _, p := range registry' loops in engine.go,
hosts.go, secretlike.go are replaced with DefaultRegistry().Match() and
DefaultRegistry().All() so sorted order is always observed.

Refs: docs/superpowers/findings/2026-04-22-codebase-audit.md §5.1"
```

---

## Task 3: Update contract test to discover providers via `Names()` (MEDIUM)

**Why:** `providers_contract_test.go:71-74` hardcodes 9 names; a new provider registered without a list update passes silently. Drive the test from `reg.Names()` instead.

**Files:**
- Modify: `internal/placeholder/providers_contract_test.go`

- [ ] **Step 1: Write the failing test (via modified expectation)**

This task edits an existing test rather than adding a new one. The "failure" we're checking for is that the current test silently ignores providers not in the `known` list. Add a new assertion first.

Append to `internal/placeholder/providers_contract_test.go`:

```go
// TestAllRegisteredProvidersHaveSamples_Dynamic drives the contract off
// Registry.Names() instead of a hardcoded list. Adding a new provider via
// register()/registerFormat() without also adding a providerSamples entry
// now fails this test loudly instead of being silently ignored.
func TestAllRegisteredProvidersHaveSamples_Dynamic(t *testing.T) {
	reg := placeholder.DefaultRegistry()
	names := reg.Names()
	if len(names) == 0 {
		t.Fatal("Registry.Names() returned empty — expected at least one provider")
	}
	for _, name := range names {
		if _, ok := providerSamples[name]; !ok {
			t.Errorf("provider %q is registered but has no entry in providerSamples (add one at the top of providers_contract_test.go)", name)
		}
	}
}
```

- [ ] **Step 2: Run the new test to verify it passes (providers listed already cover current registry)**

Run: `CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./internal/placeholder/ -run TestAllRegisteredProvidersHaveSamples_Dynamic -v`
Expected: likely FAIL — `providerSamples` in the test file covers 9 providers but the registry has ~22 (9 hand-written + 13 Formats). Every Format provider (google, replicate, huggingface, vercel, gitlab, npm, resend, postmark, datadog, pypi, docker_hub, quay, gcr) is registered but has no entry in the map.

- [ ] **Step 3: Add missing sample entries**

Edit `internal/placeholder/providers_contract_test.go`. Replace the `providerSamples` map to include every registered provider. Put this near the top:

```go
var providerSamples = map[string]sample{
	// Hand-written providers.
	"github":   {"GITHUB_TOKEN", "ghp_" + strings.Repeat("a", 36)},
	"aws":      {"AWS_ACCESS_KEY_ID", "AKIA" + strings.Repeat("A", 16)},
	"twilio":   {"TWILIO_AUTH_TOKEN", "SK" + strings.Repeat("a", 32)},
	"supabase": {"SUPABASE_KEY", "sbp_" + strings.Repeat("a", 36)},
	"sendgrid": {"SENDGRID_API_KEY", "SG." + strings.Repeat("a", 22) + "." + strings.Repeat("b", 43)},
	// Format providers (declarative).
	"openai":      {"OPENAI_API_KEY", "sk-proj-" + strings.Repeat("a", 40)},
	"anthropic":   {"ANTHROPIC_API_KEY", "sk-ant-api03-" + strings.Repeat("a", 95)},
	"stripe":      {"STRIPE_KEY", "sk_live_" + strings.Repeat("a", 24)},
	"slack":       {"SLACK_TOKEN", "xoxb-" + strings.Repeat("a", 50)},
	"google":      {"GOOGLE_API_KEY", "AIza" + strings.Repeat("a", 35)},
	"replicate":   {"REPLICATE_API_TOKEN", "r8_" + strings.Repeat("a", 37)},
	"huggingface": {"HF_TOKEN", "hf_" + strings.Repeat("a", 34)},
	"vercel":      {"VERCEL_TOKEN", "vercel_" + strings.Repeat("a", 20)},
	"gitlab":      {"GITLAB_TOKEN", "glpat-" + strings.Repeat("a", 20)},
	"npm":         {"NPM_TOKEN", "npm_" + strings.Repeat("a", 32)},
	"resend":      {"RESEND_API_KEY", "re_" + strings.Repeat("a", 20)},
	"postmark":    {"POSTMARK_SERVER_TOKEN", strings.Repeat("a", 36)},
	"datadog":     {"DD_API_KEY", strings.Repeat("a", 32)},
	"pypi":        {"TWINE_PASSWORD", "pypi-" + strings.Repeat("a", 40)},
	"docker_hub":  {"DOCKER_HUB_TOKEN", "dckr_pat_" + strings.Repeat("a", 36)},
	"quay":        {"QUAY_TOKEN", strings.Repeat("a", 32)},
	"gcr":         {"GCR_JSON_KEY", strings.Repeat("a", 32)},
}
```

(Order is documentation only; the map is keyed by provider name.)

- [ ] **Step 4: Remove the hardcoded `known` list and old `TestAllRegisteredProvidersHaveSampleOrRegex`**

In `providers_contract_test.go`, delete `TestAllRegisteredProvidersHaveSampleOrRegex` entirely (lines 66-84 of the original). The new `TestAllRegisteredProvidersHaveSamples_Dynamic` supersedes it.

- [ ] **Step 5: Run the contract tests**

Run: `CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./internal/placeholder/ -run "TestProviderContract|TestAllRegisteredProvidersHaveSamples_Dynamic" -v`
Expected: PASS. Every registered provider has a sample; every sample matches its provider.

- [ ] **Step 6: Commit**

```bash
git add internal/placeholder/providers_contract_test.go
git commit -m "test(placeholder): drive provider contract test from Registry.Names()

The previous contract test compared a hardcoded list of 9 provider names
against registry membership, so a new provider added via register() or
registerFormat() without also being listed passed silently. Driving the
test off DefaultRegistry().Names() catches every registered provider.
Expanded providerSamples to cover all ~22 registered providers.

Refs: docs/superpowers/findings/2026-04-22-codebase-audit.md §5.1"
```

---

## Task 4: `ExtractURLHost` enforces scheme allowlist (HIGH, SEC-8)

**Why:** Audit finds `ExtractURLHost` accepts any parseable URL, so `javascript://evil.com` (or any scheme with a `//` and host) yields `evil.com` and would widen the proxy's allow-host set. Apply the same `allowedSchemes` map that `tryURL` uses.

**Files:**
- Modify: `internal/placeholder/hosts.go` — enforce allowlist
- Modify: `internal/placeholder/hosts_test.go` — add regression tests

- [ ] **Step 1: Write the failing tests**

Append to `internal/placeholder/hosts_test.go`:

```go
// TestExtractURLHost_RejectsUnknownScheme asserts that schemes outside the
// allowlist yield empty host regardless of URL syntax validity. This closes
// SEC-8 from the 2026-04-22 audit: a crafted env var value like
// "javascript://evil.com" must not widen the proxy's allow-host set.
func TestExtractURLHost_RejectsUnknownScheme(t *testing.T) {
	cases := []string{
		"javascript://evil.com",
		"javascript://evil.com/foo",
		"file:///etc/passwd",
		"data://base64,abc",
		"vscode://sourcegraph/auth?token=abc",
		"ftp://ftp.example.com/file",
		"ldap://ldap.example.com",
	}
	for _, value := range cases {
		t.Run(value, func(t *testing.T) {
			host := ExtractURLHost(value)
			if host != "" {
				t.Fatalf("scheme-disallowed URL %q yielded host %q; expected empty", value, host)
			}
		})
	}
}

// TestExtractURLHost_AcceptsAllowedSchemes asserts existing scheme handling
// is preserved for the allowlisted schemes.
func TestExtractURLHost_AcceptsAllowedSchemes(t *testing.T) {
	cases := []struct {
		value    string
		wantHost string
	}{
		{"http://example.com/x", "example.com"},
		{"https://api.example.com:443/", "api.example.com"},
		{"postgres://user:pw@db.internal:5432/mydb", "db.internal"},
		{"mysql://root:pw@mysql.internal/db", "mysql.internal"},
		{"redis://:pw@redis.internal:6379/0", "redis.internal"},
		{"mongodb+srv://user:pw@cluster.mongo.internal/db", "cluster.mongo.internal"},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			got := ExtractURLHost(tc.value)
			if got != tc.wantHost {
				t.Fatalf("ExtractURLHost(%q) = %q, want %q", tc.value, got, tc.wantHost)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./internal/placeholder/ -run "TestExtractURLHost_RejectsUnknownScheme|TestExtractURLHost_AcceptsAllowedSchemes" -v`
Expected: FAIL — `javascript://evil.com` currently yields `evil.com` (url.Parse succeeds with Scheme="javascript", Host="evil.com").

- [ ] **Step 3: Add allowlist check to `ExtractURLHost`**

Edit `internal/placeholder/hosts.go`, replacing the body of `ExtractURLHost` (lines 44-55):

```go
// ExtractURLHost attempts to parse value as a URL and return the hostname
// (without port). Returns "" if value is not a parseable URL with a host,
// or if the URL scheme is outside the allowlist (see url.go). The
// allowlist gate prevents crafted env-var values like "javascript://evil.com"
// from widening the proxy's allow-host set via HostsForCredential.
func ExtractURLHost(value string) string {
	u, err := url.Parse(value)
	if err != nil {
		return ""
	}
	if u.Host == "" || u.Scheme == "" {
		return ""
	}
	if !allowedSchemes[u.Scheme] {
		return ""
	}
	return stripPort(u.Host)
}
```

`allowedSchemes` is already a package-level variable in `url.go`; both files are in the same package, so no import is needed.

- [ ] **Step 4: Run the new tests and the existing host tests**

Run: `CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./internal/placeholder/ -run "TestExtractURLHost|TestHostsForCredential" -v`
Expected: PASS — including the new scheme-rejection tests and all existing host tests (they used http/https/postgres which are allowlisted).

- [ ] **Step 5: Run the full repo suite**

Run: `make test`
Expected: PASS. `internal/proxy` uses `HostsForCredential` at credential-registration time; rejecting unknown-scheme URLs may narrow the host set for a credential whose value is a non-standard URL, but such credentials are always inert-until-scoped under the existing semantics.

- [ ] **Step 6: Commit**

```bash
git add internal/placeholder/hosts.go internal/placeholder/hosts_test.go
git commit -m "fix(placeholder): ExtractURLHost enforces scheme allowlist (SEC-8)

ExtractURLHost accepted any parseable URL, so a crafted env-var value
like \"javascript://evil.com\" yielded host \"evil.com\" which would then
widen the proxy's allow-host set via HostsForCredential. Applying the
same allowlist used by tryURL closes this gap.

Refs: docs/superpowers/findings/2026-04-22-codebase-audit.md §3.2 SEC-8"
```

---

## Task 5: `IsSecretLike` entropy + distinct-byte calibration (HIGH)

**Why:** Current floor (`len >= 20 && entropy >= 3.0 bits/char`) flags long file paths, English sentences, and many repeated-structure strings. Raise entropy floor to 4.0 bits/char AND require at least 12 distinct bytes. This lets paths like `/Users/ben/workspace/Veil/internal/placeholder/providers.go` (distinct chars ≈ 18–20 but entropy ≈ 4.1) pass without being flagged as a secret, while high-entropy tokens like `aB3$dE7&hI1!kL5@nO9#qR2%tU6^wX0*yZ4(cD8` still flag.

**Files:**
- Modify: `internal/placeholder/secretlike.go` — add `distinctBytes`; raise entropy; require both
- Modify: `internal/placeholder/secretlike_test.go` — add path/sentence regression tests; retain the high-entropy positive test

- [ ] **Step 1: Write the failing regression tests**

Append to `internal/placeholder/secretlike_test.go`:

```go
// TestIsSecretLike_FilePathNotFlagged asserts that a typical Unix file path
// is not flagged as secret-like. These are a common false-positive source
// because they have moderate entropy (~4.0 bits/char) and exceed 20 chars.
func TestIsSecretLike_FilePathNotFlagged(t *testing.T) {
	cases := []string{
		"/Users/ben/workspace/Veil/internal/placeholder/providers.go",
		"/home/alice/projects/foo/bar/baz/qux.py",
		"/var/log/syslog.1.gz",
		"~/.config/app/settings.json",
	}
	for _, value := range cases {
		t.Run(value, func(t *testing.T) {
			// Key name is deliberately non-secretish so only the
			// length+entropy heuristic can fire.
			if IsSecretLike("SOMEPATH", value) {
				t.Fatalf("expected file path not to be secret-like: %q (entropy=%.2f, distinct=%d)",
					value, shannonEntropy(value), distinctBytes(value))
			}
		})
	}
}

// TestIsSecretLike_EnglishSentenceNotFlagged asserts that a typical English
// sentence is not flagged as secret-like.
func TestIsSecretLike_EnglishSentenceNotFlagged(t *testing.T) {
	cases := []string{
		"the quick brown fox jumps over the lazy dog",
		"this is a sample log line emitted by the service",
		"error: could not connect to the backend server",
	}
	for _, value := range cases {
		t.Run(value, func(t *testing.T) {
			if IsSecretLike("LOG_LINE", value) {
				t.Fatalf("expected English sentence not to be secret-like: %q (entropy=%.2f, distinct=%d)",
					value, shannonEntropy(value), distinctBytes(value))
			}
		})
	}
}

// TestIsSecretLike_HighEntropyLong_StillFlagged preserves the original
// positive signal: a genuinely random, high-entropy string with many
// distinct bytes must still be flagged.
func TestIsSecretLike_HighEntropyLong_StillFlagged(t *testing.T) {
	value := "aB3$dE7&hI1!kL5@nO9#qR2%tU6^wX0*yZ4(cD8"
	if !IsSecretLike("UNKNOWN", value) {
		t.Fatalf("expected true for high-entropy long string (entropy=%.2f, distinct=%d)",
			shannonEntropy(value), distinctBytes(value))
	}
}

// TestDistinctBytes verifies the helper's correctness.
func TestDistinctBytes(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"a", 1},
		{"aa", 1},
		{"ab", 2},
		{"abcabc", 3},
		{"abcdefghij", 10},
	}
	for _, tc := range cases {
		if got := distinctBytes(tc.in); got != tc.want {
			t.Fatalf("distinctBytes(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
```

- [ ] **Step 2: Run new tests to verify they fail**

Run: `CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./internal/placeholder/ -run "TestIsSecretLike_FilePathNotFlagged|TestIsSecretLike_EnglishSentenceNotFlagged|TestDistinctBytes" -v`
Expected: FAIL — `distinctBytes` is undefined; file paths currently flag because `len >= 20 && entropy >= 3.0` is too loose.

- [ ] **Step 3: Add `distinctBytes` helper and raise the entropy threshold**

Edit `internal/placeholder/secretlike.go`. Replace the entire file with:

```go
package placeholder

import (
	"math"
	"regexp"
)

// secretNamePattern matches common secret-related key names.
var secretNamePattern = regexp.MustCompile(`(?i)(key|secret|token|password|passwd|pwd|auth|credential|dsn)`)

// Calibrated thresholds for the entropy-based secret heuristic. The original
// 3.0 bits/char floor was too low — long file paths and English sentences
// routinely exceed it. Raising to 4.0 and additionally requiring >= 12
// distinct bytes filters most real-world paths / sentences while keeping
// high-entropy tokens like "aB3$dE7&hI1!kL5@nO9#qR2%tU6^wX0*yZ4(cD8" flagged.
const (
	secretMinLength   = 20
	secretMinEntropy  = 4.0
	secretMinDistinct = 12
)

// IsSecretLike determines whether a name/value pair likely represents a secret.
// It returns true if:
//   - The value matches any registered provider pattern.
//   - The value is a URL with a password in a supported scheme.
//   - The key name matches common secret-related patterns.
//   - The value is long, has high Shannon entropy, AND has enough distinct
//     bytes to rule out repetitive strings and typical file paths.
func IsSecretLike(name, value string) bool {
	// 1. Check provider patterns (Priority-sorted).
	for _, p := range DefaultRegistry().All() {
		if p.Match(name, value) {
			return true
		}
	}

	// 2. Check URL with password.
	if isURLWithPassword(value) {
		return true
	}

	// 3. Check key name heuristic.
	if secretNamePattern.MatchString(name) {
		return true
	}

	// 4. Length + entropy + distinct-byte check.
	if len(value) >= secretMinLength &&
		shannonEntropy(value) >= secretMinEntropy &&
		distinctBytes(value) >= secretMinDistinct {
		return true
	}

	return false
}

// shannonEntropy computes Shannon entropy in bits per character over byte
// frequencies in s. Returns 0 for empty strings.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[byte]int)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}

	n := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / n
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// distinctBytes returns the number of distinct byte values in s.
func distinctBytes(s string) int {
	var seen [256]bool
	n := 0
	for i := 0; i < len(s); i++ {
		if !seen[s[i]] {
			seen[s[i]] = true
			n++
		}
	}
	return n
}
```

- [ ] **Step 4: Run the new tests**

Run: `CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./internal/placeholder/ -run "TestIsSecretLike|TestDistinctBytes|TestShannonEntropy" -v`
Expected: PASS — new file-path and sentence tests pass; existing `TestIsSecretLike_HighEntropyLong` (`aB3$dE7&...`) still passes because that string has ~39 distinct bytes and ~5.28 bits/char entropy.

If `TestIsSecretLike_HighEntropyLong_StillFlagged` or any existing test fails, adjust the thresholds inside the tight bracket (4.0–4.2 bits; 10–14 distinct) until positive + negative tests both pass, then re-run the full suite.

- [ ] **Step 5: Run the full placeholder suite**

Run: `CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./internal/placeholder/ -v`
Expected: PASS.

- [ ] **Step 6: Run the full repo suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/placeholder/secretlike.go internal/placeholder/secretlike_test.go
git commit -m "fix(placeholder): raise IsSecretLike entropy floor and require distinct bytes

The 3.0 bits/char entropy floor was too low — long file paths and typical
English sentences routinely exceed it. Raising the floor to 4.0 and
additionally requiring >= 12 distinct bytes filters those false positives
while keeping genuinely random high-entropy tokens flagged. Added
regression tests for file paths, English sentences, and the calibrated
threshold constants.

Refs: docs/superpowers/findings/2026-04-22-codebase-audit.md §3.3, §2"
```

---

## Task 6: Migrate `openai` to Format

**Why:** `openai` is the simplest migration — one prefix (`sk-proj-`), one keyhint (`OPENAI`), same-length output. After this task the hand-written `provider_openai.go` is gone.

**Files:**
- Modify: `internal/placeholder/provider_zzz_formats.go` — add openai Format entry
- Delete: `internal/placeholder/provider_openai.go`

- [ ] **Step 1: Add the openai Format entry**

Edit `internal/placeholder/provider_zzz_formats.go`. Inside the `init()` function, add this entry at the top (ordering within the file is cosmetic; Priority sort governs resolution):

```go
	registerFormat(Format{
		Name:     "openai",
		Prefixes: []string{"sk-proj-"},
		KeyHints: []string{"OPENAI"},
		Length:   0, // preserve input length
		Charset:  "alphanumeric",
		Hosts:    []string{"api.openai.com"},
	})
```

- [ ] **Step 2: Delete the hand-written provider file**

```bash
rm internal/placeholder/provider_openai.go
```

- [ ] **Step 3: Run tests**

Run: `CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./internal/placeholder/ -run "TestProviderOpenAI|TestGenerate_ProviderMatch|TestGenerateAlwaysContainsSentinel|TestProviderContract" -v`
Expected: PASS. `TestProviderOpenAI` still resolves via the registry (now Format-backed); length and prefix invariants hold; sentinel is embedded via `registerFormat`.

- [ ] **Step 4: Run the full repo suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/placeholder/provider_zzz_formats.go
git rm internal/placeholder/provider_openai.go
git commit -m "refactor(placeholder): migrate openai to declarative Format entry

OpenAI's sk-proj- prefix + OPENAI keyhint + same-length alphanumeric body
maps cleanly to the Format API. Deleting provider_openai.go removes ~25
LoC of duplicated prefix-scan logic. Sentinel embedding is unchanged
(registerFormat already calls sentinelize with len(prefix) offset).

Refs: docs/superpowers/findings/2026-04-22-codebase-audit.md §4.1"
```

---

## Task 7: Migrate `anthropic` to Format

**Why:** Anthropic has two overlapping prefixes (`sk-ant-api`, `sk-ant-`). Task 1's prefix-sort fix is the prerequisite — without it, Format would pick the shorter prefix and lose the `api` segment on generation.

**Files:**
- Modify: `internal/placeholder/provider_zzz_formats.go`
- Delete: `internal/placeholder/provider_anthropic.go`

- [ ] **Step 1: Add the anthropic Format entry**

Edit `internal/placeholder/provider_zzz_formats.go` to add this entry inside `init()`:

```go
	registerFormat(Format{
		Name:     "anthropic",
		Prefixes: []string{"sk-ant-api", "sk-ant-"}, // sorted by len desc inside registerFormat
		KeyHints: []string{"ANTHROPIC"},
		Length:   0,
		Charset:  "alphanumeric",
		Hosts:    []string{"api.anthropic.com"},
	})
```

- [ ] **Step 2: Delete the hand-written provider file**

```bash
rm internal/placeholder/provider_anthropic.go
```

- [ ] **Step 3: Run tests**

Run: `CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./internal/placeholder/ -run "TestProviderAnthropic|TestGenerateAlwaysContainsSentinel|TestProviderContract" -v`
Expected: PASS — including the `generate_preserves_sk-ant-api` and `generate_preserves_sk-ant-` subtests. The former verifies Task 1's fix is in effect: for input `sk-ant-api03-...`, output must start with `sk-ant-api`, not `sk-ant-`.

- [ ] **Step 4: Run the full repo suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/placeholder/provider_zzz_formats.go
git rm internal/placeholder/provider_anthropic.go
git commit -m "refactor(placeholder): migrate anthropic to declarative Format entry

Overlapping prefixes [sk-ant-api, sk-ant-] are now handled correctly by
registerFormat's length-descending sort (Task 1). Deleting
provider_anthropic.go removes ~20 LoC of duplicated prefix-scan logic.

Refs: docs/superpowers/findings/2026-04-22-codebase-audit.md §4.1"
```

---

## Task 8: Migrate `stripe` to Format

**Why:** Stripe has 6 prefixes (`sk_live_`, `sk_test_`, `pk_live_`, `pk_test_`, `rk_live_`, `rk_test_`) — all equal length. Format handles this cleanly now that Task 1 is in.

**Files:**
- Modify: `internal/placeholder/provider_zzz_formats.go`
- Delete: `internal/placeholder/provider_stripe.go`

- [ ] **Step 1: Add the stripe Format entry**

Edit `internal/placeholder/provider_zzz_formats.go` inside `init()`:

```go
	registerFormat(Format{
		Name:     "stripe",
		Prefixes: []string{"sk_live_", "sk_test_", "pk_live_", "pk_test_", "rk_live_", "rk_test_"},
		KeyHints: []string{"STRIPE"},
		Length:   0,
		Charset:  "alphanumeric",
		Hosts:    []string{"api.stripe.com", "files.stripe.com"},
	})
```

- [ ] **Step 2: Delete the hand-written provider file**

```bash
rm internal/placeholder/provider_stripe.go
```

- [ ] **Step 3: Run tests**

Run: `CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./internal/placeholder/ -run "TestProviderStripe|TestGenerateAlwaysContainsSentinel|TestProviderContract|TestGenerateRetriesOnCollision|TestGenerateReturnsCollisionErrorWhenSaturated" -v`
Expected: PASS. The collision test uses `sk_live_original` which the Format entry handles identically.

- [ ] **Step 4: Run the full repo suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/placeholder/provider_zzz_formats.go
git rm internal/placeholder/provider_stripe.go
git commit -m "refactor(placeholder): migrate stripe to declarative Format entry

Six Stripe prefixes (sk_live_, sk_test_, pk_live_, pk_test_, rk_live_,
rk_test_) map cleanly to Format.Prefixes. Deleting provider_stripe.go
removes ~30 LoC including the stripePrefixes slice.

Refs: docs/superpowers/findings/2026-04-22-codebase-audit.md §4.1"
```

---

## Task 9: Migrate `slack` to Format (drops dash-preservation)

**Why:** Slack's hand-written `Generate` preserves dashes at their positions in the remainder. Format has no dash-preservation feature — after migration, output is `xoxb-<alphanumeric>`. This is still a valid Slack-shaped placeholder string; the existing subtest `generate_preserves_dashes` is removed.

**Files:**
- Modify: `internal/placeholder/provider_zzz_formats.go`
- Delete: `internal/placeholder/provider_slack.go`
- Modify: `internal/placeholder/providers_test.go` — remove `generate_preserves_dashes` subtest in `TestProviderSlack`

- [ ] **Step 1: Add the slack Format entry**

Edit `internal/placeholder/provider_zzz_formats.go` inside `init()`:

```go
	registerFormat(Format{
		Name:     "slack",
		Prefixes: []string{"xoxb-", "xoxp-", "xoxs-", "xoxa-", "xoxr-"},
		KeyHints: []string{"SLACK"},
		Length:   0,
		Charset:  "alphanumeric",
		Hosts:    []string{"slack.com", "api.slack.com", "files.slack.com"},
	})
```

- [ ] **Step 2: Delete the hand-written provider file**

```bash
rm internal/placeholder/provider_slack.go
```

- [ ] **Step 3: Remove the `generate_preserves_dashes` subtest**

Edit `internal/placeholder/providers_test.go`. Inside `TestProviderSlack` (around line 242), delete the entire `t.Run("generate_preserves_dashes", ...)` block (the `for i, c := range remainder` loop checking dash positions). Keep the other subtests.

The remaining `TestProviderSlack` subtests should be: `match_<prefix>` for each prefix, `match_name`, `no_match`, `generate_different`. Add a new `generate_length` subtest in its place so total-length invariance is still covered:

```go
	t.Run("generate_length", func(t *testing.T) {
		value := "xoxb-123-456-abc789def"
		result := prov.Generate(value)
		if len(result) != len(value) {
			t.Fatalf("length mismatch: %d vs %d", len(result), len(value))
		}
		if !strings.HasPrefix(result, "xoxb-") {
			t.Fatalf("prefix not preserved: %s", result)
		}
	})
```

- [ ] **Step 4: Run tests**

Run: `CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./internal/placeholder/ -run "TestProviderSlack|TestGenerateAlwaysContainsSentinel|TestProviderContract" -v`
Expected: PASS.

- [ ] **Step 5: Run the full repo suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/placeholder/provider_zzz_formats.go internal/placeholder/providers_test.go
git rm internal/placeholder/provider_slack.go
git commit -m "refactor(placeholder): migrate slack to declarative Format entry

Five Slack prefixes (xoxb-, xoxp-, xoxs-, xoxa-, xoxr-) map to
Format.Prefixes. Dash-preservation in the remainder is dropped — the
output xoxb-<alphanumeric> is still a structurally valid Slack-shaped
placeholder. Removed the generate_preserves_dashes subtest.

Refs: docs/superpowers/findings/2026-04-22-codebase-audit.md §4.1"
```

---

## Task 10: Rename `provider_zzz_formats.go` → `provider_formats.go`

**Why:** The `zzz_` prefix exists solely to force registration order via filename alphabetization. With Priority-based resolution (Task 2), registration order no longer drives resolution. Rename to a descriptive filename and delete the explanatory comments about ordering.

**Files:**
- Rename: `internal/placeholder/provider_zzz_formats.go` → `internal/placeholder/provider_formats.go`
- Rename: `internal/placeholder/provider_zzz_formats_test.go` → `internal/placeholder/provider_formats_test.go`
- Modify: update any comment inside the file that references "zzz" or registration order

- [ ] **Step 1: Rename files via git mv (preserves history)**

```bash
git mv internal/placeholder/provider_zzz_formats.go internal/placeholder/provider_formats.go
git mv internal/placeholder/provider_zzz_formats_test.go internal/placeholder/provider_formats_test.go
```

- [ ] **Step 2: Update the header comment inside `provider_formats.go`**

Edit `internal/placeholder/provider_formats.go`. Update any comment that mentions "zzz" / filename ordering / registration order. Replace with a comment explaining that Priority governs ordering. A suitable leading comment at the top of the file (before `package placeholder`):

```go
// provider_formats.go registers all declarative Format-based providers.
// Resolution order against hand-written providers is governed by Priority
// (see priority.go and providers.go); previously this file was named
// provider_zzz_formats.go to force it to init() last via filename
// alphabetization, which is no longer load-bearing.
```

- [ ] **Step 3: Extend the Formats table test to cover the migrated providers**

Edit `internal/placeholder/provider_formats_test.go`. Add entries for openai, anthropic, stripe, slack at the top of the `tests` slice in `TestFormatProviders`:

```go
		{
			name:       "openai",
			matchKey:   "OPENAI_API_KEY",
			matchValue: "sk-proj-abcdef0123456789abcdef0123456789",
			noMatchKey: "OTHER_KEY",
			genInput:   "sk-proj-abcdef0123456789abcdef0123456789",
			wantPrefix: "sk-proj-",
			wantLen:    0,
			charset:    "alphanumeric",
			wantHosts:  []string{"api.openai.com"},
		},
		{
			name:       "anthropic",
			matchKey:   "ANTHROPIC_API_KEY",
			matchValue: "sk-ant-api03-" + strings.Repeat("a", 95),
			noMatchKey: "OTHER_KEY",
			genInput:   "sk-ant-api03-" + strings.Repeat("a", 95),
			wantPrefix: "sk-ant-api",
			wantLen:    0,
			charset:    "alphanumeric",
			wantHosts:  []string{"api.anthropic.com"},
		},
		{
			name:       "stripe",
			matchKey:   "STRIPE_SECRET_KEY",
			matchValue: "sk_live_" + strings.Repeat("a", 24),
			noMatchKey: "OTHER_KEY",
			genInput:   "sk_live_" + strings.Repeat("a", 24),
			wantPrefix: "sk_live_",
			wantLen:    0,
			charset:    "alphanumeric",
			wantHosts:  []string{"api.stripe.com", "files.stripe.com"},
		},
		{
			name:       "slack",
			matchKey:   "SLACK_BOT_TOKEN",
			matchValue: "xoxb-" + strings.Repeat("a", 50),
			noMatchKey: "OTHER_KEY",
			genInput:   "xoxb-" + strings.Repeat("a", 50),
			wantPrefix: "xoxb-",
			wantLen:    0,
			charset:    "alphanumeric",
			wantHosts:  []string{"slack.com", "api.slack.com", "files.slack.com"},
		},
```

- [ ] **Step 4: Run the full placeholder suite**

Run: `CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./internal/placeholder/ -v`
Expected: PASS.

- [ ] **Step 5: Grep for any lingering "zzz" references**

Run: `grep -rn "zzz" internal/ docs/ 2>/dev/null || true`
Expected: no matches inside `internal/placeholder/`. Any matches elsewhere are unrelated.

- [ ] **Step 6: Run the full repo suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/placeholder/provider_formats.go internal/placeholder/provider_formats_test.go
git commit -m "refactor(placeholder): rename provider_zzz_formats → provider_formats

The zzz_ filename prefix forced Format providers to init() last via
filename alphabetization. Priority-based resolution (Task 2) replaces
that ordering contract, so the cryptic filename is no longer needed.
Extended the Formats table test to cover openai, anthropic, stripe, slack
(migrated from hand-written in Tasks 6-9).

Refs: docs/superpowers/findings/2026-04-22-codebase-audit.md §5.1"
```

---

## Task 11: Add per-provider test files for `aws` and `github`

**Why:** Every `provider_*.go` must have a matching `provider_*_test.go`. `aws` and `github` are currently covered only in the shared `providers_test.go`. Move their dedicated tests to their own files.

**Files:**
- Create: `internal/placeholder/provider_aws_test.go`
- Create: `internal/placeholder/provider_github_test.go`
- Modify: `internal/placeholder/providers_test.go` — remove `TestProviderAWS`, `TestProviderGitHub`, `TestProviderGitHub_FinegrainedPAT`

- [ ] **Step 1: Create `provider_aws_test.go`**

Create `internal/placeholder/provider_aws_test.go` with the full body of `TestProviderAWS` moved from `providers_test.go`:

```go
package placeholder

import (
	"strings"
	"testing"
)

func TestProviderAWS(t *testing.T) {
	var prov ProviderPattern
	for _, p := range registry {
		if p.Name == "aws" {
			prov = p
			break
		}
	}
	if prov.Name == "" {
		t.Fatal("aws provider not registered")
	}

	t.Run("match_AKIA", func(t *testing.T) {
		if !prov.Match("", "AKIAIOSFODNN7EXAMPLE") {
			t.Fatal("should match AKIA prefix")
		}
	})
	t.Run("match_name_access_key_id", func(t *testing.T) {
		if !prov.Match("AWS_ACCESS_KEY_ID", "anything") {
			t.Fatal("should match AWS_ACCESS_KEY_ID")
		}
	})
	t.Run("match_name_secret", func(t *testing.T) {
		if !prov.Match("AWS_SECRET_ACCESS_KEY", "anything") {
			t.Fatal("should match AWS_SECRET_ACCESS_KEY")
		}
	})
	t.Run("no_match", func(t *testing.T) {
		if prov.Match("OTHER", "value") {
			t.Fatal("should not match unrelated")
		}
	})
	t.Run("generate_AKIA_length", func(t *testing.T) {
		value := "AKIAIOSFODNN7EXAMPLE" // 20 chars
		result := prov.Generate(value)
		if len(result) != 20 {
			t.Fatalf("expected length 20, got %d", len(result))
		}
		if !strings.HasPrefix(result, "AKIA") {
			t.Fatalf("expected AKIA prefix, got: %s", result)
		}
		// Rest should be uppercase alphanumeric (sentinel "VEIL" is uppercase alnum).
		for _, c := range result[4:] {
			isUpper := c >= 'A' && c <= 'Z'
			isDigit := c >= '0' && c <= '9'
			if !isUpper && !isDigit {
				t.Fatalf("expected uppercase alphanumeric, got: %c", c)
			}
		}
	})
	t.Run("generate_secret_key_length", func(t *testing.T) {
		value := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" // 40 chars
		result := prov.Generate(value)
		if len(result) != len(value) {
			t.Fatalf("expected length %d, got %d", len(value), len(result))
		}
	})
}
```

- [ ] **Step 2: Create `provider_github_test.go`**

Create `internal/placeholder/provider_github_test.go` with `TestProviderGitHub` and `TestProviderGitHub_FinegrainedPAT` moved from `providers_test.go`:

```go
package placeholder

import (
	"strings"
	"testing"
)

func TestProviderGitHub(t *testing.T) {
	var prov ProviderPattern
	for _, p := range registry {
		if p.Name == "github" {
			prov = p
			break
		}
	}
	if prov.Name == "" {
		t.Fatal("github provider not registered")
	}

	for _, prefix := range []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"} {
		t.Run("match_"+prefix, func(t *testing.T) {
			if !prov.Match("", prefix+"abc123") {
				t.Fatalf("should match %s prefix", prefix)
			}
		})
		t.Run("generate_"+prefix, func(t *testing.T) {
			value := prefix + "abcdef123456abcdef123456"
			result := prov.Generate(value)
			if !strings.HasPrefix(result, prefix) {
				t.Fatalf("prefix not preserved: %s", result)
			}
			if len(result) != len(value) {
				t.Fatalf("length mismatch: %d vs %d", len(result), len(value))
			}
		})
	}
	t.Run("match_name", func(t *testing.T) {
		if !prov.Match("GITHUB_TOKEN", "anything") {
			t.Fatal("should match GITHUB in name")
		}
	})
	t.Run("no_match", func(t *testing.T) {
		if prov.Match("OTHER", "value") {
			t.Fatal("should not match unrelated")
		}
	})
}

func TestProviderGitHub_FinegrainedPAT(t *testing.T) {
	var prov ProviderPattern
	for _, p := range registry {
		if p.Name == "github" {
			prov = p
			break
		}
	}

	value := "github_pat_11ABCDEFGHIJKLMNOPQRST_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXa"

	t.Run("match_github_pat_prefix", func(t *testing.T) {
		if !prov.Match("", value) {
			t.Fatal("should match github_pat_ prefix")
		}
	})

	t.Run("generate_github_pat_structure", func(t *testing.T) {
		result := prov.Generate(value)
		if len(result) != len(value) {
			t.Fatalf("length mismatch: %d vs %d", len(result), len(value))
		}
		if result[:11] != "github_pat_" {
			t.Fatalf("expected github_pat_ prefix, got: %s", result[:11])
		}
		// Position 33 (11 + 22) should be an underscore.
		if result[33] != '_' {
			t.Fatalf("expected underscore at position 33, got: %c in %s", result[33], result)
		}
		// Characters 11-32 should be alphanumeric.
		for i := 11; i < 33; i++ {
			c := rune(result[i])
			isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			if !isAlnum {
				t.Fatalf("expected alphanumeric at pos %d, got: %c", i, c)
			}
		}
		// Characters 34-92 should be alphanumeric.
		for i := 34; i < len(result); i++ {
			c := rune(result[i])
			isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			if !isAlnum {
				t.Fatalf("expected alphanumeric at pos %d, got: %c", i, c)
			}
		}
	})
}
```

- [ ] **Step 3: Remove the moved tests from `providers_test.go`**

Edit `internal/placeholder/providers_test.go`. Delete:
- `TestProviderAWS` (the entire function)
- `TestProviderGitHub` (the entire function)
- `TestProviderGitHub_FinegrainedPAT` (the entire function)

Also remove any now-unused imports (Goimports / `go vet` will flag them if so; `strings` is still used by the remaining tests).

Additionally, remove `TestProviderOpenAI`, `TestProviderAnthropic`, `TestProviderStripe`, `TestProviderSlack` since their providers are now Format-backed and coverage is provided by the Formats table test in `provider_formats_test.go`. Keeping these creates duplicate coverage without adding value; removing them completes the migration cleanly.

After these removals, `providers_test.go` should contain only:
- `TestRegisterFormat_BasicMatch`
- `TestRegisterFormat_HexCharset`
- `TestRegisterFormat_ZeroLengthPreservesInput`
- `TestRegisterFormat_LongerPrefixWins` (added in Task 1)
- `TestPriority_HandwrittenBeforeFormat` (added in Task 2)
- `TestPriority_StableWithinTier` (added in Task 2)
- `TestRegistryAll_ReturnsSortedSnapshot` (added in Task 2)
- `TestRegistryIsolation`
- `TestDefaultRegistryMatchesPackageRegistry`

- [ ] **Step 4: Run the full placeholder suite**

Run: `CGO_ENABLED=0 VEIL_TEST_KEYSTORE=mem go test -tags testkeystore ./internal/placeholder/ -v`
Expected: PASS. Total test count drops slightly (duplicate subtests removed) but every provider still has coverage.

- [ ] **Step 5: Verify per-provider test coverage**

Run: `ls internal/placeholder/provider_*_test.go`
Expected output:
```
internal/placeholder/provider_aws_test.go
internal/placeholder/provider_formats_test.go
internal/placeholder/provider_github_test.go
internal/placeholder/provider_sendgrid_test.go
internal/placeholder/provider_supabase_test.go
internal/placeholder/provider_twilio_test.go
```

Run: `ls internal/placeholder/provider_*.go | grep -v _test.go`
Expected output:
```
internal/placeholder/provider_aws.go
internal/placeholder/provider_formats.go
internal/placeholder/provider_github.go
internal/placeholder/provider_sendgrid.go
internal/placeholder/provider_supabase.go
internal/placeholder/provider_twilio.go
```

Every `provider_*.go` has a matching `provider_*_test.go`.

- [ ] **Step 6: Run the full repo suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/placeholder/provider_aws_test.go internal/placeholder/provider_github_test.go internal/placeholder/providers_test.go
git commit -m "test(placeholder): give every provider its own *_test.go file

aws and github were covered only in the shared providers_test.go. Moved
TestProviderAWS, TestProviderGitHub, and TestProviderGitHub_FinegrainedPAT
to dedicated files. Removed the now-redundant TestProviderOpenAI /
Anthropic / Stripe / Slack (those providers are Format-backed and covered
by provider_formats_test.go::TestFormatProviders).

Every provider_*.go now has a matching provider_*_test.go.

Refs: docs/superpowers/findings/2026-04-22-codebase-audit.md §4.1"
```

---

## Task 12: Final verification

- [ ] **Step 1: Run make test and capture output**

Run: `make test 2>&1 | tee /tmp/veil-placeholder-final.txt`
Expected: all packages `ok`. Key line to verify:
```
ok  	github.com/8enji/veil/internal/placeholder	...
```
and no `FAIL` lines anywhere.

- [ ] **Step 2: Run make test-race to confirm no data races**

Run: `make test-race 2>&1 | tail -30`
Expected: all packages `ok`. The sync.Once-guarded sortPatterns should never race.

- [ ] **Step 3: Run go vet on the whole repo**

Run: `CGO_ENABLED=0 go vet ./...`
Expected: no output (vet is clean).

- [ ] **Step 4: Verify file structure matches the plan**

Run: `ls internal/placeholder/*.go | sort`
Expected (alphabetical):
```
internal/placeholder/charclass.go
internal/placeholder/charclass_test.go
internal/placeholder/engine.go
internal/placeholder/engine_test.go
internal/placeholder/errors.go
internal/placeholder/fuzz_test.go
internal/placeholder/hosts.go
internal/placeholder/hosts_test.go
internal/placeholder/priority.go
internal/placeholder/provider_aws.go
internal/placeholder/provider_aws_test.go
internal/placeholder/provider_formats.go
internal/placeholder/provider_formats_test.go
internal/placeholder/provider_github.go
internal/placeholder/provider_github_test.go
internal/placeholder/provider_sendgrid.go
internal/placeholder/provider_sendgrid_test.go
internal/placeholder/provider_supabase.go
internal/placeholder/provider_supabase_test.go
internal/placeholder/provider_twilio.go
internal/placeholder/provider_twilio_test.go
internal/placeholder/providers.go
internal/placeholder/providers_contract_test.go
internal/placeholder/providers_test.go
internal/placeholder/secretlike.go
internal/placeholder/secretlike_test.go
internal/placeholder/sentinel_test.go
internal/placeholder/url.go
internal/placeholder/url_test.go
```

`provider_openai.go`, `provider_anthropic.go`, `provider_stripe.go`, `provider_slack.go`, `provider_zzz_formats.go`, `provider_zzz_formats_test.go` are absent.

- [ ] **Step 5: Write the final summary as the PR body / handoff note**

Summarize in under 200 words:

```
(a) Priority scheme:
    - New int field `Priority` on `ProviderPattern` (defined in priority.go).
    - Constants: `PriorityHandwritten = 100`, `PriorityFormat = 50`.
    - Higher runs first; `Registry.sortPatterns` does a stable sort via sync.Once
      on first Match/All/Names call. Registration order preserved within a tier.

(b) Migrated to Format:
    - openai, anthropic, stripe, slack → `provider_formats.go` Format entries.
    - Net ~60 LoC removed. Hand-written `provider_openai/anthropic/stripe/slack.go` deleted.
    - Remaining hand-written: github, aws, twilio, supabase, sendgrid (custom shapes: multi-segment PAT, two-shape AWS, length-gated Twilio, JWT Supabase, dot-split SendGrid).

(c) Contract test:
    - Uses `Registry.Names()` for dynamic discovery; hardcoded `known` list removed.
    - `providerSamples` map expanded to cover all ~22 registered providers.

(d) IsSecretLike calibration:
    - Entropy floor raised 3.0 → 4.0 bits/char.
    - New requirement: distinct bytes ≥ 12.
    - File paths and English sentences no longer false-positive; high-entropy tokens
      (distinct bytes ~39, entropy ~5.28) still flagged.

(e) make test: all packages green.
```

- [ ] **Step 6: (Optional) Create a final squash or merge commit if the team workflow prefers it**

If the team uses squash-merge, individual commits are already small and logical; skip this step. If they prefer a single merge commit, wrap via a merge commit — no rebase needed since the branch is linear.

No commit — this is a verification-only step.

---

## Self-Review Notes

- **Spec coverage:**
  - (1) registerFormat prefix-ordering → Task 1 ✓
  - (2) Priority field + sorted resolution → Task 2 ✓
  - (3) Migrate 4 providers → Tasks 6-9 ✓
  - (4) Rename provider_zzz_formats.go → Task 10 ✓
  - (5) ExtractURLHost scheme allowlist → Task 4 ✓
  - (6) IsSecretLike calibration → Task 5 ✓
  - (7) Dynamic contract-test discovery → Task 3 ✓
  - Per-provider test files for every provider_*.go → Task 11 ✓
  - Sentinel preservation → Task 6-9 (Format's `sentinelize(prefix+body, len(prefix))` is unchanged) ✓
  - No changes to proxy/cli/runner/audit/vault → constraint respected throughout ✓

- **Placeholder scan:** No TBDs, TODOs, or "add appropriate X" patterns. Every step has exact code, exact commands, and expected output.

- **Type consistency:**
  - `PriorityHandwritten`, `PriorityFormat` used consistently across Tasks 2–11.
  - `ProviderPattern.Priority` added in Task 2 and used identically in all subsequent tasks.
  - `Registry.All()`, `Registry.Names()`, `Registry.sortPatterns()` defined in Task 2 and referenced in Tasks 3, 4 (via chain), 5, 11.
  - `distinctBytes` defined in Task 5's secretlike.go edit; referenced in the new Task 5 tests.
  - `allowedSchemes` in Task 4 is pre-existing in `url.go`; reused without re-declaration.

Plan is self-consistent.
