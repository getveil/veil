package placeholder

import (
	"strings"
	"sync"
	"testing"
)

// TestRegisterDeclarative_BasicMatch exercises the declarative registration
// path: a provider with Prefixes / KeyHints / Length / Charset and no
// explicit Match/Generate gets functional defaults.
func TestRegisterDeclarative_BasicMatch(t *testing.T) {
	before := len(registry)
	saved := append([]ProviderPattern(nil), registry...)
	register(ProviderPattern{
		Name:          "testprovider",
		Prefixes:      []string{"tp_"},
		KeyHints:      []string{"TESTPROV"},
		Length:        20,
		Charset:       "alphanumeric",
		Hosts:         []string{"api.testprovider.com"},
		VaultEligible: true,
	})
	defer func() { registry = saved }()

	var prov ProviderPattern
	for _, p := range registry[before:] {
		if p.Name == "testprovider" {
			prov = p
			break
		}
	}
	if prov.Name == "" {
		t.Fatal("testprovider not registered")
	}
	if !prov.Match("ANY_KEY", "tp_abc123") {
		t.Fatal("should match tp_ prefix")
	}
	if !prov.Match("TESTPROV_KEY", "anything") {
		t.Fatal("should match TESTPROV in key name")
	}
	if prov.Match("OTHER", "other") {
		t.Fatal("should not match unrelated")
	}

	result := prov.Generate("", "tp_originalvalue1234")
	if len(result) != 20 {
		t.Fatalf("expected length 20, got %d: %s", len(result), result)
	}
	if result[:3] != "tp_" {
		t.Fatalf("expected tp_ prefix, got: %s", result)
	}
	for _, c := range result[3:] {
		isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlnum {
			t.Fatalf("expected alphanumeric char, got: %c", c)
		}
	}
	if len(prov.Hosts) != 1 || prov.Hosts[0] != "api.testprovider.com" {
		t.Fatalf("unexpected hosts: %v", prov.Hosts)
	}
}

func TestRegisterDeclarative_HexCharset(t *testing.T) {
	before := len(registry)
	saved := append([]ProviderPattern(nil), registry...)
	register(ProviderPattern{
		Name:     "testhex",
		Prefixes: nil,
		KeyHints: []string{"TESTHEX"},
		Length:   32,
		Charset:  "hex",
		Hosts:    []string{"api.testhex.com"},
	})
	defer func() { registry = saved }()

	var prov ProviderPattern
	for _, p := range registry[before:] {
		if p.Name == "testhex" {
			prov = p
			break
		}
	}

	result := prov.Generate("", "anything-at-all-here-for-32chars")
	if len(result) != 32 {
		t.Fatalf("expected length 32, got %d", len(result))
	}
	if !strings.Contains(result, Sentinel) {
		t.Fatalf("expected sentinel %q in %s", Sentinel, result)
	}
	// Skip the sentinel window when checking hex charset — sentinel intentionally
	// displaces 4 hex chars so every placeholder is detectable via bytes.Contains.
	sIdx := strings.Index(result, Sentinel)
	checked := result[:sIdx] + result[sIdx+len(Sentinel):]
	for _, c := range checked {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isHex {
			t.Fatalf("expected hex char, got: %c in %s", c, result)
		}
	}
}

func TestRegisterDeclarative_ZeroLengthPreservesInput(t *testing.T) {
	before := len(registry)
	saved := append([]ProviderPattern(nil), registry...)
	register(ProviderPattern{
		Name:     "testflex",
		Prefixes: []string{"flex_"},
		KeyHints: nil,
		Length:   0,
		Charset:  "alphanumeric",
		Hosts:    nil,
	})
	defer func() { registry = saved }()

	var prov ProviderPattern
	for _, p := range registry[before:] {
		if p.Name == "testflex" {
			prov = p
			break
		}
	}

	input := "flex_shortvalue"
	result := prov.Generate("", input)
	if len(result) != len(input) {
		t.Fatalf("expected length %d (same as input), got %d", len(input), len(result))
	}
	if result[:5] != "flex_" {
		t.Fatalf("expected flex_ prefix, got: %s", result)
	}
}

// TestRegisterDeclarative_LongerPrefixWins asserts that when a provider is
// registered with overlapping declarative Prefixes, the LONGER prefix is
// the one extracted by Generate regardless of caller-provided order. This
// is the correctness invariant required to migrate anthropic (prefixes
// "sk-ant-api", "sk-ant-") to a declarative entry.
func TestRegisterDeclarative_LongerPrefixWins(t *testing.T) {
	before := len(registry)
	saved := append([]ProviderPattern(nil), registry...)
	register(ProviderPattern{
		Name:     "testprefixorder",
		Prefixes: []string{"sk-", "sk-ant-api", "sk-ant-"}, // shortest first; intentionally unordered
		KeyHints: nil,
		Length:   40,
		Charset:  "alphanumeric",
	})
	defer func() { registry = saved }()

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
	result := prov.Generate("", "sk-ant-api-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	if !strings.HasPrefix(result, "sk-ant-api") {
		t.Fatalf("expected longest prefix sk-ant-api to win, got: %s", result)
	}

	// Value has the medium prefix. Output must start with "sk-ant-", not
	// "sk-".
	result = prov.Generate("", "sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	if !strings.HasPrefix(result, "sk-ant-") {
		t.Fatalf("expected medium prefix sk-ant- to win, got: %s", result)
	}

	// Value has only the short prefix.
	result = prov.Generate("", "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	if !strings.HasPrefix(result, "sk-") {
		t.Fatalf("expected short prefix sk- to match, got: %s", result)
	}

	// Match must return true for all three prefix tiers (it iterates the
	// same sorted prefixes slice that Generate closes over).
	if !prov.Match("", "sk-ant-api-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") {
		t.Fatal("expected Match true on longest prefix")
	}
	if !prov.Match("", "sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") {
		t.Fatal("expected Match true on medium prefix")
	}
	if !prov.Match("", "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") {
		t.Fatal("expected Match true on short prefix")
	}
}

func TestRegistryIsolation(t *testing.T) {
	r := NewRegistry()
	r.Register(ProviderPattern{
		Name:     "only-test",
		Match:    func(name, value string) bool { return name == "ONLY" },
		Generate: func(_, _ string) string { return "fake-only" },
	})
	p, ok := r.Get("only-test")
	if !ok {
		t.Fatal("expected provider found in isolated registry")
	}
	if p.Name != "only-test" {
		t.Fatalf("unexpected name: %s", p.Name)
	}
	if _, ok := DefaultRegistry().Get("only-test"); ok {
		t.Fatal("isolated registry leaked into default")
	}
}

func TestDefaultRegistryMatchesPackageRegistry(t *testing.T) {
	def := DefaultRegistry()
	for _, p := range registry {
		got, ok := def.Get(p.Name)
		if !ok {
			t.Fatalf("DefaultRegistry missing %q", p.Name)
		}
		if got.Name != p.Name {
			t.Fatalf("name mismatch: %q vs %q", got.Name, p.Name)
		}
	}
}

// TestRegistry_StableWithinRegistration asserts that providers registered
// in a particular order are matched in that order — the registry no longer
// applies any priority-based reordering after the Phase 9 cuts.
func TestRegistry_StableWithinRegistration(t *testing.T) {
	saved := append([]ProviderPattern(nil), registry...)
	// Use a value that passes the Registry-level shape gate (>= 20 chars,
	// >= 6 distinct bytes) so the ordering assertion is not masked by the
	// pre-gate short-circuit.
	const sharedVal = "shared-xB9k4mP2nQ7vY3wR8"
	register(ProviderPattern{
		Name:     "first",
		Match:    func(name, value string) bool { return value == sharedVal },
		Generate: func(_, _ string) string { return "a" },
	})
	register(ProviderPattern{
		Name:     "second",
		Match:    func(name, value string) bool { return value == sharedVal },
		Generate: func(_, _ string) string { return "b" },
	})
	defer func() { registry = saved }()

	r := DefaultRegistry()
	p := r.Match("ANY", sharedVal)
	if p == nil {
		t.Fatal("expected a match")
	}
	if p.Name != "first" {
		t.Fatalf("expected first-registered to win, got %q", p.Name)
	}
}

// TestDefaultRegistry_ConcurrentSnapshotIsRaceFree runs many goroutines
// where some iterate a wrapper's patterns while others call DefaultRegistry()
// concurrently. The defensive-copy snapshot ensures each wrapper owns its
// own slice, so iteration on one wrapper never races with a register() or
// snapshot copy in another goroutine. Run under -race to verify.
func TestDefaultRegistry_ConcurrentSnapshotIsRaceFree(t *testing.T) {
	var wg sync.WaitGroup

	// Half the goroutines grab a wrapper once and iterate it many times.
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := DefaultRegistry()
			for k := 0; k < 50; k++ {
				_ = r.Match("ANY", "sk-proj-abcdefghijklmnopqrstuvwxyz")
				_ = r.All()
				_ = r.Names()
			}
		}()
	}

	// The other half keep calling DefaultRegistry (which re-enters the
	// snapshot mutex) while the first half iterate — the exact interleaving
	// that would race on the shared backing array without a defensive copy.
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 50; k++ {
				r := DefaultRegistry()
				_ = r.Match("ANY", "github_pat_xxxxxxxxxxxxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
			}
		}()
	}

	wg.Wait()
}
