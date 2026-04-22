package placeholder

import (
	"strings"
	"sync"
	"testing"
)

func TestProviderOpenAI(t *testing.T) {
	var prov ProviderPattern
	for _, p := range registry {
		if p.Name == "openai" {
			prov = p
			break
		}
	}
	if prov.Name == "" {
		t.Fatal("openai provider not registered")
	}

	t.Run("match_prefix", func(t *testing.T) {
		if !prov.Match("", "sk-proj-abc123") {
			t.Fatal("should match sk-proj- prefix")
		}
	})
	t.Run("match_name", func(t *testing.T) {
		if !prov.Match("OPENAI_API_KEY", "anything") {
			t.Fatal("should match OPENAI in name")
		}
	})
	t.Run("no_match", func(t *testing.T) {
		if prov.Match("OTHER_KEY", "some-value") {
			t.Fatal("should not match unrelated key/value")
		}
	})
	t.Run("generate_length", func(t *testing.T) {
		value := "sk-proj-abcdef123456"
		result := prov.Generate(value)
		if len(result) != len(value) {
			t.Fatalf("length mismatch: %d vs %d", len(result), len(value))
		}
	})
	t.Run("generate_prefix", func(t *testing.T) {
		result := prov.Generate("sk-proj-abcdef123456")
		if !strings.HasPrefix(result, "sk-proj-") {
			t.Fatalf("prefix not preserved: %s", result)
		}
	})
	t.Run("generate_different", func(t *testing.T) {
		a := prov.Generate("sk-proj-abcdef123456")
		b := prov.Generate("sk-proj-abcdef123456")
		if a == b {
			t.Fatal("expected different outputs on repeated calls")
		}
	})
}

func TestProviderAnthropic(t *testing.T) {
	var prov ProviderPattern
	for _, p := range registry {
		if p.Name == "anthropic" {
			prov = p
			break
		}
	}
	if prov.Name == "" {
		t.Fatal("anthropic provider not registered")
	}

	t.Run("match_prefix", func(t *testing.T) {
		if !prov.Match("", "sk-ant-api03-abc") {
			t.Fatal("should match sk-ant- prefix")
		}
	})
	t.Run("match_name", func(t *testing.T) {
		if !prov.Match("ANTHROPIC_API_KEY", "anything") {
			t.Fatal("should match ANTHROPIC in name")
		}
	})
	t.Run("no_match", func(t *testing.T) {
		if prov.Match("OTHER_KEY", "some-value") {
			t.Fatal("should not match unrelated key/value")
		}
	})
	t.Run("generate_preserves_sk-ant-api", func(t *testing.T) {
		value := "sk-ant-api03-abcdef123456"
		result := prov.Generate(value)
		if !strings.HasPrefix(result, "sk-ant-api") {
			t.Fatalf("expected sk-ant-api prefix, got: %s", result)
		}
		if len(result) != len(value) {
			t.Fatalf("length mismatch: %d vs %d", len(result), len(value))
		}
	})
	t.Run("generate_preserves_sk-ant-", func(t *testing.T) {
		value := "sk-ant-abcdef123456"
		result := prov.Generate(value)
		if !strings.HasPrefix(result, "sk-ant-") {
			t.Fatalf("expected sk-ant- prefix, got: %s", result)
		}
		if len(result) != len(value) {
			t.Fatalf("length mismatch: %d vs %d", len(result), len(value))
		}
	})
}

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

func TestProviderStripe(t *testing.T) {
	var prov ProviderPattern
	for _, p := range registry {
		if p.Name == "stripe" {
			prov = p
			break
		}
	}
	if prov.Name == "" {
		t.Fatal("stripe provider not registered")
	}

	for _, prefix := range []string{"sk_live_", "sk_test_", "pk_live_", "pk_test_", "rk_live_", "rk_test_"} {
		t.Run("match_"+prefix, func(t *testing.T) {
			if !prov.Match("", prefix+"abc123") {
				t.Fatalf("should match %s prefix", prefix)
			}
		})
		t.Run("generate_"+prefix, func(t *testing.T) {
			value := prefix + "abcdef123456abcdef"
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
		if !prov.Match("STRIPE_SECRET_KEY", "anything") {
			t.Fatal("should match STRIPE in name")
		}
	})
}

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
		// Rest should be uppercase alphanumeric.
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

func TestProviderSlack(t *testing.T) {
	var prov ProviderPattern
	for _, p := range registry {
		if p.Name == "slack" {
			prov = p
			break
		}
	}
	if prov.Name == "" {
		t.Fatal("slack provider not registered")
	}

	for _, prefix := range []string{"xoxb-", "xoxp-", "xoxs-", "xoxa-", "xoxr-"} {
		t.Run("match_"+prefix, func(t *testing.T) {
			if !prov.Match("", prefix+"123-456-abc") {
				t.Fatalf("should match %s prefix", prefix)
			}
		})
	}
	t.Run("match_name", func(t *testing.T) {
		if !prov.Match("SLACK_BOT_TOKEN", "anything") {
			t.Fatal("should match SLACK in name")
		}
	})
	t.Run("no_match", func(t *testing.T) {
		if prov.Match("OTHER", "value") {
			t.Fatal("should not match unrelated")
		}
	})
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
	t.Run("generate_different", func(t *testing.T) {
		value := "xoxb-123-456-abc789def"
		a := prov.Generate(value)
		b := prov.Generate(value)
		if a == b {
			t.Fatal("expected different outputs on repeated calls")
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

	// github_pat_ tokens have the structure: github_pat_ + 22 alnum + _ + 59 alnum
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

func TestRegisterFormat_BasicMatch(t *testing.T) {
	before := len(registry)
	saved := append([]ProviderPattern(nil), registry...)
	registerFormat(Format{
		Name:     "testprovider",
		Prefixes: []string{"tp_"},
		KeyHints: []string{"TESTPROV"},
		Length:   20,
		Charset:  "alphanumeric",
		Hosts:    []string{"api.testprovider.com"},
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

	result := prov.Generate("tp_originalvalue1234")
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

func TestRegisterFormat_HexCharset(t *testing.T) {
	before := len(registry)
	saved := append([]ProviderPattern(nil), registry...)
	registerFormat(Format{
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

	result := prov.Generate("anything-at-all-here-for-32chars")
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

func TestRegisterFormat_ZeroLengthPreservesInput(t *testing.T) {
	before := len(registry)
	saved := append([]ProviderPattern(nil), registry...)
	registerFormat(Format{
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
	result := prov.Generate(input)
	if len(result) != len(input) {
		t.Fatalf("expected length %d (same as input), got %d", len(input), len(result))
	}
	if result[:5] != "flex_" {
		t.Fatalf("expected flex_ prefix, got: %s", result)
	}
}

// TestRegisterFormat_LongerPrefixWins asserts that when a Format is registered
// with overlapping prefixes, the LONGER prefix is the one extracted by
// Generate regardless of caller-provided order. This is the correctness
// invariant required to migrate anthropic (prefixes "sk-ant-api", "sk-ant-")
// to a Format entry.
func TestRegisterFormat_LongerPrefixWins(t *testing.T) {
	before := len(registry)
	saved := append([]ProviderPattern(nil), registry...)
	registerFormat(Format{
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
		Generate: func(value string) string { return "fake-only" },
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

// TestPriority_HandwrittenBeforeFormat asserts that a hand-written provider
// (PriorityHandwritten) is matched before a Format provider (PriorityFormat)
// when both would match the same input, regardless of init-order / filename.
func TestPriority_HandwrittenBeforeFormat(t *testing.T) {
	saved := append([]ProviderPattern(nil), registry...)
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
	defer func() { registry = saved }()

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
	saved := append([]ProviderPattern(nil), registry...)
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
	defer func() { registry = saved }()

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

// TestDefaultRegistry_ConcurrentSortIsRaceFree runs many goroutines where
// some iterate a wrapper's patterns while others call DefaultRegistry()
// concurrently (which acquires the sort mutex). This is a regression test for
// the data race pattern where a goroutine holding a wrapper iterates the
// shared backing array while another goroutine inside DefaultRegistry() is
// calling sort.SliceStable on the same array. The defensive-copy snapshot in
// DefaultRegistry ensures each wrapper owns its own slice.
//
// Run under -race to verify. Without the defensive copy, -race would report
// a DATA RACE between the iteration (Match/All/Names) and the concurrent
// sort inside another goroutine's DefaultRegistry() call.
func TestDefaultRegistry_ConcurrentSortIsRaceFree(t *testing.T) {
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

	// The other half keep calling DefaultRegistry (which re-enters the sort
	// mutex) while the first half iterate — the exact interleaving that would
	// race on the shared backing array without a defensive copy.
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
