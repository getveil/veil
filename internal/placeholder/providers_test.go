package placeholder

import (
	"strings"
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
	t.Run("generate_preserves_dashes", func(t *testing.T) {
		value := "xoxb-123-456-abc789def"
		result := prov.Generate(value)
		if len(result) != len(value) {
			t.Fatalf("length mismatch: %d vs %d", len(result), len(value))
		}
		if !strings.HasPrefix(result, "xoxb-") {
			t.Fatalf("prefix not preserved: %s", result)
		}
		// Dashes at positions in remainder should be preserved.
		remainder := value[5:]
		resultRemainder := result[5:]
		for i, c := range remainder {
			if c == '-' && rune(resultRemainder[i]) != '-' {
				t.Fatalf("dash not preserved at position %d in remainder", i)
			}
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

func TestRegisterFormat_BasicMatch(t *testing.T) {
	before := len(registry)
	registerFormat(Format{
		Name:     "testprovider",
		Prefixes: []string{"tp_"},
		KeyHints: []string{"TESTPROV"},
		Length:   20,
		Charset:  "alphanumeric",
		Hosts:    []string{"api.testprovider.com"},
	})
	defer func() { registry = registry[:before] }()

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
	registerFormat(Format{
		Name:     "testhex",
		Prefixes: nil,
		KeyHints: []string{"TESTHEX"},
		Length:   32,
		Charset:  "hex",
		Hosts:    []string{"api.testhex.com"},
	})
	defer func() { registry = registry[:before] }()

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
	for _, c := range result {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isHex {
			t.Fatalf("expected hex char, got: %c in %s", c, result)
		}
	}
}

func TestRegisterFormat_ZeroLengthPreservesInput(t *testing.T) {
	before := len(registry)
	registerFormat(Format{
		Name:     "testflex",
		Prefixes: []string{"flex_"},
		KeyHints: nil,
		Length:   0,
		Charset:  "alphanumeric",
		Hosts:    nil,
	})
	defer func() { registry = registry[:before] }()

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
