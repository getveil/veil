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
