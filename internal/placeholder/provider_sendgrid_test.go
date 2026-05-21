package placeholder

import (
	"strings"
	"testing"
)

func TestProviderSendGrid(t *testing.T) {
	prov := mustProvider(t, "sendgrid")

	t.Run("match_prefix", func(t *testing.T) {
		if !prov.Match("", "SG.abc123def456ghijklmnopqr.abcdefghijklmnopqrstuvwxyz01234567890ABCDEFG") {
			t.Fatal("should match SG. prefix")
		}
	})

	t.Run("no_match_name_only", func(t *testing.T) {
		// Name-only matching was removed to prevent FPs like
		// SENDGRID_FROM_EMAIL=team@example.somewhere.com being vaulted.
		// SendGrid API keys always start with "SG." — prefix is sufficient.
		if prov.Match("SENDGRID_API_KEY", "abcdef0123456789abcdef0123456789abcdef01") {
			t.Fatal("should not match on name alone without SG. prefix")
		}
	})

	t.Run("no_match", func(t *testing.T) {
		if prov.Match("OTHER_KEY", "some-value") {
			t.Fatal("should not match unrelated key/value")
		}
	})

	t.Run("generate_structure", func(t *testing.T) {
		value := "SG.abc123def456ghijklmnopqr.abcdefghijklmnopqrstuvwxyz01234567890ABCDEFG"
		result := prov.Generate("", value)

		if !strings.HasPrefix(result, "SG.") {
			t.Fatalf("expected SG. prefix, got: %s", result)
		}

		parts := strings.Split(result, ".")
		if len(parts) != 3 {
			t.Fatalf("expected 3 dot-separated parts, got %d: %s", len(parts), result)
		}

		if parts[0] != "SG" {
			t.Fatalf("expected first part 'SG', got: %s", parts[0])
		}

		if len(parts[1]) != 22 {
			t.Fatalf("expected second part 22 chars, got %d: %s", len(parts[1]), parts[1])
		}

		if len(parts[2]) != 43 {
			t.Fatalf("expected third part 43 chars, got %d: %s", len(parts[2]), parts[2])
		}
	})

	t.Run("generate_different", func(t *testing.T) {
		value := "SG.abc123def456ghijklmnopqr.abcdefghijklmnopqrstuvwxyz01234567890ABCDEFG"
		a := prov.Generate("", value)
		b := prov.Generate("", value)
		if a == b {
			t.Fatal("expected different outputs")
		}
	})

	t.Run("hosts", func(t *testing.T) {
		if len(prov.Hosts) != 1 || prov.Hosts[0] != "api.sendgrid.com" {
			t.Fatalf("unexpected hosts: %v", prov.Hosts)
		}
	})
}

func TestSendgridNameMatchGatedAtRegistry(t *testing.T) {
	reg := DefaultRegistry()
	cases := []struct{ name, value string }{
		{"SENDGRID_FROM_EMAIL", "foo@bar.com"},
		{"SENDGRID_REGION", "us"},
		// Long credential-shaped values without SG. prefix are also rejected
		// now that the name-hint path is removed.
		{"SENDGRID_FROM_EMAIL", "team@example.somewhere.com"},
		{"SENDGRID_API_KEY", "abcdef0123456789abcdef0123456789abcdef01"},
	}
	for _, c := range cases {
		if p := reg.Match(c.name, c.value); p != nil {
			t.Errorf("Registry.Match should not match SendGrid for %s=%q; got %s", c.name, c.value, p.Name)
		}
	}
}

func TestProviderSendgrid_IsVaultEligible(t *testing.T) {
	p, ok := DefaultRegistry().Get("sendgrid")
	if !ok {
		t.Fatal("sendgrid provider not registered")
	}
	if !p.VaultEligible {
		t.Fatal("sendgrid provider must declare VaultEligible: true")
	}
}
