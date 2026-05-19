package placeholder

import "testing"

func TestVaultEligible_Bearer(t *testing.T) {
	p := &ProviderPattern{Name: "test", AuthScheme: AuthBearer, Hosts: []string{"api.example.com"}}
	if !VaultEligible(p) {
		t.Fatalf("Bearer + hosts must be vault-eligible")
	}
}

func TestVaultEligible_OAuthExchange_Refused(t *testing.T) {
	p := &ProviderPattern{Name: "gcp_sa", AuthScheme: AuthOAuthExchange, Hosts: []string{"*.googleapis.com"}}
	if VaultEligible(p) {
		t.Fatalf("OAuth exchange must not be vault-eligible")
	}
}

func TestVaultEligible_Unknown_Refused(t *testing.T) {
	p := &ProviderPattern{Name: "x", AuthScheme: AuthUnknown, Hosts: []string{"x.com"}}
	if VaultEligible(p) {
		t.Fatalf("AuthUnknown must not be vault-eligible")
	}
}

func TestVaultEligible_MTLS_Refused(t *testing.T) {
	p := &ProviderPattern{Name: "test", AuthScheme: AuthMTLS, Hosts: []string{"api.example.com"}}
	if VaultEligible(p) {
		t.Fatalf("mTLS must not be vault-eligible")
	}
}

func TestVaultEligible_HMAC_Refused(t *testing.T) {
	p := &ProviderPattern{Name: "test", AuthScheme: AuthHMAC, Hosts: []string{"api.example.com"}}
	if VaultEligible(p) {
		t.Fatalf("HMAC must not be vault-eligible")
	}
}

func TestVaultEligible_EmptyHosts_Refused(t *testing.T) {
	p := &ProviderPattern{Name: "test", AuthScheme: AuthBearer, Hosts: nil}
	if VaultEligible(p) {
		t.Fatalf("provider with no AllowedHosts must not be vault-eligible (no host scope)")
	}
}

func TestVaultEligible_Nil_Refused(t *testing.T) {
	if VaultEligible(nil) {
		t.Fatalf("nil provider (charclass fallback path) must not be vault-eligible")
	}
}

func TestAuthSchemeReason_OAuthExchange(t *testing.T) {
	got := AuthSchemeReason(AuthOAuthExchange)
	want := "OAuth exchange (roadmap)"
	if got != want {
		t.Fatalf("AuthSchemeReason(AuthOAuthExchange) = %q, want %q", got, want)
	}
}
