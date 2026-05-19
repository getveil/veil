package placeholder

import "testing"

func TestVaultEligible_Bearer(t *testing.T) {
	p := &ProviderPattern{Name: "test", AuthScheme: AuthBearer, Hosts: []string{"api.example.com"}}
	if !VaultEligible(p) {
		t.Fatalf("Bearer + hosts must be vault-eligible")
	}
}

func TestVaultEligible_Basic(t *testing.T) {
	p := &ProviderPattern{Name: "test", AuthScheme: AuthBasic, Hosts: []string{"registry.example.com"}}
	if !VaultEligible(p) {
		t.Fatalf("Basic + hosts must be vault-eligible")
	}
}

func TestVaultEligible_SigV4_Refused(t *testing.T) {
	p := &ProviderPattern{Name: "aws", AuthScheme: AuthSigV4, Hosts: []string{"*.amazonaws.com"}}
	if VaultEligible(p) {
		t.Fatalf("SigV4 must not be vault-eligible in v0.1.x")
	}
}

func TestVaultEligible_JWT_Refused(t *testing.T) {
	p := &ProviderPattern{Name: "github_app", AuthScheme: AuthJWT_RS256, Hosts: []string{"api.github.com"}}
	if VaultEligible(p) {
		t.Fatalf("JWT RS256 must not be vault-eligible in v0.1.x")
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

func TestAuthSchemeReason_Sigv4(t *testing.T) {
	got := AuthSchemeReason(AuthSigV4)
	want := "AWS SigV4 (roadmap)"
	if got != want {
		t.Fatalf("AuthSchemeReason(AuthSigV4) = %q, want %q", got, want)
	}
}
