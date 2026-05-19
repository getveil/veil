package placeholder

// AuthScheme describes how a provider's credential reaches an HTTP
// request. Veil v0.1.x mediates only the Bearer scheme literally via the
// proxy injector. Other schemes (OAuth exchange, mTLS, HMAC) require
// signers or exchanges that are not in scope for v0.1.x; secrets matching
// those schemes are recognized but not vaulted by `veil init`.
type AuthScheme int

const (
	// AuthUnknown is the zero value. Treated as not-eligible so a
	// provider that forgets to declare its scheme fails closed.
	AuthUnknown AuthScheme = iota
	AuthBearer
	AuthOAuthExchange
	AuthMTLS
	AuthHMAC
)

// VaultEligible reports whether `veil init` may move a credential
// matched by p out of .env and into the vault. True iff the scheme is
// Bearer AND the provider has a non-empty AllowedHosts set (so the
// injector knows where to fire). A nil p (charclass fallback) is never
// eligible.
func VaultEligible(p *ProviderPattern) bool {
	if p == nil {
		return false
	}
	if len(p.Hosts) == 0 {
		return false
	}
	return p.AuthScheme == AuthBearer
}

// AuthSchemeReason returns a one-line, user-facing label explaining
// why a credential of this scheme is not yet vault-eligible. Used by
// `veil init` to label entries in the "Not managed" summary section.
func AuthSchemeReason(s AuthScheme) string {
	switch s {
	case AuthOAuthExchange:
		return "OAuth exchange (roadmap)"
	case AuthMTLS:
		return "mTLS (architectural — out of scope)"
	case AuthHMAC:
		return "HMAC signing (roadmap)"
	case AuthBearer:
		return "" // eligible; reason not used
	default:
		return "unknown scheme"
	}
}
