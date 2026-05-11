package cli

import "github.com/getveil/veil/internal/placeholder"

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
	// Pass the canonical env-var name so the AWS provider picks an AKID-style
	// placeholder unconditionally — required for callers that hand us a value
	// whose role-vs-pattern relationship is asserted by the caller (here,
	// always an access key ID).
	for i := 0; i < 10; i++ {
		cand := p.Generate("AWS_ACCESS_KEY_ID", realAKID)
		if _, clash := existing[cand]; !clash {
			return cand
		}
	}
	// Fallback: shouldn't happen with 16-char random bodies.
	return p.Generate("AWS_ACCESS_KEY_ID", realAKID)
}
