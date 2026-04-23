package proxy

import "github.com/8enji/veil/internal/audit"

// Signer Location values emitted into audit records.
const (
	LocationAWSSigV4Resigned     = "aws_sigv4_resigned"
	LocationGitHubAppJWTResigned = "github_app_jwt_resigned"
	LocationSchemeUnmediated     = "scheme_unmediated"
	LocationSignerFailed         = "signer_failed"
)

// Signer error classes recorded in Injection.SignerError.
const (
	SignerErrUnknownAccessKeyID             = "unknown_access_key_id"
	SignerErrUnknownGitHubAppID             = "unknown_github_app_id"
	SignerErrUnexpectedSessionToken         = "unexpected_session_token"
	SignerErrMissingSessionToken            = "missing_session_token"
	SignerErrAuthorizationMalformed         = "authorization_malformed"
	SignerErrCanonicalRequestReconstruction = "canonical_request_reconstruction_failed"
	SignerErrRSASignFailed                  = "rsa_sign_failed"
	SignerErrJWTMalformed                   = "jwt_malformed"
)

// firstSignerFailure returns the first signer_failed injection or nil.
func firstSignerFailure(injections []audit.Injection) *audit.Injection {
	for i := range injections {
		if injections[i].Location == LocationSignerFailed {
			return &injections[i]
		}
	}
	return nil
}
