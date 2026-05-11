package placeholder

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
)

var githubPrefixes = []string{"github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_"}

func init() {
	register(ProviderPattern{
		Name:     "github",
		Priority: PriorityHandwritten,
		Match: func(name, value string) bool {
			for _, p := range githubPrefixes {
				if strings.HasPrefix(value, p) {
					return true
				}
			}
			return strings.Contains(strings.ToUpper(name), "GITHUB")
		},
		Generate: func(_, value string) string {
			// Fine-grained PATs: github_pat_ + 22 alnum + _ + N alnum.
			// Sentinel lands in the 22-char middle block (after "github_pat_").
			if strings.HasPrefix(value, "github_pat_") {
				// Derive suffix length from the actual token to preserve total length.
				suffixLen := len(value) - 11 - 22 - 1 // len - prefix - mid - separator
				if suffixLen < 1 {
					suffixLen = 59 // default per GitHub spec
				}
				raw := "github_pat_" + randAlphanumeric(22) + "_" + randAlphanumeric(suffixLen)
				return sentinelize(raw, len("github_pat_"))
			}
			// Classic tokens: preserve prefix, fill remainder.
			prefix := ""
			for _, p := range githubPrefixes {
				if strings.HasPrefix(value, p) {
					prefix = p
					break
				}
			}
			rest := len(value) - len(prefix)
			return sentinelize(prefix+randAlphanumeric(rest), len(prefix))
		},
		Hosts: []string{"api.github.com", "uploads.github.com", "raw.githubusercontent.com", "ghcr.io"},
	})
}

// GenerateGitHubAppPrivateKey produces a fresh RSA 2048 keypair encoded as
// a PKCS#1 PEM string. Used as the placeholder for GitHub App credentials:
// the SDK loads this PEM and signs a JWT locally; the proxy detects the
// JWT via its `iss` claim and re-signs with the real vaulted PEM.
//
// The placeholder itself does not embed the placeholder.Sentinel — RSA PEM
// bytes cannot carry the sentinel without breaking PEM parsing. See
// THREAT_MODEL.md for the scoped detectLeak gap.
func GenerateGitHubAppPrivateKey() (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}
