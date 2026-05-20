package placeholder

import (
	"strings"
)

var githubPrefixes = []string{"github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_"}

func init() {
	register(ProviderPattern{
		Name:          "github",
		VaultEligible: true,
		Hosts:         []string{"api.github.com", "uploads.github.com", "raw.githubusercontent.com", "ghcr.io"},
		Match: func(name, value string) bool {
			for _, p := range githubPrefixes {
				if strings.HasPrefix(value, p) {
					return true
				}
			}
			// Name-only fallback: catches custom/unprefixed tokens stored under
			// a GITHUB_* name. The credential-shape floor lives at
			// Registry.Match (passesValueShapeGate); short non-credential CI
			// metadata like GITHUB_REF_NAME=main is rejected there before
			// this matcher is consulted.
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
	})
}
