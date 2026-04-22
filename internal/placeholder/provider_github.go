package placeholder

import "strings"

var githubPrefixes = []string{"github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_"}

func init() {
	register(ProviderPattern{
		Name: "github",
		Match: func(name, value string) bool {
			for _, p := range githubPrefixes {
				if strings.HasPrefix(value, p) {
					return true
				}
			}
			return strings.Contains(strings.ToUpper(name), "GITHUB")
		},
		Generate: func(value string) string {
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
