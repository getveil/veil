package placeholder

import "strings"

var githubPrefixes = []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}

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
			prefix := ""
			for _, p := range githubPrefixes {
				if strings.HasPrefix(value, p) {
					prefix = p
					break
				}
			}
			rest := len(value) - len(prefix)
			return prefix + randAlphanumeric(rest)
		},
	})
}
