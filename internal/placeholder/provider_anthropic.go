package placeholder

import "strings"

func init() {
	register(ProviderPattern{
		Name: "anthropic",
		Match: func(name, value string) bool {
			if strings.HasPrefix(value, "sk-ant-") {
				return true
			}
			return strings.Contains(strings.ToUpper(name), "ANTHROPIC")
		},
		Generate: func(value string) string {
			prefix := ""
			for _, p := range []string{"sk-ant-api", "sk-ant-"} {
				if strings.HasPrefix(value, p) {
					prefix = p
					break
				}
			}
			rest := len(value) - len(prefix)
			return sentinelize(prefix+randAlphanumeric(rest), len(prefix))
		},
		Hosts: []string{"api.anthropic.com"},
	})
}
