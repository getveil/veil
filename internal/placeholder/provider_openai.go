package placeholder

import "strings"

func init() {
	register(ProviderPattern{
		Name: "openai",
		Match: func(name, value string) bool {
			if strings.HasPrefix(value, "sk-proj-") {
				return true
			}
			return strings.Contains(strings.ToUpper(name), "OPENAI")
		},
		Generate: func(value string) string {
			prefix := ""
			if strings.HasPrefix(value, "sk-proj-") {
				prefix = "sk-proj-"
			}
			rest := len(value) - len(prefix)
			return sentinelize(prefix+randAlphanumeric(rest), len(prefix))
		},
		Hosts: []string{"api.openai.com"},
	})
}
