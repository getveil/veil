package placeholder

import "strings"

var stripePrefixes = []string{
	"sk_live_", "sk_test_",
	"pk_live_", "pk_test_",
	"rk_live_", "rk_test_",
}

func init() {
	register(ProviderPattern{
		Name: "stripe",
		Match: func(name, value string) bool {
			for _, p := range stripePrefixes {
				if strings.HasPrefix(value, p) {
					return true
				}
			}
			return strings.Contains(strings.ToUpper(name), "STRIPE")
		},
		Generate: func(value string) string {
			prefix := ""
			for _, p := range stripePrefixes {
				if strings.HasPrefix(value, p) {
					prefix = p
					break
				}
			}
			rest := len(value) - len(prefix)
			return sentinelize(prefix+randAlphanumeric(rest), len(prefix))
		},
		Hosts: []string{"api.stripe.com", "files.stripe.com"},
	})
}
