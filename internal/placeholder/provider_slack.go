package placeholder

import "strings"

var slackPrefixes = []string{"xoxb-", "xoxp-", "xoxs-", "xoxa-", "xoxr-"}

func init() {
	register(ProviderPattern{
		Name: "slack",
		Match: func(name, value string) bool {
			for _, p := range slackPrefixes {
				if strings.HasPrefix(value, p) {
					return true
				}
			}
			return strings.Contains(strings.ToUpper(name), "SLACK")
		},
		Generate: func(value string) string {
			prefix := ""
			for _, p := range slackPrefixes {
				if strings.HasPrefix(value, p) {
					prefix = p
					break
				}
			}
			// Preserve '-' separators at their original positions in the remainder.
			remainder := value[len(prefix):]
			out := make([]byte, len(remainder))
			// Count non-dash characters to generate random bytes in one batch.
			nonDash := 0
			for i := 0; i < len(remainder); i++ {
				if remainder[i] != '-' {
					nonDash++
				}
			}
			randChars := randAlphanumeric(nonDash)
			ri := 0
			for i := 0; i < len(remainder); i++ {
				if remainder[i] == '-' {
					out[i] = '-'
				} else {
					out[i] = randChars[ri]
					ri++
				}
			}
			return prefix + string(out)
		},
		Hosts: []string{"slack.com", "api.slack.com", "files.slack.com"},
	})
}
