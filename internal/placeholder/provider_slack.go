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
			// Overwrite the first len(Sentinel) non-dash positions with Sentinel
			// so the sentinel lives in the randomized portion without clobbering
			// structural dashes.
			si := 0
			for i := 0; i < len(out) && si < len(Sentinel); i++ {
				if out[i] != '-' {
					out[i] = Sentinel[si]
					si++
				}
			}
			if si < len(Sentinel) {
				// Not enough non-dash positions — append sentinel defensively.
				return prefix + string(out) + Sentinel
			}
			return prefix + string(out)
		},
		Hosts: []string{"slack.com", "api.slack.com", "files.slack.com"},
	})
}
