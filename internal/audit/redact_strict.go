//go:build !audit_debug

package audit

import "strings"

// redactURLPath strips any "?query" suffix from p, keeping only the path
// portion. Called at Record() time so even callers that pass raw URLs
// cannot leak query-string secrets into the audit DB.
func redactURLPath(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

// redactAgentCmd keeps only the first whitespace-separated token — typically
// argv[0]. Build with the `audit_debug` tag to log the full argv when
// diagnosing a specific audit problem.
func redactAgentCmd(cmd string) string {
	if i := strings.IndexAny(cmd, " \t"); i >= 0 {
		return cmd[:i]
	}
	return cmd
}
