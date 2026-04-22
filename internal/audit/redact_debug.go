//go:build audit_debug

package audit

// Debug build: record URLPath and AgentCmd verbatim. Enable with
// `-tags audit_debug` when diagnosing a specific audit problem.
//
// Not for production binaries — URLPath retains raw query strings and
// AgentCmd retains the raw child argv, which may contain tokens the user
// typed on the command line.

func redactURLPath(p string) string    { return p }
func redactAgentCmd(cmd string) string { return cmd }
