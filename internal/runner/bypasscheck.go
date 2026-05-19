package runner

import "path/filepath"

// BypassWarning is a startup-time hint that the command about to be run dodges
// Veil's HTTPS_PROXY. Tool is the bare binary name; Message is the rendered
// text shown to the user (without the leading "! " prefix — runner.Run adds
// that).
type BypassWarning struct {
	Tool    string
	Message string
}

// bypassRule describes one entry in the static detection table.
type bypassRule struct {
	tool    string
	goosAny bool   // true means fire on any GOOS
	goos    string // ignored when goosAny is true
	message string
}

// bypassRules lists commands whose HTTPS traffic is known to dodge Veil's
// HTTPS_PROXY on at least one platform. The list is intentionally tight:
// firing only when the user is directly invoking one of these binaries keeps
// the startup banner quiet for every other command, since `docker` is on
// PATH on almost every Mac.
var bypassRules = []bypassRule{
	{
		tool:    "docker",
		goos:    "darwin",
		message: "`docker` on macOS: the daemon runs in a Linux VM (Docker Desktop, Colima, Lima, Rancher Desktop) that does not inherit HTTPS_PROXY. See docs/DOCKER.md for setup.",
	},
	{
		tool:    "dotnet",
		goos:    "darwin",
		message: "`dotnet` on macOS uses the native cert store and bypasses Veil. See docs/USE_CASES.md (Known gaps).",
	},
	{
		tool:    "sccache",
		goosAny: true,
		message: "`sccache` uses rustls-native-certs and bypasses Veil. See docs/USE_CASES.md (Known gaps).",
	},
}

// bypassWarningForCommand returns the bypass warning associated with command
// on goos, or nil if the command isn't a known bypass-prone tool on that
// platform. command may be a bare name or a full path — the directory part
// is stripped before matching, so callers can pass the resolved realpath.
//
// This warns only when the user is *directly* invoking a bypass tool through
// `veil run`. It does not catch the case where a long-lived agent or shell
// (e.g. `veil run -- claude`) later spawns docker from inside; that scenario
// is documented in docs/USE_CASES.md "Known gaps" and docs/DOCKER.md.
func bypassWarningForCommand(goos, command string) *BypassWarning {
	if command == "" {
		return nil
	}
	base := filepath.Base(command)
	for _, r := range bypassRules {
		if !r.goosAny && r.goos != goos {
			continue
		}
		if r.tool != base {
			continue
		}
		return &BypassWarning{Tool: r.tool, Message: r.message}
	}
	return nil
}
