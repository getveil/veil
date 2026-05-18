package runner

// BypassWarning is a startup-time hint about a tool on the host that would
// dodge Veil's HTTPS_PROXY. Tool is the bare binary name; Message is the
// rendered text shown to the user (without the leading "! " prefix —
// runner.Run adds that).
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

// bypassRules is the ordered list of (tool, platform, message) checks
// detectBypassClients walks. Order matters: a test asserts on it.
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

// detectBypassClients scans PATH (via the injected lookPath) for known
// bypass-prone tools on the current platform and returns one BypassWarning
// per match. The check is static — no process spawned, no daemon contacted —
// so a missing daemon or stopped Docker Desktop doesn't suppress the warning.
//
// Errors from lookPath are treated as "not present"; the subsystem is
// best-effort and a missing warning is much less harmful than a crash at
// session start.
func detectBypassClients(goos string, lookPath func(string) (string, error)) []BypassWarning {
	var out []BypassWarning
	for _, r := range bypassRules {
		if !r.goosAny && r.goos != goos {
			continue
		}
		if _, err := lookPath(r.tool); err != nil {
			continue
		}
		out = append(out, BypassWarning{Tool: r.tool, Message: r.message})
	}
	return out
}
