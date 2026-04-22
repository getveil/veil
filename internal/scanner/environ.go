package scanner

import (
	"strings"

	"github.com/8enji/veil/internal/placeholder"
)

// EnvironCandidate is a shell-exported env var that looked secret-like.
type EnvironCandidate struct {
	Name  string
	Value string
}

// environDenylist is a set of env var names we consider *obviously* non-secret
// and therefore skip before running the secret-like heuristic. The goal is to
// reduce prompt noise during `veil init` shell-env capture; it is NOT a
// security boundary — any name not on this list is still evaluated by
// placeholder.IsSecretLike.
//
// Rules for additions:
//   - The name is ubiquitous in POSIX / common shells.
//   - Its value has no plausible reason to be a credential.
//   - Omission would produce confusing / noisy prompts.
//
// When in doubt, leave it off. False positives in the prompt are annoying but
// correctable by the user; false negatives here risk silently exempting a
// real secret from capture, which is the exact gap this feature closes.
var environDenylist = map[string]struct{}{
	// Identity / shell
	"HOME": {}, "USER": {}, "LOGNAME": {}, "SHELL": {}, "UID": {}, "EUID": {},
	// Paths
	"PATH": {}, "MANPATH": {}, "INFOPATH": {}, "LD_LIBRARY_PATH": {},
	"DYLD_LIBRARY_PATH": {}, "DYLD_FALLBACK_LIBRARY_PATH": {},
	// Working dir / temp
	"PWD": {}, "OLDPWD": {}, "TMPDIR": {}, "TMP": {}, "TEMP": {},
	// Locale
	"LANG": {}, "LC_ALL": {}, "LC_CTYPE": {}, "LC_MESSAGES": {},
	"LC_NUMERIC": {}, "LC_TIME": {}, "LC_COLLATE": {}, "LC_MONETARY": {},
	// Terminal
	"TERM": {}, "COLORTERM": {}, "TERM_PROGRAM": {}, "TERM_PROGRAM_VERSION": {},
	"TERM_SESSION_ID": {}, "ITERM_PROFILE": {}, "ITERM_SESSION_ID": {},
	// Display (desktop)
	"DISPLAY": {}, "WAYLAND_DISPLAY": {}, "XDG_RUNTIME_DIR": {},
	"XDG_SESSION_TYPE": {}, "XDG_SESSION_DESKTOP": {}, "XDG_CURRENT_DESKTOP": {},
	"XDG_CONFIG_HOME": {}, "XDG_DATA_HOME": {}, "XDG_CACHE_HOME": {},
	"DESKTOP_SESSION": {}, "GDMSESSION": {},
	// Editor / pager
	"EDITOR": {}, "VISUAL": {}, "PAGER": {}, "MANPAGER": {},
	// Language runtimes (paths/versions, not credentials)
	"GOPATH": {}, "GOROOT": {}, "GOCACHE": {}, "GOMODCACHE": {}, "GOBIN": {},
	"NODE_PATH": {}, "NVM_DIR": {}, "NVM_BIN": {}, "NVM_CD_FLAGS": {}, "NVM_INC": {},
	"PYENV_ROOT": {}, "PYENV_SHELL": {}, "PYENV_VERSION": {},
	"RBENV_ROOT": {}, "RBENV_SHELL": {}, "RBENV_VERSION": {},
	// Homebrew
	"HOMEBREW_PREFIX": {}, "HOMEBREW_CELLAR": {}, "HOMEBREW_REPOSITORY": {},
	"HOMEBREW_SHELLENV_PREFIX": {},
	// Veil's own env keys (see envkeys package)
	"VEIL_TEST_KEYSTORE": {}, "VEIL_MCP_CONFIG_PATH": {},
	// Proxy / CA vars — already handled by the runner, and would confuse the user.
	"HTTP_PROXY": {}, "HTTPS_PROXY": {}, "NO_PROXY": {},
	"NODE_EXTRA_CA_CERTS": {}, "SSL_CERT_FILE": {},
	"CURL_CA_BUNDLE": {}, "REQUESTS_CA_BUNDLE": {}, "HTTPLIB2_CA_CERTS": {},
	// Shell options
	"IFS": {}, "PS1": {}, "PS2": {}, "PROMPT_COMMAND": {}, "HISTFILE": {},
	"HISTSIZE": {}, "HISTFILESIZE": {}, "BASH_VERSION": {}, "ZSH_VERSION": {},
	"ZSH_NAME": {}, "SHLVL": {}, "_": {}, "OSTYPE": {}, "MACHTYPE": {},
	"HOSTTYPE": {}, "HOSTNAME": {},
	// SSH (paths/sockets, not credentials themselves)
	"SSH_AUTH_SOCK": {}, "SSH_AGENT_PID": {},
}

// IsObviouslyNotSecret reports whether name is on the denylist of POSIX /
// shell / system env-var names that can never plausibly be credentials.
// Both the init-time scan (scanner.ScanEnviron) and the runtime scan
// (runner.scanUnvaultedSecretLikes) use it as a pre-filter before the
// IsSecretLike heuristic, so users don't get warnings about PATH or PWD
// "looking like a secret."
//
// This is NOT a security boundary: absence from the denylist does not
// mean the name is a secret, only that IsSecretLike will get a chance
// to evaluate the value. Adding a name here silently exempts it from
// the heuristic everywhere, so additions should be limited to POSIX /
// shell / system names with no plausible credential role.
func IsObviouslyNotSecret(name string) bool {
	_, ok := environDenylist[name]
	return ok
}

// ScanEnviron returns the shell-exported env vars that look secret-like.
// Names for which IsObviouslyNotSecret returns true are skipped up-front
// as obvious non-secrets to avoid prompt noise. Remaining entries are
// evaluated by placeholder.IsSecretLike. If the same name appears more
// than once in environ, only the last occurrence is returned (matching
// the shell's "last assignment wins" semantics; os.Environ() normally
// yields unique names but we handle dupes defensively).
func ScanEnviron(environ []string) []EnvironCandidate {
	byName := make(map[string]string, len(environ))
	order := make([]string, 0, len(environ))
	for _, kv := range environ {
		key, value, ok := strings.Cut(kv, "=")
		if !ok || key == "" {
			continue
		}
		if IsObviouslyNotSecret(key) {
			continue
		}
		if _, seen := byName[key]; !seen {
			order = append(order, key)
		}
		byName[key] = value
	}

	out := make([]EnvironCandidate, 0, len(order))
	for _, name := range order {
		value := byName[name]
		if !placeholder.IsSecretLike(name, value) {
			continue
		}
		out = append(out, EnvironCandidate{Name: name, Value: value})
	}
	return out
}
