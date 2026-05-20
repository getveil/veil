package runner

import (
	"fmt"
	"io"
	"strings"

	"github.com/getveil/veil/internal/placeholder"
	"github.com/getveil/veil/internal/scanner"
	"github.com/getveil/veil/internal/ui"
)

// scanUnvaultedSecretLikes returns the names of env vars in environ that look
// secret-like but are not in the vault and not on the user-provided allow
// set. Name matching against both vaultNames and allow is case-insensitive
// (to match the child-env stripping semantics).
//
// Two-stage filter:
//  1. scanner.IsObviouslyNotSecret skips POSIX / shell / system names
//     (PATH, PWD, OLDPWD, SSH_AUTH_SOCK, TMPDIR, _, etc.) that can never
//     plausibly be credentials. This keeps a normal ambient shell from
//     tripping the fail-closed check on things like PATH.
//  2. placeholder.IsSecretLike evaluates the remaining name/value pairs.
//
// Runs against os.Environ() at veil-run startup as the sole shell-env
// surface: init only scans .env files, so any secret-shaped name still
// living in the shell needs to be flagged here before launch.
//
// Phase 9 spec called for dropping the pre-filter in favor of a "simpler
// name-match", but doing so flags PWD/PATH/ANTHROPIC_BASE_URL on every
// `veil run` invocation in a normal terminal — a recurring startup-banner
// regression that conflicts with the explicit "don't fire warnings every
// session" UX bar. The pre-filter stays.
func scanUnvaultedSecretLikes(environ, vaultNames []string, allow map[string]struct{}) []string {
	vaulted := make(map[string]struct{}, len(vaultNames))
	for _, n := range vaultNames {
		if n == "" {
			continue
		}
		vaulted[strings.ToUpper(n)] = struct{}{}
	}

	allowUpper := make(map[string]struct{}, len(allow))
	for n := range allow {
		if n == "" {
			continue
		}
		allowUpper[strings.ToUpper(n)] = struct{}{}
	}

	out := make([]string, 0)
	for _, kv := range environ {
		key, value, ok := strings.Cut(kv, "=")
		if !ok || key == "" {
			continue
		}
		if scanner.IsObviouslyNotSecret(key) {
			continue
		}
		if _, v := vaulted[strings.ToUpper(key)]; v {
			continue
		}
		if _, a := allowUpper[strings.ToUpper(key)]; a {
			continue
		}
		if !placeholder.IsSecretLike(key, value) {
			continue
		}
		out = append(out, key)
	}
	return out
}

// printUnvaultedWarning emits a loud stderr warning listing env vars whose
// values look secret-like but are not in the vault. Format mirrors
// printStrippedEnvWarning so users see parallel structure.
func printUnvaultedWarning(w io.Writer, names []string) {
	_, _ = fmt.Fprintf(w, "  %s %d shell env %s look like secrets but are NOT in the vault:\n",
		ui.Warning.Sprint("!"), len(names), plural(len(names), "var", "vars"))
	for _, n := range names {
		_, _ = fmt.Fprintf(w, "      %s\n", ui.Warning.Sprint(n))
	}
	_, _ = fmt.Fprintf(w, "    %s\n",
		ui.Muted.Sprint("the agent will see their real values. use `veil add NAME` to vault each one,"))
	_, _ = fmt.Fprintf(w, "    %s\n",
		ui.Muted.Sprint("or pass --allow-env-secret NAME to confirm intentional pass-through."))
}

// plural is a local helper to avoid depending on the cli package.
func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return singular
	}
	return pluralForm
}
