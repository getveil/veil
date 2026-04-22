package runner

import (
	"fmt"
	"io"
	"strings"

	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/ui"
)

// scanUnvaultedSecretLikes returns the names of env vars in environ that look
// secret-like (per placeholder.IsSecretLike) but are not in the vault and
// not on the user-provided allow set. Name matching against both vaultNames
// and allow is case-insensitive (to match the child-env stripping semantics).
//
// Runs against os.Environ() at veil-run startup as a belt-and-suspenders
// check: init should have captured these already, but a user may have
// added a new export since init, or run veil in a shell that init never saw.
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
		ui.Muted.Sprint("the agent will see their real values. run `veil init --force` to capture them,"))
	_, _ = fmt.Fprintf(w, "    %s\n",
		ui.Muted.Sprint("or pass --allow-env-secret NAME (repeatable) to confirm pass-through."))
}

// plural is a local helper to avoid depending on the cli package.
func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return singular
	}
	return pluralForm
}
