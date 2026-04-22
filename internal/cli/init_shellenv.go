package cli

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/8enji/veil/internal/placeholder"
	"github.com/8enji/veil/internal/scanner"
	"github.com/8enji/veil/internal/ui"
	"github.com/8enji/veil/internal/vault"
)

// processShellEnv presents shell-exported secret-like candidates, prompts the
// user (interactive) or accepts-all (non-interactive), and vaults the
// selected entries. Candidates whose name already exists in the vault are
// skipped silently — typically because they were already captured from a .env
// or MCP config earlier in the same init run. Returns (vaulted, scoped).
//
// `interactive` mirrors the convention used by processEnvFile / processMCPConfig:
// when false, all candidates are vaulted (matching the --yes / non-TTY path).
func processShellEnv(w io.Writer, in io.Reader, v *vault.Vault, candidates []scanner.EnvironCandidate, dryRun, interactive bool) (int, int, error) {
	// Filter out anything already in the vault (prior phase captured it) and
	// anything with an empty value (placeholder.Generate rejects empty, and
	// an empty export can't meaningfully be a secret even if the name matches
	// a secret-like pattern like USE_STAGING_OAUTH="").
	filtered := make([]scanner.EnvironCandidate, 0, len(candidates))
	for _, c := range candidates {
		if c.Value == "" {
			continue
		}
		if _, exists := v.Get(c.Name); exists {
			continue
		}
		filtered = append(filtered, c)
	}
	if len(filtered) == 0 {
		return 0, 0, nil
	}

	selected := selectShellEnvKeys(in, w, filtered, interactive)
	if len(selected) == 0 {
		return 0, 0, nil
	}

	seen := v.PlaceholderSet()
	var vaulted, scoped int
	for _, c := range filtered {
		if !selected[c.Name] {
			continue
		}

		ph, err := placeholder.Generate(c.Name, c.Value, seen)
		if err != nil {
			return vaulted, scoped, wrapErr(fmt.Sprintf("generating placeholder for %s", c.Name), err)
		}

		credHosts := placeholder.HostsForCredential(c.Name, c.Value)
		cred := &vault.Credential{
			ID:           vault.NewID(),
			Name:         c.Name,
			Real:         c.Value,
			Placeholder:  ph,
			Source:       "init",
			AllowedHosts: credHosts,
			CreatedAt:    time.Now(),
		}
		if err := v.Add(cred); err != nil {
			if errors.Is(err, vault.ErrDuplicateCredential) {
				ui.Warnf(w, "duplicate key %q, skipping", c.Name)
				continue
			}
			return vaulted, scoped, wrapErr(fmt.Sprintf("vaulting %s", c.Name), err)
		}
		seen[ph] = struct{}{}

		vaulted++
		if len(credHosts) > 0 {
			scoped++
		}

		if dryRun {
			ui.Dimf(w, "  would vault: %s -> %s (from shell)", c.Name, ph)
		}
	}
	return vaulted, scoped, nil
}

// selectShellEnvKeys returns the set of candidate names the user chose to
// vault. In non-interactive mode all names are selected.
func selectShellEnvKeys(in io.Reader, w io.Writer, candidates []scanner.EnvironCandidate, interactive bool) map[string]bool {
	selected := make(map[string]bool, len(candidates))
	if !interactive {
		for _, c := range candidates {
			selected[c.Name] = true
		}
		return selected
	}

	_, _ = fmt.Fprintf(w, "\nDetected %d shell-exported %s:\n",
		len(candidates), plural(len(candidates), "secret", "secrets"))
	ui.Dim(w, "(these are in your current shell environment, not in any .env file)")
	names := make([]string, len(candidates))
	for i, c := range candidates {
		_, _ = fmt.Fprintf(w, "  %-32s %s\n", c.Name, ui.Muted.Sprint(redactValue(c.Value)))
		names[i] = c.Name
	}
	_, _ = fmt.Fprintln(w)
	switch promptYNS(in, w, "Vault all?") {
	case choiceYes:
		for _, c := range candidates {
			selected[c.Name] = true
		}
	case choiceNo:
		return nil
	case choiceSelect:
		for _, name := range promptMultiSelect(in, w, names) {
			selected[name] = true
		}
	}
	return selected
}
