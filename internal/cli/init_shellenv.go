package cli

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/getveil/veil/internal/placeholder"
	"github.com/getveil/veil/internal/scanner"
	"github.com/getveil/veil/internal/ui"
	"github.com/getveil/veil/internal/vault"
)

// nonEmptyShellCandidates returns candidates whose Value is not empty.
// Empty-valued candidates can arise when a variable matches a secret-like
// name pattern but is exported with an empty value (e.g., `export API_KEY=""`),
// and they carry no secret material worth vaulting. Used by the init early-exit
// gate so it matches the behavior of processShellEnv's internal filter.
func nonEmptyShellCandidates(candidates []scanner.EnvironCandidate) []scanner.EnvironCandidate {
	out := candidates[:0:0]
	for _, c := range candidates {
		if c.Value == "" {
			continue
		}
		out = append(out, c)
	}
	return out
}

// processShellEnv scans os.Environ() for secret-like exports and vaults
// the selected entries. Kept as a thin wrapper around processShellEnvWithPool
// so init.go callers can stay terse.
func processShellEnv(w io.Writer, in io.Reader, v *vault.Vault, candidates []scanner.EnvironCandidate, dryRun, interactive bool) (int, int, error) {
	return processShellEnvWithPool(w, in, v, candidates, dryRun, interactive)
}

// processShellEnvWithPool is the testable form: callers supply the
// IsSecretLike-filtered candidates (the loose-bearer path). Production code
// uses the processShellEnv wrapper.
func processShellEnvWithPool(w io.Writer, in io.Reader, v *vault.Vault, candidates []scanner.EnvironCandidate, dryRun, interactive bool) (int, int, error) {
	type bearerCandidate struct {
		Key   string
		Value string
	}
	filtered := make([]bearerCandidate, 0, len(candidates))
	for _, c := range candidates {
		if c.Value == "" {
			continue
		}
		if _, vaulted := v.Get(c.Name); vaulted {
			continue
		}
		filtered = append(filtered, bearerCandidate{Key: c.Name, Value: c.Value})
	}
	if len(filtered) == 0 {
		return 0, 0, nil
	}

	if interactive {
		header := fmt.Sprintf("\nDetected %d shell-exported %s:", len(filtered), plural(len(filtered), "secret", "secrets"))
		_, _ = fmt.Fprintln(w, header)
		ui.Dim(w, "(these are in your current shell environment, not in any .env file)")
		names := make([]string, 0, len(filtered))
		for _, c := range filtered {
			_, _ = fmt.Fprintf(w, "  %-7s %-32s %s\n", "", c.Key, ui.Muted.Sprint(redactValue(c.Value)))
			names = append(names, c.Key)
		}
		_, _ = fmt.Fprintln(w)

		switch promptYNS(in, w, "Vault all?") {
		case choiceYes:
			// keep filtered as-is
		case choiceNo:
			return 0, 0, nil
		case choiceSelect:
			picked := make(map[string]bool)
			for _, n := range promptMultiSelect(in, w, names) {
				picked[n] = true
			}
			selected := filtered[:0:0]
			for _, c := range filtered {
				if picked[c.Key] {
					selected = append(selected, c)
				}
			}
			filtered = selected
		}
	}
	if len(filtered) == 0 {
		return 0, 0, nil
	}

	seen := v.PlaceholderSet()
	var vaulted, scoped int

	for _, c := range filtered {
		ph, err := placeholder.Generate(c.Key, c.Value, seen)
		if err != nil {
			return vaulted, scoped, wrapErr(fmt.Sprintf("generating placeholder for %s", c.Key), err)
		}

		credHosts := placeholder.HostsForCredential(c.Key, c.Value)
		cred := &vault.Credential{
			ID:           vault.NewID(),
			Name:         c.Key,
			Real:         c.Value,
			Placeholder:  ph,
			Source:       "init",
			AllowedHosts: credHosts,
			CreatedAt:    time.Now(),
		}
		if err := v.Add(cred); err != nil {
			if errors.Is(err, vault.ErrDuplicateCredential) {
				ui.Warnf(w, "duplicate key %q, skipping", c.Key)
				continue
			}
			return vaulted, scoped, wrapErr(fmt.Sprintf("vaulting %s", c.Key), err)
		}
		seen[ph] = struct{}{}

		vaulted++
		if len(credHosts) > 0 {
			scoped++
		}

		if dryRun {
			ui.Dimf(w, "  would vault: %s -> %s (from shell)", c.Key, ph)
		}
	}
	return vaulted, scoped, nil
}
