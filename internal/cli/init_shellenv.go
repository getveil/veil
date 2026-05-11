package cli

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/getveil/veil/internal/cli/correlate"
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

// processShellEnv presents shell-exported secret-like candidates, prompts the
// user (interactive) or accepts-all (non-interactive), and vaults the
// selected entries. Correlates AWS triples before the "already in vault"
// filter so an existing aws-scheme credential named AWS_ACCESS_KEY_ID drops
// the whole would-be-duplicate shell group instead of leaking orphan
// siblings as redundant bearer credentials.
func processShellEnv(w io.Writer, in io.Reader, v *vault.Vault, candidates []scanner.EnvironCandidate, dryRun, interactive bool) (int, int, error) {
	// Drop empty-valued candidates first (placeholder.Generate rejects empty).
	// We do NOT drop vault-duplicate names here — that check moves
	// post-correlation below.
	nonEmpty := make([]correlate.Candidate, 0, len(candidates))
	for _, c := range candidates {
		if c.Value == "" {
			continue
		}
		nonEmpty = append(nonEmpty, correlate.Candidate{Key: c.Name, Value: c.Value})
	}
	if len(nonEmpty) == 0 {
		return 0, 0, nil
	}

	groups, remaining := correlate.DetectAll(nonEmpty)

	// Now drop groups whose name is already in the vault, and drop loose
	// candidates whose key is already in the vault. Applying the name
	// filter AFTER correlation ensures we drop the whole AWS group cleanly
	// when the .env phase has already vaulted it — no orphan siblings
	// leaking through as bearer credentials.
	filteredGroups := make([]correlate.Group, 0, len(groups))
	for _, g := range groups {
		if _, exists := v.Get(g.Name); exists {
			continue
		}
		filteredGroups = append(filteredGroups, g)
	}
	filteredRemaining := make([]correlate.Candidate, 0, len(remaining))
	for _, c := range remaining {
		if _, exists := v.Get(c.Key); exists {
			continue
		}
		filteredRemaining = append(filteredRemaining, c)
	}
	if len(filteredGroups) == 0 && len(filteredRemaining) == 0 {
		return 0, 0, nil
	}

	selectedGroups, selectedRemaining := selectShellEnvKeys(in, w, filteredGroups, filteredRemaining, interactive)
	if len(selectedGroups) == 0 && len(selectedRemaining) == 0 {
		return 0, 0, nil
	}

	seen := v.PlaceholderSet()
	var vaulted, scoped int

	for _, g := range selectedGroups {
		n, s, err := vaultShellAWSGroup(w, v, seen, g, dryRun)
		if err != nil {
			return vaulted, scoped, err
		}
		vaulted += n
		scoped += s
	}

	for _, c := range selectedRemaining {
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

// vaultShellAWSGroup writes one Scheme:"aws" credential for g. Unlike the
// .env flow there is no file to rewrite — the user's shell export remains
// unchanged; init only vaults.
func vaultShellAWSGroup(
	w io.Writer, v *vault.Vault, seen placeholder.Set,
	g correlate.Group, dryRun bool,
) (vaulted, scoped int, err error) {
	// Pass SecretKeyVar so the AWS provider's role-aware dispatch always picks
	// a secret-style placeholder, regardless of the value's leading bytes.
	secretPh, err := placeholder.Generate(g.AWS.SecretKeyVar, g.AWS.SecretKey, seen)
	if err != nil {
		return 0, 0, wrapErr(fmt.Sprintf("generating placeholder for %s", g.AWS.SecretKeyVar), err)
	}
	seen[secretPh] = struct{}{}

	akIDPh := generateAWSAccessKeyIDPlaceholder(g.AWS.AccessKeyID, seen)
	seen[akIDPh] = struct{}{}

	var sessPh string
	if g.AWS.SessionToken != "" {
		sessPh, err = placeholder.GenerateAWSSessionToken(g.AWS.SessionToken, seen)
		if err != nil {
			return 0, 0, wrapErr(fmt.Sprintf("generating placeholder for %s", g.AWS.SessionTokenVar), err)
		}
		seen[sessPh] = struct{}{}
	}

	cred := &vault.Credential{
		ID:                         vault.NewID(),
		Name:                       g.Name,
		Real:                       g.AWS.SecretKey,
		Placeholder:                secretPh,
		Source:                     "init",
		AllowedHosts:               []string{"*.amazonaws.com"},
		CreatedAt:                  time.Now(),
		Scheme:                     "aws",
		AWSAccessKeyID:             g.AWS.AccessKeyID,
		AWSAccessKeyIDPlaceholder:  akIDPh,
		AWSSessionToken:            g.AWS.SessionToken,
		AWSSessionTokenPlaceholder: sessPh,
	}
	if err := v.Add(cred); err != nil {
		if errors.Is(err, vault.ErrDuplicateCredential) {
			ui.Warnf(w, "duplicate key %q, skipping", g.Name)
			return 0, 0, nil
		}
		return 0, 0, wrapErr(fmt.Sprintf("vaulting %s", g.Name), err)
	}

	if dryRun {
		ui.Dimf(w, "  would vault (aws): %s (from shell)", g.Name)
		ui.Dimf(w, "    %-24s -> %s", g.AWS.AccessKeyIDVar, akIDPh)
		ui.Dimf(w, "    %-24s -> %s", g.AWS.SecretKeyVar, secretPh)
		if g.AWS.SessionToken != "" {
			ui.Dimf(w, "    %-24s -> %s", g.AWS.SessionTokenVar, sessPh)
		}
	}
	return 1, 1, nil
}

// selectShellEnvKeys returns the groups and bearer candidates the user chose
// to vault. In non-interactive mode everything is selected.
func selectShellEnvKeys(
	in io.Reader, w io.Writer,
	groups []correlate.Group, remaining []correlate.Candidate, interactive bool,
) (selectedGroups []correlate.Group, selectedRemaining []correlate.Candidate) {
	if !interactive {
		return groups, remaining
	}

	total := len(remaining)
	for _, g := range groups {
		total += len(g.Members)
	}
	header := fmt.Sprintf("\nDetected %d shell-exported %s", total, plural(total, "secret", "secrets"))
	switch len(groups) {
	case 0:
		header += ":"
	case 1:
		header += fmt.Sprintf(" (%d correlated as AWS):", len(groups[0].Members))
	default:
		header += fmt.Sprintf(" (%d AWS credentials):", len(groups))
	}
	_, _ = fmt.Fprintln(w, header)
	ui.Dim(w, "(these are in your current shell environment, not in any .env file)")

	var names []string
	for _, g := range groups {
		label := fmt.Sprintf("[aws] %s", g.Name)
		for i, m := range g.Members {
			if i == 0 {
				_, _ = fmt.Fprintf(w, "  %-7s %-32s %s\n", "[aws]", m.Key, ui.Muted.Sprint(redactValue(m.Value)))
			} else {
				_, _ = fmt.Fprintf(w, "  %-7s %-32s %s\n", "", m.Key, ui.Muted.Sprint(redactValue(m.Value)))
			}
		}
		names = append(names, label)
	}
	for _, c := range remaining {
		_, _ = fmt.Fprintf(w, "  %-7s %-32s %s\n", "", c.Key, ui.Muted.Sprint(redactValue(c.Value)))
		names = append(names, c.Key)
	}
	_, _ = fmt.Fprintln(w)

	switch promptYNS(in, w, "Vault all?") {
	case choiceYes:
		return groups, remaining
	case choiceNo:
		return nil, nil
	case choiceSelect:
		picked := make(map[string]bool)
		for _, n := range promptMultiSelect(in, w, names) {
			picked[n] = true
		}
		for _, g := range groups {
			if picked[fmt.Sprintf("[aws] %s", g.Name)] {
				selectedGroups = append(selectedGroups, g)
			}
		}
		for _, c := range remaining {
			if picked[c.Key] {
				selectedRemaining = append(selectedRemaining, c)
			}
		}
		return selectedGroups, selectedRemaining
	}
	return nil, nil
}
