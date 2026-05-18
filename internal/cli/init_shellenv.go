package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
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

// processShellEnv scans os.Environ() for secret-like exports plus
// correlator-relevant pair candidates, then vaults the selected
// entries. Kept as a thin wrapper around processShellEnvWithPool so
// init.go callers can stay terse.
func processShellEnv(w io.Writer, in io.Reader, v *vault.Vault, candidates []scanner.EnvironCandidate, dryRun, interactive bool) (int, int, error) {
	pairCandidates := scanner.ScanEnvironForPairs(os.Environ())
	return processShellEnvWithPool(w, in, v, candidates, pairCandidates, dryRun, interactive)
}

// processShellEnvWithPool is the testable form: callers supply both the
// IsSecretLike-filtered candidates (for the loose-bearer path) AND the
// broader pair pool (for the correlator). Production code uses the
// processShellEnv wrapper.
func processShellEnvWithPool(w io.Writer, in io.Reader, v *vault.Vault, candidates []scanner.EnvironCandidate, pairCandidates []scanner.EnvironCandidate, dryRun, interactive bool) (int, int, error) {
	// Build the correlator pool from the BROADER set; non-secret-shaped
	// USER halves must be visible to basicCorrelator.
	allCands := make([]correlate.Candidate, 0, len(pairCandidates))
	for _, c := range pairCandidates {
		if c.Value == "" {
			continue
		}
		allCands = append(allCands, correlate.Candidate{Key: c.Name, Value: c.Value})
	}

	groups, remaining := correlate.DetectAll(allCands)

	// Filter loose-bearer candidates: must be in the IsSecretLike-filtered
	// set AND not consumed by a correlator AND not already vault-named.
	consumedByCorrelator := make(map[string]struct{}, len(allCands)-len(remaining))
	for _, c := range allCands {
		consumedByCorrelator[c.Key] = struct{}{}
	}
	for _, c := range remaining {
		delete(consumedByCorrelator, c.Key)
	}

	filteredRemaining := make([]correlate.Candidate, 0, len(candidates))
	for _, c := range candidates {
		if c.Value == "" {
			continue
		}
		if _, vaulted := v.Get(c.Name); vaulted {
			continue
		}
		if _, claimed := consumedByCorrelator[c.Name]; claimed {
			continue
		}
		filteredRemaining = append(filteredRemaining, correlate.Candidate{Key: c.Name, Value: c.Value})
	}

	// Drop groups whose canonical name is already in the vault.
	filteredGroups := make([]correlate.Group, 0, len(groups))
	for _, g := range groups {
		if _, exists := v.Get(g.Name); exists {
			continue
		}
		filteredGroups = append(filteredGroups, g)
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
		var n, s int
		var err error
		switch g.Scheme {
		case "aws":
			n, s, err = vaultShellAWSGroup(w, v, seen, g, dryRun)
		case "basic":
			n, s, err = vaultShellBasicGroup(w, v, seen, g, dryRun)
		}
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

// vaultShellBasicGroup writes one basic-scheme credential for g. Mirrors
// vaultShellAWSGroup: no file to rewrite (the shell exports are read
// once at init), only a vault entry is created.
func vaultShellBasicGroup(
	w io.Writer, v *vault.Vault, seen placeholder.Set,
	g correlate.Group, dryRun bool,
) (vaulted, scoped int, err error) {
	userPh, err := placeholder.Generate(g.Basic.UsernameVar, g.Basic.Username, seen)
	if err != nil {
		return 0, 0, wrapErr(fmt.Sprintf("generating placeholder for %s", g.Basic.UsernameVar), err)
	}
	seen[userPh] = struct{}{}
	passPh, err := placeholder.Generate(g.Basic.PasswordVar, g.Basic.Password, seen)
	if err != nil {
		return 0, 0, wrapErr(fmt.Sprintf("generating placeholder for %s", g.Basic.PasswordVar), err)
	}
	seen[passPh] = struct{}{}

	credHosts := placeholder.HostsForCredential(g.Basic.PasswordVar, g.Basic.Password)
	cred := &vault.Credential{
		ID:                  vault.NewID(),
		Name:                g.Name,
		Real:                g.Basic.Password,
		Placeholder:         passPh,
		Source:              "init",
		AllowedHosts:        credHosts,
		CreatedAt:           time.Now(),
		Username:            g.Basic.Username,
		UsernamePlaceholder: userPh,
	}
	if err := v.Add(cred); err != nil {
		if errors.Is(err, vault.ErrDuplicateCredential) {
			ui.Warnf(w, "duplicate key %q, skipping", g.Name)
			return 0, 0, nil
		}
		return 0, 0, wrapErr(fmt.Sprintf("vaulting %s", g.Name), err)
	}

	if dryRun {
		ui.Dimf(w, "  would vault (basic): %s (from shell)", g.Name)
		ui.Dimf(w, "    %-24s -> %s", g.Basic.UsernameVar, userPh)
		ui.Dimf(w, "    %-24s -> %s", g.Basic.PasswordVar, passPh)
	}
	scoped = 0
	if len(credHosts) > 0 {
		scoped = 1
	}
	return 1, scoped, nil
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
	awsCount, basicCount := 0, 0
	for _, g := range groups {
		switch g.Scheme {
		case "aws":
			awsCount++
		case "basic":
			basicCount++
		}
	}
	switch {
	case awsCount == 0 && basicCount == 0:
		header += ":"
	case awsCount > 0 && basicCount == 0:
		if awsCount == 1 {
			header += fmt.Sprintf(" (%d correlated as AWS):", len(groups[0].Members))
		} else {
			header += fmt.Sprintf(" (%d AWS credentials):", awsCount)
		}
	case awsCount == 0 && basicCount > 0:
		if basicCount == 1 {
			header += " (1 correlated as HTTP Basic):"
		} else {
			header += fmt.Sprintf(" (%d HTTP Basic credentials):", basicCount)
		}
	default:
		header += fmt.Sprintf(" (%d AWS, %d HTTP Basic):", awsCount, basicCount)
	}
	_, _ = fmt.Fprintln(w, header)
	ui.Dim(w, "(these are in your current shell environment, not in any .env file)")

	var names []string
	for _, g := range groups {
		var tag string
		switch g.Scheme {
		case "aws":
			tag = "[aws]"
		case "basic":
			tag = "[basic]"
		}
		label := fmt.Sprintf("%s %s", tag, g.Name)
		for i, m := range g.Members {
			if i == 0 {
				_, _ = fmt.Fprintf(w, "  %-7s %-32s %s\n", tag, m.Key, ui.Muted.Sprint(redactValue(m.Value)))
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
			var tag string
			switch g.Scheme {
			case "aws":
				tag = "[aws]"
			case "basic":
				tag = "[basic]"
			}
			if picked[fmt.Sprintf("%s %s", tag, g.Name)] {
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
