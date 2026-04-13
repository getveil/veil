package config

import "sort"

// SyncResult holds the outcome of a config sync operation.
type SyncResult struct {
	Config  *ProjectConfig
	Added   []string
	Removed []string
}

// Sync reconciles a ProjectConfig's scoping section with the current vault state.
// It adds entries for credentials that exist in the vault but not in the config,
// removes entries for credentials that no longer exist in the vault, and preserves
// user-customized host lists for existing entries. Ignore and SkipHosts are left
// untouched.
func Sync(existing *ProjectConfig, vaultEntries []ScopingEntry) SyncResult {
	// Build a set of vault credential names.
	vaultSet := make(map[string][]string, len(vaultEntries))
	for _, entry := range vaultEntries {
		vaultSet[entry.Name] = entry.Hosts
	}

	newScoping := make(map[string][]string, len(vaultEntries))
	var added, removed []string

	// Preserve existing entries that are still in the vault.
	for name, hosts := range existing.Scoping {
		if _, inVault := vaultSet[name]; inVault {
			newScoping[name] = hosts // preserve user's hosts
		} else {
			removed = append(removed, name)
		}
	}

	// Add new entries from vault that aren't in existing config.
	for _, entry := range vaultEntries {
		if _, exists := existing.Scoping[entry.Name]; !exists {
			newScoping[entry.Name] = entry.Hosts
			added = append(added, entry.Name)
		}
	}

	sort.Strings(added)
	sort.Strings(removed)

	return SyncResult{
		Config: &ProjectConfig{
			Scoping:   newScoping,
			Ignore:    existing.Ignore,
			SkipHosts: existing.SkipHosts,
		},
		Added:   added,
		Removed: removed,
	}
}
