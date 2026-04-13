package config

import (
	"fmt"
	"strings"
)

// ScopingEntry represents a credential's name and allowed hosts for config generation.
type ScopingEntry struct {
	Name  string
	Hosts []string
}

// Generate produces the contents of a .veil/config.yaml file.
// Credentials are listed under the scoping key with their hosts.
// The ignore and skip_hosts sections are included as commented-out examples.
func Generate(entries []ScopingEntry) string {
	var b strings.Builder

	b.WriteString("# Veil project config\n")
	b.WriteString("# Docs: https://getveil.dev/docs/config\n")
	b.WriteString("\n")

	// Scoping section.
	if len(entries) == 0 {
		b.WriteString("# Credential scoping — map credential names to allowed hosts.\n")
		b.WriteString("# These override auto-detected hosts. Remove an entry to use auto-detection.\n")
		b.WriteString("# scoping:\n")
		b.WriteString("#   EXAMPLE_KEY:\n")
		b.WriteString("#     - api.example.com\n")
	} else {
		b.WriteString("# Credential scoping — map credential names to allowed hosts.\n")
		b.WriteString("# These override auto-detected hosts. Remove an entry to use auto-detection.\n")
		b.WriteString("scoping:\n")
		for _, entry := range entries {
			if len(entry.Hosts) == 0 {
				b.WriteString(fmt.Sprintf("  %s: []\n", entry.Name))
			} else {
				b.WriteString(fmt.Sprintf("  %s:\n", entry.Name))
				for _, host := range entry.Hosts {
					b.WriteString(fmt.Sprintf("    - %s\n", host))
				}
			}
		}
	}

	b.WriteString("\n")

	// Ignore section (commented out).
	b.WriteString("# Scanner ignore — glob patterns (relative to project root) to skip during init.\n")
	b.WriteString("# ignore:\n")
	b.WriteString("#   - \"test/fixtures/**\"\n")
	b.WriteString("#   - \"*.example\"\n")

	b.WriteString("\n")

	// SkipHosts section (commented out).
	b.WriteString("# Host skip list — hosts the proxy passes through without interception.\n")
	b.WriteString("# skip_hosts:\n")
	b.WriteString("#   - \"*.internal.company.com\"\n")

	return b.String()
}

// GenerateFromConfig produces config.yaml contents from a full ProjectConfig,
// preserving populated ignore and skip_hosts sections (used by veil sync).
func GenerateFromConfig(cfg *ProjectConfig) string {
	// Build scoping entries from the config map.
	entries := make([]ScopingEntry, 0, len(cfg.Scoping))
	for name, hosts := range cfg.Scoping {
		entries = append(entries, ScopingEntry{Name: name, Hosts: hosts})
	}

	var b strings.Builder

	b.WriteString("# Veil project config\n")
	b.WriteString("# Docs: https://getveil.dev/docs/config\n")
	b.WriteString("\n")

	// Scoping section.
	b.WriteString("# Credential scoping — map credential names to allowed hosts.\n")
	b.WriteString("# These override auto-detected hosts. Remove an entry to use auto-detection.\n")
	if len(entries) == 0 {
		b.WriteString("# scoping:\n")
		b.WriteString("#   EXAMPLE_KEY:\n")
		b.WriteString("#     - api.example.com\n")
	} else {
		b.WriteString("scoping:\n")
		for _, entry := range entries {
			if len(entry.Hosts) == 0 {
				b.WriteString(fmt.Sprintf("  %s: []\n", entry.Name))
			} else {
				b.WriteString(fmt.Sprintf("  %s:\n", entry.Name))
				for _, host := range entry.Hosts {
					b.WriteString(fmt.Sprintf("    - %s\n", host))
				}
			}
		}
	}

	b.WriteString("\n")

	// Ignore section — write populated if non-empty, commented example otherwise.
	b.WriteString("# Scanner ignore — glob patterns (relative to project root) to skip during init.\n")
	if len(cfg.Ignore) > 0 {
		b.WriteString("ignore:\n")
		for _, pattern := range cfg.Ignore {
			b.WriteString(fmt.Sprintf("  - \"%s\"\n", pattern))
		}
	} else {
		b.WriteString("# ignore:\n")
		b.WriteString("#   - \"test/fixtures/**\"\n")
		b.WriteString("#   - \"*.example\"\n")
	}

	b.WriteString("\n")

	// SkipHosts section — write populated if non-empty, commented example otherwise.
	b.WriteString("# Host skip list — hosts the proxy passes through without interception.\n")
	if len(cfg.SkipHosts) > 0 {
		b.WriteString("skip_hosts:\n")
		for _, host := range cfg.SkipHosts {
			b.WriteString(fmt.Sprintf("  - \"%s\"\n", host))
		}
	} else {
		b.WriteString("# skip_hosts:\n")
		b.WriteString("#   - \"*.internal.company.com\"\n")
	}

	return b.String()
}
