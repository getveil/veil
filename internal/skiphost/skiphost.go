// Package skiphost manages the persistent skip_hosts file for proxy host bypass.
package skiphost

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/getveil/veil/internal/vault"
)

const header = "# Managed by veil skip\n"

// ErrInvalidHost is returned when a host entry fails validation.
var ErrInvalidHost = errors.New("invalid skip host")

// Validate checks that host is safe to splice into NO_PROXY. It rejects entries
// that would either disable proxying entirely (the bare "*" wildcard, which Go's
// httpproxy and curl/requests treat as "bypass everything") or corrupt the
// comma-delimited NO_PROXY format (commas, whitespace, control chars). It also
// rejects empty and pure-punctuation entries. Legitimate NO_PROXY forms are
// permitted: hostnames, IPs, CIDR notation, leading-dot, and wildcard subdomain
// patterns like "*.internal.corp.com".
func Validate(host string) error {
	trimmed := strings.TrimSpace(host)
	if trimmed == "" {
		return fmt.Errorf("%w: empty entry", ErrInvalidHost)
	}
	if trimmed == "*" {
		return fmt.Errorf("%w: %q matches all hosts and would disable proxying", ErrInvalidHost, trimmed)
	}
	hasAlnum := false
	for _, r := range trimmed {
		switch {
		case r == ',':
			return fmt.Errorf("%w: %q contains a comma (NO_PROXY delimiter)", ErrInvalidHost, trimmed)
		case r <= ' ' || r == 0x7f:
			return fmt.Errorf("%w: %q contains whitespace or control characters", ErrInvalidHost, trimmed)
		case (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			hasAlnum = true
		}
	}
	if !hasAlnum {
		return fmt.Errorf("%w: %q has no alphanumeric characters", ErrInvalidHost, trimmed)
	}
	return nil
}

// Load reads the skip_hosts file and returns the list of hosts.
// Returns an empty slice if the file does not exist.
func Load(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []string{}, nil
		}
		return nil, err
	}
	return parse(string(data)), nil
}

// Save writes the host list to the skip_hosts file, overwriting any existing
// content. The write goes through vault.WriteFileNoFollow so a pre-planted
// symlink at path can't redirect the bytes elsewhere and pre-existing widened
// perms are tightened back to 0600 (H9).
func Save(path string, hosts []string) error {
	var b strings.Builder
	b.WriteString(header)
	for _, h := range hosts {
		b.WriteString(h)
		b.WriteByte('\n')
	}
	return vault.WriteFileNoFollow(path, []byte(b.String()), 0o600)
}

// Add appends a host to the skip_hosts file. Returns true if the host was added,
// false if it was already present (duplicate). Creates the file if it does not exist.
// Returns ErrInvalidHost if host fails validation.
func Add(path string, host string) (bool, error) {
	if err := Validate(host); err != nil {
		return false, err
	}
	host = strings.TrimSpace(host)
	hosts, err := Load(path)
	if err != nil {
		return false, err
	}
	for _, h := range hosts {
		if h == host {
			return false, nil
		}
	}
	hosts = append(hosts, host)
	return true, Save(path, hosts)
}

// Remove deletes a host from the skip_hosts file. Returns true if the host was found
// and removed, false if it was not present.
func Remove(path string, host string) (bool, error) {
	hosts, err := Load(path)
	if err != nil {
		return false, err
	}
	filtered := make([]string, 0, len(hosts))
	found := false
	for _, h := range hosts {
		if h == host {
			found = true
			continue
		}
		filtered = append(filtered, h)
	}
	if !found {
		return false, nil
	}
	return true, Save(path, filtered)
}

// parse extracts host entries from file content, skipping blank lines, comments,
// and entries that fail Validate. Silently filtering invalid entries is
// defense-in-depth: a hand-edited "*" in the file would otherwise disable all
// proxying when spliced into NO_PROXY at runtime.
func parse(content string) []string {
	var hosts []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if Validate(line) != nil {
			continue
		}
		hosts = append(hosts, line)
	}
	if hosts == nil {
		hosts = []string{}
	}
	return hosts
}
