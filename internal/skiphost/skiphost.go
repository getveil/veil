// Package skiphost manages the persistent skip_hosts file for proxy host bypass.
package skiphost

import (
	"errors"
	"os"
	"strings"
)

const header = "# Managed by veil skip\n"

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

// Save writes the host list to the skip_hosts file, overwriting any existing content.
func Save(path string, hosts []string) error {
	var b strings.Builder
	b.WriteString(header)
	for _, h := range hosts {
		b.WriteString(h)
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0600)
}

// Add appends a host to the skip_hosts file. Returns true if the host was added,
// false if it was already present (duplicate). Creates the file if it does not exist.
func Add(path string, host string) (bool, error) {
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

// parse extracts host entries from file content, skipping blank lines and comments.
func parse(content string) []string {
	var hosts []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hosts = append(hosts, line)
	}
	if hosts == nil {
		hosts = []string{}
	}
	return hosts
}
