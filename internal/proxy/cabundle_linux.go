//go:build linux

package proxy

import (
	"fmt"
	"os"
)

// linuxCAPaths lists well-known CA bundle paths across Linux distributions.
var linuxCAPaths = []string{
	"/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Alpine
	"/etc/pki/tls/certs/ca-bundle.crt",   // RHEL, Fedora, CentOS
	"/etc/ssl/ca-bundle.pem",             // openSUSE
}

// systemCAPEM reads the system CA certificate bundle from the first
// well-known path that exists.
func systemCAPEM() ([]byte, error) {
	// Paths are distro-exclusive; the first match is the complete system bundle.
	for _, path := range linuxCAPaths {
		data, err := os.ReadFile(path)
		if err == nil && len(data) > 0 {
			return data, nil
		}
	}
	return nil, fmt.Errorf("no system CA bundle found (tried: %v)", linuxCAPaths)
}
