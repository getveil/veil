//go:build darwin

package proxy

import (
	"errors"
	"fmt"
	"os/exec"
)

// systemCAPEM extracts system root CA certificates as PEM from the macOS
// keychains. It exports from both the system roots keychain and the admin
// keychain.
func systemCAPEM() ([]byte, error) {
	keychains := []string{
		"/System/Library/Keychains/SystemRootCertificates.keychain",
		"/Library/Keychains/System.keychain",
	}

	var combined []byte
	var errs []error
	for _, kc := range keychains {
		out, err := exec.Command("security", "export", "-t", "certs", "-p", "-k", kc).Output()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", kc, err))
			continue
		}
		combined = append(combined, out...)
	}

	if len(combined) == 0 {
		return nil, fmt.Errorf("no system CA certificates found: %w", errors.Join(errs...))
	}
	return combined, nil
}
