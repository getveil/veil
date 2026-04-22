package proxy

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/ui"
)

// BuildCABundle creates a combined PEM file containing the system CA
// certificates plus the provided Veil CA PEM. Returns the path to the
// bundle file. Call RemoveCABundle to clean up.
func BuildCABundle(veilCAPEM []byte) (string, error) {
	systemPEM, err := systemCAPEM()
	if err != nil {
		ui.Warnf(os.Stderr, "could not extract system CAs: %v (bundle will contain only Veil CA)", err)
		systemPEM = nil
	}

	combined := make([]byte, 0, len(systemPEM)+len(veilCAPEM)+1)
	if len(systemPEM) > 0 {
		combined = append(combined, systemPEM...)
		if combined[len(combined)-1] != '\n' {
			combined = append(combined, '\n')
		}
	}
	combined = append(combined, veilCAPEM...)

	bundlePath, err := bundleFilePath()
	if err != nil {
		return "", fmt.Errorf("%w: bundle file path: %w", ErrCABundle, err)
	}

	if err := config.EnsureDir(filepath.Dir(bundlePath), 0700); err != nil {
		return "", fmt.Errorf("%w: ensure bundle dir: %w", ErrCABundle, err)
	}

	if err := atomicWrite(bundlePath, combined, 0644); err != nil {
		return "", fmt.Errorf("%w: write ca bundle: %w", ErrCABundle, err)
	}

	return bundlePath, nil
}

// BuildCABundleIn writes the combined CA bundle into sessionDir and returns
// the full file path. Prefer this over BuildCABundle in new code; the latter
// is preserved for callers still using the shared location.
func BuildCABundleIn(sessionDir string, veilCAPEM []byte) (string, error) {
	systemPEM, err := systemCAPEM()
	if err != nil {
		ui.Warnf(os.Stderr, "could not extract system CAs: %v (bundle will contain only Veil CA)", err)
		systemPEM = nil
	}

	combined := make([]byte, 0, len(systemPEM)+len(veilCAPEM)+1)
	if len(systemPEM) > 0 {
		combined = append(combined, systemPEM...)
		if combined[len(combined)-1] != '\n' {
			combined = append(combined, '\n')
		}
	}
	combined = append(combined, veilCAPEM...)

	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		return "", fmt.Errorf("%w: ensure session dir: %w", ErrCABundle, err)
	}

	path := filepath.Join(sessionDir, "ca-bundle.pem")
	if err := atomicWrite(path, combined, 0o644); err != nil {
		return "", fmt.Errorf("%w: write bundle: %w", ErrCABundle, err)
	}
	return path, nil
}

// RemoveCABundle deletes the combined CA bundle file.
func RemoveCABundle(path string) {
	_ = os.Remove(path)
}

// bundleFilePath returns the path for the combined CA bundle, stored
// alongside the Veil CA files.
func bundleFilePath() (string, error) {
	dir, err := config.CADir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ca-bundle.pem"), nil
}
