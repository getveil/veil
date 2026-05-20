package proxy

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/ui"
)

// BuildCABundle creates a combined PEM file containing the system CA
// certificates plus the provided Veil CA PEM. Returns the path to the
// bundle file. Call RemoveCABundle to clean up.
func BuildCABundle(veilCAPEM []byte) (string, error) {
	dir, err := config.CADir()
	if err != nil {
		return "", fmt.Errorf("%w: bundle file path: %w", ErrCABundle, err)
	}
	return writeCABundle(dir, veilCAPEM)
}

// BuildCABundleIn writes the combined CA bundle into sessionDir and returns
// the full file path. Prefer this over BuildCABundle in new code; the latter
// is preserved for callers still using the shared location.
func BuildCABundleIn(sessionDir string, veilCAPEM []byte) (string, error) {
	return writeCABundle(sessionDir, veilCAPEM)
}

// RemoveCABundle deletes the combined CA bundle file.
func RemoveCABundle(path string) {
	_ = os.Remove(path)
}

// writeCABundle merges system CA PEM with veilCAPEM and writes the result to
// dir/ca-bundle.pem. The directory is created 0700 if missing; the bundle
// file is written 0644 (atomically) because clients/tools loading the bundle
// must be able to read it.
func writeCABundle(dir string, veilCAPEM []byte) (string, error) {
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

	if err := config.EnsureDir(dir, 0o700); err != nil {
		return "", fmt.Errorf("%w: ensure bundle dir: %w", ErrCABundle, err)
	}

	path := filepath.Join(dir, "ca-bundle.pem")
	if err := atomicWrite(path, combined, 0o644); err != nil {
		return "", fmt.Errorf("%w: write ca bundle: %w", ErrCABundle, err)
	}
	return path, nil
}
