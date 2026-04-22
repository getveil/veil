package proxy

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/ui"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
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

// javaTruststorePassword is the conventional JDK default password. The PKCS12
// lives in a per-session 0700 tempdir, so the password is a formality — any
// process that can read the file can already read any secret on the host.
const javaTruststorePassword = "changeit"

// BuildJavaTruststoreIn writes a PKCS12 truststore to sessionDir containing
// every CERTIFICATE block in bundlePEM as a trust anchor. Returns the full
// path to the written file.
//
// Unlike BuildCABundleIn, this function hard-fails on any error. A missing or
// malformed truststore breaks TLS for every JVM host — there is no useful
// degraded mode.
func BuildJavaTruststoreIn(sessionDir string, bundlePEM []byte) (string, error) {
	var certs []*x509.Certificate
	rest := bundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("%w: parse cert: %w", ErrCABundle, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return "", fmt.Errorf("%w: no CERTIFICATE blocks found in PEM bundle", ErrCABundle)
	}

	p12Data, err := pkcs12.Modern.WithRand(rand.Reader).EncodeTrustStore(certs, javaTruststorePassword)
	if err != nil {
		return "", fmt.Errorf("%w: encode PKCS12: %w", ErrCABundle, err)
	}

	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		return "", fmt.Errorf("%w: ensure session dir: %w", ErrCABundle, err)
	}

	path := filepath.Join(sessionDir, "java-truststore.p12")
	if err := atomicWrite(path, p12Data, 0o644); err != nil {
		return "", fmt.Errorf("%w: write PKCS12: %w", ErrCABundle, err)
	}
	return path, nil
}

// JavaToolOptionsFlags returns the JVM -D flags that point JAVA_TOOL_OPTIONS
// at a Veil per-session PKCS12 truststore. The password matches the one
// BuildJavaTruststoreIn used to encode the file — keeping both in this
// package ensures they stay in sync.
func JavaToolOptionsFlags(p12Path string) string {
	return fmt.Sprintf(
		"-Djavax.net.ssl.trustStore=%s -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=%s",
		p12Path,
		javaTruststorePassword,
	)
}
