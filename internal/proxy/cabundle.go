package proxy

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/ui"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
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

// newTruststorePassword returns a cryptographically random password safe to
// embed in a double-quoted JAVA_TOOL_OPTIONS segment: base64-url alphabet
// (A-Z, a-z, 0-9, -, _) with no padding, so it contains no whitespace, no
// double-quote, and no backslash. 24 random bytes yields a 32-char password
// with ~192 bits of entropy — overkill for a file the OS already gates with
// 0700/0600, but cheap to generate.
func newTruststorePassword() (string, error) {
	var buf [24]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// BuildJavaTruststoreIn writes a PKCS12 truststore to sessionDir containing
// every CERTIFICATE block in bundlePEM as a trust anchor. Returns the full
// path to the written file and the per-session random password used to
// encode it.
//
// The password is generated fresh on every call. The same password is what
// JavaToolOptionsFlags must receive — callers should thread both values
// through to the child environment together. The truststore lives in a
// 0700 session dir and is written 0600.
//
// Unlike BuildCABundleIn, this function hard-fails on any error. A missing or
// malformed truststore breaks TLS for every JVM host — there is no useful
// degraded mode.
func BuildJavaTruststoreIn(sessionDir string, bundlePEM []byte) (path, password string, err error) {
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
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return "", "", fmt.Errorf("%w: parse cert: %w", ErrCABundle, parseErr)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return "", "", fmt.Errorf("%w: no CERTIFICATE blocks found in PEM bundle", ErrCABundle)
	}

	password, err = newTruststorePassword()
	if err != nil {
		return "", "", fmt.Errorf("%w: generate password: %w", ErrCABundle, err)
	}

	p12Data, err := pkcs12.Modern.WithRand(rand.Reader).EncodeTrustStore(certs, password)
	if err != nil {
		return "", "", fmt.Errorf("%w: encode PKCS12: %w", ErrCABundle, err)
	}

	if err := config.EnsureDir(sessionDir, 0o700); err != nil {
		return "", "", fmt.Errorf("%w: ensure session dir: %w", ErrCABundle, err)
	}

	path = filepath.Join(sessionDir, "java-truststore.p12")
	if err := atomicWrite(path, p12Data, 0o600); err != nil {
		return "", "", fmt.Errorf("%w: write PKCS12: %w", ErrCABundle, err)
	}
	return path, password, nil
}

// JavaToolOptionsFlags returns the JVM -D flags that point JAVA_TOOL_OPTIONS
// at a Veil per-session PKCS12 truststore. The password must be the value
// BuildJavaTruststoreIn returned alongside the path; keeping them threaded
// together is the caller's responsibility.
//
// The path is double-quoted (via strconv.Quote) so a session dir containing
// whitespace — common on macOS under "~/Library/Application Support/..." —
// is parsed as a single argument by the JVM launcher, which splits
// JAVA_TOOL_OPTIONS on whitespace but respects "..." and '...' quoting. The
// password is double-quoted via the same path for symmetry, even though
// newTruststorePassword guarantees a whitespace-free, quote-free string.
func JavaToolOptionsFlags(p12Path, password string) string {
	return fmt.Sprintf(
		"-Djavax.net.ssl.trustStore=%s -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=%s",
		strconv.Quote(p12Path),
		strconv.Quote(password),
	)
}
