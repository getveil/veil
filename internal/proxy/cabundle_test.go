package proxy

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestBuildCABundle(t *testing.T) {
	// Generate a CA to get realistic PEM bytes.
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	bundlePath, err := BuildCABundle(ca.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundle: %v", err)
	}
	defer func() { _ = os.Remove(bundlePath) }()

	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}

	// Bundle must contain the Veil CA.
	if !bytes.Contains(data, ca.CertPEM) {
		t.Error("bundle does not contain Veil CA PEM")
	}

	// Bundle must contain at least one other certificate (system CAs).
	// Count all CERTIFICATE blocks.
	rest := data
	count := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			count++
		}
	}
	if count < 2 {
		t.Fatalf("bundle has %d certificates, want at least 2 (system + veil)", count)
	}
}

func TestBuildCABundle_Cleanup(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	bundlePath, err := BuildCABundle(ca.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundle: %v", err)
	}

	// File should exist.
	if _, err := os.Stat(bundlePath); err != nil {
		t.Fatalf("bundle file does not exist: %v", err)
	}

	// Clean up and verify.
	RemoveCABundle(bundlePath)
	if _, err := os.Stat(bundlePath); !os.IsNotExist(err) {
		t.Fatalf("bundle file still exists after RemoveCABundle")
	}
}

func TestBuildJavaTruststoreIn(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	sessionDir := t.TempDir()
	bundlePath, err := BuildCABundleIn(sessionDir, ca.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundleIn: %v", err)
	}
	bundlePEM, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}

	p12Path, err := BuildJavaTruststoreIn(sessionDir, bundlePEM)
	if err != nil {
		t.Fatalf("BuildJavaTruststoreIn: %v", err)
	}

	// Must live inside sessionDir (not a shared global path).
	if !strings.HasPrefix(p12Path, sessionDir) {
		t.Fatalf("PKCS12 path %q is outside sessionDir %q", p12Path, sessionDir)
	}

	// File must exist and be non-empty.
	info, err := os.Stat(p12Path)
	if err != nil {
		t.Fatalf("stat PKCS12: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("PKCS12 file is empty")
	}

	// PKCS12 must decode and contain the same cert count as the PEM bundle.
	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		t.Fatalf("read PKCS12: %v", err)
	}
	decoded, err := pkcs12.DecodeTrustStore(p12Data, "changeit")
	if err != nil {
		t.Fatalf("DecodeTrustStore: %v", err)
	}

	pemCount := 0
	rest := bundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			pemCount++
		}
	}
	if len(decoded) != pemCount {
		t.Fatalf("PKCS12 has %d certs, want %d (match PEM bundle)", len(decoded), pemCount)
	}

	// Veil CA specifically must be present in the decoded set.
	veilBlock, _ := pem.Decode(ca.CertPEM)
	if veilBlock == nil {
		t.Fatal("could not decode Veil CA PEM")
	}
	veilCert, err := x509.ParseCertificate(veilBlock.Bytes)
	if err != nil {
		t.Fatalf("parse Veil CA: %v", err)
	}
	found := false
	for _, c := range decoded {
		if c.Equal(veilCert) {
			found = true
			break
		}
	}
	if !found {
		t.Error("Veil CA not found in decoded PKCS12 truststore")
	}
}

func TestBuildJavaTruststoreIn_CleanedByRemoveAll(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	sessionDir := t.TempDir()
	bundlePath, err := BuildCABundleIn(sessionDir, ca.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundleIn: %v", err)
	}
	bundlePEM, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	p12Path, err := BuildJavaTruststoreIn(sessionDir, bundlePEM)
	if err != nil {
		t.Fatalf("BuildJavaTruststoreIn: %v", err)
	}

	if err := os.RemoveAll(sessionDir); err != nil {
		t.Fatalf("RemoveAll sessionDir: %v", err)
	}
	if _, err := os.Stat(p12Path); !os.IsNotExist(err) {
		t.Fatalf("PKCS12 still exists after RemoveAll sessionDir: stat err=%v", err)
	}
}

func TestBuildJavaTruststoreIn_EmptyPEMReturnsError(t *testing.T) {
	sessionDir := t.TempDir()
	_, err := BuildJavaTruststoreIn(sessionDir, nil)
	if err == nil {
		t.Fatal("expected error for empty PEM input")
	}
}
