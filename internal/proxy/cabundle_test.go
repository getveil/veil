package proxy

import (
	"bytes"
	"encoding/pem"
	"os"
	"testing"
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
	defer os.Remove(bundlePath)

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
