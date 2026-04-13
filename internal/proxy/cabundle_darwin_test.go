//go:build darwin

package proxy

import (
	"encoding/pem"
	"testing"
)

func TestSystemCAPEM_Darwin(t *testing.T) {
	data, err := systemCAPEM()
	if err != nil {
		t.Fatalf("systemCAPEM: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("systemCAPEM returned empty data")
	}

	// Verify at least one valid PEM CERTIFICATE block.
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block found in systemCAPEM output")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("first PEM block type = %q, want CERTIFICATE", block.Type)
	}
}
