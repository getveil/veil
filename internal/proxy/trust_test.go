package proxy

import (
	"testing"
)

func TestIsTrusted_NotInstalled(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	// A freshly generated CA should not be in the system trust store.
	if IsTrusted(ca) {
		t.Error("freshly generated CA should not be trusted by the system")
	}
}
