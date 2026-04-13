package runner

import (
	"testing"
)

// TestForwardSignalsCompiles verifies that the signal forwarding function
// compiles correctly. Actual signal forwarding is tested via integration tests,
// as programmatic signal tests are inherently fragile.
func TestForwardSignalsCompiles(t *testing.T) {
	// The forwardSignals function is exercised by the integration tests in
	// runner_test.go. This test exists to ensure the function signature and
	// imports compile on all platforms.
	_ = forwardSignals
}

func TestEscalationTimings(t *testing.T) {
	// Verify constants are defined and reasonable.
	if escalateTimeout <= 0 {
		t.Error("escalateTimeout should be positive")
	}
	if killTimeout <= 0 {
		t.Error("killTimeout should be positive")
	}
	if killTimeout <= escalateTimeout {
		t.Error("killTimeout should be greater than escalateTimeout")
	}
}
