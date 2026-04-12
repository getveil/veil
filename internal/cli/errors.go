package cli

import "fmt"

// exitError returns a prefixed error suitable for CLI output.
func exitError(msg string) error {
	return fmt.Errorf("veil: %s", msg)
}
