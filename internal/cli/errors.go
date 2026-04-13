package cli

import (
	"os"

	"github.com/8enji/veil/internal/ui"
)

// cliError prints a styled error to stderr with an optional hint and returns
// an error for cobra's RunE to propagate as a non-zero exit code.
func cliError(msg string, hint string) error {
	return ui.FormatError(os.Stderr, msg, hint)
}
