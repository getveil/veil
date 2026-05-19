package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/getveil/veil/internal/audit"
	"github.com/getveil/veil/internal/proxy"
	"github.com/getveil/veil/internal/ui"
	"github.com/getveil/veil/internal/vault"
)

// Exit codes exposed to the shell. Stable across releases; scripts can rely
// on these to branch (e.g. `veil init || [[ $? -eq 4 ]] && echo already init`).
const (
	ExitSuccess            = 0
	ExitGeneric            = 1
	ExitUsage              = 2
	ExitNotInitialized     = 3
	ExitAlreadyInitialized = 4
	ExitVaultLocked        = 5
	ExitNotFound           = 6
	ExitCAError            = 7
	ExitProxyListen        = 8
	ExitCanceled           = 130 // SIGINT convention (128 + 2)
)

// Sentinel errors new to the CLI layer. They name CLI-level conditions so
// exit-code mapping can distinguish them from generic errors. These are
// NEW sentinels — they do not rename anything in audit/, vault/, or proxy/.
var (
	ErrNotInitialized     = errors.New("project not initialized")
	ErrAlreadyInitialized = errors.New("project already initialized")
	ErrNotFound           = errors.New("not found")
	ErrUsage              = errors.New("invalid usage")
	ErrCanceled           = errors.New("canceled")
)

// ExitCoder is optionally implemented by an error to carry a specific exit
// code. Wrapped errors also satisfy exitCodeFor via errors.As.
type ExitCoder interface {
	error
	ExitCode() int
}

// exitError is the internal carrier that pairs a message with an exit code
// and (optionally) a wrapped sentinel. Returned by cliErrorWith so Cobra's
// propagated err can be classified in main.go.
type exitError struct {
	code    int
	msg     string
	wrapped error
}

func (e *exitError) Error() string { return e.msg }
func (e *exitError) ExitCode() int { return e.code }
func (e *exitError) Unwrap() error { return e.wrapped }

// cliError prints a styled error to stderr with an optional hint and returns
// an error for cobra's RunE to propagate. Paths under $HOME in msg/hint are
// tilde-abbreviated so error output is safe to paste into issues and chat.
func cliError(msg string, hint string) error {
	return formatCLIError(os.Stderr, msg, hint)
}

// cliErrorf formats msg and delegates to cliError. Convenience for the
// common `cliError(fmt.Sprintf("doing X: %v", err), "")` pattern.
func cliErrorf(format string, args ...any) error {
	return cliError(fmt.Sprintf(format, args...), "")
}

// wrapErr prints "error: prefix: <cause>" on stderr and returns an error that
// wraps cause via %w — so callers can errors.Is against the underlying
// sentinel and exit-code mapping sees the full chain. If cause is nil, it
// falls back to cliError behavior. Use this instead of
// `cliError(fmt.Sprintf("prefix: %v", err), "")` whenever the cause is a
// classified error (vault/proxy/audit sentinel or CLI sentinel) so exit
// codes stay accurate.
func wrapErr(prefix string, cause error) error {
	if cause == nil {
		return cliError(prefix, "")
	}
	msg := fmt.Sprintf("%s: %s", prefix, cause.Error())
	redacted := ui.RedactPath(msg)
	_ = ui.FormatError(os.Stderr, redacted, "", cause)
	return &exitError{
		code:    exitCodeForSentinel(cause),
		msg:     redacted,
		wrapped: cause,
	}
}

// cliErrorWith prints a styled error like cliError but also wraps the
// supplied sentinel so exitCodeFor can map it to a meaningful exit code.
// The returned error is still the stable message for existing test assertions
// that match via strings.Contains.
func cliErrorWith(sentinel error, msg, hint string) error {
	_ = formatCLIError(os.Stderr, msg, hint)
	return &exitError{
		code:    exitCodeForSentinel(sentinel),
		msg:     ui.RedactPath(msg),
		wrapped: sentinel,
	}
}

// formatCLIError is cliError's writer-injectable core, used by tests.
// Returns an *exitError so cmd/veil/main.go can detect that the message has
// already been written and skip its fallback printer (which exists to surface
// cobra-internal errors like mutually-exclusive flag groups).
func formatCLIError(w io.Writer, msg, hint string) error {
	_ = ui.FormatError(w, ui.RedactPath(msg), ui.RedactPath(hint))
	return &exitError{code: ExitGeneric, msg: ui.RedactPath(msg)}
}

// IsAlreadyPrinted reports whether err was produced by a Veil error helper
// that has already written a styled message to stderr. Used by cmd/veil/main.go
// to avoid double-printing while still surfacing cobra-internal errors that
// SilenceErrors would otherwise swallow.
func IsAlreadyPrinted(err error) bool {
	if err == nil {
		return false
	}
	var ee *exitError
	return errors.As(err, &ee)
}

// FormatErrorForTest is exported for cross-package tests (cmd/veil) that need
// to simulate what commands return to Cobra. It mirrors cliError but writes
// to the supplied writer instead of os.Stderr.
func FormatErrorForTest(w io.Writer, msg, hint string) error {
	return formatCLIError(w, msg, hint)
}

// WrapExitError builds an error that carries a sentinel (for exit-code
// mapping) and a user-facing message. Exported for the main-package test
// that verifies exit codes propagate through run().
func WrapExitError(sentinel error, msg string) error {
	return &exitError{
		code:    exitCodeForSentinel(sentinel),
		msg:     ui.RedactPath(msg),
		wrapped: sentinel,
	}
}

// ExitCodeFor is exported for cmd/veil/main.go to map cobra RunE errors to
// exit codes.
func ExitCodeFor(err error) int { return exitCodeFor(err) }

// exitCodeFor classifies err into a shell exit code. Returns 0 for nil,
// respects an ExitCoder implementation, and falls back to sentinel-based
// mapping.
func exitCodeFor(err error) int {
	if err == nil {
		return ExitSuccess
	}
	var coder ExitCoder
	if errors.As(err, &coder) {
		return coder.ExitCode()
	}
	return exitCodeForSentinel(err)
}

// exitCodeForSentinel maps known sentinel errors (CLI, vault, proxy) to
// their shell exit code. Unknown errors return ExitGeneric.
func exitCodeForSentinel(err error) int {
	switch {
	case err == nil:
		return ExitSuccess
	case errors.Is(err, ErrNotInitialized):
		return ExitNotInitialized
	case errors.Is(err, ErrAlreadyInitialized):
		return ExitAlreadyInitialized
	case errors.Is(err, ErrNotFound):
		return ExitNotFound
	case errors.Is(err, ErrUsage):
		return ExitUsage
	case errors.Is(err, ErrCanceled):
		return ExitCanceled
	case errors.Is(err, vault.ErrOpen),
		errors.Is(err, vault.ErrMasterKey),
		errors.Is(err, vault.ErrCorrupt):
		return ExitVaultLocked
	case errors.Is(err, proxy.ErrCALoad),
		errors.Is(err, proxy.ErrCAGenerate),
		errors.Is(err, proxy.ErrCABundle):
		return ExitCAError
	case errors.Is(err, proxy.ErrListen):
		return ExitProxyListen
	case errors.Is(err, audit.ErrOpen):
		return ExitGeneric
	default:
		return ExitGeneric
	}
}
