package cli

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/8enji/veil/internal/ui"
)

func TestCliError_RedactsHomePathInMessage(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("cannot resolve $HOME")
	}
	ui.SetColor("never")

	var buf bytes.Buffer
	// cliError writes to os.Stderr, so we route through FormatError-backed
	// helper to verify the full path. Instead of capturing os.Stderr, we
	// call the underlying helper that cliError delegates to.
	err2 := formatCLIError(&buf, "opening vault: "+home+"/p/.veil: no such file", "")
	if err2 == nil {
		t.Fatal("expected error return")
	}
	got := buf.String()
	if strings.Contains(got, home) {
		t.Errorf("expected $HOME redacted from output, got: %q", got)
	}
	if !strings.Contains(got, "~/p/.veil") {
		t.Errorf("expected tilde-abbreviated path, got: %q", got)
	}
}

func TestExitCodeFor_DefaultsToGeneric(t *testing.T) {
	got := exitCodeFor(errors.New("boom"))
	if got != ExitGeneric {
		t.Errorf("exitCodeFor(generic) = %d, want %d", got, ExitGeneric)
	}
}

func TestExitCodeFor_NotInitialized(t *testing.T) {
	got := exitCodeFor(ErrNotInitialized)
	if got != ExitNotInitialized {
		t.Errorf("exitCodeFor(ErrNotInitialized) = %d, want %d", got, ExitNotInitialized)
	}
}

func TestExitCodeFor_AlreadyInitialized(t *testing.T) {
	got := exitCodeFor(ErrAlreadyInitialized)
	if got != ExitAlreadyInitialized {
		t.Errorf("exitCodeFor(ErrAlreadyInitialized) = %d, want %d", got, ExitAlreadyInitialized)
	}
}

func TestExitCodeFor_RespectsExitCoder(t *testing.T) {
	err := &exitError{code: 42, msg: "custom"}
	got := exitCodeFor(err)
	if got != 42 {
		t.Errorf("exitCodeFor(exitCoder) = %d, want 42", got)
	}
}

func TestExitCodeFor_Nil(t *testing.T) {
	if got := exitCodeFor(nil); got != 0 {
		t.Errorf("exitCodeFor(nil) = %d, want 0", got)
	}
}

func TestCliError_WrapsSentinel(t *testing.T) {
	// cliErrorWith should preserve the sentinel via errors.Is so exitCodeFor
	// can map it to the right exit code.
	e := cliErrorWith(ErrNotInitialized, "project not initialized", "Run veil init")
	if !errors.Is(e, ErrNotInitialized) {
		t.Errorf("expected errors.Is(e, ErrNotInitialized) to be true")
	}
	if exitCodeFor(e) != ExitNotInitialized {
		t.Errorf("expected exit code %d, got %d", ExitNotInitialized, exitCodeFor(e))
	}
}
