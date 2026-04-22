package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/8enji/veil/internal/cli"
	"github.com/spf13/cobra"
)

// TestRun_SuccessExitsZero verifies the successful path returns 0.
func TestRun_SuccessExitsZero(t *testing.T) {
	root := &cobra.Command{
		Use:           "fake",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
	got := run(context.Background(), root, []string{}, io.Discard, io.Discard)
	if got != 0 {
		t.Errorf("run on success = %d, want 0", got)
	}
}

// TestRun_SingleErrorPrint verifies the error is printed exactly once to
// stderr (no double-print from the old main.go Fprintln path).
func TestRun_SingleErrorPrint(t *testing.T) {
	var stderr bytes.Buffer
	root := &cobra.Command{
		Use:           "fake",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Simulate what real commands do: write styled error via
			// cliError/FormatError, then return the error to Cobra.
			return cli.FormatErrorForTest(cmd.ErrOrStderr(), "boom", "")
		},
	}
	root.SetOut(io.Discard)
	root.SetErr(&stderr)
	_ = run(context.Background(), root, []string{}, io.Discard, &stderr)

	s := stderr.String()
	// The word "error:" should appear exactly once.
	if n := strings.Count(s, "error:"); n != 1 {
		t.Errorf("expected exactly 1 'error:' in stderr, got %d: %q", n, s)
	}
}

// TestRun_PropagatesExitCode verifies that ExitCoder errors from commands
// produce the corresponding exit code.
func TestRun_PropagatesExitCode(t *testing.T) {
	sentinel := cli.ErrNotInitialized
	root := &cobra.Command{
		Use:           "fake",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.WrapExitError(sentinel, "project not initialized")
		},
	}
	got := run(context.Background(), root, []string{}, io.Discard, io.Discard)
	if got != cli.ExitNotInitialized {
		t.Errorf("run ExitNotInitialized = %d, want %d", got, cli.ExitNotInitialized)
	}
}

// TestRun_PassesContextForCancellation verifies that the ctx passed to run
// is propagated to commands via ExecuteContext and gets canceled when the
// parent ctx is canceled.
func TestRun_PassesContextForCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	started := make(chan struct{})
	done := make(chan error, 1)

	root := &cobra.Command{
		Use:           "fake",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			close(started)
			<-cmd.Context().Done()
			return errors.New("canceled")
		},
	}
	go func() {
		code := run(ctx, root, []string{}, io.Discard, io.Discard)
		if code == 0 {
			done <- errors.New("expected non-zero exit on cancel")
		} else {
			done <- nil
		}
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("command never started")
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after context cancel")
	}
}
