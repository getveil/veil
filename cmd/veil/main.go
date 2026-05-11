// Package main is the veil command-line entry point.
package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/8enji/veil/internal/cli"
	"github.com/8enji/veil/internal/ui"
	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := cli.NewRoot(version)
	os.Exit(run(ctx, root, os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the supplied root command under ctx and returns an exit code.
// Extracted from main() so tests can drive the full invocation path without
// calling os.Exit. The returned code is classified via cli.ExitCodeFor so
// scripts can distinguish common failure modes (not-initialized, vault
// locked, CA error, etc.).
//
// Veil command handlers print user-facing errors via ui.FormatError before
// returning, and SilenceErrors is set on the root so Cobra does not duplicate
// them. That leaves cobra-internal errors (mutually-exclusive flag groups,
// unknown subcommand, unknown flag) silently swallowed — they never reach a
// RunE. The cli.IsAlreadyPrinted check below covers that gap: only errors
// that did not pass through a Veil helper get a stderr message here.
func run(ctx context.Context, root *cobra.Command, args []string, stdout, stderr io.Writer) int {
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.ExecuteContext(ctx)
	if err != nil && !cli.IsAlreadyPrinted(err) {
		_ = ui.FormatError(stderr, err.Error(), "")
	}
	return cli.ExitCodeFor(err)
}
