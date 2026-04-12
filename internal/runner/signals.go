package runner

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// forwardSignals listens for termination-related signals and forwards them to
// the child process group (negative PID) so the entire tree receives them.
func forwardSignals(ctx context.Context, cmd *exec.Cmd) {
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	defer signal.Stop(sigs)

	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-sigs:
			if cmd.Process != nil {
				// Send to process group (negative PID).
				_ = syscall.Kill(-cmd.Process.Pid, sig.(syscall.Signal))
			}
		}
	}
}
