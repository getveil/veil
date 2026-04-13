package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/8enji/veil/internal/ui"
)

const (
	escalateTimeout = 5 * time.Second
	killTimeout     = 10 * time.Second
)

// forwardSignals listens for termination-related signals and forwards them to
// the child process group (negative PID) so the entire tree receives them.
// If the child doesn't exit within escalateTimeout after SIGINT, SIGTERM is sent.
// If still alive after killTimeout, SIGKILL is sent.
func forwardSignals(ctx context.Context, cmd *exec.Cmd) {
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	defer signal.Stop(sigs)

	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-sigs:
			if cmd.Process == nil {
				continue
			}
			// Forward the signal to the process group.
			_ = syscall.Kill(-cmd.Process.Pid, sig.(syscall.Signal))

			// Start escalation for SIGINT.
			if sig == syscall.SIGINT {
				go escalate(ctx, cmd)
			}
			return
		}
	}
}

// escalate sends SIGTERM after escalateTimeout and SIGKILL after killTimeout
// if the child process is still running.
func escalate(ctx context.Context, cmd *exec.Cmd) {
	termTimer := time.NewTimer(escalateTimeout)
	defer termTimer.Stop()

	select {
	case <-ctx.Done():
		return
	case <-termTimer.C:
		if cmd.Process == nil {
			return
		}
		fmt.Fprintln(os.Stderr, ui.Muted.Sprint("Waiting for process to exit..."))
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}

	killTimer := time.NewTimer(killTimeout - escalateTimeout)
	defer killTimer.Stop()

	select {
	case <-ctx.Done():
		return
	case <-killTimer.C:
		if cmd.Process == nil {
			return
		}
		fmt.Fprintln(os.Stderr, ui.Muted.Sprint("Force-killed child process."))
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
