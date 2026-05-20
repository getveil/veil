package runner

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/getveil/veil/internal/ui"
)

// escalateTimeout and killTimeout are var (not const) so integration tests
// can shorten them. Production callers must not mutate them at runtime.
var (
	escalateTimeout = 5 * time.Second
	killTimeout     = 10 * time.Second
)

// forwardSignals listens for termination-related signals and forwards them to
// the child process group (negative PID) so the entire tree receives them.
// If the child doesn't exit within escalateTimeout after a SIGINT or SIGTERM,
// SIGTERM is sent. If still alive after killTimeout, SIGKILL is sent.
//
// Subsequent signals received after the first are also forwarded — a user
// hitting Ctrl-C twice because their agent ignored the first signal must see
// the second one delivered to the child rather than absorbed by veil. The
// escalate goroutine that backstops a stuck initial signal runs at most once
// so the (initial)→SIGTERM→SIGKILL ladder is not duplicated by re-signals.
//
// Both SIGINT (user Ctrl-C) and SIGTERM (CI hard-timeout, init system stop)
// trigger the escalation ladder so a child that traps and ignores the
// requested termination still exits within killTimeout. SIGQUIT and SIGHUP
// are forwarded but do not start the ladder — SIGQUIT is conventionally a
// dump-and-continue signal, and SIGHUP is widely used as a reload trigger.
func forwardSignals(ctx context.Context, cmd *exec.Cmd) {
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	defer signal.Stop(sigs)

	var escalateOnce sync.Once

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

			// Start the termination-escalation ladder at most once for the
			// first SIGINT or SIGTERM. Subsequent SIGINT/SIGTERMs from the
			// user or CI still get forwarded above; we just don't stack
			// additional SIGTERM/SIGKILL timers on top.
			if sig == syscall.SIGINT || sig == syscall.SIGTERM {
				escalateOnce.Do(func() {
					go escalate(ctx, cmd)
				})
			}
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
		ui.Dim(os.Stderr, "Waiting for process to exit...")
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
		ui.Dim(os.Stderr, "Force-killed child process.")
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
