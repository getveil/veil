//go:build darwin

package runner

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
)

// parentWatcher holds a helper subprocess that kills the child process group
// if this process (veil) dies unexpectedly. macOS lacks the Linux Pdeathsig
// syscall, so we rely on kernel-guaranteed FD closure: the helper reads from
// a pipe we hold the write end of. When veil exits — cleanly or via crash —
// the kernel closes the write end, the helper sees EOF and kills the child.
//
// On clean shutdown, veil calls Close which SIGKILLs the helper before EOF
// can propagate, preventing a redundant kill against the already-reaped child.
type parentWatcher struct {
	cmd *exec.Cmd
	pw  io.Closer
}

// startParentWatch spawns the helper for childPid. childPid must be the
// process group leader (started with Setpgid=true); the kill targets -pgid.
func startParentWatch(childPid int) (*parentWatcher, error) {
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	// Shell reads stdin until EOF, then sends SIGTERM to the child's pgroup,
	// pauses briefly, and escalates to SIGKILL. Errors from kill are swallowed
	// so the script doesn't fail when the child is already gone.
	script := fmt.Sprintf(
		`cat >/dev/null; kill -TERM -%d 2>/dev/null; sleep 3; kill -KILL -%d 2>/dev/null`,
		childPid, childPid,
	)
	cmd := exec.Command("/bin/sh", "-c", script) //nolint:gosec // G204: childPid is a locally-allocated pid
	cmd.Stdin = pr
	// Setsid so the watcher survives a TTY hangup on the parent's session.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	// pr is owned by the child subprocess now.
	_ = pr.Close()
	return &parentWatcher{cmd: cmd, pw: pw}, nil
}

// Close signals clean shutdown. The watcher is SIGKILLed so its pending kill
// against the (already-reaped) child does not fire.
func (w *parentWatcher) Close() {
	if w == nil || w.cmd == nil || w.cmd.Process == nil {
		return
	}
	_ = w.cmd.Process.Kill()
	_ = w.cmd.Wait()
	if w.pw != nil {
		_ = w.pw.Close()
	}
}
