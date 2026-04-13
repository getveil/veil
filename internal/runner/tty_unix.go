//go:build darwin || linux

package runner

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/mattn/go-isatty"
	"golang.org/x/sys/unix"
)

// stdinTTYFd returns the file descriptor of stdin if it is a terminal,
// or -1 if stdin is not a terminal (e.g. piped input).
func stdinTTYFd() int {
	fd := os.Stdin.Fd()
	if isatty.IsTerminal(fd) {
		return int(fd)
	}
	return -1
}

// reclaimForeground restores the calling process's group as the terminal's
// foreground process group. This must be called after the child exits,
// because the child was made the foreground group via SysProcAttr.Foreground.
// Without this, veil (now a background group) could receive SIGTTOU when
// writing to the terminal.
//
// Best-effort: errors are ignored because veil is about to exit anyway.
func reclaimForeground(ttyFd int) {
	if ttyFd < 0 {
		return
	}
	// Ignore SIGTTOU while reclaiming — POSIX sends SIGTTOU to background
	// processes calling tcsetpgrp.
	signal.Ignore(syscall.SIGTTOU)
	_ = unix.IoctlSetPointerInt(ttyFd, unix.TIOCSPGRP, syscall.Getpgrp())
	signal.Reset(syscall.SIGTTOU)
}
