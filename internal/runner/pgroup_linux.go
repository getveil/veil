//go:build linux

package runner

import "syscall"

// procAttr returns process attributes for the child. When ttyFd >= 0 (stdin
// is a terminal), the child is placed in a new foreground process group so it
// can read from/write to the terminal. When ttyFd < 0 (piped), only Setpgid
// is used for signal-group isolation. Pdeathsig ensures the child is killed
// if the parent dies unexpectedly.
func procAttr(ttyFd int) *syscall.SysProcAttr {
	if ttyFd >= 0 {
		return &syscall.SysProcAttr{
			Setpgid:    true,
			Foreground: true,
			Ctty:       ttyFd,
			Pdeathsig:  syscall.SIGTERM,
		}
	}
	return &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGTERM,
	}
}
