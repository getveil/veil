//go:build darwin

package runner

import "syscall"

// procAttr returns process attributes for the child. When ttyFd >= 0 (stdin
// is a terminal), the child is placed in a new foreground process group so it
// can read from/write to the terminal. When ttyFd < 0 (piped), only Setpgid
// is used for signal-group isolation.
func procAttr(ttyFd int) *syscall.SysProcAttr {
	if ttyFd >= 0 {
		return &syscall.SysProcAttr{
			Setpgid:    true,
			Foreground: true,
			Ctty:       ttyFd,
		}
	}
	return &syscall.SysProcAttr{
		Setpgid: true,
	}
}
