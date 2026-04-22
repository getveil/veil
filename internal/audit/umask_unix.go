//go:build darwin || linux

package audit

import "syscall"

// withRestrictiveUmask runs fn with the process umask temporarily set to
// 0o077 so any files created inside fn inherit 0600 regardless of the
// library's internal Mode settings. SQLite's WAL/SHM sidecars are created
// at 0644 by default; this guard closes the short window before the
// subsequent Chmod can tighten them.
//
// Umask is a process-global setting. Callers must serialize invocations —
// audit.Open is called once at startup, so the concurrency concern is
// limited to whatever else is racing database creation, which in our case
// is nothing.
func withRestrictiveUmask(fn func() error) error {
	prev := syscall.Umask(0o077)
	defer syscall.Umask(prev)
	return fn()
}
