//go:build linux

package runner

// Linux relies on the Pdeathsig syscall configured in pgroup_linux.go; no
// userspace watchdog is needed.

type parentWatcher struct{}

func startParentWatch(_ int) (*parentWatcher, error) { return &parentWatcher{}, nil }

func (w *parentWatcher) Close() {}
