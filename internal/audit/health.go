package audit

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Health summarises the audit subsystem's recent behaviour. It is safe to read
// via Store.Health() on a live store, or from disk via ReadHealth(dbPath) to
// inspect the state left behind by a previous process.
type Health struct {
	Dropped       int       // rows rejected because pending buffer was full
	LastErrorTime time.Time // zero = no error recorded
	LastErrorMsg  string    // empty = no error recorded
}

// Degraded reports whether the audit subsystem saw any failure since the
// sidecar was last cleared.
func (h Health) Degraded() bool {
	return h.Dropped > 0 || !h.LastErrorTime.IsZero()
}

// healthSidecarPath returns the path to the health sidecar for dbPath.
func healthSidecarPath(dbPath string) string { return dbPath + ".health" }

// ReadHealth loads the health sidecar next to dbPath. Returns a zero Health
// (and nil error) if no sidecar exists.
func ReadHealth(dbPath string) (Health, error) {
	f, err := os.Open(healthSidecarPath(dbPath))
	if err != nil {
		if os.IsNotExist(err) {
			return Health{}, nil
		}
		return Health{}, fmt.Errorf("open health sidecar: %w", err)
	}
	defer func() { _ = f.Close() }()

	var h Health
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch key {
		case "dropped":
			n, _ := strconv.Atoi(val)
			h.Dropped = n
		case "last_error_ms":
			ms, _ := strconv.ParseInt(val, 10, 64)
			if ms > 0 {
				h.LastErrorTime = time.UnixMilli(ms).UTC()
			}
		case "last_error":
			h.LastErrorMsg = val
		}
	}
	if err := sc.Err(); err != nil {
		return h, fmt.Errorf("read health sidecar: %w", err)
	}
	return h, nil
}

// writeHealthSidecar atomically writes the health state to dbPath.health.
// Errors are intentionally swallowed by callers — if we can't persist health,
// the user's disk is already in trouble and the in-memory state is still
// surfaced via ui.Warnf.
func writeHealthSidecar(dbPath string, h Health) error {
	tmp := healthSidecarPath(dbPath) + ".tmp"
	var b strings.Builder
	fmt.Fprintf(&b, "dropped=%d\n", h.Dropped)
	if !h.LastErrorTime.IsZero() {
		fmt.Fprintf(&b, "last_error_ms=%d\n", h.LastErrorTime.UnixMilli())
	}
	if h.LastErrorMsg != "" {
		fmt.Fprintf(&b, "last_error=%s\n", sanitizeHealthMsg(h.LastErrorMsg))
	}
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, healthSidecarPath(dbPath))
}

// clearHealthSidecar removes the sidecar, marking the audit healthy.
func clearHealthSidecar(dbPath string) error {
	err := os.Remove(healthSidecarPath(dbPath))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func sanitizeHealthMsg(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
