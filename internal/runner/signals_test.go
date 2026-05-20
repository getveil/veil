package runner

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestForwardSignalsCompiles verifies that the signal forwarding function
// compiles correctly. Actual signal forwarding is tested via integration tests,
// as programmatic signal tests are inherently fragile.
func TestForwardSignalsCompiles(t *testing.T) {
	// The forwardSignals function is exercised by the integration tests in
	// runner_test.go. This test exists to ensure the function signature and
	// imports compile on all platforms.
	_ = forwardSignals
}

func TestEscalationTimings(t *testing.T) {
	// Verify constants are defined and reasonable.
	if escalateTimeout <= 0 {
		t.Error("escalateTimeout should be positive")
	}
	if killTimeout <= 0 {
		t.Error("killTimeout should be positive")
	}
	if killTimeout <= escalateTimeout {
		t.Error("killTimeout should be greater than escalateTimeout")
	}
}

// signalListenerScript is a shell snippet that traps SIGINT and SIGTERM,
// prints the signal name (newline-terminated, with explicit flush via stdbuf
// or printf) and stays alive on SIGINT but exits on SIGTERM. The test reads
// stdout line by line to confirm both signals reached the child even when
// veil's forwardSignals is invoked twice in a row.
const signalListenerScript = `
trap 'printf "INT\n"' INT
trap 'printf "TERM\n"; exit 0' TERM
# Print ready marker so the test knows traps are installed before signaling.
printf "READY\n"
# Loop with short sleeps so trap can fire between iterations on every platform.
while :; do sleep 0.05; done
`

// TestForwardSignals_SecondSignalAlsoForwarded is the regression test for the
// bug where forwardSignals returned after the first signal, causing a second
// Ctrl-C to be absorbed by veil instead of reaching the child. The test
// spawns a subprocess that traps SIGINT (does not exit) and SIGTERM (exits),
// then triggers forwardSignals twice and asserts BOTH lines reach the child.
func TestForwardSignals_SecondSignalAlsoForwarded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping signal integration test in short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("Unix signal semantics only")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Mask SIGINT/SIGTERM default actions in the test process up front so a
	// signal we send to ourselves can't terminate the test runner if it
	// races forwardSignals' own signal.Notify installation. The handler is
	// removed at test end via signal.Stop so other tests are unaffected.
	mask := make(chan os.Signal, 4)
	signal.Notify(mask, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(mask)

	// Spawn a sh subprocess in its OWN process group so forwardSignals'
	// negative-PID kill targets only the child, not the test runner.
	child := exec.CommandContext(ctx, "sh", "-c", signalListenerScript)
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	child.Stderr = io.Discard

	if err := child.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if child.Process != nil {
			_ = syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
		}
		_ = child.Wait()
	})

	// We can't use signal.Notify in the test because forwardSignals already
	// subscribes to SIGINT/SIGTERM. Instead, drive the forwarder directly by
	// calling syscall.Kill on -child.Pid the same way forwardSignals would.
	// That bypasses the OS-signal hop entirely and tests the post-forward
	// behavior precisely: that the function keeps forwarding after the first.
	//
	// Run forwardSignals in a goroutine and inject signals by sending them to
	// the current process — Go's os/signal will deliver them on the chan
	// inside forwardSignals, which then re-emits them at the child PG.
	sigCtx, sigCancel := context.WithCancel(context.Background())
	defer sigCancel()
	done := make(chan struct{})
	go func() {
		forwardSignals(sigCtx, child)
		close(done)
	}()

	// Wait for the child to print READY so trap handlers are installed before
	// the first signal is delivered. Without this gate the SIGINT can race the
	// shell's trap setup and tear the subprocess down before INT is printed.
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatalf("child exited before READY: %v", scanner.Err())
	}
	if got := scanner.Text(); got != "READY" {
		t.Fatalf("first child line = %q, want READY", got)
	}

	// Pid of the current test process — sending signals here causes
	// forwardSignals' os/signal channel to fire.
	selfPid := syscall.Getpid()

	// First signal: SIGINT. The child traps it and prints "INT" but does
	// NOT exit. forwardSignals must forward it to -child.Pid AND remain
	// running so the second signal can be forwarded too.
	if err := syscall.Kill(selfPid, syscall.SIGINT); err != nil {
		t.Fatalf("Kill SIGINT: %v", err)
	}
	if line, ok := readLineWithin(scanner, 3*time.Second); !ok || line != "INT" {
		t.Fatalf("after first SIGINT, child output = %q (ok=%v); want INT", line, ok)
	}

	// Second signal: SIGTERM. With the bug, forwardSignals had already
	// returned after the first signal, so this SIGTERM would never reach
	// the child and the test would hang. With the fix, it propagates and
	// the child prints "TERM" and exits.
	if err := syscall.Kill(selfPid, syscall.SIGTERM); err != nil {
		t.Fatalf("Kill SIGTERM: %v", err)
	}
	if line, ok := readLineWithin(scanner, 3*time.Second); !ok || line != "TERM" {
		t.Fatalf("after second SIGTERM, child output = %q (ok=%v); want TERM", line, ok)
	}

	// Child should exit cleanly via its TERM trap.
	if err := child.Wait(); err != nil {
		t.Fatalf("child.Wait: %v", err)
	}

	// Tear down the forwarder goroutine and confirm it returns.
	sigCancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("forwardSignals did not return after ctx cancel")
	}
}

// readLineWithin reads one newline-delimited line from scanner, returning the
// line text and true if a line arrived within timeout, otherwise ("", false).
// The scanner.Scan() call is itself blocking, so we run it in a goroutine.
func readLineWithin(scanner *bufio.Scanner, timeout time.Duration) (string, bool) {
	type result struct {
		line string
		ok   bool
	}
	ch := make(chan result, 1)
	go func() {
		ok := scanner.Scan()
		ch <- result{line: strings.TrimRight(scanner.Text(), "\r\n"), ok: ok}
	}()
	select {
	case r := <-ch:
		return r.line, r.ok
	case <-time.After(timeout):
		return "", false
	}
}
