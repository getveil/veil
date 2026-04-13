// Package runner orchestrates the veil run command: starts the proxy,
// launches the child process, and manages lifecycle.
package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/8enji/veil/internal/audit"
	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/proxy"
	"github.com/8enji/veil/internal/ui"
	"github.com/8enji/veil/internal/vault"
)

// Config holds the parameters for a single veil run invocation.
type Config struct {
	Root     string         // project root
	Command  string         // child command
	Args     []string       // child args
	Verbose  bool           //nolint:unused // reserved for future use
	Keystore vault.Keystore // optional; nil means AutoKeystore
}

// Result holds the outcome of a completed child process.
type Result struct {
	ExitCode int
}

// proxyEnvKeys lists all environment variable names that configure HTTP proxies.
var proxyEnvKeys = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
	"NO_PROXY", "no_proxy",
}

// Run starts the proxy, launches the child command with proxy env vars injected,
// forwards signals, waits for the child to exit, then cleans up.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	// 1. Load vault.
	ks := cfg.Keystore
	if ks == nil {
		fallbackPath, err := config.KeystoreFallbackFile()
		if err != nil {
			return nil, fmt.Errorf("keystore fallback path: %w", err)
		}
		ks = vault.AutoKeystore(fallbackPath)
	}
	vlt, err := vault.Open(cfg.Root, ks)
	if err != nil {
		return nil, fmt.Errorf("open vault: %w", err)
	}

	// 2. Open audit DB.
	auditDBPath := config.AuditDBFile(cfg.Root)
	auditStore, err := audit.Open(auditDBPath)
	if err != nil {
		return nil, fmt.Errorf("open audit db: %w", err)
	}
	defer func() { _ = auditStore.Close() }()

	// 3. Load CA.
	ca, err := proxy.LoadOrCreateCA()
	if err != nil {
		return nil, fmt.Errorf("load or create CA: %w", err)
	}

	// 3b. Build combined CA bundle (system CAs + Veil CA).
	bundlePath, err := proxy.BuildCABundle(ca.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("build ca bundle: %w", err)
	}
	defer proxy.RemoveCABundle(bundlePath)

	// 5. Start proxy.
	server, err := proxy.New(ca, vlt, auditStore, os.Getpid(), cfg.Command)
	if err != nil {
		return nil, fmt.Errorf("create proxy: %w", err)
	}
	if err := server.Start(); err != nil {
		return nil, fmt.Errorf("start proxy: %w", err)
	}
	defer func() { _ = server.Stop() }()

	// Write PID file for veil status to detect running proxy.
	pidPath := config.PidFile(cfg.Root)
	if err := WritePidFile(pidPath, os.Getpid()); err != nil {
		// Non-fatal — status won't detect proxy, but run still works.
		fmt.Fprintf(os.Stderr, "%s\n", ui.Muted.Sprintf("warning: could not write pid file: %v", err))
	}
	defer RemovePidFile(pidPath)

	// 5b. Print startup line to stderr.
	credCount := len(vlt.List())
	fmt.Fprintf(os.Stderr, "\n%s proxy active · %d credentials loaded\n",
		ui.Success.Sprint("veil"), credCount)
	fmt.Fprintln(os.Stderr, ui.Muted.Sprint("───────────────────────────────────────"))
	if warning := formatStartupWarning(credCount); warning != "" {
		fmt.Fprintf(os.Stderr, "  %s\n", ui.Warning.Sprint("! ")+warning)
	}

	// 6. Build child env: strip existing proxy vars and inject ours.
	proxyURL := "http://" + server.Addr()
	env := buildChildEnv(os.Environ(), proxyURL, bundlePath)

	// 7. Exec child.
	ttyFd := stdinTTYFd()
	child := exec.CommandContext(ctx, cfg.Command, cfg.Args...) //nolint:gosec // G204: command is explicitly provided by the user via CLI
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.Env = env
	child.SysProcAttr = procAttr(ttyFd)

	// 8. Start child.
	sessionStart := time.Now()
	if err := child.Start(); err != nil {
		return nil, fmt.Errorf("start child: %w", err)
	}

	// 9. Signal forwarding.
	sigCtx, sigCancel := context.WithCancel(ctx)
	defer sigCancel()
	go forwardSignals(sigCtx, child)

	// 10. Wait for child to exit.
	waitErr := child.Wait()
	sigCancel()

	// 11. Reclaim foreground process group so veil can write to the terminal.
	reclaimForeground(ttyFd)

	// 11b. Compute exit code for summary.
	exitCode := 0
	if exitErr, ok := waitErr.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	}

	// 11c. Print exit summary to stderr.
	sessionDuration := time.Since(sessionStart)
	sessionTotal, sessionBlocked, sessionHosts, _, summaryErr := auditStore.Summary(sessionStart)
	fmt.Fprintln(os.Stderr, ui.Muted.Sprint("───────────────────────────────────────"))
	fmt.Fprintf(os.Stderr, "%s %s\n", ui.Success.Sprint("veil"), formatExitSummary(exitCode))
	fmt.Fprintf(os.Stderr, "  Duration:    %s\n", formatDuration(sessionDuration))
	if summaryErr == nil {
		hostInfo := "0 hosts"
		if len(sessionHosts) > 0 {
			hostInfo = fmt.Sprintf("%d host(s)", len(sessionHosts))
		}
		fmt.Fprintf(os.Stderr, "  Injections:  %d across %s\n", sessionTotal, hostInfo)
		if sessionBlocked > 0 {
			fmt.Fprintf(os.Stderr, "  Blocked:     %d\n", sessionBlocked)
		}
	}
	fmt.Fprintln(os.Stderr)

	// 12. Return result.
	if waitErr != nil {
		if _, ok := waitErr.(*exec.ExitError); ok {
			return &Result{ExitCode: exitCode}, nil
		}
		return nil, fmt.Errorf("child process failed: %w", waitErr)
	}
	return &Result{ExitCode: 0}, nil
}

// buildChildEnv takes the current env, strips proxy-related and CA-related vars,
// and adds the proxy vars pointing to proxyURL and CA vars pointing to bundlePath.
func buildChildEnv(environ []string, proxyURL, bundlePath string) []string {
	stripped := make([]string, 0, len(environ))
	for _, kv := range environ {
		key, _, ok := strings.Cut(kv, "=")
		if !ok {
			stripped = append(stripped, kv)
			continue
		}
		if isProxyEnvKey(key) || isCAEnvKey(key) {
			continue
		}
		stripped = append(stripped, kv)
	}

	return append(stripped,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
		"NO_PROXY=localhost,127.0.0.1,::1",
		"no_proxy=localhost,127.0.0.1,::1",
		"NODE_EXTRA_CA_CERTS="+bundlePath,
		"SSL_CERT_FILE="+bundlePath,
		"CURL_CA_BUNDLE="+bundlePath,
		"REQUESTS_CA_BUNDLE="+bundlePath,
		"HTTPLIB2_CA_CERTS="+bundlePath,
	)
}

// isProxyEnvKey returns true if the given key is a proxy-related environment
// variable that should be stripped and replaced.
func isProxyEnvKey(key string) bool {
	for _, k := range proxyEnvKeys {
		if strings.EqualFold(key, k) {
			return true
		}
	}
	return false
}

// caEnvKeys lists environment variable names that configure CA certificate
// bundles across runtimes. These are stripped and replaced with Veil's
// combined bundle.
var caEnvKeys = []string{
	"NODE_EXTRA_CA_CERTS",
	"SSL_CERT_FILE",
	"CURL_CA_BUNDLE",
	"REQUESTS_CA_BUNDLE",
	"HTTPLIB2_CA_CERTS",
}

// isCAEnvKey returns true if the given key is a CA-related environment
// variable that should be stripped and replaced.
func isCAEnvKey(key string) bool {
	for _, k := range caEnvKeys {
		if strings.EqualFold(key, k) {
			return true
		}
	}
	return false
}

// formatStartupWarning returns a warning message if credCount is zero, or empty string otherwise.
func formatStartupWarning(credCount int) string {
	if credCount == 0 {
		return "No credentials to inject. Add secrets with veil add or create a .env file and re-run veil init."
	}
	return ""
}

// formatExitSummary returns the session summary line based on exit code.
func formatExitSummary(exitCode int) string {
	if exitCode == 0 {
		return "session complete"
	}
	return fmt.Sprintf("session ended (exit %d)", exitCode)
}

// formatDuration formats a duration as "Xh Ym Zs", omitting zero components.
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60

	switch {
	case h > 0:
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	case m > 0:
		return fmt.Sprintf("%dm %ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}
