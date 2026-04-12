// Package runner orchestrates the veil run command: starts the proxy,
// launches the child process, and manages lifecycle.
package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/8enji/veil/internal/audit"
	"github.com/8enji/veil/internal/config"
	"github.com/8enji/veil/internal/proxy"
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

	// 4. Trust preflight.
	if !proxy.IsTrusted(ca) {
		fmt.Fprintln(os.Stderr,
			"WARNING: Veil's root CA is not trusted by the system. "+
				"Agents may see TLS errors. Run 'veil trust' to install it.")
	}

	// 5. Start proxy.
	server, err := proxy.New(ca, vlt, auditStore, os.Getpid(), cfg.Command)
	if err != nil {
		return nil, fmt.Errorf("create proxy: %w", err)
	}
	if err := server.Start(); err != nil {
		return nil, fmt.Errorf("start proxy: %w", err)
	}
	defer func() { _ = server.Stop() }()

	// 6. Build child env: strip existing proxy vars and inject ours.
	proxyURL := "http://" + server.Addr()
	env := buildChildEnv(os.Environ(), proxyURL)

	// 7. Exec child.
	child := exec.CommandContext(ctx, cfg.Command, cfg.Args...) //nolint:gosec // G204: command is explicitly provided by the user via CLI
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.Env = env
	child.SysProcAttr = procAttr()

	// 8. Start child.
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

	// 11. Extract exit code.
	if exitErr, ok := waitErr.(*exec.ExitError); ok {
		return &Result{ExitCode: exitErr.ExitCode()}, nil
	}
	if waitErr != nil {
		return nil, fmt.Errorf("child process failed: %w", waitErr)
	}
	return &Result{ExitCode: 0}, nil
}

// buildChildEnv takes the current env, strips proxy-related vars, and adds the
// proxy vars pointing to addr.
func buildChildEnv(environ []string, proxyURL string) []string {
	stripped := make([]string, 0, len(environ))
	for _, kv := range environ {
		key, _, ok := strings.Cut(kv, "=")
		if !ok {
			stripped = append(stripped, kv)
			continue
		}
		if isProxyEnvKey(key) {
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
