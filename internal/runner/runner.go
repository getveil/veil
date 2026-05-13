// Package runner orchestrates the veil run command: starts the proxy,
// launches the child process, and manages lifecycle.
package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/getveil/veil/internal/audit"
	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/envkeys"
	"github.com/getveil/veil/internal/proxy"
	"github.com/getveil/veil/internal/ui"
	"github.com/getveil/veil/internal/vault"
)

// Config holds the parameters for a single veil run invocation.
type Config struct {
	Root            string         // project root
	Command         string         // child command
	Args            []string       // child args
	Verbose         bool           //nolint:unused // reserved for future use
	SkipHosts       []string       // hosts to exclude from proxying (added to NO_PROXY)
	Keystore        vault.Keystore // optional; nil means AutoKeystore
	AllowEnvSecrets []string       // env var names to pass through even if secret-like and not in vault
}

// Result holds the outcome of a completed child process.
type Result struct {
	ExitCode int
}

// Run starts the proxy, launches the child command with proxy env vars injected,
// forwards signals, waits for the child to exit, then cleans up.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	sweepStaleSessionDirs()

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

	// 3b. Per-session temp directory that holds the CA bundle and any other
	// short-lived artifacts. Cleaned up on exit.
	sessionDir, err := os.MkdirTemp("", "veil-session-*")
	if err != nil {
		return nil, fmt.Errorf("create session dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(sessionDir) }()

	bundlePath, err := proxy.BuildCABundleIn(sessionDir, ca.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("build ca bundle: %w", err)
	}

	bundlePEM, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("read ca bundle: %w", err)
	}
	javaTruststorePath, javaTruststorePassword, err := proxy.BuildJavaTruststoreIn(sessionDir, bundlePEM)
	if err != nil {
		return nil, fmt.Errorf("build java truststore: %w", err)
	}

	// 4. Resolve the child command to a realpath before touching the proxy
	// or spawning anything — this is the forensic anchor for audit rows and
	// the banner. A shadow binary in a writable PATH dir is a real threat for
	// a tool whose promise is "the agent never sees real tokens".
	resolvedCmd, err := resolveAgentCommand(cfg.Command)
	if err != nil {
		return nil, fmt.Errorf("resolve agent command: %w", err)
	}

	// 5. Start proxy. Use resolvedCmd so every audit row records the binary
	// that actually ran, not whatever token the user typed on the CLI.
	server, err := proxy.New(ca, vlt, auditStore, os.Getpid(), resolvedCmd)
	if err != nil {
		return nil, fmt.Errorf("create proxy: %w", err)
	}
	if err := server.Start(); err != nil {
		return nil, fmt.Errorf("start proxy: %w", err)
	}
	defer func() { _ = server.Stop() }()

	// Write PID file for veil status to detect running proxy.
	pidPath := config.PidFile(cfg.Root, os.Getpid())
	if err := WritePidFile(pidPath, os.Getpid()); err != nil {
		// Non-fatal — status won't detect proxy, but run still works.
		ui.Warnf(os.Stderr, "could not write pid file: %v", err)
	}
	defer RemovePidFile(pidPath)

	// 5b. Print startup line to stderr.
	credCount := len(vlt.List())
	fmt.Fprintf(os.Stderr, "\n%s proxy active · %d credentials loaded\n",
		ui.Success.Sprint("veil"), credCount)
	fmt.Fprintf(os.Stderr, "  %s %s\n", ui.Muted.Sprint("agent:"), ui.Muted.Sprint(resolvedCmd))
	ui.Dim(os.Stderr, "───────────────────────────────────────")
	if warning := formatStartupWarning(credCount); warning != "" {
		fmt.Fprintf(os.Stderr, "  %s\n", ui.Warning.Sprint("! ")+warning)
	}

	// 6. Build child env: strip existing proxy vars and inject ours, and
	// remove any shell-exported var whose name matches a vault credential
	// (SEC-1). Announce the strip loudly so the user knows their shell was
	// intervened on — this is the single most important guarantee in the
	// product ("the agent never sees real tokens").
	proxyURL := "http://" + server.Addr()
	creds := vlt.List()
	entries := make([]vaultEntry, 0, len(creds))
	for _, c := range creds {
		entries = append(entries, vaultEntry{Name: c.Name, Placeholder: c.Placeholder})
	}
	env, strippedVault, strippedInternal := buildChildEnv(os.Environ(), proxyURL, bundlePath, javaTruststorePath, javaTruststorePassword, cfg.SkipHosts, entries)
	if len(strippedVault) > 0 {
		printStrippedEnvWarning(os.Stderr, strippedVault)
	}
	if len(strippedInternal) > 0 {
		printStrippedInternalWarning(os.Stderr, len(strippedInternal))
	}

	// 6b. Belt-and-suspenders: scan for secret-like env vars that slipped past
	// init (e.g., a new export since `veil init` ran). Warn interactively;
	// fail-closed non-interactively unless --allow-env-secret covers them.
	allowSet := make(map[string]struct{}, len(cfg.AllowEnvSecrets))
	for _, n := range cfg.AllowEnvSecrets {
		if n == "" {
			continue
		}
		allowSet[strings.ToUpper(n)] = struct{}{}
	}
	unvaulted := scanUnvaultedSecretLikes(os.Environ(), vlt.Names(), allowSet)
	if len(unvaulted) > 0 {
		printUnvaultedWarning(os.Stderr, unvaulted)
		if stdinTTYFd() < 0 {
			return nil, fmt.Errorf("refusing to launch: %d shell env var(s) look like unvaulted secrets (%s); rerun with --allow-env-secret or veil init --force",
				len(unvaulted), strings.Join(unvaulted, ", "))
		}
	}

	// 7. Exec child using the resolved realpath so we cannot race with a
	// PATH change between resolve and exec.
	ttyFd := stdinTTYFd()
	child := exec.CommandContext(ctx, resolvedCmd, cfg.Args...) //nolint:gosec // G204: command is explicitly provided by the user via CLI and resolved upfront
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

	// 8b. Guard against parent crash. On Linux this is a no-op; on macOS
	// (which lacks Pdeathsig) it spawns a helper that kills the child's
	// process group if veil dies unexpectedly.
	watcher, werr := startParentWatch(child.Process.Pid)
	if werr != nil {
		ui.Warnf(os.Stderr, "could not start parent watcher: %v", werr)
	}
	defer watcher.Close()

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
	printSessionFooter(os.Stderr, auditStore, sessionStart, time.Since(sessionStart), exitCode)

	// 12. Return result.
	if waitErr != nil {
		if _, ok := waitErr.(*exec.ExitError); ok {
			return &Result{ExitCode: exitCode}, nil
		}
		return nil, fmt.Errorf("child process failed: %w", waitErr)
	}
	return &Result{ExitCode: 0}, nil
}

// vaultEntry is the minimum subset of a vault credential that buildChildEnv
// needs: the env var name that may be shell-exported, and the placeholder to
// substitute in its place so the child still has a value (the placeholder)
// associated with that name.
type vaultEntry struct {
	Name        string
	Placeholder string
}

// NO_PROXY list. javaTruststorePath is the per-session PKCS12 that JVM
// children use via JAVA_TOOL_OPTIONS. javaTruststorePassword is the random
// password BuildJavaTruststoreIn returned alongside that path. vaultEntries
// is the set of credentials loaded from the vault; any env var whose key
// matches (case-insensitively) has its real value stripped and replaced
// with the credential's placeholder, so the child process cannot observe
// the real secret that the user exported in their shell. The names of env
// vars actually stripped because of the vault match are returned (using
// the original casing from the environment), so the caller can surface a
// startup warning.
//
// strippedInternal returns the names of Veil's own control env vars
// (envkeys.VeilInternalKeys) that were present in environ and removed from
// the child. These are control variables — never reinjected — and the
// caller surfaces a separate, muted notice for them. VEIL_PASSPHRASE in
// particular would let the agent decrypt the vault on Linux file-keystore
// systems, so silent leakage would defeat Veil's core guarantee.
func buildChildEnv(environ []string, proxyURL, bundlePath, javaTruststorePath, javaTruststorePassword string, skipHosts []string, vaultEntries []vaultEntry) ([]string, []string, []string) {
	vaultMap := make(map[string]string, len(vaultEntries))
	for _, e := range vaultEntries {
		if e.Name == "" {
			continue
		}
		vaultMap[strings.ToUpper(e.Name)] = e.Placeholder
	}

	stripped := make([]string, 0, len(environ))
	strippedVault := make([]string, 0)
	strippedInternal := make([]string, 0)
	reinject := make([]string, 0)
	for _, kv := range environ {
		key, _, ok := strings.Cut(kv, "=")
		if !ok {
			stripped = append(stripped, kv)
			continue
		}
		if isProxyEnvKey(key) || isCAEnvKey(key) || strings.EqualFold(key, "JAVA_TOOL_OPTIONS") {
			continue
		}
		if isVeilInternalEnvKey(key) {
			strippedInternal = append(strippedInternal, key)
			continue
		}
		if ph, hit := vaultMap[strings.ToUpper(key)]; hit {
			strippedVault = append(strippedVault, key)
			reinject = append(reinject, key+"="+ph)
			continue
		}
		stripped = append(stripped, kv)
	}

	veilJavaFlags := proxy.JavaToolOptionsFlags(javaTruststorePath, javaTruststorePassword)
	javaToolOpts := veilJavaFlags
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(k, "JAVA_TOOL_OPTIONS") {
			if existing := strings.TrimSpace(v); existing != "" {
				javaToolOpts = existing + " " + veilJavaFlags
			}
			break
		}
	}

	noProxy := "localhost,127.0.0.1,::1"
	if len(skipHosts) > 0 {
		noProxy = noProxy + "," + strings.Join(skipHosts, ",")
	}

	env := append(stripped,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
		"NO_PROXY="+noProxy,
		"no_proxy="+noProxy,
		"NODE_EXTRA_CA_CERTS="+bundlePath,
		"SSL_CERT_FILE="+bundlePath,
		"CURL_CA_BUNDLE="+bundlePath,
		"REQUESTS_CA_BUNDLE="+bundlePath,
		"HTTPLIB2_CA_CERTS="+bundlePath,
		"CARGO_HTTP_CAINFO="+bundlePath,
		"JAVA_TOOL_OPTIONS="+javaToolOpts,
	)
	// Append re-injected placeholders last for readability. The proxy/CA
	// filter above skips any name matching isProxyEnvKey/isCAEnvKey before
	// reaching the vault branch, so there is no collision with the proxy/CA
	// vars we just appended.
	env = append(env, reinject...)
	return env, strippedVault, strippedInternal
}

// isProxyEnvKey returns true if the given key is a proxy-related environment
// variable that should be stripped and replaced.
func isProxyEnvKey(key string) bool {
	for _, k := range envkeys.ProxyKeys {
		if strings.EqualFold(key, k) {
			return true
		}
	}
	return false
}

// isCAEnvKey returns true if the given key is a CA-related environment
// variable that should be stripped and replaced with Veil's combined bundle.
func isCAEnvKey(key string) bool {
	for _, k := range envkeys.CAKeys {
		if strings.EqualFold(key, k) {
			return true
		}
	}
	return false
}

// isVeilInternalEnvKey returns true if the given key is one of Veil's own
// control variables that must not be inherited by the agent child. The
// canonical risk is VEIL_PASSPHRASE on Linux file-keystore systems: if it
// reaches the agent, the agent can read master.key.age from disk and
// decrypt every vault entry without privilege escalation.
func isVeilInternalEnvKey(key string) bool {
	for _, k := range envkeys.VeilInternalKeys {
		if strings.EqualFold(key, k) {
			return true
		}
	}
	return false
}

// resolveAgentCommand resolves cmd to an absolute, symlink-free path. Bare
// names are looked up on PATH; anything containing a separator is made
// absolute relative to the current working directory. The result is then
// passed through filepath.EvalSymlinks so a symlinked binary is recorded in
// the audit trail by its true path. This is SEC-23 forensics support: when
// the product promise is "the agent never sees real tokens", a later
// investigation needs to know exactly which binary ran, not which PATH entry
// was first on that day.
func resolveAgentCommand(cmd string) (string, error) {
	if cmd == "" {
		return "", fmt.Errorf("empty command")
	}
	resolved, err := exec.LookPath(cmd)
	if err != nil {
		return "", fmt.Errorf("resolve command %q: %w", cmd, err)
	}
	if !filepath.IsAbs(resolved) {
		abs, absErr := filepath.Abs(resolved)
		if absErr != nil {
			return "", fmt.Errorf("absolute path for %q: %w", cmd, absErr)
		}
		resolved = abs
	}
	real, err := filepath.EvalSymlinks(resolved)
	if err != nil {
		return "", fmt.Errorf("eval symlinks for %q: %w", cmd, err)
	}
	return real, nil
}

// printStrippedEnvWarning announces that one or more shell-exported env vars
// whose names matched a vault credential have been removed from the child
// environment. This has to be impossible to miss: it is the product's single
// biggest failure mode if it goes silent. Format:
//
//	! stripped N credential(s) from agent environment (sourced from your shell):
//	    NAME_1
//	    NAME_2
//	  the agent will see Veil's placeholders instead.
func printStrippedEnvWarning(w *os.File, names []string) {
	_, _ = fmt.Fprintf(w, "  %s stripped %d credential(s) from agent environment (sourced from your shell):\n",
		ui.Warning.Sprint("!"), len(names))
	for _, n := range names {
		_, _ = fmt.Fprintf(w, "      %s\n", ui.Warning.Sprint(n))
	}
	_, _ = fmt.Fprintf(w, "    %s\n", ui.Muted.Sprint("the agent will see Veil's placeholders instead."))
}

// printStrippedInternalWarning announces that Veil's own control vars
// (VEIL_PASSPHRASE et al.) were present in the parent environment and have
// been removed before exec. Muted, single-line, unnamed — the user set
// these intentionally for Veil's use, so this is implementation detail, not
// an alarm. Format:
//
//	  removed N veil-internal var(s) from agent environment
func printStrippedInternalWarning(w *os.File, count int) {
	msg := fmt.Sprintf("removed %d veil-internal var(s) from agent environment", count)
	_, _ = fmt.Fprintf(w, "  %s\n", ui.Muted.Sprint(msg))
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

// auditFooterSource is the audit-store surface the session footer needs:
// flush any buffered rows so the SELECT below sees an up-to-date view, then
// query aggregates. Defined as an interface so footer-rendering tests can
// substitute a fake without spinning up SQLite.
type auditFooterSource interface {
	Flush()
	Summary(since time.Time) (total int, blocked int, leaked int, hosts []string, lastInjection *audit.Row, err error)
}

// printSessionFooter writes the session-end summary block to w. Flushes the
// audit buffer first because audit.Store batches writes in memory; without
// the flush, a short session whose injection count never reached the 50-row
// auto-flush threshold or the 100ms ticker tick would render zeros while
// the rows are still buffered (F-9).
func printSessionFooter(w io.Writer, store auditFooterSource, sessionStart time.Time, sessionDuration time.Duration, exitCode int) {
	store.Flush()
	sessionTotal, sessionBlocked, sessionLeaked, sessionHosts, _, summaryErr := store.Summary(sessionStart)
	ui.Dim(w, "───────────────────────────────────────")
	_, _ = fmt.Fprintf(w, "%s %s\n", ui.Success.Sprint("veil"), formatExitSummary(exitCode))
	_, _ = fmt.Fprintf(w, "  Duration:    %s\n", formatDuration(sessionDuration))
	if summaryErr == nil {
		hostInfo := "0 hosts"
		if len(sessionHosts) > 0 {
			hostInfo = fmt.Sprintf("%d host(s)", len(sessionHosts))
		}
		_, _ = fmt.Fprintf(w, "  Injections:  %d across %s\n", sessionTotal, hostInfo)
		if sessionBlocked > 0 {
			_, _ = fmt.Fprintf(w, "  Blocked:     %d\n", sessionBlocked)
		}
		// Leaks are distinct from injections: the request was refused before
		// any real secret reached the wire. Surface them separately so a
		// user trusting "Injections: N" never mistakes a placeholder leak
		// for a successful swap.
		if sessionLeaked > 0 {
			_, _ = fmt.Fprintf(w, "  Leaks:       %d\n", sessionLeaked)
		}
	} else {
		_, _ = fmt.Fprintf(w, "  Injections:  %s\n", ui.Muted.Sprint("(unavailable)"))
	}
	_, _ = fmt.Fprintln(w)
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

// sweepStaleSessionDirs removes veil-session-* directories under the OS temp
// root that are older than 24h. Best-effort; errors are silently tolerated.
func sweepStaleSessionDirs() {
	sweepStaleSessionDirsIn(os.TempDir())
}

// sweepStaleSessionDirsIn is the inner form of sweepStaleSessionDirs that
// accepts a custom root. Exposed via SweepStaleSessionDirsForTest so tests
// can point the sweeper at t.TempDir() instead of the shared OS temp dir.
func sweepStaleSessionDirsIn(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "veil-session-") {
			continue
		}
		p := filepath.Join(root, e.Name())
		info, err := os.Stat(p)
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		_ = os.RemoveAll(p)
	}
}

// SweepStaleSessionDirsForTest exposes the sweeper for tests. Callers pass
// a custom root to avoid interfering with the shared OS temp dir; passing
// "" uses os.TempDir() (the production path).
func SweepStaleSessionDirsForTest(root string) {
	if root == "" {
		sweepStaleSessionDirs()
		return
	}
	sweepStaleSessionDirsIn(root)
}
