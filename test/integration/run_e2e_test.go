package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/getveil/veil/internal/placeholder"
	"github.com/getveil/veil/internal/scanner"
)

// projectRoot returns the absolute path to the Veil repo root. It walks
// upward from the current file until it finds go.mod.
func projectRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine caller file")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("cannot find repo root (go.mod)")
		}
		dir = parent
	}
}

// buildVeil compiles the veil binary into the given directory and returns
// its path. The caller should use t.TempDir() for binDir.
func buildVeil(t *testing.T, binDir string) string {
	t.Helper()
	veilBin := filepath.Join(binDir, "veil")
	build := exec.Command("go", "build", "-o", veilBin, "./cmd/veil")
	build.Dir = projectRoot(t)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("build veil binary: %v\n%s", err, out)
	}
	return veilBin
}

// buildTestClient compiles the testclient helper binary into binDir.
func buildTestClient(t *testing.T, binDir string) string {
	t.Helper()
	clientBin := filepath.Join(binDir, "testclient")
	build := exec.Command("go", "build", "-o", clientBin, "./test/integration/testclient")
	build.Dir = projectRoot(t)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("build testclient binary: %v\n%s", err, out)
	}
	return clientBin
}

// makeEnv constructs environment variables for veil CLI invocations.
//
// On Linux/CI we point HOME at t.TempDir() so the file-fallback keystore
// is used instead of any ambient keyring — tests are hermetic and the
// file-fallback path is exercised. All binary invocations in one test
// share the same HOME (per-test, not per-invocation), so the file
// keystore is visible across veil init / veil run / veil status.
//
// On macOS we keep the real HOME because go-keyring calls /usr/bin/security,
// which resolves the login keychain via $HOME/Library/Keychains. Overriding
// HOME makes the keychain unreachable (errSecInteractionNotAllowed / exit
// 154), and AutoKeystore on darwin never falls back to file regardless.
// macOS CI would need a separate env-var hook to force file-fallback; that's
// a production change outside the scope of this test-only work. Keychain
// entries keyed by unique project IDs don't collide between tests.
//
// We do NOT set VEIL_TEST_KEYSTORE=mem because e2e tests span multiple
// processes that must share the keystore via disk.
//
// We also scrub ambient secret-like vars (ANTHROPIC_API_KEY, GITHUB_TOKEN,
// USE_STAGING_OAUTH, etc.) that a developer or CI runner may have exported
// in their shell. These would otherwise trip the runtime fail-closed scan in
// `veil run` (see internal/runner/envscan.go). This mirrors the unit-test
// hygiene in internal/cli/init_shellenv_test.go (clearShellEnvTestNoise) and
// internal/runner/runner_test.go (allowAllAmbientSecretLikes): the tests
// simulate a clean shell, which is what they always meant to model. POSIX
// names on the scanner denylist (PATH, PWD, etc.) are left alone.
func makeEnv(t *testing.T) []string {
	t.Helper()
	src := os.Environ()
	out := make([]string, 0, len(src)+1)
	overrideHome := runtime.GOOS != "darwin"
	for _, kv := range src {
		if strings.HasPrefix(kv, "VEIL_TEST_KEYSTORE=") {
			continue
		}
		if overrideHome && strings.HasPrefix(kv, "HOME=") {
			continue
		}
		key, value, ok := strings.Cut(kv, "=")
		if ok && key != "" &&
			!scanner.IsObviouslyNotSecret(key) &&
			placeholder.IsSecretLike(key, value) {
			// Drop genuine ambient secret-like vars so veil run's
			// fail-closed scan doesn't reject the test subprocess.
			continue
		}
		out = append(out, kv)
	}
	if overrideHome {
		out = append(out, "HOME="+t.TempDir())
	}
	return out
}

// assertFileExists fails the test if the given path does not exist.
func assertFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("expected file to exist: %s", path)
	}
}

// TestE2E_InitAndRun exercises the full veil lifecycle: build, init, inspect,
// run with a trivial command, and verify CLI output.
func TestE2E_InitAndRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	env := makeEnv(t)

	// 1. Build the veil binary.
	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)

	// 2. Create a test project.
	projDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projDir, ".git"), 0755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	envContent := "# Test environment\nOPENAI_API_KEY=sk-proj-test1234567890abcdef1234567890abcdef\nDATABASE_URL=postgres://user:supersecretpassword@localhost:5432/mydb\nHOSTNAME=myserver.local\nDEBUG=true\n"
	if err := os.WriteFile(filepath.Join(projDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	// 3. Run veil init.
	initCmd := exec.Command(veilBin, "init", "--path", projDir)
	initCmd.Env = env
	initOut, err := initCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil init failed: %v\n%s", err, initOut)
	}
	t.Logf("veil init output:\n%s", initOut)

	// 4. Verify .env was rewritten.
	rewrittenEnv, err := os.ReadFile(filepath.Join(projDir, ".env"))
	if err != nil {
		t.Fatalf("reading rewritten .env: %v", err)
	}
	envStr := string(rewrittenEnv)

	// Secret values should be replaced with placeholders.
	if strings.Contains(envStr, "sk-proj-test1234567890abcdef") {
		t.Error("OPENAI_API_KEY was not replaced with a placeholder")
	}
	if strings.Contains(envStr, "supersecretpassword") {
		t.Error("DATABASE_URL password was not replaced")
	}

	// Non-secret values should be unchanged.
	if !strings.Contains(envStr, "HOSTNAME=myserver.local") {
		t.Error("HOSTNAME should not have been changed")
	}
	if !strings.Contains(envStr, "DEBUG=true") {
		t.Error("DEBUG should not have been changed")
	}

	// Comments should be preserved.
	if !strings.Contains(envStr, "# Test environment") {
		t.Error("comment was not preserved in .env round-trip")
	}

	// 5. Verify .veil/ structure created by init.
	assertFileExists(t, filepath.Join(projDir, ".veil", "vault.bin"))
	assertFileExists(t, filepath.Join(projDir, ".veil", "vault.meta"))
	assertFileExists(t, filepath.Join(projDir, ".veil", ".gitignore"))
	// Note: audit.sqlite is created lazily on first veil run/status/log call.

	// 6. Run veil run with a trivial command.
	runCmd := exec.Command(veilBin, "run", "--path", projDir, "--", "sh", "-c", "exit 0")
	runCmd.Env = env
	runOut, err := runCmd.CombinedOutput()
	if err != nil {
		t.Logf("veil run output: %s", runOut)
		t.Fatalf("veil run (exit 0) failed: %v", err)
	}

	// Verify audit.sqlite was created by veil run.
	assertFileExists(t, filepath.Join(projDir, ".veil", "audit.sqlite"))

	// 7. Test exit code propagation.
	runCmd2 := exec.Command(veilBin, "run", "--path", projDir, "--", "sh", "-c", "exit 7")
	runCmd2.Env = env
	_ = runCmd2.Run()
	if runCmd2.ProcessState == nil {
		t.Fatal("veil run (exit 7): no ProcessState")
	}
	if got := runCmd2.ProcessState.ExitCode(); got != 7 {
		t.Errorf("exit code propagation: got %d, want 7", got)
	}

	// 8. Check veil status.
	statusCmd := exec.Command(veilBin, "status", "--path", projDir)
	statusCmd.Env = env
	statusOut, err := statusCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil status failed: %v\n%s", err, statusOut)
	}
	statusStr := string(statusOut)
	if !strings.Contains(statusStr, "Credentials") {
		t.Error("status output missing Credentials line")
	}
	if !strings.Contains(statusStr, "Veil Status") {
		t.Error("status output missing 'Veil Status' header")
	}

	// 9. Check veil list.
	listCmd := exec.Command(veilBin, "list", "--path", projDir)
	listCmd.Env = env
	listOut, err := listCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil list failed: %v\n%s", err, listOut)
	}
	listStr := string(listOut)
	if !strings.Contains(listStr, "OPENAI_API_KEY") {
		t.Error("list output missing OPENAI_API_KEY")
	}
	if !strings.Contains(listStr, "DATABASE_URL") {
		t.Error("list output missing DATABASE_URL")
	}
	if strings.Contains(listStr, "HOSTNAME") {
		t.Error("HOSTNAME should not appear in vault list")
	}
	if strings.Contains(listStr, "DEBUG") {
		t.Error("DEBUG should not appear in vault list")
	}

	// 10. Check veil log.
	logCmd := exec.Command(veilBin, "log", "--path", projDir)
	logCmd.Env = env
	logOut, err := logCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil log failed: %v\n%s", err, logOut)
	}
	// No injections happened (no HTTP requests through the proxy), so just
	// verify it doesn't crash and prints the expected empty-state message.
	if !strings.Contains(string(logOut), "No credential injections") {
		t.Error("log output missing 'No credential injections'")
	}
}

// TestE2E_EnvRoundTrip verifies that .env files with comments, blank lines,
// mixed quoting, and export prefixes survive veil init with only secret
// values changed.
func TestE2E_EnvRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	env := makeEnv(t)

	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)

	projDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projDir, ".git"), 0755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	envContent := `# Database config
export DB_HOST=localhost
DB_PORT=5432
DB_PASSWORD=mysecretpassword1234567890

# API Keys
OPENAI_API_KEY=sk-proj-1234567890abcdef1234567890abcdef
SIMPLE_VALUE=hello

# Empty and special
EMPTY_VAL=
URL_WITH_PASS=postgres://admin:secretpass123456789@db.example.com:5432/app
`
	if err := os.WriteFile(filepath.Join(projDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	initCmd := exec.Command(veilBin, "init", "--path", projDir)
	initCmd.Env = env
	initOut, err := initCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil init failed: %v\n%s", err, initOut)
	}

	rewritten, err := os.ReadFile(filepath.Join(projDir, ".env"))
	if err != nil {
		t.Fatalf("reading .env: %v", err)
	}
	envStr := string(rewritten)

	// Comments should be preserved.
	for _, comment := range []string{
		"# Database config",
		"# API Keys",
		"# Empty and special",
	} {
		if !strings.Contains(envStr, comment) {
			t.Errorf("comment not preserved: %q", comment)
		}
	}

	// Non-secret values should be unchanged.
	if !strings.Contains(envStr, "export DB_HOST=localhost") {
		t.Error("export DB_HOST should be unchanged (and export prefix preserved)")
	}
	if !strings.Contains(envStr, "DB_PORT=5432") {
		t.Error("DB_PORT should be unchanged")
	}
	if !strings.Contains(envStr, "SIMPLE_VALUE=hello") {
		t.Error("SIMPLE_VALUE should be unchanged")
	}
	if !strings.Contains(envStr, "EMPTY_VAL=") {
		t.Error("EMPTY_VAL should be unchanged")
	}

	// Secret values should be replaced.
	if strings.Contains(envStr, "mysecretpassword1234567890") {
		t.Error("DB_PASSWORD was not replaced")
	}
	if strings.Contains(envStr, "sk-proj-1234567890abcdef") {
		t.Error("OPENAI_API_KEY was not replaced")
	}
	if strings.Contains(envStr, "secretpass123456789") {
		t.Error("URL_WITH_PASS password was not replaced")
	}

	// Verify key names are still present (only values changed).
	for _, key := range []string{"DB_PASSWORD=", "OPENAI_API_KEY=", "URL_WITH_PASS="} {
		if !strings.Contains(envStr, key) {
			t.Errorf("key %q should still be present in .env", key)
		}
	}

	// Verify line count is preserved (structural round-trip).
	origLines := strings.Count(envContent, "\n")
	newLines := strings.Count(envStr, "\n")
	if origLines != newLines {
		t.Errorf("line count changed: orig=%d, new=%d", origLines, newLines)
	}
}

// TestE2E_ProxyInjection verifies that the proxy actually replaces
// placeholder values in HTTP requests with real secret values.
func TestE2E_ProxyInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// Channel to capture the Authorization header received by the test server.
	type captured struct {
		Auth   string `json:"auth"`
		Method string `json:"method"`
	}
	captureCh := make(chan captured, 1)

	// 1. Start HTTP test server that echoes the Authorization header.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		resp := map[string]interface{}{
			"auth":   r.Header.Get("Authorization"),
			"body":   string(body),
			"method": r.Method,
		}
		captureCh <- captured{
			Auth:   r.Header.Get("Authorization"),
			Method: r.Method,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	env := makeEnv(t)

	// 2. Build binaries.
	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)
	clientBin := buildTestClient(t, binDir)

	// 3. Create project with a known secret.
	projDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projDir, ".git"), 0755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	originalKey := "sk-proj-test1234567890abcdef1234567890abcdef"
	envContent := fmt.Sprintf("OPENAI_API_KEY=%s\n", originalKey)
	if err := os.WriteFile(filepath.Join(projDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	// 4. veil init
	initCmd := exec.Command(veilBin, "init", "--path", projDir)
	initCmd.Env = env
	initOut, err := initCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil init failed: %v\n%s", err, initOut)
	}

	// 5. Read the placeholder from the rewritten .env.
	rewritten, err := os.ReadFile(filepath.Join(projDir, ".env"))
	if err != nil {
		t.Fatalf("reading .env: %v", err)
	}
	envStr := string(rewritten)

	// Parse out the placeholder value.
	var placeholder string
	for _, line := range strings.Split(envStr, "\n") {
		if strings.HasPrefix(line, "OPENAI_API_KEY=") {
			placeholder = strings.TrimPrefix(line, "OPENAI_API_KEY=")
			break
		}
	}
	if placeholder == "" {
		t.Fatal("could not find OPENAI_API_KEY in rewritten .env")
	}
	if placeholder == originalKey {
		t.Fatal("OPENAI_API_KEY was not replaced with a placeholder")
	}
	t.Logf("placeholder: %s", placeholder)

	// 6. Run testclient through veil run.
	// The testclient reads TEST_API_KEY from env and sends it as an
	// Authorization header. The credential is auto-scoped to api.openai.com
	// (via provider detection), so host-scoping denies the swap and the
	// placeholder would reach the wire. The fail-closed guard (SEC-2) must
	// then detect the sentinel and refuse to forward the request — the test
	// server should receive nothing.
	//
	// TEST_API_KEY is an intentionally-passed test fixture whose value is a
	// Veil placeholder that looks secret-like; --allow-env-secret satisfies
	// the runtime fail-closed scan so the test can still exercise the path.
	runCmd := exec.Command(veilBin, "run", "--path", projDir,
		"--allow-env-secret", "TEST_API_KEY",
		"--", clientBin, ts.URL+"/echo")
	runEnv := append(env, "TEST_API_KEY="+placeholder)
	runCmd.Env = runEnv
	// The proxy returns 502 to the testclient; testclient still exits 0 and
	// writes the 502 body to stdout. We only use the output for diagnostics.
	runOut, _ := runCmd.CombinedOutput()
	t.Logf("testclient response: %s", runOut)

	// 7. The fail-closed guard must prevent the placeholder from reaching a
	// host outside the credential's allowed set. Any capture indicates a
	// bypass of the guard — the real secret was not leaked, but sending a
	// sentinelled placeholder to an unrelated host is still rejected.
	select {
	case cap := <-captureCh:
		t.Fatalf("fail-closed bypass: server received request at non-matching host\n  Authorization: %s", cap.Auth)
	case <-time.After(500 * time.Millisecond):
		// Expected — the guard blocked the request.
	}

	// 8. Verify audit log recorded both events:
	//   - blocked: the injector denied the swap on host-scope mismatch.
	//   - leaked:  the fail-closed guard caught the sentinel on the wire.
	logCmd := exec.Command(veilBin, "log", "--path", projDir, "--json", "--blocked")
	logCmd.Env = env
	logOut, err := logCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil log failed: %v\n%s", err, logOut)
	}
	logStr := string(logOut)
	t.Logf("audit log:\n%s", logStr)
	if strings.TrimSpace(logStr) == "" {
		t.Fatal("audit log is empty; expected blocked + leaked events")
	}

	var sawBlocked, sawLeaked bool
	for _, line := range strings.Split(strings.TrimSpace(logStr), "\n") {
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("parsing audit log JSON: %v\nline: %s", err, line)
		}
		switch entry["location"] {
		case "blocked":
			if entry["credential"] == "OPENAI_API_KEY" {
				sawBlocked = true
			}
		case "leaked":
			sawLeaked = true
		}
	}
	if !sawBlocked {
		t.Error("audit log missing blocked event for OPENAI_API_KEY (injector did not record host-scope denial)")
	}
	if !sawLeaked {
		t.Error("audit log missing leaked event (fail-closed guard did not record sentinel detection)")
	}
}

// buildTestClientPost compiles the testclient_post helper binary into binDir.
func buildTestClientPost(t *testing.T, binDir string) string {
	t.Helper()
	clientBin := filepath.Join(binDir, "testclient_post")
	build := exec.Command("go", "build", "-o", clientBin, "./test/integration/testclient_post")
	build.Dir = projectRoot(t)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("build testclient_post binary: %v\n%s", err, out)
	}
	return clientBin
}

// TestE2E_ProxyBodyInjection verifies that the proxy replaces placeholder
// values in HTTP POST request bodies.
func TestE2E_ProxyBodyInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	type captured struct {
		Body string `json:"body"`
	}
	captureCh := make(chan captured, 1)

	// Start HTTP test server that captures the request body.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captureCh <- captured{Body: string(body)}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	env := makeEnv(t)

	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)
	postClientBin := buildTestClientPost(t, binDir)

	// Create project with a credential manually scoped to the test server.
	projDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projDir, ".git"), 0755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	originalKey := "sk-proj-bodytest1234567890abcdef1234567890"
	envContent := fmt.Sprintf("OPENAI_API_KEY=%s\n", originalKey)
	if err := os.WriteFile(filepath.Join(projDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	// Init to vault the secret.
	initCmd := exec.Command(veilBin, "init", "--path", projDir)
	initCmd.Env = env
	initOut, err := initCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil init failed: %v\n%s", err, initOut)
	}

	// Read the placeholder.
	rewritten, err := os.ReadFile(filepath.Join(projDir, ".env"))
	if err != nil {
		t.Fatalf("reading .env: %v", err)
	}
	var placeholder string
	for _, line := range strings.Split(string(rewritten), "\n") {
		if strings.HasPrefix(line, "OPENAI_API_KEY=") {
			placeholder = strings.TrimPrefix(line, "OPENAI_API_KEY=")
			break
		}
	}
	if placeholder == "" || placeholder == originalKey {
		t.Fatal("could not find placeholder in rewritten .env")
	}

	// Extract the test server's host (without port) for scoping.
	// HostMatches strips port from the request host, so allowed hosts must be portless.
	tsHostPort := strings.TrimPrefix(ts.URL, "http://")
	tsHost, _, _ := net.SplitHostPort(tsHostPort)

	// Manually add the credential scoped to the test server host.
	addCmd := exec.Command(veilBin, "add", "--path", projDir, "--force",
		"--value", originalKey, "--host", tsHost, "OPENAI_API_KEY")
	addCmd.Env = env
	addOut, err := addCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil add failed: %v\n%s", err, addOut)
	}

	// Re-read the updated placeholder.
	rewritten2, err := os.ReadFile(filepath.Join(projDir, ".env"))
	if err != nil {
		t.Fatalf("reading .env: %v", err)
	}
	for _, line := range strings.Split(string(rewritten2), "\n") {
		if strings.HasPrefix(line, "OPENAI_API_KEY=") {
			placeholder = strings.TrimPrefix(line, "OPENAI_API_KEY=")
			break
		}
	}

	// Build a JSON body containing the placeholder.
	testBody := fmt.Sprintf(`{"model":"gpt-4","key":"%s"}`, placeholder)

	// Run testclient_post through veil run. TEST_BODY carries the
	// placeholder; --allow-env-secret lets it past the runtime fail-closed
	// scan.
	runCmd := exec.Command(veilBin, "run", "--path", projDir,
		"--allow-env-secret", "TEST_BODY",
		"--", postClientBin, ts.URL+"/v1/chat")
	runCmd.Env = append(env, "TEST_BODY="+testBody)
	runOut, err := runCmd.CombinedOutput()
	if err != nil {
		t.Logf("veil run output: %s", runOut)
		t.Fatalf("veil run failed: %v", err)
	}

	// Check what the test server received.
	cap := <-captureCh
	t.Logf("server received body: %s", cap.Body)

	// The body should contain the REAL key, not the placeholder.
	if !strings.Contains(cap.Body, originalKey) {
		t.Errorf("body injection failed — real key not found in body:\n  got: %s", cap.Body)
	}
	if strings.Contains(cap.Body, placeholder) {
		t.Errorf("placeholder was not replaced in body:\n  got: %s", cap.Body)
	}
}

// TestE2E_ProxyHeaderInjectionAuthorizedHost verifies that the proxy injects
// credentials into requests to authorized hosts (not just blocks wrong hosts).
func TestE2E_ProxyHeaderInjectionAuthorizedHost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	type captured struct {
		Auth string
	}
	captureCh := make(chan captured, 1)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captureCh <- captured{Auth: r.Header.Get("Authorization")}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	env := makeEnv(t)
	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)
	clientBin := buildTestClient(t, binDir)

	projDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projDir, ".git"), 0755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	originalKey := "ghp_authtest1234567890abcdef1234567890ab"
	envContent := fmt.Sprintf("GITHUB_TOKEN=%s\n", originalKey)
	if err := os.WriteFile(filepath.Join(projDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	// Init.
	initCmd := exec.Command(veilBin, "init", "--path", projDir)
	initCmd.Env = env
	initOut, err := initCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil init failed: %v\n%s", err, initOut)
	}

	// Read the placeholder.
	rewritten, err := os.ReadFile(filepath.Join(projDir, ".env"))
	if err != nil {
		t.Fatalf("reading .env: %v", err)
	}
	var placeholder string
	for _, line := range strings.Split(string(rewritten), "\n") {
		if strings.HasPrefix(line, "GITHUB_TOKEN=") {
			placeholder = strings.TrimPrefix(line, "GITHUB_TOKEN=")
			break
		}
	}
	if placeholder == "" || placeholder == originalKey {
		t.Fatal("could not find placeholder in rewritten .env")
	}

	// Scope the credential to the test server host (without port).
	tsHostPort := strings.TrimPrefix(ts.URL, "http://")
	tsHost, _, _ := net.SplitHostPort(tsHostPort)
	addCmd := exec.Command(veilBin, "add", "--path", projDir, "--force",
		"--value", originalKey, "--host", tsHost, "GITHUB_TOKEN")
	addCmd.Env = env
	addOut, err := addCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil add --force failed: %v\n%s", err, addOut)
	}

	// Re-read the updated placeholder.
	rewritten2, err := os.ReadFile(filepath.Join(projDir, ".env"))
	if err != nil {
		t.Fatalf("reading .env: %v", err)
	}
	for _, line := range strings.Split(string(rewritten2), "\n") {
		if strings.HasPrefix(line, "GITHUB_TOKEN=") {
			placeholder = strings.TrimPrefix(line, "GITHUB_TOKEN=")
			break
		}
	}

	// Run testclient through veil run with the placeholder as TEST_API_KEY.
	// --allow-env-secret permits the test-injected var past the runtime
	// fail-closed scan.
	runCmd := exec.Command(veilBin, "run", "--path", projDir,
		"--allow-env-secret", "TEST_API_KEY",
		"--", clientBin, ts.URL+"/repos")
	runCmd.Env = append(env, "TEST_API_KEY="+placeholder)
	runOut, err := runCmd.CombinedOutput()
	if err != nil {
		t.Logf("veil run output: %s", runOut)
		t.Fatalf("veil run failed: %v", err)
	}

	// The server should have received the REAL token, not the placeholder.
	cap := <-captureCh
	t.Logf("server received Authorization: %s", cap.Auth)

	expectedAuth := "Bearer " + originalKey
	if cap.Auth != expectedAuth {
		t.Errorf("header injection to authorized host failed:\n  got:  %s\n  want: %s", cap.Auth, expectedAuth)
	}
	if strings.Contains(cap.Auth, placeholder) {
		t.Errorf("placeholder was not replaced in header:\n  got: %s", cap.Auth)
	}

	// Verify audit log shows successful injection (not blocked).
	logCmd := exec.Command(veilBin, "log", "--path", projDir, "--json")
	logCmd.Env = env
	logOut, err := logCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil log failed: %v\n%s", err, logOut)
	}
	logStr := strings.TrimSpace(string(logOut))
	if logStr == "" {
		t.Error("audit log is empty; expected injection event")
	} else {
		var entry map[string]interface{}
		lines := strings.Split(logStr, "\n")
		if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
			t.Fatalf("parsing audit log JSON: %v", err)
		}
		if entry["location"] == "blocked" {
			t.Error("injection should not be blocked for authorized host")
		}
		if entry["credential"] != "GITHUB_TOKEN" {
			t.Errorf("expected credential GITHUB_TOKEN, got %v", entry["credential"])
		}
	}
}

// TestE2E_ExitCodeAndEnvVars verifies proxy environment injection and exit code propagation.
func TestE2E_ExitCodeAndEnvVars(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	env := makeEnv(t)
	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)

	projDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projDir, ".git"), 0755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projDir, ".env"),
		[]byte("API_KEY=sk-proj-envtest1234567890abcdef1234567890\n"), 0644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	initCmd := exec.Command(veilBin, "init", "--path", projDir)
	initCmd.Env = env
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("veil init failed: %v\n%s", err, out)
	}

	// Verify proxy env vars are set in child.
	runCmd := exec.Command(veilBin, "run", "--path", projDir, "--",
		"sh", "-c", "echo PROXY=$HTTPS_PROXY; echo CA=$SSL_CERT_FILE; echo NP=$NO_PROXY")
	runCmd.Env = env
	runOut, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil run failed: %v\n%s", err, runOut)
	}
	outStr := string(runOut)
	if !strings.Contains(outStr, "PROXY=http://127.0.0.1:") {
		t.Error("HTTPS_PROXY not set to loopback")
	}
	if !strings.Contains(outStr, "CA=") {
		t.Error("SSL_CERT_FILE not set")
	}
	if !strings.Contains(outStr, "NP=localhost,127.0.0.1,::1") {
		t.Error("NO_PROXY defaults not set")
	}

	// Verify exit code propagation.
	runCmd2 := exec.Command(veilBin, "run", "--path", projDir, "--",
		"sh", "-c", "exit 42")
	runCmd2.Env = env
	_ = runCmd2.Run()
	if runCmd2.ProcessState == nil {
		t.Fatal("no ProcessState")
	}
	if got := runCmd2.ProcessState.ExitCode(); got != 42 {
		t.Errorf("exit code: got %d, want 42", got)
	}
}

// TestE2E_InitIdempotent verifies that running init twice (without --force)
// returns an error, and that --force reinitializes cleanly.
func TestE2E_InitIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	env := makeEnv(t)

	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)

	projDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projDir, ".git"), 0755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	envContent := []byte("API_KEY=sk-proj-abcdef1234567890abcdef1234567890\n")
	envPath := filepath.Join(projDir, ".env")
	if err := os.WriteFile(envPath, envContent, 0644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	// First init should succeed.
	cmd1 := exec.Command(veilBin, "init", "--path", projDir)
	cmd1.Env = env
	out1, err := cmd1.CombinedOutput()
	if err != nil {
		t.Fatalf("first init failed: %v\n%s", err, out1)
	}

	// Second init without --force should fail.
	cmd2 := exec.Command(veilBin, "init", "--path", projDir)
	cmd2.Env = env
	out2, err := cmd2.CombinedOutput()
	if err == nil {
		t.Fatal("second init should have failed without --force")
	}
	if !strings.Contains(string(out2), "already initialized") {
		t.Errorf("error should mention 'already initialized', got: %s", out2)
	}

	// Restore the original .env so --force has fresh input to re-vault.
	// Without this, init refuses to re-vault a placeholder-laden .env by
	// design (the data-loss guard added in
	// TestInitForce_PreservesOriginalSecretsWhenEnvAlreadyVaulted).
	if err := os.WriteFile(envPath, envContent, 0644); err != nil {
		t.Fatalf("restore .env: %v", err)
	}

	// With --force should succeed.
	cmd3 := exec.Command(veilBin, "init", "--force", "--path", projDir)
	cmd3.Env = env
	out3, err := cmd3.CombinedOutput()
	if err != nil {
		t.Fatalf("init --force failed: %v\n%s", err, out3)
	}
}

// TestE2E_DryRun verifies that --dry-run shows what would be vaulted
// without modifying the .env file.
func TestE2E_DryRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	env := makeEnv(t)

	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)

	projDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projDir, ".git"), 0755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	original := "OPENAI_API_KEY=sk-proj-dryrun1234567890abcdef1234567890\n"
	if err := os.WriteFile(filepath.Join(projDir, ".env"), []byte(original), 0644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	cmd := exec.Command(veilBin, "init", "--dry-run", "--path", projDir)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("init --dry-run failed: %v\n%s", err, out)
	}

	// The .env file should be unchanged after dry-run.
	after, err := os.ReadFile(filepath.Join(projDir, ".env"))
	if err != nil {
		t.Fatalf("reading .env: %v", err)
	}
	if string(after) != original {
		t.Errorf(".env was modified during dry-run:\n  before: %q\n  after:  %q", original, string(after))
	}
}
