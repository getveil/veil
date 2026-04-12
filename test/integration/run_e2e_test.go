package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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
// We keep the real HOME so the macOS keychain is accessible (the keyring
// is tied to the login keychain, not HOME). The CA certificate is stored
// under HOME too and is shared/idempotent. All project-specific state
// lives under the --path directory, so tests are isolated via t.TempDir().
//
// We do NOT set VEIL_TEST_KEYSTORE=mem because e2e tests span multiple
// processes (veil init, veil run, veil status, ...) that must share the
// keystore.
func makeEnv() []string {
	env := os.Environ()
	// Strip any leftover VEIL_TEST_KEYSTORE from the parent process
	// (e.g. if `make test` sets it). We need the real keystore.
	filtered := env[:0]
	for _, kv := range env {
		if strings.HasPrefix(kv, "VEIL_TEST_KEYSTORE=") {
			continue
		}
		filtered = append(filtered, kv)
	}
	return filtered
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

	env := makeEnv()

	// 1. Build the veil binary.
	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)

	// 2. Create a test project.
	projDir := t.TempDir()
	os.Mkdir(filepath.Join(projDir, ".git"), 0755)

	envContent := "# Test environment\nOPENAI_API_KEY=sk-proj-test1234567890abcdef1234567890abcdef\nDATABASE_URL=postgres://user:supersecretpassword@localhost:5432/mydb\nHOSTNAME=myserver.local\nDEBUG=true\n"
	os.WriteFile(filepath.Join(projDir, ".env"), []byte(envContent), 0644)

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
	if !strings.Contains(statusStr, "Credentials:") {
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
	if !strings.Contains(string(logOut), "No injection events found") {
		t.Error("log output missing 'No injection events found'")
	}
}

// TestE2E_EnvRoundTrip verifies that .env files with comments, blank lines,
// mixed quoting, and export prefixes survive veil init with only secret
// values changed.
func TestE2E_EnvRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	env := makeEnv()

	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)

	projDir := t.TempDir()
	os.Mkdir(filepath.Join(projDir, ".git"), 0755)

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
	os.WriteFile(filepath.Join(projDir, ".env"), []byte(envContent), 0644)

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
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	env := makeEnv()

	// 2. Build binaries.
	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)
	clientBin := buildTestClient(t, binDir)

	// 3. Create project with a known secret.
	projDir := t.TempDir()
	os.Mkdir(filepath.Join(projDir, ".git"), 0755)

	originalKey := "sk-proj-test1234567890abcdef1234567890abcdef"
	envContent := fmt.Sprintf("OPENAI_API_KEY=%s\n", originalKey)
	os.WriteFile(filepath.Join(projDir, ".env"), []byte(envContent), 0644)

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
	// The testclient reads TEST_API_KEY from env, sends it as an
	// Authorization header, and the proxy should swap the placeholder for
	// the real value.
	runCmd := exec.Command(veilBin, "run", "--path", projDir, "--",
		clientBin, ts.URL+"/echo")
	runEnv := append(env, "TEST_API_KEY="+placeholder)
	runCmd.Env = runEnv
	runOut, err := runCmd.CombinedOutput()
	if err != nil {
		t.Logf("veil run output: %s", runOut)
		t.Fatalf("veil run failed: %v", err)
	}
	t.Logf("testclient response: %s", runOut)

	// 7. Check what the test server received.
	cap := <-captureCh
	t.Logf("server received Authorization: %s", cap.Auth)

	// The proxy should have replaced the placeholder with the real key.
	expectedAuth := "Bearer " + originalKey
	if cap.Auth != expectedAuth {
		t.Errorf("proxy injection failed:\n  got:  %s\n  want: %s", cap.Auth, expectedAuth)
	}
	if strings.Contains(cap.Auth, placeholder) {
		t.Error("server received the placeholder instead of the real secret")
	}

	// 8. Verify audit log recorded the injection.
	logCmd := exec.Command(veilBin, "log", "--path", projDir, "--json")
	logCmd.Env = env
	logOut, err := logCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil log failed: %v\n%s", err, logOut)
	}
	logStr := string(logOut)
	t.Logf("audit log:\n%s", logStr)

	// The JSON log should have at least one injection event.
	if strings.TrimSpace(logStr) == "" {
		t.Error("audit log is empty; expected at least one injection event")
	} else {
		// Parse the first JSON line.
		var entry map[string]interface{}
		lines := strings.Split(strings.TrimSpace(logStr), "\n")
		if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
			t.Fatalf("parsing audit log JSON: %v\nline: %s", err, lines[0])
		}
		if entry["credential"] != "OPENAI_API_KEY" {
			t.Errorf("audit entry credential = %v, want OPENAI_API_KEY", entry["credential"])
		}
		if entry["location"] != "header" {
			t.Errorf("audit entry location = %v, want header", entry["location"])
		}
	}
}

// TestE2E_InitIdempotent verifies that running init twice (without --force)
// returns an error, and that --force reinitializes cleanly.
func TestE2E_InitIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	env := makeEnv()

	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)

	projDir := t.TempDir()
	os.Mkdir(filepath.Join(projDir, ".git"), 0755)
	os.WriteFile(filepath.Join(projDir, ".env"),
		[]byte("API_KEY=sk-proj-abcdef1234567890abcdef1234567890\n"), 0644)

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

	env := makeEnv()

	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)

	projDir := t.TempDir()
	os.Mkdir(filepath.Join(projDir, ".git"), 0755)

	original := "OPENAI_API_KEY=sk-proj-dryrun1234567890abcdef1234567890\n"
	os.WriteFile(filepath.Join(projDir, ".env"), []byte(original), 0644)

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
